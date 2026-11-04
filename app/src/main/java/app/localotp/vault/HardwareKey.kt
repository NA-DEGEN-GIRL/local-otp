package app.localotp.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import app.localotp.otp.OtpException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The non-exportable Android Keystore key that wraps the vault's random half.
 * Every use needs a fresh biometric or screen-lock authentication (no timeout),
 * the device must be unlocked, and software-only keys are refused.
 */
object HardwareKey {
    private const val STORE = "AndroidKeyStore"
    private const val PREFIX = "LocalOtp.Vault."

    enum class Level(val label: String) {
        STRONGBOX("StrongBox 보안 칩"),
        TEE("TEE(보안 영역)"),
    }

    fun alias(keyId: ByteArray) = PREFIX + keyId.joinToString("") { "%02x".format(it) }

    private fun store() = KeyStore.getInstance(STORE).apply { load(null) }

    fun get(keyId: ByteArray): SecretKey? = store().getKey(alias(keyId), null) as SecretKey?

    /** Create the key for a new vault. Prefers StrongBox, never falls back to software. */
    fun create(keyId: ByteArray): SecretKey {
        val alias = alias(keyId)
        if (store().containsAlias(alias)) throw OtpException("같은 이름의 키가 이미 있습니다.")
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            // Enrolling another fingerprint must not destroy the vault.
            .setInvalidatedByBiometricEnrollment(false)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE)
        val key = try {
            try {
                generator.init(spec(true))
                generator.generateKey()
            } catch (e: StrongBoxUnavailableException) {
                generator.init(spec(false))
                generator.generateKey()
            }
        } catch (e: java.security.GeneralSecurityException) {
            throw OtpException("보안 키를 만들 수 없습니다. 화면 잠금(PIN·패턴·비밀번호)을 설정했는지 확인하세요. (${e.javaClass.simpleName})")
        } catch (e: IllegalStateException) {
            throw OtpException("보안 키를 만들 수 없습니다. 화면 잠금(PIN·패턴·비밀번호)을 먼저 설정하세요.")
        }
        if (level(key) == null) {
            delete(keyId)
            throw OtpException("이 기기는 하드웨어 보안 키를 지원하지 않아 보관함을 만들 수 없습니다.")
        }
        return key
    }

    /** Hardware protection level, or null if the key is software-only. */
    fun level(key: SecretKey): Level? {
        val info = SecretKeyFactory.getInstance(key.algorithm, STORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> Level.STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> Level.TEE
            else -> null
        }
    }

    /** Only used to roll back a vault creation that did not complete. */
    fun delete(keyId: ByteArray) {
        store().deleteEntry(alias(keyId))
    }

    // Initialized only: AAD and data are passed after the user authenticates the
    // operation through BiometricPrompt.
    fun encryptCipher(key: SecretKey): Cipher = cipher { init(Cipher.ENCRYPT_MODE, key) }

    fun decryptCipher(key: SecretKey, iv: ByteArray): Cipher =
        cipher { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }

    private fun cipher(setup: Cipher.() -> Unit): Cipher = try {
        Cipher.getInstance("AES/GCM/NoPadding").apply(setup)
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw OtpException(
            "기기의 화면 잠금이 해제되었거나 보안 키가 무효화되어 이 보관함은 영구히 열 수 없습니다."
        )
    }
}
