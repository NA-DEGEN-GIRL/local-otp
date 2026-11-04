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

/** The Keystore key can never be used again (screen lock removed, new fingerprint). */
class KeyInvalidated : OtpException("보안 키가 영구히 무효화되었습니다.")

/**
 * Non-exportable Android Keystore keys. Every use needs a fresh user
 * authentication (no timeout), the device must be unlocked, and software-only
 * keys are refused.
 *
 * - Vault key: wraps the random half S of the vault key. Biometric or screen lock.
 * - Quick key: wraps the session keys for fingerprint-only unlock. Strong
 *   biometrics only; invalidated when a new fingerprint is enrolled.
 */
object HardwareKey {
    private const val STORE = "AndroidKeyStore"
    private const val VAULT = "LocalOtp.Vault."
    private const val QUICK = "LocalOtp.Quick."

    enum class Level(val label: String) {
        STRONGBOX("StrongBox 보안 칩"),
        TEE("TEE(보안 영역)"),
    }

    private fun hex(id: ByteArray) = id.joinToString("") { "%02x".format(it) }
    fun vaultAlias(keyId: ByteArray) = VAULT + hex(keyId)
    fun quickAlias(keyId: ByteArray) = QUICK + hex(keyId)

    private fun store() = KeyStore.getInstance(STORE).apply { load(null) }

    fun get(alias: String): SecretKey? = store().getKey(alias, null) as SecretKey?

    fun createVaultKey(keyId: ByteArray): SecretKey = create(
        vaultAlias(keyId),
        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
        // Enrolling another fingerprint must not destroy the vault.
        invalidatedByEnrollment = false,
    )

    fun createQuickKey(keyId: ByteArray): SecretKey = create(
        quickAlias(keyId),
        KeyProperties.AUTH_BIOMETRIC_STRONG,
        // A newly enrolled fingerprint must not open the vault without the password.
        invalidatedByEnrollment = true,
    )

    /** Prefers StrongBox, never falls back to software. */
    private fun create(alias: String, authenticators: Int, invalidatedByEnrollment: Boolean): SecretKey {
        if (store().containsAlias(alias)) throw OtpException("같은 이름의 키가 이미 있습니다.")
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, authenticators)
            .setInvalidatedByBiometricEnrollment(invalidatedByEnrollment)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE)
        val key = try {
            try {
                generator.init(spec(true))
                generator.generateKey()
            } catch (e: Exception) {
                // No StrongBox, or (on some devices) a ProviderException for an
                // unsupported parameter combination: use the TEE instead.
                if (e !is StrongBoxUnavailableException && e !is java.security.ProviderException) throw e
                runCatching { store().deleteEntry(alias) }
                generator.init(spec(false))
                generator.generateKey()
            }
        } catch (e: OtpException) {
            throw e
        } catch (e: Exception) {
            throw OtpException("보안 키를 만들 수 없습니다. 화면 잠금(과 생체인증)이 설정되어 있는지 확인하세요. (${e.javaClass.simpleName})")
        } catch (e: IllegalStateException) {
            throw OtpException("보안 키를 만들 수 없습니다. 화면 잠금(과 생체인증)이 설정되어 있는지 확인하세요.")
        }
        if (level(key) == null) {
            delete(alias)
            throw OtpException("이 기기는 하드웨어 보안 키를 지원하지 않습니다.")
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

    /** Only for an unfinished vault creation, or the quick key when turned off. */
    fun delete(alias: String) {
        store().deleteEntry(alias)
    }

    /** Delete every quick-unlock key (separate prefix; vault keys are never touched). */
    fun deleteAllQuick() {
        val ks = store()
        ks.aliases().toList().filter { it.startsWith(QUICK) }.forEach { runCatching { ks.deleteEntry(it) } }
    }

    // Initialized only: AAD and data are passed after the user authenticates the
    // operation through BiometricPrompt.
    fun encryptCipher(key: SecretKey): Cipher = cipher { init(Cipher.ENCRYPT_MODE, key) }

    fun decryptCipher(key: SecretKey, iv: ByteArray): Cipher =
        cipher { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }

    private fun cipher(setup: Cipher.() -> Unit): Cipher = try {
        Cipher.getInstance("AES/GCM/NoPadding").apply(setup)
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw KeyInvalidated()
    }
}
