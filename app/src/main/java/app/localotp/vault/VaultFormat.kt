package app.localotp.vault

import app.localotp.otp.Algorithm
import app.localotp.otp.Base32
import app.localotp.otp.OtpException
import app.localotp.otp.SUPPORTED_DIGITS
import app.localotp.otp.SUPPORTED_PERIODS
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** A stored account. The secret is cleared with [wipe] when the vault locks. */
class Account(
    val name: String,
    val secret: ByteArray,
    val algorithm: Algorithm,
    val digits: Int,
    val period: Int,
) {
    fun wipe() = secret.fill(0)
}

/** Plaintext account list, same layout as the Windows app ("LOTP0002"). */
object EntryCodec {
    private val MAGIC = "LOTP0002".toByteArray(Charsets.US_ASCII)
    const val MAX_ACCOUNTS = 1000

    fun serialize(accounts: List<Account>): ByteArray {
        if (accounts.size > MAX_ACCOUNTS) throw OtpException("계정이 너무 많습니다.")
        var size = 12
        val names = accounts.map { it.name.toByteArray(Charsets.UTF_8) }
        accounts.forEachIndexed { i, a ->
            if (names[i].isEmpty() || names[i].size > 1024 || a.secret.isEmpty() || a.secret.size > Base32.MAX_SECRET_BYTES) {
                throw OtpException("계정 데이터 크기가 올바르지 않습니다.")
            }
            if (a.digits !in SUPPORTED_DIGITS || a.period !in SUPPORTED_PERIODS) {
                throw OtpException("지원하지 않는 OTP 설정입니다.")
            }
            size += 11 + names[i].size + a.secret.size
        }
        // Exact allocation: a growing buffer would leave copies of secrets behind.
        val out = ByteBuffer.allocate(size).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        out.put(MAGIC).putInt(accounts.size)
        accounts.forEachIndexed { i, a ->
            out.putInt(names[i].size).putInt(a.secret.size)
            out.put(a.algorithm.code.toByte()).put(a.digits.toByte()).put(a.period.toByte())
            out.put(names[i]).put(a.secret)
        }
        return out.array()
    }

    fun deserialize(data: ByteArray): List<Account> {
        val fail = { OtpException("보관함 내용이 올바르지 않습니다.") }
        if (data.size < 12 || !data.copyOfRange(0, 8).contentEquals(MAGIC)) throw fail()
        val b = ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        b.position(8)
        val count = b.int
        if (count < 0 || count > MAX_ACCOUNTS) throw fail()
        val result = ArrayList<Account>(count)
        try {
            repeat(count) {
                if (b.remaining() < 11) throw fail()
                val n = b.int
                val s = b.int
                if (n !in 1..1024 || s !in 1..Base32.MAX_SECRET_BYTES) throw fail()
                val algorithm = Algorithm.fromCode(b.get().toInt()) ?: throw fail()
                val digits = b.get().toInt() and 0xff
                val period = b.get().toInt() and 0xff
                if (digits !in SUPPORTED_DIGITS || period !in SUPPORTED_PERIODS) throw fail()
                if (b.remaining() < n + s) throw fail()
                val nameBytes = ByteArray(n).also { b.get(it) }
                val name = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(nameBytes)).toString()
                val secret = ByteArray(s).also { b.get(it) }
                result += Account(name, secret, algorithm, digits, period)
            }
            if (b.hasRemaining()) throw fail()
        } catch (e: java.nio.charset.CharacterCodingException) {
            result.forEach { it.wipe() }
            throw fail()
        } catch (e: OtpException) {
            result.forEach { it.wipe() }
            throw e
        }
        return result
    }
}

/**
 * Vault file layout (all integers big-endian):
 *
 *     0  magic "LOTPAND1"          8
 *     8  PBKDF2 iterations         4
 *    12  password salt            32
 *    44  Keystore key id          16  (alias LocalOtp.Vault.<hex>)
 *    60  Keystore GCM IV          12
 *    72  wrapped random S         48  (32 + 16-byte tag; AAD = bytes 0..60)
 *   120  data nonce               12
 *   132  data length               4
 *   136  AES-256-GCM(K, data) + tag, AAD = bytes 0..136
 *
 * K = PBKDF2(password) XOR S. S can only be unwrapped by the non-exportable
 * Keystore key after the user authenticates (biometric or screen lock), so the
 * password alone, or the file alone, opens nothing.
 */
class VaultHeader(
    val iterations: Int,
    val salt: ByteArray,
    val keyId: ByteArray,
    val wrapIv: ByteArray,
    val wrapped: ByteArray,
) {
    /** Additional authenticated data for wrapping S: binds it to this vault. */
    fun wrapAad(): ByteArray = prefix().copyOfRange(0, WRAP_AAD_LEN)

    internal fun prefix(): ByteArray = ByteBuffer.allocate(NONCE_OFFSET)
        .put(VaultFile.MAGIC).putInt(iterations).put(salt).put(keyId).put(wrapIv).put(wrapped).array()

    companion object {
        const val WRAP_AAD_LEN = 60
        const val NONCE_OFFSET = 120
    }
}

object VaultFile {
    val MAGIC = "LOTPAND1".toByteArray(Charsets.US_ASCII)
    const val ITERATIONS = 600_000
    const val HEADER = 136
    const val TAG = 16
    const val MAX_FILE = 16 * 1024 * 1024
    private val random = SecureRandom()

    fun randomBytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }

    fun readHeader(blob: ByteArray): VaultHeader {
        if (blob.size < HEADER + TAG || blob.size > MAX_FILE || !blob.copyOfRange(0, 8).contentEquals(MAGIC)) {
            throw OtpException("보관함 파일 형식이 올바르지 않습니다.")
        }
        val b = ByteBuffer.wrap(blob)
        b.position(8)
        val iterations = b.int
        if (iterations < 100_000 || iterations > 10_000_000) throw OtpException("보관함 파일 형식이 올바르지 않습니다.")
        val salt = ByteArray(32).also { b.get(it) }
        val keyId = ByteArray(16).also { b.get(it) }
        val iv = ByteArray(12).also { b.get(it) }
        val wrapped = ByteArray(48).also { b.get(it) }
        b.position(132)
        val length = b.int
        if (length < 0 || blob.size != HEADER + length + TAG) throw OtpException("보관함 파일 길이가 올바르지 않습니다.")
        return VaultHeader(iterations, salt, keyId, iv, wrapped)
    }

    /**
     * PBKDF2-HMAC-SHA256 over the UTF-8 bytes of the password. The bytes are
     * hex-encoded into ASCII chars for PBEKeySpec, so the result never depends
     * on how a crypto provider encodes non-ASCII characters (a provider change
     * must not make a Korean password stop working).
     */
    fun derivePassword(password: CharArray, salt: ByteArray, iterations: Int): ByteArray {
        val utf8 = Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(password))
        val bytes = ByteArray(utf8.remaining()).also { utf8.get(it) }
        if (utf8.hasArray()) utf8.array().fill(0)
        val hexChars = CharArray(bytes.size * 2)
        val digits = "0123456789abcdef"
        bytes.forEachIndexed { i, x ->
            hexChars[2 * i] = digits[(x.toInt() ushr 4) and 15]
            hexChars[2 * i + 1] = digits[x.toInt() and 15]
        }
        bytes.fill(0)
        val spec = PBEKeySpec(hexChars, salt, iterations, 256)
        hexChars.fill('\u0000')
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    fun combine(passwordKey: ByteArray, s: ByteArray): ByteArray =
        ByteArray(32) { (passwordKey[it].toInt() xor s[it].toInt()).toByte() }

    fun sameKey(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)

    /** Encrypt `plaintext` with a fresh nonce. Verifies the result before returning. */
    fun seal(header: VaultHeader, key: ByteArray, plaintext: ByteArray): ByteArray {
        if (plaintext.size > MAX_FILE - HEADER - TAG) throw OtpException("보관함이 너무 큽니다.")
        val nonce = randomBytes(12)
        val head = ByteBuffer.allocate(HEADER).put(header.prefix()).put(nonce).putInt(plaintext.size).array()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(head)
        val body = cipher.doFinal(plaintext)
        val blob = head + body
        // The new blob replaces the only copy: prove it opens and round-trips.
        val check = open(blob, key)
        val same = check.contentEquals(plaintext)
        check.fill(0)
        if (!same) throw OtpException("새로 암호화한 보관함 검증 실패, 저장하지 않았습니다.")
        return blob
    }

    fun open(blob: ByteArray, key: ByteArray): ByteArray {
        readHeader(blob)
        val nonce = blob.copyOfRange(120, 132)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(blob, 0, HEADER)
        return try {
            cipher.doFinal(blob, HEADER, blob.size - HEADER)
        } catch (e: AEADBadTagException) {
            throw OtpException("비밀번호가 올바르지 않거나 보관함 파일이 손상되었습니다.")
        }
    }
}
