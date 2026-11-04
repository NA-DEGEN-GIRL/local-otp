package app.localotp.otp

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** A user-facing validation or format error (Korean message). */
open class OtpException(message: String) : Exception(message)

enum class Algorithm(val label: String, internal val mac: String, val code: Int) {
    SHA1("SHA-1", "HmacSHA1", 1),
    SHA256("SHA-256", "HmacSHA256", 2),
    SHA512("SHA-512", "HmacSHA512", 3);

    companion object {
        fun fromCode(code: Int): Algorithm? = entries.firstOrNull { it.code == code }
    }
}

/** Supported settings; the vault format stores exactly these. */
val SUPPORTED_DIGITS = listOf(6, 8)
val SUPPORTED_PERIODS = listOf(30, 60)

object Base32 {
    const val MAX_SECRET_BYTES = 4096

    /**
     * RFC 4648 Base32, case-insensitive, optional padding. Spaces and hyphens
     * are ignored for grouped manual input. Unused trailing bits are ignored,
     * as other authenticator apps do.
     */
    fun decode(input: CharSequence): ByteArray {
        if (input.length > 8192) throw OtpException("비밀키가 너무 깁니다.")
        val values = ByteArray(input.length)
        try {
            var count = 0
            var padding = 0
            var seenPadding = false
            for (ch in input) {
                if (ch.isWhitespace() || ch == '-') continue
                if (ch == '=') {
                    seenPadding = true
                    padding++
                    continue
                }
                if (seenPadding) throw OtpException("Base32 패딩(=)은 끝에만 올 수 있습니다.")
                val v = when (ch) {
                    in 'A'..'Z' -> ch - 'A'
                    in 'a'..'z' -> ch - 'a'
                    in '2'..'7' -> ch - '2' + 26
                    '0', '1', '8', '9' -> throw OtpException(
                        "숫자 0, 1, 8, 9는 Base32에 없습니다. O, I, B 등을 잘못 읽었는지 확인하세요."
                    )
                    else -> throw OtpException("Base32에 사용할 수 없는 문자가 있습니다. (A–Z, 2–7만 가능)")
                }
                values[count++] = v.toByte()
            }
            if (count == 0) throw OtpException("비밀키가 비어 있습니다.")
            if (count > (MAX_SECRET_BYTES * 8 + 4) / 5) throw OtpException("비밀키가 너무 깁니다.")
            val expectedPadding = when (count % 8) {
                0 -> 0
                2 -> 6
                4 -> 4
                5 -> 3
                7 -> 1
                else -> throw OtpException("비밀키 길이가 올바르지 않습니다. 빠지거나 더 들어간 글자를 확인하세요.")
            }
            if (padding != 0 && padding != expectedPadding) {
                throw OtpException("Base32 패딩(=) 개수가 올바르지 않습니다.")
            }
            val out = ByteArray(count * 5 / 8)
            var acc = 0
            var bits = 0
            var index = 0
            for (i in 0 until count) {
                acc = (acc shl 5) or values[i].toInt()
                bits += 5
                if (bits >= 8) {
                    bits -= 8
                    out[index++] = (acc ushr bits).toByte()
                    acc = acc and ((1 shl bits) - 1)
                }
            }
            return out
        } finally {
            values.fill(0)
        }
    }
}

object Totp {
    private val POWERS = intArrayOf(1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000)

    /** RFC 6238. The caller owns and clears `secret`. */
    fun code(secret: ByteArray, timeSeconds: Long, period: Int, digits: Int, algorithm: Algorithm): String {
        require(secret.isNotEmpty() && secret.size <= Base32.MAX_SECRET_BYTES)
        require(period > 0 && digits in 6..8)
        val counter = Math.floorDiv(timeSeconds, period.toLong())
        val mac = Mac.getInstance(algorithm.mac)
        mac.init(SecretKeySpec(secret, algorithm.mac))
        val hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array())
        try {
            val offset = hash.last().toInt() and 0x0f
            val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
                ((hash[offset + 1].toInt() and 0xff) shl 16) or
                ((hash[offset + 2].toInt() and 0xff) shl 8) or
                (hash[offset + 3].toInt() and 0xff)
            return (binary % POWERS[digits]).toString().padStart(digits, '0')
        } finally {
            hash.fill(0)
        }
    }

    fun remaining(timeSeconds: Long, period: Int): Int = (period - Math.floorMod(timeSeconds, period.toLong())).toInt()

    /** "123456" -> "123 456", "12345678" -> "1234 5678". */
    fun group(code: String): String = code.substring(0, code.length / 2) + " " + code.substring(code.length / 2)
}

/** One account read from user input or a QR code. The caller clears `secret`. */
class ParsedAccount(
    val name: String,
    val secret: ByteArray,
    val algorithm: Algorithm,
    val digits: Int,
    val period: Int,
)
