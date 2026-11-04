package app.localotp.otp

import java.util.Base64

/**
 * Parsers for `otpauth://totp/...` key URIs and Google Authenticator export
 * links (`otpauth-migration://offline?data=...`). Everything is decoded on the
 * device; nothing is sent anywhere.
 */
object Links {
    private const val OTPAUTH = "otpauth://"
    private const val MIGRATION = "otpauth-migration://"

    fun isLink(text: CharSequence): Boolean {
        val t = text.trim()
        return t.startsWith(OTPAUTH, ignoreCase = true) || t.startsWith(MIGRATION, ignoreCase = true)
    }

    /** Parse either link type into one or more accounts. */
    fun parse(text: String): List<ParsedAccount> {
        val t = text.trim()
        return when {
            t.startsWith(MIGRATION, ignoreCase = true) -> parseMigration(t)
            t.startsWith(OTPAUTH, ignoreCase = true) -> listOf(parseOtpAuth(t))
            else -> throw OtpException("otpauth:// 링크나 QR 코드가 아닙니다.")
        }
    }

    fun parseOtpAuth(uri: String): ParsedAccount {
        if (uri.length > 16384) throw OtpException("링크가 너무 깁니다.")
        val rest = uri.substring(OTPAUTH.length)
        val slash = rest.indexOf('/')
        if (slash < 0) throw OtpException("otpauth 링크 형식이 올바르지 않습니다.")
        val kind = rest.substring(0, slash)
        if (kind.equals("hotp", ignoreCase = true)) throw OtpException("HOTP(카운터 방식)는 지원하지 않습니다.")
        if (!kind.equals("totp", ignoreCase = true)) throw OtpException("TOTP 링크가 아닙니다.")
        val afterKind = rest.substring(slash + 1)
        val q = afterKind.indexOf('?')
        val label = text(if (q < 0) afterKind else afterKind.substring(0, q), plusIsSpace = false).trim()
        val query = if (q < 0) "" else afterKind.substring(q + 1)
        var secret: ByteArray? = null
        var issuer = ""
        var algorithm = Algorithm.SHA1
        var digits = 6
        var period = 30
        try {
            for (pair in query.split('&')) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                val key = (if (eq < 0) pair else pair.substring(0, eq)).lowercase()
                val value = if (eq < 0) "" else pair.substring(eq + 1)
                when (key) {
                    "secret" -> {
                        val raw = percentDecode(value, plusIsSpace = true)
                        try {
                            val chars = CharArray(raw.size) { (raw[it].toInt() and 0xff).toChar() }
                            secret?.fill(0)
                            secret = Base32.decode(java.nio.CharBuffer.wrap(chars))
                            chars.fill('\u0000')
                        } finally {
                            raw.fill(0)
                        }
                    }
                    "issuer" -> issuer = text(value, plusIsSpace = true).trim()
                    "algorithm" -> algorithm = when (value.uppercase().replace("-", "")) {
                        "SHA1" -> Algorithm.SHA1
                        "SHA256" -> Algorithm.SHA256
                        "SHA512" -> Algorithm.SHA512
                        else -> throw OtpException("지원하지 않는 알고리즘입니다: $value")
                    }
                    "digits" -> digits = value.toIntOrNull() ?: throw OtpException("자릿수 값이 올바르지 않습니다: $value")
                    "period" -> period = value.toIntOrNull() ?: throw OtpException("주기 값이 올바르지 않습니다: $value")
                    // A non-standard encoder (e.g. Steam Guard) would never match
                    // numeric codes; refuse instead of silently showing wrong codes.
                    "encoder" -> throw OtpException("지원하지 않는 코드 형식입니다: $value")
                }
            }
            val s = secret ?: throw OtpException("링크에 secret 값이 없습니다.")
            checkSupported(digits, period)
            secret = null
            return ParsedAccount(displayName(label, issuer), s, algorithm, digits, period)
        } finally {
            secret?.fill(0)
        }
    }

    /** Google Authenticator export (protobuf MigrationPayload). Period is always 30. */
    fun parseMigration(uri: String): List<ParsedAccount> {
        val q = uri.indexOf('?')
        if (q < 0) throw OtpException("내보내기 링크에 data 값이 없습니다.")
        val data = uri.substring(q + 1).split('&')
            .firstOrNull { it.startsWith("data=", ignoreCase = true) }
            ?.substring(5) ?: throw OtpException("내보내기 링크에 data 값이 없습니다.")
        val encoded = String(percentDecode(data, plusIsSpace = false), Charsets.US_ASCII)
        val payload = try {
            Base64.getDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            try {
                Base64.getUrlDecoder().decode(encoded)
            } catch (e2: IllegalArgumentException) {
                throw OtpException("내보내기 데이터가 올바르지 않습니다.")
            }
        }
        val result = mutableListOf<ParsedAccount>()
        try {
            val reader = Proto(payload)
            while (!reader.eof()) {
                val (field, wire) = reader.tag()
                if (field == 1 && wire == 2) {
                    val item = reader.bytes()
                    try {
                        result += parseMigrationItem(item)
                    } finally {
                        item.fill(0)
                    }
                } else {
                    reader.skip(wire)
                }
            }
        } catch (e: OtpException) {
            result.forEach { it.secret.fill(0) }
            throw e
        } finally {
            payload.fill(0)
        }
        if (result.isEmpty()) throw OtpException("내보내기 데이터에 계정이 없습니다.")
        return result
    }

    private fun parseMigrationItem(bytes: ByteArray): ParsedAccount {
        val r = Proto(bytes)
        var secret: ByteArray? = null
        var name = ""
        var issuer = ""
        var algorithm = 1
        var digits = 1
        var type = 2
        try {
            while (!r.eof()) {
                val (field, wire) = r.tag()
                when {
                    field == 1 && wire == 2 -> { secret?.fill(0); secret = r.bytes() }
                    field == 2 && wire == 2 -> name = String(r.bytes(), Charsets.UTF_8)
                    field == 3 && wire == 2 -> issuer = String(r.bytes(), Charsets.UTF_8)
                    field == 4 && wire == 0 -> algorithm = r.varint().toInt()
                    field == 5 && wire == 0 -> digits = r.varint().toInt()
                    field == 6 && wire == 0 -> type = r.varint().toInt()
                    else -> r.skip(wire)
                }
            }
            if (type == 1) throw OtpException("HOTP(카운터 방식) 계정은 지원하지 않습니다: $name")
            if (type != 0 && type != 2) throw OtpException("알 수 없는 OTP 종류입니다: $name")
            val alg = when (algorithm) {
                0, 1 -> Algorithm.SHA1
                2 -> Algorithm.SHA256
                3 -> Algorithm.SHA512
                else -> throw OtpException("지원하지 않는 알고리즘(MD5 등)입니다: $name")
            }
            val d = when (digits) {
                0, 1 -> 6
                2 -> 8
                else -> throw OtpException("지원하지 않는 자릿수입니다: $name")
            }
            val s = secret?.takeIf { it.isNotEmpty() && it.size <= Base32.MAX_SECRET_BYTES }
                ?: throw OtpException("비밀키가 올바르지 않습니다: $name")
            secret = null
            return ParsedAccount(displayName(name.trim(), issuer.trim()), s, alg, d, 30)
        } finally {
            secret?.fill(0)
        }
    }

    fun checkSupported(digits: Int, period: Int) {
        if (digits !in SUPPORTED_DIGITS) throw OtpException("6자리와 8자리만 지원합니다. (링크: ${digits}자리)")
        if (period !in SUPPORTED_PERIODS) throw OtpException("30초와 60초 주기만 지원합니다. (링크: ${period}초)")
    }

    /** "Issuer:account" like other apps; avoids repeating the issuer. */
    fun displayName(label: String, issuer: String): String {
        val colon = label.indexOf(':')
        return when {
            label.isEmpty() -> issuer
            colon >= 0 -> label.substring(0, colon).trim() + ":" + label.substring(colon + 1).trim()
            issuer.isNotEmpty() && label != issuer -> "$issuer:$label"
            else -> label
        }
    }

    private fun text(value: String, plusIsSpace: Boolean): String {
        val raw = percentDecode(value, plusIsSpace)
        val decoder = Charsets.UTF_8.newDecoder()
        return try {
            decoder.decode(java.nio.ByteBuffer.wrap(raw)).toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw OtpException("링크의 문자 인코딩이 올바르지 않습니다.")
        }
    }

    private fun hex(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    internal fun percentDecode(value: String, plusIsSpace: Boolean): ByteArray {
        val out = java.io.ByteArrayOutputStream(value.length)
        var i = 0
        while (i < value.length) {
            val c = value[i]
            when {
                c == '%' -> {
                    val hi = if (i + 1 < value.length) hex(value[i + 1]) else -1
                    val lo = if (i + 2 < value.length) hex(value[i + 2]) else -1
                    if (hi < 0 || lo < 0) throw OtpException("링크의 % 인코딩이 올바르지 않습니다.")
                    out.write(hi * 16 + lo)
                    i += 3
                }
                c == '+' && plusIsSpace -> { out.write(' '.code); i++ }
                c.code < 0x80 -> { out.write(c.code); i++ }
                else -> {
                    val bytes = c.toString().toByteArray(Charsets.UTF_8)
                    out.write(bytes, 0, bytes.size)
                    i++
                }
            }
        }
        return out.toByteArray()
    }

    /** Minimal protobuf reader for the fields used above. */
    private class Proto(private val b: ByteArray) {
        private var p = 0
        fun eof() = p >= b.size
        fun tag(): Pair<Int, Int> {
            val t = varint()
            return Pair((t ushr 3).toInt(), (t and 7).toInt())
        }
        fun varint(): Long {
            var shift = 0
            var result = 0L
            while (true) {
                if (p >= b.size || shift > 63) throw OtpException("내보내기 데이터가 손상되었습니다.")
                val x = b[p++].toInt() and 0xff
                result = result or ((x and 0x7f).toLong() shl shift)
                if (x and 0x80 == 0) return result
                shift += 7
            }
        }
        fun bytes(): ByteArray {
            val n = varint()
            if (n < 0 || n > b.size - p) throw OtpException("내보내기 데이터가 손상되었습니다.")
            val out = b.copyOfRange(p, p + n.toInt())
            p += n.toInt()
            return out
        }
        fun skip(wire: Int) {
            when (wire) {
                0 -> varint()
                1 -> p += 8
                2 -> bytes().fill(0)
                5 -> p += 4
                else -> throw OtpException("내보내기 데이터가 손상되었습니다.")
            }
            if (p > b.size) throw OtpException("내보내기 데이터가 손상되었습니다.")
        }
    }
}
