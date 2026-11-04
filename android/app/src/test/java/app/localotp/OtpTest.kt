package app.localotp

import app.localotp.otp.Algorithm
import app.localotp.otp.Base32
import app.localotp.otp.Links
import app.localotp.otp.OtpException
import app.localotp.otp.Totp
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class OtpTest {
    @Test
    fun base32() {
        mapOf(
            "MY======" to "f", "MZXQ====" to "fo", "MZXW6===" to "foo", "MZXW6YQ=" to "foob",
            "mzxw6ytb" to "fooba", "MZXW-6YTB OI======" to "foobar", "MZ" to "f",
        ).forEach { (encoded, plain) -> assertArrayEquals(encoded, plain.toByteArray(), Base32.decode(encoded)) }
        listOf("", "A", "MZX", "MZXW6Y", "MY=", "M=Y", "MZXW6!", "MZ0W6", "========").forEach {
            assertThrows(it, OtpException::class.java) { Base32.decode(it) }
        }
        assertEquals(4096, Base32.decode("A".repeat(6554)).size)
        assertThrows(OtpException::class.java) { Base32.decode("A".repeat(6555)) }
    }

    @Test
    fun rfc6238() {
        val k1 = "12345678901234567890".toByteArray()
        val k256 = "12345678901234567890123456789012".toByteArray()
        val k512 = "1234567890123456789012345678901234567890123456789012345678901234".toByteArray()
        listOf(
            arrayOf<Any>(59L, "94287082", "46119246", "90693936"),
            arrayOf<Any>(1111111109L, "07081804", "68084774", "25091201"),
            arrayOf<Any>(1111111111L, "14050471", "67062674", "99943326"),
            arrayOf<Any>(1234567890L, "89005924", "91819424", "93441116"),
            arrayOf<Any>(2000000000L, "69279037", "90698825", "38618901"),
            arrayOf<Any>(20000000000L, "65353130", "77737706", "47863826"),
        ).forEach { (t, a, b, c) ->
            val time = t as Long
            assertEquals(a, Totp.code(k1, time, 30, 8, Algorithm.SHA1))
            assertEquals(b, Totp.code(k256, time, 30, 8, Algorithm.SHA256))
            assertEquals(c, Totp.code(k512, time, 30, 8, Algorithm.SHA512))
            assertEquals((a as String).substring(2), Totp.code(k1, time, 30, 6, Algorithm.SHA1))
        }
        assertEquals("123 456", Totp.group("123456"))
        assertEquals("1234 5678", Totp.group("12345678"))
        assertEquals(30, Totp.remaining(60, 30))
        assertEquals(1, Totp.remaining(59, 30))
    }

    @Test
    fun otpauthLinks() {
        val a = Links.parse("otpauth://totp/Example:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example").single()
        assertEquals("Example:alice@google.com", a.name)
        assertArrayEquals(byteArrayOf(72, 101, 108, 108, 111, 33, -34, -83, -66, -17), a.secret)
        assertEquals(Triple(Algorithm.SHA1, 6, 30), Triple(a.algorithm, a.digits, a.period))
        val b = Links.parse("OTPAUTH://TOTP/alice?issuer=My+Org&secret=jbswy3dpehpk3pxp&algorithm=SHA256&digits=8&period=60").single()
        assertEquals("My Org:alice", b.name)
        assertEquals(Triple(Algorithm.SHA256, 8, 60), Triple(b.algorithm, b.digits, b.period))
        listOf(
            "https://example.com/?secret=MZXW6",
            "otpauth://hotp/x?secret=MZXW6&counter=1",
            "otpauth://totp/x?issuer=a",
            "otpauth://totp/x%zz?secret=MZXW6",
            "otpauth://totp/x?secret=MZ%+9XW6",
            "otpauth://totp/x?secret=MZXW6&algorithm=MD5",
            "otpauth://totp/x?secret=MZXW6&digits=7",
            "otpauth://totp/x?secret=MZXW6&period=15",
            "otpauth://totp/x?secret=MZXW6&encoder=steam",
        ).forEach { assertThrows(it, OtpException::class.java) { Links.parse(it) } }
    }

    private fun field(out: ByteArrayOutputStream, number: Int, bytes: ByteArray) {
        out.write(number shl 3 or 2)
        out.write(bytes.size)
        out.write(bytes)
    }

    private fun varint(out: ByteArrayOutputStream, number: Int, value: Int) {
        out.write(number shl 3)
        out.write(value)
    }

    private fun item(secret: ByteArray, name: String, issuer: String, algorithm: Int, digits: Int, type: Int): ByteArray {
        val out = ByteArrayOutputStream()
        field(out, 1, secret)
        field(out, 2, name.toByteArray())
        field(out, 3, issuer.toByteArray())
        varint(out, 4, algorithm)
        varint(out, 5, digits)
        varint(out, 6, type)
        return out.toByteArray()
    }

    private fun migration(vararg items: ByteArray): String {
        val out = ByteArrayOutputStream()
        items.forEach { field(out, 1, it) }
        varint(out, 2, 1) // version
        val data = URLEncoder.encode(Base64.getEncoder().encodeToString(out.toByteArray()), "UTF-8")
        return "otpauth-migration://offline?data=$data"
    }

    @Test
    fun googleExportLinks() {
        val accounts = Links.parse(
            migration(
                item("Hello!".toByteArray(), "alice@example.com", "Example", 1, 1, 2),
                item(ByteArray(20) { it.toByte() }, "Bank:bob", "", 2, 2, 2),
            ),
        )
        assertEquals(2, accounts.size)
        assertEquals("Example:alice@example.com", accounts[0].name)
        assertArrayEquals("Hello!".toByteArray(), accounts[0].secret)
        assertEquals(Triple(Algorithm.SHA1, 6, 30), Triple(accounts[0].algorithm, accounts[0].digits, accounts[0].period))
        assertEquals("Bank:bob", accounts[1].name)
        assertEquals(Triple(Algorithm.SHA256, 8, 30), Triple(accounts[1].algorithm, accounts[1].digits, accounts[1].period))
        // HOTP and MD5 entries are refused rather than producing wrong codes.
        assertThrows(OtpException::class.java) { Links.parse(migration(item(byteArrayOf(1), "h", "", 1, 1, 1))) }
        assertThrows(OtpException::class.java) { Links.parse(migration(item(byteArrayOf(1), "m", "", 4, 1, 2))) }
        assertThrows(OtpException::class.java) { Links.parse("otpauth-migration://offline?data=%%%") }
        assertThrows(OtpException::class.java) { Links.parse("otpauth-migration://offline?data=CgM=") }
    }
}
