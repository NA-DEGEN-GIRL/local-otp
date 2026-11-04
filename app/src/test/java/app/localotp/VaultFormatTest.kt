package app.localotp

import app.localotp.otp.Algorithm
import app.localotp.otp.OtpException
import app.localotp.vault.Account
import app.localotp.vault.EntryCodec
import app.localotp.vault.VaultFile
import app.localotp.vault.VaultHeader
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultFormatTest {
    private fun header() = VaultHeader(
        VaultFile.ITERATIONS,
        ByteArray(32) { 1 },
        ByteArray(16) { 2 },
        ByteArray(12) { 3 },
        ByteArray(48) { 4 },
    )

    @Test
    fun entryCodecRoundTripAndTruncation() {
        val accounts = listOf(
            Account("test", byteArrayOf(1, 2, 3), Algorithm.SHA1, 6, 30),
            Account("두번째", ByteArray(20) { 9 }, Algorithm.SHA512, 8, 60),
        )
        val data = EntryCodec.serialize(accounts)
        val back = EntryCodec.deserialize(data)
        assertEquals(listOf("test", "두번째"), back.map { it.name })
        assertArrayEquals(byteArrayOf(1, 2, 3), back[0].secret)
        assertEquals(Triple(Algorithm.SHA512, 8, 60), Triple(back[1].algorithm, back[1].digits, back[1].period))
        for (n in 0 until data.size) {
            assertThrows(OtpException::class.java) { EntryCodec.deserialize(data.copyOf(n)) }
        }
        assertTrue(EntryCodec.deserialize(EntryCodec.serialize(emptyList())).isEmpty())
        assertThrows(OtpException::class.java) {
            EntryCodec.serialize(listOf(Account("x", byteArrayOf(1), Algorithm.SHA1, 7, 30)))
        }
    }

    @Test
    fun sealOpenAndTamper() {
        val key = ByteArray(32) { it.toByte() }
        val plain = EntryCodec.serialize(listOf(Account("a", byteArrayOf(5), Algorithm.SHA1, 6, 30)))
        val blob = VaultFile.seal(header(), key, plain)
        assertArrayEquals(plain, VaultFile.open(blob, key))
        val again = VaultFile.seal(header(), key, plain)
        assertNotEquals(blob.copyOfRange(120, 132).toList(), again.copyOfRange(120, 132).toList())
        val h = VaultFile.readHeader(blob)
        assertArrayEquals(header().salt, h.salt)
        assertArrayEquals(header().wrapped, h.wrapped)
        assertArrayEquals(blob.copyOfRange(0, 60), h.wrapAad())
        // Wrong key, any flipped byte (header, wrapped key, nonce, data, tag) fails.
        assertThrows(OtpException::class.java) { VaultFile.open(blob, ByteArray(32)) }
        for (i in listOf(9, 20, 50, 70, 100, 125, blob.size - 20, blob.size - 1)) {
            val bad = blob.copyOf()
            bad[i] = (bad[i].toInt() xor 1).toByte()
            assertThrows("byte $i", OtpException::class.java) { VaultFile.open(bad, key) }
        }
        assertThrows(OtpException::class.java) { VaultFile.open(blob.copyOf(blob.size - 1), key) }
    }

    @Test
    fun passwordKeyIsStableAndProviderIndependent() {
        // Known answer computed independently (Python hashlib): PBKDF2-SHA256
        // over the hex of the UTF-8 password, 100,000 iterations.
        val salt = ByteArray(32) { it.toByte() }
        val key = VaultFile.derivePassword("한글 password 123".toCharArray(), salt, 100_000)
        assertEquals(
            "1a5272cfa750c2558cad9c3518ddc22ae5d93316d6bd497af0be7016a1e52cb3",
            key.joinToString("") { "%02x".format(it) },
        )
        val other = VaultFile.derivePassword("한글 password 124".toCharArray(), salt, 100_000)
        assertFalse(VaultFile.sameKey(key, other))
        assertTrue(VaultFile.sameKey(key, key.copyOf()))
        val s = ByteArray(32) { 0x55 }
        assertArrayEquals(key, VaultFile.combine(VaultFile.combine(key, s), s))
    }
}
