package dev.sidali.clipway

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * Reproduces docs/VECTORS.json, shared with relay/crypto.js and the Mac app.
 * The working directory of the tests is android/app.
 */
class CryptoTest {

    private val v = JSONObject(File("../../docs/VECTORS.json").readText())
    private val words: List<String> = File("src/main/res/raw/bip39_english.txt").readLines().filter { it.isNotBlank() }
    private val s get() = Crypto.fromHex(v.getString("S"))
    private val id get() = v.getString("id")

    private fun env(o: JSONObject) = Crypto.Envelope(o.getString("nonce"), o.getString("enc"))

    private fun refused(block: () -> Unit) {
        try {
            block()
            fail("accepted")
        } catch (e: Exception) {
            // expected
        }
    }

    @Test
    fun officialWordList() {
        assertEquals(2048, words.size)
        val digest = Crypto.hex(Crypto.sha256(File("src/main/res/raw/bip39_english.txt").readBytes()))
        assertEquals(v.getString("wordlist_sha256"), digest)
    }

    @Test
    fun proofChainIdAndKeys() {
        assertEquals(v.getString("P"), Crypto.hex(Crypto.proof(s)))
        assertEquals(id, Crypto.chainId(s))
        assertEquals(id, Crypto.idFromProof(Crypto.fromHex(v.getString("P"))))
        assertEquals(v.getString("K_enc"), Crypto.hex(Crypto.encKey(s)))
        assertEquals(v.getString("K_mac"), Crypto.hex(Crypto.macKey(s)))
        assertEquals(v.getString("subprotocol"), Crypto.subprotocols(s).joinToString(", "))
    }

    @Test
    fun wordsAndQrCode() {
        val expected = v.getJSONArray("words").let { a -> List(a.length()) { a.getString(it) } }
        assertEquals(expected, Crypto.toWords(s, words))
        assertArrayEquals(s, Crypto.fromWords(expected.joinToString("  ").uppercase(), words))
        refused { Crypto.fromWords(expected.drop(1).joinToString(" "), words) }
        refused { Crypto.fromWords((listOf(expected[1], expected[0]) + expected.drop(2)).joinToString(" "), words) }

        val def = "https://clip.sidali.dev"
        assertEquals(v.getString("qr"), Crypto.toQr(s, def, def))
        val withRelay = v.getJSONObject("qr_with_relay")
        assertEquals(withRelay.getString("text"), Crypto.toQr(s, withRelay.getString("relay"), def))
        val bare = Crypto.fromQr(v.getString("qr"))
        assertArrayEquals(s, bare.secret)
        assertNull(bare.relay)
        assertEquals(withRelay.getString("relay"), Crypto.fromQr(withRelay.getString("text")).relay)
        refused { Crypto.fromQr("https://example.com/#s=AAECAwQFBgcICQoLDA0ODw") }
        refused { Crypto.fromQr("clipway:AAECAwQFBgcICQoLDA0O") }
    }

    @Test
    fun fingerprintAndEnvelope() {
        val f = v.getJSONObject("fingerprint")
        assertEquals(f.getString("fp"), Crypto.fingerprint(Crypto.macKey(s), f.getString("content_utf8").toByteArray(Charsets.UTF_8)))
        val e = v.getJSONObject("envelope")
        val sealed = Crypto.seal(Crypto.encKey(s), e.getString("aad"), e.getString("plaintext_utf8").toByteArray(Charsets.UTF_8), Crypto.fromHex(e.getString("nonce")))
        assertEquals(env(e.getJSONObject("envelope")), sealed)
        assertEquals(e.getString("plaintext_utf8"), String(Crypto.open(Crypto.encKey(s), e.getString("aad"), sealed), Charsets.UTF_8))
        val neg = v.getJSONObject("negative")
        refused { Crypto.open(Crypto.encKey(s), id, env(neg.getJSONObject("tampered_envelope"))) }
        refused { Crypto.open(Crypto.encKey(s), neg.getString("wrong_aad"), env(v.getJSONObject("text_item").getJSONObject("envelope"))) }
    }

    private val items = listOf("text_item", "hello_item", "offer_item", "offer_file_item", "reply_item")

    @Test
    fun padding() {
        val p = v.getJSONObject("padding")
        assertEquals(p.getString("padded"), Crypto.padHead(p.getString("unpadded")))
        for (name in items) {
            assertEquals(name, 0, v.getJSONObject(name).getString("plaintext").toByteArray(Charsets.UTF_8).size % Crypto.PAD_BLOCK)
        }
    }

    @Test
    fun limits() {
        val l = v.getJSONObject("limits")
        assertEquals(l.getInt("text"), Crypto.TEXT_MAX)
        assertEquals(l.getInt("head"), Crypto.HEAD_MAX)
        assertEquals(l.getInt("file"), Crypto.FILE_MAX)
    }

    @Test
    fun itemsSealAndOpen() {
        for (name in items) {
            val item = v.getJSONObject(name)
            val e = env(item.getJSONObject("envelope"))
            val plaintext = item.getString("plaintext")
            assertEquals(name, e, Crypto.seal(Crypto.encKey(s), id, plaintext.toByteArray(Charsets.UTF_8), Crypto.fromHex(e.nonce)))
            assertEquals(name, plaintext, String(Crypto.open(Crypto.encKey(s), id, e), Charsets.UTF_8))
        }
        // The inline text decodes to the fingerprinted content.
        val head = JSONObject(v.getJSONObject("text_item").getString("plaintext"))
        val content = Base64.getDecoder().decode(head.getString("data"))
        assertEquals(v.getJSONObject("fingerprint").getString("content_utf8"), String(content, Charsets.UTF_8))
        assertEquals(head.getString("fp"), Crypto.fingerprint(Crypto.macKey(s), content))
        assertEquals(head.getInt("size"), content.size)
    }

    @Test
    fun directKey() {
        assertEquals(v.getJSONObject("direct").getString("K_direct"), Crypto.hex(Crypto.directKey(s)))
    }

    @Test
    fun randomSecretsRoundTrip() {
        repeat(50) {
            val r = Crypto.generateSecret()
            assertArrayEquals(r, Crypto.fromWords(Crypto.toWords(r, words).joinToString(" "), words))
            assertArrayEquals(r, Crypto.fromQr(Crypto.toQr(r, "https://clip.sidali.dev", "https://clip.sidali.dev")).secret)
        }
        assertTrue(Crypto.fromQr("clipway:AAECAwQFBgcICQoLDA0ODw==").secret.size == Crypto.SECRET_SIZE)
    }
}
