package dev.sidali.clipway

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.UUID

/**
 * Nearby pairing (docs/PROTOCOL.md, section 13) against the `nearby` block of docs/VECTORS.json,
 * shared with relay/nearby.js and the Mac app. java.security XDH on the JVM is the same API as on
 * Android 13 and later. The working directory of the tests is android/app.
 */
class NearbyTest {

    private val v = JSONObject(File("../../docs/VECTORS.json").readText())
    private val n = v.getJSONObject("nearby")
    private fun h(key: String, o: JSONObject = n) = Crypto.fromHex(o.getString(key))

    private val mac = Nearby.keyPairFromRaw(h("mac_private"))
    private val phone = Nearby.keyPairFromRaw(h("phone_private"))
    private val pkMac = h("mac_public")
    private val pkPhone = h("phone_public")

    private fun refused(block: () -> Unit) {
        try {
            block()
            fail("accepted")
        } catch (e: Exception) {
            // expected
        }
    }

    private fun machine(keys: Nearby.KeyPair = phone) = NearbyPhone(keys) { Nearby.sharedSecret(keys.privateKey, it) }

    private val chars: Map<String, UUID> by lazy {
        val c = n.getJSONObject("characteristics")
        c.keys().asSequence().associateWith { UUID.fromString(c.getString(it)) }
    }

    @Test
    fun serviceAndConstants() {
        assertEquals(UUID.fromString(n.getString("service")), Nearby.SERVICE)
        assertEquals(chars["commit"], Nearby.COMMIT)
        assertEquals(chars["phone_key"], Nearby.PHONE_KEY)
        assertEquals(chars["mac_key"], Nearby.MAC_KEY)
        assertEquals(chars["confirm"], Nearby.CONFIRM)
        assertEquals(chars["status"], Nearby.STATUS)
        assertEquals(chars["packet"], Nearby.PACKET)
        assertEquals(6, Nearby.CHARACTERISTICS.toSet().size)
        assertEquals(UUID.fromString(n.getString("cccd")), Nearby.CCCD)
        val s = n.getJSONObject("status")
        assertEquals(s.getInt("waiting"), Nearby.WAITING)
        assertEquals(s.getInt("ready"), Nearby.READY)
        assertEquals(s.getInt("canceled"), Nearby.CANCELED)
        assertEquals(s.getInt("expired"), Nearby.EXPIRED)
        assertEquals(s.getInt("failed"), Nearby.FAILED)
        assertEquals(s.getInt("busy"), Nearby.BUSY)
        assertEquals(n.getInt("max_code_length"), Nearby.MAX_CODE_LENGTH)
        assertEquals(284, Nearby.PACKET_SIZE)
        assertTrue(Nearby.retryable(133) && Nearby.retryable(62) && Nearby.retryable(8))
        assertFalse(Nearby.retryable(0) || Nearby.retryable(19))
    }

    @Test
    fun keysFromTheRfc() {
        assertArrayEquals(pkMac, mac.publicKey)
        assertArrayEquals(pkPhone, phone.publicKey)
        // The raw key is the last 32 bytes of the X.509 encoding, after the documented prefix.
        val prefixes = n.getJSONObject("der_prefixes")
        val fresh = Nearby.generateKeyPair()
        val encoded = java.security.KeyFactory.getInstance("XDH")
            .generatePublic(java.security.spec.X509EncodedKeySpec(Crypto.fromHex(prefixes.getString("x509_public")) + fresh.publicKey)).encoded
        assertEquals(prefixes.getString("x509_public"), Crypto.hex(encoded.copyOf(12)))
        assertArrayEquals(fresh.publicKey, Nearby.rawPublic(encoded))
        // Anything but the X25519 X.509 encoding is refused (another curve, a raw key, a wrong prefix).
        refused { Nearby.rawPublic(fresh.publicKey) }
        refused { Nearby.rawPublic(encoded.copyOf(43)) }
        refused { Nearby.rawPublic(encoded.copyOf().also { it[8] = 0x71 }) }
        assertEquals(prefixes.getString("pkcs8_private"), Crypto.hex(fresh.privateKey.encoded.copyOf(16)))
        // Two fresh pairs agree on the same Z.
        val other = Nearby.generateKeyPair()
        assertArrayEquals(
            Nearby.sharedSecret(fresh.privateKey, other.publicKey),
            Nearby.sharedSecret(other.privateKey, fresh.publicKey),
        )
        assertFalse(Crypto.same(fresh.publicKey, other.publicKey))
    }

    @Test
    fun derivations() {
        assertArrayEquals(h("shared"), Nearby.sharedSecret(phone.privateKey, pkMac))
        assertArrayEquals(h("shared"), Nearby.sharedSecret(mac.privateKey, pkPhone))
        assertArrayEquals(h("commit"), Nearby.commitment(pkMac))
        assertArrayEquals(h("transcript"), Nearby.transcript(pkMac, pkPhone))
        val k = Nearby.derive(h("shared"), pkMac, pkPhone)
        assertArrayEquals(h("N"), k.n)
        assertArrayEquals(h("K_sas"), k.sas)
        assertArrayEquals(h("K_key"), k.key)
        assertArrayEquals(h("sas_bytes"), Nearby.sasBytes(k.sas, pkMac, pkPhone))
        assertEquals(n.getLong("sas_integer") % 10_000, Nearby.code(k.sas, pkMac, pkPhone).toLong())
        assertEquals(n.getString("sas"), Nearby.code(k.sas, pkMac, pkPhone))
        assertEquals("5456", Nearby.code(k.sas, pkMac, pkPhone))
        assertArrayEquals(h("confirm"), Nearby.confirmTag(k.sas, pkMac, pkPhone))
        assertEquals(n.getString("aad"), Nearby.aad(pkMac, pkPhone))
        assertEquals(144, Nearby.aad(pkMac, pkPhone).toByteArray(Charsets.UTF_8).size)
    }

    @Test
    fun leadingZero() {
        val lz = n.getJSONObject("leading_zero")
        val p = Nearby.keyPairFromRaw(h("phone_private", lz))
        assertArrayEquals(h("phone_public", lz), p.publicKey)
        val z = Nearby.sharedSecret(p.privateKey, pkMac)
        assertArrayEquals(h("shared", lz), z)
        val k = Nearby.derive(z, pkMac, p.publicKey)
        assertArrayEquals(h("K_sas", lz), k.sas)
        assertArrayEquals(h("K_key", lz), k.key)
        assertArrayEquals(h("sas_bytes", lz), Nearby.sasBytes(k.sas, pkMac, p.publicKey))
        assertEquals("0195", Nearby.code(k.sas, pkMac, p.publicKey))
        assertEquals(lz.getString("sas"), Nearby.code(k.sas, pkMac, p.publicKey))
        assertArrayEquals(h("confirm", lz), Nearby.confirmTag(k.sas, pkMac, p.publicKey))
    }

    @Test
    fun codeSamples() {
        val samples = n.getJSONArray("sas_samples")
        for (i in 0 until samples.length()) {
            val s = samples.getJSONObject(i)
            assertEquals(s.getString("bytes"), s.getString("sas"), Nearby.sasFromBytes(h("bytes", s)))
            assertEquals(4, Nearby.sasFromBytes(h("bytes", s)).length)
        }
    }

    @Test
    fun packets() {
        val kKey = h("K_key")
        for (name in listOf("packet", "packet_with_relay")) {
            val p = n.getJSONObject(name)
            val code = p.getString("code")
            assertEquals(name, p.getString("plaintext"), Nearby.packetPlaintext(code))
            assertEquals(name, p.getInt("plaintext_bytes"), Nearby.packetPlaintext(code).toByteArray(Charsets.UTF_8).size)
            // Sealed again with the fixed nonce: the same 284 bytes.
            val bytes = h("bytes", p)
            assertEquals(Nearby.PACKET_SIZE, bytes.size)
            assertArrayEquals(name, bytes, Nearby.sealPacket(kKey, pkMac, pkPhone, code, h("nonce", p)))
            // Opened: the code, then read like a scanned one.
            val opened = Nearby.openPacket(kKey, pkMac, pkPhone, bytes)
            assertEquals(code, opened)
            val pairing = Crypto.fromQr(opened)
            val expect = p.getJSONObject("opened")
            assertArrayEquals(h("secret", expect), pairing.secret)
            assertArrayEquals(h("S", v), pairing.secret)
            if (expect.isNull("relay")) assertNull(pairing.relay) else assertEquals(expect.getString("relay"), pairing.relay)
        }
        // The pairing code of the top-level vectors, as the Mac builds it.
        assertEquals(n.getJSONObject("packet").getString("code"), Crypto.toQr(h("S", v), "https://clip.sidali.dev", "https://clip.sidali.dev"))
        // A code longer than 230 characters does not fit.
        val long = "clipway:AAECAwQFBgcICQoLDA0ODw?relay=https%3A%2F%2F" + "a".repeat(Nearby.MAX_CODE_LENGTH)
        refused { Nearby.packetPlaintext(long) }
        val fits = "clipway:" + "A".repeat(Nearby.MAX_CODE_LENGTH - 8)
        assertEquals(256, Nearby.packetPlaintext(fits).toByteArray(Charsets.UTF_8).size)
        refused { Nearby.packetPlaintext(fits + "A") }
    }

    @Test
    fun negativeCases() {
        val neg = n.getJSONObject("negative")
        val low = neg.getJSONObject("low_order_keys").getJSONArray("keys")
        for (i in 0 until low.length()) {
            val key = Crypto.fromHex(low.getString(i))
            refused { Nearby.checkPeerKey(key, phone.publicKey); Nearby.sharedSecret(phone.privateKey, key) }
        }
        refused { Nearby.checkPeerKey(h("key", neg.getJSONObject("high_bit_key")), mac.publicKey) }
        refused { Nearby.checkPeerKey(h("key", neg.getJSONObject("own_key")), mac.publicKey) }
        refused { Nearby.checkPeerKey(phone.publicKey, phone.publicKey) }
        refused { Nearby.checkPeerKey(pkMac.copyOf(31), phone.publicKey) }
        Nearby.checkPeerKey(pkMac, phone.publicKey)

        val wc = neg.getJSONObject("wrong_commitment")
        assertFalse(Crypto.same(h("commit", wc), Nearby.commitment(h("mac_public", wc))))

        val k = Nearby.derive(h("shared"), pkMac, pkPhone)
        assertFalse(Crypto.same(h("confirm", neg.getJSONObject("wrong_confirm")), Nearby.confirmTag(k.sas, pkMac, pkPhone)))

        refused { Nearby.openPacket(k.key, pkMac, pkPhone, h("bytes", neg.getJSONObject("tampered_packet"))) }
        val good = h("bytes", n.getJSONObject("packet"))
        val swapped = neg.getJSONObject("swapped_aad").getString("aad")
        assertEquals(Nearby.aad(pkPhone, pkMac), swapped)
        refused { Nearby.openPacket(k.key, pkPhone, pkMac, good) }
        refused { Nearby.openPacket(k.key, pkMac, pkPhone, good.copyOf(neg.getJSONObject("short_packet").getInt("length"))) }
        refused { Nearby.openPacket(k.key, pkMac, pkPhone, good + 0) }
        refused { Nearby.openPacket(h("K_sas"), pkMac, pkPhone, good) }
    }

    // ---------------------------------------------------------------------
    // The phone's side of the exchange
    // ---------------------------------------------------------------------

    /**
     * Replays a session of the vectors through [NearbyPhone]: each request the phone makes must be
     * the next one of the session, it writes exactly the session's values, shows the code the Mac
     * shows, and opens the packet it reads. Status reads in the session are answered too (the phone
     * may skip them), and Read Blob continuations are the Bluetooth stack's, not the app's.
     */
    private fun replay(name: String): NearbyPhone {
        val session = (0 until n.getJSONArray("sessions").length()).map { n.getJSONArray("sessions").getJSONObject(it) }
            .first { it.getString("name") == name }
        val m = machine()
        var op: NearbyPhone.Op? = m.start()
        fun notify(step: JSONObject) {
            val list = step.optJSONArray("notify") ?: return
            for (i in 0 until list.length()) m.status(Crypto.fromHex(list.getString(i)))?.let { assertNull("one request at a time", op); op = it }
        }
        val steps = session.getJSONArray("steps")
        for (i in 0 until steps.length()) {
            val st = steps.getJSONObject(i)
            val label = "$name, step $i"
            if (st.getString("by") == "phone") {
                val char = if (st.has("char")) chars.getValue(st.getString("char")) else null
                when (st.getString("op")) {
                    "subscribe" -> {
                        assertEquals(label, NearbyPhone.Op.Subscribe, op)
                        op = m.subscribed()
                    }
                    "read" -> {
                        if (st.optInt("offset", 0) > 0) continue
                        val value = Crypto.fromHex(st.getJSONObject("expect").getString("value"))
                        val o = op
                        if (o is NearbyPhone.Op.Read && o.char == char) {
                            op = m.read(char, value)
                        } else {
                            assertEquals(label, Nearby.STATUS, char)
                            assertNull(label, m.status(value))
                        }
                    }
                    "write" -> {
                        // The person presses Pair before the phone writes Confirm.
                        if (char == Nearby.CONFIRM && op == null) {
                            assertEquals(label, NearbyPhone.Phase.Code, m.phase)
                            op = m.pair()
                        }
                        val o = op
                        assertTrue(label, o is NearbyPhone.Op.Write && o.char == char)
                        assertEquals(label, st.getString("value"), Crypto.hex((o as NearbyPhone.Op.Write).value))
                        assertTrue(label, st.getJSONObject("expect").optBoolean("ok"))
                        op = m.written(char!!)
                    }
                    "unsubscribe" -> assertEquals(label, NearbyPhone.Op.Leave, op)
                    else -> fail("$label: unexpected ${st.getString("op")}")
                }
            }
            notify(st)
            if (st.has("mac_shows") && m.code != null) assertEquals(label, st.getString("mac_shows"), m.code)
        }
        assertEquals(name, NearbyPhone.Op.Leave, op)
        return m
    }

    @Test
    fun successSessions() {
        for (name in listOf("success, phone confirms first", "success, Mac confirms first, long read")) {
            val m = replay(name)
            assertEquals(name, "5456", m.code)
            val out = m.outcome
            assertTrue(name, out is NearbyPhone.Outcome.Paired)
            val code = (out as NearbyPhone.Outcome.Paired).code
            assertEquals(n.getJSONObject("packet").getString("code"), code)
            assertArrayEquals(h("S", v), Crypto.fromQr(code).secret)
        }
    }

    /** Drives a machine up to the code on screen, as a Mac answering correctly would. */
    private fun toCode(m: NearbyPhone = machine()): NearbyPhone {
        assertEquals(NearbyPhone.Op.Subscribe, m.start())
        assertEquals(NearbyPhone.Op.Read(Nearby.COMMIT), m.subscribed())
        val w = m.read(Nearby.COMMIT, h("commit")) as NearbyPhone.Op.Write
        assertEquals(Nearby.PHONE_KEY, w.char)
        assertArrayEquals(pkPhone, w.value)
        assertEquals(NearbyPhone.Op.Read(Nearby.MAC_KEY), m.written(Nearby.PHONE_KEY))
        assertNull(m.read(Nearby.MAC_KEY, pkMac))
        assertEquals(NearbyPhone.Phase.Code, m.phase)
        assertEquals("5456", m.code)
        return m
    }

    @Test
    fun finalStatusesEndTheAttempt() {
        val cases = mapOf(
            Nearby.CANCELED to NearbyPhone.Outcome.Canceled,
            Nearby.EXPIRED to NearbyPhone.Outcome.Expired,
            Nearby.FAILED to NearbyPhone.Outcome.Failed,
            Nearby.BUSY to NearbyPhone.Outcome.Busy,
        )
        for ((status, outcome) in cases) {
            // While the code is shown, and after Pair on the phone.
            val a = toCode()
            assertEquals(NearbyPhone.Op.Leave, a.status(byteArrayOf(status.toByte())))
            assertEquals(outcome, a.outcome)
            val b = toCode()
            assertNotNull(b.pair())
            assertNull(b.written(Nearby.CONFIRM))
            assertEquals(NearbyPhone.Op.Leave, b.status(byteArrayOf(status.toByte())))
            assertEquals(outcome, b.outcome)
            assertNull(b.pair())
            assertNull(b.status(byteArrayOf(Nearby.READY.toByte())))
        }
        // Waiting changes nothing; an unknown value ends the attempt.
        val w = toCode()
        assertNull(w.status(byteArrayOf(Nearby.WAITING.toByte())))
        assertEquals(NearbyPhone.Phase.Code, w.phase)
        assertEquals(NearbyPhone.Op.Leave, w.status(byteArrayOf(9)))
        assertEquals(NearbyPhone.Outcome.Failed, w.outcome)
    }

    @Test
    fun readyBeforeTheConfirmAnswer() {
        val m = toCode()
        assertTrue(m.pair() is NearbyPhone.Op.Write)
        // Ready notified before the answer to Confirm arrives: the packet is asked once.
        assertEquals(NearbyPhone.Op.Read(Nearby.PACKET), m.status(byteArrayOf(Nearby.READY.toByte())))
        assertNull(m.written(Nearby.CONFIRM))
        assertNull(m.status(byteArrayOf(Nearby.READY.toByte())))
        assertEquals(NearbyPhone.Op.Leave, m.read(Nearby.PACKET, h("bytes", n.getJSONObject("packet"))))
        assertTrue(m.outcome is NearbyPhone.Outcome.Paired)
    }

    @Test
    fun readyBeforePairOnThePhoneWaitsForPair() {
        val m = toCode()
        assertNull(m.status(byteArrayOf(Nearby.READY.toByte())))
        assertEquals(NearbyPhone.Phase.Code, m.phase)
        assertTrue(m.pair() is NearbyPhone.Op.Write)
        assertEquals(NearbyPhone.Op.Read(Nearby.PACKET), m.written(Nearby.CONFIRM))
    }

    @Test
    fun refusedExchanges() {
        val neg = n.getJSONObject("negative")
        // A Mac key that does not match the commitment read first.
        val wc = neg.getJSONObject("wrong_commitment")
        val a = machine()
        a.start(); a.subscribed()
        a.read(Nearby.COMMIT, h("commit", wc))
        a.written(Nearby.PHONE_KEY)
        assertEquals(NearbyPhone.Op.Leave, a.read(Nearby.MAC_KEY, h("mac_public", wc)))
        assertEquals(NearbyPhone.Outcome.Failed, a.outcome)
        assertNull(a.code)

        // Low-order Mac keys, even with a matching commitment.
        val low = neg.getJSONObject("low_order_keys").getJSONArray("keys")
        for (i in 0 until low.length()) {
            val key = Crypto.fromHex(low.getString(i))
            val m = machine()
            m.start(); m.subscribed()
            m.read(Nearby.COMMIT, Nearby.commitment(key))
            m.written(Nearby.PHONE_KEY)
            assertEquals(NearbyPhone.Op.Leave, m.read(Nearby.MAC_KEY, key))
            assertEquals(NearbyPhone.Outcome.Failed, m.outcome)
        }

        // The Mac sending the phone's own key back, and a key with the top bit set.
        for (key in listOf(pkPhone, h("key", neg.getJSONObject("high_bit_key")))) {
            val m = machine()
            m.start(); m.subscribed()
            m.read(Nearby.COMMIT, Nearby.commitment(key))
            m.written(Nearby.PHONE_KEY)
            assertEquals(NearbyPhone.Op.Leave, m.read(Nearby.MAC_KEY, key))
            assertEquals(NearbyPhone.Outcome.Failed, m.outcome)
        }

        // A short commitment.
        val s = machine()
        s.start(); s.subscribed()
        assertEquals(NearbyPhone.Op.Leave, s.read(Nearby.COMMIT, h("commit").copyOf(31)))

        // A tampered packet.
        val t = toCode()
        t.pair(); t.written(Nearby.CONFIRM)
        assertEquals(NearbyPhone.Op.Read(Nearby.PACKET), t.status(byteArrayOf(Nearby.READY.toByte())))
        assertEquals(NearbyPhone.Op.Leave, t.read(Nearby.PACKET, h("bytes", neg.getJSONObject("tampered_packet"))))
        assertEquals(NearbyPhone.Outcome.Failed, t.outcome)
    }

    @Test
    fun anotherPhoneTookTheAttempt() {
        // The Mac refuses the key (0x03): the phone reads Status to tell busy from a failure.
        val busy = machine()
        busy.start(); busy.subscribed(); busy.read(Nearby.COMMIT, h("commit"))
        assertEquals(NearbyPhone.Op.Read(Nearby.STATUS), busy.error(Nearby.PHONE_KEY))
        assertEquals(NearbyPhone.Op.Leave, busy.read(Nearby.STATUS, byteArrayOf(Nearby.BUSY.toByte())))
        assertEquals(NearbyPhone.Outcome.Busy, busy.outcome)

        val other = machine()
        other.start(); other.subscribed(); other.read(Nearby.COMMIT, h("commit"))
        other.error(Nearby.PHONE_KEY)
        assertEquals(NearbyPhone.Op.Leave, other.read(Nearby.STATUS, byteArrayOf(Nearby.WAITING.toByte())))
        assertEquals(NearbyPhone.Outcome.Failed, other.outcome)

        // Any other refused request ends the attempt.
        val m = toCode()
        m.pair()
        assertEquals(NearbyPhone.Op.Leave, m.error(Nearby.CONFIRM))
        assertEquals(NearbyPhone.Outcome.Failed, m.outcome)
    }

    @Test
    fun cancelFromThePhoneForgetsTheKeys() {
        val m = toCode()
        assertEquals(NearbyPhone.Op.Leave, m.end(NearbyPhone.Outcome.Canceled))
        assertEquals(NearbyPhone.Outcome.Canceled, m.outcome)
        assertNull(m.pair())
        assertNull(m.read(Nearby.PACKET, h("bytes", n.getJSONObject("packet"))))
        // A later end keeps the first outcome.
        m.end(NearbyPhone.Outcome.Failed)
        assertEquals(NearbyPhone.Outcome.Canceled, m.outcome)
    }

    @Test
    fun freshKeysEveryAttempt() {
        val a = Nearby.generateKeyPair()
        val b = Nearby.generateKeyPair()
        assertFalse(Crypto.same(a.publicKey, b.publicKey))
        assertEquals(0, a.publicKey[31].toInt() and 0x80)
        // A full exchange with fresh keys on both sides gives the same code.
        val m = machine(b)
        m.start(); m.subscribed()
        m.read(Nearby.COMMIT, Nearby.commitment(a.publicKey))
        m.written(Nearby.PHONE_KEY)
        assertNull(m.read(Nearby.MAC_KEY, a.publicKey))
        val k = Nearby.derive(Nearby.sharedSecret(a.privateKey, b.publicKey), a.publicKey, b.publicKey)
        assertEquals(Nearby.code(k.sas, a.publicKey, b.publicKey), m.code)
        val confirm = m.pair() as NearbyPhone.Op.Write
        assertArrayEquals(Nearby.confirmTag(k.sas, a.publicKey, b.publicKey), confirm.value)
        m.written(Nearby.CONFIRM)
        m.status(byteArrayOf(Nearby.READY.toByte()))
        val code = "clipway:" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(Crypto.generateSecret())
        m.read(Nearby.PACKET, Nearby.sealPacket(k.key, a.publicKey, b.publicKey, code, Crypto.randomBytes(12)))
        assertEquals(code, (m.outcome as NearbyPhone.Outcome.Paired).code)
    }

    @Test
    fun scanStartsStayUnderAndroidsLimit() {
        val s = ScanStarts()
        repeat(4) { i ->
            assertEquals(0L, s.wait(1_000L + i))
            s.note(1_000L + i)
        }
        // A fifth start within 30 s waits until the first one is 30 s old.
        assertEquals(30_000L - 4, s.wait(1_004L))
        assertEquals(0L, s.wait(31_000L))
        s.note(31_000L)
        assertEquals(1L, s.wait(31_000L))
        assertEquals(0L, s.wait(31_001L))
    }
}
