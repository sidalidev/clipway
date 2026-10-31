package dev.sidali.clipway

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Direct transfer (docs/PROTOCOL.md, section 14): the vectors, then a real transfer on the loopback interface. */
class DirectTest {

    private val v = JSONObject(File("../../docs/VECTORS.json").readText())
    private val d = v.getJSONObject("direct")
    private val s = Crypto.fromHex(v.getString("S"))
    private val keys = Protocol.Keys.of(s)
    private val transfer = d.getString("transfer")
    private val kT = Direct.transferKey(keys.direct, transfer)
    private val mac = Protocol.Device("f0e1d2c3b4a5968778695a4b3c2d1e0f", "Mac", "mac")

    private fun content() = ByteArray(d.getInt("size")) { (it % 251).toByte() }

    @Test
    fun keysAndPreamble() {
        assertEquals(d.getString("K_direct"), Crypto.hex(keys.direct))
        assertEquals(d.getString("K_t"), Crypto.hex(kT))
        assertEquals(d.getString("preamble"), Crypto.hex(Direct.preamble(transfer)))
        assertEquals(transfer, Direct.readPreamble(Direct.preamble(transfer)))
        assertNull(Direct.readPreamble("CWD2".toByteArray() + ByteArray(16)))
        assertEquals(d.getInt("record_data"), Direct.RECORD_DATA)
        assertEquals(d.getInt("record_max"), Direct.RECORD_MAX)
    }

    @Test
    fun records() {
        val get0 = d.getJSONObject("get0")
        val sealed = Direct.sealRecord(kT, transfer, "get", 0, get0.getString("plaintext_utf8").toByteArray(), Crypto.fromHex(get0.getString("nonce")))
        assertEquals(get0.getString("bytes"), Crypto.hex(sealed))
        assertEquals(get0.getString("plaintext_utf8"), Direct.getRequest(transfer))
        val data = content()
        assertEquals(d.getString("content_sha256"), Crypto.hex(Crypto.sha256(data)))
        val puts = d.getJSONArray("puts")
        assertEquals(puts.length(), Direct.recordCount(data.size.toLong()))
        for (i in 0 until puts.length()) {
            val r = puts.getJSONObject(i)
            val plain = data.copyOfRange(i * Direct.RECORD_DATA, minOf(data.size, (i + 1) * Direct.RECORD_DATA))
            val bytes = Direct.sealRecord(kT, transfer, "put", i, plain, Crypto.fromHex(r.getString("nonce")))
            assertEquals(r.getInt("length"), bytes.size)
            assertEquals(r.getString("sha256"), Crypto.hex(Crypto.sha256(bytes)))
            if (i == 0) assertEquals(d.getString("put0_head"), Crypto.hex(bytes.copyOf(64)))
        }
        val get1 = d.getJSONObject("get1")
        assertEquals(get1.getString("plaintext_utf8"), String(Direct.openRecord(kT, transfer, "get", 1, Crypto.fromHex(get1.getString("bytes")).copyOfRange(4, Crypto.fromHex(get1.getString("bytes")).size))))
        assertEquals(get1.getString("plaintext_utf8"), Direct.getStatus("done"))
        // Each must be refused.
        val body = Crypto.fromHex(get0.getString("bytes")).let { it.copyOfRange(4, it.size) }
        fun refused(f: () -> Unit) = try { f(); fail("accepted") } catch (e: Exception) { }
        refused { Direct.openRecord(kT, transfer, "put", 0, body) }
        refused { Direct.openRecord(kT, transfer, "get", 1, body) }
        val other = v.getJSONObject("offer_item").getJSONObject("head").getString("item")
        refused { Direct.openRecord(Direct.transferKey(keys.direct, other), other, "get", 0, body) }
        val tampered = Crypto.fromHex(d.getJSONObject("negative").getString("tampered_get0"))
        refused { Direct.openRecord(kT, transfer, "get", 0, tampered.copyOfRange(4, tampered.size)) }
    }

    @Test
    fun addresses() {
        val h = d.getJSONObject("private_hosts")
        val ok = h.getJSONArray("allowed")
        for (i in 0 until ok.length()) assertTrue(ok.getString(i), Direct.isPrivate(ok.getString(i)))
        val no = h.getJSONArray("refused")
        for (i in 0 until no.length()) assertFalse(no.getString(i), Direct.isPrivate(no.getString(i)))
        assertFalse(Direct.mayConnect("127.0.0.1", debug = false))
        assertTrue(Direct.mayConnect("127.0.0.1", debug = true))
        assertTrue(Direct.mayConnect("10.0.2.2", debug = true))
        for (host in Direct.localHosts()) assertTrue(Direct.isPrivate(host))
    }

    private class Waiter {
        val latch = CountDownLatch(1)
        val outcome = AtomicReference<Direct.Outcome>()
        fun set(o: Direct.Outcome) { outcome.set(o); latch.countDown() }
        fun get(): Direct.Outcome { assertTrue(latch.await(20, TimeUnit.SECONDS)); return outcome.get() }
    }

    private fun offerHead(item: String, data: ByteArray, port: Int) = Protocol.Head(
        type = "offer", item = item, device = mac, ts = System.currentTimeMillis(), media = "file", mime = "application/octet-stream",
        name = "a.bin", size = data.size.toLong(), fp = Crypto.fingerprint(keys.mac, data), port = port, hosts = listOf("127.0.0.1"),
    )

    @Test
    fun aFileGoesOnceFromSenderToReceiver() {
        val server = Direct.Server()
        val data = Crypto.randomBytes(1_000_003)
        val item = Protocol.newItemId()
        val w = Waiter()
        val port = server.offer(item, Direct.transferKey(keys.direct, item), data, w::set)
        var saved: ByteArray? = null
        val r = Direct.fetch(keys, offerHead(item, data, port), debug = true) { saved = it }
        assertTrue(r is Direct.Fetched.Ok)
        assertArrayEquals(data, saved)
        assertEquals(Direct.Outcome.Done, w.get())
        // Spent: the listening socket closed with its last offer.
        assertTrue(Direct.fetch(keys, offerHead(item, data, port), debug = true) { } !is Direct.Fetched.Ok)
        server.close()
    }

    @Test
    fun theReferenceVectorTransfers() {
        val server = Direct.Server()
        val data = content()
        val w = Waiter()
        val port = server.offer(transfer, kT, data, w::set)
        val r = Direct.fetch(keys, offerHead(transfer, data, port), debug = true) { }
        assertArrayEquals(data, (r as Direct.Fetched.Ok).content)
        assertEquals(Direct.Outcome.Done, w.get())
    }

    @Test
    fun strangersGetNothing() {
        val server = Direct.Server()
        val data = Crypto.randomBytes(5000)
        val item = Protocol.newItemId()
        val w = Waiter()
        val port = server.offer(item, Direct.transferKey(keys.direct, item), data, w::set)
        // Another chain's key: refused, the offer stays open for the right device.
        val other = Protocol.Keys.of(ByteArray(16) { 7 })
        assertTrue(Direct.fetch(other, offerHead(item, data, port), debug = true) { } is Direct.Fetched.Failed)
        // Garbage after a valid preamble: closed.
        Socket("127.0.0.1", port).use { s ->
            s.getOutputStream().write(Direct.preamble(item) + byteArrayOf(0, 0, 0, 40) + ByteArray(40))
            assertEquals(-1, s.getInputStream().read())
        }
        val r = Direct.fetch(keys, offerHead(item, data, port), debug = true) { }
        assertTrue(r is Direct.Fetched.Ok)
        assertEquals(Direct.Outcome.Done, w.get())
    }

    @Test
    fun aWrongFingerprintIsNotSaved() {
        val server = Direct.Server()
        val data = Crypto.randomBytes(70_000)
        val item = Protocol.newItemId()
        val w = Waiter()
        val port = server.offer(item, Direct.transferKey(keys.direct, item), data, w::set)
        var saved = false
        val r = Direct.fetch(keys, offerHead(item, data, port).copy(fp = "0".repeat(32)), debug = true) { saved = true }
        assertTrue(r is Direct.Fetched.Failed)
        assertFalse(saved)
        assertEquals(Direct.Outcome.Failed, w.get())
    }

    @Test
    fun unreachableAndExpired() {
        val data = ByteArray(10)
        // Release rules: loopback is not the local network, and public addresses are never tried.
        assertTrue(Direct.fetch(keys, offerHead(Protocol.newItemId(), data, 9).copy(hosts = listOf("127.0.0.1", "8.8.8.8")), debug = false) { } === Direct.Fetched.Unreachable)
        val server = Direct.Server(ttlMs = 100)
        val w = Waiter()
        val item = Protocol.newItemId()
        server.offer(item, Direct.transferKey(keys.direct, item), data, w::set)
        assertEquals(Direct.Outcome.Expired, w.get())
        val w2 = Waiter()
        val item2 = Protocol.newItemId()
        server.offer(item2, Direct.transferKey(keys.direct, item2), data, w2::set)
        server.cancel(item2, Direct.Outcome.Unreachable)
        assertEquals(Direct.Outcome.Unreachable, w2.get())
        assertFalse(server.isOpen(item2))
    }

    @Test
    fun anOfferHeadMatchesTheVector() {
        val o = v.getJSONObject("offer_file_item").getJSONObject("head")
        assertEquals(transfer, o.getString("item"))
        assertEquals(d.getInt("size"), o.getInt("size"))
        assertEquals(o.getString("fp"), Crypto.fingerprint(keys.mac, content()))
    }
}
