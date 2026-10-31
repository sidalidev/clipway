package dev.sidali.clipway

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The client side of the relay protocol, driven frame by frame with a fake socket. */
class EngineTest {

    private val keys = Protocol.Keys.of(ByteArray(16) { it.toByte() })
    private val mac = Protocol.Device("f0e1d2c3b4a5968778695a4b3c2d1e0f", "Mac", "mac")
    private val phone = Protocol.Device("0f1e2d3c4b5a69788796a5b4c3d2e1f0", "Pixel", "android")

    private class Wire : Engine.Wire {
        val sent = ArrayList<String>()
        var queue = 0L
        override fun send(text: String): Boolean { sent += text; return true }
        override fun queueSize() = queue
        fun kinds() = sent.map { JSONObject(it).getString("kind") }
    }

    private class Cursor : Engine.Cursor {
        override var epoch = ""
        override var after = 0L
    }

    private class Events : Engine.Events {
        val delivered = ArrayList<Long>()
        val stored = ArrayList<Pair<String, Long>>()
        var answer = Engine.Delivery.Ack
        var presence = 0
        var acked = ArrayList<Long>()
        override fun onDelivery(seq: Long, parts: List<Crypto.Envelope>): Engine.Delivery { delivered += seq; return answer }
        override fun onSynced() = Unit
        override fun onPresence(devices: Int) { presence = devices }
        override fun onStored(item: String, seq: Long, othersOnline: Boolean) { stored += item to seq }
        override fun onDelivered(seq: Long) { acked += seq }
        override fun onRefused(item: String, code: String) = Unit
        override fun onBackOff(ms: Long) = Unit
    }

    private fun itemFrame(seq: Long, part: Int, parts: Int, e: Crypto.Envelope) =
        """{"kind":"item","seq":$seq,"part":$part,"parts":$parts,"ts":1,"blob":{"nonce":"${e.nonce}","enc":"${e.enc}"}}"""

    @Test
    fun syncThenUploadThenStored() {
        val outbox = Outbox()
        val cursor = Cursor().apply { epoch = "aaaaaaaaaaaaaaaa"; after = 5 }
        val ev = Events()
        val e = Engine(keys, outbox, cursor, ev)
        val w = Wire()
        val big = Protocol.build(keys, "text", phone, 1, ByteArray(65_536) { 'z'.code.toByte() })
        outbox.add(Outbox.Pending(big.head.item, "text", big.head.fp!!, big.parts))
        e.attach(w)
        // Nothing before synced.
        assertEquals(false, e.pump(0))
        assertTrue(w.sent.isEmpty())
        // Same epoch: sync after the stored cursor.
        e.onFrame("""{"kind":"welcome","v":1,"epoch":"aaaaaaaaaaaaaaaa","devices":2,"limits":{}}""", 0)
        assertEquals("""{"kind":"sync","epoch":"aaaaaaaaaaaaaaaa","after":5}""", w.sent.single())
        assertEquals(2, ev.presence)
        e.onFrame("""{"kind":"synced","last":9}""", 0)
        assertEquals(9L, cursor.after)
        // synced pumps the outbox: the largest text is one envelope, part 0 of 1.
        val parts = w.sent.drop(1).map { JSONObject(it) }
        assertEquals(listOf(0), parts.map { it.getInt("part") })
        assertTrue(parts.all { it.getInt("parts") == 1 })
        assertTrue(parts[0].getJSONObject("blob").getString("enc").length <= 117_440)
        // stored removes it from the outbox and records its seq.
        e.onFrame("""{"kind":"stored","ref":${parts[0].getInt("ref")},"seq":10}""", 0)
        assertEquals(listOf(big.head.item to 10L), ev.stored)
        assertEquals(0, outbox.size())
        assertEquals(10L, cursor.after)
        e.onFrame("""{"kind":"delivered","seq":10}""", 0)
        assertEquals(listOf(10L), ev.acked)
    }

    @Test
    fun newEpochAsksForEverything() {
        val cursor = Cursor().apply { epoch = "aaaaaaaaaaaaaaaa"; after = 40 }
        val e = Engine(keys, Outbox(), cursor, Events())
        val w = Wire()
        e.attach(w)
        e.onFrame("""{"kind":"welcome","v":1,"epoch":"bbbbbbbbbbbbbbbb","devices":1,"limits":{}}""", 0)
        assertEquals("""{"kind":"sync","epoch":"aaaaaaaaaaaaaaaa","after":0}""", w.sent.single())
        e.onFrame("""{"kind":"synced","last":3}""", 0)
        assertEquals("bbbbbbbbbbbbbbbb", cursor.epoch)
        assertEquals(3L, cursor.after)
    }

    @Test
    fun partsAreCollectedThenAcknowledged() {
        val cursor = Cursor()
        val ev = Events()
        val e = Engine(keys, Outbox(), cursor, ev)
        val w = Wire()
        e.attach(w)
        e.onFrame("""{"kind":"welcome","v":1,"epoch":"aaaaaaaaaaaaaaaa","devices":2,"limits":{}}""", 0)
        val item = Protocol.build(keys, "text", mac, 1, ByteArray(1_500) { 'b'.code.toByte() })
        item.parts.forEachIndexed { i, p -> e.onFrame(itemFrame(7, i, item.parts.size, p), 0) }
        assertEquals(listOf(7L), ev.delivered)
        assertEquals("""{"kind":"ack","seq":7}""", w.sent.last())
        assertEquals(7L, cursor.after)
        // Own item delivered back: no ack, but handled.
        ev.answer = Engine.Delivery.NoAck
        e.onFrame(itemFrame(8, 0, 1, item.parts[0]), 0)
        assertEquals(listOf("sync", "ack"), w.kinds())
        assertEquals(8L, cursor.after)
        // Not handled: no ack, and after does not move past it.
        ev.answer = Engine.Delivery.Retry
        e.onFrame(itemFrame(9, 0, 1, item.parts[0]), 0)
        assertEquals(8L, cursor.after)
        // An item in several parts (Clipway 0.2's images and files) is never handed over.
        ev.answer = Engine.Delivery.Ack
        e.onFrame(itemFrame(11, 0, 3, item.parts[0]), 0)
        e.onFrame(itemFrame(11, 1, 3, item.parts[0]), 0)
        assertEquals(listOf(7L, 8L, 9L), ev.delivered)
    }

    @Test
    fun uploadWaitsForRoomInTheSocket() {
        val outbox = Outbox()
        val e = Engine(keys, outbox, Cursor(), Events())
        val w = Wire()
        val big = Protocol.build(keys, "text", phone, 1, ByteArray(60_000) { 3 })
        outbox.add(Outbox.Pending(big.head.item, "text", big.head.fp!!, big.parts))
        e.attach(w)
        e.onFrame("""{"kind":"welcome","v":1,"epoch":"e","devices":2,"limits":{}}""", 0)
        w.queue = Engine.QUEUE_HIGH + 1
        e.onFrame("""{"kind":"synced","last":0}""", 0)
        assertEquals(listOf("sync"), w.kinds())
        w.queue = 0
        assertEquals(false, e.pump(0))
        assertEquals(listOf("sync", "item"), w.kinds())
    }

    @Test
    fun reconnectionSendsTheSameItemAgain() {
        val outbox = Outbox()
        val e = Engine(keys, outbox, Cursor(), Events())
        val text = Protocol.build(keys, "text", phone, 1, "hi".toByteArray())
        outbox.add(Outbox.Pending(text.head.item, "text", text.head.fp!!, text.parts))
        val w1 = Wire()
        e.attach(w1)
        e.onFrame("""{"kind":"welcome","v":1,"epoch":"e","devices":1,"limits":{}}""", 0)
        e.onFrame("""{"kind":"synced","last":0}""", 0)
        assertEquals(listOf("sync", "item"), w1.kinds())
        // The connection drops before stored: the item stays and goes again on the next connection.
        e.detach()
        assertEquals(1, outbox.size())
        val w2 = Wire()
        e.attach(w2)
        e.onFrame("""{"kind":"welcome","v":1,"epoch":"e","devices":2,"limits":{}}""", 0)
        e.onFrame("""{"kind":"synced","last":0}""", 0)
        assertEquals(listOf("sync", "item"), w2.kinds())
        assertEquals(JSONObject(w1.sent[1]).getJSONObject("blob").toString(), JSONObject(w2.sent[1]).getJSONObject("blob").toString())
    }

    @Test
    fun relayErrors() {
        val outbox = Outbox()
        val ev = Events()
        val e = Engine(keys, outbox, Cursor(), ev)
        val a = Protocol.build(keys, "text", phone, 1, "a".toByteArray())
        val b = Protocol.build(keys, "text", phone, 1, "b".toByteArray())
        outbox.add(Outbox.Pending(a.head.item, "text", a.head.fp!!, a.parts))
        outbox.add(Outbox.Pending(b.head.item, "text", b.head.fp!!, b.parts))
        val w = Wire()
        e.attach(w)
        e.onFrame("""{"kind":"welcome","v":1,"epoch":"e","devices":2,"limits":{}}""", 0)
        e.onFrame("""{"kind":"synced","last":0}""", 0)
        val ref = JSONObject(w.sent.last()).getInt("ref")
        // Refused for good: dropped, the next one goes.
        e.onFrame("""{"kind":"error","ref":$ref,"code":"too_big","message":"x"}""", 0)
        assertEquals(1, outbox.size())
        assertEquals(listOf("sync", "item", "item"), w.kinds())
        // Rate limited: kept, nothing more until the back-off is over.
        val ref2 = JSONObject(w.sent.last()).getInt("ref")
        e.onFrame("""{"kind":"error","ref":$ref2,"code":"rate_limited","message":"x"}""", 0)
        assertEquals(1, outbox.size())
        assertEquals(false, e.pump(1000))
        assertEquals(3, w.sent.size)
        e.pump(Engine.BACK_OFF_MS + 1)
        assertEquals(4, w.sent.size)
    }
}
