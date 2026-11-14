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
import java.util.Base64

/** Heads, offers and replies, freshness, duplicates, names, relay addresses and frames, against docs/VECTORS.json. */
class ProtocolTest {

    private val v = JSONObject(File("../../docs/VECTORS.json").readText())
    private val s = Crypto.fromHex(v.getString("S"))
    private val keys = Protocol.Keys.of(s)
    private val now = 1_792_300_005_000L
    private val me = "11111111111111111111111111111111"

    private fun env(o: JSONObject) = Crypto.Envelope(o.getString("nonce"), o.getString("enc"))

    private fun headOf(o: JSONObject): Protocol.Head {
        val d = o.getJSONObject("device")
        return Protocol.Head(
            type = o.getString("type"), item = o.getString("item"),
            device = Protocol.Device(d.getString("id"), d.getString("name"), d.getString("kind")), ts = o.getLong("ts"),
            mime = if (o.has("mime")) o.getString("mime") else null, name = if (o.has("name")) o.getString("name") else null,
            size = o.optLong("size", 0), fp = if (o.has("fp")) o.getString("fp") else null,
            data = if (o.has("data")) o.getString("data") else null,
            media = if (o.has("media")) o.getString("media") else null, port = o.optInt("port", 0),
            hosts = o.optJSONArray("hosts")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList(),
            offer = if (o.has("offer")) o.getString("offer") else null, status = if (o.has("status")) o.getString("status") else null,
            chunks = o.optInt("chunks", 0),
        )
    }

    @Test
    fun keysMatchTheVectors() {
        assertEquals(v.getString("id"), keys.chainId)
        assertEquals(v.getString("P"), keys.proofHex)
        assertEquals(v.getString("subprotocol"), keys.subprotocolHeader)
    }

    /** The native serializer writes the vector plaintext byte for byte (reference order, JSON.stringify). */
    @Test
    fun headsSerializeLikeTheVectors() {
        for (name in listOf("text_item", "hello_item", "offer_item", "offer_file_item", "reply_item", "chunked_item", "chunked_file_item", "chunked_empty_item")) {
            val item = v.getJSONObject(name)
            val head = headOf(item.getJSONObject("head"))
            assertEquals(name, item.getString("plaintext"), Crypto.padHead(Protocol.serialize(head)))
            assertEquals(name, item.getInt("plaintext_bytes"), item.getString("plaintext").toByteArray(Charsets.UTF_8).size)
        }
    }

    @Test
    fun buildReproducesTheTextVector() {
        val item = v.getJSONObject("text_item")
        val h = item.getJSONObject("head")
        val d = h.getJSONObject("device")
        val content = Base64.getDecoder().decode(h.getString("data"))
        val built = Protocol.build(
            keys, "text", Protocol.Device(d.getString("id"), d.getString("name"), d.getString("kind")), h.getLong("ts"), content,
            item = h.getString("item"), nonce = Crypto.fromHex(item.getJSONObject("envelope").getString("nonce")),
        )
        assertEquals(env(item.getJSONObject("envelope")), built.parts.single())
    }

    @Test
    fun buildReproducesTheOfferAndReplyVectors() {
        val o = v.getJSONObject("offer_file_item")
        val h = headOf(o.getJSONObject("head"))
        val content = ByteArray(h.size.toInt()) { (it % 251).toByte() }
        val built = Protocol.offer(keys, h.device, h.ts, h.media!!, h.mime, h.name, content, h.port, h.hosts, h.item, Crypto.fromHex(o.getJSONObject("envelope").getString("nonce")))
        assertEquals(env(o.getJSONObject("envelope")), built.parts.single())
        val r = v.getJSONObject("reply_item")
        val rh = headOf(r.getJSONObject("head"))
        val reply = Protocol.reply(keys, rh.device, rh.ts, rh.offer!!, rh.status!!, rh.item, Crypto.fromHex(r.getJSONObject("envelope").getString("nonce")))
        assertEquals(env(r.getJSONObject("envelope")), reply.parts.single())
    }

    private fun sha256Hex(s: String) = Crypto.hex(Crypto.sha256(s.toByteArray(Charsets.UTF_8)))

    /** Images and files through the relay: the head and its chunks, byte for byte, then opened. */
    @Test
    fun chunkedItemsMatchTheVectors() {
        val big = ByteArray(150_000) { (it % 251).toByte() }
        val png = Crypto.open(keys.enc, v.getJSONObject("chunked_item").getJSONArray("chunks").getJSONObject(0).getString("aad"),
            env(v.getJSONObject("chunked_item").getJSONArray("chunks").getJSONObject(0).getJSONObject("envelope")))
        for ((name, content) in listOf("chunked_item" to png, "chunked_file_item" to big, "chunked_empty_item" to ByteArray(0))) {
            val o = v.getJSONObject(name)
            val h = headOf(o.getJSONObject("head"))
            val chunks = o.getJSONArray("chunks")
            assertEquals(name, Crypto.chunkCount(h.size), h.chunks)
            assertEquals(name, h.chunks, chunks.length())
            val nonces = listOf(Crypto.fromHex(o.getJSONObject("envelope").getString("nonce"))) +
                (0 until chunks.length()).map { Crypto.fromHex(chunks.getJSONObject(it).getString("nonce")) }
            val built = Protocol.chunked(keys, h.device, h.ts, h.media!!, h.mime, h.name, content, h.item, nonces)
            assertEquals(name, 1 + h.chunks, built.parts.size)
            assertEquals(name, env(o.getJSONObject("envelope")), built.parts[0])
            for (i in 0 until chunks.length()) {
                val c = chunks.getJSONObject(i)
                assertEquals(c.getString("aad"), Crypto.chunkAad(keys.chainId, h.item, i, h.chunks))
                assertEquals("$name chunk $i", c.getString("enc_sha256"), sha256Hex(built.parts[i + 1].enc))
                if (c.has("envelope")) assertEquals(env(c.getJSONObject("envelope")), built.parts[i + 1])
            }
            val opened = Protocol.open(keys, built.parts, h.ts + 1000, me, Protocol.Seen()) as Protocol.Opened.Ok
            assertEquals("chunked", opened.head.type)
            assertArrayEquals(name, content, opened.content)
        }
        assertEquals(v.getJSONObject("chunked_file_item").getString("content_sha256"), Crypto.hex(Crypto.sha256(big)))
        // Swapped, missing, extra, or a chunk of another item: never handed over.
        val h = headOf(v.getJSONObject("chunked_file_item").getJSONObject("head"))
        val p = Protocol.chunked(keys, h.device, now, "file", h.mime, h.name, big).parts
        val other = Protocol.chunked(keys, h.device, now, "file", h.mime, h.name, big).parts
        fun dropped(parts: List<Crypto.Envelope>) = (Protocol.open(keys, parts, now, me, Protocol.Seen()) as Protocol.Opened.Dropped).why
        assertEquals(Protocol.Drop.Unreadable, dropped(listOf(p[0], p[2], p[1], p[3])))
        assertEquals(Protocol.Drop.Parts, dropped(p.take(3)))
        assertEquals(Protocol.Drop.Parts, dropped(p + p[3]))
        assertEquals(Protocol.Drop.Unreadable, dropped(listOf(p[0], other[1], p[2], p[3])))
        // The largest one: 65 parts, each under the relay's envelope limit; one byte more is refused.
        val largest = Protocol.chunked(keys, mac, now, "file", "application/zip", "big.zip", ByteArray(Crypto.RELAY_FILE_MAX))
        assertEquals(v.getJSONObject("limits").getInt("parts"), largest.parts.size)
        assertTrue(largest.parts.all { it.enc.length <= v.getJSONObject("limits").getInt("enc") })
        try {
            Protocol.chunked(keys, mac, now, "file", "application/zip", "big.zip", ByteArray(Crypto.RELAY_FILE_MAX + 1))
            fail("over 4 MiB accepted")
        } catch (e: IllegalArgumentException) {
            // expected
        }
        // What fits the relay: 4 MiB at most, and only on a relay that takes 65 parts.
        assertTrue(Protocol.fitsRelay(Crypto.RELAY_FILE_MAX.toLong(), 65))
        assertFalse(Protocol.fitsRelay(Crypto.RELAY_FILE_MAX + 1L, 65))
        assertFalse(Protocol.fitsRelay(100_000, 1))
        assertTrue(Protocol.fitsRelay(0, 1))
        assertEquals(Crypto.CHUNK_SIZE, v.getJSONObject("limits").getInt("chunk"))
        assertEquals(Crypto.RELAY_FILE_MAX, v.getJSONObject("limits").getInt("relay_file"))
    }

    @Test
    fun theVectorsOpen() {
        val seen = Protocol.Seen()
        val text = Protocol.open(keys, listOf(env(v.getJSONObject("text_item").getJSONObject("envelope"))), now, me, seen)
        assertTrue(text is Protocol.Opened.Ok)
        text as Protocol.Opened.Ok
        assertEquals(v.getJSONObject("fingerprint").getString("content_utf8"), String(text.content!!, Charsets.UTF_8))
        assertEquals("Test Mac", text.head.device.name)

        // The offer vectors are older than 2 minutes at `now`: check them at their own time.
        val offerHead = v.getJSONObject("offer_item").getJSONObject("head")
        val offer = Protocol.open(keys, listOf(env(v.getJSONObject("offer_item").getJSONObject("envelope"))), offerHead.getLong("ts") + 1000, me, seen)
        offer as Protocol.Opened.Ok
        assertNull(offer.content)
        assertEquals(listOf("image", "dot.png", "41234"), listOf(offer.head.media, offer.head.name, offer.head.port.toString()))
        assertEquals(listOf("192.168.1.23", "10.0.0.7"), offer.head.hosts)
        assertEquals(Protocol.Drop.Stale, (Protocol.open(keys, listOf(env(v.getJSONObject("offer_item").getJSONObject("envelope"))), offerHead.getLong("ts") + Protocol.OFFER_MS + 1, me, seen) as Protocol.Opened.Dropped).why)
        val reply = Protocol.open(keys, listOf(env(v.getJSONObject("reply_item").getJSONObject("envelope"))), now, me, seen) as Protocol.Opened.Ok
        assertEquals("unreachable", reply.head.status)
        // Images and files inside items (Clipway 0.2), chunks, too long a text: dropped as invalid.
        val refused = v.getJSONObject("refused_heads").getJSONArray("cases")
        for (i in 0 until refused.length()) {
            val c = refused.getJSONObject(i)
            val r = Protocol.open(keys, listOf(env(c.getJSONObject("envelope"))), now, me, seen) as Protocol.Opened.Dropped
            assertEquals(c.getString("why"), Protocol.Drop.Invalid, r.why)
            assertTrue(r.why.ack)
        }

        val hello = Protocol.open(keys, listOf(env(v.getJSONObject("hello_item").getJSONObject("envelope"))), now, me, seen)
        assertNull((hello as Protocol.Opened.Ok).content)
        assertEquals("hello", hello.head.type)
    }

    private val mac = Protocol.Device("f0e1d2c3b4a5968778695a4b3c2d1e0f", "MacBook Air", "mac")

    @Test
    fun sizes() {
        // 64 KiB of text is one envelope under the relay's limit; one byte more is refused.
        val max = Protocol.build(keys, "text", mac, now, ByteArray(65_536) { 'a'.code.toByte() })
        assertEquals(1, max.parts.size)
        assertTrue(max.parts[0].enc.length <= v.getJSONObject("limits").getInt("enc"))
        try {
            Protocol.build(keys, "text", mac, now, ByteArray(65_537) { 'a'.code.toByte() })
            fail("text over 64 KiB accepted")
        } catch (e: IllegalArgumentException) {
            // expected
        }
        // Images and files are never items: only offers stand for them.
        try {
            Protocol.build(keys, "image", mac, now, ByteArray(10))
            fail("image item built")
        } catch (e: IllegalArgumentException) {
            // expected
        }
        // An offer for 25 MiB is a 512-byte head; one byte more is refused.
        val offer = Protocol.offer(keys, mac, now, "file", "application/zip", "big.zip", ByteArray(26_214_400), 40_000, listOf("192.168.1.10"))
        assertEquals(512, Crypto.open(keys.enc, keys.chainId, offer.parts[0]).size)
        try {
            Protocol.offer(keys, mac, now, "file", "application/zip", "big.zip", ByteArray(26_214_401), 40_000, listOf("192.168.1.10"))
            fail("over 25 MiB accepted")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun headsArePadded() {
        for (len in listOf(0, 1, 300, 450, 1000, 5000)) {
            val built = Protocol.build(keys, "text", mac, now, ByteArray(len) { 'a'.code.toByte() })
            val plain = Crypto.open(keys.enc, keys.chainId, built.parts[0])
            assertEquals(0, plain.size % Crypto.PAD_BLOCK)
        }
    }

    @Test
    fun receiverRules() {
        val seen = Protocol.Seen()
        val text = Protocol.build(keys, "text", mac, now, "hello".toByteArray())
        // Own item: dropped and never acknowledged.
        val own = Protocol.open(keys, text.parts, now, mac.id, seen) as Protocol.Opened.Dropped
        assertEquals(Protocol.Drop.Own, own.why)
        assertFalse(own.why.ack)
        // Too old, too far ahead.
        val old = Protocol.build(keys, "text", mac, now - Protocol.PAST_MS - 1, "x".toByteArray())
        assertEquals(Protocol.Drop.Stale, (Protocol.open(keys, old.parts, now, me, seen) as Protocol.Opened.Dropped).why)
        val ahead = Protocol.build(keys, "text", mac, now + Protocol.FUTURE_MS + 1, "x".toByteArray())
        assertEquals(Protocol.Drop.Stale, (Protocol.open(keys, ahead.parts, now, me, seen) as Protocol.Opened.Dropped).why)
        val edge = Protocol.build(keys, "text", mac, now - Protocol.PAST_MS, "x".toByteArray())
        assertTrue(Protocol.open(keys, edge.parts, now, me, seen) is Protocol.Opened.Ok)
        // Duplicate item id.
        seen.add(text.head.item, now)
        assertEquals(Protocol.Drop.Duplicate, (Protocol.open(keys, text.parts, now, me, seen) as Protocol.Opened.Dropped).why)
        // Another chain's key: unreadable, acknowledged.
        val other = Protocol.Keys.of(ByteArray(16) { 9 })
        val foreign = Protocol.build(other, "text", mac, now, "x".toByteArray())
        val bad = Protocol.open(keys, foreign.parts, now, me, seen) as Protocol.Opened.Dropped
        assertEquals(Protocol.Drop.Unreadable, bad.why)
        assertTrue(bad.why.ack)
        // An item is one envelope: two are refused.
        val two = Protocol.build(keys, "text", mac, now, "y".toByteArray())
        assertEquals(Protocol.Drop.Parts, (Protocol.open(keys, two.parts + two.parts, now, me, seen) as Protocol.Opened.Dropped).why)
    }

    @Test
    fun headValidation() {
        fun bad(json: String) {
            try {
                Protocol.parseHead(json)
                fail("accepted: $json")
            } catch (e: IllegalArgumentException) {
                // expected
            }
        }
        val dev = """"device":{"id":"f0e1d2c3b4a5968778695a4b3c2d1e0f","name":"Mac","kind":"mac"}"""
        val fp = "963175147d5b7e6d67e6f296258e84b5"
        bad("""{"v":2,"type":"hello","item":"00112233445566778899aabbccddeeff",$dev,"ts":1}""")
        bad("""{"v":1,"type":"note","item":"00112233445566778899aabbccddeeff",$dev,"ts":1}""")
        bad("""{"v":1,"type":"text","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"mime":"text/html","size":1,"fp":"$fp","data":"YQ=="}""")
        bad("""{"v":1,"type":"text","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"mime":"text/plain","size":2,"fp":"$fp","data":"YQ=="}""")
        bad("""{"v":1,"type":"text","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"mime":"text/plain","name":"a","size":1,"fp":"$fp","data":"YQ=="}""")
        bad("""{"v":1,"type":"file","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"mime":"application/pdf","name":"a","size":1,"fp":"$fp","data":"YQ=="}""")
        bad("""{"v":1,"type":"image","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"mime":"image/png","size":1,"fp":"$fp","data":"YQ=="}""")
        bad("""{"v":1,"type":"text","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"mime":"text/plain","size":1,"fp":"$fp","data":"YQ==","chunks":1}""")
        val chunked = """"type":"chunked","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"fp":"$fp""""
        assertEquals(2, Protocol.parseHead("""{"v":1,$chunked,"media":"image","mime":"image/png","size":70000,"chunks":2}""").chunks)
        bad("""{"v":1,$chunked,"media":"image","mime":"image/png","size":70000,"chunks":1}""")
        bad("""{"v":1,$chunked,"media":"image","mime":"image/png","size":70000}""")
        bad("""{"v":1,$chunked,"media":"image","mime":"text/plain","size":70000,"chunks":2}""")
        bad("""{"v":1,$chunked,"media":"file","mime":"text/plain","size":70000,"chunks":2}""")
        bad("""{"v":1,$chunked,"media":"image","mime":"image/png","size":4194305,"chunks":65}""")
        bad("""{"v":1,$chunked,"media":"image","mime":"image/png","size":1,"chunks":1,"data":"YQ=="}""")
        bad("""{"v":1,$chunked,"media":"image","mime":"image/png","size":1,"chunks":"1"}""")
        val offer = """"type":"offer","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"size":1,"fp":"$fp""""
        bad("""{"v":1,$offer,"media":"video","mime":"video/mp4","port":1,"hosts":["10.0.0.1"]}""")
        bad("""{"v":1,$offer,"media":"image","mime":"application/pdf","port":1,"hosts":["10.0.0.1"]}""")
        bad("""{"v":1,$offer,"media":"file","mime":"application/pdf","port":1,"hosts":["10.0.0.1"]}""")
        bad("""{"v":1,$offer,"media":"image","mime":"image/png","port":0,"hosts":["10.0.0.1"]}""")
        bad("""{"v":1,$offer,"media":"image","mime":"image/png","port":70000,"hosts":["10.0.0.1"]}""")
        bad("""{"v":1,$offer,"media":"image","mime":"image/png","port":1,"hosts":[]}""")
        bad("""{"v":1,$offer,"media":"image","mime":"image/png","port":1,"hosts":["mac.local"]}""")
        bad("""{"v":1,$offer,"media":"image","mime":"image/png","port":1,"hosts":["10.0.0.01"]}""")
        bad("""{"v":1,$offer,"media":"image","mime":"image/png","port":1,"hosts":["10.0.0.1"],"data":"YQ=="}""")
        assertEquals(41234, Protocol.parseHead("""{"v":1,$offer,"media":"image","mime":"image/png","port":41234,"hosts":["10.0.0.1"]}""").port)
        bad("""{"v":1,$offer,"media":"image","mime":"image/png","port":41234,"hosts":["10.0.0.1"],"chunks":1}""")
        bad("""{"v":1,"type":"reply","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"offer":"00112233445566778899aabbccddeeff","status":"maybe"}""")
        bad("""{"v":1,"type":"reply","item":"00112233445566778899aabbccddeeff",$dev,"ts":1,"offer":"x","status":"done"}""")
        bad("""{"v":1,"type":"hello","item":"0011",$dev,"ts":1}""")
        bad("""{"v":1,"type":"hello","item":"00112233445566778899aabbccddeeff","device":{"id":"f0e1d2c3b4a5968778695a4b3c2d1e0f","name":"","kind":"mac"},"ts":1}""")
        bad("""{"v":1,"type":"hello","item":"00112233445566778899aabbccddeeff","device":{"id":"f0e1d2c3b4a5968778695a4b3c2d1e0f","name":"x","kind":"linux"},"ts":1}""")
        bad("not json")
        // Any order and unknown fields are fine.
        val ok = Protocol.parseHead("""{"pad":"  ","future":true,"ts":5,$dev,"item":"00112233445566778899aabbccddeeff","type":"hello","v":1}""")
        assertEquals("hello", ok.type)
    }

    @Test
    fun jsonEscapingMatchesJavaScript() {
        val d = Protocol.Device("f0e1d2c3b4a5968778695a4b3c2d1e0f", "Sid's \"Mac\" \\ /\n\t\u0001 é 👋", "mac")
        val json = Protocol.serialize(Protocol.Head(type = "hello", item = "00112233445566778899aabbccddeeff", device = d, ts = 1))
        assertEquals(
            """{"v":1,"type":"hello","item":"00112233445566778899aabbccddeeff","device":{"id":"f0e1d2c3b4a5968778695a4b3c2d1e0f","name":"Sid's \"Mac\" \\ /\n\t\u0001 é 👋","kind":"mac"},"ts":1}""",
            json,
        )
        assertEquals(d.name, Protocol.parseHead(json).device.name)
    }

    @Test
    fun seenItems() {
        val s = Protocol.Seen(maxAgeMs = 1000, max = 3)
        s.add("a".repeat(32), 0)
        assertTrue(s.contains("a".repeat(32), 999))
        assertFalse(s.contains("a".repeat(32), 1001))
        for (i in 0 until 5) s.add(i.toString().repeat(32), 2000)
        assertEquals(3, s.size())
        assertFalse(s.contains("0".repeat(32), 2000))
        assertTrue(s.contains("4".repeat(32), 2000))
        val round = Protocol.Seen.decode(Protocol.Seen().apply { add("b".repeat(32), 10) }.encode(), 20)
        assertTrue(round.contains("b".repeat(32), 20))
    }

    @Test
    fun receivedFileNames() {
        assertEquals("etcpasswd", Protocol.safeFileName("../../etc/passwd"))
        assertEquals("evil.sh", Protocol.safeFileName(".evil.sh"))
        assertEquals("ab.txt", Protocol.safeFileName("a\u0000b\u202E.txt"))
        assertEquals("file", Protocol.safeFileName(" ... "))
        assertEquals("file", Protocol.safeFileName(null))
        assertEquals("C:Windowsx.exe", Protocol.safeFileName("C:\\Windows\\x.exe"))
        val long = "x".repeat(300) + ".pdf"
        val cut = Protocol.safeFileName(long)
        assertEquals(120, cut.length)
        assertTrue(cut.endsWith(".pdf"))
        assertEquals("photo 2.jpg", Protocol.freeName("photo.jpg", setOf("photo.jpg")))
        assertEquals("photo 3.jpg", Protocol.freeName("photo.jpg", setOf("photo.jpg", "photo 2.jpg")))
        assertEquals("notes 2", Protocol.freeName("notes", setOf("notes")))
        assertEquals("a.png", Protocol.freeName("a.png", emptySet()))
    }

    @Test
    fun whatMayBeSent() {
        assertEquals(Protocol.Refusal.Sensitive, Protocol.refusal("text", 10, sensitive = true))
        assertEquals(Protocol.Refusal.Empty, Protocol.refusal("text", 0, sensitive = false))
        assertEquals(Protocol.Refusal.TooLarge, Protocol.refusal("text", 65_537, sensitive = false))
        assertNull(Protocol.refusal("text", 65_536, sensitive = false))
        assertNull(Protocol.refusal("image", 26_214_400, sensitive = false))
        assertEquals(Protocol.Refusal.TooLarge, Protocol.refusal("file", 26_214_401, sensitive = false))
        // Sensitive wins over everything, even an empty or huge clip.
        assertEquals(Protocol.Refusal.Sensitive, Protocol.refusal("file", 99_000_000, sensitive = true))
        // The extra Android sets on a sensitive clip (ClipDescription.EXTRA_IS_SENSITIVE).
        assertEquals("android.content.extra.IS_SENSITIVE", Protocol.EXTRA_IS_SENSITIVE)
    }

    @Test
    fun relayAddresses() {
        assertTrue(Protocol.relayAllowed("https://clip.sidali.dev", false))
        assertTrue(Protocol.relayAllowed(" https://clip.example.org/ ", false))
        assertFalse(Protocol.relayAllowed("http://clip.example.org", false))
        assertFalse(Protocol.relayAllowed("http://10.0.2.2:7710", false))
        assertTrue(Protocol.relayAllowed("http://10.0.2.2:7710", true))
        assertTrue(Protocol.relayAllowed("http://127.0.0.1:7710", true))
        assertFalse(Protocol.relayAllowed("http://192.168.1.2:7710", true))
        assertFalse(Protocol.relayAllowed("https://u:p@clip.example.org", false))
        assertFalse(Protocol.relayAllowed("https://clip.example.org/?x=1", false))
        assertFalse(Protocol.relayAllowed("ftp://clip.example.org", false))
        // A keyboard capitalizes the first letter: the scheme and host are case-insensitive, the path is not.
        assertTrue(Protocol.relayAllowed("Http://10.0.2.2:7710", true))
        assertEquals("http://10.0.2.2:7710", Protocol.normalizeRelay(" Http://10.0.2.2:7710/ "))
        assertEquals("https://clip.example.org/Clipway", Protocol.normalizeRelay("HTTPS://Clip.Example.org/Clipway/"))
        assertEquals("ws://10.0.2.2:7710/ws", Protocol.webSocketUrl("Http://10.0.2.2:7710"))
        assertEquals("wss://clip.sidali.dev/ws", Protocol.webSocketUrl("https://clip.sidali.dev/"))
        assertEquals("ws://10.0.2.2:7710/ws", Protocol.webSocketUrl("http://10.0.2.2:7710"))
        assertEquals("clip.sidali.dev", Protocol.relayHost("https://clip.sidali.dev"))
        assertEquals("10.0.2.2:7710", Protocol.relayHost("http://10.0.2.2:7710"))
    }

    @Test
    fun framesOfTheVectors() {
        val f = v.getJSONObject("frames")
        val w = Protocol.parseFrame(f.getJSONObject("welcome").toString()) as Protocol.Incoming.Welcome
        assertEquals("5f3a9c0d1e2b4a68", w.epoch)
        assertEquals(2, w.devices)
        assertEquals(65, w.parts)
        assertEquals(1, (Protocol.parseFrame("""{"kind":"welcome","v":1,"epoch":"e","devices":1,"limits":{"parts":1}}""") as Protocol.Incoming.Welcome).parts)
        assertEquals(1, (Protocol.parseFrame("""{"kind":"welcome","v":1,"epoch":"e","devices":1}""") as Protocol.Incoming.Welcome).parts)
        assertEquals(42L, (Protocol.parseFrame(f.getJSONObject("synced").toString()) as Protocol.Incoming.Synced).last)
        val d = Protocol.parseFrame(f.getJSONObject("delivery").toString()) as Protocol.Incoming.Item
        assertEquals(43L, d.seq)
        assertEquals(1, d.parts)
        assertEquals(43L, (Protocol.parseFrame(f.getJSONObject("stored").toString()) as Protocol.Incoming.Stored).seq)
        assertEquals(1, (Protocol.parseFrame(f.getJSONObject("presence").toString()) as Protocol.Incoming.Presence).devices)
        assertEquals("too_big", (Protocol.parseFrame(f.getJSONObject("error").toString()) as Protocol.Incoming.Error).code)
        assertTrue(Protocol.parseFrame(f.getJSONObject("pong").toString()) === Protocol.Incoming.Pong)
        assertTrue(Protocol.parseFrame("{\"kind\":\"nope\"}") === Protocol.Incoming.Other)
        assertTrue(Protocol.parseFrame("garbage") === Protocol.Incoming.Other)
        // What we send has the exact shape of the vectors.
        val up = f.getJSONObject("upload")
        val built = JSONObject(Protocol.Frames.item(up.getInt("ref"), up.getInt("part"), up.getInt("parts"), env(up.getJSONObject("blob"))))
        assertEquals(up.toString(), built.toString())
        val upChunk = f.getJSONObject("upload_chunked")
        assertEquals(upChunk.toString(), JSONObject(Protocol.Frames.item(upChunk.getInt("ref"), upChunk.getInt("part"), upChunk.getInt("parts"), env(upChunk.getJSONObject("blob")))).toString())
        assertEquals(f.getJSONObject("sync").toString(), JSONObject(Protocol.Frames.sync("5f3a9c0d1e2b4a68", 41)).toString())
        assertEquals(f.getJSONObject("ack").toString(), JSONObject(Protocol.Frames.ack(43)).toString())
        assertEquals(f.getJSONObject("ping").toString(), JSONObject(Protocol.Frames.PING).toString())
    }
}
