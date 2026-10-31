package dev.sidali.clipway

import org.json.JSONObject
import java.net.URI
import java.util.Base64

/**
 * The Clipway protocol, version 1 (docs/PROTOCOL.md): item heads (texts, hellos, offers and
 * replies), frames, freshness and duplicates, file names, relay addresses. Pure Kotlin on top of
 * [Crypto] and org.json, so every rule is tested on the JVM against docs/VECTORS.json.
 * The relay carries texts only: images and files go directly ([Direct]).
 */
object Protocol {

    const val VERSION = 1
    const val TEXT_MIME = "text/plain"
    const val DEVICE_NAME_MAX = 64
    const val NAME_MAX = 255
    const val FILE_NAME_KEEP = 120
    /** Every item is one envelope: the relay refuses anything in parts. */
    const val PARTS_MAX = 1
    const val FRAME_MAX = 131_072
    const val HOSTS_MAX = 8

    /** An offer is valid this long: its sender listens that long, then stops. */
    const val OFFER_MS = 120_000L

    /** Clipboard writes only for items younger than this (a phone back online does not paste old items). */
    const val CLIPBOARD_WINDOW_MS = 10L * 60 * 1000

    /** Heads older than 24 h + 10 min or more than 10 min ahead are replays or broken clocks. */
    const val PAST_MS = 24L * 3600 * 1000 + 10L * 60 * 1000
    const val FUTURE_MS = 10L * 60 * 1000

    /** The same content sent or received less than this ago is not sent again (echo, double tap). */
    const val ECHO_MS = 10_000L

    /** What travels through the relay. "image" and "file" (Clipway 0.2) are refused: an offer stands for them. */
    val TYPES = setOf("text", "hello", "offer", "reply")
    val MEDIA = setOf("image", "file")
    val REPLY_STATUS = setOf("done", "unreachable", "declined", "failed")
    val KINDS = setOf("mac", "android")
    private val RE_HEX32 = Regex("^[0-9a-f]{32}$")
    private val RE_MIME = Regex("^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$")
    private val RE_BASE64 = Regex("^[A-Za-z0-9+/]*={0,2}$")
    private val RE_IPV4 = Regex("^(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$")

    /** A dotted IPv4 address without leading zeros. */
    fun isIPv4(host: String): Boolean = RE_IPV4.matches(host)

    // ---------------------------------------------------------------------
    // Keys of a chain
    // ---------------------------------------------------------------------

    /** Everything a device derives from S. S itself is not kept here. */
    class Keys(val chainId: String, val proof: ByteArray, val enc: ByteArray, val mac: ByteArray, val direct: ByteArray) {
        val proofHex: String get() = Crypto.hex(proof)

        /** Value of the Sec-WebSocket-Protocol request header. */
        val subprotocolHeader: String get() = Crypto.SUBPROTOCOL + ", clipway.p." + proofHex

        companion object {
            fun of(s: ByteArray): Keys {
                val p = Crypto.proof(s)
                return Keys(Crypto.idFromProof(p), p, Crypto.encKey(s), Crypto.macKey(s), Crypto.directKey(s))
            }
        }
    }

    // ---------------------------------------------------------------------
    // Head (part 0)
    // ---------------------------------------------------------------------

    data class Device(val id: String, val name: String, val kind: String)

    data class Head(
        val type: String,
        val item: String,
        val device: Device,
        val ts: Long,
        val mime: String? = null,
        val name: String? = null,
        val size: Long = 0,
        val fp: String? = null,
        /** text: the content in base64. */
        val data: String? = null,
        /** offer: "image" or "file", and where the sender listens. */
        val media: String? = null,
        val port: Int = 0,
        val hosts: List<String> = emptyList(),
        /** reply: the offer it answers, and why. */
        val offer: String? = null,
        val status: String? = null,
        val v: Int = VERSION,
    )

    class Invalid(why: String) : IllegalArgumentException("Invalid head: $why")

    private fun codePoints(s: String) = s.codePointCount(0, s.length)

    /** Largest content for a type: a text (64 KiB), or an image or a file sent directly (25 MiB). */
    fun maxSize(type: String): Long = if (type == "text") Crypto.TEXT_MAX.toLong() else Crypto.FILE_MAX.toLong()

    /** Checks every rule of section 3.1. Throws [Invalid]. */
    fun validate(h: Head): Head {
        fun fail(why: String): Nothing = throw Invalid(why)
        if (h.v != VERSION) fail("unknown version")
        if (h.type !in TYPES) fail(if (h.type in MEDIA) "images and files travel directly" else "unknown type")
        if (!RE_HEX32.matches(h.item)) fail("item")
        if (!RE_HEX32.matches(h.device.id)) fail("device.id")
        val n = codePoints(h.device.name)
        if (h.device.name.isEmpty() || n > DEVICE_NAME_MAX) fail("device.name")
        if (h.device.kind !in KINDS) fail("device.kind")
        if (h.ts < 0) fail("ts")
        val bare = h.copy(mime = null, name = null, size = 0, fp = null, data = null, media = null, port = 0, hosts = emptyList(), offer = null, status = null)
        when (h.type) {
            "hello" -> return bare
            "reply" -> {
                if (h.offer == null || !RE_HEX32.matches(h.offer)) fail("offer")
                if (h.status !in REPLY_STATUS) fail("status")
                return bare.copy(offer = h.offer, status = h.status)
            }
        }
        val mime = h.mime ?: fail("mime")
        if (!RE_MIME.matches(mime)) fail("mime")
        if (h.size < 0) fail("size")
        if (h.fp == null || !RE_HEX32.matches(h.fp)) fail("fp")
        if (h.type == "text") {
            if (mime != TEXT_MIME) fail("text mime")
            if (h.size > Crypto.TEXT_MAX) fail("too big")
            if (h.name != null) fail("text with name")
            val data = h.data ?: fail("data")
            if (data.length % 4 != 0 || !RE_BASE64.matches(data)) fail("data")
            val decoded = try {
                Base64.getDecoder().decode(data)
            } catch (e: IllegalArgumentException) {
                fail("data")
            }
            if (decoded.size.toLong() != h.size) fail("data length")
            return bare.copy(mime = mime, size = h.size, fp = h.fp, data = data)
        }
        // offer
        if (h.media !in MEDIA) fail("media")
        if (h.media == "image" && !mime.startsWith("image/")) fail("image mime")
        if (h.size > Crypto.FILE_MAX) fail("too big")
        if (h.media == "file" && h.name == null) fail("file without name")
        if (h.name != null && (h.name.isEmpty() || codePoints(h.name) > NAME_MAX)) fail("name")
        if (h.data != null) fail("an offer carries no content")
        if (h.port !in 1..65_535) fail("port")
        if (h.hosts.isEmpty() || h.hosts.size > HOSTS_MAX || !h.hosts.all { isIPv4(it) }) fail("hosts")
        return bare.copy(mime = mime, name = h.name, size = h.size, fp = h.fp, media = h.media, port = h.port, hosts = h.hosts)
    }

    /**
     * Serializes a head like JSON.stringify in the reference order, without padding:
     * v, type, item, device{id,name,kind}, ts, then text: mime, size, fp, data; offer: media, mime,
     * name, size, fp, port, hosts; reply: offer, status. Readers accept any order; this order only
     * matters to reproduce docs/VECTORS.json byte for byte.
     */
    fun serialize(h: Head): String {
        val sb = StringBuilder(256 + (h.data?.length ?: 0))
        sb.append("{\"v\":").append(h.v)
        sb.append(",\"type\":"); str(sb, h.type)
        sb.append(",\"item\":"); str(sb, h.item)
        sb.append(",\"device\":{\"id\":"); str(sb, h.device.id)
        sb.append(",\"name\":"); str(sb, h.device.name)
        sb.append(",\"kind\":"); str(sb, h.device.kind)
        sb.append("},\"ts\":").append(h.ts)
        when (h.type) {
            "text" -> {
                sb.append(",\"mime\":"); str(sb, h.mime ?: "")
                sb.append(",\"size\":").append(h.size)
                sb.append(",\"fp\":"); str(sb, h.fp ?: "")
                sb.append(",\"data\":"); str(sb, h.data ?: "")
            }
            "offer" -> {
                sb.append(",\"media\":"); str(sb, h.media ?: "")
                sb.append(",\"mime\":"); str(sb, h.mime ?: "")
                if (h.name != null) { sb.append(",\"name\":"); str(sb, h.name) }
                sb.append(",\"size\":").append(h.size)
                sb.append(",\"fp\":"); str(sb, h.fp ?: "")
                sb.append(",\"port\":").append(h.port)
                sb.append(",\"hosts\":[")
                h.hosts.forEachIndexed { i, host -> if (i > 0) sb.append(','); str(sb, host) }
                sb.append(']')
            }
            "reply" -> {
                sb.append(",\"offer\":"); str(sb, h.offer ?: "")
                sb.append(",\"status\":"); str(sb, h.status ?: "")
            }
        }
        return sb.append('}').toString()
    }

    /** A JSON string the way JSON.stringify writes it: only quotes, backslashes and controls escaped. */
    private fun str(sb: StringBuilder, s: String) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\b' -> sb.append("\\b")
                c == '\u000C' -> sb.append("\\f")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' -> sb.append("\\u").append(String.format("%04x", c.code))
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> {
                    sb.append(c).append(s[i + 1]); i++
                }
                Character.isSurrogate(c) -> sb.append("\\u").append(String.format("%04x", c.code))
                else -> sb.append(c)
            }
            i++
        }
        sb.append('"')
    }

    /** Parses and validates a decrypted head (any field order, unknown fields and pad ignored). */
    fun parseHead(text: String): Head {
        val o = try {
            JSONObject(text)
        } catch (e: Exception) {
            throw Invalid("not JSON")
        }
        fun int(key: String): Long? = (o.opt(key) as? Number)?.let { n ->
            val l = n.toLong()
            if (n is Double || n is Float) { if (n.toDouble() != l.toDouble()) return@let null }
            l
        }
        fun string(key: String, from: JSONObject = o): String? = from.opt(key) as? String
        val d = o.optJSONObject("device") ?: throw Invalid("device")
        val type = string("type") ?: throw Invalid("type")
        val content = type == "text" || type == "offer"
        val hosts = if (o.has("hosts")) {
            val a = o.optJSONArray("hosts") ?: throw Invalid("hosts")
            if (a.length() > HOSTS_MAX) throw Invalid("hosts")
            (0 until a.length()).map { a.opt(it) as? String ?: throw Invalid("hosts") }
        } else emptyList()
        val head = Head(
            v = int("v")?.toInt() ?: throw Invalid("v"),
            type = type,
            item = string("item") ?: throw Invalid("item"),
            device = Device(
                string("id", d) ?: throw Invalid("device.id"),
                string("name", d) ?: throw Invalid("device.name"),
                string("kind", d) ?: throw Invalid("device.kind"),
            ),
            ts = int("ts") ?: throw Invalid("ts"),
            mime = string("mime"),
            name = if (o.has("name")) string("name") ?: throw Invalid("name") else null,
            size = int("size") ?: if (content) throw Invalid("size") else 0,
            fp = string("fp"),
            data = if (o.has("data")) string("data") ?: throw Invalid("data") else null,
            media = string("media"),
            port = if (o.has("port")) int("port")?.takeIf { it in 0..65_535 }?.toInt() ?: throw Invalid("port") else 0,
            hosts = hosts,
            offer = string("offer"),
            status = string("status"),
        )
        // Chunks were Clipway 0.2's way to carry images and files through the relay: refused.
        if (o.has("chunks")) throw Invalid("chunks")
        return validate(head)
    }

    // ---------------------------------------------------------------------
    // Building and opening items
    // ---------------------------------------------------------------------

    /** An item ready for the relay: its head and its one envelope. */
    class Built(val head: Head, val parts: List<Crypto.Envelope>)

    fun newItemId(): String = Crypto.hex(Crypto.randomBytes(16))

    /** Seals a head: padded, one envelope, AAD = chain id. Never larger than a 64 KiB text. */
    fun seal(keys: Keys, head: Head, nonce: ByteArray? = null): Built {
        validate(head)
        val plain = Crypto.padHead(serialize(head)).toByteArray(Charsets.UTF_8)
        require(plain.size <= Crypto.HEAD_MAX) { "head too large" }
        return Built(head, listOf(Crypto.seal(keys.enc, keys.chainId, plain, nonce ?: Crypto.randomBytes(Crypto.NONCE_SIZE))))
    }

    /** Builds a text (64 KiB at most), or a hello when [type] is "hello". */
    fun build(
        keys: Keys,
        type: String,
        device: Device,
        ts: Long,
        content: ByteArray?,
        item: String = newItemId(),
        nonce: ByteArray? = null,
    ): Built {
        require(type == "text" || type == "hello") { "texts and hellos only: images and files are offered" }
        var head = Head(type = type, item = item, device = device, ts = ts)
        if (type == "text") {
            requireNotNull(content) { "content expected" }
            head = head.copy(
                mime = TEXT_MIME, size = content.size.toLong(), fp = Crypto.fingerprint(keys.mac, content),
                data = Base64.getEncoder().encodeToString(content),
            )
        }
        return seal(keys, head, nonce)
    }

    /** An offer for an image or a file that this device serves directly on [port] (section 14). */
    fun offer(
        keys: Keys,
        device: Device,
        ts: Long,
        media: String,
        mime: String?,
        name: String?,
        content: ByteArray,
        port: Int,
        hosts: List<String>,
        item: String = newItemId(),
        nonce: ByteArray? = null,
    ): Built = seal(
        keys,
        Head(
            type = "offer", item = item, device = device, ts = ts, media = media,
            mime = if (media == "image") cleanMime(mime, "image/png") else cleanMime(mime), name = name,
            size = content.size.toLong(), fp = Crypto.fingerprint(keys.mac, content), port = port, hosts = hosts,
        ),
        nonce,
    )

    /** The answer to an offer that could not be delivered directly. */
    fun reply(keys: Keys, device: Device, ts: Long, offer: String, status: String, item: String = newItemId(), nonce: ByteArray? = null): Built =
        seal(keys, Head(type = "reply", item = item, device = device, ts = ts, offer = offer, status = status), nonce)

    /** Why an item is dropped. [ack] is false only for the device's own items (section 5.6). */
    enum class Drop(val ack: Boolean) {
        Unreadable(true), Invalid(true), Own(false), Stale(true), Duplicate(true), Parts(true), Mismatch(true)
    }

    sealed class Opened {
        class Ok(val head: Head, val content: ByteArray?) : Opened()
        class Dropped(val why: Drop) : Opened()
    }

    /** A head is fresh unless it is more than 24 h + 10 min old or more than 10 min ahead. */
    fun fresh(ts: Long, now: Long): Boolean = now - ts <= PAST_MS && ts - now <= FUTURE_MS

    /**
     * Opens an item (section 5.3): its one envelope, the rules of 3.4, then the size and fp of a
     * text. An offer older than 2 minutes is stale: its sender stopped listening.
     * [seen] is only read: the caller records the item once it is handled.
     */
    fun open(keys: Keys, parts: List<Crypto.Envelope>, now: Long, ownDeviceId: String, seen: Seen): Opened {
        if (parts.size != 1) return Opened.Dropped(Drop.Parts)
        val headText = try {
            String(Crypto.open(keys.enc, keys.chainId, parts[0]), Charsets.UTF_8)
        } catch (e: Exception) {
            return Opened.Dropped(Drop.Unreadable)
        }
        val head = try {
            parseHead(headText)
        } catch (e: IllegalArgumentException) {
            return Opened.Dropped(Drop.Invalid)
        }
        if (head.device.id == ownDeviceId) return Opened.Dropped(Drop.Own)
        if (!fresh(head.ts, now)) return Opened.Dropped(Drop.Stale)
        if (head.type == "offer" && now - head.ts > OFFER_MS) return Opened.Dropped(Drop.Stale)
        if (seen.contains(head.item, now)) return Opened.Dropped(Drop.Duplicate)
        if (head.type != "text") return Opened.Ok(head, null)
        val content = Base64.getDecoder().decode(head.data)
        if (content.size.toLong() != head.size) return Opened.Dropped(Drop.Mismatch)
        if (!Crypto.same(Crypto.fromHex(Crypto.fingerprint(keys.mac, content)), Crypto.fromHex(head.fp!!))) {
            return Opened.Dropped(Drop.Mismatch)
        }
        return Opened.Ok(head, content)
    }

    // ---------------------------------------------------------------------
    // Item ids already handled: 48 h, 2 000 at most (section 3.4)
    // ---------------------------------------------------------------------

    class Seen(private val maxAgeMs: Long = 48L * 3600 * 1000, private val max: Int = 2000) {
        private val ids = LinkedHashMap<String, Long>()

        @Synchronized
        fun contains(item: String, now: Long): Boolean {
            prune(now)
            return ids.containsKey(item)
        }

        @Synchronized
        fun add(item: String, now: Long) {
            ids.remove(item)
            ids[item] = now
            prune(now)
        }

        @Synchronized
        fun size() = ids.size

        private fun prune(now: Long) {
            val it = ids.entries.iterator()
            while (it.hasNext()) {
                val e = it.next()
                if (now - e.value > maxAgeMs || ids.size > max) it.remove() else break
            }
        }

        /** "id:ts,id:ts", oldest first. */
        @Synchronized
        fun encode(): String = ids.entries.joinToString(",") { "${it.key}:${it.value}" }

        companion object {
            fun decode(text: String?, now: Long): Seen {
                val s = Seen()
                text?.split(',')?.forEach { e ->
                    val i = e.indexOf(':')
                    if (i == 32) e.substring(i + 1).toLongOrNull()?.let { ts -> s.ids[e.substring(0, i)] = ts }
                }
                s.prune(now)
                return s
            }
        }
    }

    // ---------------------------------------------------------------------
    // Received file names (section 3.5)
    // ---------------------------------------------------------------------

    /**
     * Never trusted as a path: separators, control and format characters and leading dots removed,
     * trimmed to 120 characters (the extension kept when possible), "file" if nothing is left.
     */
    fun safeFileName(name: String?): String {
        val sb = StringBuilder()
        (name ?: "").codePoints().forEach { cp ->
            val bad = cp == '/'.code || cp == '\\'.code || cp < 0x20 || cp == 0x7f ||
                Character.getType(cp) == Character.FORMAT.toInt() || cp in 0x80..0x9f
            if (!bad) sb.appendCodePoint(cp)
        }
        var s = sb.toString().trim().trimStart('.').trim()
        if (s.isEmpty()) return "file"
        if (codePoints(s) > FILE_NAME_KEEP) {
            val dot = s.lastIndexOf('.')
            val ext = if (dot > 0 && s.length - dot in 2..16) s.substring(dot) else ""
            val keep = FILE_NAME_KEEP - codePoints(ext)
            s = s.substring(0, s.offsetByCodePoints(0, keep)).trimEnd() + ext
        }
        return s
    }

    /** "photo.jpg" and 2 give "photo 2.jpg". */
    fun numbered(name: String, n: Int): String {
        if (n < 2) return name
        val dot = name.lastIndexOf('.')
        return if (dot > 0) name.substring(0, dot) + " $n" + name.substring(dot) else "$name $n"
    }

    /** The first free name among name, "name 2", "name 3"... */
    fun freeName(name: String, taken: Set<String>): String {
        if (name !in taken) return name
        var n = 2
        while (numbered(name, n) in taken) n++
        return numbered(name, n)
    }

    /** File extension for an image type, for the private clipboard copies. */
    fun extensionFor(mime: String?): String = when (mime) {
        "image/png" -> "png"
        "image/jpeg" -> "jpg"
        "image/webp" -> "webp"
        "image/gif" -> "gif"
        "image/heic" -> "heic"
        "image/heif" -> "heif"
        "image/tiff" -> "tiff"
        "image/bmp" -> "bmp"
        else -> "bin"
    }

    /** Lowercase type/subtype without parameters, or the default when it does not look like a type. */
    fun cleanMime(mime: String?, fallback: String = "application/octet-stream"): String {
        val m = mime?.substringBefore(';')?.trim()?.lowercase() ?: return fallback
        return if (RE_MIME.matches(m)) m else fallback
    }

    // ---------------------------------------------------------------------
    // What may be sent (section 5.4)
    // ---------------------------------------------------------------------

    /** The clip description extra that marks a clip as sensitive (ClipDescription.EXTRA_IS_SENSITIVE). */
    const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"

    enum class Refusal { Empty, Sensitive, TooLarge }

    /** Why a content cannot be sent, or null when it can. Sensitive content is never sent. */
    fun refusal(type: String, size: Long, sensitive: Boolean): Refusal? = when {
        sensitive -> Refusal.Sensitive
        size <= 0 && type != "file" -> Refusal.Empty
        size > maxSize(type) -> Refusal.TooLarge
        else -> null
    }

    // ---------------------------------------------------------------------
    // Relay address (section 5.1)
    // ---------------------------------------------------------------------

    val LOCAL_HOSTS = setOf("127.0.0.1", "localhost", "10.0.2.2")

    /** Trims spaces and trailing slashes. */
    /** Trims spaces and trailing slashes, and lowercases the scheme and host ("Http://..." from a keyboard). */
    fun normalizeRelay(text: String): String {
        val t = text.trim().trimEnd('/')
        val i = t.indexOf("://")
        if (i <= 0) return t
        val rest = t.substring(i + 3)
        val end = rest.indexOf('/').let { if (it < 0) rest.length else it }
        return t.substring(0, i).lowercase() + "://" + rest.substring(0, end).lowercase() + rest.substring(end)
    }

    /** https:// only; plain http:// only in debug builds and only to this computer. */
    fun relayAllowed(text: String, allowLocalHttp: Boolean): Boolean {
        val u = try {
            URI(normalizeRelay(text))
        } catch (e: Exception) {
            return false
        }
        val host = u.host ?: return false
        if (u.rawUserInfo != null || u.rawQuery != null || u.rawFragment != null) return false
        return when (u.scheme) {
            "https" -> host.isNotEmpty()
            "http" -> allowLocalHttp && host.lowercase() in LOCAL_HOSTS
            else -> false
        }
    }

    /** https://host gives wss://host/ws, http://127.0.0.1:7710 gives ws://127.0.0.1:7710/ws. */
    fun webSocketUrl(relay: String): String {
        val r = normalizeRelay(relay)
        return when {
            r.startsWith("https://") -> "wss://" + r.removePrefix("https://") + "/ws"
            r.startsWith("http://") -> "ws://" + r.removePrefix("http://") + "/ws"
            else -> throw IllegalArgumentException("relay")
        }
    }

    /** The host (and port) shown to people. */
    fun relayHost(relay: String): String = try {
        val u = URI(normalizeRelay(relay))
        (u.host ?: relay) + if (u.port > 0) ":${u.port}" else ""
    } catch (e: Exception) {
        relay
    }

    // ---------------------------------------------------------------------
    // Frames (section 4.2)
    // ---------------------------------------------------------------------

    object Frames {
        fun sync(epoch: String, after: Long) = JSONObject().put("kind", "sync").put("epoch", epoch).put("after", after).toString()
        fun ack(seq: Long) = """{"kind":"ack","seq":$seq}"""
        const val PING = """{"kind":"ping"}"""

        /** Built by hand: the blob can be 1.4 MB, and org.json would copy it twice. */
        fun item(ref: Int, part: Int, parts: Int, e: Crypto.Envelope): String =
            StringBuilder(e.enc.length + 120).append("{\"kind\":\"item\",\"ref\":").append(ref)
                .append(",\"part\":").append(part).append(",\"parts\":").append(parts)
                .append(",\"blob\":{\"nonce\":\"").append(e.nonce).append("\",\"enc\":\"").append(e.enc).append("\"}}").toString()
    }

    /** A frame from the relay. Anything unknown or malformed is [Other]. */
    sealed class Incoming {
        class Welcome(val epoch: String, val devices: Int) : Incoming()
        class Synced(val last: Long) : Incoming()
        class Item(val seq: Long, val part: Int, val parts: Int, val ts: Long, val blob: Crypto.Envelope) : Incoming()
        class Stored(val ref: Int, val seq: Long) : Incoming()
        class Delivered(val seq: Long) : Incoming()
        class Presence(val devices: Int) : Incoming()
        object Pong : Incoming()
        class Error(val ref: Int?, val code: String) : Incoming()
        object Other : Incoming()
    }

    private val RE_NONCE = Regex("^[0-9a-f]{24}$")

    fun parseFrame(text: String): Incoming = try {
        val o = JSONObject(text)
        when (o.optString("kind")) {
            "welcome" -> Incoming.Welcome(o.getString("epoch"), o.optInt("devices", 1))
            "synced" -> Incoming.Synced(o.getLong("last"))
            "item" -> {
                val b = o.getJSONObject("blob")
                val nonce = b.getString("nonce")
                if (!RE_NONCE.matches(nonce)) Incoming.Other
                else Incoming.Item(o.getLong("seq"), o.getInt("part"), o.getInt("parts"), o.optLong("ts"), Crypto.Envelope(nonce, b.getString("enc")))
            }
            "stored" -> Incoming.Stored(o.getInt("ref"), o.getLong("seq"))
            "delivered" -> Incoming.Delivered(o.getLong("seq"))
            "presence" -> Incoming.Presence(o.getInt("devices"))
            "pong" -> Incoming.Pong
            "error" -> Incoming.Error(if (o.isNull("ref")) null else o.optInt("ref"), o.optString("code"))
            else -> Incoming.Other
        }
    } catch (e: Exception) {
        Incoming.Other
    }
}
