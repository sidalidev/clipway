package dev.sidali.clipway

/**
 * The client side of the relay protocol (docs/PROTOCOL.md, sections 4 and 5), without Android or
 * network code: the service feeds it frames and gives it a [Wire] to write to. Everything runs on
 * one thread (the service's worker), so there is no locking here except in [Outbox].
 *
 * Rules it keeps: nothing is sent before `synced`; one upload at a time, kept until `stored` and
 * sent again after a reconnection; parts of an item are collected in order and handed over once
 * complete; an ack only after the item is handled; `after` never moves past an item in progress.
 */
class Engine(
    private val keys: Protocol.Keys,
    private val outbox: Outbox,
    private val cursor: Cursor,
    private val events: Events,
) {
    /** The socket, seen from the engine. */
    interface Wire {
        fun send(text: String): Boolean
        fun queueSize(): Long
    }

    /** Where (epoch, after) is kept between connections and restarts. */
    interface Cursor {
        var epoch: String
        var after: Long
    }

    interface Events {
        /** A complete item. Returns true when it is handled (or dropped on purpose) and may be acknowledged. */
        fun onDelivery(seq: Long, parts: List<Crypto.Envelope>): Delivery

        fun onSynced()
        fun onPresence(devices: Int)

        /** The relay holds an item we sent. */
        fun onStored(item: String, seq: Long, othersOnline: Boolean)

        /** Another device acknowledged an item we sent. */
        fun onDelivered(seq: Long)

        /** The relay refused an item for good (too big, malformed). */
        fun onRefused(item: String, code: String)

        /** The relay asked to slow down: try the outbox again later. */
        fun onBackOff(ms: Long)
    }

    /** What to do with a complete item once handled. */
    enum class Delivery { Ack, NoAck, Retry }

    var synced = false
        private set
    var devices = 1
        private set
    /** The most parts of one item the relay takes, from welcome: 1 means images and files only go directly. */
    @Volatile
    var relayParts = 1
        private set
    /** The largest frame the relay takes, from welcome (never more than [Protocol.FRAME_MAX]). */
    var frameMax = Protocol.FRAME_MAX
        private set
    private var wire: Wire? = null
    private var epoch = ""

    /** Upload in progress: the item, its ref and the next part to write. */
    private var upload: Outbox.Pending? = null
    private var ref = 0
    private var nextPart = 0
    private var holdUntil = 0L

    /**
     * Connections cut while the same item was being uploaded, before `stored`. An item the relay
     * keeps closing the connection on (a frame over its limit: close code 1009) is dropped after
     * [CUTS_MAX] tries instead of being sent again forever.
     */
    private var cutItem: String? = null
    private var cuts = 0

    /** Item being received. */
    private var inSeq = -1L
    private val inParts = ArrayList<Crypto.Envelope>()
    private var inCount = 0

    /** Seq numbers of our own uploads, to match `delivered`. */
    private val mine = LinkedHashMap<Long, String>()

    fun attach(w: Wire) {
        wire = w
        synced = false
        upload = null
        nextPart = 0
        resetIncoming()
    }

    /**
     * The connection is gone, with the WebSocket close [code] when there is one. An upload cut in
     * the middle is sent again after the next sync, unless the relay closed with 1009 (a frame too
     * big for it) or the same item was cut [CUTS_MAX] times in a row: then it fails, once.
     */
    fun detach(code: Int = 1000) {
        val u = upload
        if (u != null && nextPart > 0) {
            if (cutItem == u.item) cuts++ else { cutItem = u.item; cuts = 1 }
            if (code == CLOSE_TOO_BIG || cuts >= CUTS_MAX) {
                outbox.remove(u.item)
                cutItem = null
                cuts = 0
                events.onRefused(u.history, if (code == CLOSE_TOO_BIG) "too_big" else "cut")
            }
        }
        wire = null
        synced = false
        // The upload in progress is sent again, from part 0 and with a new ref, after the next sync.
        upload = null
        nextPart = 0
        resetIncoming()
    }

    private fun resetIncoming() {
        inSeq = -1L
        inParts.clear()
        inCount = 0
    }

    /** Handles one text frame from the relay. */
    fun onFrame(text: String, now: Long) {
        when (val f = Protocol.parseFrame(text)) {
            is Protocol.Incoming.Welcome -> {
                epoch = f.epoch
                devices = f.devices
                relayParts = f.parts
                frameMax = f.frame.coerceIn(FRAME_MIN, Protocol.FRAME_MAX)
                events.onPresence(devices)
                // The stored epoch (not the new one): a different epoch makes the relay send its whole queue.
                val after = if (cursor.epoch == f.epoch) cursor.after else 0L
                wire?.send(Protocol.Frames.sync(cursor.epoch, after))
            }
            is Protocol.Incoming.Item -> onPart(f)
            is Protocol.Incoming.Synced -> {
                // Every item of the backlog came before synced and has been handled on this thread.
                if (cursor.epoch != epoch) {
                    cursor.epoch = epoch
                    cursor.after = f.last
                } else if (f.last > cursor.after) {
                    cursor.after = f.last
                }
                synced = true
                events.onSynced()
                pump(now)
            }
            is Protocol.Incoming.Stored -> {
                val u = upload
                if (u != null && f.ref == ref) {
                    upload = null
                    nextPart = 0
                    if (cutItem == u.item) { cutItem = null; cuts = 0 }
                    outbox.remove(u.item)
                    mine[f.seq] = u.history
                    while (mine.size > 200) mine.remove(mine.keys.first())
                    if (f.seq > cursor.after) cursor.after = f.seq
                    events.onStored(u.history, f.seq, devices > 1)
                    pump(now)
                }
            }
            is Protocol.Incoming.Delivered -> if (mine.remove(f.seq) != null) events.onDelivered(f.seq)
            is Protocol.Incoming.Presence -> {
                devices = f.devices
                events.onPresence(devices)
            }
            is Protocol.Incoming.Error -> onError(f, now)
            Protocol.Incoming.Pong, Protocol.Incoming.Other -> Unit
        }
    }

    private fun onPart(f: Protocol.Incoming.Item) {
        if (f.parts !in 1..Protocol.PARTS_MAX || f.part !in 0 until f.parts) return
        if (f.part == 0) {
            resetIncoming()
            inSeq = f.seq
            inCount = f.parts
        } else if (f.seq != inSeq || f.part != inParts.size || f.parts != inCount) {
            // Out of order: the relay never does this; drop what we have.
            resetIncoming()
            return
        }
        inParts += f.blob
        if (inParts.size < inCount) return
        val seq = inSeq
        val parts = ArrayList(inParts)
        resetIncoming()
        when (events.onDelivery(seq, parts)) {
            Delivery.Ack -> {
                wire?.send(Protocol.Frames.ack(seq))
                if (seq > cursor.after) cursor.after = seq
            }
            // Our own item, delivered back: never acknowledged, but handled.
            Delivery.NoAck -> if (seq > cursor.after) cursor.after = seq
            // Not handled (storage full, for example): the relay sends it again at the next connection.
            Delivery.Retry -> Unit
        }
    }

    private fun onError(f: Protocol.Incoming.Error, now: Long) {
        val u = upload ?: return
        if (f.ref != null && f.ref != ref) return
        when (f.code) {
            "too_big", "bad_request" -> {
                upload = null
                nextPart = 0
                outbox.remove(u.item)
                events.onRefused(u.history, f.code)
                pump(now)
            }
            "incomplete" -> {
                upload = null
                nextPart = 0
                pump(now)
            }
            else -> {
                // rate_limited, quota, busy: keep the item, try again later.
                upload = null
                nextPart = 0
                holdUntil = now + BACK_OFF_MS
                events.onBackOff(BACK_OFF_MS)
            }
        }
    }

    /**
     * Writes as many parts as the socket buffer allows. Returns true when parts are still waiting
     * for room (the caller runs it again shortly): OkHttp closes a socket whose queue passes 16 MiB.
     */
    fun pump(now: Long): Boolean {
        val w = wire ?: return false
        if (!synced || now < holdUntil) return false
        while (true) {
            var u = upload
            if (u == null) {
                u = outbox.next() ?: return false
                upload = u
                ref = (ref + 1) and Int.MAX_VALUE
                nextPart = 0
            }
            // Never a frame over the relay's limit: it would close the connection (1009), and the
            // item would be sent again at every reconnection. Checked for every part before the first.
            if (nextPart == 0 && !Outbox.fits(u, frameMax)) {
                upload = null
                outbox.remove(u.item)
                events.onRefused(u.history, "too_big")
                continue
            }
            while (nextPart < u.parts.size) {
                if (w.queueSize() > QUEUE_HIGH) return true
                if (!w.send(Protocol.Frames.item(ref, nextPart, u.parts.size, u.parts[nextPart]))) return false
                nextPart++
            }
            return false
        }
    }

    /** Application heartbeat. */
    fun ping(): Boolean = wire?.send(Protocol.Frames.PING) ?: false

    companion object {
        /** Bytes queued in the socket above which the next part waits. */
        const val QUEUE_HIGH = 4L * 1_048_576
        const val BACK_OFF_MS = 30_000L
        /** WebSocket close code "message too big", sent by the relay's WebSocket library. */
        const val CLOSE_TOO_BIG = 1009
        const val CUTS_MAX = 3
        /** A relay announcing a smaller frame than this is not believed (it could not carry a text). */
        const val FRAME_MIN = 16 * 1024
        /** Room the relay keeps in a frame for the fields it adds when it forwards a part (seq, ts). */
        const val FRAME_SLACK = 256
    }
}

/**
 * Items waiting to be sent, in order. Shared by the activities that send (tile, share, text
 * selection) and the service. An item stays here until the relay answers `stored`.
 */
class Outbox {
    /**
     * [history]: the history row this item updates. The same as [item], except for an image or a
     * file sent through the relay after its direct offer failed: a new item, the same row.
     */
    class Pending(val item: String, val type: String, val fp: String, val parts: List<Crypto.Envelope>, val history: String = item)

    private val queue = ArrayDeque<Pending>()

    /** Queues [p], unless it is already there or one of its frames could never be sent. */
    @Synchronized
    fun add(p: Pending): Boolean {
        if (!fits(p)) return false
        if (queue.none { it.item == p.item }) queue.addLast(p)
        return true
    }

    /**
     * Removes what can never be sent (a frame over [frameMax]) and returns it, so that the caller
     * marks it failed. Run when the service starts; the engine checks again before each upload.
     */
    @Synchronized
    fun purge(frameMax: Int = Protocol.FRAME_MAX): List<Pending> {
        val bad = queue.filter { !fits(it, frameMax) }
        queue.removeAll(bad.toSet())
        return bad
    }

    @Synchronized
    fun next(): Pending? = queue.firstOrNull()

    @Synchronized
    fun remove(item: String) {
        queue.removeAll { it.item == item }
    }

    @Synchronized
    fun size() = queue.size

    @Synchronized
    fun clear() = queue.clear()

    companion object {
        /**
         * Every part of [p] fits in one frame of [frameMax] bytes, with the room the relay keeps
         * when it forwards it: the relay closes the connection on a larger frame. Frames are ASCII.
         */
        fun fits(p: Pending, frameMax: Int = Protocol.FRAME_MAX): Boolean =
            p.parts.isNotEmpty() && p.parts.size <= Protocol.PARTS_MAX && p.parts.all { e ->
                frameLength(e, p.parts.size) <= frameMax && e.enc.length + Engine.FRAME_SLACK <= frameMax
            }

        /** Bytes of the item frame of [e] (with the largest ref and part numbers). */
        fun frameLength(e: Crypto.Envelope, parts: Int): Int =
            Protocol.Frames.item(Int.MAX_VALUE, parts - 1, parts, e).length
    }
}
