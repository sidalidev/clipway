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
    private var wire: Wire? = null
    private var epoch = ""

    /** Upload in progress: the item, its ref and the next part to write. */
    private var upload: Outbox.Pending? = null
    private var ref = 0
    private var nextPart = 0
    private var holdUntil = 0L

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

    fun detach() {
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
                    outbox.remove(u.item)
                    mine[f.seq] = u.item
                    while (mine.size > 200) mine.remove(mine.keys.first())
                    if (f.seq > cursor.after) cursor.after = f.seq
                    events.onStored(u.item, f.seq, devices > 1)
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
                events.onRefused(u.item, f.code)
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
        var u = upload
        if (u == null) {
            u = outbox.next() ?: return false
            upload = u
            ref = (ref + 1) and Int.MAX_VALUE
            nextPart = 0
        }
        while (nextPart < u.parts.size) {
            if (w.queueSize() > QUEUE_HIGH) return true
            if (!w.send(Protocol.Frames.item(ref, nextPart, u.parts.size, u.parts[nextPart]))) return false
            nextPart++
        }
        return false
    }

    /** Application heartbeat. */
    fun ping(): Boolean = wire?.send(Protocol.Frames.PING) ?: false

    companion object {
        /** Bytes queued in the socket above which the next part waits. */
        const val QUEUE_HIGH = 4L * 1_048_576
        const val BACK_OFF_MS = 30_000L
    }
}

/**
 * Items waiting to be sent, in order. Shared by the activities that send (tile, share, text
 * selection) and the service. An item stays here until the relay answers `stored`.
 */
class Outbox {
    class Pending(val item: String, val type: String, val fp: String, val parts: List<Crypto.Envelope>)

    private val queue = ArrayDeque<Pending>()

    @Synchronized
    fun add(p: Pending) {
        if (queue.none { it.item == p.item }) queue.addLast(p)
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
}
