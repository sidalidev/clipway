package dev.sidali.clipway

import java.io.DataInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Direct transfer of images and files (docs/PROTOCOL.md, section 14). They never go through the
 * relay: the sender listens on the local network and sends an offer through the relay; the
 * receiver connects, proves it holds the chain key, and the content comes encrypted with a key of
 * that transfer only. Pure JVM (java.net and javax.crypto), tested against docs/VECTORS.json and
 * on the loopback interface.
 *
 *   K_t = HKDF(K_direct, "clipway-direct|" + transfer)
 *   receiver: "CWD1" || transfer (16 bytes), then get 0 {"v":1,"get":transfer}
 *   sender:   put 0..n-1, 65 536 bytes of content each
 *   receiver: get 1 {"v":1,"status":"done"} once the content is checked and written
 *   record:   length (4, big-endian) || nonce (12) || ciphertext || tag (16), AAD "clipway-direct|<t>|<dir>|<i>"
 */
object Direct {
    const val MAGIC = "CWD1"
    const val PREAMBLE = 20
    const val RECORD_DATA = 65_536
    const val RECORD_MAX = Crypto.NONCE_SIZE + RECORD_DATA + Crypto.TAG_SIZE
    const val GET_MAX = 1024
    const val CONNECT_EACH_MS = 3_000
    const val CONNECT_TOTAL_MS = 12_000L
    const val IDLE_MS = 15_000
    const val HANDSHAKE_MS = 5_000
    const val UNPROVEN_MAX = 8

    /** Debug builds listen here when it is free, so `adb forward tcp:7721 tcp:7721` reaches the emulator. */
    const val DEBUG_PORT = 7721

    // -----------------------------------------------------------------
    // Keys and records
    // -----------------------------------------------------------------

    /** K_t = HKDF-SHA256(K_direct, empty salt, "clipway-direct|" + transfer, 32). */
    fun transferKey(kDirect: ByteArray, transfer: String): ByteArray {
        require(Regex("^[0-9a-f]{32}$").matches(transfer)) { "transfer id" }
        return Crypto.hkdf(kDirect, ByteArray(0), "clipway-direct|$transfer".toByteArray(Charsets.UTF_8), 32)
    }

    fun aad(transfer: String, dir: String, index: Int) = "clipway-direct|$transfer|$dir|$index"

    fun preamble(transfer: String): ByteArray = MAGIC.toByteArray(Charsets.US_ASCII) + Crypto.fromHex(transfer)

    /** The transfer id of a preamble, or null. */
    fun readPreamble(bytes: ByteArray): String? {
        if (bytes.size != PREAMBLE || String(bytes, 0, 4, Charsets.US_ASCII) != MAGIC) return null
        return Crypto.hex(bytes.copyOfRange(4, PREAMBLE))
    }

    /** A record on the wire, length first. Never pass a fixed nonce outside tests. */
    fun sealRecord(kT: ByteArray, transfer: String, dir: String, index: Int, plain: ByteArray, nonce: ByteArray = Crypto.randomBytes(Crypto.NONCE_SIZE)): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(kT, "AES"), GCMParameterSpec(Crypto.TAG_SIZE * 8, nonce))
        c.updateAAD(aad(transfer, dir, index).toByteArray(Charsets.UTF_8))
        val sealed = c.doFinal(plain)
        return ByteBuffer.allocate(4 + Crypto.NONCE_SIZE + sealed.size).putInt(Crypto.NONCE_SIZE + sealed.size).put(nonce).put(sealed).array()
    }

    /** Opens a record body (without its length). Throws if anything does not match. */
    fun openRecord(kT: ByteArray, transfer: String, dir: String, index: Int, body: ByteArray): ByteArray {
        require(body.size in (Crypto.NONCE_SIZE + Crypto.TAG_SIZE)..RECORD_MAX) { "record size" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(kT, "AES"), GCMParameterSpec(Crypto.TAG_SIZE * 8, body, 0, Crypto.NONCE_SIZE))
        c.updateAAD(aad(transfer, dir, index).toByteArray(Charsets.UTF_8))
        return c.doFinal(body, Crypto.NONCE_SIZE, body.size - Crypto.NONCE_SIZE)
    }

    fun recordCount(size: Long): Int = ((size + RECORD_DATA - 1) / RECORD_DATA).toInt()

    fun getRequest(transfer: String) = """{"v":1,"get":"$transfer"}"""
    fun getStatus(status: String) = """{"v":1,"status":"$status"}"""

    // -----------------------------------------------------------------
    // Addresses: the local network only
    // -----------------------------------------------------------------

    /** 10/8, 172.16/12, 192.168/16 and link-local 169.254/16. */
    fun isPrivate(host: String): Boolean {
        if (!Protocol.isIPv4(host)) return false
        val (a, b) = host.split('.').map { it.toInt() }
        return a == 10 || (a == 172 && b in 16..31) || (a == 192 && b == 168) || (a == 169 && b == 254)
    }

    /** Release builds connect to the local network only; debug builds also to this computer (emulator). */
    fun mayConnect(host: String, debug: Boolean): Boolean =
        isPrivate(host) || (debug && (host == "127.0.0.1" || host == "10.0.2.2"))

    /** This device's private IPv4 addresses, the ones an offer lists (8 at most). */
    fun localHosts(): List<String> = try {
        NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            .filter { runCatching { it.isUp && !it.isLoopback }.getOrDefault(false) }
            .flatMap { it.inetAddresses.toList() }
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
            .filter { isPrivate(it) }
            .distinct()
            .take(Protocol.HOSTS_MAX)
    } catch (e: Exception) {
        emptyList()
    }

    // -----------------------------------------------------------------
    // Streams
    // -----------------------------------------------------------------

    private fun readRecord(input: DataInputStream, max: Int): ByteArray {
        val length = input.readInt()
        if (length < Crypto.NONCE_SIZE + Crypto.TAG_SIZE || length > max) throw IOException("record size")
        return ByteArray(length).also { input.readFully(it) }
    }

    private fun json(bytes: ByteArray) = org.json.JSONObject(String(bytes, Charsets.UTF_8))

    // -----------------------------------------------------------------
    // Sender: listens while it has offers open, serves each one once
    // -----------------------------------------------------------------

    /** What happened to an offer: delivered, failed, nobody came in time, or a reply said why. */
    enum class Outcome { Done, Failed, Expired, Unreachable, Declined }

    /**
     * The listening side. [offer] registers a content and returns the port; [onOutcome] is called
     * once per offer, on a background thread. The socket closes when no offer is open.
     */
    class Server(private val preferredPort: Int = 0, private val ttlMs: Long = Protocol.OFFER_MS) {
        private class Pending(val key: ByteArray, val content: ByteArray, val onOutcome: (Outcome) -> Unit, val deadline: Long) {
            @Volatile var taken = false
        }

        private val pending = ConcurrentHashMap<String, Pending>()
        private val pool = Executors.newCachedThreadPool { r -> Thread(r, "clipway-direct").apply { isDaemon = true } }
        private val unproven = AtomicInteger(0)
        private var socket: ServerSocket? = null

        val port: Int get() = socket?.localPort ?: 0

        fun isOpen(transfer: String) = pending.containsKey(transfer)

        /** Starts listening if needed and registers the offer. Returns the port, or throws. */
        @Synchronized
        fun offer(transfer: String, key: ByteArray, content: ByteArray, onOutcome: (Outcome) -> Unit): Int {
            require(content.size <= Crypto.FILE_MAX) { "too large" }
            val s = socket ?: open().also { socket = it }
            pending[transfer] = Pending(key, content, onOutcome, System.currentTimeMillis() + ttlMs)
            pool.execute {
                try {
                    Thread.sleep(ttlMs)
                } catch (_: InterruptedException) {
                }
                finish(transfer, Outcome.Expired)
            }
            return s.localPort
        }

        /** A reply came through the relay: stop waiting for this offer. */
        fun cancel(transfer: String, outcome: Outcome) = finish(transfer, outcome)

        private fun open(): ServerSocket {
            val s = ServerSocket()
            s.reuseAddress = true
            try {
                s.bind(InetSocketAddress(preferredPort))
            } catch (e: IOException) {
                if (preferredPort == 0) throw e
                s.bind(InetSocketAddress(0))
            }
            pool.execute { accept(s) }
            return s
        }

        private fun accept(s: ServerSocket) {
            while (!s.isClosed) {
                val c = try {
                    s.accept()
                } catch (e: IOException) {
                    break
                }
                if (unproven.incrementAndGet() > UNPROVEN_MAX) {
                    unproven.decrementAndGet()
                    runCatching { c.close() }
                    continue
                }
                pool.execute { serve(c) }
            }
        }

        private fun serve(c: Socket) {
            var proven = false
            var transfer: String? = null
            try {
                c.soTimeout = HANDSHAKE_MS
                c.tcpNoDelay = true
                val input = DataInputStream(c.getInputStream().buffered())
                val head = ByteArray(PREAMBLE).also { input.readFully(it) }
                val t = readPreamble(head) ?: throw IOException("preamble")
                val p = pending[t] ?: throw IOException("unknown transfer")
                val request = json(openRecord(p.key, t, "get", 0, readRecord(input, GET_MAX)))
                if (request.optInt("v") != 1 || request.optString("get") != t) throw IOException("request")
                synchronized(p) {
                    if (p.taken) throw IOException("taken")
                    p.taken = true
                }
                proven = true
                transfer = t
                unproven.decrementAndGet()
                c.soTimeout = IDLE_MS
                val out = c.getOutputStream().buffered(RECORD_MAX + 8)
                for (i in 0 until recordCount(p.content.size.toLong())) {
                    val from = i * RECORD_DATA
                    out.write(sealRecord(p.key, t, "put", i, p.content.copyOfRange(from, minOf(p.content.size, from + RECORD_DATA))))
                }
                out.flush()
                val answer = json(openRecord(p.key, t, "get", 1, readRecord(input, GET_MAX)))
                finish(t, if (answer.optInt("v") == 1 && answer.optString("status") == "done") Outcome.Done else Outcome.Failed)
            } catch (e: Exception) {
                transfer?.let { finish(it, Outcome.Failed) }
            } finally {
                if (!proven) unproven.decrementAndGet()
                runCatching { c.close() }
            }
        }

        private fun finish(transfer: String, outcome: Outcome) {
            val p = pending.remove(transfer) ?: return
            try {
                p.onOutcome(outcome)
            } catch (_: Exception) {
            }
            synchronized(this) {
                if (pending.isEmpty()) {
                    runCatching { socket?.close() }
                    socket = null
                }
            }
        }

        fun close() {
            synchronized(this) {
                runCatching { socket?.close() }
                socket = null
            }
            pending.clear()
        }
    }

    // -----------------------------------------------------------------
    // Receiver: connects to an offer and fetches its content
    // -----------------------------------------------------------------

    sealed class Fetched {
        class Ok(val content: ByteArray) : Fetched()
        /** No address answered: not on the same network. */
        object Unreachable : Fetched()
        /** Connected, but the transfer broke or the content did not match. */
        object Failed : Fetched()
    }

    /**
     * Fetches the content of an offer [head]. [save] runs once the size and fingerprint are checked;
     * get 1 "done" is sent when it returns, "failed" when it throws.
     */
    fun fetch(keys: Protocol.Keys, head: Protocol.Head, debug: Boolean, save: (ByteArray) -> Unit): Fetched {
        val kT = transferKey(keys.direct, head.item)
        val started = System.currentTimeMillis()
        val hosts = (head.hosts + if (debug) listOf("10.0.2.2") else emptyList()).filter { mayConnect(it, debug) }.distinct()
        var reached = false
        for (host in hosts) {
            val left = CONNECT_TOTAL_MS - (System.currentTimeMillis() - started)
            if (left <= 0) break
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(host, head.port), minOf(CONNECT_EACH_MS.toLong(), left).toInt())
            } catch (e: Exception) {
                runCatching { socket.close() }
                continue
            }
            reached = true
            return socket.use { s -> transfer(s, kT, keys, head, save) }
        }
        return if (reached) Fetched.Failed else Fetched.Unreachable
    }

    private fun transfer(s: Socket, kT: ByteArray, keys: Protocol.Keys, head: Protocol.Head, save: (ByteArray) -> Unit): Fetched {
        val t = head.item
        return try {
            s.soTimeout = IDLE_MS
            s.tcpNoDelay = true
            val out: OutputStream = s.getOutputStream()
            out.write(preamble(t) + sealRecord(kT, t, "get", 0, getRequest(t).toByteArray(Charsets.UTF_8)))
            out.flush()
            val input = DataInputStream(s.getInputStream().buffered(RECORD_MAX + 8))
            val size = head.size.toInt()
            val content = ByteArray(size)
            var at = 0
            for (i in 0 until recordCount(head.size)) {
                val chunk = openRecord(kT, t, "put", i, readRecord(input, RECORD_MAX))
                if (at + chunk.size > size || (chunk.size != RECORD_DATA && at + chunk.size != size)) throw IOException("size")
                System.arraycopy(chunk, 0, content, at, chunk.size)
                at += chunk.size
            }
            if (at != size || !Crypto.same(Crypto.fromHex(Crypto.fingerprint(keys.mac, content)), Crypto.fromHex(head.fp ?: ""))) {
                throw IOException("fingerprint")
            }
            val saved = runCatching { save(content) }.isSuccess
            out.write(sealRecord(kT, t, "get", 1, getStatus(if (saved) "done" else "failed").toByteArray(Charsets.UTF_8)))
            out.flush()
            if (saved) Fetched.Ok(content) else Fetched.Failed
        } catch (e: Exception) {
            // Timeout, closed connection, a record that does not open, a wrong fingerprint.
            Fetched.Failed
        }
    }
}
