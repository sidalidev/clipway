package dev.sidali.clipway

import android.app.Activity
import android.app.PendingIntent
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import android.view.HapticFeedbackConstants
import android.widget.Toast
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors

/**
 * Sending from the phone (docs/PROTOCOL.md, sections 5.2, 5.4 and 6). Local first: the item goes
 * to history at once, then it is sealed and queued, and the service sends it after `synced`.
 */
object Sender {
    val outbox = Outbox()
    private val worker = Executors.newSingleThreadExecutor()

    @Volatile
    private var echoFp: String? = null

    @Volatile
    private var echoAt = 0L

    class Outgoing(val type: String, val content: ByteArray, val mime: String? = null, val name: String? = null)

    enum class Result { Sent, Waiting, Direct, NoLocalNetwork, NotPaired, Paused, Empty, Nothing, Sensitive, TooLarge, TooLong, Repeated }

    /** Images and files are served from here, on the local network, never through the relay. */
    val direct = Direct.Server(if (BuildConfig.DEBUG) Direct.DEBUG_PORT else 0)

    /** The same content sent or received less than 10 s ago is not sent again. */
    fun noteEcho(fp: String?) {
        echoFp = fp
        echoAt = System.currentTimeMillis()
    }

    fun send(context: Context, o: Outgoing, sensitive: Boolean = false): Result {
        val c = context.applicationContext ?: context
        when (Protocol.refusal(o.type, o.content.size.toLong(), sensitive)) {
            Protocol.Refusal.Sensitive -> return Result.Sensitive
            Protocol.Refusal.Empty -> return Result.Empty
            Protocol.Refusal.TooLarge -> return if (o.type == "text") Result.TooLong else Result.TooLarge
            null -> Unit
        }
        val keys = Vault.keys(c) ?: return Result.NotPaired
        val fp = Crypto.fingerprint(keys.mac, o.content)
        val now = System.currentTimeMillis()
        if (fp == echoFp && now - echoAt < Protocol.ECHO_MS) return Result.Repeated
        noteEcho(fp)
        val prefs = Prefs(c)
        val device = Protocol.Device(prefs.deviceId, prefs.deviceName, "android")
        val item = Protocol.newItemId()
        // Started now, while the sending activity is in the foreground: Android allows it.
        if (ClipService.instance == null) ClipService.start(c, ClipService.ACTION_PUMP)
        if (o.type != "text") return offer(c, o, keys, device, item, fp, now)
        worker.execute {
            try {
                val keep = o.type == "text" || o.type == "image"
                History.add(
                    c,
                    History.Entry(
                        item = item, type = o.type, outgoing = true, device = device.name, ts = now, mime = o.mime,
                        name = o.name, size = o.content.size.toLong(), status = "sending",
                        preview = if (o.type == "text") History.preview(String(o.content, Charsets.UTF_8)) else null,
                    ),
                    if (keep) o.content else null,
                )
                val built = Protocol.build(keys, o.type, device, now, o.content, item)
                outbox.add(Outbox.Pending(item, o.type, fp, built.parts))
                ClipService.kick(c)
            } catch (e: Exception) {
                Log.w("ClipwaySender", "Not sent: ${e.javaClass.simpleName}")
                History.update(c, item) { it.copy(status = "failed") }
            }
        }
        return if (Status.macOnline) Result.Sent else Result.Waiting
    }

    /**
     * An image or a file (docs/PROTOCOL.md, section 14): this phone listens on the local network for
     * 2 minutes and sends an offer through the relay; the Mac connects and fetches it. The content
     * never reaches the relay.
     */
    private fun offer(c: Context, o: Outgoing, keys: Protocol.Keys, device: Protocol.Device, item: String, fp: String, now: Long): Result {
        val local = localHosts(c)
        Log.i("ClipwaySender", "Offering on ${local.size} local address(es)")
        if (local.isEmpty()) return Result.NoLocalNetwork
        // Debug builds also list this computer, reached with `adb forward tcp:7721 tcp:7721`.
        val hosts = ((if (BuildConfig.DEBUG) listOf("127.0.0.1") else emptyList()) + local).take(Protocol.HOSTS_MAX)
        val port = try {
            direct.offer(item, Direct.transferKey(keys.direct, item), o.content) { outcome -> outcome(c, item, o, outcome) }
        } catch (e: Exception) {
            Log.w("ClipwaySender", "Cannot listen: ${e.javaClass.simpleName}")
            return Result.NoLocalNetwork
        }
        worker.execute {
            try {
                History.add(
                    c,
                    History.Entry(
                        item = item, type = o.type, outgoing = true, device = device.name, ts = now, mime = o.mime,
                        name = o.name, size = o.content.size.toLong(), status = "sending",
                    ),
                    if (o.type == "image") o.content else null,
                )
                val built = Protocol.offer(keys, device, now, o.type, o.mime, o.name, o.content, port, hosts, item)
                outbox.add(Outbox.Pending(item, "offer", fp, built.parts))
                ClipService.kick(c)
            } catch (e: Exception) {
                Log.w("ClipwaySender", "Not offered: ${e.javaClass.simpleName}")
                direct.cancel(item, Direct.Outcome.Failed)
            }
        }
        return if (Status.macOnline) Result.Direct else Result.Waiting
    }

    /**
     * This phone's addresses on a local network: from the connected networks Android reports (Wi-Fi,
     * Ethernet), then from the interfaces. Private IPv4 only (docs/PROTOCOL.md, 14.4).
     */
    private fun localHosts(c: Context): List<String> {
        val fromNetworks = try {
            val cm = c.getSystemService(android.net.ConnectivityManager::class.java)
            @Suppress("DEPRECATION")
            cm.allNetworks.flatMap { n -> cm.getLinkProperties(n)?.linkAddresses.orEmpty() }
                .mapNotNull { (it.address as? java.net.Inet4Address)?.hostAddress }
        } catch (e: Exception) {
            emptyList()
        }
        return (fromNetworks + Direct.localHosts()).filter { Direct.isPrivate(it) }.distinct().take(Protocol.HOSTS_MAX)
    }

    /** The end of a direct transfer: the history row, and a quiet notification when it did not go. */
    private fun outcome(c: Context, item: String, o: Outgoing, outcome: Direct.Outcome) {
        val status = when (outcome) {
            Direct.Outcome.Done -> "delivered"
            Direct.Outcome.Unreachable, Direct.Outcome.Expired -> "unreachable"
            Direct.Outcome.Failed, Direct.Outcome.Declined -> "failed"
        }
        History.update(c, item) { it.copy(status = status) }
        // An offer nobody fetched does not need to go out any more.
        outbox.remove(item)
        if (outcome != Direct.Outcome.Done) Notices.notSent(c, o.name ?: c.getString(R.string.an_image_lower), outcome)
    }

    /** Answers an offer through the relay when it could not be fetched directly. */
    fun reply(context: Context, keys: Protocol.Keys, offer: String, status: String) {
        val prefs = Prefs(context)
        val built = Protocol.reply(keys, Protocol.Device(prefs.deviceId, prefs.deviceName, "android"), System.currentTimeMillis(), offer, status)
        outbox.add(Outbox.Pending(built.head.item, "reply", "", built.parts))
        ClipService.kick(context)
    }

    /** hello: tells the Mac this phone's name, right after joining and when the name changes. */
    fun hello(context: Context, keys: Protocol.Keys) {
        val prefs = Prefs(context)
        val built = Protocol.build(keys, "hello", Protocol.Device(prefs.deviceId, prefs.deviceName, "android"), System.currentTimeMillis(), null)
        outbox.add(Outbox.Pending(built.head.item, "hello", "", built.parts))
    }

    // -----------------------------------------------------------------
    // Reading what to send
    // -----------------------------------------------------------------

    class Read(val items: List<Outgoing>, val refusal: Protocol.Refusal? = null)

    /** The clipboard, read by an activity that has window focus (the only time Android allows it). */
    fun fromClipboard(c: Context): Read {
        val cm = c.getSystemService(ClipboardManager::class.java)
        val clip = cm.primaryClip ?: return Read(emptyList(), Protocol.Refusal.Empty)
        val desc = clip.description
        if (isSensitive(desc)) return Read(emptyList(), Protocol.Refusal.Sensitive)
        if (clip.itemCount == 0) return Read(emptyList(), Protocol.Refusal.Empty)
        val first = clip.getItemAt(0)
        val uri = first.uri
        if (uri != null && first.text.isNullOrEmpty()) return fromUris(c, listOf(uri), null)
        val text = first.coerceToText(c)?.toString().orEmpty()
        if (text.isEmpty()) return Read(emptyList(), Protocol.Refusal.Empty)
        return Read(listOf(Outgoing("text", text.toByteArray(Charsets.UTF_8))))
    }

    /** ClipDescription.EXTRA_IS_SENSITIVE (Android 13 and later; some apps set it earlier too). */
    fun isSensitive(desc: ClipDescription?): Boolean =
        desc?.extras?.getBoolean(Protocol.EXTRA_IS_SENSITIVE, false) == true

    /** Shared content: text, or images and files read with the grant the share gave us. */
    fun fromShare(c: Context, intent: Intent): Read {
        val uris = when (intent.action) {
            Intent.ACTION_SEND -> listOfNotNull(intent.parcelable<Uri>(Intent.EXTRA_STREAM))
            Intent.ACTION_SEND_MULTIPLE -> intent.parcelables<Uri>(Intent.EXTRA_STREAM)
            else -> emptyList()
        }
        if (uris.isNotEmpty()) return fromUris(c, uris, intent.type)
        val text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString().orEmpty()
        if (text.isEmpty()) return Read(emptyList(), Protocol.Refusal.Empty)
        return Read(listOf(Outgoing("text", text.toByteArray(Charsets.UTF_8))))
    }

    private fun fromUris(c: Context, uris: List<Uri>, fallbackType: String?): Read {
        val out = ArrayList<Outgoing>()
        var refusal: Protocol.Refusal? = null
        for (uri in uris) {
            val mime = Protocol.cleanMime(c.contentResolver.getType(uri) ?: fallbackType)
            val name = displayName(c, uri)
            val type = if (mime.startsWith("image/")) "image" else "file"
            val bytes = try {
                read(c, uri, Protocol.maxSize(type))
            } catch (e: TooLarge) {
                refusal = Protocol.Refusal.TooLarge
                continue
            } catch (e: Exception) {
                null
            }
            if (bytes == null) refusal = refusal ?: Protocol.Refusal.Empty
            else out += Outgoing(type, bytes, mime, name ?: if (type == "file") "file" else null)
        }
        return Read(out, refusal)
    }

    private class TooLarge : Exception()

    /** Stops reading past the limit, so a larger content is refused without filling the memory. */
    private fun read(c: Context, uri: Uri, limit: Long): ByteArray? {
        c.contentResolver.openInputStream(uri)?.use { input ->
            val out = ByteArrayOutputStream()
            val buf = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                if (total > limit) throw TooLarge()
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }
        return null
    }

    private fun displayName(c: Context, uri: Uri): String? = try {
        c.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) it.getString(0)?.take(Protocol.NAME_MAX)?.takeIf { n -> n.isNotBlank() } else null
        }
    } catch (e: Exception) {
        null
    } ?: uri.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotBlank() && it.length <= Protocol.NAME_MAX }

    /** The short message shown after a send. */
    fun message(c: Context, r: Result, count: Int = 1): String {
        val mac = Status.peer.value ?: c.getString(R.string.your_mac)
        return when (r) {
            Result.Sent -> if (count > 1) c.resources.getQuantityString(R.plurals.sent_many, count, count, mac) else c.getString(R.string.sent_to, mac)
            Result.Direct -> c.getString(R.string.sending_directly, mac)
            Result.NoLocalNetwork -> c.getString(R.string.no_local_network)
            Result.TooLong -> c.getString(R.string.too_long)
            Result.Waiting -> c.getString(R.string.waiting_for, mac)
            Result.NotPaired -> c.getString(R.string.not_paired_toast)
            Result.Paused -> c.getString(R.string.paused_toast)
            Result.Empty -> c.getString(R.string.clipboard_empty)
            Result.Nothing -> c.getString(R.string.nothing_to_send)
            Result.Sensitive -> c.getString(R.string.not_sent_sensitive)
            Result.TooLarge -> c.getString(R.string.too_large)
            Result.Repeated -> c.getString(R.string.already_sent)
        }
    }

    fun refusalResult(r: Protocol.Refusal?): Result = when (r) {
        Protocol.Refusal.Sensitive -> Result.Sensitive
        Protocol.Refusal.TooLarge -> Result.TooLarge
        else -> Result.Empty
    }

    /** Sends everything read and returns the message to show, and whether it went well. */
    fun sendAll(c: Context, read: Read, clipboard: Boolean = true): Pair<String, Boolean> {
        val prefs = Prefs(c)
        if (!Vault.paired(c) || prefs.chainErased) return message(c, Result.NotPaired) to false
        if (!Power.maySend(paired = true, erased = false, paused = prefs.paused)) return message(c, Result.Paused) to false
        if (read.items.isEmpty()) {
            val r = refusalResult(read.refusal)
            return message(c, if (r == Result.Empty && !clipboard) Result.Nothing else r) to false
        }
        var last = Result.Empty
        var ok = 0
        for (o in read.items) {
            last = send(c, o)
            if (last == Result.Sent || last == Result.Waiting || last == Result.Direct) ok++
        }
        return if (ok > 0) message(c, last, ok) to true else message(c, last) to false
    }
}

@Suppress("DEPRECATION")
private inline fun <reified T : android.os.Parcelable> Intent.parcelable(key: String): T? =
    if (Build.VERSION.SDK_INT >= 33) getParcelableExtra(key, T::class.java) else getParcelableExtra(key) as? T

@Suppress("DEPRECATION")
private inline fun <reified T : android.os.Parcelable> Intent.parcelables(key: String): List<T> =
    (if (Build.VERSION.SDK_INT >= 33) getParcelableArrayListExtra(key, T::class.java) else getParcelableArrayListExtra<T>(key)).orEmpty()

/** Shows the result, confirms with haptics, and closes. */
private fun Activity.finishWith(message: String, ok: Boolean) {
    window?.decorView?.performHapticFeedback(if (ok) HapticFeedbackConstants.CONFIRM else HapticFeedbackConstants.REJECT)
    Toast.makeText(applicationContext, message, Toast.LENGTH_SHORT).show()
    finish()
    noAnimation(false)
}

@Suppress("DEPRECATION")
private fun Activity.noAnimation(opening: Boolean) {
    if (Build.VERSION.SDK_INT >= 34) {
        overrideActivityTransition(if (opening) Activity.OVERRIDE_TRANSITION_OPEN else Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
    } else {
        overridePendingTransition(0, 0)
    }
}

/**
 * Invisible activity started by the tile: Android only lets the focused app read the clipboard,
 * so it waits for window focus, reads, sends, and closes.
 */
class SendActivity : Activity() {
    private var done = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        noAnimation(true)
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || done) return
        done = true
        val read = Sender.fromClipboard(this)
        val (message, ok) = Sender.sendAll(this, read)
        finishWith(message, ok)
    }
}

/** "Send to Mac" in the text selection menu: sends the selection, never changes it, copies nothing. */
class ProcessTextActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val text = intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString().orEmpty()
        val read = if (text.isEmpty()) Sender.Read(emptyList(), Protocol.Refusal.Empty)
        else Sender.Read(listOf(Sender.Outgoing("text", text.toByteArray(Charsets.UTF_8))))
        val (message, ok) = Sender.sendAll(this, read, clipboard = false)
        finishWith(message, ok)
    }
}

/** Share target for text, images and files. Reads with the share's grant, then closes. */
class ShareActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = applicationContext
        val shared = intent
        Thread {
            val read = try {
                Sender.fromShare(app, shared)
            } catch (e: Exception) {
                Sender.Read(emptyList(), Protocol.Refusal.Empty)
            }
            runOnUiThread {
                val (message, ok) = Sender.sendAll(this, read, clipboard = false)
                finishWith(message, ok)
            }
        }.start()
    }
}

/** Quick Settings tile "Send to Mac": one tap sends the clipboard. */
class SendTile : TileService() {
    companion object {
        /** Asks Android to redraw the tile, after the Home switch changed. */
        fun refresh(context: Context) {
            try {
                requestListeningState(context, android.content.ComponentName(context, SendTile::class.java))
            } catch (_: Exception) {
            }
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        val prefs = Prefs(this)
        val power = Power.tile(Vault.paired(this), prefs.chainErased, prefs.paused)
        qsTile?.apply {
            state = if (power == Power.Tile.Ready) Tile.STATE_INACTIVE else Tile.STATE_UNAVAILABLE
            label = getString(R.string.tile_label)
            // Paused: the tile says so, and TalkBack reads it.
            subtitle = if (power == Power.Tile.Paused) getString(R.string.power_paused) else null
            stateDescription = if (power == Power.Tile.Paused) getString(R.string.power_paused) else null
            updateTile()
        }
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) unlockAndRun { open() } else open()
    }

    @Suppress("DEPRECATION")
    @android.annotation.SuppressLint("StartActivityAndCollapseDeprecated") // only below Android 14, where the PendingIntent form does not exist
    private fun open() {
        val intent = Intent(this, SendActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            startActivityAndCollapse(intent)
        }
    }
}
