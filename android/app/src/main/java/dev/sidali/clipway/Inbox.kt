package dev.sidali.clipway

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Environment
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.util.Log
import java.io.File
import java.io.FileNotFoundException
import java.util.concurrent.Executors

/**
 * What the phone does with an item from the Mac (docs/PROTOCOL.md, sections 3.4, 3.5 and 5.3):
 * open and check it, write it to the clipboard or Downloads, add it to history, show a quiet
 * notification, and only then let the engine acknowledge it. An offer is fetched directly from
 * the Mac on the local network (section 14), on its own thread.
 */
class Inbox(private val context: Context) {
    private val prefs = Prefs(context)
    private var seen: Protocol.Seen? = null
    private val fetcher = Executors.newSingleThreadExecutor { r -> Thread(r, "clipway-fetch").apply { isDaemon = true } }

    fun handle(keys: Protocol.Keys, parts: List<Crypto.Envelope>): Engine.Delivery {
        val now = System.currentTimeMillis()
        val s = seen ?: prefs.seen(now).also { seen = it }
        return when (val o = Protocol.open(keys, parts, now, prefs.deviceId, s)) {
            is Protocol.Opened.Dropped -> {
                Log.i(TAG, "Item dropped: ${o.why}")
                if (o.why == Protocol.Drop.Unreadable) prefs.unreadable = prefs.unreadable + 1
                if (o.why.ack) Engine.Delivery.Ack else Engine.Delivery.NoAck
            }
            is Protocol.Opened.Ok -> try {
                act(keys, o.head, o.content, now)
                s.add(o.head.item, now)
                prefs.saveSeen(s)
                Engine.Delivery.Ack
            } catch (e: Exception) {
                // Not written: no ack, so the relay sends it again at the next connection.
                Log.w(TAG, "Item not handled: ${e.javaClass.simpleName}")
                Engine.Delivery.Retry
            }
        }
    }

    private fun act(keys: Protocol.Keys, head: Protocol.Head, content: ByteArray?, now: Long) {
        val from = head.device.name
        // The peer is the Mac: another phone on the chain (or this phone before an erase) is not.
        if (head.device.kind == "mac") {
            if (prefs.peerName != from) prefs.peerName = from
            Status.peer.value = from
            if (!prefs.celebrated) {
                prefs.celebrated = true
                Status.celebrate.value = true
            }
        }
        when (head.type) {
            "reply" -> {
                val outcome = when (head.status) {
                    "done" -> Direct.Outcome.Done
                    "unreachable" -> Direct.Outcome.Unreachable
                    "declined" -> Direct.Outcome.Declined
                    else -> Direct.Outcome.Failed
                }
                Sender.direct.cancel(head.offer ?: return, outcome)
                return
            }
            "offer" -> {
                fetcher.execute { fetch(keys, head) }
                return
            }
        }
        if (head.type != "text" || content == null) return
        receive(head, head.type, content, now)
    }

    /** Fetches an offered image or file from the Mac; says so through the relay and a notification if it cannot. */
    private fun fetch(keys: Protocol.Keys, head: Protocol.Head) {
        val from = head.device.name
        val name = head.name ?: context.getString(R.string.an_image_lower)
        val result = Direct.fetch(keys, head, BuildConfig.DEBUG) { content ->
            receive(head, head.media ?: "file", content, System.currentTimeMillis())
        }
        Log.i(TAG, "Direct ${head.media}: ${result.javaClass.simpleName}")
        when (result) {
            is Direct.Fetched.Ok -> Unit
            Direct.Fetched.Unreachable -> {
                Sender.reply(context, keys, head.item, "unreachable")
                Notices.notReceived(context, name, from, network = true)
            }
            Direct.Fetched.Failed -> {
                Sender.reply(context, keys, head.item, "failed")
                Notices.notReceived(context, name, from, network = false)
            }
        }
    }

    /** A text, or an image or a file fetched directly: clipboard or Downloads, history, notification. */
    private fun receive(head: Protocol.Head, type: String, content: ByteArray, now: Long) {
        val from = head.device.name
        Sender.noteEcho(head.fp)
        val fresh = head.ts >= prefs.lastClipTs && now - head.ts < Protocol.CLIPBOARD_WINDOW_MS
        val base = History.Entry(
            item = head.item, type = type, outgoing = false, device = from, ts = head.ts,
            mime = head.mime, name = head.name, size = head.size,
        )
        when (type) {
            "text" -> {
                val text = String(content, Charsets.UTF_8)
                val copy = prefs.copyAutomatically && fresh
                if (copy) {
                    Clips.text(context, text)
                    prefs.lastClipTs = head.ts
                }
                History.add(context, base.copy(preview = History.preview(text)), content)
                if (copy) Notices.copied(context, from)
            }
            "image" -> {
                val copy = prefs.copyAutomatically && prefs.imagesToo && fresh
                if (copy) {
                    Clips.image(context, head.item, head.mime, content)
                    prefs.lastClipTs = head.ts
                }
                History.add(context, base, content)
                if (copy) Notices.copied(context, from)
            }
            "file" -> {
                val (uri, name) = Downloads.save(context, head.name ?: "file", head.mime, content)
                History.add(context, base.copy(name = name, uri = uri.toString()), null)
                Notices.file(context, name, from, uri, head.mime)
            }
        }
    }

    private companion object {
        const val TAG = "ClipwayInbox"
    }
}

/** Writes to the clipboard: text directly, images as a private copy served by [ClipProvider]. */
object Clips {
    const val AUTHORITY = "dev.sidali.clipway.clips"
    private const val KEEP = 2
    private val SAFE = Regex("^[0-9a-f]{32}\\.[a-z]{2,5}$")

    fun dir(c: Context) = File(c.noBackupFilesDir, "clips").apply { mkdirs() }
    fun isSafeName(name: String) = SAFE.matches(name)

    fun text(c: Context, text: String) {
        c.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText(c.getString(R.string.clip_label), text))
    }

    /** Keeps only the last two copies: the clipboard only needs the current one. */
    fun image(c: Context, item: String, mime: String?, bytes: ByteArray) {
        val name = "$item.${Protocol.extensionFor(mime)}"
        val out = File(dir(c), name)
        val tmp = File(dir(c), "$name.part")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(out)) error("rename failed")
        val uri = Uri.parse("content://$AUTHORITY/$name")
        c.getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newUri(c.contentResolver, c.getString(R.string.clip_label), uri))
        dir(c).listFiles()?.filter { isSafeName(it.name) }?.sortedByDescending { it.lastModified() }?.drop(KEEP)?.forEach { it.delete() }
        dir(c).listFiles()?.filter { it.name.endsWith(".part") }?.forEach { it.delete() }
    }

    fun mimeFor(name: String): String = when (name.substringAfterLast('.')) {
        "png" -> "image/png"
        "jpg" -> "image/jpeg"
        "webp" -> "image/webp"
        "gif" -> "image/gif"
        "heic" -> "image/heic"
        "heif" -> "image/heif"
        "tiff" -> "image/tiff"
        "bmp" -> "image/bmp"
        else -> "application/octet-stream"
    }
}

/**
 * Read-only, non-exported provider for the clipboard image copies. The clipboard grants the app
 * that pastes a temporary read permission; nothing else can list or read these files.
 */
class ClipProvider : ContentProvider() {
    override fun onCreate() = true

    private fun file(uri: Uri): File {
        val c = context ?: throw FileNotFoundException()
        val name = uri.pathSegments.singleOrNull()?.takeIf { Clips.isSafeName(it) } ?: throw FileNotFoundException()
        val f = File(Clips.dir(c), name)
        if (!f.isFile) throw FileNotFoundException(name)
        return f
    }

    override fun getType(uri: Uri): String? = uri.lastPathSegment?.takeIf { Clips.isSafeName(it) }?.let { Clips.mimeFor(it) }

    override fun getStreamTypes(uri: Uri, mimeTypeFilter: String): Array<String>? = getType(uri)?.let { arrayOf(it) }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw SecurityException("read-only")
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun query(uri: Uri, projection: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor {
        val f = file(uri)
        val cols = (projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE))
            .filter { it == OpenableColumns.DISPLAY_NAME || it == OpenableColumns.SIZE }.toTypedArray()
        return MatrixCursor(cols, 1).apply { addRow(cols.map { if (it == OpenableColumns.SIZE) f.length() else f.name }) }
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, s: String?, a: Array<out String>?): Int = throw UnsupportedOperationException()
    override fun delete(uri: Uri, s: String?, a: Array<out String>?): Int = throw UnsupportedOperationException()
}

/** Received files go to Download/Clipway through MediaStore: no storage permission. */
object Downloads {
    private const val FOLDER = "Clipway"

    /** Returns the new file's address and the name it got (sanitized, " 2" when taken). */
    @Suppress("UNUSED_PARAMETER")
    fun save(c: Context, wanted: String, mime: String?, bytes: ByteArray): Pair<Uri, String> {
        val cr = c.contentResolver
        val path = Environment.DIRECTORY_DOWNLOADS + "/" + FOLDER + "/"
        val taken = HashSet<String>()
        cr.query(
            MediaStore.Downloads.EXTERNAL_CONTENT_URI, arrayOf(MediaStore.MediaColumns.DISPLAY_NAME),
            "${MediaStore.MediaColumns.RELATIVE_PATH}=?", arrayOf(path), null,
        )?.use { cur -> while (cur.moveToNext()) cur.getString(0)?.let { taken += it } }
        val name = Protocol.freeName(Protocol.safeFileName(wanted), taken)
        fun insert(type: String): Uri? = cr.insert(
            MediaStore.Downloads.EXTERNAL_CONTENT_URI,
            ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, name)
                put(MediaStore.MediaColumns.MIME_TYPE, type)
                put(MediaStore.MediaColumns.RELATIVE_PATH, path)
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            },
        )
        // The type comes from the name's extension, so MediaStore keeps the name the sender gave
        // (it renames a file whose extension does not match its type).
        val ext = name.substringAfterLast('.', "").lowercase()
        val type = android.webkit.MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
        val uri = (try { insert(type) } catch (e: Exception) { null }) ?: insert("application/octet-stream") ?: error("insert refused")
        try {
            cr.openOutputStream(uri, "w")?.use { it.write(bytes) } ?: error("no stream")
            cr.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
        } catch (e: Exception) {
            cr.delete(uri, null, null)
            throw e
        }
        val finalName = cr.query(uri, arrayOf(MediaStore.MediaColumns.DISPLAY_NAME), null, null, null)
            ?.use { if (it.moveToFirst()) it.getString(0) else null } ?: name
        return uri to finalName
    }
}

/** Quiet notifications: no sound, hidden on the lock screen, no content of the item. */
object Notices {
    private const val COPIED = 2

    fun copied(c: Context, from: String) {
        ClipService.channels(c)
        val n = Notification.Builder(c, ClipService.CHANNEL_RECEIVED)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(c.getColor(R.color.lac))
            .setContentTitle(c.getString(R.string.copied_from, from))
            .setTimeoutAfter(4_000L)
            .setAutoCancel(true)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .setCategory(Notification.CATEGORY_STATUS)
            .build()
        post(c, COPIED, n)
    }

    /** An image or a file this phone offered did not reach the Mac. */
    fun notSent(c: Context, name: String, outcome: Direct.Outcome) {
        val mac = Status.peer.value ?: c.getString(R.string.your_mac)
        val body = when (outcome) {
            Direct.Outcome.Unreachable -> c.getString(R.string.not_sent_network_body, mac)
            Direct.Outcome.Expired -> c.getString(R.string.not_sent_expired_body, mac)
            else -> c.getString(R.string.not_sent_failed_body)
        }
        quiet(c, c.getString(R.string.not_sent_title, name), body)
    }

    /** An image or a file the Mac offered could not be fetched. */
    fun notReceived(c: Context, name: String, from: String, network: Boolean) {
        quiet(c, c.getString(R.string.not_received_network, name, from), c.getString(if (network) R.string.not_received_network_body else R.string.not_received_failed_body))
    }

    private fun quiet(c: Context, title: String, body: String) {
        ClipService.channels(c)
        val open = PendingIntent.getActivity(
            c, 0, Intent(c, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE,
        )
        val n = Notification.Builder(c, ClipService.CHANNEL_RECEIVED)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(c.getColor(R.color.lac))
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(Notification.BigTextStyle().bigText(body))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
        post(c, 3 + (title.hashCode() and 0xfff), n)
    }

    fun file(c: Context, name: String, from: String, uri: Uri, mime: String?) {
        ClipService.channels(c)
        val view = Intent(Intent.ACTION_VIEW).setDataAndType(uri, Protocol.cleanMime(mime))
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        val open = PendingIntent.getActivity(c, name.hashCode(), view, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = Notification.Builder(c, ClipService.CHANNEL_RECEIVED)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(c.getColor(R.color.lac))
            .setContentTitle(c.getString(R.string.received_file, name, from))
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, c.getString(R.string.open), open).build())
            .setAutoCancel(true)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
        post(c, 100 + (uri.hashCode() and 0xffff), n)
    }

    private fun post(c: Context, id: Int, n: Notification) {
        try {
            c.getSystemService(NotificationManager::class.java).notify(id, n)
        } catch (_: SecurityException) {
        }
    }
}
