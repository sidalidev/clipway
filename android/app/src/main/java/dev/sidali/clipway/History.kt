package dev.sidali.clipway

import android.annotation.SuppressLint
import android.content.Context
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.OutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The last 50 items, sent and received (docs/PROTOCOL.md, section 9), encrypted at rest:
 * AES-256-GCM with a random 32-byte key, itself wrapped by a Keystore key. Erase everything
 * deletes the Keystore key, which makes every file here unreadable even if the flash keeps it.
 *
 * Layout in the app's files: history/index.bin (the rows) and history/c/<item>.bin (texts and
 * images). Received files are not copied: their row points to Download/Clipway.
 */
object History {

    const val MAX_ITEMS = 50
    const val MAX_BYTES = 200L * 1_048_576
    const val PREVIEW = 200
    private const val TAG = "ClipwayHistory"

    data class Entry(
        val item: String,
        val type: String,
        val outgoing: Boolean,
        val device: String,
        val ts: Long,
        val mime: String? = null,
        val name: String? = null,
        val size: Long = 0,
        val preview: String? = null,
        /** The content is kept (texts, images). */
        val kept: Boolean = false,
        /** The content was dropped to stay under 200 MiB. */
        val removed: Boolean = false,
        /** Received files: their place in Downloads. */
        val uri: String? = null,
        /** Sent items: sending, sent, waiting, delivered, failed. */
        val status: String? = null,
        val seq: Long = 0,
    )

    private val _entries = MutableStateFlow<List<Entry>>(emptyList())
    val entries: StateFlow<List<Entry>> = _entries
    private var loaded = false
    private var dataKey: ByteArray? = null

    private fun dir(c: Context) = File(c.filesDir, "history").apply { mkdirs() }
    private fun contentDir(c: Context) = File(dir(c), "c").apply { mkdirs() }
    private fun contentFile(c: Context, item: String): File {
        require(Regex("^[0-9a-f]{32}$").matches(item))
        return File(contentDir(c), "$item.bin")
    }

    @SuppressLint("ApplySharedPref")
    @Synchronized
    private fun key(c: Context): ByteArray {
        dataKey?.let { return it }
        val prefs = Prefs(c).raw
        val box = prefs.getString("history_key", null)
        val k = if (box != null) {
            Keystore.unwrap(c, Keystore.HISTORY, Base64.decode(box, Base64.NO_WRAP))
        } else {
            // A new key makes old files unreadable: start from an empty history, folders ready.
            dir(c).deleteRecursively()
            contentDir(c)
            Crypto.randomBytes(32).also {
                prefs.edit().putString("history_key", Base64.encodeToString(Keystore.wrap(c, Keystore.HISTORY, it), Base64.NO_WRAP)).commit()
            }
        }
        dataKey = k
        return k
    }

    private fun seal(c: Context, aad: String, plain: ByteArray): ByteArray {
        val iv = Crypto.randomBytes(12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key(c), "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad.toByteArray())
        return iv + cipher.doFinal(plain)
    }

    private fun unseal(c: Context, aad: String, box: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key(c), "AES"), GCMParameterSpec(128, box, 0, 12))
        cipher.updateAAD(aad.toByteArray())
        return cipher.doFinal(box, 12, box.size - 12)
    }

    private fun writeAtomic(f: File, bytes: ByteArray) {
        val tmp = File(f.parentFile, f.name + ".tmp")
        tmp.outputStream().use { it.write(bytes); it.fd.sync() }
        if (!tmp.renameTo(f)) error("rename failed")
    }

    @Synchronized
    fun load(c: Context): List<Entry> {
        if (loaded) return _entries.value
        loaded = true
        val f = File(dir(c), "index.bin")
        _entries.value = if (!f.exists()) emptyList() else try {
            fromJson(String(unseal(c, "index", f.readBytes()), Charsets.UTF_8))
        } catch (e: Exception) {
            Log.w(TAG, "History unreadable, starting again: ${e.javaClass.simpleName}")
            emptyList()
        }
        return _entries.value
    }

    private fun save(c: Context, list: List<Entry>) {
        _entries.value = list
        writeAtomic(File(dir(c), "index.bin"), seal(c, "index", toJson(list).toByteArray(Charsets.UTF_8)))
    }

    /** Adds an item at the top. Content (text or image bytes) is kept encrypted. */
    @Synchronized
    fun add(c: Context, e: Entry, content: ByteArray?) {
        load(c)
        var entry = e
        if (content != null) {
            writeAtomic(contentFile(c, e.item), seal(c, e.item, content))
            entry = e.copy(kept = true)
        }
        val list = listOf(entry) + _entries.value.filter { it.item != e.item }
        save(c, prune(c, list))
    }

    /** Keeps 50 rows and 200 MiB of content: beyond, the oldest rows go, then the oldest content. */
    private fun prune(c: Context, list: List<Entry>): List<Entry> {
        val keep = list.take(MAX_ITEMS)
        list.drop(MAX_ITEMS).forEach { contentFile(c, it.item).delete() }
        var total = 0L
        return keep.map { e ->
            if (!e.kept) return@map e
            val size = contentFile(c, e.item).length()
            if (total + size <= MAX_BYTES) {
                total += size
                e
            } else {
                contentFile(c, e.item).delete()
                e.copy(kept = false, removed = true)
            }
        }
    }

    @Synchronized
    fun update(c: Context, item: String, change: (Entry) -> Entry) {
        load(c)
        if (_entries.value.none { it.item == item }) return
        save(c, _entries.value.map { if (it.item == item) change(it) else it })
    }

    @Synchronized
    fun updateBySeq(c: Context, seq: Long, change: (Entry) -> Entry) {
        load(c)
        val e = _entries.value.firstOrNull { it.outgoing && it.seq == seq } ?: return
        update(c, e.item, change)
    }

    fun content(c: Context, item: String): ByteArray? = try {
        val f = contentFile(c, item)
        if (f.exists()) unseal(c, item, f.readBytes()) else null
    } catch (e: Exception) {
        null
    }

    @Synchronized
    fun delete(c: Context, items: Set<String>) {
        load(c)
        items.forEach { contentFile(c, it).delete() }
        save(c, _entries.value.filter { it.item !in items })
    }

    @Synchronized
    fun clear(c: Context) {
        load(c)
        contentDir(c).deleteRecursively()
        save(c, emptyList())
    }

    /** Erase everything: files gone and, with the Keystore key deleted by the caller, unreadable anyway. */
    @Synchronized
    fun wipe(c: Context) {
        dataKey?.fill(0)
        dataKey = null
        dir(c).deleteRecursively()
        Keystore.delete(Keystore.HISTORY)
        _entries.value = emptyList()
        loaded = false
    }

    /**
     * Export (section 9): a ZIP readable without Clipway. history.json has one object per item
     * (type, device, ts, mime, name, size, and text for texts); items/ has the images.
     */
    fun export(c: Context, out: OutputStream) {
        val list = load(c)
        ZipOutputStream(out).use { zip ->
            val json = JSONArray()
            for (e in list) {
                val o = JSONObject().put("type", e.type).put("device", e.device).put("ts", e.ts)
                    .put("direction", if (e.outgoing) "sent" else "received")
                e.mime?.let { o.put("mime", it) }
                e.name?.let { o.put("name", it) }
                o.put("size", e.size)
                val bytes = if (e.kept) content(c, e.item) else null
                if (e.type == "text" && bytes != null) o.put("text", String(bytes, Charsets.UTF_8))
                if (e.type == "image" && bytes != null) {
                    val path = "items/${e.item}.${Protocol.extensionFor(e.mime)}"
                    o.put("file", path)
                    zip.putNextEntry(ZipEntry(path))
                    zip.write(bytes)
                    zip.closeEntry()
                }
                json.put(o)
            }
            zip.putNextEntry(ZipEntry("history.json"))
            zip.write(json.toString(2).replace("\\/", "/").toByteArray(Charsets.UTF_8))
            zip.closeEntry()
        }
    }

    private fun toJson(list: List<Entry>): String {
        val a = JSONArray()
        for (e in list) {
            val o = JSONObject().put("item", e.item).put("type", e.type).put("out", e.outgoing).put("device", e.device)
                .put("ts", e.ts).put("size", e.size).put("kept", e.kept).put("removed", e.removed).put("seq", e.seq)
            e.mime?.let { o.put("mime", it) }
            e.name?.let { o.put("name", it) }
            e.preview?.let { o.put("preview", it) }
            e.uri?.let { o.put("uri", it) }
            e.status?.let { o.put("status", it) }
            a.put(o)
        }
        return a.toString()
    }

    private fun fromJson(text: String): List<Entry> {
        val a = JSONArray(text)
        return (0 until a.length()).mapNotNull { i ->
            val o = a.optJSONObject(i) ?: return@mapNotNull null
            fun s(k: String) = if (o.has(k) && !o.isNull(k)) o.optString(k) else null
            Entry(
                item = o.optString("item"), type = o.optString("type"), outgoing = o.optBoolean("out"),
                device = o.optString("device"), ts = o.optLong("ts"), mime = s("mime"), name = s("name"),
                size = o.optLong("size"), preview = s("preview"), kept = o.optBoolean("kept"),
                removed = o.optBoolean("removed"), uri = s("uri"), status = s("status"), seq = o.optLong("seq"),
            )
        }
    }

    /** First 200 characters of a text, on one line. */
    fun preview(text: String): String {
        val one = text.replace(Regex("\\s+"), " ").trim()
        return if (one.length <= PREVIEW) one else one.substring(0, PREVIEW).trimEnd() + "…"
    }
}
