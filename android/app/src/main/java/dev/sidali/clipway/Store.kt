package dev.sidali.clipway

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Settings and small state, in the app's credential-protected storage (readable after the first
 * unlock, never backed up: allowBackup is off and the extraction rules exclude everything).
 */
@SuppressLint("ApplySharedPref")
class Prefs(context: Context) {
    private val app = context.applicationContext ?: context
    val raw: SharedPreferences get() = app.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /** Random per installation, only inside envelopes: the relay never sees it. New after Erase everything. */
    val deviceId: String
        @Synchronized get() {
            raw.getString("device_id", null)?.let { return it }
            val id = Crypto.hex(Crypto.randomBytes(16))
            raw.edit().putString("device_id", id).commit()
            return id
        }

    var deviceName: String
        get() = raw.getString("device_name", null)?.takeIf { it.isNotBlank() } ?: defaultName()
        set(v) = raw.edit().putString("device_name", cleanName(v)).apply()

    var relay: String
        get() = raw.getString("relay", null) ?: BuildConfig.DEFAULT_RELAY
        set(v) = raw.edit().putString("relay", Protocol.normalizeRelay(v)).apply()

    /** Write what the Mac sends into the clipboard. */
    var copyAutomatically: Boolean
        get() = raw.getBoolean("copy_auto", true)
        set(v) = raw.edit().putBoolean("copy_auto", v).apply()

    /** Images too (otherwise they only go to history). */
    var imagesToo: Boolean
        get() = raw.getBoolean("images_too", true)
        set(v) = raw.edit().putBoolean("images_too", v).apply()

    var startAtBoot: Boolean
        get() = raw.getBoolean("start_at_boot", true)
        set(v) = raw.edit().putBoolean("start_at_boot", v).apply()

    /** The Home switch is off: nothing runs in the background until it is turned back on. */
    var paused: Boolean
        get() = raw.getBoolean("paused", false)
        set(v) { raw.edit().putBoolean("paused", v).commit() }

    /** The last name the Mac announced (hello or any item). */
    var peerName: String?
        get() = raw.getString("peer_name", null)
        set(v) = raw.edit().putString("peer_name", v).apply()

    /** Onboarding finished (key saved or skipped). */
    var onboarded: Boolean
        get() = raw.getBoolean("onboarded", false)
        set(v) = raw.edit().putBoolean("onboarded", v).apply()

    var keySaved: Boolean
        get() = raw.getBoolean("key_saved", false)
        set(v) = raw.edit().putBoolean("key_saved", v).apply()

    /** The pairing worked end to end once (the one celebration). */
    var celebrated: Boolean
        get() = raw.getBoolean("celebrated", false)
        set(v) = raw.edit().putBoolean("celebrated", v).apply()

    var tileHintDismissed: Boolean
        get() = raw.getBoolean("tile_hint_done", false)
        set(v) = raw.edit().putBoolean("tile_hint_done", v).apply()

    /** Clipway asked for this runtime permission at least once (the Permissions screen tells "Off" from "Not asked yet"). */
    fun asked(permission: String): Boolean = raw.getBoolean("asked_$permission", false)
    fun markAsked(permission: String) = raw.edit().putBoolean("asked_$permission", true).apply()

    /** Version whose notes were seen, for What's new. */
    var versionSeen: String?
        get() = raw.getString("version_seen", null)
        set(v) = raw.edit().putString("version_seen", v).apply()

    /** ts of the newest text or image written to the clipboard (section 3.5). */
    var lastClipTs: Long
        get() = raw.getLong("last_clip_ts", 0L)
        set(v) = raw.edit().putLong("last_clip_ts", v).apply()

    /** Envelopes that could not be opened (shown in Settings, never more). */
    var unreadable: Int
        get() = raw.getInt("unreadable", 0)
        set(v) = raw.edit().putInt("unreadable", v).apply()

    /** Relay status from /.well-known/clipway-relay.json, checked once a day. */
    var relayNotice: String?
        get() = raw.getString("relay_notice", null)
        set(v) = raw.edit().putString("relay_notice", v).apply()
    var relayCheckedAt: Long
        get() = raw.getLong("relay_checked", 0L)
        set(v) = raw.edit().putLong("relay_checked", v).apply()

    /** (epoch, after) of the relay protocol. */
    val cursor = object : Engine.Cursor {
        override var epoch: String
            get() = raw.getString("epoch", "") ?: ""
            set(v) { raw.edit().putString("epoch", v).commit() }
        override var after: Long
            get() = raw.getLong("after", 0L)
            set(v) { raw.edit().putLong("after", v).commit() }
    }

    fun seen(now: Long): Protocol.Seen = Protocol.Seen.decode(raw.getString("seen", null), now)
    fun saveSeen(s: Protocol.Seen) = raw.edit().putString("seen", s.encode()).apply()

    /** Another device erased the chain on the relay (close code 4001): stay stopped until paired again. */
    var chainErased: Boolean
        get() = raw.getBoolean("chain_erased", false)
        set(v) { raw.edit().putBoolean("chain_erased", v).commit() }

    /** Forget the chain state, keep settings and history (pair again). */
    fun forgetChain() {
        raw.edit().remove("chain_erased").remove("epoch").remove("after").remove("seen").remove("peer_name").remove("onboarded")
            .remove("key_saved").remove("celebrated").remove("last_clip_ts").commit()
    }

    fun clear() = raw.edit().clear().commit()

    companion object {
        const val FILE = "clipway"

        /** The phone's model, as people call it ("Pixel 10 Pro"). */
        fun defaultName(): String = cleanName(Build.MODEL.ifBlank { "Android phone" })

        /** 1 to 64 characters, no line breaks. */
        fun cleanName(v: String): String {
            val s = v.replace(Regex("\\s+"), " ").trim()
            if (s.isEmpty()) return defaultName()
            return if (s.codePointCount(0, s.length) <= Protocol.DEVICE_NAME_MAX) s
            else s.substring(0, s.offsetByCodePoints(0, Protocol.DEVICE_NAME_MAX)).trim()
        }
    }
}

/**
 * Non-exportable AES-256-GCM keys of the Android Keystore (StrongBox when the phone has one).
 * No user authentication: the service must read the chain and write history while the phone is
 * locked, after the first unlock. Erase everything deletes the keys (crypto-shredding).
 */
object Keystore {
    private const val TAG = "ClipwayKeystore"
    const val CHAIN = "clipway-chain"
    const val HISTORY = "clipway-history"

    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Synchronized
    private fun key(context: Context, alias: String, create: Boolean): SecretKey? {
        (store().getKey(alias, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        fun make(sb: Boolean): SecretKey {
            val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            g.init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setIsStrongBoxBacked(sb)
                    .build(),
            )
            return g.generateKey()
        }
        return try {
            make(strongBox)
        } catch (e: StrongBoxUnavailableException) {
            Log.i(TAG, "StrongBox unavailable, using the TEE")
            make(false)
        }
    }

    /** iv (12 bytes) followed by ciphertext and tag. */
    fun wrap(context: Context, alias: String, plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key(context, alias, true))
        return c.iv + c.doFinal(plain)
    }

    fun unwrap(context: Context, alias: String, box: ByteArray): ByteArray {
        require(box.size > 12) { "box too short" }
        val k = key(context, alias, false) ?: error("Keystore key missing")
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, box, 0, 12))
        return c.doFinal(box, 12, box.size - 12)
    }

    fun delete(alias: String) {
        try {
            store().deleteEntry(alias)
        } catch (e: Exception) {
            Log.w(TAG, "Key not deleted: ${e.javaClass.simpleName}")
        }
    }

    /** Every key of this app (Erase everything). */
    fun deleteAll() {
        try {
            val ks = store()
            for (a in ks.aliases().toList()) ks.deleteEntry(a)
        } catch (e: Exception) {
            Log.w(TAG, "Keystore not fully cleared: ${e.javaClass.simpleName}")
        }
    }
}

/** The chain secret S: encrypted by a Keystore key, in the app's private preferences. */
object Vault {
    @Volatile
    private var cache: ByteArray? = null

    @Volatile
    private var keysCache: Protocol.Keys? = null

    fun paired(context: Context): Boolean = Prefs(context).raw.contains("chain")

    /** A copy of S, or null when not paired or unreadable. Callers fill it with zeros when done. */
    @Synchronized
    fun secret(context: Context): ByteArray? {
        cache?.let { return it.copyOf() }
        val box = Prefs(context).raw.getString("chain", null) ?: return null
        return try {
            val s = Keystore.unwrap(context, Keystore.CHAIN, Base64.decode(box, Base64.NO_WRAP))
            if (s.size != Crypto.SECRET_SIZE) null else s.also { cache = it.copyOf() }
        } catch (e: Exception) {
            Log.w("ClipwayVault", "Key unreadable: ${e.javaClass.simpleName}")
            null
        }
    }

    @Synchronized
    fun keys(context: Context): Protocol.Keys? {
        keysCache?.let { return it }
        val s = secret(context) ?: return null
        return Protocol.Keys.of(s).also {
            s.fill(0)
            keysCache = it
        }
    }

    @Synchronized
    @SuppressLint("ApplySharedPref")
    fun join(context: Context, s: ByteArray, relay: String?) {
        require(s.size == Crypto.SECRET_SIZE)
        val p = Prefs(context)
        val box = Keystore.wrap(context, Keystore.CHAIN, s)
        p.forgetChain()
        p.raw.edit().putString("chain", Base64.encodeToString(box, Base64.NO_WRAP)).remove("paused")
            .putString("relay", Protocol.normalizeRelay(relay ?: BuildConfig.DEFAULT_RELAY)).commit()
        cache?.fill(0)
        cache = s.copyOf()
        keysCache = null
    }

    /** Leaves the chain on this phone: S and its key are destroyed. */
    @Synchronized
    @SuppressLint("ApplySharedPref")
    fun forget(context: Context) {
        Prefs(context).raw.edit().remove("chain").commit()
        Keystore.delete(Keystore.CHAIN)
        cache?.fill(0)
        cache = null
        keysCache = null
    }
}
