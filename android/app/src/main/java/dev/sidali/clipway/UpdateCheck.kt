package dev.sidali.clipway

import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/**
 * The Android entry of update.json (docs/UPDATES.md), validated.
 * [certSha256]: SHA-256 of the signing certificate (DER), lowercase hex.
 */
data class Release(
    val version: String,
    val versionCode: Long,
    val url: String,
    val sha256: String,
    val size: Long,
    val certSha256: String,
    val notes: String,
)

/** Why an update is refused or failed. */
enum class UpdateFailure { NETWORK, SIZE, CHECKSUM, CERTIFICATE, PACKAGE, STORAGE, INSTALL }

/**
 * The checks of the built-in update, in plain Kotlin (tested on the JVM): reading update.json,
 * versions, the SHA-256 of the APK and its signing certificate. Same rules as Sonne's.
 */
object UpdateCheck {
    const val HOST = "clip.sidali.dev"
    const val MANIFEST_URL = "https://$HOST/update.json"
    /** An APK of Clipway is a few MB. */
    const val APK_MAX = 150L * 1024 * 1024
    const val MANIFEST_MAX = 64 * 1024

    private val RE_HEX64 = Regex("^[0-9a-f]{64}$")
    private val RE_VERSION = Regex("^\\d{1,4}\\.\\d{1,4}\\.\\d{1,4}$")

    /**
     * Reads update.json. Returns the Android release when it is well formed, its APK comes from
     * [origin]/download/clipway-<version>.apk exactly, and it is newer than [installedCode]
     * (versionCode is authoritative); null otherwise.
     */
    fun parse(text: String?, installedCode: Long, origin: String = "https://$HOST"): Release? {
        if (text.isNullOrBlank() || text.length > MANIFEST_MAX) return null
        val r = try {
            val root = JSONObject(text)
            val a = root.getJSONObject("android")
            Release(
                version = a.getString("version"),
                versionCode = a.getLong("versionCode"),
                url = a.getString("url"),
                sha256 = a.getString("sha256").lowercase(),
                size = a.getLong("size"),
                certSha256 = a.getString("certSha256").lowercase().replace(":", ""),
                notes = root.optString("notes").take(2000),
            )
        } catch (_: Exception) {
            return null
        }
        if (!RE_VERSION.matches(r.version) || r.versionCode <= 0) return null
        if (r.url != "$origin/download/clipway-${r.version}.apk") return null
        if (!RE_HEX64.matches(r.sha256) || !RE_HEX64.matches(r.certSha256)) return null
        if (r.size <= 0 || r.size > APK_MAX) return null
        if (r.versionCode <= installedCode) return null
        return r
    }

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun sha256Hex(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    fun sha256Hex(input: InputStream): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
        }
        return hex(md.digest())
    }

    /** Two hex fingerprints are equal, compared in constant time. */
    fun same(a: String, b: String): Boolean = MessageDigest.isEqual(a.lowercase().toByteArray(), b.lowercase().toByteArray())

    /** The file has the announced size and SHA-256. */
    fun fileMatches(file: File, release: Release): Boolean =
        file.isFile && file.length() == release.size && same(file.inputStream().use { sha256Hex(it) }, release.sha256)

    /**
     * Signing certificates (DER): the APK's must be exactly the installed app's, include the one
     * announced, and, when [pinned] is set (release builds), that one too. null when all match.
     */
    fun checkCertificates(apk: List<ByteArray>, installed: List<ByteArray>, announced: String, pinned: String?): UpdateFailure? {
        if (apk.isEmpty() || installed.isEmpty()) return UpdateFailure.CERTIFICATE
        val a = apk.map { sha256Hex(it) }.toSet()
        if (a != installed.map { sha256Hex(it) }.toSet()) return UpdateFailure.CERTIFICATE
        if (a.none { same(it, announced) }) return UpdateFailure.CERTIFICATE
        if (pinned != null && a.none { same(it, pinned) }) return UpdateFailure.CERTIFICATE
        return null
    }
}
