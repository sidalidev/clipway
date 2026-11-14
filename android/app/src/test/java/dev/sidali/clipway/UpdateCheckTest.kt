package dev.sidali.clipway

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Built-in updates: update.json, the APK's checksum and its signing certificate. */
class UpdateCheckTest {

    private val cert = "0b48d179121e2af12f34f73f9b68dbb8966cd6495174a507959e309a88fea38e"

    private fun manifest(
        version: String = "0.4.2",
        code: Long = 8,
        url: String? = null,
        sha: String = "a".repeat(64),
        size: Long = 1000,
        certSha: String = "0B:48:D1:79:12:1E:2A:F1:2F:34:F7:3F:9B:68:DB:B8:96:6C:D6:49:51:74:A5:07:95:9E:30:9A:88:FE:A3:8E",
    ): String = JSONObject()
        .put("version", version)
        .put("android", JSONObject().put("version", version).put("versionCode", code)
            .put("url", url ?: "https://clip.sidali.dev/download/clipway-$version.apk")
            .put("sha256", sha).put("size", size).put("certSha256", certSha))
        .put("mac", JSONObject().put("version", version))
        .put("notes", "Fixes.")
        .toString()

    @Test
    fun aNewerVersionCodeIsOffered() {
        val r = UpdateCheck.parse(manifest(), installedCode = 7)
        assertNotNull(r)
        assertEquals("0.4.2", r!!.version)
        assertEquals(8L, r.versionCode)
        assertEquals(cert, r.certSha256)
        assertEquals("Fixes.", r.notes)
    }

    @Test
    fun theSameOrAnOlderVersionCodeIsNot() {
        assertNull(UpdateCheck.parse(manifest(), installedCode = 8))
        assertNull(UpdateCheck.parse(manifest(), installedCode = 9))
    }

    @Test
    fun onlyTheReferenceHostAndTheExactFileName() {
        for (url in listOf(
            "http://clip.sidali.dev/download/clipway-0.4.2.apk",
            "https://example.org/download/clipway-0.4.2.apk",
            "https://clip.sidali.dev.example.org/download/clipway-0.4.2.apk",
            "https://clip.sidali.dev:8443/download/clipway-0.4.2.apk",
            "https://user@clip.sidali.dev/download/clipway-0.4.2.apk",
            "https://clip.sidali.dev/download/clipway-0.4.3.apk",
            "https://clip.sidali.dev/download/clipway-mac-0.4.2.zip",
            "https://clip.sidali.dev/download/../clipway-0.4.2.apk",
            "https://clip.sidali.dev/download/clipway-0.4.2.apk?x",
        )) assertNull(url, UpdateCheck.parse(manifest(url = url), 7))
    }

    @Test
    fun malformedManifestsAreIgnored() {
        assertNull(UpdateCheck.parse(null, 7))
        assertNull(UpdateCheck.parse("{", 7))
        assertNull(UpdateCheck.parse("[]", 7))
        assertNull(UpdateCheck.parse("""{"mac":{}}""", 7))
        assertNull(UpdateCheck.parse(manifest(version = "0.4"), 7))
        assertNull(UpdateCheck.parse(manifest(code = 0), -1))
        assertNull(UpdateCheck.parse(manifest(sha = "zz"), 7))
        assertNull(UpdateCheck.parse(manifest(certSha = "12"), 7))
        assertNull(UpdateCheck.parse(manifest(size = UpdateCheck.APK_MAX + 1), 7))
        assertNull(UpdateCheck.parse(manifest(size = 0), 7))
        assertNull(UpdateCheck.parse(" ".repeat(UpdateCheck.MANIFEST_MAX + 1), 7))
    }

    @Test
    fun theFileMustHaveTheSizeAndChecksum() {
        val f = File.createTempFile("clipway", ".apk")
        try {
            f.writeBytes(ByteArray(1000) { it.toByte() })
            val sha = UpdateCheck.sha256Hex(f.readBytes())
            assertTrue(UpdateCheck.fileMatches(f, UpdateCheck.parse(manifest(sha = sha), 7)!!))
            assertFalse(UpdateCheck.fileMatches(f, UpdateCheck.parse(manifest(sha = "b".repeat(64)), 7)!!))
            assertFalse(UpdateCheck.fileMatches(f, UpdateCheck.parse(manifest(sha = sha, size = 999), 7)!!))
            f.appendBytes(byteArrayOf(1))
            assertFalse(UpdateCheck.fileMatches(f, UpdateCheck.parse(manifest(sha = sha), 7)!!))
        } finally {
            f.delete()
        }
    }

    @Test
    fun certificates() {
        val ours = byteArrayOf(1, 2, 3)
        val other = byteArrayOf(9, 9, 9)
        val oursSha = UpdateCheck.sha256Hex(ours)
        // Same as installed and as announced: accepted; pinned too in release builds.
        assertNull(UpdateCheck.checkCertificates(listOf(ours), listOf(ours), oursSha, null))
        assertNull(UpdateCheck.checkCertificates(listOf(ours), listOf(ours), oursSha, oursSha))
        // Signed by another key: refused, whatever the manifest says.
        assertEquals(UpdateFailure.CERTIFICATE, UpdateCheck.checkCertificates(listOf(other), listOf(ours), UpdateCheck.sha256Hex(other), null))
        // The manifest names another certificate: refused.
        assertEquals(UpdateFailure.CERTIFICATE, UpdateCheck.checkCertificates(listOf(ours), listOf(ours), "c".repeat(64), null))
        // Release builds: not the certificate compiled in, refused.
        assertEquals(UpdateFailure.CERTIFICATE, UpdateCheck.checkCertificates(listOf(ours), listOf(ours), oursSha, cert))
        // An extra signer: refused.
        assertEquals(UpdateFailure.CERTIFICATE, UpdateCheck.checkCertificates(listOf(ours, other), listOf(ours), oursSha, null))
        assertEquals(UpdateFailure.CERTIFICATE, UpdateCheck.checkCertificates(emptyList(), listOf(ours), oursSha, null))
    }

    @Test
    fun thePinnedCertificateIsTheOneInSecurityMd() {
        val security = File("../../SECURITY.md").readText()
        val line = Regex("SHA-256: ([0-9A-F:]{95})").find(security)!!.groupValues[1]
        assertEquals(line.replace(":", "").lowercase(), BuildConfig.UPDATE_CERT_SHA256)
    }
}
