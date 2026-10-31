package dev.sidali.clipway

import java.math.BigInteger
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Clipway cryptography, as specified in docs/PROTOCOL.md and checked against docs/VECTORS.json
 * (the same vectors as relay/crypto.js and the Mac app). Same construction as the Sonne sync
 * chain, with Clipway labels. Pure functions without Android dependencies: tested on the JVM.
 * Only standard primitives from the platform: HMAC-SHA256 (HKDF per RFC 5869), SHA-256, AES-256-GCM.
 */
object Crypto {

    const val SECRET_SIZE = 16
    const val PROOF_SIZE = 16
    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16
    const val FP_SIZE = 16
    const val PAD_BLOCK = 512
    /** Largest text: 64 KiB. The relay carries texts only. */
    const val TEXT_MAX = 65_536
    /** Largest head plaintext: a 64 KiB text with the largest fields, padded (172 x 512). */
    const val HEAD_MAX = 88_064
    /** Largest image or file, sent directly between the devices (docs/PROTOCOL.md, section 14). */
    const val FILE_MAX = 26_214_400
    const val QR_PREFIX = "clipway:"
    const val SUBPROTOCOL = "clipway.v1"

    private val random = SecureRandom()

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            sb.append("0123456789abcdef"[v shr 4]).append("0123456789abcdef"[v and 0xf])
        }
        return sb.toString()
    }

    /** Hex to bytes. Throws IllegalArgumentException if the text is not even-length hex. */
    fun fromHex(text: String): ByteArray {
        require(text.length % 2 == 0) { "Hex of odd length" }
        return ByteArray(text.length / 2) { i ->
            val hi = Character.digit(text[2 * i], 16)
            val lo = Character.digit(text[2 * i + 1], 16)
            require(hi >= 0 && lo >= 0) { "Non-hex character" }
            ((hi shl 4) or lo).toByte()
        }
    }

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** HKDF-SHA256 (RFC 5869). An empty salt is the same as 32 zero bytes. */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var filled = 0
        var counter = 1
        while (filled < length) {
            previous = hmacSha256(prk, previous + info + byteArrayOf(counter.toByte()))
            val n = minOf(previous.size, length - filled)
            System.arraycopy(previous, 0, out, filled, n)
            filled += n
            counter++
        }
        return out
    }

    /** Constant-time comparison. */
    fun same(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    private fun checkSecret(s: ByteArray) = require(s.size == SECRET_SIZE) { "Invalid key: $SECRET_SIZE bytes expected" }

    private fun label(s: ByteArray, info: String, length: Int): ByteArray {
        checkSecret(s)
        return hkdf(s, ByteArray(0), info.toByteArray(Charsets.UTF_8), length)
    }

    // ---------------------------------------------------------------------
    // Secret, proof, chain id and keys
    // ---------------------------------------------------------------------

    fun generateSecret(): ByteArray = randomBytes(SECRET_SIZE)

    /** P = HKDF-SHA256(S, empty salt, "clipway-proof", 16). Shown to the relay, never S. */
    fun proof(s: ByteArray): ByteArray = label(s, "clipway-proof", PROOF_SIZE)

    /** Chain id = hex(SHA-256("clipway-id" || P))[0:32]. The relay computes it from P. */
    fun idFromProof(p: ByteArray): String {
        require(p.size == PROOF_SIZE) { "Invalid proof: $PROOF_SIZE bytes expected" }
        return hex(sha256("clipway-id".toByteArray(Charsets.UTF_8), p)).substring(0, 32)
    }

    fun chainId(s: ByteArray): String = idFromProof(proof(s))

    /** K_enc = HKDF-SHA256(S, empty salt, "clipway-enc", 32). */
    fun encKey(s: ByteArray): ByteArray = label(s, "clipway-enc", 32)

    /** K_mac = HKDF-SHA256(S, empty salt, "clipway-mac", 32). */
    fun macKey(s: ByteArray): ByteArray = label(s, "clipway-mac", 32)

    /** K_direct = HKDF-SHA256(S, empty salt, "clipway-direct", 32): root of the direct transfer keys. */
    fun directKey(s: ByteArray): ByteArray = label(s, "clipway-direct", 32)

    /** WebSocket subprotocols: "clipway.v1, clipway.p.<hex P>". The chain id never goes in a URL. */
    fun subprotocols(s: ByteArray): List<String> = listOf(SUBPROTOCOL, "clipway.p." + hex(proof(s)))

    /** fp = hex(HMAC-SHA256(K_mac, content)[0:16]). */
    fun fingerprint(kMac: ByteArray, content: ByteArray): String = hex(hmacSha256(kMac, content).copyOf(FP_SIZE))

    // ---------------------------------------------------------------------
    // Envelope: AES-256-GCM { nonce: hex(12), enc: base64(ciphertext || tag) }
    // ---------------------------------------------------------------------

    data class Envelope(val nonce: String, val enc: String)

    /** Seals bytes with K_enc. aad is authenticated as UTF-8. Never pass a fixed nonce outside tests. */
    fun seal(kEnc: ByteArray, aad: String, plaintext: ByteArray, nonce: ByteArray = randomBytes(NONCE_SIZE)): Envelope {
        require(nonce.size == NONCE_SIZE) { "12-byte nonce expected" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(kEnc, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
        c.updateAAD(aad.toByteArray(Charsets.UTF_8))
        return Envelope(hex(nonce), Base64.getEncoder().encodeToString(c.doFinal(plaintext)))
    }

    /** Opens an envelope. Throws if the key, the aad or the bytes do not match. */
    fun open(kEnc: ByteArray, aad: String, envelope: Envelope): ByteArray {
        val iv = fromHex(envelope.nonce)
        require(iv.size == NONCE_SIZE) { "12-byte nonce expected" }
        val data = Base64.getDecoder().decode(envelope.enc)
        require(data.size >= TAG_SIZE) { "Envelope too short" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(kEnc, "AES"), GCMParameterSpec(TAG_SIZE * 8, iv))
        c.updateAAD(aad.toByteArray(Charsets.UTF_8))
        return c.doFinal(data)
    }

    /**
     * Pads a serialized head: adds "pad" (spaces) before the final "}" so that the UTF-8 length is the
     * smallest multiple of 512 that is at least the length + 9. Input: JSON without pad, ending with "}".
     */
    fun padHead(json: String): String {
        require(json.length >= 2 && json.endsWith("}")) { "Invalid head JSON" }
        val length = json.toByteArray(Charsets.UTF_8).size
        val total = (length + 9 + PAD_BLOCK - 1) / PAD_BLOCK * PAD_BLOCK
        return json.dropLast(1) + ",\"pad\":\"" + " ".repeat(total - length - 9) + "\"}"
    }

    // ---------------------------------------------------------------------
    // 12 BIP39 words (128 bits + 4 checksum bits)
    // ---------------------------------------------------------------------

    /** S to 12 words, with the official English list of 2048 words (res/raw/bip39_english.txt). */
    fun toWords(s: ByteArray, list: List<String>): List<String> {
        checkSecret(s)
        require(list.size == 2048) { "2048-word BIP39 list expected" }
        val checksum = (sha256(s)[0].toInt() and 0xff) shr 4
        val bits = BigInteger(1, s).shiftLeft(4).or(BigInteger.valueOf(checksum.toLong()))
        val mask = BigInteger.valueOf(0x7ff)
        return (11 downTo 0).map { i -> list[bits.shiftRight(i * 11).and(mask).toInt()] }
    }

    /** 12 words to S. Throws IllegalArgumentException if a word is unknown or the checksum is wrong. */
    fun fromWords(text: String, list: List<String>): ByteArray {
        val words = text.trim().lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
        require(words.size == 12) { "Exactly 12 words expected" }
        var bits = BigInteger.ZERO
        for (w in words) {
            val index = list.indexOf(w)
            require(index >= 0) { "Unknown word: $w" }
            bits = bits.shiftLeft(11).or(BigInteger.valueOf(index.toLong()))
        }
        val checksum = bits.and(BigInteger.valueOf(0xf)).toInt()
        val raw = bits.shiftRight(4).toByteArray()
        val s = ByteArray(SECRET_SIZE)
        // BigInteger may add a sign byte or drop leading zeros: align to the right.
        val n = minOf(raw.size, SECRET_SIZE)
        System.arraycopy(raw, raw.size - n, s, SECRET_SIZE - n, n)
        require(((sha256(s)[0].toInt() and 0xff) shr 4) == checksum) { "Wrong checksum" }
        return s
    }

    // ---------------------------------------------------------------------
    // Pairing QR code: clipway:<base64url(S)>[?relay=<percent-encoded URL>]
    // ---------------------------------------------------------------------

    /** Result of reading a pairing code. relay is null when the code names none (default relay). */
    class Pairing(val secret: ByteArray, val relay: String?)

    fun toQr(s: ByteArray, relay: String, defaultRelay: String): String {
        checkSecret(s)
        val base = QR_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(s)
        val r = relay.trimEnd('/')
        return if (r.isEmpty() || r == defaultRelay.trimEnd('/')) base else base + "?relay=" + URLEncoder.encode(r, "UTF-8")
    }

    private val reKey = Regex("^[A-Za-z0-9_-]{22}$")

    /** Reads a pairing code. Throws IllegalArgumentException if malformed. */
    fun fromQr(text: String): Pairing {
        val t = text.trim()
        require(t.startsWith(QR_PREFIX)) { "Invalid code: clipway: expected" }
        val rest = t.substring(QR_PREFIX.length)
        val q = rest.indexOf('?')
        val value = (if (q < 0) rest else rest.substring(0, q)).trimEnd('=')
        require(reKey.matches(value)) { "Invalid code: malformed key" }
        val s = Base64.getUrlDecoder().decode(value)
        require(s.size == SECRET_SIZE) { "Invalid code: key of the wrong size" }
        var relay: String? = null
        if (q >= 0) {
            val param = rest.substring(q + 1).split('&').firstOrNull { it.startsWith("relay=") }?.removePrefix("relay=")
            if (!param.isNullOrEmpty()) {
                val r = URLDecoder.decode(param, "UTF-8").trimEnd('/')
                val scheme = runCatching { URI(r).scheme }.getOrNull()
                require(scheme == "https" || scheme == "http") { "Invalid code: relay must be http(s)" }
                relay = r
            }
        }
        return Pairing(s, relay)
    }
}
