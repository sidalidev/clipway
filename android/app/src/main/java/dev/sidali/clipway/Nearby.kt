package dev.sidali.clipway

import androidx.annotation.RequiresApi
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID
import javax.crypto.KeyAgreement

/**
 * Nearby pairing over Bluetooth LE (docs/PROTOCOL.md, section 13), the phone's side without any
 * radio: constants, the X25519 exchange, the derivations, the packet, and [NearbyPhone], the order
 * of the requests the phone makes. Pure JVM, checked against the `nearby` block of
 * docs/VECTORS.json. The radio is in NearbyCentral.kt, the screen in PairNearby.kt.
 *
 * X25519 comes from the platform (java.security "XDH", Android 13 and later): no new dependency.
 */
object Nearby {

    private fun uuid(prefix: String): UUID = UUID.fromString("$prefix-4541-4fcc-bcac-ee9b5ce269d0")

    /** Version 1 of the exchange is this service UUID. */
    val SERVICE: UUID = uuid("a4985110")
    val COMMIT: UUID = uuid("a4985111")
    val PHONE_KEY: UUID = uuid("a4985112")
    val MAC_KEY: UUID = uuid("a4985113")
    val CONFIRM: UUID = uuid("a4985114")
    val STATUS: UUID = uuid("a4985115")
    val PACKET: UUID = uuid("a4985116")
    val CHARACTERISTICS: List<UUID> = listOf(COMMIT, PHONE_KEY, MAC_KEY, CONFIRM, STATUS, PACKET)

    /** Client Characteristic Configuration Descriptor: turns Status notifications on. */
    val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    const val KEY_SIZE = 32
    const val CONFIRM_SIZE = 16
    const val CODE_DIGITS = 4
    const val PACKET_PLAINTEXT_SIZE = 256
    const val PACKET_SIZE = Crypto.NONCE_SIZE + PACKET_PLAINTEXT_SIZE + Crypto.TAG_SIZE
    const val MAX_CODE_LENGTH = 230

    // Status values (one byte).
    const val WAITING = 0x00
    const val READY = 0x01
    const val CANCELED = 0x02
    const val EXPIRED = 0x03
    const val FAILED = 0x04
    const val BUSY = 0x05

    // Times and limits (13.6).
    /** The phone's attempt: 120 s from the tap. */
    const val SESSION_MS = 120_000L
    /** No Mac found after this long: "No Mac found nearby". */
    const val NO_MAC_MS = 30_000L
    /** After the first scan result, keep scanning this long and take the strongest signal. */
    const val EXTRA_SCAN_MS = 1_000L
    /** One connection, retry included. */
    const val CONNECT_MS = 5_000L
    /** A quick failure (133, 62 or 8) within this time gets one more try... */
    const val RETRY_WITHIN_MS = 3_000L
    /** ...after this pause, the time for the stack to release the failed connection. */
    const val RETRY_PAUSE_MS = 400L
    /** From connected to the code on screen. */
    const val TO_CODE_MS = 10_000L
    /** From Status ready to the packet read. */
    const val TO_PACKET_MS = 10_000L
    const val REQUEST_MTU = 517
    /** A 32-byte write needs 3 bytes of ATT header on top. */
    const val MIN_MTU = 35
    /** Android silently refuses more than 5 scan starts in 30 s: at most 4. */
    const val SCAN_STARTS = 4
    const val SCAN_WINDOW_MS = 30_000L

    private const val LABEL_COMMIT = "clipway-nearby-commit"
    private const val LABEL_SECRET = "clipway-nearby"
    private const val LABEL_SAS = "clipway-nearby-sas"
    private const val LABEL_KEY = "clipway-nearby-key"
    private const val LABEL_CONFIRM = "clipway-nearby-confirm"
    private const val LABEL_AAD = "clipway-nearby"

    /** DER prefixes that wrap a raw X25519 key for java.security. */
    private val PKCS8_PREFIX = Crypto.fromHex("302e020100300506032b656e04220420")
    private val X509_PREFIX = Crypto.fromHex("302a300506032b656e032100")

    /** A connection failure worth a second try: 133 (GATT_ERROR), 62 (not established), 8 (timeout). */
    fun retryable(status: Int): Boolean = status == 133 || status == 62 || status == 8

    // ---------------------------------------------------------------------
    // X25519 (java.security XDH: Android 13 and later, any JDK 11 and later)
    // ---------------------------------------------------------------------

    /** An ephemeral key pair: the private key stays inside java.security, the public key is raw. */
    class KeyPair(val privateKey: PrivateKey, val publicKey: ByteArray)

    /** Thrown for any key, commitment or packet that must end the attempt. */
    class Refused(message: String) : Exception(message)

    /**
     * A new key pair, drawn for one attempt only. The JDK wants the curve named; Android's provider
     * (Conscrypt) refuses NamedParameterSpec with InvalidAlgorithmParameterException and draws
     * X25519 by default, so the generator is used as it comes there. The key is checked either way.
     */
    @RequiresApi(33)
    fun generateKeyPair(): KeyPair {
        val kp = try {
            KeyPairGenerator.getInstance("XDH").apply { initialize(NamedParameterSpec.X25519) }.generateKeyPair()
        } catch (e: java.security.InvalidAlgorithmParameterException) {
            KeyPairGenerator.getInstance("XDH").generateKeyPair()
        }
        val pk = rawPublic(kp.public.encoded)
        if (pk[KEY_SIZE - 1].toInt() and 0x80 != 0) throw Refused("Not an X25519 key")
        return KeyPair(kp.private, pk)
    }

    /** A fixed key pair from a raw private key: tests and vectors only. */
    @RequiresApi(33)
    fun keyPairFromRaw(privateKey: ByteArray): KeyPair {
        require(privateKey.size == KEY_SIZE) { "32-byte private key expected" }
        val f = KeyFactory.getInstance("XDH")
        val sk = f.generatePrivate(PKCS8EncodedKeySpec(PKCS8_PREFIX + privateKey))
        // The public key of a private key: X25519 with the base point u = 9.
        val base = ByteArray(KEY_SIZE).also { it[0] = 9 }
        val pk = KeyAgreement.getInstance("XDH").run {
            init(sk)
            doPhase(f.generatePublic(X509EncodedKeySpec(X509_PREFIX + base)), true)
            generateSecret()
        }
        return KeyPair(sk, pk)
    }

    /** The raw public key: the last 32 bytes of the X.509 encoding (44 bytes, X25519 prefix). */
    fun rawPublic(encoded: ByteArray): ByteArray {
        if (encoded.size != X509_PREFIX.size + KEY_SIZE || !Crypto.same(encoded.copyOf(X509_PREFIX.size), X509_PREFIX)) {
            throw Refused("Not an X25519 public key")
        }
        return encoded.copyOfRange(X509_PREFIX.size, encoded.size)
    }

    /**
     * Checks the other side's key before use (13.4): 32 bytes, the top bit of its last byte clear,
     * and not our own key sent back.
     */
    fun checkPeerKey(peer: ByteArray, own: ByteArray) {
        if (peer.size != KEY_SIZE) throw Refused("Key refused: 32 bytes expected")
        if (peer[KEY_SIZE - 1].toInt() and 0x80 != 0) throw Refused("Key refused: top bit set")
        if (Crypto.same(peer, own)) throw Refused("Key refused: our own key")
    }

    /** Z = X25519(own private key, peer public key). A low-order point (Z all zeros, or a throw) is refused. */
    @RequiresApi(33)
    fun sharedSecret(own: PrivateKey, peer: ByteArray): ByteArray {
        val z = try {
            val pub = KeyFactory.getInstance("XDH").generatePublic(X509EncodedKeySpec(X509_PREFIX + peer))
            KeyAgreement.getInstance("XDH").run {
                init(own)
                doPhase(pub, true)
                generateSecret()
            }
        } catch (e: Exception) {
            throw Refused("Key refused: low-order point")
        }
        if (z.size != KEY_SIZE || z.all { it.toInt() == 0 }) throw Refused("Key refused: low-order point")
        return z
    }

    // ---------------------------------------------------------------------
    // Derivations (13.4)
    // ---------------------------------------------------------------------

    private fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)

    private fun hkdf32(ikm: ByteArray, label: String) = Crypto.hkdf(ikm, ByteArray(0), utf8(label), 32)

    /** commit = SHA-256("clipway-nearby-commit" || pk_mac). */
    fun commitment(pkMac: ByteArray): ByteArray = Crypto.sha256(utf8(LABEL_COMMIT), pkMac)

    /** T = pk_mac || pk_phone, always the Mac first. */
    fun transcript(pkMac: ByteArray, pkPhone: ByteArray): ByteArray = pkMac + pkPhone

    /** N, K_sas and K_key. */
    class Keys(val n: ByteArray, val sas: ByteArray, val key: ByteArray) {
        fun forget() {
            n.fill(0)
            sas.fill(0)
            key.fill(0)
        }
    }

    /** N = HKDF(Z || T, "clipway-nearby"), K_sas = HKDF(N, "clipway-nearby-sas"), K_key = HKDF(N, "clipway-nearby-key"). */
    fun derive(z: ByteArray, pkMac: ByteArray, pkPhone: ByteArray): Keys {
        val n = hkdf32(z + transcript(pkMac, pkPhone), LABEL_SECRET)
        return Keys(n, hkdf32(n, LABEL_SAS), hkdf32(n, LABEL_KEY))
    }

    /** The first 6 bytes of HMAC-SHA256(K_sas, T). */
    fun sasBytes(kSas: ByteArray, pkMac: ByteArray, pkPhone: ByteArray): ByteArray =
        Crypto.hmacSha256(kSas, transcript(pkMac, pkPhone)).copyOf(6)

    /** 6 bytes as an unsigned big-endian integer, modulo 10 000, 4 digits with leading zeros. */
    fun sasFromBytes(six: ByteArray): String {
        require(six.size == 6) { "6 bytes expected" }
        var v = 0L
        for (b in six) v = (v shl 8) or (b.toLong() and 0xff)
        return (v % 10_000).toString().padStart(CODE_DIGITS, '0')
    }

    /** The 4-digit code both screens show. */
    fun code(kSas: ByteArray, pkMac: ByteArray, pkPhone: ByteArray): String = sasFromBytes(sasBytes(kSas, pkMac, pkPhone))

    /** confirm = HMAC-SHA256(K_sas, "clipway-nearby-confirm" || T)[0:16], written when the person presses Pair. */
    fun confirmTag(kSas: ByteArray, pkMac: ByteArray, pkPhone: ByteArray): ByteArray =
        Crypto.hmacSha256(kSas, utf8(LABEL_CONFIRM) + transcript(pkMac, pkPhone)).copyOf(CONFIRM_SIZE)

    /** "clipway-nearby|<hex pk_mac>|<hex pk_phone>", 144 bytes. */
    fun aad(pkMac: ByteArray, pkPhone: ByteArray): String = "$LABEL_AAD|${Crypto.hex(pkMac)}|${Crypto.hex(pkPhone)}"

    // ---------------------------------------------------------------------
    // Packet (13.5)
    // ---------------------------------------------------------------------

    /**
     * {"v":1,"code":"<pairing code>"}, serialized like a head and padded to exactly 256 bytes. The
     * pairing code is base64url and a percent-encoded URL: nothing in it needs JSON escaping.
     */
    fun packetPlaintext(code: String): String {
        require(code.startsWith(Crypto.QR_PREFIX) && code.all { it in ' '..'~' && it != '"' && it != '\\' }) { "Invalid pairing code" }
        val json = "{\"v\":1,\"code\":\"$code\"}"
        val length = utf8(json).size
        require(length + 9 <= PACKET_PLAINTEXT_SIZE) { "Pairing code too long for nearby pairing" }
        return json.dropLast(1) + ",\"pad\":\"" + " ".repeat(PACKET_PLAINTEXT_SIZE - length - 9) + "\"}"
    }

    /** nonce (12) || AES-256-GCM ciphertext (256) || tag (16). The Mac's side; here for the tests. */
    fun sealPacket(kKey: ByteArray, pkMac: ByteArray, pkPhone: ByteArray, code: String, nonce: ByteArray): ByteArray {
        val e = Crypto.seal(kKey, aad(pkMac, pkPhone), utf8(packetPlaintext(code)), nonce)
        return Crypto.fromHex(e.nonce) + Base64.getDecoder().decode(e.enc)
    }

    /**
     * Opens a packet: exactly 284 bytes, authentication, JSON, v equal to 1, code a string.
     * Returns the pairing code, to be read by Crypto.fromQr like a scanned one. Throws [Refused].
     */
    fun openPacket(kKey: ByteArray, pkMac: ByteArray, pkPhone: ByteArray, packet: ByteArray): String {
        if (packet.size != PACKET_SIZE) throw Refused("Packet of the wrong size")
        val envelope = Crypto.Envelope(
            Crypto.hex(packet.copyOf(Crypto.NONCE_SIZE)),
            Base64.getEncoder().encodeToString(packet.copyOfRange(Crypto.NONCE_SIZE, packet.size)),
        )
        val plain = try {
            Crypto.open(kKey, aad(pkMac, pkPhone), envelope)
        } catch (e: Exception) {
            throw Refused("Packet authentication failed")
        }
        val code = try {
            val o = JSONObject(String(plain, Charsets.UTF_8))
            if (o.opt("v") != 1) throw Refused("Unknown packet version")
            o.get("code") as? String ?: throw Refused("Packet without a code")
        } catch (e: Refused) {
            throw e
        } catch (e: Exception) {
            throw Refused("Packet is not JSON")
        } finally {
            plain.fill(0)
        }
        return code
    }
}

/**
 * The phone's side of one attempt, without radio: which request comes next, and what each answer
 * means. The radio layer (NearbyCentral) performs each [Op] and reports back; nothing here talks
 * to Bluetooth, so the JVM tests replay the vector sessions through it.
 *
 * Order (13.3): subscribe to Status, read Commit, write Phone key, read Mac key, check the
 * commitment, show the code; on Pair write Confirm; on Status ready read Packet, open it, leave.
 */
class NearbyPhone(private val own: Nearby.KeyPair, private val agree: (ByteArray) -> ByteArray) {

    /** A request for the radio layer. */
    sealed interface Op {
        data object Subscribe : Op
        data class Read(val char: UUID) : Op
        class Write(val char: UUID, val value: ByteArray) : Op
        /** Disconnect and close: the attempt is over (see [outcome]). */
        data object Leave : Op
    }

    /** How the attempt ended. */
    sealed interface Outcome {
        /** The pairing code, read from the packet: continue as after a scan. */
        class Paired(val code: String) : Outcome
        data object Canceled : Outcome
        data object Expired : Outcome
        data object Failed : Outcome
        data object Busy : Outcome
    }

    enum class Phase { Start, Exchange, Code, Confirmed, Receiving, Ended }

    var phase = Phase.Start
        private set

    /** The 4-digit code, once both keys are known. */
    var code: String? = null
        private set

    var outcome: Outcome? = null
        private set

    private var commit: ByteArray? = null
    private var pkMac: ByteArray? = null
    private var keys: Nearby.Keys? = null
    private var ready = false
    private var packetAsked = false
    private var keyRefused = false

    /** Services found and checked: the first request. */
    fun start(): Op {
        check(phase == Phase.Start)
        phase = Phase.Exchange
        return Op.Subscribe
    }

    /** Status notifications are on. Commit is read before the phone sends its key (13.9). */
    fun subscribed(): Op? = if (phase == Phase.Exchange && commit == null) Op.Read(Nearby.COMMIT) else null

    fun read(char: UUID, value: ByteArray): Op? {
        if (phase == Phase.Ended) return null
        return when (char) {
            Nearby.COMMIT -> {
                if (phase != Phase.Exchange || commit != null) return null
                if (value.size != 32) return end(Outcome.Failed)
                commit = value.copyOf()
                Op.Write(Nearby.PHONE_KEY, own.publicKey.copyOf())
            }
            Nearby.MAC_KEY -> {
                if (phase != Phase.Exchange || pkMac != null) return null
                try {
                    Nearby.checkPeerKey(value, own.publicKey)
                    if (!Crypto.same(Nearby.commitment(value), commit ?: return end(Outcome.Failed))) {
                        throw Nearby.Refused("Commitment does not match the Mac key")
                    }
                    val z = agree(value)
                    val k = Nearby.derive(z, value, own.publicKey)
                    z.fill(0)
                    pkMac = value.copyOf()
                    keys = k
                    code = Nearby.code(k.sas, value, own.publicKey)
                    phase = Phase.Code
                    null
                } catch (e: Exception) {
                    end(Outcome.Failed)
                }
            }
            Nearby.STATUS -> status(value)
            Nearby.PACKET -> {
                if (phase != Phase.Receiving) return null
                val k = keys ?: return end(Outcome.Failed)
                try {
                    end(Outcome.Paired(Nearby.openPacket(k.key, pkMac!!, own.publicKey, value)))
                } catch (e: Exception) {
                    end(Outcome.Failed)
                }
            }
            else -> null
        }
    }

    fun written(char: UUID): Op? {
        if (phase == Phase.Ended) return null
        return when (char) {
            Nearby.PHONE_KEY -> if (phase == Phase.Exchange) Op.Read(Nearby.MAC_KEY) else null
            Nearby.CONFIRM -> if (phase == Phase.Confirmed && ready) receive() else null
            else -> null
        }
    }

    /** The person pressed Pair on the phone. */
    fun pair(): Op? {
        if (phase != Phase.Code) return null
        val k = keys ?: return null
        phase = Phase.Confirmed
        return Op.Write(Nearby.CONFIRM, Nearby.confirmTag(k.sas, pkMac!!, own.publicKey))
    }

    /** A Status value, notified or read. */
    fun status(value: ByteArray): Op? {
        if (phase == Phase.Ended || value.size != 1) return null
        return when (value[0].toInt() and 0xff) {
            Nearby.WAITING -> if (keyRefused) end(Outcome.Failed) else null
            // After Pair on the phone, ready asks for the packet once, whether it comes before or
            // after the answer to Confirm (the radio layer runs one request at a time).
            Nearby.READY -> {
                ready = true
                if (phase == Phase.Confirmed) receive() else null
            }
            Nearby.CANCELED -> end(Outcome.Canceled)
            Nearby.EXPIRED -> end(Outcome.Expired)
            Nearby.FAILED -> end(Outcome.Failed)
            Nearby.BUSY -> end(Outcome.Busy)
            else -> end(Outcome.Failed)
        }
    }

    /** A request was refused by the Mac (an ATT error), or could not be made. */
    fun error(char: UUID): Op? {
        if (phase == Phase.Ended) return null
        // A refused key: another phone took this attempt (Status reads 05), or something else.
        if (char == Nearby.PHONE_KEY && !keyRefused) {
            keyRefused = true
            return Op.Read(Nearby.STATUS)
        }
        return end(Outcome.Failed)
    }

    private fun receive(): Op? {
        if (packetAsked) return null
        packetAsked = true
        phase = Phase.Receiving
        return Op.Read(Nearby.PACKET)
    }

    /** Ends the attempt from the outside (cancel, timeout): forgets the keys. */
    fun end(o: Outcome): Op {
        if (phase != Phase.Ended) {
            outcome = o
            phase = Phase.Ended
            keys?.forget()
            keys = null
        }
        return Op.Leave
    }
}
