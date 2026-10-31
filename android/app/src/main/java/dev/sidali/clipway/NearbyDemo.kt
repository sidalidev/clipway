package dev.sidali.clipway

import android.os.Handler
import android.os.Looper
import androidx.annotation.RequiresApi

/**
 * Debug builds only: a Mac played in the app, without Bluetooth, so that nearby pairing can be
 * tried on the emulator (which has no Mac to find). The phone side is the real one: the same
 * [NearbyPhone] requests, keys, code, confirmation and packet as over the air; only the radio is
 * replaced by this stand-in, which answers like the Mac (docs/PROTOCOL.md, 13.7) and presses Pair
 * on its side a few seconds after the phone did.
 *
 * Started with `adb shell am start -n dev.sidali.clipway/.MainActivity --es nearby_demo '<pairing code>'`
 * (see android/README.md). [NearbyPairing.demoCode] is only set when BuildConfig.DEBUG is true, so
 * release builds never reach this class and R8 removes it.
 */
@RequiresApi(33)
class NearbyDemo(private val code: String, private val publish: (NearbyState) -> Unit) : NearbyPairing.Attempt {

    private val main = Handler(Looper.getMainLooper())
    private val phone = Nearby.generateKeyPair()
    private val machine = NearbyPhone(phone) { Nearby.sharedSecret(phone.privateKey, it) }
    private val mac = Nearby.generateKeyPair()
    private var pkPhone: ByteArray? = null
    private var macPressed = false
    private var confirmed = false
    private var finished = false

    fun start() {
        publish(NearbyState.Searching)
        main.postDelayed({ answer(machine.start()) }, FOUND_MS)
    }

    override fun pair() {
        if (finished || machine.phase != NearbyPhone.Phase.Code) return
        answer(machine.pair())
        refresh()
        // The person at the Mac presses Pair a moment later.
        main.postDelayed({ macPair() }, MAC_PAIR_MS)
    }

    override fun cancel() {
        finished = true
        main.removeCallbacksAndMessages(null)
        machine.end(NearbyPhone.Outcome.Canceled)
    }

    private fun macPair() {
        macPressed = true
        if (confirmed) notifyReady()
    }

    private fun notifyReady() = main.postDelayed({ answer(machine.status(byteArrayOf(Nearby.READY.toByte()))) }, STEP_MS)

    /** Answers one request as the Mac would, after a short radio delay. */
    private fun answer(op: NearbyPhone.Op?) {
        if (finished || op == null) return refresh()
        main.postDelayed({
            if (finished) return@postDelayed
            val next = when (op) {
                NearbyPhone.Op.Subscribe -> machine.subscribed()
                is NearbyPhone.Op.Read -> when (op.char) {
                    Nearby.COMMIT -> machine.read(op.char, Nearby.commitment(mac.publicKey))
                    Nearby.MAC_KEY -> machine.read(op.char, mac.publicKey)
                    Nearby.STATUS -> machine.read(op.char, byteArrayOf(Nearby.WAITING.toByte()))
                    Nearby.PACKET -> machine.read(op.char, packet())
                    else -> machine.error(op.char)
                }
                is NearbyPhone.Op.Write -> when (op.char) {
                    Nearby.PHONE_KEY -> {
                        pkPhone = op.value.copyOf()
                        machine.written(op.char)
                    }
                    Nearby.CONFIRM -> if (Crypto.same(op.value, Nearby.confirmTag(keys().sas, mac.publicKey, pkPhone!!))) {
                        confirmed = true
                        if (macPressed) notifyReady()
                        machine.written(op.char)
                    } else {
                        machine.error(op.char)
                    }
                    else -> machine.error(op.char)
                }
                NearbyPhone.Op.Leave -> null
            }
            answer(next)
        }, STEP_MS)
        refresh()
    }

    private fun keys(): Nearby.Keys {
        val pk = pkPhone!!
        return Nearby.derive(Nearby.sharedSecret(mac.privateKey, pk), mac.publicKey, pk)
    }

    private fun packet(): ByteArray = Nearby.sealPacket(keys().key, mac.publicKey, pkPhone!!, code, Crypto.randomBytes(Crypto.NONCE_SIZE))

    private fun refresh() {
        if (finished) return
        when (machine.phase) {
            NearbyPhone.Phase.Code, NearbyPhone.Phase.Confirmed ->
                publish(NearbyState.Code(machine.code!!, machine.phase == NearbyPhone.Phase.Confirmed))
            NearbyPhone.Phase.Receiving -> publish(NearbyState.Finishing(machine.code!!))
            NearbyPhone.Phase.Ended -> {
                finished = true
                main.removeCallbacksAndMessages(null)
                publish(
                    when (val o = machine.outcome) {
                        is NearbyPhone.Outcome.Paired -> NearbyState.Paired(o.code)
                        else -> NearbyState.Ended(NearbyState.Why.Failed)
                    },
                )
            }
            else -> Unit
        }
    }

    companion object {
        private const val FOUND_MS = 1_500L
        private const val STEP_MS = 60L
        private const val MAC_PAIR_MS = 2_500L

        /**
         * Checks this phone's X25519 and the derivations against the vectors (RFC 7748, section 6.1:
         * Mac = Alice, phone = Bob; docs/VECTORS.json, `nearby`). The JVM tests use the JDK; this
         * runs the same code on Android's provider. Logged as "Nearby self-check".
         */
        fun selfCheck(): String = try {
            val mac = Nearby.keyPairFromRaw(Crypto.fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
            val phone = Nearby.keyPairFromRaw(Crypto.fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
            val z = Nearby.sharedSecret(phone.privateKey, mac.publicKey)
            val k = Nearby.derive(z, mac.publicKey, phone.publicKey)
            val packet = Nearby.sealPacket(k.key, mac.publicKey, phone.publicKey, "clipway:AAECAwQFBgcICQoLDA0ODw", Crypto.fromHex("c0c1c2c3c4c5c6c7c8c9cacb"))
            val fresh = Nearby.generateKeyPair()
            val checks = mapOf(
                "mac key" to (Crypto.hex(mac.publicKey) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
                "phone key" to (Crypto.hex(phone.publicKey) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
                "Z" to (Crypto.hex(z) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
                "Z both ways" to Crypto.same(z, Nearby.sharedSecret(mac.privateKey, phone.publicKey)),
                "code" to (Nearby.code(k.sas, mac.publicKey, phone.publicKey) == "5456"),
                "confirm" to (Crypto.hex(Nearby.confirmTag(k.sas, mac.publicKey, phone.publicKey)) == "728d99b4c5f2a3e067b4e71d736d7948"),
                "packet" to (Crypto.hex(packet) == PACKET),
                "packet opens" to (Nearby.openPacket(k.key, mac.publicKey, phone.publicKey, packet) == "clipway:AAECAwQFBgcICQoLDA0ODw"),
                "fresh pair" to Crypto.same(
                    Nearby.sharedSecret(fresh.privateKey, mac.publicKey), Nearby.sharedSecret(mac.privateKey, fresh.publicKey),
                ),
                "low-order key refused" to runCatching { Nearby.sharedSecret(phone.privateKey, ByteArray(32)) }.isFailure,
            )
            val failed = checks.filterValues { !it }.keys
            if (failed.isEmpty()) "ok (${checks.size} checks)" else "FAILED: ${failed.joinToString()}"
        } catch (e: Exception) {
            "FAILED: ${e.javaClass.simpleName}: ${e.message}"
        }

        private const val PACKET =
            "c0c1c2c3c4c5c6c7c8c9cacbfa753743685bf63ee4952bd86a1cc59c1a37d8eabab35a5451a1134e3cb3082e1f1649ae" +
            "09c40acdda399794cd7eaed0f11d4055e2c14bcdff5cdc96366e07b4f7c0679adbc3c33566d9ad54a83e54d2b503e08f" +
            "487e79acbbedd3b5caf7e971855ddaa3497360f20f6bf26b14081ad289ce11f654984aa3a3aa58d2b234f0834ef45cbc" +
            "faa6a8d1af5843e17e66ad14c75a6b385b0afeba100712a208778df4fbcbc641288c32e18960b129e9e29b2bd50b3902" +
            "9095730f38fced48fab54a917de00a6acfe296c601f0ace8a4448d0ff848744ca4b4b2e32445199b8e4c142b29964f11" +
            "e030ddd2b05f3733296e4f8664f1d6b349a71880eacc6930475ea57a9b57b90b17f7a714ea27d9fc68110156"
    }
}
