package dev.sidali.clipway

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.os.SystemClock
import android.util.Log
import androidx.annotation.RequiresApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** What the Pair nearby screen shows. */
sealed interface NearbyState {
    data object Idle : NearbyState
    /** Scanning, then connecting to the Mac found: "Looking for your Mac." */
    data object Searching : NearbyState
    /** The code on screen; [pressed] once the person pressed Pair on the phone. */
    data class Code(val code: String, val pressed: Boolean) : NearbyState
    /** Both sides pressed Pair: the packet is on its way. */
    data class Finishing(val code: String) : NearbyState
    /** The pairing code from the packet: the screen continues as after a scan. */
    class Paired(val code: String) : NearbyState
    data class Ended(val why: Why) : NearbyState

    enum class Why { NoMac, Canceled, Expired, Failed, Busy, BluetoothOff, NotAllowed, Unavailable }

    /** An attempt is running (the radio is in use). */
    val active: Boolean get() = this is Searching || this is Code || this is Finishing
}

/**
 * The one nearby attempt of the app, shared by the screen across rotations. Bluetooth is used
 * only between [start] and the end of the attempt, at most 120 s, and only from the foreground
 * pairing screen.
 */
object NearbyPairing {
    private val mutable = MutableStateFlow<NearbyState>(NearbyState.Idle)
    val state: StateFlow<NearbyState> = mutable
    private var central: Attempt? = null

    /** One running attempt, as the screen sees it. */
    interface Attempt {
        fun pair()
        fun cancel()
    }

    /** The permissions of nearby pairing (Nearby devices). BLUETOOTH_SCAN is neverForLocation. */
    val PERMISSIONS = arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)

    /** Offered on Android 13 and later (X25519 in the platform), on a phone with Bluetooth LE. */
    fun offered(c: Context): Boolean =
        Build.VERSION.SDK_INT >= 33 && c.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)

    fun allowed(c: Context): Boolean = PERMISSIONS.all { c.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }

    private fun adapter(c: Context): BluetoothAdapter? =
        try {
            c.getSystemService(BluetoothManager::class.java)?.adapter
        } catch (_: Exception) {
            null
        }

    /** Bluetooth present on this phone. */
    fun present(c: Context): Boolean = adapter(c) != null

    /** Bluetooth on (no permission needed to read it since Android 12). */
    fun on(c: Context): Boolean =
        try {
            adapter(c)?.isEnabled == true
        } catch (_: Exception) {
            false
        }

    /** Starts a new attempt: new keys, a new scan. Never retries on its own. */
    fun start(c: Context) {
        central?.cancel()
        central = null
        if (Build.VERSION.SDK_INT < 33) {
            mutable.value = NearbyState.Ended(NearbyState.Why.Unavailable)
            return
        }
        val publish = { s: NearbyState ->
            mutable.value = s
            if (!s.active) central = null
        }
        // Debug builds only: a Mac played in the app, for the emulator (NearbyDemo.kt).
        val demo = demoCode
        if (BuildConfig.DEBUG && demo != null) {
            val d = NearbyDemo(demo, publish)
            central = d
            d.start()
            return
        }
        val n = NearbyCentral(c.applicationContext, publish)
        central = n
        n.start()
    }

    /** Debug builds only: the pairing code the stand-in Mac of NearbyDemo sends. */
    @Volatile
    var demoCode: String? = null

    fun pair() {
        central?.pair()
    }

    /** Cancel on the phone, or the screen left: disconnects, forgets the keys, back to the start. */
    fun cancel() {
        central?.cancel()
        central = null
        mutable.value = NearbyState.Idle
    }

    /** Shows an end state decided by the screen (permissions refused, Bluetooth off). */
    fun show(why: NearbyState.Why) {
        cancel()
        mutable.value = NearbyState.Ended(why)
    }
}

/**
 * Process-wide record of scan starts: Android silently refuses a sixth start in 30 s, so Clipway
 * keeps to four. Pure, tested on the JVM.
 */
class ScanStarts(private val max: Int = Nearby.SCAN_STARTS, private val windowMs: Long = Nearby.SCAN_WINDOW_MS) {
    private val starts = ArrayDeque<Long>()

    /** How long to wait before the next start is allowed (0: now). */
    @Synchronized
    fun wait(now: Long): Long {
        while (starts.isNotEmpty() && now - starts.first() >= windowMs) starts.removeFirst()
        return if (starts.size < max) 0L else starts.first() + windowMs - now
    }

    @Synchronized
    fun note(now: Long) {
        starts.addLast(now)
        while (starts.size > max) starts.removeFirst()
    }
}

/**
 * The phone as a GATT central for one attempt (docs/PROTOCOL.md, 13.3): scan filtered on the
 * Clipway service, the strongest Mac 1 s after the first result, a direct LE connection, MTU,
 * discovery, then the requests [NearbyPhone] asks for, one at a time. Everything runs on the main
 * thread (callbacks are posted to it). Permissions are checked by the screen before [start].
 */
@RequiresApi(33)
@SuppressLint("MissingPermission")
class NearbyCentral(private val context: Context, private val publish: (NearbyState) -> Unit) : NearbyPairing.Attempt {

    private val main = Handler(Looper.getMainLooper())
    private var keys: Nearby.KeyPair? = null
    private var machine: NearbyPhone? = null
    private var gatt: BluetoothGatt? = null
    private var finished = false
    private var byUser = false

    // Scan
    private var scanning = false
    private var firstResultAt = 0L
    private val found = HashMap<String, Pair<BluetoothDevice, Int>>()

    // Connection
    private var device: BluetoothDevice? = null
    private var connectStart = 0L
    private var retried = false
    private var connected = false
    /** Discovery runs once: a later onMtuChanged (the Mac may start its own MTU exchange) is ignored. */
    private var discovering = false

    // Requests: one in flight at a time, the others wait.
    private var inFlight = false
    private val queue = ArrayDeque<NearbyPhone.Op>()
    private var shown: NearbyState? = null

    private val expire = Runnable { if (machine?.phase != NearbyPhone.Phase.Receiving) end(NearbyState.Why.Expired, "120 s") }
    private val noMac = Runnable { end(NearbyState.Why.NoMac, "no Mac in 30 s") }
    private val pick = Runnable { connectStrongest() }
    private val restartScan = Runnable { startScan() }
    private val connectTimeout = Runnable { end(NearbyState.Why.Failed, "connection timed out") }
    private val codeTimeout = Runnable { end(NearbyState.Why.Failed, "no code within 10 s") }
    private val packetTimeout = Runnable { end(NearbyState.Why.Failed, "no packet within 10 s") }

    fun start() {
        val adapter = try {
            context.getSystemService(BluetoothManager::class.java)?.adapter
        } catch (_: Exception) {
            null
        }
        when {
            adapter == null -> return end(NearbyState.Why.Unavailable, "no adapter")
            !adapter.isEnabled -> return end(NearbyState.Why.BluetoothOff, "off")
        }
        val pair = try {
            Nearby.generateKeyPair()
        } catch (e: Exception) {
            return end(NearbyState.Why.Unavailable, "no X25519: ${e.javaClass.simpleName}")
        }
        keys = pair
        machine = NearbyPhone(pair) { Nearby.sharedSecret(pair.privateKey, it) }
        try {
            androidx.core.content.ContextCompat.registerReceiver(
                context, bluetoothState, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED,
            )
        } catch (_: Exception) {
        }
        show(NearbyState.Searching)
        main.postDelayed(expire, Nearby.SESSION_MS)
        main.postDelayed(noMac, Nearby.NO_MAC_MS)
        startScan()
    }

    /** The person pressed Pair on the phone. */
    override fun pair() {
        val m = machine ?: return
        if (finished || m.phase != NearbyPhone.Phase.Code) return
        run(m.pair())
    }

    override fun cancel() {
        if (finished) return
        byUser = true
        machine?.end(NearbyPhone.Outcome.Canceled)
        finish(null)
    }

    private val bluetoothState = object : BroadcastReceiver() {
        override fun onReceive(c: Context, intent: Intent) {
            val s = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1)
            if (s == BluetoothAdapter.STATE_TURNING_OFF || s == BluetoothAdapter.STATE_OFF) end(NearbyState.Why.BluetoothOff, "turned off")
        }
    }

    // ---------------------------------------------------------------------
    // Scan: filtered on the service, low latency, the strongest after 1 s
    // ---------------------------------------------------------------------

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            main.post { seen(result) }
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            main.post { results.forEach { seen(it) } }
        }

        override fun onScanFailed(errorCode: Int) {
            main.post {
                scanning = false
                if (finished) return@post
                Log.i(TAG, "Scan refused ($errorCode)")
                // Too frequent: try again within the attempt. Anything else: Bluetooth is not usable.
                if (errorCode == SCAN_FAILED_SCANNING_TOO_FREQUENTLY) {
                    main.postDelayed(restartScan, Nearby.SCAN_WINDOW_MS / 5)
                } else {
                    end(NearbyState.Why.Unavailable, "scan failed $errorCode")
                }
            }
        }
    }

    private fun startScan() {
        if (finished || device != null) return
        val now = SystemClock.elapsedRealtime()
        val wait = starts.wait(now)
        if (wait > 0) {
            main.postDelayed(restartScan, wait)
            return
        }
        val scanner = try {
            context.getSystemService(BluetoothManager::class.java)?.adapter?.bluetoothLeScanner
        } catch (_: Exception) {
            null
        }
        if (scanner == null) return end(NearbyState.Why.BluetoothOff, "no scanner")
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(Nearby.SERVICE)).build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setReportDelay(0)
            .build()
        try {
            starts.note(now)
            scanner.startScan(listOf(filter), settings, scanCallback)
            scanning = true
        } catch (e: Exception) {
            end(NearbyState.Why.Unavailable, "scan not started: ${e.javaClass.simpleName}")
        }
    }

    private fun stopScan() {
        if (!scanning) return
        scanning = false
        try {
            context.getSystemService(BluetoothManager::class.java)?.adapter?.bluetoothLeScanner?.stopScan(scanCallback)
        } catch (_: Exception) {
        }
    }

    private fun seen(r: ScanResult) {
        if (finished || device != null) return
        // The result's BluetoothDevice keeps the Mac's random address type: connect with it.
        val address = r.device.address
        val best = found[address]
        if (best == null || r.rssi > best.second) found[address] = r.device to r.rssi
        if (firstResultAt == 0L) {
            firstResultAt = SystemClock.elapsedRealtime()
            main.removeCallbacks(noMac)
            main.postDelayed(pick, Nearby.EXTRA_SCAN_MS)
        }
    }

    private fun connectStrongest() {
        if (finished) return
        stopScan()
        val strongest = found.values.maxByOrNull { it.second }?.first ?: return end(NearbyState.Why.NoMac, "nothing kept")
        found.clear()
        device = strongest
        connectStart = SystemClock.elapsedRealtime()
        main.postDelayed(connectTimeout, Nearby.CONNECT_MS)
        connect()
    }

    // ---------------------------------------------------------------------
    // GATT
    // ---------------------------------------------------------------------

    private fun connect() {
        val d = device ?: return
        gatt = try {
            d.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
        } catch (e: Exception) {
            null
        }
        if (gatt == null) end(NearbyState.Why.Failed, "connectGatt refused")
    }

    private fun closeGatt() {
        gatt?.let {
            try {
                it.disconnect()
                it.close()
            } catch (_: Exception) {
            }
        }
        gatt = null
    }

    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            main.post {
                if (finished || g !== gatt) return@post
                if (status == BluetoothGatt.GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED) {
                    connected = true
                    main.removeCallbacks(connectTimeout)
                    main.postDelayed(codeTimeout, Nearby.TO_CODE_MS)
                    if (!g.requestMtu(Nearby.REQUEST_MTU)) end(NearbyState.Why.Failed, "MTU not requested")
                } else if (!connected && !retried && Nearby.retryable(status) &&
                    SystemClock.elapsedRealtime() - connectStart < Nearby.RETRY_WITHIN_MS
                ) {
                    // A quick, common failure: release the failed connection and try once more.
                    retried = true
                    Log.i(TAG, "Connection failed ($status): second try")
                    closeGatt()
                    main.postDelayed({ if (!finished) connect() }, Nearby.RETRY_PAUSE_MS)
                } else {
                    end(NearbyState.Why.Failed, "disconnected ($status)")
                }
            }
        }

        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
            main.post {
                if (finished || g !== gatt || discovering) return@post
                if (mtu < Nearby.MIN_MTU) {
                    end(NearbyState.Why.Failed, "MTU $mtu")
                } else {
                    discovering = true
                    if (!g.discoverServices()) end(NearbyState.Why.Failed, "discovery not started")
                }
            }
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            main.post {
                // Once only: the exchange may already be running.
                if (finished || g !== gatt || machine?.phase != NearbyPhone.Phase.Start) return@post
                val service = g.getService(Nearby.SERVICE)
                val complete = service != null && Nearby.CHARACTERISTICS.all { service.getCharacteristic(it) != null } &&
                    service.getCharacteristic(Nearby.STATUS).getDescriptor(Nearby.CCCD) != null
                if (status != BluetoothGatt.GATT_SUCCESS || !complete) return@post end(NearbyState.Why.Failed, "service incomplete")
                run(machine!!.start())
            }
        }

        override fun onDescriptorWrite(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            main.post {
                if (finished || g !== gatt) return@post
                inFlight = false
                if (status != BluetoothGatt.GATT_SUCCESS) return@post end(NearbyState.Why.Failed, "subscription refused ($status)")
                after(machine!!.subscribed())
            }
        }

        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
            val copy = value.copyOf()
            main.post {
                if (finished || g !== gatt) return@post
                inFlight = false
                val m = machine!!
                after(if (status == BluetoothGatt.GATT_SUCCESS) m.read(c.uuid, copy) else m.error(c.uuid))
            }
        }

        override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
            main.post {
                if (finished || g !== gatt) return@post
                inFlight = false
                val m = machine!!
                after(if (status == BluetoothGatt.GATT_SUCCESS) m.written(c.uuid) else m.error(c.uuid))
            }
        }

        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray) {
            if (c.uuid != Nearby.STATUS) return
            val copy = value.copyOf()
            main.post {
                if (finished || g !== gatt) return@post
                after(machine!!.status(copy))
            }
        }
    }

    /** After an answer: the next request, then whatever waits, then the screen. */
    private fun after(next: NearbyPhone.Op?) {
        if (next != null) run(next)
        while (!finished && !inFlight && queue.isNotEmpty()) perform(queue.removeFirst())
        refresh()
    }

    private fun run(op: NearbyPhone.Op?) {
        if (op == null || finished) return
        if (op == NearbyPhone.Op.Leave) {
            refresh()
            return
        }
        if (inFlight) queue.addLast(op) else perform(op)
        refresh()
    }

    private fun perform(op: NearbyPhone.Op) {
        val g = gatt ?: return end(NearbyState.Why.Failed, "no connection")
        val service = g.getService(Nearby.SERVICE) ?: return end(NearbyState.Why.Failed, "service gone")
        val ok = try {
            when (op) {
                NearbyPhone.Op.Subscribe -> {
                    val status = service.getCharacteristic(Nearby.STATUS)
                    g.setCharacteristicNotification(status, true) &&
                        g.writeDescriptor(status.getDescriptor(Nearby.CCCD), BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) ==
                        BluetoothStatusCodes.SUCCESS
                }
                is NearbyPhone.Op.Read -> g.readCharacteristic(service.getCharacteristic(op.char))
                is NearbyPhone.Op.Write -> g.writeCharacteristic(
                    service.getCharacteristic(op.char), op.value, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
                ) == BluetoothStatusCodes.SUCCESS
                NearbyPhone.Op.Leave -> true
            }
        } catch (e: Exception) {
            false
        }
        if (ok) inFlight = true else end(NearbyState.Why.Failed, "request not sent")
    }

    /** Publishes what the machine's phase means for the screen, and ends the attempt when it is over. */
    private fun refresh() {
        if (finished) return
        val m = machine ?: return
        when (m.phase) {
            NearbyPhone.Phase.Code, NearbyPhone.Phase.Confirmed -> {
                main.removeCallbacks(codeTimeout)
                show(NearbyState.Code(m.code!!, m.phase == NearbyPhone.Phase.Confirmed))
            }
            NearbyPhone.Phase.Receiving -> {
                if (shown !is NearbyState.Finishing) {
                    main.removeCallbacks(expire)
                    main.postDelayed(packetTimeout, Nearby.TO_PACKET_MS)
                }
                show(NearbyState.Finishing(m.code!!))
            }
            NearbyPhone.Phase.Ended -> finish(m.outcome)
            else -> Unit
        }
    }

    private fun show(s: NearbyState) {
        if (s == shown) return
        shown = s
        publish(s)
    }

    /** Ends the attempt for a reason found by the radio layer. */
    private fun end(why: NearbyState.Why, reason: String) {
        if (finished) return
        Log.i(TAG, "Nearby pairing ended: $reason")
        val m = machine
        if (m == null) {
            finished = true
            release()
            publish(NearbyState.Ended(why))
            return
        }
        m.end(
            when (why) {
                NearbyState.Why.Canceled -> NearbyPhone.Outcome.Canceled
                NearbyState.Why.Expired -> NearbyPhone.Outcome.Expired
                NearbyState.Why.Busy -> NearbyPhone.Outcome.Busy
                else -> NearbyPhone.Outcome.Failed
            },
        )
        finish(null, why)
    }

    private fun finish(outcome: NearbyPhone.Outcome?, why: NearbyState.Why? = null) {
        if (finished) return
        finished = true
        release()
        if (byUser) return
        publish(
            when (outcome) {
                is NearbyPhone.Outcome.Paired -> NearbyState.Paired(outcome.code)
                NearbyPhone.Outcome.Canceled -> NearbyState.Ended(NearbyState.Why.Canceled)
                NearbyPhone.Outcome.Expired -> NearbyState.Ended(NearbyState.Why.Expired)
                NearbyPhone.Outcome.Busy -> NearbyState.Ended(NearbyState.Why.Busy)
                NearbyPhone.Outcome.Failed -> NearbyState.Ended(NearbyState.Why.Failed)
                null -> NearbyState.Ended(why ?: NearbyState.Why.Failed)
            },
        )
    }

    /** Stops the radio and forgets everything: nothing of the attempt is kept. */
    private fun release() {
        main.removeCallbacksAndMessages(null)
        stopScan()
        closeGatt()
        queue.clear()
        found.clear()
        try {
            context.unregisterReceiver(bluetoothState)
        } catch (_: Exception) {
        }
        keys = null
        machine = null
    }

    private companion object {
        const val TAG = "ClipwayNearby"
        const val SCAN_FAILED_SCANNING_TOO_FREQUENTLY = 6
        val starts = ScanStarts()
    }
}
