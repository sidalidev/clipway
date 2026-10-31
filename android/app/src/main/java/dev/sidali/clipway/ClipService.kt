package dev.sidali.clipway

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/** What the screens show about the connection. Written by the service, read by the UI. */
object Status {
    enum class Link { Off, Connecting, Online, NoNetwork, Unreachable, Erased, Paused }

    val link = MutableStateFlow(Link.Off)

    /** Open connections of the chain, this phone included (presence). */
    val devices = MutableStateFlow(1)
    val peer = MutableStateFlow<String?>(null)
    val relayNotice = MutableStateFlow<String?>(null)

    /** Set once, the first time the Mac answers after pairing. */
    val celebrate = MutableStateFlow(false)

    val macOnline: Boolean get() = link.value == Link.Online && devices.value > 1
}

/**
 * Keeps the WebSocket to the relay (docs/PROTOCOL.md, section 6): foreground service of type
 * specialUse, low-importance notification "Connected to <Mac>". All protocol work runs on one
 * worker thread; OkHttp only posts frames to it.
 *
 * Timers: a Handler stops counting while the processor sleeps, so long waits and the heartbeat go
 * through an inexact alarm ([Watchdog], every 4.5 min) that wakes the phone, under a wake lock
 * released as soon as the relay answers.
 */
class ClipService : Service() {

    companion object {
        private const val TAG = "ClipwayService"
        private const val NOTIFICATION = 1
        const val CHANNEL_CONNECTION = "connection"
        const val CHANNEL_RECEIVED = "received"
        const val ACTION_RECONNECT = "dev.sidali.clipway.action.RECONNECT"
        const val ACTION_PUMP = "dev.sidali.clipway.action.PUMP"
        const val ACTION_HELLO = "dev.sidali.clipway.action.HELLO"

        /** Just paired: load the new key, connect, and announce this phone with a hello. */
        const val ACTION_JOINED = "dev.sidali.clipway.action.JOINED"
        const val WATCHDOG_MS = 270_000L
        private const val PONG_WAIT_MS = 20_000L
        private const val OPEN_MAX_MS = 60_000L
        private const val DELAY_MIN_MS = 1_000L
        private const val DELAY_MAX_MS = 60_000L

        @Volatile
        var instance: ClipService? = null
            private set

        /** Starts the service (or wakes it with [action]). Only when paired and not paused. */
        fun start(context: Context, action: String? = null) {
            if (!Vault.paired(context)) return
            val prefs = Prefs(context)
            if (prefs.chainErased) {
                Status.link.value = Status.Link.Erased
                return
            }
            if (prefs.paused) {
                Status.link.value = Status.Link.Paused
                return
            }
            try {
                context.startForegroundService(Intent(context, ClipService::class.java).setAction(action))
            } catch (e: Exception) {
                Log.w(TAG, "Start refused: ${e.javaClass.simpleName}")
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, ClipService::class.java))
        }

        /**
         * The Home switch. Paused: the service stops (no relay connection, no alarm, no
         * notification) and stays stopped after a restart. On: everything starts again as before.
         */
        fun setPaused(context: Context, paused: Boolean) {
            val app = context.applicationContext ?: context
            Prefs(app).paused = paused
            if (paused) {
                stop(app)
                instance?.let { s -> s.post { s.pause() } }
                try {
                    app.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION)
                } catch (_: Exception) {
                }
            }
            Status.link.value = Power.linkWhenStopped(Status.link.value, paused)
            if (!paused) start(app)
            SendTile.refresh(app)
        }

        /** Something new in the outbox: send it now if connected, or connect. */
        fun kick(context: Context) {
            val s = instance
            if (s != null) s.post { s.pumpNow(); if (s.socket == null) s.connect() } else start(context, ACTION_PUMP)
        }

        fun channels(context: Context) {
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_CONNECTION, context.getString(R.string.channel_connection), NotificationManager.IMPORTANCE_MIN).apply {
                    setShowBadge(false)
                    lockscreenVisibility = Notification.VISIBILITY_SECRET
                },
            )
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_RECEIVED, context.getString(R.string.channel_received), NotificationManager.IMPORTANCE_LOW).apply {
                    setShowBadge(false)
                    setSound(null, null)
                    enableVibration(false)
                    lockscreenVisibility = Notification.VISIBILITY_SECRET
                },
            )
        }
    }

    private val thread = HandlerThread("clipway").apply { start() }
    private val worker = Handler(thread.looper)
    private lateinit var prefs: Prefs
    private lateinit var client: OkHttpClient
    private lateinit var inbox: Inbox
    private var keys: Protocol.Keys? = null
    private var engine: Engine? = null
    private var started = false

    private var socket: WebSocket? = null
    private var generation = 0
    private var attempts = 0
    private var openedAt = 0L
    private var pingAt = 0L
    private var network: Network? = null
    private var networkKnown = false
    private var wake: PowerManager.WakeLock? = null
    private lateinit var shortWake: PowerManager.WakeLock

    fun post(r: () -> Unit) = worker.post(r)

    private val reconnect = Runnable { connect() }
    private val pump = Runnable { pumpNow() }
    private val checkPong = Runnable {
        if (pingAt > 0 && SystemClock.elapsedRealtime() - pingAt >= PONG_WAIT_MS) {
            Log.i(TAG, "No pong: reconnecting")
            attempts = 0
            connect()
        }
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(n: Network) {
            worker.post {
                val first = !networkKnown
                networkKnown = true
                val changed = network != n
                network = n
                if ((changed && !first) || socket == null) {
                    attempts = 0
                    connect()
                }
            }
        }

        override fun onLost(n: Network) {
            worker.post {
                if (n != network) return@post
                network = null
                drop()
                setLink(Status.Link.NoNetwork)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        channels(this)
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION, notification(Status.Link.Connecting), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION, notification(Status.Link.Connecting))
            }
        } catch (e: Exception) {
            Log.w(TAG, "Cannot go to the foreground: ${e.javaClass.simpleName}")
            stopSelf()
            return
        }
        started = true
        instance = this
        prefs = Prefs(this)
        inbox = Inbox(this)
        Status.peer.value = prefs.peerName
        Status.relayNotice.value = prefs.relayNotice
        shortWake = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "clipway:reconnect").apply { setReferenceCounted(false) }
        client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            // No OkHttp ping: every ping wakes the radio. The relay pings every 4 min and the
            // watchdog sends an application ping every 4.5 min.
            .build()
        getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(networkCallback, worker)
        worker.post { connect() }
        scheduleWatchdog(WATCHDOG_MS)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!started) return START_NOT_STICKY
        worker.post {
            when (intent?.action) {
                ACTION_RECONNECT -> {
                    // The relay changed: the Mac may only be on the new one, so say hello there too.
                    keys = null
                    attempts = 0
                    sendHello()
                    connect()
                }
                ACTION_HELLO -> sendHello()
                ACTION_JOINED -> {
                    keys = null
                    attempts = 0
                    if (Status.link.value == Status.Link.Erased) Status.link.value = Status.Link.Off
                    sendHello()
                    connect()
                }
                else -> {
                    pumpNow()
                    if (socket == null) {
                        attempts = 0
                        connect()
                    }
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        if (started) {
            instance = null
            try {
                getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(networkCallback)
            } catch (_: Exception) {
            }
            cancelWatchdog()
            worker.removeCallbacksAndMessages(null)
            generation++
            socket?.close(1000, null)
            socket = null
            engine?.detach()
            Status.link.value = Power.linkWhenStopped(Status.link.value, prefs.paused)
            releaseWake()
            if (shortWake.isHeld) shortWake.release()
            client.dispatcher.executorService.shutdown()
        }
        thread.quitSafely()
        super.onDestroy()
    }

    // -----------------------------------------------------------------
    // Connection
    // -----------------------------------------------------------------

    private fun loadKeys(): Protocol.Keys? {
        keys?.let { return it }
        val k = Vault.keys(this) ?: return null
        keys = k
        engine = Engine(k, Sender.outbox, prefs.cursor, events)
        return k
    }

    fun connect() {
        if (!started || prefs.paused) return
        worker.removeCallbacks(reconnect)
        worker.removeCallbacks(checkPong)
        drop()
        if (Status.link.value == Status.Link.Erased) return
        val k = loadKeys()
        if (k == null) {
            Log.w(TAG, "No key: stopping")
            stopSelf()
            return
        }
        val relay = prefs.relay
        if (!Protocol.relayAllowed(relay, BuildConfig.ALLOW_LOCAL_HTTP)) {
            setLink(Status.Link.Unreachable)
            return
        }
        val request = Request.Builder()
            .url(Protocol.webSocketUrl(relay))
            // The proof, never the chain id, and never in the URL: proxies write URLs to their logs.
            .header("Sec-WebSocket-Protocol", k.subprotocolHeader)
            .header("User-Agent", "Clipway-Android/${BuildConfig.VERSION_NAME}")
            .build()
        val gen = ++generation
        openedAt = SystemClock.elapsedRealtime()
        if (network != null || !networkKnown) setLink(Status.Link.Connecting)
        Log.i(TAG, "Connecting (chain ${k.chainId.take(6)})")
        socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                worker.post {
                    if (gen != generation) return@post
                    engine?.attach(wireOf(webSocket))
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                worker.post { if (gen == generation) onFrame(text) }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                worker.post { if (gen == generation) onClosed(code) }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                worker.post { if (gen == generation) onClosed(code) }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                worker.post { if (gen == generation) onClosed(response?.code ?: -1) }
            }
        })
    }

    private fun wireOf(ws: WebSocket) = object : Engine.Wire {
        override fun send(text: String) = ws.send(text)
        override fun queueSize() = ws.queueSize()
    }

    private fun onFrame(text: String) {
        pingAt = 0L
        worker.removeCallbacks(checkPong)
        releaseWake()
        engine?.onFrame(text, System.currentTimeMillis())
    }

    private fun onClosed(code: Int) {
        Log.i(TAG, "Connection closed ($code)")
        drop()
        if (code == 4001) {
            // The chain was erased from another device: stop and say so, also after a restart.
            prefs.chainErased = true
            setLink(Status.Link.Erased)
            stopSelf()
            return
        }
        setLink(if (network == null && networkKnown) Status.Link.NoNetwork else if (attempts >= 3) Status.Link.Unreachable else Status.Link.Connecting)
        scheduleReconnect()
        releaseWake()
    }

    /** Paused from the Home switch: close at once, before the service is destroyed. */
    private fun pause() {
        worker.removeCallbacks(reconnect)
        worker.removeCallbacks(checkPong)
        worker.removeCallbacks(pump)
        cancelWatchdog()
        drop()
        releaseWake()
        if (shortWake.isHeld) shortWake.release()
    }

    /** Forgets the current socket without scheduling anything. */
    private fun drop() {
        generation++
        socket?.cancel()
        socket = null
        engine?.detach()
        pingAt = 0L
    }

    /** 1 s, 2 s, 4 s... 60 s at most, plus up to 20 % random. Long waits also set an alarm. */
    private fun scheduleReconnect() {
        if (network == null && networkKnown) return
        val base = minOf(DELAY_MAX_MS, DELAY_MIN_MS shl minOf(attempts, 6))
        val delay = base + Random.nextLong(0, base / 5 + 1)
        attempts++
        worker.removeCallbacks(reconnect)
        worker.postDelayed(reconnect, delay)
        if (delay <= 5_000L) shortWake.acquire(delay + 10_000L) else scheduleWatchdog(delay)
    }

    private fun setLink(l: Status.Link) {
        if (prefs.paused || Status.link.value == l) return
        Status.link.value = l
        updateNotification()
    }

    private fun updateNotification() {
        try {
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION, notification(Status.link.value))
        } catch (_: SecurityException) {
        }
    }

    fun pumpNow() {
        worker.removeCallbacks(pump)
        val more = engine?.pump(System.currentTimeMillis()) ?: false
        if (more) worker.postDelayed(pump, 60L)
    }

    private fun sendHello() {
        val k = loadKeys() ?: return
        Sender.hello(this, k)
        pumpNow()
    }

    private val events = object : Engine.Events {
        override fun onDelivery(seq: Long, parts: List<Crypto.Envelope>): Engine.Delivery {
            val k = keys ?: return Engine.Delivery.Retry
            return inbox.handle(k, parts)
        }

        override fun onSynced() {
            attempts = 0
            setLink(Status.Link.Online)
            releaseWake()
            checkRelay()
        }

        override fun onPresence(devices: Int) {
            Status.devices.value = devices
            updateNotification()
        }

        override fun onStored(item: String, seq: Long, othersOnline: Boolean) {
            // An offer stays "Sending" until the Mac fetched it directly (or could not).
            val offer = Sender.direct.isOpen(item)
            History.update(this@ClipService, item) {
                it.copy(status = if (offer && othersOnline) "sending" else if (othersOnline) "sent" else "waiting", seq = seq)
            }
        }

        override fun onDelivered(seq: Long) {
            // For an offer, "Delivered" comes from the direct transfer, not from the relay's ack.
            History.updateBySeq(this@ClipService, seq) { if (Sender.direct.isOpen(it.item)) it else it.copy(status = "delivered") }
        }

        override fun onRefused(item: String, code: String) {
            History.update(this@ClipService, item) { it.copy(status = "failed") }
        }

        override fun onBackOff(ms: Long) {
            worker.postDelayed(pump, ms + 100)
        }
    }

    // -----------------------------------------------------------------
    // Watchdog (inexact alarm, wakes the phone)
    // -----------------------------------------------------------------

    private fun watchdogIntent(): PendingIntent = PendingIntent.getBroadcast(
        this, 0, Intent(this, Watchdog::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun scheduleWatchdog(delay: Long) {
        try {
            getSystemService(AlarmManager::class.java).setAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + delay, watchdogIntent(),
            )
        } catch (e: Exception) {
            Log.w(TAG, "Watchdog refused: ${e.javaClass.simpleName}")
        }
    }

    private fun cancelWatchdog() {
        try {
            getSystemService(AlarmManager::class.java).cancel(watchdogIntent())
        } catch (_: Exception) {
        }
    }

    /** Called from the alarm, holding [lock]: ping, or reconnect. The lock is released on the answer. */
    fun watchdog(lock: PowerManager.WakeLock) {
        worker.post {
            releaseWake()
            wake = lock
            scheduleWatchdog(WATCHDOG_MS)
            val now = SystemClock.elapsedRealtime()
            val e = engine
            when {
                socket == null -> {
                    attempts = 0
                    connect()
                }
                e == null || !e.synced -> if (now - openedAt > OPEN_MAX_MS) connect()
                pingAt > 0 && now - pingAt >= PONG_WAIT_MS -> {
                    attempts = 0
                    connect()
                }
                else -> {
                    if (pingAt == 0L) pingAt = now
                    e.ping()
                    worker.removeCallbacks(checkPong)
                    worker.postDelayed(checkPong, PONG_WAIT_MS)
                }
            }
            if (socket == null) releaseWake()
        }
    }

    private fun releaseWake() {
        wake?.let { if (it.isHeld) try { it.release() } catch (_: Exception) {} }
        wake = null
    }

    // -----------------------------------------------------------------
    // Relay status (/.well-known/clipway-relay.json), once a day
    // -----------------------------------------------------------------

    private fun checkRelay() {
        val now = System.currentTimeMillis()
        if (now - prefs.relayCheckedAt < 24L * 3600 * 1000) return
        prefs.relayCheckedAt = now
        val url = Protocol.normalizeRelay(prefs.relay) + "/.well-known/clipway-relay.json"
        val request = try {
            Request.Builder().url(url).header("User-Agent", "Clipway-Android/${BuildConfig.VERSION_NAME}").build()
        } catch (e: Exception) {
            return
        }
        client.newCall(request).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) = Unit
            override fun onResponse(call: okhttp3.Call, response: Response) {
                val notice = try {
                    response.use {
                        if (!it.isSuccessful) return
                        val o = JSONObject(it.body?.string() ?: return)
                        val min = o.optJSONObject("minClient")?.optString("android").orEmpty()
                        val status = o.optString("status", "ok")
                        when {
                            min.isNotEmpty() && Versions.older(BuildConfig.VERSION_NAME, min) -> "update"
                            status == "end-of-service" || status == "degraded" -> status
                            else -> null
                        }
                    }
                } catch (e: Exception) {
                    return
                }
                prefs.relayNotice = notice
                Status.relayNotice.value = notice
            }
        })
    }

    // -----------------------------------------------------------------
    // Notification
    // -----------------------------------------------------------------

    private fun notification(l: Status.Link): Notification {
        val mac = Status.peer.value ?: getString(R.string.your_mac)
        val text = when (l) {
            Status.Link.Online -> if (Status.devices.value > 1) getString(R.string.connected_to, mac) else getString(R.string.waiting_for, mac)
            Status.Link.NoNetwork -> getString(R.string.waiting_for_network)
            Status.Link.Unreachable -> getString(R.string.relay_unreachable)
            Status.Link.Erased -> getString(R.string.chain_erased_short)
            else -> getString(R.string.connecting)
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_CONNECTION)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(getColor(R.color.lac))
            .setContentTitle(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setShowWhen(false)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }
}

/** Compares "1.2.3" versions. */
object Versions {
    fun older(a: String, b: String): Boolean {
        val x = a.split('.', '-').map { it.toIntOrNull() ?: 0 }
        val y = b.split('.', '-').map { it.toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(x.size, y.size)) {
            val d = x.getOrElse(i) { 0 } - y.getOrElse(i) { 0 }
            if (d != 0) return d < 0
        }
        return false
    }
}

/** The watchdog alarm: takes a wake lock (30 s at most) and hands it to the service. */
class Watchdog : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val lock = context.getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "clipway:watchdog").apply { setReferenceCounted(false) }
        lock.acquire(30_000L)
        val s = ClipService.instance
        if (s != null) {
            s.watchdog(lock)
        } else {
            ClipService.start(context)
            lock.release()
        }
    }
}

/** Start at boot, when the setting is on (the receiver is turned off otherwise). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (Prefs(context).startAtBoot) ClipService.start(context)
    }

    companion object {
        fun apply(context: Context, on: Boolean) {
            context.packageManager.setComponentEnabledSetting(
                ComponentName(context, BootReceiver::class.java),
                if (on) PackageManager.COMPONENT_ENABLED_STATE_ENABLED else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP,
            )
        }
    }
}

/** After an update of the app: the connection comes back by itself. */
class UpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) ClipService.start(context)
    }
}
