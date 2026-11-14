package dev.sidali.clipway

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** The built-in update, as the Home banner and Settings show it. */
sealed class UpdateState {
    data object None : UpdateState()
    data class Available(val release: Release) : UpdateState()
    /** "Install unknown apps" is off for Clipway: the banner explains it and opens the setting. */
    data class NeedsPermission(val release: Release) : UpdateState()
    data class Downloading(val release: Release, val percent: Int) : UpdateState()
    data class Verifying(val release: Release) : UpdateState()
    /** The PackageInstaller session is committed: the system confirmation is up to the user. */
    data class Installing(val release: Release) : UpdateState()
    data class Failed(val release: Release, val why: UpdateFailure) : UpdateState()
}

/**
 * Built-in update, without a store (docs/UPDATES.md), the same as Sonne's. Obtainium keeps working
 * beside it: both install the same APK, signed with the same key.
 *
 * - Check: GET https://clip.sidali.dev/update.json when the app opens (at most once a minute) and
 *   once a day from the watchdog, when Automatic updates is on (the default). No identifier: no
 *   cookie, no device id, the User-Agent "Clipway-Android/<version>" only.
 * - On Install: download into the cache, then the size and SHA-256 announced, the package name and
 *   versionCode, and the signing certificate, which must be the installed app's, the announced one
 *   and, in release builds, the one compiled in (SECURITY.md). Otherwise refused and deleted.
 * - PackageInstaller with USER_ACTION_REQUIRED: the system confirmation is always shown.
 */
object Updater {
    private const val TAG = "ClipwayUpdate"
    const val CHANNEL = "updates"
    private const val NOTIFICATION = 4
    const val ACTION_INSTALL = "dev.sidali.clipway.action.UPDATE"
    const val ACTION_RESULT = "dev.sidali.clipway.action.INSTALL_RESULT"
    private const val DAY_MS = 24L * 3600 * 1000
    private const val RETRY_MS = 3600L * 1000
    private const val OPEN_MIN_MS = 60_000L

    val state = MutableStateFlow<UpdateState>(UpdateState.None)
    /** The system confirmation to show as soon as an activity is in the foreground. */
    val confirmation = MutableStateFlow<Intent?>(null)

    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "clipway-update").apply { isDaemon = true } }
    private val main = Handler(Looper.getMainLooper())
    private val client by lazy {
        OkHttpClient.Builder().connectTimeout(15, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS)
            .followRedirects(false).build()
    }

    @Volatile private var checking = false
    @Volatile private var lastOpen = 0L

    private class Refused(val why: UpdateFailure, message: String) : Exception(message)

    /** The certificate release builds accept (SECURITY.md); debug builds compare with the installed app only. */
    private val pinned: String? get() = if (BuildConfig.DEBUG) null else BuildConfig.UPDATE_CERT_SHA256

    private fun installedCode(): Long = BuildConfig.VERSION_CODE.toLong()

    /** After a process restart: the release known from the last check, and a clean cache. */
    fun restore(c: Context) {
        val prefs = Prefs(c)
        val known = UpdateCheck.parse(prefs.updateManifest, installedCode())
        if (state.value is UpdateState.None && prefs.automaticUpdates && known != null) state.value = UpdateState.Available(known)
        if (state.value is UpdateState.None) worker.execute { folder(c).listFiles()?.forEach { it.delete() } }
    }

    /** The app comes to the foreground: check, at most once a minute. */
    fun onOpen(c: Context) {
        if (!Prefs(c).automaticUpdates) return
        val now = System.currentTimeMillis()
        if (now - lastOpen < OPEN_MIN_MS) return
        lastOpen = now
        check(c)
    }

    /** From the watchdog: once a day, again an hour after a failure. */
    fun checkIfDue(c: Context) {
        val prefs = Prefs(c)
        if (!prefs.automaticUpdates) return
        val now = System.currentTimeMillis()
        if (now - prefs.updateCheckedAt < DAY_MS || now - prefs.updateTriedAt < RETRY_MS) return
        check(c)
    }

    /** Asks update.json. [done] (main thread): true if an update is available, false if up to date, null on failure. */
    fun check(context: Context, done: ((Boolean?) -> Unit)? = null) {
        val c = context.applicationContext ?: context
        if (checking) {
            done?.let { main.post { it(null) } }
            return
        }
        checking = true
        val prefs = Prefs(c)
        prefs.updateTriedAt = System.currentTimeMillis()
        worker.execute {
            var result: Boolean? = null
            try {
                result = fetch(c, prefs)
            } catch (e: Exception) {
                Log.w(TAG, "Cannot check for updates: ${e.javaClass.simpleName}")
            } finally {
                checking = false
            }
            done?.let { f -> main.post { f(result) } }
        }
    }

    private fun fetch(c: Context, prefs: Prefs): Boolean {
        val request = Request.Builder().url(UpdateCheck.MANIFEST_URL)
            .header("User-Agent", "Clipway-Android/${BuildConfig.VERSION_NAME}").header("Cache-Control", "no-cache").build()
        val text = client.newCall(request).execute().use { r ->
            if (r.code == 404) {
                prefs.updateCheckedAt = System.currentTimeMillis()
                return false
            }
            if (!r.isSuccessful) throw IOException("HTTP ${r.code}")
            val body = r.body ?: throw IOException("empty")
            if (body.contentLength() > UpdateCheck.MANIFEST_MAX) throw IOException("too large")
            body.string()
        }
        prefs.updateCheckedAt = System.currentTimeMillis()
        val release = UpdateCheck.parse(text, installedCode())
        Log.i(TAG, "Checked: ${release?.let { "${it.version} (${it.versionCode}) available" } ?: "up to date"}")
        if (release == null) {
            main.post { if (state.value is UpdateState.Available) state.value = UpdateState.None }
            return false
        }
        prefs.updateManifest = text
        main.post {
            when (state.value) {
                // Never interrupt a download or an installation.
                is UpdateState.None, is UpdateState.Available, is UpdateState.Failed ->
                    if (prefs.automaticUpdates) state.value = UpdateState.Available(release)
                else -> Unit
            }
        }
        if (prefs.updateNotified < release.versionCode) {
            prefs.updateNotified = release.versionCode
            notify(c, c.getString(R.string.update_notification_body, release.version))
        }
        return true
    }

    /** Automatic updates turned off: no banner, no notification (an operation in progress goes on). */
    fun turnedOff(c: Context) {
        cancelNotification(c)
        when (state.value) {
            is UpdateState.Available, is UpdateState.Failed, is UpdateState.NeedsPermission -> state.value = UpdateState.None
            else -> Unit
        }
    }

    fun canInstall(c: Context): Boolean = c.packageManager.canRequestPackageInstalls()

    fun permissionIntent(c: Context): Intent =
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${c.packageName}"))

    private fun current(c: Context): Release? = when (val s = state.value) {
        is UpdateState.Available -> s.release
        is UpdateState.NeedsPermission -> s.release
        is UpdateState.Failed -> s.release
        is UpdateState.Downloading -> s.release
        is UpdateState.Verifying -> s.release
        is UpdateState.Installing -> s.release
        UpdateState.None -> UpdateCheck.parse(Prefs(c).updateManifest, installedCode())
    }

    /** Install, from the banner or the notification: download, check, install. */
    fun install(context: Context) {
        val c = context.applicationContext ?: context
        val release = current(c) ?: return
        when (state.value) {
            is UpdateState.Downloading, is UpdateState.Verifying, is UpdateState.Installing -> return
            else -> Unit
        }
        cancelNotification(c)
        if (!canInstall(c)) {
            state.value = UpdateState.NeedsPermission(release)
            return
        }
        state.value = UpdateState.Downloading(release, 0)
        worker.execute {
            var file: File? = null
            try {
                file = download(c, release)
                state.value = UpdateState.Verifying(release)
                verify(c, release, file)
                Log.i(TAG, "APK ${release.version} checked (size, SHA-256, package, certificate), installing")
                commit(c, release, file)
            } catch (e: Refused) {
                Log.w(TAG, "Update refused (${e.why}): ${e.message}")
                file?.delete()
                state.value = UpdateState.Failed(release, e.why)
            } catch (e: Exception) {
                Log.w(TAG, "Update failed: ${e.javaClass.simpleName}")
                file?.delete()
                state.value = UpdateState.Failed(release, if (e is IOException) UpdateFailure.NETWORK else UpdateFailure.INSTALL)
            }
        }
    }

    private fun folder(c: Context) = File(c.cacheDir, "update")

    private fun download(c: Context, release: Release): File {
        val dir = folder(c).apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val file = File(dir, "clipway-${release.versionCode}.apk")
        val request = Request.Builder().url(release.url).header("User-Agent", "Clipway-Android/${BuildConfig.VERSION_NAME}").build()
        client.newCall(request).execute().use { r ->
            if (!r.isSuccessful) throw IOException("HTTP ${r.code}")
            val body = r.body ?: throw IOException("empty")
            if (body.contentLength() > release.size) throw Refused(UpdateFailure.SIZE, "larger than announced")
            try {
                body.byteStream().use { input ->
                    file.outputStream().use { out ->
                        val buf = ByteArray(64 * 1024)
                        var read = 0L
                        var shown = -1
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            read += n
                            if (read > release.size) throw Refused(UpdateFailure.SIZE, "larger than announced")
                            out.write(buf, 0, n)
                            val p = (read * 100 / release.size).toInt().coerceIn(0, 100)
                            if (p != shown) {
                                shown = p
                                state.value = UpdateState.Downloading(release, p)
                            }
                        }
                    }
                }
            } catch (e: IOException) {
                if (dir.usableSpace < 1024L * 1024) throw Refused(UpdateFailure.STORAGE, "storage full")
                throw e
            }
        }
        return file
    }

    /** Size and SHA-256, then package and versionCode, then the signing certificate. */
    private fun verify(c: Context, release: Release, file: File) {
        if (!UpdateCheck.fileMatches(file, release)) throw Refused(UpdateFailure.CHECKSUM, "size or SHA-256 differs")
        val pm = c.packageManager
        val apk = archiveInfo(pm, file) ?: throw Refused(UpdateFailure.PACKAGE, "unreadable APK")
        if (apk.packageName != c.packageName) throw Refused(UpdateFailure.PACKAGE, "another package")
        if (apk.longVersionCode != release.versionCode) throw Refused(UpdateFailure.PACKAGE, "versionCode differs")
        val installed = installedInfo(pm, c.packageName)
        val certsApk = apk.signingInfo?.apkContentsSigners?.map { it.toByteArray() }.orEmpty()
        val certsInstalled = installed.signingInfo?.apkContentsSigners?.map { it.toByteArray() }.orEmpty()
        UpdateCheck.checkCertificates(certsApk, certsInstalled, release.certSha256, pinned)?.let {
            throw Refused(it, "signing certificate differs")
        }
    }

    @Suppress("DEPRECATION")
    private fun archiveInfo(pm: PackageManager, file: File): PackageInfo? =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageArchiveInfo(file.path, PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
        } else {
            pm.getPackageArchiveInfo(file.path, PackageManager.GET_SIGNING_CERTIFICATES)
        }

    @Suppress("DEPRECATION")
    private fun installedInfo(pm: PackageManager, name: String): PackageInfo =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(name, PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
        } else {
            pm.getPackageInfo(name, PackageManager.GET_SIGNING_CERTIFICATES)
        }

    private fun commit(c: Context, release: Release, file: File) {
        val installer = c.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(c.packageName)
            setSize(file.length())
            // Always the system confirmation: nothing installs without the user.
            setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
        }
        val id = installer.createSession(params)
        try {
            installer.openSession(id).use { session ->
                session.openWrite("clipway.apk", 0, file.length()).use { out ->
                    file.inputStream().use { it.copyTo(out) }
                    session.fsync(out)
                }
                val back = Intent(c, InstallResult::class.java).setAction(ACTION_RESULT)
                // Mutable: PackageInstaller adds the status and the confirmation to this explicit intent.
                val pi = PendingIntent.getBroadcast(c, id, back, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                state.value = UpdateState.Installing(release)
                session.commit(pi.intentSender)
            }
        } catch (e: Exception) {
            try {
                installer.abandonSession(id)
            } catch (_: Exception) {
            }
            throw e
        }
    }

    internal fun onResult(c: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val release = current(c)
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm: Intent? = if (Build.VERSION.SDK_INT >= 33) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT)
                }
                // The activity starts it once in the foreground (no start from the background).
                confirmation.value = confirm
                if (release != null) notify(c, c.getString(R.string.update_notification_confirm, release.version))
            }
            PackageInstaller.STATUS_SUCCESS -> {
                state.value = UpdateState.None
                folder(c).listFiles()?.forEach { it.delete() }
            }
            PackageInstaller.STATUS_FAILURE_ABORTED -> {
                folder(c).listFiles()?.forEach { it.delete() }
                state.value = release?.let { UpdateState.Available(it) } ?: UpdateState.None
            }
            else -> {
                Log.w(TAG, "Installation refused ($status)")
                folder(c).listFiles()?.forEach { it.delete() }
                state.value = release?.let { UpdateState.Failed(it, UpdateFailure.INSTALL) } ?: UpdateState.None
            }
        }
    }

    fun channel(c: Context) {
        c.getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, c.getString(R.string.channel_updates), NotificationManager.IMPORTANCE_DEFAULT).apply {
                setShowBadge(false)
            },
        )
    }

    private fun notify(c: Context, text: String) {
        channel(c)
        val open = PendingIntent.getActivity(
            c, 4, Intent(c, MainActivity::class.java).setAction(ACTION_INSTALL).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = Notification.Builder(c, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(c.getColor(R.color.lac))
            .setContentTitle(c.getString(R.string.update_notification_title))
            .setContentText(text)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try {
            c.getSystemService(NotificationManager::class.java).notify(NOTIFICATION, n)
        } catch (_: SecurityException) {
        }
    }

    private fun cancelNotification(c: Context) {
        try {
            c.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION)
        } catch (_: Exception) {
        }
    }
}

/** The result of a PackageInstaller session (not exported, explicit PendingIntent). */
class InstallResult : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Updater.ACTION_RESULT) Updater.onResult(context, intent)
    }
}
