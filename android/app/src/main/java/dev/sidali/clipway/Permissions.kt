package dev.sidali.clipway

import android.Manifest
import android.app.Activity
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner

// ---------------------------------------------------------------------
// Permissions: each one on a row, why it is needed, its state, and one tap to turn it on or off
// ---------------------------------------------------------------------

/** From Settings and About. Re-read each time the app comes back to the front. */
@Composable
fun PermissionsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    Screen(stringResource(R.string.permissions), onBack) {
        Footnote(stringResource(R.string.permissions_intro), Modifier.padding(start = Tokens.gutter, end = Tokens.gutter, bottom = Tokens.Space.m))
        Card(padding = Tokens.Space.none) {
            NotificationsRow()
            if (remember { NearbyPairing.offered(context) }) {
                Hairline()
                NearbyRow()
            }
            Hairline()
            CameraRow()
            Hairline()
            BatteryRow()
        }
        Footnote(stringResource(R.string.permissions_also), Modifier.padding(start = Tokens.gutter, end = Tokens.gutter, top = Tokens.Space.s))
    }
}

/** Counts the times the screen comes back to the front, so the rows read their state again. */
@Composable
fun resumeCount(): Int {
    var n by remember { mutableIntStateOf(0) }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val o = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_RESUME) n++ }
        owner.lifecycle.addObserver(o)
        onDispose { owner.lifecycle.removeObserver(o) }
    }
    return n
}

// The permission's name is a constant string, also on Android 12, where it is never asked.
@android.annotation.SuppressLint("InlinedApi")
@Composable
fun NotificationsRow() {
    val context = LocalContext.current
    val activity = context as Activity
    val view = LocalView.current
    val prefs = remember { Prefs(context) }
    var after by remember { mutableIntStateOf(0) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        prefs.markAsked(Manifest.permission.POST_NOTIFICATIONS)
        if (ok) view.confirm()
        after++
    }
    val n = resumeCount() + after
    val enabled = remember(n) { context.getSystemService(NotificationManager::class.java).areNotificationsEnabled() }
    val granted = remember(n) { Build.VERSION.SDK_INT < 33 || granted(context, Manifest.permission.POST_NOTIFICATIONS) }
    val asked = remember(n) { Build.VERSION.SDK_INT < 33 || prefs.asked(Manifest.permission.POST_NOTIFICATIONS) || granted }
    val action = Access.notifications(enabled, granted, asked, Build.VERSION.SDK_INT >= 33 && activity.shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS))
    AccessRow(
        stringResource(R.string.setup_notifications), stringResource(R.string.setup_notifications_why),
        Access.state(enabled, asked), stringResource(R.string.notifications_off), stringResource(R.string.notifications_not_asked),
        action, where = null,
    ) {
        if (action == Access.Action.Ask && Build.VERSION.SDK_INT >= 33) ask.launch(Manifest.permission.POST_NOTIFICATIONS)
        else openSettings(context, notificationSettings(context))
    }
}

@Composable
fun BatteryRow() {
    val context = LocalContext.current
    val n = resumeCount()
    val exempt = remember(n) { context.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(context.packageName) }
    val action = Access.battery(exempt)
    AccessRow(
        stringResource(R.string.setup_battery), stringResource(R.string.setup_battery_why),
        Access.state(exempt, asked = true), stringResource(R.string.battery_off), "",
        action, where = if (exempt) stringResource(R.string.battery_where) else null,
    ) {
        if (action == Access.Action.Ask) openSettings(context, batteryIntent(context))
        else openSettings(context, Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }
}

@Composable
private fun CameraRow() = RuntimeRow(
    arrayOf(Manifest.permission.CAMERA),
    stringResource(R.string.camera), stringResource(R.string.camera_row_why),
    stringResource(R.string.camera_off), stringResource(R.string.camera_not_asked), stringResource(R.string.camera_where),
)

@Composable
private fun NearbyRow() = RuntimeRow(
    NearbyPairing.PERMISSIONS,
    stringResource(R.string.nearby_devices), stringResource(R.string.nearby_row_why),
    stringResource(R.string.nearby_off), stringResource(R.string.nearby_not_asked), stringResource(R.string.nearby_where),
)

/** A runtime permission, or a group Android shows as one (Nearby devices). */
@Composable
private fun RuntimeRow(permissions: Array<String>, title: String, why: String, off: String, notAsked: String, where: String) {
    val context = LocalContext.current
    val activity = context as Activity
    val view = LocalView.current
    val prefs = remember { Prefs(context) }
    var after by remember { mutableIntStateOf(0) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
        permissions.forEach { prefs.markAsked(it) }
        if (result.isNotEmpty() && result.values.all { it }) view.confirm()
        after++
    }
    val n = resumeCount() + after
    val granted = remember(n) { permissions.all { granted(context, it) } }
    val asked = remember(n) { permissions.any { prefs.asked(it) } }
    val rationale = permissions.any { activity.shouldShowRequestPermissionRationale(it) }
    val action = Access.runtime(granted, asked, rationale)
    AccessRow(title, why, Access.state(granted, asked), off, notAsked, action, where = if (action == Access.Action.Ask) null else where) {
        if (action == Access.Action.Ask) ask.launch(permissions) else openSettings(context, appSettings(context))
    }
}

/**
 * One row: the name, why Clipway needs it, what happens without it, and the action, all one tap
 * target. TalkBack reads the state ("On", "Off") and the action ("Turn off in Settings").
 */
@Composable
private fun AccessRow(
    title: String,
    why: String,
    state: Access.State,
    offNote: String,
    notAskedNote: String,
    action: Access.Action,
    where: String?,
    onTap: () -> Unit,
) {
    val view = LocalView.current
    val stateText = stringResource(
        when (state) {
            Access.State.On -> R.string.access_on
            Access.State.Off -> R.string.access_off
            Access.State.NotAsked -> R.string.access_not_asked
        },
    )
    val actionText = stringResource(
        when (action) {
            Access.Action.Ask -> R.string.allow
            Access.Action.OpenToTurnOn -> R.string.turn_on_in_settings
            Access.Action.OpenToTurnOff -> R.string.turn_off_in_settings
        },
    )
    Row(
        Modifier.fillMaxWidth().semantics { stateDescription = stateText }.pressable(actionText) { view.tick(); onTap() }
            .padding(horizontal = Tokens.gutter, vertical = Tokens.Space.m),
        verticalAlignment = Alignment.Top,
    ) {
        Column(Modifier.weight(1f)) {
            Line(title)
            Footnote(why)
            val note = when (state) {
                Access.State.On -> null
                Access.State.Off -> offNote
                Access.State.NotAsked -> notAskedNote
            }
            if (!note.isNullOrEmpty()) {
                Spacer(Modifier.height(Tokens.Space.xs))
                Footnote(note)
            }
            Spacer(Modifier.height(Tokens.Space.s))
            Line(actionText, color = Tokens.colors.accent, size = Tokens.Type.callout, line = Tokens.Type.calloutLine, weight = FontWeight.SemiBold)
            if (where != null) Footnote(where)
        }
        Spacer(Modifier.width(Tokens.Space.m))
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (state == Access.State.On) {
                Glyph(G.Check, Tokens.colors.success, Modifier.size(Tokens.Size.glyphSmall))
                Spacer(Modifier.width(Tokens.Space.xs))
                Line(stateText, color = Tokens.colors.success, size = Tokens.Type.callout, line = Tokens.Type.calloutLine)
            } else {
                Line(stateText, color = Tokens.colors.secondaryText, size = Tokens.Type.callout, line = Tokens.Type.calloutLine)
            }
        }
    }
}

private fun granted(c: Context, permission: String) = c.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

/** The app's page in Settings, where Permissions lists the camera and Nearby devices. */
fun appSettings(c: Context) = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + c.packageName))

/** The app's notification page in Settings: one switch for all, and one per channel. */
fun notificationSettings(c: Context): Intent =
    Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, c.packageName)
