package dev.sidali.clipway

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight

/** Starts the system confirmation of an update as soon as PackageInstaller asks for it. */
@Composable
fun UpdateConfirmation() {
    val context = LocalContext.current
    val confirm by Updater.confirmation.collectAsState()
    LaunchedEffect(confirm) {
        val i = confirm ?: return@LaunchedEffect
        Updater.confirmation.value = null
        try {
            context.startActivity(i)
        } catch (_: Exception) {
        }
    }
}

/** The Home banner: a newer Clipway, and where its installation stands. Nothing when up to date. */
@Composable
fun UpdateBanner() {
    val context = LocalContext.current
    val state by Updater.state.collectAsState()
    val release = when (val s = state) {
        UpdateState.None -> return
        is UpdateState.Available -> s.release
        is UpdateState.NeedsPermission -> s.release
        is UpdateState.Downloading -> s.release
        is UpdateState.Verifying -> s.release
        is UpdateState.Installing -> s.release
        is UpdateState.Failed -> s.release
    }
    Card(padding = Tokens.Space.l) {
        Row(verticalAlignment = Alignment.Top) {
            Glyph(G.Info, Tokens.colors.accent, Modifier.size(Tokens.Size.glyph))
            Spacer(Modifier.width(Tokens.Space.m))
            Column(Modifier.weight(1f)) {
                Line(stringResource(R.string.update_available, release.version), weight = FontWeight.SemiBold)
                val detail = when (val s = state) {
                    is UpdateState.NeedsPermission -> stringResource(R.string.update_permission)
                    is UpdateState.Downloading -> stringResource(R.string.update_downloading, s.percent)
                    is UpdateState.Verifying -> stringResource(R.string.update_verifying)
                    is UpdateState.Installing -> stringResource(R.string.update_installing)
                    is UpdateState.Failed -> stringResource(
                        when (s.why) {
                            UpdateFailure.NETWORK -> R.string.update_failed_network
                            UpdateFailure.SIZE, UpdateFailure.CHECKSUM -> R.string.update_failed_checksum
                            UpdateFailure.CERTIFICATE, UpdateFailure.PACKAGE -> R.string.update_failed_certificate
                            UpdateFailure.STORAGE -> R.string.update_failed_storage
                            UpdateFailure.INSTALL -> R.string.update_failed_other
                        },
                    )
                    else -> null
                }
                if (detail != null) {
                    Spacer(Modifier.height(Tokens.Space.xxs))
                    Secondary(detail)
                }
                when (state) {
                    is UpdateState.Available, is UpdateState.Failed -> {
                        Spacer(Modifier.height(Tokens.Space.m))
                        Capsule(stringResource(R.string.update_install)) { Updater.install(context) }
                    }
                    is UpdateState.NeedsPermission -> {
                        Spacer(Modifier.height(Tokens.Space.m))
                        Capsule(stringResource(R.string.update_permission_action)) {
                            openSettings(context, Updater.permissionIntent(context))
                        }
                    }
                    else -> Unit
                }
            }
        }
    }
    Spacer(Modifier.height(Tokens.Space.l))
}

/** Settings: Automatic updates, and Check for updates. */
@Composable
fun UpdateSettings() {
    val context = LocalContext.current
    val prefs = remember { Prefs(context) }
    var on by remember { mutableStateOf(prefs.automaticUpdates) }
    var note by remember { mutableStateOf<String?>(null) }
    val checking = stringResource(R.string.checking_updates)
    val upToDate = stringResource(R.string.up_to_date, BuildConfig.VERSION_NAME)
    val failed = stringResource(R.string.update_check_failed)
    SectionLabel(stringResource(R.string.updates))
    Card(padding = Tokens.Space.none) {
        ToggleRow(stringResource(R.string.automatic_updates), stringResource(R.string.automatic_updates_detail), on) {
            on = it
            prefs.automaticUpdates = it
            if (it) Updater.check(context) else Updater.turnedOff(context)
        }
        Hairline()
        LinkRow(stringResource(R.string.check_updates), detail = note, chevron = false) {
            note = checking
            Updater.check(context) { found ->
                note = when (found) {
                    true -> null
                    false -> upToDate
                    null -> failed
                }
                if (found == true && !prefs.automaticUpdates) {
                    // Off, but asked by hand: show it anyway.
                    UpdateCheck.parse(prefs.updateManifest, BuildConfig.VERSION_CODE.toLong())?.let {
                        Updater.state.value = UpdateState.Available(it)
                    }
                }
            }
        }
    }
}
