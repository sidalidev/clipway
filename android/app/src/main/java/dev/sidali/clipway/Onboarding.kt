package dev.sidali.clipway

import android.Manifest
import android.app.Activity
import android.app.StatusBarManager
import android.bluetooth.BluetoothAdapter
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.text.InputType
import android.util.TypedValue
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlinx.coroutines.launch

/** First launch in three screens: what Clipway does, pair with the Mac, save the key. */
@Composable
fun Onboarding(paired: Boolean, onPaired: () -> Unit, onDone: () -> Unit) {
    var step by rememberSaveable { mutableIntStateOf(if (paired) 2 else 0) }
    BackHandler(step == 1) { step = 0 }
    AnimatedContent(
        targetState = step,
        transitionSpec = { fadeIn(tween(Tokens.Motion.PAGE_MS)).togetherWith(fadeOut(tween(Tokens.Motion.FADE_MS))) },
        label = "onboarding",
    ) { s ->
        when (s) {
            0 -> Welcome { step = 1 }
            1 -> PairScreen(onBack = { step = 0 }, onPaired = { onPaired(); step = 2 })
            else -> SaveKeyScreen(onDone)
        }
    }
}

/** Full-page layout of the first launch: content scrolls at the top, actions stay at the bottom. */
@Composable
private fun Page(top: @Composable ColumnScope.() -> Unit, bottom: @Composable ColumnScope.() -> Unit) {
    Box(Modifier.fillMaxSize().background(Tokens.colors.page)) {
        Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.systemBars).imePadding()) {
            Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = Tokens.gutter)) {
                Column(Modifier.widthIn(max = Tokens.Size.maxWidth).align(Alignment.CenterHorizontally).fillMaxWidth()) {
                    top()
                    Spacer(Modifier.height(Tokens.Space.xxl))
                }
            }
            Column(
                Modifier.padding(horizontal = Tokens.gutter).widthIn(max = Tokens.Size.maxWidth).align(Alignment.CenterHorizontally).fillMaxWidth(),
            ) {
                bottom()
                Spacer(Modifier.height(Tokens.Space.l))
            }
        }
        StatusBarScrim()
    }
}

@Composable
private fun Welcome(next: () -> Unit) {
    Page(
        top = {
            Spacer(Modifier.height(Tokens.Space.huge))
            Hero(Modifier.fillMaxWidth().height(Tokens.Size.hero))
            Spacer(Modifier.height(Tokens.Space.xxxl))
            LargeTitle(stringResource(R.string.welcome_title))
            Spacer(Modifier.height(Tokens.Space.m))
            Line(stringResource(R.string.welcome_body), Modifier.padding(horizontal = Tokens.Space.xs), color = Tokens.colors.secondaryText)
        },
        bottom = {
            PrimaryButton(stringResource(R.string.welcome_action), onClick = next)
            Spacer(Modifier.height(Tokens.Space.m))
            Footnote(stringResource(R.string.welcome_note), Modifier.fillMaxWidth(), align = TextAlign.Center)
        },
    )
}

// ---------------------------------------------------------------------
// Pairing: nearby over Bluetooth, scan, type the words, or ask the password manager
// ---------------------------------------------------------------------

@android.annotation.SuppressLint("MissingPermission")
@Composable
private fun PairScreen(onBack: () -> Unit, onPaired: () -> Unit) {
    val context = LocalContext.current
    val activity = context as Activity
    val view = LocalView.current
    val scope = rememberCoroutineScope()
    var mode by rememberSaveable { mutableStateOf("choose") }
    var error by rememberSaveable { mutableStateOf<String?>(null) }
    var typed by rememberSaveable { mutableStateOf("") }
    var confirm by remember { mutableStateOf<Key.Parsed.Ok?>(null) }
    val nearbyOffered = remember { NearbyPairing.offered(context) }
    val nearby by NearbyPairing.state.collectAsState()
    // After a process death the attempt is gone: the screen starts over.
    val showNearby = mode == "nearby" && nearby != NearbyState.Idle

    fun join(p: Key.Parsed.Ok) {
        // The words field keeps the keyboard open otherwise.
        context.getSystemService(android.view.inputmethod.InputMethodManager::class.java)
            ?.hideSoftInputFromWindow(view.windowToken, 0)
        Sender.outbox.clear()
        Vault.join(context, p.secret, p.relay)
        p.secret.fill(0)
        ClipService.start(context, ClipService.ACTION_JOINED)
        view.confirm()
        onPaired()
    }

    fun accept(text: String) {
        val msg = when (val p = Key.parse(context, text)) {
            is Key.Parsed.Ok -> {
                if (p.relay != null && Protocol.normalizeRelay(p.relay) != BuildConfig.DEFAULT_RELAY) confirm = p else join(p)
                return
            }
            Key.Parsed.NotTwelve -> R.string.error_twelve
            Key.Parsed.UnknownWord -> R.string.error_unknown_word
            Key.Parsed.BadChecksum -> R.string.error_checksum
            Key.Parsed.BadCode -> R.string.error_code
            Key.Parsed.RelayRefused -> R.string.error_relay_refused
        }
        view.reject()
        error = context.getString(msg)
        if (mode == "scan") mode = "choose"
    }

    val camera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        Prefs(context).markAsked(Manifest.permission.CAMERA)
        if (ok) mode = "scan" else error = context.getString(R.string.camera_denied)
    }

    fun scan() {
        NearbyPairing.cancel()
        error = null
        if (context.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) mode = "scan"
        else {
            mode = "choose"
            camera.launch(Manifest.permission.CAMERA)
        }
    }

    // Pair nearby: Nearby devices permission at the tap, then Bluetooth on, then a new attempt.
    val bluetoothOn = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        mode = "nearby"
        if (NearbyPairing.on(context)) NearbyPairing.start(context) else NearbyPairing.show(NearbyState.Why.BluetoothOff)
    }
    fun turnOnBluetooth() {
        try {
            bluetoothOn.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
        } catch (_: Exception) {
            openSettings(context, Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
        }
    }
    fun startNearby() {
        error = null
        when {
            !NearbyPairing.present(context) -> { mode = "nearby"; NearbyPairing.show(NearbyState.Why.Unavailable) }
            !NearbyPairing.on(context) -> turnOnBluetooth()
            else -> { mode = "nearby"; NearbyPairing.start(context) }
        }
    }
    val nearbyPermissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        NearbyPairing.PERMISSIONS.forEach { p -> Prefs(context).markAsked(p) }
        if (NearbyPairing.allowed(context)) startNearby() else {
            mode = "nearby"
            NearbyPairing.show(NearbyState.Why.NotAllowed)
        }
    }
    fun pairNearby() {
        if (NearbyPairing.allowed(context)) startNearby() else nearbyPermissions.launch(NearbyPairing.PERMISSIONS)
    }
    fun leaveNearby() {
        NearbyPairing.cancel()
        mode = "choose"
    }

    // The packet arrived: exactly the path of a scanned code (relay check, join, hello, save the key).
    LaunchedEffect(nearby) {
        when (val s = nearby) {
            is NearbyState.Paired -> {
                NearbyPairing.cancel()
                mode = "choose"
                accept(s.code)
            }
            is NearbyState.Code -> if (!s.pressed) view.tick()
            is NearbyState.Ended -> if (mode == "nearby") view.reject()
            else -> Unit
        }
    }
    // Bluetooth only while this screen is in front: leaving the app ends the attempt. Coming back
    // after allowing Nearby devices or turning Bluetooth on elsewhere shows the start again.
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val o = LifecycleEventObserver { _, e ->
            val s = NearbyPairing.state.value
            if (e == Lifecycle.Event.ON_STOP && !activity.isChangingConfigurations && s.active) leaveNearby()
            if (e == Lifecycle.Event.ON_RESUME && s is NearbyState.Ended &&
                ((s.why == NearbyState.Why.NotAllowed && NearbyPairing.allowed(context)) ||
                    (s.why == NearbyState.Why.BluetoothOff && NearbyPairing.on(context)))
            ) leaveNearby()
        }
        owner.lifecycle.addObserver(o)
        onDispose {
            owner.lifecycle.removeObserver(o)
            if (!activity.isChangingConfigurations) NearbyPairing.cancel()
        }
    }
    // The screen stays on during an attempt (2 minutes at most).
    val active = showNearby && nearby.active
    DisposableEffect(active) {
        if (active) activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        onDispose { activity.window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
    }

    BackHandler(mode != "choose") { if (mode == "nearby") leaveNearby() else mode = "choose" }

    Page(
        top = {
            Spacer(Modifier.height(Tokens.Space.s))
            BackButton { if (mode == "nearby") leaveNearby() else if (mode != "choose") mode = "choose" else onBack() }
            Spacer(Modifier.height(Tokens.Space.m))
            LargeTitle(stringResource(if (showNearby) R.string.nearby_title else R.string.pair_title))
            if (!showNearby) {
                Spacer(Modifier.height(Tokens.Space.m))
                Line(
                    stringResource(if (nearbyOffered && mode == "choose") R.string.pair_body_nearby else R.string.pair_body),
                    Modifier.padding(horizontal = Tokens.Space.xs), color = Tokens.colors.secondaryText,
                )
            }
            Spacer(Modifier.height(Tokens.Space.xxl))
            when {
                showNearby -> NearbyCard(nearby)
                mode == "scan" -> {
                    Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(Tokens.cardRadius)).background(Tokens.colors.card)) {
                        QrScanner(onText = { accept(it) }, modifier = Modifier.fillMaxWidth().heightIn(max = Tokens.Size.scanner))
                    }
                    Spacer(Modifier.height(Tokens.Space.m))
                    Footnote(stringResource(R.string.scan_hint), Modifier.fillMaxWidth(), align = TextAlign.Center)
                }
                mode == "type" -> {
                    Card(padding = Tokens.Space.l) {
                        WordsField(typed) { typed = it; error = null }
                    }
                    Spacer(Modifier.height(Tokens.Space.s))
                    Footnote(stringResource(R.string.type_hint), Modifier.padding(horizontal = Tokens.Space.xs))
                }
                else -> Card {
                    Column(verticalArrangement = Arrangement.spacedBy(Tokens.Space.l)) {
                        Step(1, stringResource(R.string.pair_step1))
                        Step(2, stringResource(R.string.pair_step2))
                        Step(3, stringResource(if (nearbyOffered) R.string.pair_step3_nearby else R.string.pair_step3))
                    }
                }
            }
            AnimatedVisibility(error != null) {
                Row(Modifier.padding(top = Tokens.Space.l, start = Tokens.Space.xs, end = Tokens.Space.xs), verticalAlignment = Alignment.Top) {
                    Glyph(G.Info, Tokens.colors.danger, Modifier.size(Tokens.Size.glyphSmall))
                    Spacer(Modifier.width(Tokens.Space.s))
                    Line(error ?: "", color = Tokens.colors.danger, size = Tokens.Type.callout, line = Tokens.Type.calloutLine)
                }
            }
        },
        bottom = {
            when {
                showNearby -> NearbyActions(
                    nearby,
                    onPair = { NearbyPairing.pair() },
                    onCancel = { leaveNearby() },
                    onRetry = { pairNearby() },
                    onScan = { scan() },
                    onTurnOn = { turnOnBluetooth() },
                    onSettings = { openSettings(context, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + context.packageName))) },
                )
                mode == "type" -> PrimaryButton(stringResource(R.string.pair_action), enabled = typed.isNotBlank()) { accept(typed) }
                mode == "scan" -> SecondaryButton(stringResource(R.string.cancel)) { mode = "choose" }
                nearbyOffered -> {
                    PrimaryButton(stringResource(R.string.nearby_action)) { pairNearby() }
                    Spacer(Modifier.height(Tokens.Space.s))
                    Footnote(stringResource(R.string.nearby_why), Modifier.fillMaxWidth(), align = TextAlign.Center)
                    Spacer(Modifier.height(Tokens.Space.l))
                    SecondaryButton(stringResource(R.string.pair_scan_instead)) { scan() }
                    Spacer(Modifier.height(Tokens.Space.s))
                    Footnote(stringResource(R.string.camera_why), Modifier.fillMaxWidth(), align = TextAlign.Center)
                    Spacer(Modifier.height(Tokens.Space.s))
                    OtherWays(onType = { error = null; mode = "type" }, onPasswordManager = {
                        error = null
                        scope.launch {
                            when (val got = Key.fromPasswordManager(activity)) {
                                is Key.Fetched.Found -> accept(got.text)
                                Key.Fetched.Nothing -> error = context.getString(R.string.password_manager_nothing)
                                Key.Fetched.Cancelled -> Unit
                            }
                        }
                    })
                }
                else -> {
                    PrimaryButton(stringResource(R.string.pair_scan)) { scan() }
                    Spacer(Modifier.height(Tokens.Space.s))
                    Footnote(stringResource(R.string.camera_why), Modifier.fillMaxWidth(), align = TextAlign.Center)
                    Spacer(Modifier.height(Tokens.Space.l))
                    SecondaryButton(stringResource(R.string.pair_type)) { error = null; mode = "type" }
                    if (Key.passwordManagerAvailable) {
                        Spacer(Modifier.height(Tokens.Space.m))
                        SecondaryButton(stringResource(R.string.pair_password_manager)) {
                            error = null
                            scope.launch {
                                when (val got = Key.fromPasswordManager(activity)) {
                                    is Key.Fetched.Found -> accept(got.text)
                                    Key.Fetched.Nothing -> error = context.getString(R.string.password_manager_nothing)
                                    Key.Fetched.Cancelled -> Unit
                                }
                            }
                        }
                    }
                }
            }
        },
    )

    confirm?.let { p ->
        CardDialog(
            title = stringResource(R.string.other_relay_title),
            body = stringResource(R.string.other_relay_body, Protocol.relayHost(p.relay ?: "")),
            onDismiss = { confirm = null; p.secret.fill(0) },
        ) {
            DialogButtons(
                stringResource(R.string.cancel), stringResource(R.string.other_relay_use),
                onCancel = { confirm = null; p.secret.fill(0) },
                onAction = { confirm = null; join(p) },
            )
        }
    }
}

/** Type the 12 words and Use my password manager: quiet text actions under the two main ways. */
@Composable
private fun OtherWays(onType: () -> Unit, onPasswordManager: () -> Unit) {
    TextAction(stringResource(R.string.pair_type), onClick = onType)
    if (Key.passwordManagerAvailable) TextAction(stringResource(R.string.pair_password_manager), onClick = onPasswordManager)
}

/** The buttons under the nearby card, for each moment of the attempt. */
@Composable
private fun NearbyActions(
    state: NearbyState,
    onPair: () -> Unit,
    onCancel: () -> Unit,
    onRetry: () -> Unit,
    onScan: () -> Unit,
    onTurnOn: () -> Unit,
    onSettings: () -> Unit,
) {
    when (state) {
        is NearbyState.Code -> if (!state.pressed) {
            PrimaryButton(stringResource(R.string.pair_action), confirm = true, onClick = onPair)
            Spacer(Modifier.height(Tokens.Space.m))
            SecondaryButton(stringResource(R.string.cancel), onClick = onCancel)
        } else {
            SecondaryButton(stringResource(R.string.cancel), onClick = onCancel)
        }
        is NearbyState.Ended -> when (state.why) {
            NearbyState.Why.BluetoothOff -> {
                PrimaryButton(stringResource(R.string.turn_on_bluetooth), onClick = onTurnOn)
                Spacer(Modifier.height(Tokens.Space.xs))
                TextAction(stringResource(R.string.pair_scan_instead), onClick = onScan)
            }
            NearbyState.Why.NotAllowed -> {
                PrimaryButton(stringResource(R.string.open_settings), onClick = onSettings)
                Spacer(Modifier.height(Tokens.Space.xs))
                TextAction(stringResource(R.string.pair_scan_instead), onClick = onScan)
            }
            NearbyState.Why.Unavailable -> PrimaryButton(stringResource(R.string.pair_scan_instead), onClick = onScan)
            else -> {
                PrimaryButton(stringResource(R.string.try_again), onClick = onRetry)
                Spacer(Modifier.height(Tokens.Space.m))
                SecondaryButton(stringResource(R.string.pair_scan_instead), onClick = onScan)
            }
        }
        else -> SecondaryButton(stringResource(R.string.cancel), onClick = onCancel)
    }
}

/** A numbered step: the number in a tinted circle, then one sentence. */
@Composable
private fun Step(n: Int, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(Tokens.Size.iconButton).clip(CircleShape).background(Tokens.colors.badge),
            contentAlignment = Alignment.Center,
        ) { Line("$n", color = Tokens.colors.onBadge, weight = FontWeight.SemiBold) }
        Spacer(Modifier.width(Tokens.Space.l))
        Line(text, Modifier.weight(1f), size = Tokens.Type.callout, line = Tokens.Type.calloutLine)
    }
}

/**
 * The 12 words: a plain EditText, because Compose cannot ask the keyboard not to learn
 * (IME_FLAG_NO_PERSONALIZED_LEARNING). No suggestions; only a password manager may fill it.
 */
@Composable
private fun WordsField(value: String, onChange: (String) -> Unit) {
    val text = Tokens.colors.text.toArgb()
    val hint = Tokens.colors.secondaryText.toArgb()
    val label = stringResource(R.string.words_label)
    val placeholder = stringResource(R.string.words_placeholder)
    AndroidView(
        factory = { ctx ->
            EditText(ctx).apply {
                background = null
                setPadding(0, 0, 0, 0)
                gravity = android.view.Gravity.TOP or android.view.Gravity.START
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_ACTION_DONE
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
                setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, Tokens.Type.body.value)
                typeface = android.graphics.Typeface.MONOSPACE
                setTextColor(text)
                setHintTextColor(hint)
                this.hint = placeholder
                contentDescription = label
                minLines = 3
                setText(value)
                addTextChangedListener(object : android.text.TextWatcher {
                    override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
                    override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
                    override fun afterTextChanged(s: android.text.Editable?) = onChange(s?.toString().orEmpty())
                })
                requestFocus()
            }
        },
        update = { if (it.text.toString() != value) it.setText(value) },
        modifier = Modifier.fillMaxWidth().heightIn(min = Tokens.Size.wordsField),
    )
}

// ---------------------------------------------------------------------
// Save the key, then the few permissions that make it work in the background
// ---------------------------------------------------------------------

@Composable
private fun SaveKeyScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val activity = context as Activity
    val view = LocalView.current
    val scope = rememberCoroutineScope()
    val prefs = remember { Prefs(context) }
    var saved by rememberSaveable { mutableStateOf(prefs.keySaved) }
    val note = remember { Note() }
    val link by Status.link.collectAsState()
    val devices by Status.devices.collectAsState()
    val peer by Status.peer.collectAsState()
    val celebrate by Status.celebrate.collectAsState()
    LaunchedEffect(celebrate) {
        if (celebrate) {
            view.confirm()
            Status.celebrate.value = false
        }
    }

    Page(
        top = {
            Spacer(Modifier.height(Tokens.Space.huge))
            LargeTitle(stringResource(R.string.save_title))
            Spacer(Modifier.height(Tokens.Space.m))
            Line(stringResource(R.string.save_body), Modifier.padding(horizontal = Tokens.Space.xs), color = Tokens.colors.secondaryText)
            Spacer(Modifier.height(Tokens.Space.xxl))
            val mac = peer ?: stringResource(R.string.your_mac)
            val connected = link == Status.Link.Online && (devices > 1 || peer != null)
            Card(padding = Tokens.Space.l) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier.size(Tokens.Size.iconButton).clip(CircleShape)
                            .background(if (connected) Tokens.colors.success.copy(alpha = 0.16f) else Tokens.colors.raised),
                        contentAlignment = Alignment.Center,
                    ) { Glyph(if (connected) G.Check else G.Mac, if (connected) Tokens.colors.success else Tokens.colors.secondaryText, Modifier.size(Tokens.Size.glyph)) }
                    Spacer(Modifier.width(Tokens.Space.m))
                    Line(
                        if (connected) stringResource(R.string.connected_to, mac) else stringResource(R.string.connecting_to_mac),
                        weight = FontWeight.SemiBold,
                    )
                }
            }
            Spacer(Modifier.height(Tokens.Space.xxl))
            SectionLabel(stringResource(R.string.finish_setup))
            Card(padding = Tokens.Space.none) { SetupRows() }
            Spacer(Modifier.height(Tokens.Space.l))
            Footnote(stringResource(R.string.key_truth), Modifier.padding(horizontal = Tokens.Space.xs))
        },
        bottom = {
            val words = remember { Vault.secret(context)?.let { s -> Key.words(context, s).also { s.fill(0) } } ?: emptyList() }
            if (!saved && Key.passwordManagerAvailable) {
                PrimaryButton(stringResource(R.string.save_password_manager)) {
                    scope.launch {
                        when (Key.save(activity, words)) {
                            Key.Saved.Yes -> {
                                prefs.keySaved = true
                                saved = true
                                view.confirm()
                                note.show(context.getString(R.string.saved))
                            }
                            Key.Saved.No -> {
                                view.reject()
                                note.show(context.getString(R.string.save_failed), false)
                            }
                            Key.Saved.Cancelled -> Unit
                        }
                    }
                }
                Spacer(Modifier.height(Tokens.Space.m))
                SecondaryButton(stringResource(R.string.print_kit)) { printKit(activity, words); prefs.keySaved = true }
                Spacer(Modifier.height(Tokens.Space.xs))
                TextAction(stringResource(R.string.not_now), onClick = onDone)
            } else {
                PrimaryButton(stringResource(R.string.done), onClick = onDone)
                Spacer(Modifier.height(Tokens.Space.m))
                SecondaryButton(stringResource(R.string.print_kit)) { printKit(activity, words); prefs.keySaved = true }
            }
            NoteLine(note)
        },
    )
}

fun printKit(activity: Activity, words: List<String>) {
    val prefs = Prefs(activity)
    val s = Vault.secret(activity) ?: return
    val code = Crypto.toQr(s, prefs.relay, BuildConfig.DEFAULT_RELAY)
    s.fill(0)
    Key.printKit(activity, words, code, Protocol.relayHost(prefs.relay))
}

/**
 * Notifications, the tile and background use: each with one sentence on why, and one tap to turn
 * it on or off. The first launch shows all three; Settings shows the tile and links to Permissions.
 */
@Composable
fun SetupRows(permissions: Boolean = true) {
    val context = LocalContext.current
    val prefs = remember { Prefs(context) }
    var tileAdded by remember { mutableStateOf(prefs.tileHintDismissed) }
    Column {
        if (permissions) {
            NotificationsRow()
            Hairline()
        }
        StateRow(
            stringResource(R.string.setup_tile), stringResource(R.string.setup_tile_why), tileAdded, stringResource(R.string.add),
        ) {
            requestTile(context) { prefs.tileHintDismissed = true; tileAdded = true }
        }
        if (permissions) {
            Hairline()
            BatteryRow()
        }
    }
}

@Composable
private fun StateRow(title: String, why: String, done: Boolean, action: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Tokens.gutter, vertical = Tokens.Space.m),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Line(title)
            Footnote(why)
        }
        Spacer(Modifier.width(Tokens.Space.m))
        if (done) {
            val label = stringResource(R.string.done)
            Box(Modifier.semantics { contentDescription = label }) { Glyph(G.Check, Tokens.colors.success) }
        } else {
            Capsule(action, onClick = onClick)
        }
    }
}

@android.annotation.SuppressLint("BatteryLife")
fun batteryIntent(c: Context): Intent =
    Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + c.packageName))

/** Offers to add the Send to Mac tile (Android 13 and later); before that, explains where it is. */
fun requestTile(c: Context, onAdded: () -> Unit) {
    if (Build.VERSION.SDK_INT >= 33) {
        c.getSystemService(StatusBarManager::class.java).requestAddTileService(
            ComponentName(c, SendTile::class.java), c.getString(R.string.tile_label), Icon.createWithResource(c, R.drawable.ic_tile),
            c.mainExecutor,
        ) { result ->
            if (result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ADDED || result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ALREADY_ADDED) onAdded()
        }
    } else {
        android.widget.Toast.makeText(c, c.getString(R.string.tile_manual), android.widget.Toast.LENGTH_LONG).show()
        onAdded()
    }
}
