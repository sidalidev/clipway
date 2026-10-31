package dev.sidali.clipway

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import android.util.LruCache
import android.view.WindowManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.material3.Text
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------
// Home: connection state, the last item, Send clipboard
// ---------------------------------------------------------------------

@Composable
fun HomeTab(go: (Page) -> Unit, onReset: () -> Unit, openHistory: () -> Unit) {
    val context = LocalContext.current
    val view = LocalView.current
    val prefs = remember { Prefs(context) }
    LaunchedEffect(Unit) { if (prefs.chainErased) Status.link.value = Status.Link.Erased }
    val link by Status.link.collectAsState()
    val devices by Status.devices.collectAsState()
    val peer by Status.peer.collectAsState()
    val notice by Status.relayNotice.collectAsState()
    val celebrate by Status.celebrate.collectAsState()
    val entries by History.entries.collectAsState()
    LaunchedEffect(Unit) { withContext(Dispatchers.IO) { History.load(context) } }
    LaunchedEffect(celebrate) { if (celebrate) { view.confirm(); Status.celebrate.value = false } }
    val note = remember { Note() }
    var tileHint by remember { mutableStateOf(!prefs.tileHintDismissed) }
    val mac = peer ?: stringResource(R.string.your_mac)
    var paused by remember { mutableStateOf(prefs.paused) }

    Screen(stringResource(R.string.app_name), onBack = null) {
        if (link != Status.Link.Erased) {
            PowerCard(paused, mac) {
                paused = it
                ClipService.setPaused(context, it)
            }
            Spacer(Modifier.height(Tokens.Space.xxl))
        }
        if (link == Status.Link.Erased) {
            Card {
                Line(stringResource(R.string.chain_erased_title), weight = FontWeight.SemiBold)
                Spacer(Modifier.height(Tokens.Space.xs))
                Secondary(stringResource(R.string.chain_erased_body))
                Spacer(Modifier.height(Tokens.Space.l))
                PrimaryButton(stringResource(R.string.pair_again)) {
                    Vault.forget(context)
                    Prefs(context).forgetChain()
                    Status.link.value = Status.Link.Off
                    onReset()
                }
            }
            return@Screen
        }
        notice?.let { n ->
            Card(padding = Tokens.Space.l) {
                Row(verticalAlignment = Alignment.Top) {
                    Glyph(G.Info, Tokens.colors.danger, Modifier.size(Tokens.Size.glyph))
                    Spacer(Modifier.width(Tokens.Space.m))
                    Secondary(
                        stringResource(
                            when (n) {
                                "update" -> R.string.notice_update
                                "end-of-service" -> R.string.notice_end
                                else -> R.string.notice_degraded
                            },
                        ),
                    )
                }
            }
            Spacer(Modifier.height(Tokens.Space.l))
        }

        if (!paused) {
            StatusCard(link, devices, mac)
            Spacer(Modifier.height(Tokens.Space.xxl))
        }

        PrimaryButton(stringResource(R.string.send_clipboard), enabled = !paused) {
            val (message, ok) = Sender.sendAll(context, Sender.fromClipboard(context))
            if (ok) view.confirm() else view.reject()
            note.show(message, ok)
        }
        NoteLine(note)
        Spacer(Modifier.height(Tokens.Space.xxl))

        SectionLabel(stringResource(R.string.last_item))
        val last = entries.firstOrNull()
        if (last == null) {
            Card { Secondary(stringResource(R.string.nothing_yet_home, mac)) }
        } else {
            Card(padding = Tokens.Space.none) {
                EntryRow(last, actions = true)
                Hairline()
                LinkRow(stringResource(R.string.see_history), onClick = openHistory)
            }
        }

        if (tileHint) {
            Spacer(Modifier.height(Tokens.Space.xxl))
            Card(padding = Tokens.Space.l) {
                Row(verticalAlignment = Alignment.Top) {
                    Glyph(G.Send, Tokens.colors.accent, Modifier.size(Tokens.Size.glyph))
                    Spacer(Modifier.width(Tokens.Space.m))
                    Column(Modifier.weight(1f)) {
                        Line(stringResource(R.string.tip_title), weight = FontWeight.SemiBold)
                        Spacer(Modifier.height(Tokens.Space.xxs))
                        Secondary(stringResource(R.string.tip_body))
                        Spacer(Modifier.height(Tokens.Space.m))
                        Row(horizontalArrangement = Arrangement.spacedBy(Tokens.Space.s)) {
                            Capsule(stringResource(R.string.add_tile)) {
                                requestTile(context) { prefs.tileHintDismissed = true; tileHint = false }
                            }
                            Capsule(stringResource(R.string.not_now)) { prefs.tileHintDismissed = true; tileHint = false }
                        }
                    }
                }
            }
        }
    }
}

/**
 * The master switch: everything on, or everything paused, in one tap both ways. One sentence says
 * what stops. The whole row is the switch, so TalkBack reads "Clipway, On" or "Clipway, Paused".
 */
@Composable
private fun PowerCard(paused: Boolean, mac: String, onChange: (Boolean) -> Unit) {
    val view = LocalView.current
    val state = stringResource(if (paused) R.string.power_paused else R.string.power_on)
    Card(padding = Tokens.Space.none) {
        Row(
            Modifier.fillMaxWidth().heightIn(min = Tokens.Size.row)
                .toggleable(value = !paused, role = Role.Switch) { on -> view.tick(); onChange(!on) }
                .semantics { stateDescription = state }
                .padding(start = Tokens.gutter, end = Tokens.Space.l, top = Tokens.Space.m, bottom = Tokens.Space.m),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f).animateContentSize()) {
                Line(stringResource(R.string.power_title), weight = FontWeight.SemiBold)
                Spacer(Modifier.height(Tokens.Space.xxs))
                Footnote(if (paused) stringResource(R.string.power_paused_detail, mac) else stringResource(R.string.power_on_detail))
            }
            Spacer(Modifier.width(Tokens.Space.m))
            Line(state, Modifier.clearAndSetSemantics {}, color = if (paused) Tokens.colors.secondaryText else Tokens.colors.success, weight = FontWeight.Medium)
            Spacer(Modifier.width(Tokens.Space.s))
            GreenSwitch(!paused, null)
        }
    }
}

@Composable
private fun StatusCard(link: Status.Link, devices: Int, mac: String) {
    val (title, detail, good) = when {
        link == Status.Link.Online && devices > 1 -> Triple(stringResource(R.string.connected_to, mac), stringResource(R.string.status_online_detail), true)
        link == Status.Link.Online -> Triple(stringResource(R.string.mac_offline, mac), stringResource(R.string.status_waiting_detail), true)
        link == Status.Link.NoNetwork -> Triple(stringResource(R.string.waiting_for_network), stringResource(R.string.status_network_detail), false)
        link == Status.Link.Unreachable -> Triple(stringResource(R.string.relay_unreachable), stringResource(R.string.status_unreachable_detail), false)
        else -> Triple(stringResource(R.string.connecting), stringResource(R.string.status_connecting_detail), false)
    }
    Card {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(Tokens.Size.badge).clip(CircleShape)
                    .background(if (good) Tokens.colors.success.copy(alpha = 0.16f) else Tokens.colors.raised),
                contentAlignment = Alignment.Center,
            ) {
                Glyph(G.Mac, if (good) Tokens.colors.success else Tokens.colors.secondaryText, Modifier.size(Tokens.Size.glyph))
            }
            Spacer(Modifier.width(Tokens.Space.l))
            Column(Modifier.weight(1f).animateContentSize()) {
                Line(title, weight = FontWeight.SemiBold)
                Spacer(Modifier.height(Tokens.Space.xxs))
                Secondary(detail)
            }
        }
    }
}

// ---------------------------------------------------------------------
// History: the last 50 items, Copy, Delete with Undo, Export, Clear
// ---------------------------------------------------------------------

private val thumbs = LruCache<String, ImageBitmap>(24)

@Composable
private fun Thumb(e: History.Entry) {
    val context = LocalContext.current
    val image by produceState(thumbs.get(e.item), e.item) {
        if (value == null && e.kept) value = withContext(Dispatchers.IO) {
            History.content(context, e.item)?.let { bytes ->
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                var sample = 1
                while (bounds.outWidth / (sample * 2) >= 160 && bounds.outHeight / (sample * 2) >= 160) sample *= 2
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample })?.asImageBitmap()
            }?.also { thumbs.put(e.item, it) }
        }
    }
    Box(
        Modifier.size(Tokens.Size.thumb).clip(RoundedCornerShape(Tokens.fieldRadius)).background(Tokens.colors.raised),
        contentAlignment = Alignment.Center,
    ) {
        val img = image
        if (img != null) Image(img, null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop, filterQuality = FilterQuality.Medium)
        else Glyph(G.Image, Tokens.colors.secondaryText)
    }
}

/** One history row: what it is, from where and when, and its actions. */
@Composable
fun EntryRow(e: History.Entry, actions: Boolean, onDelete: (() -> Unit)? = null) {
    val context = LocalContext.current
    val view = LocalView.current
    val note = remember { Note() }
    Column(Modifier.fillMaxWidth().padding(horizontal = Tokens.gutter, vertical = Tokens.Space.l)) {
        Row(verticalAlignment = Alignment.Top) {
            when (e.type) {
                "image" -> Thumb(e)
                else -> Box(
                    Modifier.size(Tokens.Size.iconButton).clip(RoundedCornerShape(Tokens.fieldRadius)).background(Tokens.colors.raised),
                    contentAlignment = Alignment.Center,
                ) { Glyph(if (e.type == "file") G.File else G.Text, Tokens.colors.accent) }
            }
            Spacer(Modifier.width(Tokens.Space.m))
            Column(Modifier.weight(1f)) {
                val main = when {
                    e.removed -> stringResource(R.string.content_removed)
                    e.type == "text" -> e.preview.orEmpty()
                    e.type == "image" -> e.name ?: stringResource(R.string.an_image)
                    else -> e.name ?: stringResource(R.string.a_file)
                }
                Text(main, fontSize = Tokens.Type.body, lineHeight = Tokens.Type.bodyLine, color = Tokens.colors.text, maxLines = 3, overflow = TextOverflow.Ellipsis)
                Spacer(Modifier.height(Tokens.Space.xxs))
                Footnote(describe(context, e))
            }
        }
        if (actions) {
            Spacer(Modifier.height(Tokens.Space.m))
            Row(horizontalArrangement = Arrangement.spacedBy(Tokens.Space.s), verticalAlignment = Alignment.CenterVertically) {
                if (e.kept && (e.type == "text" || e.type == "image")) {
                    Capsule(stringResource(R.string.copy), glyph = G.Copy) {
                        copyBack(context, e)
                        view.confirm()
                        note.show(context.getString(R.string.copied))
                    }
                }
                if (e.type == "file" && e.uri != null) {
                    Capsule(stringResource(R.string.open), glyph = G.File) { openFile(context, e) }
                }
                if (onDelete != null) Capsule(stringResource(R.string.delete), glyph = G.Trash, onClick = onDelete)
            }
            NoteLine(note)
        }
    }
}

private fun describe(c: Context, e: History.Entry): String {
    val time = ago(c, e.ts)
    val size = if (e.type != "text") " · " + sizeText(e.size) else ""
    if (!e.outgoing) return c.getString(R.string.from_device, e.device) + " · " + time + size
    val mac = Status.peer.value ?: c.getString(R.string.your_mac)
    val state = when (e.status) {
        "delivered" -> c.getString(R.string.state_delivered)
        "sent" -> c.getString(R.string.state_sent)
        "waiting" -> c.getString(R.string.waiting_for, mac)
        "failed" -> c.getString(R.string.state_failed)
        "unreachable" -> c.getString(R.string.state_unreachable)
        else -> c.getString(R.string.state_sending)
    }
    return state + " · " + time + size
}

private fun copyBack(c: Context, e: History.Entry) {
    val bytes = History.content(c, e.item) ?: return
    if (e.type == "text") Clips.text(c, String(bytes, Charsets.UTF_8)) else Clips.image(c, e.item, e.mime, bytes)
}

private fun openFile(c: Context, e: History.Entry) {
    val uri = Uri.parse(e.uri ?: return)
    try {
        c.startActivity(
            Intent(Intent.ACTION_VIEW).setDataAndType(uri, Protocol.cleanMime(e.mime)).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION),
        )
    } catch (_: Exception) {
        android.widget.Toast.makeText(c, c.getString(R.string.no_app_for_file), android.widget.Toast.LENGTH_SHORT).show()
    }
}

@Composable
fun HistoryTab() {
    val context = LocalContext.current
    val view = LocalView.current
    val entries by History.entries.collectAsState()
    LaunchedEffect(Unit) { withContext(Dispatchers.IO) { History.load(context) } }
    // Deleted rows hide at once and go for good after 5 s, unless Undo.
    var hidden by remember { mutableStateOf(setOf<String>()) }
    var undoAt by remember { mutableStateOf(0L) }
    var exportWarning by rememberSaveable { mutableStateOf(false) }
    val visible = entries.filter { it.item !in hidden }

    fun commit() {
        val gone = hidden
        if (gone.isEmpty()) return
        hidden = emptySet()
        undoAt = 0L
        Thread { History.delete(context, gone) }.start()
    }
    LaunchedEffect(undoAt) {
        if (undoAt > 0) {
            delay(Tokens.Motion.UNDO_MS)
            commit()
        }
    }
    DisposableEffect(Unit) { onDispose { commit() } }

    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
        if (uri != null) Thread {
            val ok = try {
                context.contentResolver.openOutputStream(uri)?.use { History.export(context, it) } != null
            } catch (e: Exception) {
                false
            }
            (context as Activity).runOnUiThread {
                android.widget.Toast.makeText(context, context.getString(if (ok) R.string.exported else R.string.export_failed), android.widget.Toast.LENGTH_SHORT).show()
            }
        }.start()
    }

    Box(Modifier.fillMaxSize().background(Tokens.colors.page)) {
        LazyColumn(
            Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.statusBars).padding(horizontal = Tokens.Space.l),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            item(key = "title", contentType = "title") {
                Column(Modifier.widthIn(max = Tokens.Size.maxWidth).fillMaxWidth()) {
                    Spacer(Modifier.height(Tokens.Space.s + Tokens.Size.iconButton + Tokens.Space.m))
                    LargeTitle(stringResource(R.string.history))
                    Spacer(Modifier.height(Tokens.Space.l))
                    if (visible.isNotEmpty()) {
                        Row(horizontalArrangement = Arrangement.spacedBy(Tokens.Space.s), modifier = Modifier.padding(start = Tokens.Space.xs)) {
                            Capsule(stringResource(R.string.export), glyph = G.Share) { exportWarning = true }
                            Capsule(stringResource(R.string.clear_history), glyph = G.Trash) {
                                view.tick()
                                hidden = hidden + entries.map { it.item }
                                undoAt = System.currentTimeMillis()
                            }
                        }
                        Spacer(Modifier.height(Tokens.Space.l))
                    }
                }
            }
            if (visible.isEmpty()) item(key = "empty", contentType = "empty") {
                Column(Modifier.widthIn(max = Tokens.Size.maxWidth).fillMaxWidth()) {
                    Card { Secondary(stringResource(R.string.history_empty)) }
                }
            }
            items(visible, key = { it.item }, contentType = { it.type }) { e ->
                Column(Modifier.widthIn(max = Tokens.Size.maxWidth).fillMaxWidth().animateItem()) {
                    Card(padding = Tokens.Space.none) {
                        EntryRow(e, actions = true, onDelete = {
                            hidden = hidden + e.item
                            undoAt = System.currentTimeMillis()
                        })
                    }
                    Spacer(Modifier.height(Tokens.Space.m))
                }
            }
            if (visible.isNotEmpty()) item(key = "end", contentType = "end") {
                Footnote(
                    stringResource(R.string.thats_everything),
                    Modifier.fillMaxWidth().padding(vertical = Tokens.Space.l), align = TextAlign.Center,
                )
            }
            item(key = "space", contentType = "space") { Spacer(Modifier.height(Tokens.Space.huge + Tokens.Space.huge)) }
        }
        StatusBarScrim()
        AnimatedVisibility(hidden.isNotEmpty(), Modifier.align(Alignment.BottomCenter)) {
            Row(
                Modifier.padding(Tokens.Space.l).widthIn(max = Tokens.Size.maxWidth).fillMaxWidth()
                    .clip(RoundedCornerShape(Tokens.buttonRadius)).background(Tokens.colors.text)
                    .padding(start = Tokens.gutter, end = Tokens.Space.s, top = Tokens.Space.s, bottom = Tokens.Space.s),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Line(
                    context.resources.getQuantityString(R.plurals.deleted, hidden.size, hidden.size),
                    Modifier.weight(1f), color = Tokens.colors.page, size = Tokens.Type.callout, line = Tokens.Type.calloutLine,
                )
                Box(
                    Modifier.pressable(stringResource(R.string.undo)) { view.tick(); hidden = emptySet(); undoAt = 0L }
                        .padding(horizontal = Tokens.Space.m, vertical = Tokens.Space.s),
                ) { Line(stringResource(R.string.undo), color = Tokens.colors.page, weight = FontWeight.SemiBold) }
            }
        }
    }

    if (exportWarning) {
        CardDialog(stringResource(R.string.export_title), stringResource(R.string.export_body), onDismiss = { exportWarning = false }) {
            DialogButtons(
                stringResource(R.string.cancel), stringResource(R.string.export),
                onCancel = { exportWarning = false },
                onAction = { exportWarning = false; export.launch("clipway-history.zip") },
            )
        }
    }
}

// ---------------------------------------------------------------------
// Settings (10 at most)
// ---------------------------------------------------------------------

@Composable
fun SettingsTab(go: (Page) -> Unit) {
    val context = LocalContext.current
    val activity = context as Activity
    val prefs = remember { Prefs(context) }
    var name by remember { mutableStateOf(prefs.deviceName) }
    var relay by remember { mutableStateOf(prefs.relay) }
    var copyAuto by remember { mutableStateOf(prefs.copyAutomatically) }
    var images by remember { mutableStateOf(prefs.imagesToo) }
    var boot by remember { mutableStateOf(prefs.startAtBoot) }
    var editName by rememberSaveable { mutableStateOf(false) }
    var editRelay by rememberSaveable { mutableStateOf(false) }
    var showKey by rememberSaveable { mutableStateOf(false) }

    Screen(stringResource(R.string.settings), onBack = null) {
        SectionLabel(stringResource(R.string.this_phone))
        Card(padding = Tokens.Space.none) {
            LinkRow(stringResource(R.string.device_name), value = name) { editName = true }
            Hairline()
            LinkRow(stringResource(R.string.relay), detail = stringResource(R.string.relay_detail), value = Protocol.relayHost(relay)) { editRelay = true }
        }
        Spacer(Modifier.height(Tokens.Space.xxl))

        SectionLabel(stringResource(R.string.from_your_mac))
        Card(padding = Tokens.Space.none) {
            ToggleRow(stringResource(R.string.copy_automatically), stringResource(R.string.copy_automatically_detail), copyAuto) {
                copyAuto = it; prefs.copyAutomatically = it
            }
            Hairline()
            ToggleRow(stringResource(R.string.images_too), stringResource(R.string.images_too_detail), images) {
                images = it; prefs.imagesToo = it
            }
        }
        Spacer(Modifier.height(Tokens.Space.xxl))

        SectionLabel(stringResource(R.string.background))
        Card(padding = Tokens.Space.none) {
            ToggleRow(stringResource(R.string.start_at_boot), stringResource(R.string.start_at_boot_detail), boot) {
                boot = it; prefs.startAtBoot = it; BootReceiver.apply(context, it)
            }
            Hairline()
            SetupRows(permissions = false)
            Hairline()
            LinkRow(stringResource(R.string.permissions), detail = stringResource(R.string.permissions_detail)) { go(Page.Permissions) }
        }
        Spacer(Modifier.height(Tokens.Space.xxl))

        SectionLabel(stringResource(R.string.your_key))
        Card(padding = Tokens.Space.none) {
            LinkRow(stringResource(R.string.show_key), glyph = G.Key) { showKey = true }
            Hairline()
            LinkRow(stringResource(R.string.print_kit), detail = stringResource(R.string.print_kit_detail), glyph = G.File) {
                val s = Vault.secret(context) ?: return@LinkRow
                val words = Key.words(context, s)
                s.fill(0)
                printKit(activity, words)
                prefs.keySaved = true
            }
        }
        Spacer(Modifier.height(Tokens.Space.xxl))

        Card(padding = Tokens.Space.none) {
            LinkRow(stringResource(R.string.about), glyph = G.Info) { go(Page.About) }
        }
    }

    if (editName) {
        var v by rememberSaveable { mutableStateOf(name) }
        CardDialog(stringResource(R.string.device_name), stringResource(R.string.device_name_body), onDismiss = { editName = false }) {
            Field(v, { v = it.take(Protocol.DEVICE_NAME_MAX) }, stringResource(R.string.device_name))
            Spacer(Modifier.height(Tokens.Space.xl))
            DialogButtons(stringResource(R.string.cancel), stringResource(R.string.save), enabled = v.isNotBlank(), onCancel = { editName = false }) {
                prefs.deviceName = v
                name = prefs.deviceName
                editName = false
                ClipService.start(context, ClipService.ACTION_HELLO)
            }
        }
    }

    if (editRelay) {
        var v by rememberSaveable { mutableStateOf(relay) }
        val ok = Protocol.relayAllowed(v, BuildConfig.ALLOW_LOCAL_HTTP)
        CardDialog(stringResource(R.string.relay), stringResource(R.string.relay_body), onDismiss = { editRelay = false }) {
            Field(v, { v = it.trim() }, stringResource(R.string.relay), keyboard = androidx.compose.ui.text.input.KeyboardType.Uri)
            Spacer(Modifier.height(Tokens.Space.s))
            if (v.isNotBlank() && !ok) Footnote(stringResource(R.string.relay_refused), color = Tokens.colors.danger)
            Spacer(Modifier.height(Tokens.Space.m))
            Capsule(stringResource(R.string.relay_default)) { v = BuildConfig.DEFAULT_RELAY }
            Spacer(Modifier.height(Tokens.Space.xl))
            DialogButtons(stringResource(R.string.cancel), stringResource(R.string.save), enabled = ok, onCancel = { editRelay = false }) {
                prefs.relay = v
                prefs.relayCheckedAt = 0L
                prefs.relayNotice = null
                Status.relayNotice.value = null
                relay = prefs.relay
                editRelay = false
                ClipService.start(context, ClipService.ACTION_RECONNECT)
            }
        }
    }

    if (showKey) {
        LaunchedEffect(Unit) {
            showKey = false
            if (Key.canLock(context)) Key.unlock(activity) { go(Page.Key) } else go(Page.Key)
        }
    }
}

// ---------------------------------------------------------------------
// Show my key: behind the lock screen, hidden from screenshots, gone after 60 s
// ---------------------------------------------------------------------

@Composable
fun KeyScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val activity = context as Activity
    val prefs = remember { Prefs(context) }
    val needsConfirm = remember { !Key.canLock(context) }
    var confirmed by rememberSaveable { mutableStateOf(!needsConfirm) }
    val secret = remember { Vault.secret(context) }
    val words = remember { secret?.let { Key.words(context, it) } ?: emptyList() }
    val code = remember { secret?.let { Crypto.toQr(it, prefs.relay, BuildConfig.DEFAULT_RELAY) }.also { secret?.fill(0) } }
    val window = activity.window
    DisposableEffect(Unit) {
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
    LaunchedEffect(confirmed) {
        if (confirmed) {
            delay(Tokens.Motion.KEY_MS)
            onBack()
        }
    }
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val view = LocalView.current
    val note = remember { Note() }

    Screen(stringResource(R.string.your_key), onBack = onBack) {
        if (!confirmed) {
            Card {
                Line(stringResource(R.string.key_confirm_body))
                Spacer(Modifier.height(Tokens.Space.xl))
                PrimaryButton(stringResource(R.string.show_key)) { confirmed = true }
            }
            return@Screen
        }
        Card {
            val dark = Tokens.colors.text.toArgb()
            val light = Tokens.colors.card.toArgb()
            val qr = remember(code, dark, light) { code?.let { Key.qr(it, 640, dark, light).asImageBitmap() } }
            if (qr != null) {
                val qrLabel = stringResource(R.string.key_qr)
                Image(
                    qr, qrLabel, Modifier.size(Tokens.Size.qr).align(Alignment.CenterHorizontally).semantics { contentDescription = qrLabel },
                    filterQuality = FilterQuality.None,
                )
                Spacer(Modifier.height(Tokens.Space.xl))
            }
            words.chunked(2).forEachIndexed { row, pair ->
                Row(Modifier.fillMaxWidth().padding(vertical = Tokens.Space.xs)) {
                    pair.forEachIndexed { col, w ->
                        Row(Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                "${row * 2 + col + 1}".padStart(2), fontFamily = FontFamily.Monospace, fontSize = Tokens.Type.footnote,
                                color = Tokens.colors.secondaryText,
                            )
                            Spacer(Modifier.width(Tokens.Space.s))
                            Text(w, fontFamily = FontFamily.Monospace, fontSize = Tokens.Type.mono, color = Tokens.colors.text, fontWeight = FontWeight.Medium)
                        }
                    }
                }
            }
        }
        Spacer(Modifier.height(Tokens.Space.l))
        Footnote(stringResource(R.string.key_body), Modifier.padding(horizontal = Tokens.Space.xs))
        Spacer(Modifier.height(Tokens.Space.s))
        Footnote(stringResource(R.string.key_truth), Modifier.padding(horizontal = Tokens.Space.xs))
        Spacer(Modifier.height(Tokens.Space.xxl))
        if (Key.passwordManagerAvailable) {
            PrimaryButton(stringResource(R.string.save_password_manager)) {
                scope.launch {
                    when (Key.save(activity, words)) {
                        Key.Saved.Yes -> {
                            prefs.keySaved = true
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
        }
        SecondaryButton(stringResource(R.string.print_kit)) { printKit(activity, words); prefs.keySaved = true }
        NoteLine(note)
        Spacer(Modifier.height(Tokens.Space.m))
        Footnote(stringResource(R.string.key_hides), Modifier.fillMaxWidth(), align = TextAlign.Center)
    }
}
