package dev.sidali.clipway

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.widget.Toast
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.windowInsetsTopHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.window.Dialog
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/** A sub screen: back button, large title, scrolling content, status bar tinted like the page. */
@Composable
fun Screen(title: String, onBack: (() -> Unit)?, content: @Composable ColumnScope.() -> Unit) {
    Box(Modifier.fillMaxSize().background(Tokens.colors.page)) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                .windowInsetsPadding(WindowInsets.systemBars).padding(horizontal = Tokens.Space.l),
        ) {
            Column(Modifier.widthIn(max = Tokens.Size.maxWidth).align(Alignment.CenterHorizontally)) {
                Spacer(Modifier.height(Tokens.Space.s))
                if (onBack != null) BackButton(onBack) else Spacer(Modifier.height(Tokens.Size.iconButton))
                Spacer(Modifier.height(Tokens.Space.m))
                LargeTitle(title)
                Spacer(Modifier.height(Tokens.Space.xxl))
                content()
                Spacer(Modifier.height(Tokens.Space.xxxl))
            }
        }
        StatusBarScrim()
    }
}

@Composable
fun StatusBarScrim() {
    Box(Modifier.fillMaxWidth().windowInsetsTopHeight(WindowInsets.statusBars).background(Tokens.colors.page.copy(alpha = 0.94f)))
}

@Composable
fun BackButton(onBack: () -> Unit) {
    val view = LocalView.current
    val back = stringResource(R.string.back)
    Box(
        Modifier.size(Tokens.Size.iconButton).pressable(back) { view.tick(); onBack() }.clip(CircleShape).background(Tokens.colors.raised)
            .semantics { contentDescription = back },
        contentAlignment = Alignment.Center,
    ) { Glyph(G.Chevron, Tokens.colors.text, Modifier.size(Tokens.Size.glyphSmall).rotate(90f)) }
}

@Composable
fun LargeTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text, fontSize = Tokens.Type.largeTitle, fontWeight = FontWeight.Bold, letterSpacing = Tokens.Type.largeTitleTracking,
        fontFamily = Tokens.Fonts.display,
        lineHeight = Tokens.Type.largeTitleLine, color = Tokens.colors.text,
        modifier = modifier.padding(start = Tokens.Space.xs).semantics { heading() },
    )
}

@Composable
fun Line(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = Tokens.colors.text,
    size: TextUnit = Tokens.Type.body,
    line: TextUnit = Tokens.Type.bodyLine,
    weight: FontWeight? = null,
    align: TextAlign? = null,
) {
    Text(text, fontSize = size, lineHeight = line, color = color, fontWeight = weight, textAlign = align, modifier = modifier)
}

@Composable
fun Secondary(text: String, modifier: Modifier = Modifier, align: TextAlign? = null) =
    Line(text, modifier, Tokens.colors.secondaryText, Tokens.Type.callout, Tokens.Type.calloutLine, align = align)

@Composable
fun Footnote(text: String, modifier: Modifier = Modifier, color: Color = Tokens.colors.secondaryText, align: TextAlign? = null) =
    Line(text, modifier, color, Tokens.Type.footnote, Tokens.Type.footnoteLine, align = align)

@Composable
fun Hairline(inset: Boolean = true) {
    Box(
        Modifier.fillMaxWidth().padding(start = if (inset) Tokens.gutter else Tokens.Space.none).height(Tokens.Size.hairline)
            .background(Tokens.colors.hairline.copy(alpha = 0.6f)),
    )
}

/** A tappable row inside a card: title, optional detail, chevron when it leads somewhere. */
@Composable
fun LinkRow(
    title: String,
    detail: String? = null,
    color: Color = Tokens.colors.text,
    chevron: Boolean = true,
    glyph: G? = null,
    value: String? = null,
    onClick: () -> Unit,
) {
    val view = LocalView.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = Tokens.Size.row).pressable(title) { view.tick(); onClick() }
            .padding(horizontal = Tokens.gutter, vertical = Tokens.Space.m),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (glyph != null) {
            Glyph(glyph, if (color == Tokens.colors.text) Tokens.colors.accent else color, Modifier.size(Tokens.Size.glyph))
            Spacer(Modifier.width(Tokens.Space.m))
        }
        Column(Modifier.weight(1f)) {
            Line(title, color = color)
            if (detail != null) Footnote(detail)
        }
        if (value != null) {
            Spacer(Modifier.width(Tokens.Space.s))
            Line(value, color = Tokens.colors.secondaryText, size = Tokens.Type.callout, line = Tokens.Type.calloutLine)
        }
        if (chevron) {
            Spacer(Modifier.width(Tokens.Space.s))
            Glyph(G.Chevron, Tokens.colors.secondaryText.copy(alpha = 0.7f), Modifier.size(Tokens.Size.glyphSmall).rotate(-90f))
        }
    }
}

/** A row with a switch. The whole row toggles it. */
@Composable
fun ToggleRow(title: String, detail: String?, checked: Boolean, onChange: (Boolean) -> Unit) {
    val view = LocalView.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = Tokens.Size.row).pressable(title) { view.tick(); onChange(!checked) }
            .padding(start = Tokens.gutter, end = Tokens.Space.l, top = Tokens.Space.s, bottom = Tokens.Space.s),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Line(title)
            if (detail != null) Footnote(detail)
        }
        Spacer(Modifier.width(Tokens.Space.m))
        GreenSwitch(checked, onChange)
    }
}

@Composable
fun Bullet(text: String) {
    Row(verticalAlignment = Alignment.Top) {
        Box(Modifier.padding(top = Tokens.Space.s + Tokens.Space.xxs).size(Tokens.Size.bullet).clip(CircleShape).background(Tokens.colors.accent))
        Spacer(Modifier.width(Tokens.Space.m))
        Line(text, Modifier.weight(1f), size = Tokens.Type.callout, line = Tokens.Type.calloutLine)
    }
}

/** A quiet action under the buttons: text only, in the accent color. */
@Composable
fun TextAction(text: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val view = LocalView.current
    Box(
        modifier.fillMaxWidth().heightIn(min = Tokens.Size.touch).pressable(text) { view.tick(); onClick() },
        contentAlignment = Alignment.Center,
    ) { Line(text, color = Tokens.colors.accent, weight = FontWeight.SemiBold) }
}

/** A card dialog: title, text, then the actions the caller adds. */
@Composable
fun CardDialog(title: String, body: String?, onDismiss: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    Dialog(onDismissRequest = onDismiss) {
        Card {
            Text(
                title, fontSize = Tokens.Type.title, lineHeight = Tokens.Type.titleLine, fontWeight = FontWeight.Bold,
                fontFamily = Tokens.Fonts.display, letterSpacing = Tokens.Type.titleTracking, color = Tokens.colors.text,
            )
            if (body != null) {
                Spacer(Modifier.height(Tokens.Space.m))
                Line(body, size = Tokens.Type.callout, line = Tokens.Type.calloutLine)
            }
            Spacer(Modifier.height(Tokens.Space.xl))
            content()
        }
    }
}

/** Two buttons side by side: cancel and the action. */
@Composable
fun DialogButtons(cancel: String, action: String, enabled: Boolean = true, danger: Boolean = false, onCancel: () -> Unit, onAction: () -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(Tokens.Space.m)) {
        SecondaryButton(cancel, Modifier.weight(1f), onClick = onCancel)
        if (danger) {
            val view = LocalView.current
            Box(
                Modifier.weight(1f).height(Tokens.buttonHeight)
                    .then(if (enabled) Modifier.pressable { view.confirm(); onAction() } else Modifier)
                    .clip(RoundedCornerShape(Tokens.buttonRadius))
                    .background(if (enabled) Tokens.colors.danger else Tokens.colors.raised),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    action, fontSize = Tokens.Type.headline, fontWeight = FontWeight.SemiBold,
                    color = if (enabled) Tokens.colors.onDanger else Tokens.colors.secondaryText,
                )
            }
        } else {
            PrimaryButton(action, Modifier.weight(1f), enabled = enabled, onClick = onAction)
        }
    }
}

/** A one-line text field in the app's style. */
@Composable
fun Field(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    mono: Boolean = false,
    caps: Boolean = false,
    keyboard: KeyboardType = KeyboardType.Text,
    focus: Boolean = true,
) {
    val requester = remember { FocusRequester() }
    if (focus) LaunchedEffect(Unit) { requester.requestFocus() }
    BasicTextField(
        value, onChange, singleLine = true,
        textStyle = TextStyle(
            fontSize = Tokens.Type.body, color = Tokens.colors.text,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
            letterSpacing = if (mono) Tokens.Type.monoTracking else androidx.compose.ui.unit.TextUnit.Unspecified,
        ),
        cursorBrush = SolidColor(Tokens.colors.accent),
        keyboardOptions = KeyboardOptions(
            capitalization = when {
                caps -> KeyboardCapitalization.Characters
                keyboard == KeyboardType.Uri -> KeyboardCapitalization.None
                else -> KeyboardCapitalization.Sentences
            },
            autoCorrectEnabled = false, keyboardType = keyboard, imeAction = ImeAction.Done,
        ),
        modifier = modifier.fillMaxWidth().focusRequester(requester).clip(RoundedCornerShape(Tokens.fieldRadius))
            .background(Tokens.colors.raised).padding(horizontal = Tokens.Space.l, vertical = Tokens.Space.l)
            .semantics { contentDescription = label },
    )
}

/** A short-lived message that slides under an action. */
class Note {
    var text by mutableStateOf<String?>(null)
    var ok by mutableStateOf(true)
    var at by mutableStateOf(0L)

    fun show(t: String, good: Boolean = true) {
        text = t
        ok = good
        at = System.nanoTime()
    }
}

@Composable
fun NoteLine(note: Note) {
    val t = note.text
    LaunchedEffect(note.at) {
        if (t != null) {
            kotlinx.coroutines.delay(Tokens.Motion.NOTE_MS)
            note.text = null
        }
    }
    androidx.compose.animation.AnimatedVisibility(t != null) {
        Row(Modifier.fillMaxWidth().padding(top = Tokens.Space.m), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
            Glyph(if (note.ok) G.Check else G.Info, if (note.ok) Tokens.colors.success else Tokens.colors.secondaryText, Modifier.size(Tokens.Size.glyphSmall))
            Spacer(Modifier.width(Tokens.Space.s))
            Line(t ?: "", color = Tokens.colors.text, size = Tokens.Type.callout, line = Tokens.Type.calloutLine)
        }
    }
}

/** Opens a link or the mail app: always a tap from the user, and the network is the browser's, not Clipway's. */
fun openLink(c: Context, uri: String, subject: String? = null) {
    val i = if (uri.startsWith("mailto:")) {
        Intent(Intent.ACTION_SENDTO, Uri.parse(uri)).apply { subject?.let { putExtra(Intent.EXTRA_SUBJECT, it) } }
    } else {
        Intent(Intent.ACTION_VIEW, Uri.parse(uri))
    }
    try {
        c.startActivity(i)
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(c, c.getString(R.string.no_app_for_link, uri.removePrefix("mailto:")), Toast.LENGTH_LONG).show()
    }
}

/** Opens a system settings screen, falling back to the app's page. */
fun openSettings(c: Context, intent: Intent) {
    try {
        c.startActivity(intent)
    } catch (_: Exception) {
        try {
            c.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + c.packageName)))
        } catch (_: Exception) {
        }
    }
}

/** "Just now", "3 min ago", "2 h ago", then "24 Oct, 14:05". English only, like the rest of the app. */
fun ago(c: Context, ts: Long, now: Long = System.currentTimeMillis()): String {
    val d = (now - ts).coerceAtLeast(0)
    val min = (d / 60_000).toInt()
    val h = (d / 3_600_000).toInt()
    return when {
        min < 1 -> c.getString(R.string.just_now)
        min < 60 -> c.resources.getQuantityString(R.plurals.minutes_ago, min, min)
        h < 24 -> c.resources.getQuantityString(R.plurals.hours_ago, h, h)
        else -> DateTimeFormatter.ofPattern("d MMM, HH:mm", Locale.ENGLISH).format(Instant.ofEpochMilli(ts).atZone(ZoneId.systemDefault()))
    }
}

/** "1.4 MB", "820 KB": decimal units, as file managers show them. */
fun sizeText(bytes: Long): String = when {
    bytes >= 1_000_000 -> String.format(Locale.ENGLISH, "%.1f MB", bytes / 1_000_000.0)
    bytes >= 1_000 -> String.format(Locale.ENGLISH, "%d KB", bytes / 1_000)
    else -> String.format(Locale.ENGLISH, "%d bytes", bytes)
}

/** A screen-wide state that survives rotation and process death. */
@Composable
fun <T : Any> saved(init: () -> T) = rememberSaveable { mutableStateOf(init()) }
