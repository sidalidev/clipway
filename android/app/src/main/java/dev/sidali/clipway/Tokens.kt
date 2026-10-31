package dev.sidali.clipway

import android.os.Build
import android.view.HapticFeedbackConstants
import android.view.View
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.platform.LocalView
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp

/* ---------- tokens: the one place for colors, sizes, type and springs ---------- */
object Tokens {
    val cardRadius = 24.dp
    val buttonRadius = 14.dp
    val fieldRadius = 12.dp
    val buttonHeight = 54.dp
    val gutter = 20.dp
    val pressedScale = 0.97f

    /** The 4 dp grid. Screens use these, never a raw .dp (CI checks it). */
    object Space {
        val none = 0.dp
        val xxs = 2.dp
        val xs = 4.dp
        val s = 8.dp
        val m = 12.dp
        val l = 16.dp
        val xl = 20.dp
        val xxl = 24.dp
        val xxxl = 32.dp
        val huge = 48.dp
    }

    /** Fixed sizes of things on screen. */
    object Size {
        val hairline = 1.dp
        val bullet = 6.dp
        val dot = 10.dp
        val glyphSmall = 18.dp
        val glyph = 22.dp
        val glyphLarge = 28.dp
        val iconButton = 40.dp
        val badge = 44.dp
        val touch = 48.dp
        val row = 54.dp
        val thumb = 56.dp
        val tabBar = 64.dp
        val status = 72.dp
        val wordsField = 120.dp
        val hero = 220.dp
        val qr = 232.dp
        val scanner = 320.dp
        val maxWidth = 640.dp
        /** Pair nearby: the searching rings, one digit of the code, the card that holds either. */
        val radar = 168.dp
        val radarCore = 64.dp
        val digitWidth = 60.dp
        val digitHeight = 80.dp
        val nearbyCard = 232.dp
    }

    /** Type scale: large and tight. Screens use these, never a raw .sp (CI checks it). */
    object Type {
        val largeTitle = 34.sp
        val largeTitleLine = 40.sp
        /** Titles in Bricolage Grotesque, tracked -2 %. */
        val largeTitleTracking = (-0.02).em
        val titleTracking = (-0.02).em
        val title = 22.sp
        val titleLine = 28.sp
        val headline = 17.sp
        val body = 17.sp
        val bodyLine = 23.sp
        val callout = 15.sp
        val calloutLine = 20.sp
        val footnote = 13.sp
        val footnoteLine = 18.sp
        val caption = 12.sp
        val captionTracking = 0.6.sp
        val tab = 11.sp
        val mono = 16.sp
        val monoTracking = 1.sp
        /** The 4-digit code of Pair nearby, one digit per tile. */
        val code = 44.sp
        val codeLine = 52.sp
    }

    /** Durations and springs. */
    object Motion {
        const val PAGE_MS = 320
        const val FADE_MS = 180
        const val HERO_MS = 4800
        /** How long Undo stays. */
        const val UNDO_MS = 5_000L
        /** How long a short message stays under a button. */
        const val NOTE_MS = 3_000L
        /** The key hides itself after this long. */
        const val KEY_MS = 60_000L
        /** One wave of the Pair nearby rings. */
        const val RADAR_MS = 2_000
        const val PRESS_DAMPING = 0.55f
        const val PRESS_STIFFNESS = 900f
    }

    /** Ink of the printed rescue kit (paper, not screen: always dark on white). */
    object Print {
        const val ink = 0xFF111111.toInt()
        const val gray = 0xFF5F5F66.toInt()
        const val paper = 0xFFFFFFFF.toInt()
    }

    /** The roles the screens use, from the app's own palette (Lac), light or dark. */
    val colors: Roles
        @Composable @ReadOnlyComposable get() = LocalRoles.current

    /**
     * Type: titles in Bricolage Grotesque 700, text in Figtree. Both SIL Open Font License, shipped
     * in the app (res/font, licenses in assets/licenses), variable fonts set to the weight asked.
     */
    @OptIn(ExperimentalTextApi::class)
    object Fonts {
        val display = FontFamily(
            Font(R.font.bricolage_grotesque, FontWeight.Bold, variationSettings = FontVariation.Settings(FontVariation.weight(700), FontVariation.Setting("opsz", 32f))),
            Font(R.font.bricolage_grotesque, FontWeight.SemiBold, variationSettings = FontVariation.Settings(FontVariation.weight(600), FontVariation.Setting("opsz", 24f))),
        )
        val text = FontFamily(
            Font(R.font.figtree, FontWeight.Normal, variationSettings = FontVariation.Settings(FontVariation.weight(400))),
            Font(R.font.figtree, FontWeight.Medium, variationSettings = FontVariation.Settings(FontVariation.weight(500))),
            Font(R.font.figtree, FontWeight.SemiBold, variationSettings = FontVariation.Settings(FontVariation.weight(600))),
            Font(R.font.figtree, FontWeight.Bold, variationSettings = FontVariation.Settings(FontVariation.weight(700))),
        )
    }
}

/**
 * What each color is for. Screens never pick a raw color: they ask for a role, and the role comes
 * from Clipway's palette ([Lac]): the color of its icon, the same on every phone, light and dark.
 */
@Immutable
class Roles(
    /** Page behind the cards. */
    val page: Color,
    /** Cards, action tiles. */
    val card: Color,
    /** One step above a card: a lifted row, the close button, an icon placeholder. */
    val raised: Color,
    val hairline: Color,
    val text: Color,
    val secondaryText: Color,
    /** The one filled action per screen, and accent glyphs. */
    val accent: Color,
    val onAccent: Color,
    /** Tinted secondary actions and capsules. */
    val tonal: Color,
    val onTonal: Color,
    /** Badges and placeholders. */
    val badge: Color,
    val onBadge: Color,
    /** A third color, for illustrations: the palette's tertiary, so two devices read apart. */
    val target: Color,
    val onTarget: Color,
    /** Switches. Green stays green, nudged toward the palette so it never clashes. */
    val success: Color,
    val onSuccess: Color,
    /** Destructive actions (Erase everything): the palette's error color. */
    val danger: Color,
    val onDanger: Color,
    val scrim: Color,
)

private val LocalRoles = staticCompositionLocalOf<Roles> { error("ClipwayTheme is missing") }

/**
 * The charter "Miel du Champsaur": every app of the family has its own color, the same in its icon
 * and in the app. Clipway is Lac (#2E7FA1, the icon). Filled controls in light mode use the same lac
 * deepened by 6 % (#2B7797) so cream text on it passes WCAG AA (4.69:1); dark mode uses light lac
 * (#5BB0D3) with ink text (6.54:1). Every pair below was checked by calculation (docs/DESIGN.md).
 * These are the only literal colors in the app.
 */
private object Lac {
    // The icon's lac, #2E7FA1, is drawn in res/drawable/ic_bg.xml; the app deepens it (see above).
    private val honey = Color(0xFFE9A23B)
    private val ink = Color(0xFF1F2A22)
    private val cream = Color(0xFFFBF7EF)

    val light = lightColorScheme(
        primary = Color(0xFF2B7797), onPrimary = cream,
        primaryContainer = Color(0xFFD5E9F2), onPrimaryContainer = Color(0xFF123F54),
        inversePrimary = Color(0xFF5BB0D3),
        secondary = Color(0xFF4A5A4F), onSecondary = cream,
        secondaryContainer = Color(0xFFDEE6E4), onSecondaryContainer = Color(0xFF1A566F),
        tertiary = honey, onTertiary = ink,
        tertiaryContainer = Color(0xFFF4E3C3), onTertiaryContainer = Color(0xFF6B4A12),
        error = Color(0xFFB3261E), onError = Color(0xFFFFFFFF),
        errorContainer = Color(0xFFF9DEDC), onErrorContainer = Color(0xFF410E0B),
        background = cream, onBackground = ink,
        surface = cream, onSurface = ink,
        surfaceVariant = Color(0xFFECE5D8), onSurfaceVariant = Color(0xFF4A5A4F),
        surfaceTint = Color(0xFF2B7797),
        inverseSurface = ink, inverseOnSurface = cream,
        outline = Color(0xFF7A867D), outlineVariant = Color(0xFFE4DCCC), scrim = Color(0xFF000000),
        surfaceBright = Color(0xFFFFFDF9), surfaceDim = Color(0xFFE8E1D4),
        surfaceContainerLowest = Color(0xFFFFFDF9), surfaceContainerLow = Color(0xFFF7F2E8),
        surfaceContainer = Color(0xFFF2ECE0), surfaceContainerHigh = Color(0xFFECE5D8),
        surfaceContainerHighest = Color(0xFFE6DFD1),
    )
    val dark = darkColorScheme(
        primary = Color(0xFF5BB0D3), onPrimary = Color(0xFF0E2430),
        primaryContainer = Color(0xFF1F4A5C), onPrimaryContainer = Color(0xFFD4EEF8),
        inversePrimary = Color(0xFF2B7797),
        secondary = Color(0xFF9FB3A8), onSecondary = Color(0xFF12201A),
        secondaryContainer = Color(0xFF274545), onSecondaryContainer = Color(0xFFBFE3F2),
        tertiary = honey, onTertiary = ink,
        tertiaryContainer = Color(0xFF4A3612), onTertiaryContainer = Color(0xFFF4E3C3),
        error = Color(0xFFF2B8B5), onError = Color(0xFF601410),
        errorContainer = Color(0xFF8C1D18), onErrorContainer = Color(0xFFF9DEDC),
        background = Color(0xFF12201A), onBackground = Color(0xFFF3EFE6),
        surface = Color(0xFF12201A), onSurface = Color(0xFFF3EFE6),
        surfaceVariant = Color(0xFF263B32), onSurfaceVariant = Color(0xFF9FB3A8),
        surfaceTint = Color(0xFF5BB0D3),
        inverseSurface = Color(0xFFF3EFE6), inverseOnSurface = ink,
        outline = Color(0xFF6E8378), outlineVariant = Color(0xFF30463B), scrim = Color(0xFF000000),
        surfaceBright = Color(0xFF2C4238), surfaceDim = Color(0xFF12201A),
        surfaceContainerLowest = Color(0xFF0D1813), surfaceContainerLow = Color(0xFF172820),
        surfaceContainer = Color(0xFF1C2E26), surfaceContainerHigh = Color(0xFF263B32),
        surfaceContainerHighest = Color(0xFF30463B),
    )

    /** Switches stay green (a semantic color), dark enough for a white thumb in light mode (5.4:1). */
    val successLight = Color(0xFF1F7A3E)
    val onSuccessLight = Color(0xFFFFFFFF)
    val successDark = Color(0xFF7BD88F)
    val onSuccessDark = Color(0xFF00391A)
}

private fun roles(c: ColorScheme, dark: Boolean, sheet: Boolean) = Roles(
    // Light: cream page under warm white cards. Dark: fir night page, cards one tone up; a sheet sits
    // one step higher than the app, so it reads as a layer over whatever is behind it.
    page = when { !dark -> c.background; sheet -> c.surfaceContainerLow; else -> c.background },
    card = when { !dark -> c.surfaceContainerLowest; sheet -> c.surfaceContainerHigh; else -> c.surfaceContainer },
    raised = if (dark) c.surfaceContainerHighest else c.surfaceContainer,
    hairline = c.outlineVariant,
    text = c.onSurface,
    secondaryText = c.onSurfaceVariant,
    accent = c.primary, onAccent = c.onPrimary,
    tonal = c.secondaryContainer, onTonal = c.onSecondaryContainer,
    badge = c.primaryContainer, onBadge = c.onPrimaryContainer,
    target = c.tertiary, onTarget = c.onTertiary,
    success = if (dark) Lac.successDark else Lac.successLight,
    onSuccess = if (dark) Lac.onSuccessDark else Lac.onSuccessLight,
    danger = c.error, onDanger = c.onError,
    scrim = c.scrim,
)

@Composable
fun ClipwayTheme(sheet: Boolean = false, content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    // Clipway's own colors, the same as its icon: never the wallpaper's.
    val scheme = if (dark) Lac.dark else Lac.light
    val r = remember(scheme, dark, sheet) { roles(scheme, dark, sheet) }
    // Large, tight type: Figtree for text, Bricolage Grotesque for titles. Sizes stay in sp, so the
    // phone's text size setting applies.
    val base = MaterialTheme.typography
    val text = Tokens.Fonts.text
    val display = Tokens.Fonts.display
    val typography = base.copy(
        displayLarge = base.displayLarge.copy(fontFamily = display, fontWeight = FontWeight.Bold, letterSpacing = Tokens.Type.titleTracking),
        displayMedium = base.displayMedium.copy(fontFamily = display, fontWeight = FontWeight.Bold, letterSpacing = Tokens.Type.titleTracking),
        displaySmall = base.displaySmall.copy(fontFamily = display, fontWeight = FontWeight.Bold, letterSpacing = Tokens.Type.titleTracking),
        headlineLarge = base.headlineLarge.copy(fontFamily = display, fontWeight = FontWeight.Bold, letterSpacing = Tokens.Type.titleTracking),
        headlineMedium = base.headlineMedium.copy(fontFamily = display, fontWeight = FontWeight.Bold, letterSpacing = Tokens.Type.titleTracking),
        headlineSmall = base.headlineSmall.copy(fontFamily = display, fontWeight = FontWeight.Bold, letterSpacing = Tokens.Type.titleTracking),
        titleLarge = base.titleLarge.copy(fontFamily = display, fontWeight = FontWeight.Bold, letterSpacing = Tokens.Type.titleTracking),
        titleMedium = base.titleMedium.copy(fontFamily = text),
        titleSmall = base.titleSmall.copy(fontFamily = text),
        bodyLarge = base.bodyLarge.copy(fontFamily = text, letterSpacing = (-0.1).sp),
        bodyMedium = base.bodyMedium.copy(fontFamily = text, letterSpacing = 0.sp),
        bodySmall = base.bodySmall.copy(fontFamily = text, letterSpacing = 0.sp),
        labelLarge = base.labelLarge.copy(fontFamily = text, letterSpacing = 0.sp),
        labelMedium = base.labelMedium.copy(fontFamily = text),
        labelSmall = base.labelSmall.copy(fontFamily = text),
    )
    CompositionLocalProvider(LocalRoles provides r) {
        MaterialTheme(colorScheme = scheme, typography = typography, content = content)
    }
}

/** Haptics always go through the view, so the system "touch feedback" setting is respected. */
fun View.tick() = performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
fun View.confirm() = performHapticFeedback(HapticFeedbackConstants.CONFIRM)
fun View.longPress() = performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
fun View.reject() = performHapticFeedback(HapticFeedbackConstants.REJECT)

/** Apple-like press: shrinks to 0.97 on a spring, no Material ripple. */
fun Modifier.pressable(label: String? = null, role: Role = Role.Button, onClick: () -> Unit): Modifier = composed {
    val src = remember { MutableInteractionSource() }
    val pressed by src.collectIsPressedAsState()
    val s by animateFloatAsState(if (pressed) Tokens.pressedScale else 1f, spring(dampingRatio = Tokens.Motion.PRESS_DAMPING, stiffness = Tokens.Motion.PRESS_STIFFNESS), label = "press")
    this
        .graphicsLayer { scaleX = s; scaleY = s; alpha = if (pressed) 0.85f else 1f }
        .clickable(interactionSource = src, indication = null, role = role, onClickLabel = label, onClick = onClick)
}

@Composable
fun Card(modifier: Modifier = Modifier, padding: Dp = 20.dp, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier.fillMaxWidth().clip(RoundedCornerShape(Tokens.cardRadius)).background(Tokens.colors.card).padding(padding),
        content = content,
    )
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(), fontSize = 12.sp, letterSpacing = 0.6.sp, fontWeight = FontWeight.SemiBold,
        color = Tokens.colors.secondaryText, modifier = modifier.padding(start = 20.dp, bottom = 8.dp).semantics { heading() },
    )
}

/** The one filled action of a screen. Dimmed and inert when [enabled] is false. [confirm]: a confirmation haptic, not a tick. */
@Composable
fun PrimaryButton(text: String, modifier: Modifier = Modifier, enabled: Boolean = true, confirm: Boolean = false, onClick: () -> Unit) {
    val view = LocalView.current
    Box(
        modifier.fillMaxWidth().height(Tokens.buttonHeight)
            .then(if (enabled) Modifier.pressable { if (confirm) view.confirm() else view.tick(); onClick() } else Modifier)
            .clip(RoundedCornerShape(Tokens.buttonRadius))
            .background(if (enabled) Tokens.colors.accent else Tokens.colors.raised),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text, color = if (enabled) Tokens.colors.onAccent else Tokens.colors.secondaryText,
            fontSize = 17.sp, fontWeight = FontWeight.SemiBold,
        )
    }
}

/** Tinted secondary action. [danger] paints it in the semantic red. */
@Composable
fun SecondaryButton(text: String, modifier: Modifier = Modifier, danger: Boolean = false, onClick: () -> Unit) {
    val view = LocalView.current
    Box(
        modifier.fillMaxWidth().height(Tokens.buttonHeight).pressable { view.tick(); onClick() }
            .clip(RoundedCornerShape(Tokens.buttonRadius))
            .background(if (danger) Tokens.colors.danger.copy(alpha = 0.12f) else Tokens.colors.tonal),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text, color = if (danger) Tokens.colors.danger else Tokens.colors.onTonal,
            fontSize = 17.sp, fontWeight = FontWeight.SemiBold,
        )
    }
}

/** Small tinted capsule, for row actions. */
@Composable
fun Capsule(text: String, modifier: Modifier = Modifier, glyph: G? = null, onClick: () -> Unit) {
    val view = LocalView.current
    Row(
        modifier.heightIn(min = 36.dp).pressable(text) { view.tick(); onClick() }.clip(RoundedCornerShape(50)).background(Tokens.colors.tonal)
            .padding(horizontal = 14.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (glyph != null) {
            Glyph(glyph, Tokens.colors.onTonal, Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
        }
        Text(text, color = Tokens.colors.onTonal, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun GreenSwitch(checked: Boolean, onChange: ((Boolean) -> Unit)?) {
    val view = LocalView.current
    Switch(
        // null: the row around it is the control (one TalkBack stop, one haptic).
        checked = checked, onCheckedChange = onChange?.let { f -> { view.tick(); f(it) } },
        colors = SwitchDefaults.colors(
            checkedTrackColor = Tokens.colors.success, checkedThumbColor = Tokens.colors.onSuccess,
            checkedIconColor = Tokens.colors.success, checkedBorderColor = Color.Transparent,
        ),
    )
}

/* ---------- glyphs: drawn, so no icon font or icon library is needed ---------- */
enum class G { Copy, Image, Close, Chevron, Text, File, Check, Home, Clock, Sliders, Send, Mac, Phone, Lock, Key, Camera, Keyboard, Trash, Info, Share, Bluetooth }

@Composable
fun Glyph(g: G, color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier.size(22.dp)) { drawGlyph(g, color) }
}

fun DrawScope.drawGlyph(g: G, color: Color) {
    val u = size.minDimension / 24f
    val st = Stroke(width = 2.1f * u, cap = StrokeCap.Round, join = StrokeJoin.Round)
    fun p(x: Float, y: Float) = Offset(x * u, y * u)
    fun rr(x: Float, y: Float, w: Float, h: Float, r: Float) =
        drawRoundRect(color, p(x, y), Size(w * u, h * u), CornerRadius(r * u), style = st)
    fun line(vararg pts: Float) {
        val path = Path().apply { moveTo(pts[0] * u, pts[1] * u); var i = 2; while (i < pts.size) { lineTo(pts[i] * u, pts[i + 1] * u); i += 2 } }
        drawPath(path, color, style = st)
    }
    fun ring(x: Float, y: Float, r: Float) = drawCircle(color, r * u, p(x, y), style = st)
    when (g) {
        G.Copy -> { rr(8f, 8f, 12f, 13f, 3f); line(5f, 15f, 4f, 15f, 4f, 6f, 4f, 5f, 5f, 4f, 13f, 4f, 15f, 4f, 16f, 5f) }
        G.Image -> { rr(3f, 5f, 18f, 14f, 3f); line(3.5f, 17f, 9f, 11.5f, 13f, 15.5f, 15.5f, 13f, 20.5f, 18f); drawCircle(color, 1.8f * u, p(15.5f, 9.5f)) }
        G.Close -> { line(7f, 7f, 17f, 17f); line(17f, 7f, 7f, 17f) }
        G.Chevron -> line(7f, 9.5f, 12f, 14.5f, 17f, 9.5f)
        G.Text -> { line(5f, 7f, 19f, 7f); line(5f, 12f, 19f, 12f); line(5f, 17f, 14f, 17f) }
        G.File -> { line(14f, 3.5f, 6f, 3.5f, 5f, 4.5f, 5f, 19.5f, 6f, 20.5f, 18f, 20.5f, 19f, 19.5f, 19f, 8.5f, 14f, 3.5f, 14f, 8.5f, 19f, 8.5f) }
        G.Check -> line(6f, 12.5f, 10f, 16.5f, 18f, 8f)
        G.Home -> { line(4f, 11f, 12f, 4f, 20f, 11f); line(6.5f, 9.5f, 6.5f, 20f, 17.5f, 20f, 17.5f, 9.5f); line(10.5f, 20f, 10.5f, 15f, 13.5f, 15f, 13.5f, 20f) }
        G.Clock -> { ring(12f, 12f, 8.5f); line(12f, 7.5f, 12f, 12f, 15f, 14f) }
        G.Sliders -> {
            line(4f, 7f, 20f, 7f); line(4f, 12f, 20f, 12f); line(4f, 17f, 20f, 17f)
            drawCircle(color, 2.4f * u, p(9f, 7f)); drawCircle(color, 2.4f * u, p(15f, 12f)); drawCircle(color, 2.4f * u, p(8f, 17f))
        }
        G.Send -> { line(12f, 19f, 12f, 5f); line(6.5f, 10.5f, 12f, 5f, 17.5f, 10.5f) }
        G.Mac -> { rr(5f, 5f, 14f, 10f, 1.8f); line(2.5f, 18.5f, 21.5f, 18.5f) }
        G.Phone -> { rr(7f, 3f, 10f, 18f, 2.5f); line(11f, 18f, 13f, 18f) }
        G.Lock -> { rr(5f, 10.5f, 14f, 10f, 2.5f); line(8f, 10.5f, 8f, 7.5f, 9.5f, 4.8f, 12f, 4f, 14.5f, 4.8f, 16f, 7.5f, 16f, 10.5f) }
        G.Key -> { ring(8f, 14f, 4f); line(11f, 11f, 19.5f, 2.5f); line(16.5f, 5.5f, 19f, 8f); line(14f, 8f, 16f, 10f) }
        G.Camera -> { rr(3f, 7f, 18f, 13f, 3f); line(8.5f, 7f, 10f, 4.5f, 14f, 4.5f, 15.5f, 7f); ring(12f, 13.5f, 3.4f) }
        G.Keyboard -> {
            rr(2.5f, 6f, 19f, 12f, 2.5f)
            for (x in listOf(6.5f, 10f, 13.5f, 17f)) drawCircle(color, 1.1f * u, p(x, 10f))
            line(8f, 14.5f, 16f, 14.5f)
        }
        G.Trash -> { line(4.5f, 6.5f, 19.5f, 6.5f); line(9.5f, 6.5f, 9.5f, 4f, 14.5f, 4f, 14.5f, 6.5f); line(6.5f, 6.5f, 7.5f, 20f, 16.5f, 20f, 17.5f, 6.5f) }
        G.Info -> { ring(12f, 12f, 8.5f); line(12f, 11f, 12f, 16.5f); drawCircle(color, 1.3f * u, p(12f, 7.8f)) }
        G.Share -> { line(12f, 14f, 12f, 3.5f); line(8f, 7.5f, 12f, 3.5f, 16f, 7.5f); line(8f, 10.5f, 5.5f, 10.5f, 5.5f, 20f, 18.5f, 20f, 18.5f, 10.5f, 16f, 10.5f) }
        G.Bluetooth -> line(7f, 7.5f, 16.5f, 16f, 12f, 20.5f, 12f, 3.5f, 16.5f, 8f, 7f, 16.5f)
    }
}
