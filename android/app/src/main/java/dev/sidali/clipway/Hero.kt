package dev.sidali.clipway

import android.provider.Settings
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import kotlin.math.sin

/**
 * What Clipway does, in one loop: a copied snippet leaves the Mac, passes the lock (the relay only
 * sees ciphertext) and lands on the phone, which shows a check; then one goes back the other way.
 * Colors come from the phone's palette. Still when the system turns animations off.
 */
@Composable
fun Hero(modifier: Modifier) {
    val context = LocalContext.current
    val still = remember {
        Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f
    }
    val anim by rememberInfiniteTransition(label = "hero").animateFloat(
        0f, 1f, infiniteRepeatable(tween(Tokens.Motion.HERO_MS, easing = LinearEasing)), label = "t",
    )
    val t = if (still) 0.3f else anim
    val c = Tokens.colors
    val measurer = rememberTextMeasurer()
    val labels = listOf(stringResource(R.string.hero_mac), stringResource(R.string.hero_relay), stringResource(R.string.hero_phone))
    val description = stringResource(R.string.hero_description)
    val labelStyle = TextStyle(fontSize = Tokens.Type.footnote, fontWeight = FontWeight.SemiBold, color = c.secondaryText)

    Canvas(modifier.semantics { contentDescription = description }) {
        val u = size.width / 340f
        val cy = size.height / 2 - 14 * u
        val xs = listOf(size.width * 0.17f, size.width * 0.5f, size.width * 0.83f)
        fun seg(a: Float, b: Float) = ((t - a) / (b - a)).coerceIn(0f, 1f)
        fun bump(a: Float, b: Float) = sin(seg(a, b) * Math.PI).toFloat()

        val go = FastOutSlowInEasing.transform(seg(0.08f, 0.40f))
        val back = FastOutSlowInEasing.transform(seg(0.56f, 0.88f))
        val phonePulse = bump(0.38f, 0.52f)
        val macPulse = bump(0.86f, 1f)
        val phoneCheck = seg(0.40f, 0.46f) - seg(0.54f, 0.58f)
        val macCheck = seg(0.88f, 0.93f) - seg(0.97f, 1f)
        val lockGlow = bump(0.18f, 0.30f) + bump(0.66f, 0.78f)

        // dotted path
        val dash = PathEffect.dashPathEffect(floatArrayOf(2 * u, 7 * u), 0f)
        for (i in 0..1) drawLine(
            c.secondaryText.copy(alpha = 0.45f), Offset(xs[i] + 44 * u, cy), Offset(xs[i + 1] - 30 * u, cy),
            strokeWidth = 2.5f * u, cap = StrokeCap.Round, pathEffect = dash,
        )

        // the Mac
        translate(xs[0], cy) {
            scale(1f + macPulse * 0.06f, pivot = Offset.Zero) {
                drawRoundRect(c.accent, Offset(-38 * u, -30 * u), Size(76 * u, 50 * u), CornerRadius(8 * u))
                drawRoundRect(c.accent, Offset(-46 * u, 22 * u), Size(92 * u, 7 * u), CornerRadius(3.5f * u))
                if (macCheck > 0f) {
                    drawLine(c.onAccent.copy(alpha = macCheck), Offset(-10 * u, -6 * u), Offset(-3 * u, 1 * u), 4 * u, StrokeCap.Round)
                    drawLine(c.onAccent.copy(alpha = macCheck), Offset(-3 * u, 1 * u), Offset(11 * u, -13 * u), 4 * u, StrokeCap.Round)
                } else {
                    for (r in 0..2) drawRoundRect(
                        c.onAccent.copy(alpha = 0.75f - r * 0.2f), Offset(-26 * u, (-20 + r * 11) * u),
                        Size((if (r == 1) 40 else 52) * u, 6 * u), CornerRadius(3 * u),
                    )
                }
            }
        }

        // the relay: a lock, because it only ever sees ciphertext
        translate(xs[1], cy) {
            scale(1f + lockGlow * 0.08f, pivot = Offset.Zero) {
                drawCircle(c.card, 28 * u, Offset.Zero)
                drawCircle(c.hairline, 28 * u, Offset.Zero, style = Stroke(1.2f * u))
                drawRoundRect(c.secondaryText, Offset(-10 * u, -3 * u), Size(20 * u, 15 * u), CornerRadius(3.5f * u))
                drawArc(
                    c.secondaryText, 180f, 180f, false, Offset(-7 * u, -13 * u), Size(14 * u, 16 * u),
                    style = Stroke(3 * u, cap = StrokeCap.Round),
                )
            }
        }

        // the phone
        translate(xs[2], cy) {
            scale(1f + phonePulse * 0.06f, pivot = Offset.Zero) {
                drawRoundRect(c.target, Offset(-24 * u, -40 * u), Size(48 * u, 80 * u), CornerRadius(10 * u))
                drawRoundRect(c.onTarget.copy(alpha = 0.5f), Offset(-6 * u, 31 * u), Size(12 * u, 3 * u), CornerRadius(1.5f * u))
                if (phoneCheck > 0f) {
                    drawLine(c.onTarget.copy(alpha = phoneCheck), Offset(-9 * u, -2 * u), Offset(-2 * u, 5 * u), 4 * u, StrokeCap.Round)
                    drawLine(c.onTarget.copy(alpha = phoneCheck), Offset(-2 * u, 5 * u), Offset(10 * u, -8 * u), 4 * u, StrokeCap.Round)
                } else {
                    for (r in 0..2) drawRoundRect(
                        c.onTarget.copy(alpha = 0.7f - r * 0.2f), Offset(-15 * u, (-24 + r * 11) * u),
                        Size((if (r == 1) 22 else 30) * u, 6 * u), CornerRadius(3 * u),
                    )
                }
            }
        }

        // the snippet, flying along an arc
        val visible = (t in 0.06f..0.42f) || (t in 0.54f..0.90f)
        if (visible) {
            val forward = t < 0.5f
            val k = if (forward) go else back
            val from = if (forward) xs[0] else xs[2]
            val to = if (forward) xs[2] else xs[0]
            val p = Offset(from + (to - from) * k, cy - 46 * u - sin(k * Math.PI).toFloat() * 22 * u)
            val w = 44 * u
            val h = 28 * u
            drawRoundRect(c.raised, p + Offset(-w / 2, -h / 2), Size(w, h), CornerRadius(8 * u))
            drawRoundRect(c.hairline, p + Offset(-w / 2, -h / 2), Size(w, h), CornerRadius(8 * u), style = Stroke(1f * u))
            val ink = if (forward) c.accent else c.target
            drawRoundRect(ink, p + Offset(-w / 2 + 6 * u, -h / 2 + 7 * u), Size(10 * u, 10 * u), CornerRadius(3 * u))
            drawRoundRect(c.secondaryText.copy(alpha = 0.5f), p + Offset(-w / 2 + 20 * u, -h / 2 + 8 * u), Size(18 * u, 4 * u), CornerRadius(2 * u))
            drawRoundRect(c.secondaryText.copy(alpha = 0.3f), p + Offset(-w / 2 + 6 * u, -h / 2 + 20 * u), Size(30 * u, 4 * u), CornerRadius(2 * u))
        }

        labels.forEachIndexed { i, s ->
            val m = measurer.measure(s, labelStyle)
            drawText(m, topLeft = Offset(xs[i] - m.size.width / 2f, cy + 52 * u))
        }
    }
}
