package dev.sidali.clipway

import android.provider.Settings
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign

/**
 * The card of a Pair nearby attempt (docs/PROTOCOL.md, 13.8): rings while it looks for the Mac,
 * the 4-digit code once both keys are known, or why it stopped. Words from the protocol's table.
 */
@Composable
fun NearbyCard(state: NearbyState) {
    // What the card shows; the code keeps one layout while Pair is pressed and the packet comes.
    val kind = when (state) {
        is NearbyState.Code, is NearbyState.Finishing -> "code"
        is NearbyState.Ended -> "ended-" + state.why.name
        else -> "searching"
    }
    Card(Modifier.heightIn(min = Tokens.Size.nearbyCard)) {
        AnimatedContent(
            targetState = kind,
            transitionSpec = { fadeIn(tween(Tokens.Motion.PAGE_MS)).togetherWith(fadeOut(tween(Tokens.Motion.FADE_MS))) },
            label = "nearby",
            modifier = Modifier.fillMaxWidth().heightIn(min = Tokens.Size.nearbyCard - Tokens.Space.xl - Tokens.Space.xl),
            contentAlignment = Alignment.Center,
        ) { k ->
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                when {
                    k == "code" -> {
                        val code = (state as? NearbyState.Code)?.code ?: (state as? NearbyState.Finishing)?.code ?: ""
                        CodeTiles(code)
                        Spacer(Modifier.height(Tokens.Space.xl))
                        val line = when {
                            state is NearbyState.Finishing -> stringResource(R.string.nearby_finishing)
                            state is NearbyState.Code && state.pressed -> stringResource(R.string.nearby_press_mac)
                            else -> stringResource(R.string.nearby_check)
                        }
                        Line(
                            line, Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
                            weight = FontWeight.SemiBold, align = TextAlign.Center,
                        )
                    }
                    k.startsWith("ended-") -> Ended((state as? NearbyState.Ended)?.why ?: NearbyState.Why.Failed)
                    else -> {
                        Radar()
                        Spacer(Modifier.height(Tokens.Space.l))
                        Line(
                            stringResource(R.string.nearby_searching), Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
                            color = Tokens.colors.secondaryText, align = TextAlign.Center,
                        )
                    }
                }
            }
        }
    }
}

/** The 4 digits, one tile each, read digit by digit by TalkBack. */
@Composable
private fun CodeTiles(code: String) {
    val spoken = stringResource(R.string.nearby_code_spoken, code.toList().joinToString(" "))
    Row(
        Modifier.clearAndSetSemantics { contentDescription = spoken; liveRegion = LiveRegionMode.Polite },
        horizontalArrangement = Arrangement.spacedBy(Tokens.Space.m),
    ) {
        for (d in code) {
            Box(
                Modifier.size(Tokens.Size.digitWidth, Tokens.Size.digitHeight).clip(RoundedCornerShape(Tokens.buttonRadius))
                    .background(Tokens.colors.raised),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    d.toString(), fontSize = Tokens.Type.code, lineHeight = Tokens.Type.codeLine, fontWeight = FontWeight.Bold,
                    fontFamily = Tokens.Fonts.display, color = Tokens.colors.text,
                )
            }
        }
    }
}

/** Why the attempt stopped, in the protocol's words. */
@Composable
private fun Ended(why: NearbyState.Why) {
    val bluetooth = why == NearbyState.Why.BluetoothOff || why == NearbyState.Why.NotAllowed || why == NearbyState.Why.Unavailable
    Box(
        Modifier.size(Tokens.Size.radarCore).clip(CircleShape).background(Tokens.colors.raised),
        contentAlignment = Alignment.Center,
    ) { Glyph(if (bluetooth) G.Bluetooth else G.Mac, Tokens.colors.secondaryText, Modifier.size(Tokens.Size.glyphLarge)) }
    Spacer(Modifier.height(Tokens.Space.l))
    val (title, detail) = when (why) {
        NearbyState.Why.NoMac -> R.string.nearby_no_mac to R.string.nearby_no_mac_detail
        NearbyState.Why.Canceled -> R.string.nearby_canceled to null
        NearbyState.Why.Expired -> R.string.nearby_expired to null
        NearbyState.Why.Failed -> R.string.nearby_failed to null
        NearbyState.Why.Busy -> R.string.nearby_busy to null
        NearbyState.Why.BluetoothOff -> R.string.nearby_bluetooth_off to null
        NearbyState.Why.NotAllowed -> R.string.nearby_not_allowed to null
        NearbyState.Why.Unavailable -> R.string.nearby_unavailable to null
    }
    Line(
        stringResource(title), Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
        weight = FontWeight.SemiBold, align = TextAlign.Center,
    )
    if (detail != null) {
        Spacer(Modifier.height(Tokens.Space.xs))
        Line(
            stringResource(detail), Modifier.fillMaxWidth(), color = Tokens.colors.secondaryText,
            size = Tokens.Type.callout, line = Tokens.Type.calloutLine, align = TextAlign.Center,
        )
    }
}

/** Rings that leave the Mac while the phone looks for it. Still when the system turns animations off. */
@Composable
private fun Radar() {
    val context = LocalContext.current
    val still = remember {
        Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f
    }
    val wave by rememberInfiniteTransition(label = "radar").animateFloat(
        0f, 1f, infiniteRepeatable(tween(Tokens.Motion.RADAR_MS, easing = LinearEasing)), label = "wave",
    )
    val t = if (still) 0.5f else wave
    val ring = Tokens.colors.accent
    val description = stringResource(R.string.nearby_searching_description)
    Box(Modifier.size(Tokens.Size.radar).semantics { contentDescription = description }, contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val core = Tokens.Size.radarCore.toPx() / 2
            val max = size.minDimension / 2
            val stroke = Tokens.Size.hairline.toPx() * 2
            for (i in 0 until 3) {
                val p = (t + i / 3f) % 1f
                drawCircle(ring.copy(alpha = (1f - p) * 0.5f), core + (max - core) * p, style = Stroke(stroke))
            }
        }
        Box(
            Modifier.size(Tokens.Size.radarCore).clip(CircleShape).background(Tokens.colors.badge),
            contentAlignment = Alignment.Center,
        ) { Glyph(G.Mac, Tokens.colors.onBadge, Modifier.size(Tokens.Size.glyphLarge)) }
    }
}
