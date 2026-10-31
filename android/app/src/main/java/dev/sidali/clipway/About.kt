package dev.sidali.clipway

import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.security.MessageDigest
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.concurrent.TimeUnit

/** What the About screen shows so anyone can check it, and Erase everything. */
object Trust {
    const val CONTACT = "contact@sidali.dev"
    const val SITE = "https://sidali.dev"

    /** SHA-256 of the certificate that signed the installed APK, read from the system at run time. */
    fun signingSha256(c: Context): String? = try {
        val si = c.packageManager.getPackageInfo(c.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
        val cert = when {
            si == null -> null
            si.hasMultipleSigners() -> si.apkContentsSigners.firstOrNull()
            else -> si.signingCertificateHistory.lastOrNull()
        }
        cert?.let { MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).joinToString("") { b -> "%02X".format(b) } }
    } catch (_: Exception) {
        null
    }

    /** First 8 and last 4 characters, enough to compare with SECURITY.md at a glance. */
    fun short(fp: String) = if (fp.length <= 12) fp else fp.take(8) + "…" + fp.takeLast(4)

    fun grouped(fp: String) = fp.chunked(2).joinToString(":")

    /** "2026-10-25" becomes "25 Oct 2026". */
    fun reviewDate(iso: String): String = try {
        LocalDate.parse(iso).format(DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH))
    } catch (_: Exception) {
        iso
    }

    /** CHANGELOG.md and PRIVACY.md, bundled from the repository at build time. */
    fun document(c: Context, name: String): String =
        try { c.assets.open(name).bufferedReader().use { it.readText() } } catch (_: Exception) { "" }

    /**
     * Erase everything (docs/PROTOCOL.md, section 5.7): if asked, the relay first (DELETE /chain,
     * best effort), then the key and the history key (crypto-shredding), the files and the settings.
     * Files saved to Downloads stay: they belong to the user. [done] runs on the main thread.
     */
    fun eraseEverything(c: Context, alsoRelay: Boolean, done: () -> Unit) {
        val app = c.applicationContext
        val keys = Vault.keys(app)
        val relay = Prefs(app).relay
        ClipService.stop(app)
        Thread {
            if (alsoRelay && keys != null) deleteChain(relay, keys.proofHex)
            Sender.outbox.clear()
            History.wipe(app)
            Vault.forget(app)
            Keystore.deleteAll()
            Prefs(app).clear()
            for (dir in listOf(app.filesDir, app.noBackupFilesDir, app.cacheDir)) dir.listFiles()?.forEach(File::deleteRecursively)
            try {
                app.getSystemService(NotificationManager::class.java).cancelAll()
            } catch (_: Exception) {
            }
            BootReceiver.apply(app, true)
            Status.link.value = Status.Link.Off
            Status.devices.value = 1
            Status.peer.value = null
            Status.relayNotice.value = null
            Handler(Looper.getMainLooper()).post(done)
        }.start()
    }

    /** DELETE /chain with the proof. 204 whatever the chain held; any failure is ignored (24 h purge). */
    private fun deleteChain(relay: String, proofHex: String) {
        try {
            val client = OkHttpClient.Builder().callTimeout(8, TimeUnit.SECONDS).build()
            val req = Request.Builder().url(Protocol.normalizeRelay(relay) + "/chain").delete()
                .header("X-Clipway-Proof", proofHex).header("User-Agent", "Clipway-Android/${BuildConfig.VERSION_NAME}").build()
            client.newCall(req).execute().close()
        } catch (e: Exception) {
            Log.i("ClipwayErase", "Relay not reached: ${e.javaClass.simpleName}")
        }
    }
}

// ---------------------------------------------------------------------
// About
// ---------------------------------------------------------------------

@Composable
fun AboutScreen(go: (Page) -> Unit, onBack: () -> Unit, onErased: () -> Unit) {
    val context = LocalContext.current
    val view = LocalView.current
    var erasing by rememberSaveable { mutableStateOf(false) }

    Screen(stringResource(R.string.about), onBack) {
        SectionLabel(stringResource(R.string.principles))
        Card(padding = Tokens.Space.none) {
            Column(
                Modifier.padding(start = Tokens.gutter, end = Tokens.gutter, top = Tokens.Space.l, bottom = Tokens.Space.m),
                verticalArrangement = Arrangement.spacedBy(Tokens.Space.m),
            ) {
                listOf(R.string.principle1, R.string.principle2, R.string.principle3, R.string.principle4).forEach {
                    Row(verticalAlignment = Alignment.Top) {
                        Glyph(G.Check, Tokens.colors.accent, Modifier.padding(top = Tokens.Space.xxs).size(Tokens.Size.glyph))
                        Spacer(Modifier.width(Tokens.Space.m))
                        Line(stringResource(it), Modifier.weight(1f))
                    }
                }
            }
            Hairline()
            LinkRow(stringResource(R.string.what_leaves)) { go(Page.Leaves) }
            Hairline()
            LinkRow(stringResource(R.string.permissions), detail = stringResource(R.string.permissions_detail)) { go(Page.Permissions) }
        }
        Spacer(Modifier.height(Tokens.Space.xxl))

        SectionLabel(stringResource(R.string.version_title))
        Card(padding = Tokens.Space.none) {
            Line(stringResource(R.string.version, BuildConfig.VERSION_NAME), Modifier.padding(horizontal = Tokens.gutter, vertical = Tokens.Space.l))
            Hairline()
            LinkRow(stringResource(R.string.whats_new)) { go(Page.WhatsNew) }
        }
        Spacer(Modifier.height(Tokens.Space.xxl))

        SectionLabel(stringResource(R.string.security))
        Card(padding = Tokens.Space.none) {
            Column(Modifier.padding(horizontal = Tokens.gutter, vertical = Tokens.Space.m)) {
                Line(stringResource(R.string.last_review, Trust.reviewDate(BuildConfig.SECURITY_REVIEW)))
                Footnote(stringResource(R.string.audit_state))
            }
            Hairline()
            val fp = remember { Trust.signingSha256(context) }
            var full by rememberSaveable { mutableStateOf(false) }
            LinkRow(
                stringResource(R.string.signing_certificate),
                detail = when {
                    fp == null -> stringResource(R.string.unavailable)
                    full -> Trust.grouped(fp)
                    else -> Trust.short(fp)
                },
                chevron = false,
            ) { if (fp != null) full = !full }
            Hairline()
            val subject = stringResource(R.string.security_subject)
            LinkRow(stringResource(R.string.report_issue), color = Tokens.colors.accent, chevron = false) {
                openLink(context, "mailto:${Trust.CONTACT}", subject)
            }
        }
        Spacer(Modifier.height(Tokens.Space.xxl))

        SectionLabel(stringResource(R.string.links))
        Card(padding = Tokens.Space.none) {
            LinkRow(stringResource(R.string.privacy_policy)) { go(Page.Privacy) }
            Hairline()
            val subject = stringResource(R.string.app_name)
            LinkRow(stringResource(R.string.contact), detail = Trust.CONTACT) { openLink(context, "mailto:${Trust.CONTACT}", subject) }
        }
        Spacer(Modifier.height(Tokens.Space.xxl))

        Card(padding = Tokens.Space.none) {
            LinkRow(stringResource(R.string.erase_title), color = Tokens.colors.danger, chevron = false) { erasing = true }
        }
        Footnote(stringResource(R.string.erase_hint), Modifier.padding(start = Tokens.gutter, end = Tokens.gutter, top = Tokens.Space.s))
        Spacer(Modifier.height(Tokens.Space.xxl))

        Footnote(
            stringResource(R.string.footer),
            Modifier.fillMaxWidth().pressable(stringResource(R.string.open_site)) { openLink(context, Trust.SITE) }.padding(vertical = Tokens.Space.s),
            align = TextAlign.Center,
        )
        Footnote(stringResource(R.string.fonts_credit), Modifier.fillMaxWidth(), align = TextAlign.Center)
    }

    if (erasing) EraseDialog(onCancel = { erasing = false }) { alsoRelay ->
        Trust.eraseEverything(context, alsoRelay) {
            view.confirm()
            Toast.makeText(context, R.string.erased, Toast.LENGTH_SHORT).show()
            erasing = false
            onErased()
        }
    }
}

/** Strong confirmation: the button only works once ERASE is typed. */
@Composable
private fun EraseDialog(onCancel: () -> Unit, onErase: (Boolean) -> Unit) {
    val word = stringResource(R.string.erase_word)
    var typed by rememberSaveable { mutableStateOf("") }
    var alsoRelay by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    val ready = typed.trim() == word && !busy
    CardDialog(stringResource(R.string.erase_confirm_title), stringResource(R.string.erase_confirm_body), onDismiss = onCancel) {
        Card(padding = Tokens.Space.none) {
            ToggleRow(stringResource(R.string.erase_relay), stringResource(R.string.erase_relay_detail), alsoRelay) { alsoRelay = it }
        }
        Spacer(Modifier.height(Tokens.Space.l))
        Footnote(stringResource(R.string.erase_type, word))
        Spacer(Modifier.height(Tokens.Space.s))
        Field(typed, { typed = it.uppercase(Locale.ROOT).take(12) }, stringResource(R.string.erase_field), mono = true, caps = true)
        Spacer(Modifier.height(Tokens.Space.xl))
        DialogButtons(stringResource(R.string.cancel), stringResource(R.string.erase), enabled = ready, danger = true, onCancel = onCancel) {
            busy = true
            onErase(alsoRelay)
        }
    }
}

// ---------------------------------------------------------------------
// What leaves your device (same facts as PRIVACY.md)
// ---------------------------------------------------------------------

@Composable
fun LeavesScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val host = remember { Protocol.relayHost(Prefs(context).relay) }
    Screen(stringResource(R.string.what_leaves), onBack) {
        Leave(stringResource(R.string.leaves_sent_title), stringResource(R.string.leaves_sent_body, host), stringResource(R.string.leaves_encrypted))
        Leave(stringResource(R.string.leaves_direct_title), stringResource(R.string.leaves_direct_body), stringResource(R.string.leaves_encrypted))
        Leave(stringResource(R.string.leaves_received_title), stringResource(R.string.leaves_received_body, host), stringResource(R.string.leaves_encrypted))
        Leave(stringResource(R.string.leaves_relay_title), stringResource(R.string.leaves_relay_body), null)
        Leave(stringResource(R.string.leaves_time_title), stringResource(R.string.leaves_time_body), null)
        Leave(stringResource(R.string.leaves_status_title), stringResource(R.string.leaves_status_body, host), null)
        Leave(stringResource(R.string.leaves_bluetooth_title), stringResource(R.string.leaves_bluetooth_body), null)
        Leave(stringResource(R.string.leaves_never_title), stringResource(R.string.leaves_never_body), null)
        Leave(stringResource(R.string.leaves_key_title), stringResource(R.string.leaves_key_body), null)
        SectionLabel(stringResource(R.string.leaves_stays))
        Card {
            Column(verticalArrangement = Arrangement.spacedBy(Tokens.Space.m)) {
                Bullet(stringResource(R.string.stays_key))
                Bullet(stringResource(R.string.stays_history))
                Bullet(stringResource(R.string.stays_files))
                Bullet(stringResource(R.string.stays_local))
                Bullet(stringResource(R.string.stays_backup))
            }
        }
        Spacer(Modifier.height(Tokens.Space.l))
        Footnote(stringResource(R.string.leaves_nothing_else), Modifier.padding(horizontal = Tokens.Space.xs))
    }
}

@Composable
private fun Leave(title: String, body: String, badge: String?) {
    Card {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(title, fontSize = Tokens.Type.headline, fontWeight = FontWeight.SemiBold, color = Tokens.colors.text, modifier = Modifier.weight(1f))
            if (badge != null) {
                Spacer(Modifier.width(Tokens.Space.s))
                Glyph(G.Lock, Tokens.colors.success, Modifier.size(Tokens.Size.glyphSmall))
                Spacer(Modifier.width(Tokens.Space.xs))
                Text(badge, fontSize = Tokens.Type.footnote, fontWeight = FontWeight.SemiBold, color = Tokens.colors.success)
            }
        }
        Spacer(Modifier.height(Tokens.Space.s))
        Line(body, size = Tokens.Type.callout, line = Tokens.Type.calloutLine, color = Tokens.colors.secondaryText)
    }
    Spacer(Modifier.height(Tokens.Space.m))
}

// ---------------------------------------------------------------------
// Documents bundled from the repository: CHANGELOG.md, PRIVACY.md
// ---------------------------------------------------------------------

/** A tiny reader for the Markdown of CHANGELOG.md and PRIVACY.md: headings, bullets, paragraphs. */
sealed interface Block {
    data class Title(val text: String) : Block
    data class Heading(val text: String) : Block
    data class Bullet(val text: String) : Block
    data class Para(val text: String) : Block

    companion object {
        private val LINK = Regex("""\[([^\]]+)]\([^)]*\)""")
        private fun inline(s: String) = LINK.replace(s) { it.groupValues[1] }.replace("**", "").replace("`", "").trim()

        fun parse(md: String): List<Block> {
            val out = mutableListOf<Block>()
            val para = StringBuilder()
            fun flush() {
                if (para.isNotBlank()) out += Para(inline(para.toString()))
                para.clear()
            }
            for (raw in md.lines()) {
                val line = raw.trimEnd()
                when {
                    line.isBlank() -> flush()
                    line.startsWith("## ") -> { flush(); out += Heading(inline(line.removePrefix("## "))) }
                    line.startsWith("# ") -> { flush(); out += Title(inline(line.removePrefix("# "))) }
                    line.startsWith("- ") -> { flush(); out += Bullet(inline(line.removePrefix("- "))) }
                    line.startsWith("  ") && out.lastOrNull() is Bullet && para.isEmpty() ->
                        out[out.lastIndex] = Bullet((out.last() as Bullet).text + " " + inline(line))
                    else -> { if (para.isNotEmpty()) para.append(' '); para.append(line.trim()) }
                }
            }
            flush()
            return out
        }

        /** The notes of one version: from "## <version>" to the next "## ". */
        fun section(md: String, version: String): String {
            val lines = md.lines()
            val start = lines.indexOfFirst { it.trim() == "## $version" || it.trim().startsWith("## $version ") }
            if (start < 0) return md
            val end = (start + 1 until lines.size).firstOrNull { lines[it].startsWith("## ") } ?: lines.size
            return lines.subList(start + 1, end).joinToString("\n")
        }
    }
}

@Composable
private fun Blocks(blocks: List<Block>) {
    Column(Modifier.padding(horizontal = Tokens.Space.xs)) {
        blocks.forEachIndexed { i, b ->
            when (b) {
                is Block.Title -> Unit
                is Block.Heading -> {
                    if (i > 1) Spacer(Modifier.height(Tokens.Space.xl))
                    Text(
                        b.text, fontSize = Tokens.Type.title, lineHeight = Tokens.Type.titleLine, fontWeight = FontWeight.Bold,
                        fontFamily = Tokens.Fonts.display, letterSpacing = Tokens.Type.titleTracking,
                        color = Tokens.colors.text, modifier = Modifier.semantics { heading() },
                    )
                    Spacer(Modifier.height(Tokens.Space.s))
                }
                is Block.Bullet -> { Bullet(b.text); Spacer(Modifier.height(Tokens.Space.s)) }
                is Block.Para -> {
                    val bold = b.text.length < 40 && i > 0 && blocks.getOrNull(i + 1) is Block.Bullet
                    Line(b.text, size = Tokens.Type.callout, line = Tokens.Type.calloutLine, weight = if (bold) FontWeight.SemiBold else null)
                    Spacer(Modifier.height(Tokens.Space.s))
                }
            }
        }
    }
}

@Composable
fun DocumentScreen(title: String, file: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val blocks = remember(file) { Block.parse(Trust.document(context, file)) }
    Screen(title, onBack) { Blocks(blocks) }
}

@Composable
fun WhatsNewScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val blocks = remember { Block.parse(Block.section(Trust.document(context, "CHANGELOG.md"), BuildConfig.VERSION_NAME)) }
    Screen(stringResource(R.string.whats_new), onBack) {
        Footnote(stringResource(R.string.version, BuildConfig.VERSION_NAME), Modifier.padding(horizontal = Tokens.Space.xs))
        Spacer(Modifier.height(Tokens.Space.l))
        Card { Blocks(blocks) }
        Spacer(Modifier.height(Tokens.Space.xxl))
        PrimaryButton(stringResource(R.string.continue_action), onClick = onBack)
    }
}
