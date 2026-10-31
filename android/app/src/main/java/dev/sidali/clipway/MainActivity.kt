package dev.sidali.clipway

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        demo(intent)
        setContent { ClipwayTheme { App() } }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        demo(intent)
    }

    /** Debug builds only: Pair nearby talks to a Mac played in the app (NearbyDemo.kt, android/README.md). */
    private fun demo(i: android.content.Intent?) {
        if (!BuildConfig.DEBUG || i == null) return
        i.getStringExtra("nearby_demo")?.let { NearbyPairing.demoCode = it }
        if (i.getBooleanExtra("nearby_selfcheck", false) && android.os.Build.VERSION.SDK_INT >= 33) {
            android.util.Log.i("ClipwayNearby", "Nearby self-check: " + NearbyDemo.selfCheck())
        }
    }

    override fun onResume() {
        super.onResume()
        // Coming to the foreground reconnects at once (section 5.1).
        if (Vault.paired(this)) ClipService.start(this)
    }
}

/** Screens above the tabs, by depth: a deeper screen slides in from the right. */
enum class Page(val depth: Int) { Tabs(0), Key(1), About(1), Leaves(2), Privacy(2), WhatsNew(2), Permissions(2) }

enum class Tab { Home, History, Settings }

@Composable
fun App() {
    val context = LocalContext.current
    val prefs = remember { Prefs(context) }
    var paired by remember { mutableStateOf(Vault.paired(context)) }
    var onboarded by remember { mutableStateOf(prefs.onboarded) }
    // Re-read after an erase or a pairing done elsewhere in the app.
    val reset = { paired = Vault.paired(context); onboarded = prefs.onboarded }

    Box(Modifier.fillMaxSize().background(Tokens.colors.page)) {
        if (!paired || !onboarded) {
            Onboarding(
                paired = paired,
                onPaired = { paired = true },
                onDone = {
                    prefs.onboarded = true
                    prefs.versionSeen = BuildConfig.VERSION_NAME
                    onboarded = true
                },
            )
        } else {
            Main(onReset = reset)
        }
    }
}

@Composable
private fun Main(onReset: () -> Unit) {
    val context = LocalContext.current
    val prefs = remember { Prefs(context) }
    var stack by rememberSaveable { mutableStateOf(listOf(Page.Tabs.name)) }
    var tab by rememberSaveable { mutableStateOf(Tab.Home.name) }
    val top = Page.valueOf(stack.last())
    val holder = androidx.compose.runtime.saveable.rememberSaveableStateHolder()
    fun go(p: Page) { stack = stack + p.name }
    fun back() {
        if (stack.size <= 1) return
        // A screen left with Back starts fresh next time (the key screen asks again, for one).
        holder.removeState(stack.last())
        stack = stack.dropLast(1)
    }
    BackHandler(stack.size > 1) { back() }
    BackHandler(stack.size == 1 && tab != Tab.Home.name) { tab = Tab.Home.name }

    // What's new: once after each update.
    LaunchedEffect(Unit) {
        if (prefs.versionSeen != BuildConfig.VERSION_NAME) {
            prefs.versionSeen = BuildConfig.VERSION_NAME
            go(Page.WhatsNew)
        }
    }

    AnimatedContent(
        targetState = top,
        transitionSpec = {
            val forward = targetState.depth >= initialState.depth
            val dur = Tokens.Motion.PAGE_MS
            (slideInHorizontally(tween(dur)) { w -> if (forward) w else -w / 4 } + fadeIn(tween(dur)))
                .togetherWith(slideOutHorizontally(tween(dur)) { w -> if (forward) -w / 4 else w } + fadeOut(tween(dur)))
        },
        label = "page",
    ) { page ->
        // Each screen keeps its state (scroll, tab) while a deeper one is shown.
        holder.SaveableStateProvider(page.name) { PageContent(page, tab, { tab = it.name }, ::go, ::back, onReset) }
    }
}

@Composable
private fun PageContent(page: Page, tab: String, select: (Tab) -> Unit, go: (Page) -> Unit, back: () -> Unit, onReset: () -> Unit) {
    when (page) {
            Page.Tabs -> Tabs(Tab.valueOf(tab), select, go, onReset)
            Page.Key -> KeyScreen(onBack = back)
            Page.About -> AboutScreen(go = go, onBack = back, onErased = onReset)
            Page.Leaves -> LeavesScreen(onBack = back)
            Page.Privacy -> DocumentScreen(stringResource(R.string.privacy_policy), "PRIVACY.md", onBack = back)
            Page.WhatsNew -> WhatsNewScreen(onBack = back)
            Page.Permissions -> PermissionsScreen(onBack = back)
    }
}

@Composable
private fun Tabs(tab: Tab, select: (Tab) -> Unit, go: (Page) -> Unit, onReset: () -> Unit) {
    Column(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f)) {
            when (tab) {
                Tab.Home -> HomeTab(go = go, onReset = onReset, openHistory = { select(Tab.History) })
                Tab.History -> HistoryTab()
                Tab.Settings -> SettingsTab(go = go)
            }
        }
        TabBar(tab, select)
    }
}

@Composable
private fun TabBar(tab: Tab, select: (Tab) -> Unit) {
    val view = LocalView.current
    Column(Modifier.fillMaxWidth().background(Tokens.colors.card)) {
        Hairline(inset = false)
        Row(Modifier.fillMaxWidth().windowInsetsPadding(WindowInsets.navigationBars).height(Tokens.Size.tabBar)) {
            listOf(
                Triple(Tab.Home, G.Home, R.string.tab_home),
                Triple(Tab.History, G.Clock, R.string.tab_history),
                Triple(Tab.Settings, G.Sliders, R.string.tab_settings),
            ).forEach { (t, g, label) ->
                val on = t == tab
                val color = if (on) Tokens.colors.accent else Tokens.colors.secondaryText
                Column(
                    Modifier.weight(1f).fillMaxSize().pressable(stringResource(label), Role.Tab) { view.tick(); select(t) }
                        .semantics { selected = on },
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = androidx.compose.foundation.layout.Arrangement.Center,
                ) {
                    Glyph(g, color, Modifier.size(Tokens.Size.glyph))
                    Spacer(Modifier.height(Tokens.Space.xs))
                    Text(stringResource(label), fontSize = Tokens.Type.tab, fontWeight = if (on) FontWeight.SemiBold else FontWeight.Medium, color = color)
                }
            }
        }
    }
}
