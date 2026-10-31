import AppKit
import ClipwayCore
import SwiftUI

/// First launch: what Clipway does, in one sentence, then Pair.
struct WelcomeView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.router) private var router

    var body: some View {
        VStack(spacing: Tokens.Space.xxl) {
            ScreenHeader(appIcon: true, title: "Clipway",
                         subtitle: "Copy on your Mac, paste on your phone. And back.")
            Card {
                InfoRow(symbol: "lock.fill", title: "End-to-end encrypted",
                        detail: "Only your devices hold the key. The relay passes sealed items it cannot read.")
                InfoRow(symbol: "person.crop.circle.badge.xmark", title: "No account",
                        detail: "Your Mac makes a key and hands it to your phone nearby. That is all.")
                InfoRow(symbol: "eye.slash", title: "Secrets stay here",
                        detail: "What a password manager marks as secret is never sent.")
            }
            VStack(spacing: Tokens.Space.s) {
                Button("Pair a phone") {
                    if model.needsPairing && !model.createChain() { return }
                    router?.show(.pair)
                    router?.close(.welcome)
                }
                .buttonStyle(.primary)
                .keyboardShortcut(.defaultAction)
                Button("I already have 12 words") {
                    router?.show(.join)
                    router?.close(.welcome)
                }
                .buttonStyle(.quiet)
            }
        }
        .padding(.horizontal, Tokens.Space.xxl)
        .padding(.top, Tokens.Space.titlebar)
        .padding(.bottom, Tokens.Space.xxl)
    }
}

/// Pair a phone: opens on Pair nearby (Bluetooth, section 13), with Show a code instead for the QR
/// code. Then the words behind Touch ID and the rescue kit, once the phone has joined.
struct PairView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.router) private var router
    @State private var showWords = false
    @State private var launchAtLogin = LoginItem.isOn
    @State private var nearbyMode: Bool
    var revealForSnapshot = false

    init(revealForSnapshot: Bool = false, nearby: Bool = true) {
        self.revealForSnapshot = revealForSnapshot
        _nearbyMode = State(initialValue: nearby)
    }

    var body: some View {
        VStack(spacing: Tokens.Space.xl) {
            if let name = model.pairedWith {
                ScreenHeader(symbol: "checkmark.circle.fill", symbolColor: Tokens.Colors.success, title: "Connected to \(name)",
                             subtitle: "Copy something on your Mac: it is on your phone.")
                    .transition(.scale(scale: 0.9).combined(with: .opacity))
                if let keys = model.keys {
                    // The phone has joined: only the words stay, for the backup.
                    KeyCard(keys: keys, relay: model.relay, showWords: $showWords, showCode: false, revealForSnapshot: revealForSnapshot)
                }
                finish
            } else if nearbyMode && model.canPairNearby {
                NearbyPanel(owner: "pair", showCode: { nearbyMode = false }, done: { router?.close(.pair) })
                    .transition(.opacity)
            } else {
                ScreenHeader(title: "Scan this code with your phone",
                             subtitle: "In Clipway on your phone, choose Scan a code instead, then point it at this code.")
                if let keys = model.keys {
                    KeyCard(keys: keys, relay: model.relay, showWords: $showWords, revealForSnapshot: revealForSnapshot)
                }
                if model.canPairNearby {
                    Button("Pair nearby instead") { nearbyMode = true }
                        .buttonStyle(.quiet)
                }
                finish
            }
        }
        .animation(Tokens.Motion.celebrate, value: model.pairedWith)
        .animation(Tokens.Motion.appear, value: nearbyMode)
        .padding(.horizontal, Tokens.Space.xxl)
        .padding(.top, Tokens.Space.titlebar)
        .padding(.bottom, Tokens.Space.xxl)
    }

    @ViewBuilder
    private var finish: some View {
        Toggle("Open Clipway when you log in", isOn: $launchAtLogin)
            .toggleStyle(.clipSwitch)
            .font(Tokens.Typography.body)
            .onChange(of: launchAtLogin) { _, on in
                if !LoginItem.set(on) { launchAtLogin = LoginItem.isOn }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        Button("Done") { router?.close(.pair) }
            .buttonStyle(.primary)
            .keyboardShortcut(.defaultAction)
    }
}

/// QR code, words (hidden until the owner confirms), the truth about losing them, the rescue kit.
struct KeyCard: View {
    let keys: ChainKeys
    let relay: String
    @Binding var showWords: Bool
    var showCode = true
    var revealForSnapshot = false
    @State private var hideTask: Task<Void, Never>?

    var body: some View {
        VStack(spacing: Tokens.Space.l) {
            if showCode {
                QRCodeView(text: keys.pairingCode(relay: relay))
                    .transition(.scale(scale: 0.8).combined(with: .opacity))
            }
            Card {
                if showWords || revealForSnapshot {
                    WordsGrid(words: keys.words)
                        .transition(.opacity)
                } else {
                    HStack {
                        IconText("12 words, hidden", symbol: "lock.fill")
                            .font(Tokens.Typography.body)
                            .foregroundStyle(Tokens.Colors.secondaryText)
                        Spacer()
                        Button("Show words") { reveal() }
                            .buttonStyle(.secondary)
                    }
                }
                Text("These 12 words are your key. Anyone who has them can read what you copy. Your Mac keeps them in its Keychain.")
                    .font(Tokens.Typography.callout)
                    .foregroundStyle(Tokens.Colors.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
                Text("If you lose these 12 words and all your devices, nobody can recover your key, not even us.")
                    .font(Tokens.Typography.callout.weight(.medium))
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Print a rescue kit") { printKit() }
                        .buttonStyle(.secondary)
                    Spacer()
                    if !RelayAddress.host(relay).isEmpty && relay != ClipwayInfo.defaultRelay {
                        Text("Relay: \(RelayAddress.host(relay))")
                            .font(Tokens.Typography.footnote)
                            .foregroundStyle(Tokens.Colors.secondaryText)
                    }
                }
            }
        }
        .animation(Tokens.Motion.appear, value: showWords)
        .animation(Tokens.Motion.appear, value: showCode)
        .onDisappear {
            hideTask?.cancel()
            showWords = false
        }
    }

    private func reveal() {
        Task {
            guard await OwnerCheck.confirm(reason: "show your 12 words") else { return }
            showWords = true
            Haptics.alignment()
            hideTask?.cancel()
            hideTask = Task {
                try? await Task.sleep(nanoseconds: UInt64(Tokens.Motion.keyVisibleSeconds * 1_000_000_000))
                if !Task.isCancelled { showWords = false }
            }
        }
    }

    private func printKit() {
        Task {
            if !showWords {
                guard await OwnerCheck.confirm(reason: "print your rescue kit") else { return }
            }
            RescueKit.print(keys: keys, relay: relay)
        }
    }
}

/// Show the key: Touch ID or the Mac password first, hidden again after 60 seconds. Pair nearby
/// is offered there too, behind the same check, since it hands the key to a phone.
struct KeyView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.router) private var router
    @State private var unlocked = false
    @State private var showWords = false
    @State private var nearbyMode = false
    @State private var hideTask: Task<Void, Never>?
    var revealForSnapshot = false

    var body: some View {
        VStack(spacing: Tokens.Space.xl) {
            if model.keys != nil, unlocked, nearbyMode {
                NearbyPanel(owner: "key", showCode: {
                    nearbyMode = false
                    hideLater()
                }, done: { router?.close(.key) })
                .transition(.opacity)
            } else if let keys = model.keys, unlocked || revealForSnapshot {
                ScreenHeader(title: "Your key", subtitle: "Scan it with a new phone, or keep the words somewhere safe.")
                KeyCard(keys: keys, relay: model.relay, showWords: $showWords, revealForSnapshot: revealForSnapshot)
                if model.canPairNearby {
                    Button("Pair a phone nearby") {
                        // The code on screen is not the key: no need to hide it while the phone pairs.
                        hideTask?.cancel()
                        nearbyMode = true
                    }
                    .buttonStyle(.secondary)
                }
                Button("Done") { router?.close(.key) }
                    .buttonStyle(.primary)
                    .keyboardShortcut(.defaultAction)
            } else {
                ScreenHeader(symbol: "lock.fill", title: "Your key",
                             subtitle: "Confirm it is you to see the code and the 12 words. They hide again after a minute.")
                Button("Show the key") { unlock() }
                    .buttonStyle(.primary)
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.keys == nil)
            }
        }
        .padding(.horizontal, Tokens.Space.xxl)
        .padding(.top, Tokens.Space.titlebar)
        .padding(.bottom, Tokens.Space.xxl)
        .animation(Tokens.Motion.appear, value: unlocked)
        .animation(Tokens.Motion.appear, value: nearbyMode)
        .onDisappear { hideTask?.cancel() }
    }

    private func unlock() {
        Task {
            guard await OwnerCheck.confirm(reason: "show your key") else { return }
            unlocked = true
            showWords = true
            hideLater()
        }
    }

    private func hideLater() {
        hideTask?.cancel()
        hideTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(Tokens.Motion.keyVisibleSeconds * 1_000_000_000))
            guard !Task.isCancelled else { return }
            unlocked = false
            showWords = false
        }
    }
}

/// Join an existing chain with its 12 words (or a clipway: code). Never creates a chain.
struct JoinView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.router) private var router
    @State private var words = ""
    @State private var error: AppModel.JoinError?
    @State private var joined = false

    var body: some View {
        VStack(spacing: Tokens.Space.xl) {
            if joined {
                ScreenHeader(symbol: "checkmark.circle.fill", symbolColor: Tokens.Colors.success, title: "This Mac has your key",
                             subtitle: "Copy something here: it goes to \(model.peer).")
                Button("Done") { router?.close(.join) }
                    .buttonStyle(.primary)
                    .keyboardShortcut(.defaultAction)
            } else {
                ScreenHeader(title: "Join with 12 words",
                             subtitle: "Type the 12 words of your key, in order, separated by spaces.")
                VStack(alignment: .leading, spacing: Tokens.Space.s) {
                    TextField("12 words", text: $words, axis: .vertical)
                        .lineLimit(3...4)
                        .font(Tokens.Typography.words)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textContentType(.none)
                        .onSubmit(join)
                        .onChange(of: words) { _, _ in error = nil }
                    if let error {
                        FieldMessage(text: error.message)
                    } else if let relay = model.relayInCode(words) {
                        FieldMessage(text: "This code uses the relay \(RelayAddress.host(relay)).", isError: false)
                    }
                }
                Text("Lost the words? Open Show the key on a device that still has them.")
                    .font(Tokens.Typography.callout)
                    .foregroundStyle(Tokens.Colors.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button("Join", action: join)
                    .buttonStyle(.primary)
                    .keyboardShortcut(.defaultAction)
                    .disabled(words.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(.horizontal, Tokens.Space.xxl)
        .padding(.top, Tokens.Space.titlebar)
        .padding(.bottom, Tokens.Space.xxl)
        .animation(Tokens.Motion.appear, value: joined)
        .onDisappear { words = "" }
    }

    private func join() {
        if let problem = model.join(words) {
            error = problem
            NSHapticFeedbackManager.defaultPerformer.perform(.generic, performanceTime: .now)
            return
        }
        words = ""
        joined = true
        Haptics.success()
    }
}
