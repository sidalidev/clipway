import AppKit
import ClipwayCore
import SwiftUI

/// Pair nearby (docs/PROTOCOL.md, 13.8): one panel for every state, the stage the same height in
/// each (no jump), one primary action at most. The sentences are those of the protocol's table.
struct NearbyPanel: View {
    @Environment(AppModel.self) private var model
    /// The window that runs the attempt: "pair" or "key".
    let owner: String
    /// Show a code instead.
    let showCode: () -> Void
    /// Done, once the phone said hello.
    let done: () -> Void

    private var nearby: NearbyPairing { model.nearby }

    /// The phone's hello after this attempt started: it joined the chain.
    private var joined: AppModel.Hello? {
        guard let hello = model.lastHello, hello.at >= nearby.startedAt else { return nil }
        return hello
    }

    var body: some View {
        VStack(spacing: Tokens.Space.xl) {
            if let joined {
                ScreenHeader(title: "Connected to \(joined.name)", subtitle: "Copy something on your Mac: it is on your phone.")
            } else {
                ScreenHeader(title: "Pair nearby", subtitle: message)
            }
            Card {
                stage
                    .frame(maxWidth: .infinity)
                    .frame(height: Tokens.Size.nearbyStage)
            }
            actions
        }
        .animation(Tokens.Motion.appear, value: nearby.screen)
        .animation(Tokens.Motion.celebrate, value: joined)
        .onAppear(perform: start)
        .onDisappear { nearby.stop(owner: owner) }
        .onChange(of: joined) { _, hello in
            if hello != nil { Haptics.success() }
        }
    }

    private func start() {
        guard !model.isPreview, let code = model.pairingCode else { return }
        nearby.start(code: code, owner: owner)
    }

    // MARK: Words (13.8)

    private var message: String {
        switch nearby.screen {
        case .idle, .starting, .advertising: "Bring your phone near your Mac."
        case .code(_, macConfirmed: false): "Check that your phone shows the same code."
        case .code(_, macConfirmed: true): "Now press Pair on your phone."
        case .finishing: "Finishing on your phone."
        case .stoppedOnPhone: "Pairing stopped on your phone."
        case .expired: "Time is up. Try again."
        case .failed: "Couldn't pair. Try again, or show a code instead."
        case .bluetoothOff: "Turn on Bluetooth to pair nearby, or show a code instead."
        case .notAllowed: "Clipway can't use Bluetooth. Allow it in System Settings, Privacy & Security, Bluetooth, or show a code instead."
        case .unsupported: "This Mac can't pair over Bluetooth. Show a code instead."
        }
    }

    // MARK: The stage

    @ViewBuilder
    private var stage: some View {
        if joined != nil {
            symbol("checkmark.circle.fill", Tokens.Colors.success)
        } else {
            switch nearby.screen {
            case .idle, .starting, .advertising:
                VStack(spacing: Tokens.Space.m) {
                    Beacon(active: nearby.screen == .advertising)
                    Text("On your phone, open Clipway and tap Pair nearby.")
                        .font(Tokens.Typography.callout)
                        .foregroundStyle(Tokens.Colors.secondaryText)
                        .multilineTextAlignment(.center)
                }
            case let .code(code, _):
                CodeTiles(code: code, animated: !nearby.isPreview)
            case .finishing:
                ProgressView()
                    .controlSize(.large)
                    .accessibilityLabel("Finishing on your phone")
            case .stoppedOnPhone:
                symbol("iphone.slash", Tokens.Colors.secondaryText)
            case .expired:
                symbol("clock", Tokens.Colors.secondaryText)
            case .failed:
                symbol("xmark.circle.fill", Tokens.Colors.danger)
            case .bluetoothOff, .unsupported:
                symbol("antenna.radiowaves.left.and.right.slash", Tokens.Colors.secondaryText)
            case .notAllowed:
                symbol("hand.raised.fill", Tokens.Colors.warning)
            }
        }
    }

    private func symbol(_ name: String, _ color: Color) -> some View {
        Image(systemName: name)
            .font(.system(size: Tokens.Size.beacon * 0.6, weight: .medium))
            .foregroundStyle(color)
            .transition(.scale(scale: 0.8).combined(with: .opacity))
            .accessibilityHidden(true)
    }

    // MARK: Actions

    @ViewBuilder
    private var actions: some View {
        if joined != nil {
            Button("Done", action: done)
                .buttonStyle(.primary)
                .keyboardShortcut(.defaultAction)
        } else {
            switch nearby.screen {
            case .idle, .starting, .advertising:
                showCodeButton
            case .code(_, macConfirmed: false):
                VStack(spacing: Tokens.Space.s) {
                    Button("Pair") { nearby.pair() }
                        .buttonStyle(.primary)
                        .keyboardShortcut(.defaultAction)
                    Button("Cancel") { nearby.cancel() }
                        .buttonStyle(.quiet)
                        .keyboardShortcut(.cancelAction)
                }
            case .code(_, macConfirmed: true):
                Button("Cancel") { nearby.cancel() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
            case .finishing:
                // In case the phone stops before its hello: the QR code is still a way through.
                showCodeButton
            case .stoppedOnPhone, .expired, .failed:
                VStack(spacing: Tokens.Space.s) {
                    Button("Try again") { nearby.retry() }
                        .buttonStyle(.primary)
                        .keyboardShortcut(.defaultAction)
                    showCodeButton
                }
            case .bluetoothOff:
                VStack(spacing: Tokens.Space.s) {
                    Button("Open Bluetooth settings") { open("x-apple.systempreferences:com.apple.BluetoothSettings") }
                        .buttonStyle(.secondary)
                    showCodeButton
                }
            case .notAllowed:
                VStack(spacing: Tokens.Space.s) {
                    Button("Open System Settings") { open("x-apple.systempreferences:com.apple.preference.security?Privacy_Bluetooth") }
                        .buttonStyle(.secondary)
                    showCodeButton
                }
            case .unsupported:
                Button("Show a code instead", action: showCode)
                    .buttonStyle(.primary)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private var showCodeButton: some View {
        Button("Show a code instead", action: showCode)
            .buttonStyle(.quiet)
    }

    private func open(_ address: String) {
        if let url = URL(string: address) { NSWorkspace.shared.open(url) }
    }
}

/// The 4-digit code, very large, one tile per digit, landing one after the other. VoiceOver reads
/// it digit by digit.
struct CodeTiles: View {
    let code: String
    var animated = true
    @State private var shown = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: Tokens.Space.m) {
            ForEach(Array(code.enumerated()), id: \.offset) { index, digit in
                Text(String(digit))
                    .font(Tokens.Typography.codeDigit)
                    .foregroundStyle(Tokens.Colors.text)
                    .frame(width: Tokens.Size.codeTileWidth, height: Tokens.Size.codeTileHeight)
                    .background(Tokens.Colors.tint, in: RoundedRectangle(cornerRadius: Tokens.Radius.button, style: .continuous))
                    .scaleEffect(visible || reduceMotion ? 1 : 0.6)
                    .opacity(visible ? 1 : 0)
                    .animation(reduceMotion ? nil : Tokens.Motion.digit.delay(Double(index) * Tokens.Motion.digitStagger), value: visible)
            }
        }
        .textSelection(.disabled)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Code \(code.map(String.init).joined(separator: " "))")
        .onAppear { shown = true }
    }

    private var visible: Bool { shown || !animated }
}

/// Looking for the phone: the symbol's waves move while the Mac advertises.
struct Beacon: View {
    let active: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Image(systemName: "iphone.radiowaves.left.and.right")
            .font(.system(size: Tokens.Size.beacon * 0.6, weight: .regular))
            .foregroundStyle(Tokens.Colors.accent)
            .symbolEffect(.variableColor.iterative.reversing, options: .repeating, isActive: active && !reduceMotion)
            .frame(width: Tokens.Size.beacon, height: Tokens.Size.beacon)
            .accessibilityHidden(true)
    }
}
