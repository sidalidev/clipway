import AppKit
import ClipwayCore
import CoreBluetooth
import ServiceManagement
import SwiftUI
import UserNotifications

/// Settings, Permissions: what Clipway may use on this Mac, why, its state, and one click to turn
/// it on or off. Read again each time Clipway comes back to the front (after System Settings).
struct PermissionsCard: View {
    @State private var bluetooth: Access.State
    @State private var notifications: Access.State
    @State private var login: Access.State

    init(preview: (Access.State, Access.State, Access.State)? = nil) {
        let s = preview ?? (PermissionsCard.bluetoothState(), .notAsked, PermissionsCard.loginState())
        _bluetooth = State(initialValue: s.0)
        _notifications = State(initialValue: s.1)
        _login = State(initialValue: s.2)
        isPreview = preview != nil
    }

    private let isPreview: Bool

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: Tokens.Space.xs) {
                Text("Permissions").font(Tokens.Typography.headline)
                Text("Turn each one on or off at any time. Without one, Clipway keeps working and only that feature waits.")
                    .font(Tokens.Typography.footnote)
                    .foregroundStyle(Tokens.Colors.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            AccessRow(
                title: "Bluetooth",
                why: "Pair nearby finds your phone next to this Mac, only while its window is open. Never your location.",
                off: "Off: choose Show a code instead when you pair.",
                notAsked: "Asked the first time you pair nearby, or here.",
                state: bluetooth, kind: .permission
            ) { action in
                switch action {
                case .ask: BluetoothAsk.shared.ask { Task { @MainActor in refresh(); if bluetooth == .on { Haptics.success() } } }
                default: open("x-apple.systempreferences:com.apple.preference.security?Privacy_Bluetooth")
                }
            }
            Divider()
            AccessRow(
                title: "Notifications",
                why: "Show \"Copied from your phone\" for a few seconds, and where a received file went.",
                off: "Off: what your phone sends is still copied, without a notice.",
                notAsked: "Clipway asks when you click here.",
                state: notifications, kind: .permission
            ) { action in
                switch action {
                case .ask:
                    Task {
                        if await Notifier.shared.askNow() { Haptics.success() }
                        refresh()
                    }
                default: open("x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=\(Bundle.main.bundleIdentifier ?? "dev.sidali.clipway")")
                }
            }
            Divider()
            AccessRow(
                title: "Open at login",
                why: "Clipway starts when you log in, so what you copy on your phone arrives without opening it.",
                off: "Off: open Clipway yourself after you log in. Also in System Settings, General, Login Items.",
                notAsked: "",
                approval: "macOS waits for your approval in General, Login Items.",
                state: login, kind: .setting
            ) { action in
                switch action {
                case .turnOnHere, .turnOffHere:
                    if LoginItem.set(action == .turnOnHere), action == .turnOnHere { Haptics.success() }
                    refresh()
                default: SMAppService.openSystemSettingsLoginItems()
                }
            }
        }
        .task { if !isPreview { refresh() } }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            if !isPreview { refresh() }
        }
    }

    @MainActor
    private func refresh() {
        bluetooth = Self.bluetoothState()
        login = Self.loginState()
        Task {
            notifications = switch await Notifier.shared.status() {
            case .authorized, .provisional, .ephemeral: .on
            case .denied: .off
            default: .notAsked
            }
        }
    }

    private func open(_ url: String) {
        if let u = URL(string: url) { NSWorkspace.shared.open(u) }
    }

    static func bluetoothState() -> Access.State {
        switch CBPeripheralManager.authorization {
        case .allowedAlways: .on
        case .notDetermined: .notAsked
        default: .off
        }
    }

    static func loginState() -> Access.State {
        switch SMAppService.mainApp.status {
        case .enabled: .on
        case .requiresApproval: .needsApproval
        default: .off
        }
    }
}

/// One row: name, why, what happens without it, the state, and the action. The whole row is one
/// button, read by VoiceOver as its name, its state and its action.
private struct AccessRow: View {
    let title: String
    let why: String
    let off: String
    let notAsked: String
    var approval: String = ""
    let state: Access.State
    let kind: Access.Kind
    let perform: (Access.Action) -> Void

    var body: some View {
        let action = Access.action(state, kind: kind)
        let note = switch state {
        case .on: ""
        case .off: off
        case .notAsked: notAsked
        case .needsApproval: approval
        }
        Button {
            Haptics.tap()
            perform(action)
        } label: {
            HStack(alignment: .firstTextBaseline, spacing: Tokens.Space.m) {
                VStack(alignment: .leading, spacing: Tokens.Space.xxs) {
                    Text(title).font(Tokens.Typography.body.weight(.medium))
                    Text(why)
                        .font(Tokens.Typography.footnote)
                        .foregroundStyle(Tokens.Colors.secondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                    if !note.isEmpty {
                        Text(note)
                            .font(Tokens.Typography.footnote)
                            .foregroundStyle(Tokens.Colors.secondaryText)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Text(Access.label(action))
                        .font(Tokens.Typography.callout.weight(.semibold))
                        .foregroundStyle(Tokens.Colors.accent)
                        .padding(.top, Tokens.Space.xxs)
                }
                Spacer(minLength: Tokens.Space.s)
                HStack(spacing: Tokens.Space.xs) {
                    if state == .on {
                        Image(systemName: "checkmark.circle.fill").accessibilityHidden(true)
                    }
                    Text(Access.label(state))
                }
                .font(Tokens.Typography.callout)
                .foregroundStyle(state == .on ? Tokens.Colors.success : Tokens.Colors.secondaryText)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
        .accessibilityValue(Access.label(state))
        .accessibilityHint("\(why) \(note)")
        .accessibilityAction(named: Access.label(action)) { perform(action) }
        .accessibilityAddTraits(.isButton)
    }
}

/// Asks macOS for Bluetooth once, from Settings: the prompt shows when a manager is created.
@MainActor
final class BluetoothAsk: NSObject {
    static let shared = BluetoothAsk()
    private var manager: CBPeripheralManager?
    private var done: (@Sendable () -> Void)?

    func ask(done: @escaping @Sendable () -> Void) {
        self.done = done
        manager = CBPeripheralManager(delegate: self, queue: .main, options: [CBPeripheralManagerOptionShowPowerAlertKey: false])
    }
}

extension BluetoothAsk: @preconcurrency CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard peripheral === manager, CBPeripheralManager.authorization != .notDetermined else { return }
        manager = nil
        done?()
        done = nil
    }
}
