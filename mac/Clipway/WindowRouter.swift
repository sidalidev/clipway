import AppKit
import SwiftUI

/// Opens each screen in its own window, once. Windows that show the key cannot be captured
/// (sharingType none) and forget the words when they close.
@MainActor
final class WindowRouter: NSObject, NSWindowDelegate {
    enum Screen: String, CaseIterable {
        case welcome, pair, join, key, settings, about, whatLeaves, history, privacy, changelog

        var title: String {
            switch self {
            case .welcome: "Welcome to Clipway"
            case .pair: "Pair a phone"
            case .join: "Join with 12 words"
            case .key: "Your key"
            case .settings: "Settings"
            case .about: "About Clipway"
            case .whatLeaves: "What leaves your device"
            case .history: "History"
            case .privacy: "Privacy policy"
            case .changelog: "What's new"
            }
        }

        /// Screens that show or take the key.
        var isSecret: Bool { self == .pair || self == .key || self == .join }

        var width: CGFloat {
            switch self {
            case .history, .whatLeaves, .privacy, .changelog, .pair, .key: Tokens.Size.wideWindowWidth
            default: Tokens.Size.windowWidth
            }
        }
    }

    let model: AppModel
    private var windows: [Screen: NSWindow] = [:]

    init(model: AppModel) {
        self.model = model
    }

    func show(_ screen: Screen) {
        if let window = windows[screen] {
            NSApp.activate()
            window.makeKeyAndOrderFront(nil)
            return
        }
        let window = Self.makeWindow(screen, content: view(for: screen))
        window.delegate = self
        windows[screen] = window
        window.center()
        NSApp.activate()
        window.makeKeyAndOrderFront(nil)
    }

    var hasOpenWindow: Bool { windows.values.contains { $0.isVisible } }

    func close(_ screen: Screen) {
        windows[screen]?.close()
    }

    func closeAll() {
        for window in windows.values { window.close() }
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow,
              let screen = windows.first(where: { $0.value === window })?.key else { return }
        windows[screen] = nil
        // Closing a window that pairs nearby ends the attempt (Status 02 to the phone).
        if screen == .pair || screen == .key { model.nearby.stop(owner: screen.rawValue) }
    }

    static func makeWindow(_ screen: Screen, content: some View) -> NSWindow {
        // The content draws under the transparent title bar and leaves room for it itself
        // (Tokens.Space.titlebar), so the window size never depends on the safe area.
        let host = NSHostingController(rootView: content.ignoresSafeArea())
        host.sizingOptions = [.preferredContentSize]
        let window = NSWindow(contentViewController: host)
        window.title = screen.title
        window.styleMask = [.titled, .closable, .fullSizeContentView]
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.isReleasedWhenClosed = false
        window.tabbingMode = .disallowed
        // Clipway's page color under the transparent title bar too, light and dark.
        window.backgroundColor = Tokens.Colors.pageNS
        if screen.isSecret { window.sharingType = .none }
        return window
    }

    @ViewBuilder
    func view(for screen: Screen) -> some View {
        Group {
            switch screen {
            case .welcome: WelcomeView()
            case .pair: PairView()
            case .join: JoinView()
            case .key: KeyView()
            case .settings: SettingsView()
            case .about: AboutView()
            case .whatLeaves: WhatLeavesView()
            case .history: HistoryView()
            case .privacy: DocumentView(resource: "PRIVACY")
            case .changelog: DocumentView(resource: "CHANGELOG")
            }
        }
        .frame(width: screen.width)
        .font(Tokens.Typography.body)
        .foregroundStyle(Tokens.Colors.text)
        .tint(Tokens.Colors.accent)
        .background(Tokens.Colors.page)
        .environment(model)
        .environment(\.router, self)
    }
}

private struct RouterKey: EnvironmentKey {
    static let defaultValue: WindowRouter? = nil
}

extension EnvironmentValues {
    var router: WindowRouter? {
        get { self[RouterKey.self] }
        set { self[RouterKey.self] = newValue }
    }
}
