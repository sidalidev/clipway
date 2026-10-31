#if DEBUG
import AppKit
import ClipwayCore
import SwiftUI

/// Debug builds only: `Clipway --snapshots <folder>` renders every window, light and dark, with
/// sample data (no Keychain, no network), into PNG files, then quits. Used for docs/screenshots/mac.
@MainActor
enum Snapshots {
    /// The sandbox only lets the app write in its container: the files go to its temporary folder
    /// (printed on the standard output) unless the given folder is writable.
    static func run(to requested: URL) {
        var folder = requested
        if (try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)) == nil {
            folder = FileManager.default.temporaryDirectory.appendingPathComponent("snapshots", isDirectory: true)
            try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        }
        print("snapshots: \(folder.path)")
        let paired = AppModel.preview()
        let fresh = AppModel.preview(linked: false)
        let router = WindowRouter(model: paired)
        let screens: [(String, WindowRouter.Screen, AnyView)] = [
            ("welcome", .welcome, AnyView(WelcomeView().environment(fresh))),
            ("pair-nearby", .pair, AnyView(PairView().environment(AppModel.preview(nearby: .advertising)))),
            ("pair-nearby-code", .pair, AnyView(PairView().environment(AppModel.preview(nearby: .code("5456", macConfirmed: false))))),
            ("pair-nearby-waiting", .pair, AnyView(PairView().environment(AppModel.preview(nearby: .code("5456", macConfirmed: true))))),
            ("pair-nearby-off", .pair, AnyView(PairView().environment(AppModel.preview(nearby: .bluetoothOff)))),
            ("pair", .pair, AnyView(PairView(revealForSnapshot: true, nearby: false).environment(paired))),
            ("pair-hidden", .pair, AnyView(PairView(nearby: false).environment(paired))),
            ("pair-connected", .pair, AnyView(PairView().environment(AppModel.preview(pairedWith: "Pixel 10 Pro")))),
            ("key-locked", .key, AnyView(KeyView().environment(paired))),
            ("join", .join, AnyView(JoinView().environment(fresh))),
            ("settings", .settings, AnyView(SettingsView(permissionsPreview: (.on, .off, .on), scrolls: false).environment(paired))),
            ("about", .about, AnyView(AboutView(scrolls: false).environment(paired))),
            ("what-leaves", .whatLeaves, AnyView(WhatLeavesView(scrolls: false).environment(paired))),
            ("history", .history, AnyView(HistoryView().environment(paired))),
            ("erase", .about, AnyView(EraseSheet().environment(paired).background(Tokens.Colors.page))),
        ]
        for appearance in [NSAppearance.Name.aqua, .darkAqua] {
            let suffix = appearance == .aqua ? "light" : "dark"
            for (name, screen, view) in screens {
                print("rendering \(name)-\(suffix)")
                let content = view.frame(width: name == "erase" ? Tokens.Size.windowWidth : screen.width).environment(\.router, router)
                let window = WindowRouter.makeWindow(screen, content: content)
                window.appearance = NSAppearance(named: appearance)
                // The erase sheet has no title bar of its own.
                capture(window, to: folder.appendingPathComponent("\(name)-\(suffix).png"), frameOnly: name != "erase")
            }
        }
        // The rescue kit, as printed (always light).
        if let keys = paired.keys {
            for (i, page) in RescueKit.pages(keys: keys, relay: paired.relay, size: Tokens.Size.page).enumerated() {
                let window = WindowRouter.makeWindow(.key, content: page)
                window.appearance = NSAppearance(named: .aqua)
                capture(window, to: folder.appendingPathComponent("rescue-kit-\(i + 1).png"), frameOnly: false)
            }
        }
        NSApp.terminate(nil)
    }

    private static func capture(_ window: NSWindow, to url: URL, frameOnly: Bool = true) {
        // Invisible and click-through while it renders.
        window.alphaValue = 0
        window.ignoresMouseEvents = true
        window.center()
        window.orderFrontRegardless()
        window.layoutIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.6))
        guard let view = frameOnly ? window.contentView?.superview ?? window.contentView : window.contentView else { return }
        view.layoutSubtreeIfNeeded()
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        if let png = rep.representation(using: .png, properties: [:]) { try? png.write(to: url) }
        window.orderOut(nil)
    }
}
#endif
