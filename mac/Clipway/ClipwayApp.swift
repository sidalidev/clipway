import AppKit
import ClipwayCore
import SwiftUI

/// Clipway for the Mac: a menu bar app, with a Dock icon unless Show in Dock is off (DockIcon).
/// AppKit drives the status item and the windows; the windows' content is SwiftUI.
@main
enum ClipwayMain {
    @MainActor private static var delegate: AppDelegate?

    @MainActor
    static func main() {
        #if DEBUG
        if let index = CommandLine.arguments.firstIndex(of: "--debug-nearby-vectors") {
            let path = index + 1 < CommandLine.arguments.count ? CommandLine.arguments[index + 1] : nil
            exit(NearbyVectorsCheck.run(path: path))
        }
        #endif
        let app = NSApplication.shared
        let delegate = AppDelegate()
        Self.delegate = delegate
        app.delegate = delegate
        DockIcon.apply(DockIcon.isOn())
        app.run()
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var model: AppModel?
    private var router: WindowRouter?
    private var statusItem: StatusItemController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        Fonts.register()
        NSApp.mainMenu = Self.mainMenu()
        #if DEBUG
        if let index = CommandLine.arguments.firstIndex(of: "--snapshots"), index + 1 < CommandLine.arguments.count {
            Snapshots.run(to: URL(fileURLWithPath: CommandLine.arguments[index + 1]))
            return
        }
        #endif
        let model = AppModel()
        let router = WindowRouter(model: model)
        let status = StatusItemController(model: model, router: router)
        model.onLinkChange = { [weak status] in status?.refresh() }
        self.model = model
        self.router = router
        statusItem = status
        model.start()
        #if DEBUG
        if CommandLine.arguments.contains("--debug-menu") {
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                for title in status.debugMenuTitles() { model.trace("menu: \(title)") }
            }
        }
        if DebugArguments.run(model) { return }
        #endif
        if !model.isPaired { router.show(.welcome) }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    /// Opening the app again (Dock icon, Finder, Spotlight) brings its windows to the front, or
    /// shows the menu's main screen when none is open: the history, or Pair a phone.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard let model, let router else { return false }
        // The status item's window counts as visible: ask the router about Clipway's own windows.
        if router.hasOpenWindow { return true }
        router.show(model.isPaired ? .history : .welcome)
        return false
    }

    /// A small menu bar when Clipway is in the Dock. Without the Dock, there is no menu bar, but the
    /// key equivalents of the Edit menu (paste in the relay field, Cmd W) still need a main menu.
    static func mainMenu() -> NSMenu {
        let main = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: "Clipway")
        appMenu.addItem(withTitle: "Quit Clipway", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        main.addItem(appItem)

        let editItem = NSMenuItem()
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(.separator())
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit
        main.addItem(editItem)

        let windowItem = NSMenuItem()
        let window = NSMenu(title: "Window")
        window.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        windowItem.submenu = window
        main.addItem(windowItem)
        return main
    }
}

#if DEBUG
/// Debug builds only: `Clipway --debug-nearby-vectors [VECTORS.json]` plays the phone against the
/// Mac's nearby pairing state machine from the shared vectors, without Bluetooth, prints each
/// check and exits with 0 when all pass (mac/tools/nearby-vectors.sh). The sandbox may not let the
/// app open the file: the vectors are then read from the standard input.
enum NearbyVectorsCheck {
    static func run(path: String?) -> Int32 {
        var data = path.flatMap { FileManager.default.contents(atPath: $0) }
        if data == nil { data = FileHandle.standardInput.readDataToEndOfFile() }
        let report = NearbyReplay.run(vectors: data ?? Data())
        for line in report.lines { print(line) }
        fflush(stdout)
        return report.passed ? 0 : 1
    }
}

/// Debug builds only: launch arguments for the local end-to-end test (mac/tools/e2e.sh). They go
/// through the same code as the screens.
@MainActor
enum DebugArguments {
    /// Returns true when an argument was handled (no first-launch window then).
    static func run(_ model: AppModel) -> Bool {
        let args = CommandLine.arguments
        func value(_ flag: String) -> String? {
            guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
            return args[i + 1]
        }
        var handled = false
        if let relay = value("--debug-relay") {
            model.trace("relay: \(model.setRelay(relay) ?? "set")")
            handled = true
        }
        if args.contains("--debug-pair") {
            // Pair a phone, as the pairing window does. The words of this throwaway test chain are
            // printed so that the test can type them on the phone, as a person reads them on screen.
            if model.createChain(askNotifications: false), let keys = model.keys {
                print("clipway: debug pair words: \(keys.words.joined(separator: " "))")
                print("clipway: debug pair code: \(keys.pairingCode(relay: model.relay))")
                fflush(stdout)
            }
            handled = true
        }
        if let words = value("--debug-join") {
            model.trace("join: \(model.join(words, askNotifications: false)?.message ?? "ok")")
            handled = true
        }
        if let path = value("--debug-send-path") {
            // Send a file..., with a file the test put in ~/Downloads (the sandbox can read it).
            Task { @MainActor in
                while model.link == .connecting { try? await Task.sleep(nanoseconds: 200_000_000) }
                model.send(files: [URL(fileURLWithPath: path)])
            }
            handled = true
        }
        if let size = value("--debug-send-file").flatMap(Int.init) {
            // A file of `size` bytes (byte i = i mod 251), sent once the connection is synced.
            let content = Data((0..<size).map { UInt8($0 % 251) })
            Task { @MainActor in
                while model.link == .connecting { try? await Task.sleep(nanoseconds: 200_000_000) }
                model.send(type: .file, content: content, mime: "application/octet-stream", name: "pattern.bin", automatic: false)
            }
            handled = true
        }
        if args.contains("--debug-erase") {
            Task { @MainActor in
                let relayErased = await model.eraseEverything()
                model.trace("erased, relay confirmed: \(relayErased)")
                NSApp.terminate(nil)
            }
            handled = true
        }
        return handled
    }
}
#endif
