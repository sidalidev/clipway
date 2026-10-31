import AppKit
import ClipwayCore

/// The menu bar icon and its menu (docs/PROTOCOL.md, section 7). The menu is rebuilt each time it
/// opens, from the model. Files dropped on the icon are sent.
@MainActor
final class StatusItemController: NSObject, NSMenuDelegate, NSWindowDelegate, NSDraggingDestination {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let model: AppModel
    private let router: WindowRouter
    private let menu = NSMenu()

    init(model: AppModel, router: WindowRouter) {
        self.model = model
        self.router = router
        super.init()
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        item.button?.toolTip = "Clipway"
        item.button?.setAccessibilityLabel("Clipway")
        if let window = item.button?.window {
            window.registerForDraggedTypes([.fileURL])
            window.delegate = self
        }
        refresh()
    }

    func refresh() {
        // The arrows of the icon; dimmed when the phone is not connected, a pause sign when paused.
        let label = model.link == .paused ? "Clipway, paused" : "Clipway"
        let image: NSImage?
        if model.link == .paused {
            image = NSImage(systemSymbolName: "pause.circle", accessibilityDescription: label)
            image?.isTemplate = true
        } else {
            image = Glyphs.statusIcon(dimmed: model.link != .connected, label: label)
        }
        item.button?.image = image
        item.button?.toolTip = label
        item.button?.setAccessibilityLabel(label)
        item.button?.appearsDisabled = model.link != .connected && model.link != .phoneOffline && model.link != .paused
    }

    // MARK: Menu

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        if model.isPaired && model.link != .erasedElsewhere {
            // The master switch comes first: one click pauses everything, one click brings it back.
            let power = NSMenuItem()
            let view = PowerMenuView(paused: model.paused, detail: model.powerDetail)
            view.onChange = { [weak self] paused in
                Haptics.tap()
                self?.model.setPaused(paused)
                self?.menu.cancelTracking()
            }
            power.view = view
            menu.addItem(power)
            menu.addItem(.separator())
        }
        if model.link != .paused { menu.addItem(info(model.statusText, symbol: statusSymbol)) }
        if let notice = model.relayNotice { menu.addItem(info(notice, symbol: "exclamationmark.triangle")) }
        if let note = model.currentNote {
            menu.addItem(info(note, symbol: "info.circle"))
        } else if let last = model.lastStatusText, model.isPaired {
            menu.addItem(info("Last item: \(last)", symbol: "arrow.up.circle"))
        }
        menu.addItem(.separator())

        if model.link == .erasedElsewhere {
            menu.addItem(action("Pair a phone…", #selector(pair)))
            menu.addItem(action("Join with 12 words…", #selector(join)))
            menu.addItem(.separator())
        }
        if model.isPaired {
            let recent = Array(model.history.prefix(10))
            if recent.isEmpty {
                menu.addItem(info("Copy something: it goes to \(model.peer)", symbol: nil))
            } else {
                menu.addItem(NSMenuItem.sectionHeader(title: "Recent"))
                for (index, entry) in recent.enumerated() {
                    let row = action(title(for: entry), #selector(useEntry(_:)), key: index < 9 ? "\(index + 1)" : "")
                    row.representedObject = entry.id
                    row.image = icon(for: entry)
                    row.toolTip = "\(entry.direction == .sent ? "Sent" : "From \(entry.device)"), \(relative(entry.ts))"
                    menu.addItem(row)
                }
            }
            menu.addItem(.separator())
            let auto = action("Send automatically", #selector(toggleSend))
            auto.state = model.sendAutomatically ? .on : .off
            menu.addItem(auto)
            let images = action("Images too", #selector(toggleImages))
            images.state = model.imagesToo ? .on : .off
            images.isEnabled = model.sendAutomatically
            images.indentationLevel = 1
            menu.addItem(images)
            let sendFile = action("Send a file…", #selector(sendFile), key: "o")
            sendFile.isEnabled = !model.paused
            menu.addItem(sendFile)
            menu.addItem(action("History…", #selector(openHistory), key: "y"))
            menu.addItem(.separator())
            menu.addItem(action("Show the key…", #selector(showKey)))
        } else {
            menu.addItem(action("Pair a phone…", #selector(pair)))
            menu.addItem(action("Join with 12 words…", #selector(join)))
        }
        menu.addItem(action("Settings…", #selector(openSettings), key: ","))
        menu.addItem(.separator())
        menu.addItem(action("About Clipway", #selector(openAbout)))
        menu.addItem(action("What leaves your device", #selector(openWhatLeaves)))
        menu.addItem(.separator())
        menu.addItem(action("Quit Clipway", #selector(quit), key: "q"))
    }

    private var statusSymbol: String {
        switch model.link {
        case .connected: "checkmark.circle.fill"
        case .phoneOffline: "moon.zzz"
        case .connecting: "arrow.triangle.2.circlepath"
        case .unreachable: "wifi.exclamationmark"
        case .notPaired: "iphone.slash"
        case .erasedElsewhere: "xmark.octagon"
        case .paused: "pause.circle"
        }
    }

    private func info(_ text: String, symbol: String?) -> NSMenuItem {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.isEnabled = false
        if let symbol { item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil) }
        return item
    }

    private func action(_ title: String, _ selector: Selector, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        item.target = self
        item.isEnabled = true
        return item
    }

    private func title(for entry: HistoryEntry) -> String {
        let limit = Tokens.Typography.menuPreviewLength
        switch entry.type {
        case .text:
            let preview = entry.contentRemoved ? "Content removed to save space" : entry.preview
            return preview.count > limit ? String(preview.prefix(limit - 1)) + "…" : preview
        case .image: return entry.contentRemoved ? "Image, removed to save space" : "Image, \(Self.bytes(entry.size))"
        case .file: return "\(entry.name ?? "File"), \(Self.bytes(entry.size))"
        case .hello, .offer, .reply: return entry.device
        }
    }

    private func icon(for entry: HistoryEntry) -> NSImage? {
        if entry.type == .image, let thumb = model.thumbnail(entry, size: Tokens.Size.menuThumbnail) { return thumb }
        let symbol = entry.type == .file ? "doc" : entry.type == .image ? "photo" : (entry.direction == .sent ? "arrow.up.right" : "arrow.down.left")
        return NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
    }

    private func relative(_ ts: Int64) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: "en_US")
        formatter.unitsStyle = .full
        return formatter.localizedString(for: Date(timeIntervalSince1970: Double(ts) / 1000), relativeTo: Date())
    }

    static func bytes(_ count: Int) -> String {
        let f = ByteCountFormatter()
        f.countStyle = .file
        return f.string(fromByteCount: Int64(count))
    }

    #if DEBUG
    /// The menu as it would open now, for tools/e2e.sh.
    func debugMenuTitles() -> [String] {
        menuNeedsUpdate(menu)
        return menu.items.map { $0.isSeparatorItem ? "---" : ($0.view as? PowerMenuView)?.debugTitle ?? $0.title }
    }
    #endif

    // MARK: Actions

    @objc private func useEntry(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String, let entry = model.history.first(where: { $0.id == id }) else { return }
        model.use(entry)
    }

    @objc private func toggleSend() { model.sendAutomatically.toggle() }
    @objc private func toggleImages() { model.imagesToo.toggle() }
    @objc private func openHistory() { router.show(.history) }
    @objc private func showKey() { router.show(.key) }
    @objc private func pair() { router.show(.welcome) }
    @objc private func join() { router.show(.join) }
    @objc private func openSettings() { router.show(.settings) }
    @objc private func openAbout() { router.show(.about) }
    @objc private func openWhatLeaves() { router.show(.whatLeaves) }
    @objc private func quit() { NSApp.terminate(nil) }

    @objc private func sendFile() {
        NSApp.activate()
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Send"
        panel.message = "Choose files to send straight to \(model.peer), on the same network. Up to 25 MB each."
        if panel.runModal() == .OK { model.send(files: panel.urls) }
    }

    // MARK: Drop files on the icon

    func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        guard model.isPaired, !fileURLs(sender).isEmpty else { return [] }
        item.button?.highlight(true)
        return .copy
    }

    func draggingExited(_ sender: NSDraggingInfo?) {
        item.button?.highlight(false)
    }

    func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        item.button?.highlight(false)
        let urls = fileURLs(sender)
        guard model.isPaired, !urls.isEmpty else { return false }
        model.send(files: urls)
        Haptics.success()
        return true
    }

    private func fileURLs(_ sender: NSDraggingInfo) -> [URL] {
        sender.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
    }
}

/// The first row of the menu: "Clipway", On or Paused, a switch, and one sentence on what it does.
/// The whole row is one switch for VoiceOver, read as "Clipway, On" or "Clipway, Paused".
@MainActor
final class PowerMenuView: NSView {
    var onChange: ((_ paused: Bool) -> Void)?
    private let paused: Bool
    private let toggle = NSSwitch()

    init(paused: Bool, detail: String) {
        self.paused = paused
        super.init(frame: NSRect(x: 0, y: 0, width: Tokens.Size.menuSwitchWidth, height: 1))
        let title = NSTextField(labelWithString: "Clipway")
        title.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .semibold)
        let state = NSTextField(labelWithString: Power.label(paused: paused))
        state.font = .systemFont(ofSize: NSFont.systemFontSize)
        state.textColor = paused ? .secondaryLabelColor : .systemGreen
        toggle.state = paused ? .off : .on
        toggle.controlSize = .small
        toggle.target = self
        toggle.action = #selector(flip)
        let text = NSTextField(wrappingLabelWithString: detail)
        text.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        text.textColor = .secondaryLabelColor
        text.preferredMaxLayoutWidth = Tokens.Size.menuSwitchWidth - 2 * Tokens.Space.l
        for v in [title, state, text] { v.setAccessibilityElement(false) }

        let top = NSStackView(views: [title, NSView(), state, toggle])
        top.orientation = .horizontal
        top.spacing = Tokens.Space.s
        let stack = NSStackView(views: [top, text])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = Tokens.Space.xs
        stack.edgeInsets = NSEdgeInsets(top: Tokens.Space.xs, left: Tokens.Space.l, bottom: Tokens.Space.xs, right: Tokens.Space.l)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor),
            stack.topAnchor.constraint(equalTo: topAnchor),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor),
            top.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -2 * Tokens.Space.l),
            widthAnchor.constraint(equalToConstant: Tokens.Size.menuSwitchWidth),
        ])
        setFrameSize(NSSize(width: Tokens.Size.menuSwitchWidth, height: fittingSize.height))

        toggle.setAccessibilityLabel("Clipway")
        toggle.setAccessibilityValueDescription(Power.label(paused: paused))
        toggle.setAccessibilityHelp(detail)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    var debugTitle: String { "Clipway: \(Power.label(paused: paused))" }

    @objc private func flip() { onChange?(toggle.state == .off) }

    /// A click anywhere on the row flips the switch too.
    override func mouseUp(with event: NSEvent) {
        toggle.state = toggle.state == .on ? .off : .on
        flip()
    }
}
