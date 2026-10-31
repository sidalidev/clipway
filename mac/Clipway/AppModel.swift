import AppKit
import ClipwayCore
import CryptoKit
import Observation
import SystemConfiguration
import UniformTypeIdentifiers

/// The state of the app and everything it does: pairing, the clipboard watch, sending, receiving,
/// history, settings and Erase everything. Views and the menu read it; services report to it.
@MainActor
@Observable
final class AppModel {
    enum Link: Equatable {
        case notPaired, connecting, connected, phoneOffline, unreachable, erasedElsewhere, paused
    }

    struct Note: Equatable {
        let text: String
        let at: Date
    }

    struct Hello: Equatable {
        let name: String
        let at: Date
    }

    struct UndoAction: Identifiable {
        let id = UUID()
        let label: String
        let restore: @MainActor () -> Void
    }

    enum JoinError: Error, Equatable {
        case wordCount, unknownWord, checksum, badCode, keychain

        var message: String {
            switch self {
            case .wordCount: "Type all 12 words, separated by spaces."
            case .unknownWord: "Check the words: one of them is not in the list."
            case .checksum: "These words do not form a valid key."
            case .badCode: "This pairing code is not valid."
            case .keychain: "The key could not be saved in the Keychain."
            }
        }
    }

    // MARK: Settings (UserDefaults; the key lives in the Keychain)

    var relay: String { didSet { defaults.set(relay, forKey: Keys.relay) } }
    var sendAutomatically: Bool { didSet { defaults.set(sendAutomatically, forKey: Keys.sendAutomatically) } }
    var imagesToo: Bool { didSet { defaults.set(imagesToo, forKey: Keys.imagesToo) } }
    var showInDock: Bool {
        didSet {
            defaults.set(showInDock, forKey: Keys.showInDock)
            if !isPreview { DockIcon.apply(showInDock) }
        }
    }
    /// The master switch is off: no relay connection, no automatic sending, nothing received.
    private(set) var paused: Bool
    private(set) var deviceName: String
    private(set) var deviceId: String

    // MARK: State

    private(set) var keys: ChainKeys?
    private(set) var link: Link = .notPaired
    private(set) var peerName: String?
    /// Set when the phone's hello arrives during pairing: the one celebration.
    private(set) var pairedWith: String?
    /// The last hello received, so that Pair nearby from Show the key sees its phone arrive.
    private(set) var lastHello: Hello?
    /// Pair nearby over Bluetooth (section 13), only while a window shows it.
    @ObservationIgnored private(set) var nearby = NearbyPairing()
    private(set) var history: [HistoryEntry] = []
    private(set) var note: Note?
    private(set) var lastStatus: HistoryEntry.Status?
    private(set) var relayNotice: String?
    private(set) var undo: UndoAction?
    /// Envelopes that could not be opened and items dropped by the receive rules.
    var droppedCount: Int { engine?.dropped ?? 0 }
    /// Called when the menu bar icon should change.
    @ObservationIgnored var onLinkChange: (@MainActor () -> Void)?

    @ObservationIgnored let isPreview: Bool
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let pasteboard = Pasteboard()
    @ObservationIgnored private let client = RelayClient()
    @ObservationIgnored private var engine: SyncEngine?
    /// Images and files are served from here, on the local network, never through the relay (section 14).
    @ObservationIgnored private let direct = Direct.Server()
    @ObservationIgnored private var store: HistoryStore?
    @ObservationIgnored private var echo = EchoGuard()
    @ObservationIgnored private var recency = ClipboardRecency()
    @ObservationIgnored private var thumbnails: [String: NSImage] = [:]

    enum Keys {
        static let relay = "relay"
        static let sendAutomatically = "sendAutomatically"
        static let imagesToo = "imagesToo"
        static let showInDock = DockIcon.key
        static let deviceName = "deviceName"
        static let deviceId = "deviceId"
        static let peerName = "peerName"
        static let relayChecked = "relayChecked"
        /// Set when the relay closed with 4001: the key was erased from another device.
        static let erasedElsewhere = "erasedElsewhere"
        static let paused = "paused"
    }

    static var version: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0" }

    static var isDebugBuild: Bool {
        #if DEBUG
        true
        #else
        false
        #endif
    }

    static var computerName: String {
        (SCDynamicStoreCopyComputerName(nil, nil) as String?).map { Device.cleanName($0, fallback: "Mac") } ?? "Mac"
    }

    static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    init(defaults: UserDefaults = .standard, preview: Bool = false) {
        self.defaults = defaults
        isPreview = preview
        relay = defaults.string(forKey: Keys.relay) ?? ClipwayInfo.defaultRelay
        sendAutomatically = defaults.object(forKey: Keys.sendAutomatically) as? Bool ?? true
        imagesToo = defaults.object(forKey: Keys.imagesToo) as? Bool ?? true
        showInDock = DockIcon.isOn(defaults)
        paused = defaults.bool(forKey: Keys.paused)
        deviceName = defaults.string(forKey: Keys.deviceName) ?? Self.computerName
        peerName = defaults.string(forKey: Keys.peerName)
        if let id = defaults.string(forKey: Keys.deviceId), ClipwayCrypto.isId(id) {
            deviceId = id
        } else {
            deviceId = ClipwayCrypto.randomId()
            if !preview { defaults.set(deviceId, forKey: Keys.deviceId) }
        }
    }

    var me: Device { Device(id: deviceId, name: deviceName, kind: .mac) }
    var peer: String { peerName ?? "your phone" }
    var isPaired: Bool { keys != nil }
    var relayHost: String { RelayAddress.host(relay) }
    var isDefaultRelay: Bool { relay == ClipwayInfo.defaultRelay }

    // MARK: Start

    func start() {
        Notifier.shared.setUp()
        nearby.trace = { [weak self] in self?.trace($0) }
        client.onOpen = { [weak self] in self?.engine?.connected() }
        client.onText = { [weak self] text in self?.engine?.receive(text) }
        client.onClosed = { [weak self] code in self?.connectionClosed(code) }
        client.onState = { [weak self] in self?.refreshLink() }
        pasteboard.onChange = { [weak self] board in self?.pasteboardChanged(board) }
        if !paused { pasteboard.start() }
        // The history key is created with the first chain, not before.
        if Keychain.read(Keychain.historyKey) != nil { openHistory() }
        if let secret = Keychain.read(Keychain.chain), let keys = try? ChainKeys(secret: secret) {
            if defaults.bool(forKey: Keys.erasedElsewhere) {
                // Erased from another device before the last quit: do not bring the chain back.
                self.keys = keys
                link = .erasedElsewhere
            } else {
                activate(keys)
            }
        }
        refreshLink()
    }

    private func activate(_ keys: ChainKeys) {
        self.keys = keys
        if store == nil { openHistory() }
        let state = loadState()
        recency = state.recency
        let engine = SyncEngine(keys: keys, deviceId: deviceId, cursor: state.cursor, guardian: state.guardian)
        engine.send = { [weak self] text in self?.client.send(text) }
        engine.onReceive = { [weak self] incoming in self?.handle(incoming) ?? false }
        engine.onStatus = { [weak self] item, status in self?.statusChanged(item, status) }
        engine.onPersist = { [weak self] in self?.saveState() }
        engine.onPhase = { [weak self] in self?.refreshLink() }
        engine.onPong = { [weak self] in self?.client.pong() }
        engine.onError = { [weak self] code in self?.relayError(code) }
        self.engine = engine
        connect()
    }

    private func connect() {
        guard !paused, let keys, let url = RelayAddress.webSocketURL(relay) else { return }
        client.start(url: url, protocols: keys.subprotocols)
        checkRelay(force: false)
        refreshLink()
    }

    private func connectionClosed(_ code: Int?) {
        engine?.disconnected()
        if code == 4001 {
            // The chain was erased on the relay, from another device. Remembered across restarts.
            client.stop()
            defaults.set(true, forKey: Keys.erasedElsewhere)
            link = .erasedElsewhere
            trace("link erasedElsewhere")
            onLinkChange?()
            return
        }
        refreshLink()
    }

    private func refreshLink() {
        let next: Link
        if keys == nil {
            next = .notPaired
        } else if link == .erasedElsewhere {
            next = .erasedElsewhere
        } else if paused {
            next = .paused
        } else if let engine, engine.phase == .syncing || engine.phase == .ready {
            next = engine.devices >= 2 ? .connected : .phoneOffline
        } else if client.failures >= 2 {
            next = .unreachable
        } else {
            next = .connecting
        }
        if next != link {
            link = next
            trace("link \(next)")
            onLinkChange?()
        }
    }

    var statusText: String {
        switch link {
        case .notPaired: "Not paired"
        case .connecting: "Connecting"
        case .connected: "Connected to \(peer)"
        case .phoneOffline: "Phone offline, items wait up to 24 hours"
        case .unreachable: "Relay unreachable"
        case .erasedElsewhere: "This key was erased on another device"
        case .paused: "Paused"
        }
    }

    // MARK: The master switch

    var powerLabel: String { Power.label(paused: paused) }
    var powerDetail: String { Power.detail(paused: paused, peer: peer) }

    /// Pauses everything, or turns everything back on as it was. Remembered across restarts.
    func setPaused(_ value: Bool) {
        guard value != paused else { return }
        paused = value
        defaults.set(value, forKey: Keys.paused)
        trace("paused \(value)")
        if value {
            engine?.disconnected()
            client.stop()
            pasteboard.stop()
        } else {
            pasteboard.start()
            if link != .erasedElsewhere { connect() }
        }
        refreshLink()
    }

    var lastStatusText: String? {
        switch lastStatus {
        case .sending: "Sending"
        case .sent: "Sent"
        case .waiting: "Waiting for your phone"
        case .delivered: "Delivered"
        case .failed: "Not sent"
        case .unreachable: "Not sent: not on the same network"
        case nil: nil
        }
    }

    // MARK: Pairing

    /// Pair a phone is offered: not paired yet, or the key was erased from another device.
    var needsPairing: Bool { !isPaired || link == .erasedElsewhere }

    /// Draws a new key, keeps it in the Keychain and connects. The pairing window shows it.
    @discardableResult
    func createChain(askNotifications: Bool = true) -> Bool {
        adopt(secret: ClipwayCrypto.generateSecret(), relay: nil, askNotifications: askNotifications) == nil
    }

    /// Joins with 12 words or a clipway: code.
    func join(_ text: String, askNotifications: Bool = true) -> JoinError? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.lowercased().hasPrefix(ClipwayCrypto.qrPrefix) {
            guard let code = try? ClipwayCrypto.fromQr(t) else { return .badCode }
            var relay: String?
            if let r = code.relay { relay = try? RelayAddress.normalize(r, allowLocalHTTP: Self.isDebugBuild) }
            if code.relay != nil && relay == nil { return .badCode }
            return adopt(secret: code.secret, relay: relay, askNotifications: askNotifications)
        }
        do {
            return adopt(secret: try ClipwayCrypto.fromWords(t), relay: nil, askNotifications: askNotifications)
        } catch ClipwayCrypto.Failure.wordCount {
            return .wordCount
        } catch ClipwayCrypto.Failure.unknownWord {
            return .unknownWord
        } catch {
            return .checksum
        }
    }

    /// The text of the QR code: the key, and the relay when it is not the default one.
    var pairingCode: String? { keys?.pairingCode(relay: relay) }

    /// Pair nearby is offered when the pairing code fits in its packet (a very long relay address does not).
    var canPairNearby: Bool { pairingCode.map { Nearby.fits(code: $0) } ?? false }

    /// A pairing code names a relay other than the default one.
    func relayInCode(_ text: String) -> String? {
        guard let code = try? ClipwayCrypto.fromQr(text.trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
        return code.relay
    }

    private func adopt(secret: Data, relay newRelay: String?, askNotifications: Bool = true) -> JoinError? {
        guard let keys = try? ChainKeys(secret: secret) else { return .checksum }
        do {
            try Keychain.write(Keychain.chain, secret)
        } catch {
            return .keychain
        }
        leaveChain()
        defaults.removeObject(forKey: Keys.erasedElsewhere)
        if paused {
            paused = false
            defaults.removeObject(forKey: Keys.paused)
            pasteboard.start()
        }
        if let newRelay { relay = newRelay }
        resetState()
        peerName = nil
        defaults.removeObject(forKey: Keys.peerName)
        pairedWith = nil
        link = .connecting
        activate(keys)
        sendHello()
        if askNotifications { Notifier.shared.ask() }
        return nil
    }

    /// Stops syncing without touching the Keychain.
    private func leaveChain() {
        // A nearby attempt would hand over the key being replaced.
        if let owner = nearby.owner { nearby.stop(owner: owner) }
        client.stop()
        engine = nil
        keys = nil
    }

    /// Settings > Change the key: erases the chain on the relay (the lost device keeps an empty
    /// chain), then draws a new key. The phone must pair again.
    func changeKey() async {
        let old = keys
        leaveChain()
        if let old { _ = await RelayClient.eraseChain(relay: relay, proofHex: old.proofHex) }
        createChain()
    }

    func sendHello() {
        guard let keys, let engine else { return }
        if let built = try? ItemCodec.build(keys: keys, type: .hello, device: me, ts: Self.nowMs()) {
            engine.enqueue(built)
        }
    }

    func rename(_ name: String) {
        let clean = Device.cleanName(name, fallback: Self.computerName)
        guard clean != deviceName else { return }
        deviceName = clean
        defaults.set(clean, forKey: Keys.deviceName)
        sendHello()
    }

    /// Returns an error message, or nil when the relay was changed.
    func setRelay(_ text: String) -> String? {
        let value: String
        do {
            value = try RelayAddress.normalize(text, allowLocalHTTP: Self.isDebugBuild)
        } catch RelayAddress.Problem.notHTTPS {
            return "The relay must use https://."
        } catch {
            return "This is not a relay address. Example: \(ClipwayInfo.defaultRelay)"
        }
        guard value != relay else { return nil }
        relay = value
        defaults.removeObject(forKey: Keys.relayChecked)
        relayNotice = nil
        if let keys {
            engine?.disconnected()
            resetCursor()
            client.stop()
            activate(keys)
            // The phone may only be on the new relay: say hello there too.
            sendHello()
        }
        return nil
    }

    // MARK: Clipboard watch (Mac to phone, automatic)

    private func pasteboardChanged(_ board: NSPasteboard) {
        guard Power.mayAutoSend(paired: isPaired, erased: link == .erasedElsewhere, paused: paused, sendAutomatically: sendAutomatically) else { return }
        trace("pasteboard changed")
        switch PasteboardRule.decide(pasteboard.types(), imagesToo: imagesToo) {
        case .text:
            guard let text = board.string(forType: .string), !text.isEmpty else { return }
            let bytes = Data(text.utf8)
            guard bytes.count <= ClipwayCrypto.textMax else {
                show("Too long to send: Clipway sends texts up to 64 KB")
                return
            }
            send(type: .text, content: bytes, mime: Head.textMime, automatic: true)
        case let .image(type):
            // An image goes straight to the phone, so only while it is connected: an offer lasts 2 minutes.
            guard link == .connected else {
                show("Image not sent: your phone is offline, and images go straight to it")
                return
            }
            guard let data = board.data(forType: NSPasteboard.PasteboardType(type)) else { return }
            Task {
                let png = await Task.detached(priority: .userInitiated) { Pasteboard.png(from: data, type: type) }.value
                guard let png else { return }
                guard png.count <= ClipwayCrypto.fileMax else {
                    self.show("Too large to send automatically")
                    return
                }
                self.send(type: .image, content: png, mime: "image/png", automatic: true)
            }
        case .secret:
            show("Not sent: marked as secret by the app you copied from")
            return
        case .files, .nothing:
            break
        }
    }

    // MARK: Sending

    func send(type: ItemType, content: Data, mime: String, name: String? = nil, path: String? = nil, automatic: Bool) {
        guard let keys, let engine else { return }
        let now = Self.nowMs()
        let fp = keys.fingerprint(content)
        if automatic && echo.isEcho(fp, now: now) { return }
        let item = ClipwayCrypto.randomId()
        let device = me
        // Images and files: an offer through the relay, the content straight to the phone.
        var port = 0
        var hosts: [String] = []
        if type != .text {
            let local = Direct.localHosts()
            guard !local.isEmpty else {
                show("Not sent: connect to the same Wi-Fi as your phone")
                return
            }
            hosts = Array(((Self.isDebugBuild ? ["127.0.0.1"] : []) + local).prefix(Head.hostsMax))
            do {
                let key = try Direct.transferKey(direct: keys.direct, transfer: item)
                port = try direct.offer(transfer: item, key: key, content: content) { [weak self] outcome in
                    Task { @MainActor in self?.directOutcome(item, outcome) }
                }
            } catch {
                show("Not sent: Clipway could not open the local network")
                return
            }
        }
        echo.note(fp, now: now)
        // Local first: history and the menu change before any network call.
        let entry = HistoryEntry(
            id: item, type: type, direction: .sent, device: device.name, kind: .mac, ts: now, mime: mime, name: name,
            size: content.count, fp: fp, text: type == .text ? String(decoding: content, as: UTF8.self) : nil, path: path,
            status: .sending)
        addToHistory(entry, image: type == .image ? content : nil)
        lastStatus = .sending
        let offerPort = port
        let offerHosts = hosts
        Task {
            let built = try? await Task.detached(priority: .userInitiated) {
                type == .text
                    ? try ItemCodec.build(keys: keys, type: .text, item: item, device: device, ts: now, content: content)
                    : try ItemCodec.offer(keys: keys, item: item, device: device, ts: now, media: type, mime: mime, name: name,
                                          content: content, port: offerPort, hosts: offerHosts)
            }.value
            guard let built, self.engine === engine else {
                self.direct.cancel(item, outcome: .failed)
                self.statusChanged(item, .failed)
                return
            }
            engine.enqueue(built)
        }
    }

    /// The end of a direct transfer this Mac offered (section 14.5).
    private func directOutcome(_ item: String, _ outcome: Direct.Outcome) {
        let name = history.first(where: { $0.id == item }).map { $0.name ?? ($0.type == .image ? "The image" : "The file") } ?? "The item"
        switch outcome {
        case .done:
            finishStatus(item, .delivered)
        case .unreachable:
            finishStatus(item, .unreachable)
            show("\(name) not sent: your phone isn't on the same network")
            Notifier.shared.post("\(name) not sent", body: "Your Mac and \(peer) need to be on the same network.")
        case .expired:
            finishStatus(item, .unreachable)
            show("\(name) not sent: \(peer) didn't answer")
            Notifier.shared.post("\(name) not sent", body: "\(peer.prefix(1).uppercased() + peer.dropFirst()) didn't answer. Both need to be on, with Clipway on, on the same network.")
        case .failed, .declined:
            finishStatus(item, .failed)
            show("\(name) not sent: the transfer broke")
        }
    }

    /// Send a file..., and files dropped on the menu bar icon.
    func send(files urls: [URL]) {
        guard isPaired else { return }
        guard Power.maySend(paired: true, erased: link == .erasedElsewhere, paused: paused) else {
            show("Clipway is paused. Turn it on to send.")
            return
        }
        for url in urls {
            let values = try? url.resourceValues(forKeys: [.fileSizeKey, .isDirectoryKey, .contentTypeKey])
            if values?.isDirectory == true {
                show("Folders are not sent. Send the files inside.")
                continue
            }
            guard (values?.fileSize ?? 0) <= ClipwayCrypto.fileMax else {
                show("Too large: Clipway sends up to 25 MB")
                continue
            }
            guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
                show("This file could not be read")
                continue
            }
            var mime = values?.contentType?.preferredMIMEType?.lowercased() ?? "application/octet-stream"
            if !Head.isMime(mime) { mime = "application/octet-stream" }
            var name = url.lastPathComponent
            while name.unicodeScalars.count > Head.nameMax { name.removeFirst() }
            send(type: .file, content: data, mime: mime, name: name, path: url.path, automatic: false)
        }
    }

    private func statusChanged(_ item: String, _ status: HistoryEntry.Status) {
        // An offer is delivered when the phone fetched it directly, not when the relay passed it on.
        if direct.isOpen(item) && status != .waiting && status != .failed { return }
        finishStatus(item, status)
    }

    private func finishStatus(_ item: String, _ status: HistoryEntry.Status) {
        trace("sent item \(item.prefix(6)): \(status.rawValue)")
        store?.update(item) { $0.status = status }
        if let store { history = store.entries }
        if history.first(where: { $0.direction == .sent })?.id == item { lastStatus = status }
    }

    private func relayError(_ code: String) {
        switch code {
        case "rate_limited": show("Sending too fast: the relay will take it in a moment")
        case "quota", "busy": show("The relay is full: trying again soon")
        case "too_big": show("Not sent: the relay carries texts of 64 KB at most")
        default: break
        }
    }

    // MARK: Receiving (phone to Mac)

    /// Writes one received item. Returns false when it could not be written (no ack, it comes back).
    private func handle(_ incoming: SyncEngine.Incoming) -> Bool {
        let head = incoming.head
        trace("received \(head.type.rawValue), \(incoming.content?.count ?? 0) bytes, seq \(incoming.seq)")
        if head.device.kind == .android || head.type == .hello {
            learnPeer(head.device.name, hello: head.type == .hello)
        }
        switch head.type {
        case .reply:
            let outcome: Direct.Outcome = switch head.status {
            case "done": .done
            case "unreachable": .unreachable
            case "declined": .declined
            default: .failed
            }
            if let offer = head.offer { direct.cancel(offer, outcome: outcome) }
            return true
        case .offer:
            fetch(head)
            return true
        default:
            break
        }
        guard head.type == .text, let content = incoming.content else { return true }
        return receive(head, type: .text, content: content)
    }

    /// Fetches an offered image or file from the phone, off the main thread (section 14). If it
    /// cannot, says so here and answers the phone through the relay.
    private func fetch(_ head: Head) {
        guard let keys else { return }
        let media = head.media ?? .file
        let label = head.name ?? (media == .image ? "an image" : "a file")
        let debug = Self.isDebugBuild
        trace("fetching \(media.rawValue) directly, \(head.size ?? 0) bytes")
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = Direct.fetch(keys: keys, head: head, debug: debug) { content in
                let saved = DispatchQueue.main.sync {
                    MainActor.assumeIsolated { self?.receive(head, type: media, content: content) ?? false }
                }
                if !saved { throw Direct.Failure.request }
            }
            await MainActor.run { self?.fetched(head, label: label, result: result) }
        }
    }

    private func fetched(_ head: Head, label: String, result: Direct.Fetched) {
        let from = head.device.name
        let status: String
        switch result {
        case .ok:
            trace("fetched directly")
            return
        case .unreachable:
            status = "unreachable"
            show("Couldn't receive \(label) from \(from): not on the same network")
            Notifier.shared.post("Couldn't receive \(label) from \(from)", body: "Your Mac and \(from) need to be on the same network.")
        case .failed:
            status = "failed"
            show("Couldn't receive \(label) from \(from)")
            Notifier.shared.post("Couldn't receive \(label) from \(from)", body: "The transfer broke. Ask for it again.")
        }
        trace("direct transfer \(status)")
        guard let keys, let engine, let reply = try? ItemCodec.reply(keys: keys, device: me, ts: Self.nowMs(), offer: head.item, status: status) else { return }
        engine.enqueue(reply)
    }

    /// Writes a text, or an image or a file fetched directly: clipboard or Downloads, history, notification.
    private func receive(_ head: Head, type: ItemType, content: Data) -> Bool {
        let now = Self.nowMs()
        echo.note(head.fp ?? "", now: now)
        var entry = HistoryEntry(
            id: head.item, type: type, direction: .received, device: head.device.name, kind: head.device.kind, ts: head.ts,
            mime: head.mime ?? "application/octet-stream", name: head.name, size: content.count, fp: head.fp ?? "")
        switch type {
        case .text:
            let text = String(decoding: content, as: UTF8.self)
            entry.text = text
            if recency.shouldWrite(ts: head.ts, now: now) {
                pasteboard.write(text: text)
                Notifier.shared.post("Copied from \(head.device.name)")
            }
            addToHistory(entry, image: nil)
        case .image:
            if recency.shouldWrite(ts: head.ts, now: now) {
                pasteboard.write(image: content, mime: entry.mime)
                Notifier.shared.post("Copied from \(head.device.name)")
            }
            addToHistory(entry, image: content)
        case .file:
            do {
                let url = try saveFile(content, name: head.name ?? "file")
                entry.path = url.path
                entry.name = url.lastPathComponent
                Notifier.shared.post("Received \(url.lastPathComponent) from \(head.device.name)", body: "In Downloads, Clipway folder",
                                     reveal: url.path)
            } catch {
                show("A file from \(head.device.name) could not be saved in Downloads")
                return false
            }
            addToHistory(entry, image: nil)
        case .hello, .offer, .reply:
            break
        }
        saveState()
        return true
    }

    private func learnPeer(_ name: String, hello: Bool) {
        if peerName != name {
            peerName = name
            defaults.set(name, forKey: Keys.peerName)
        }
        if hello { lastHello = Hello(name: name, at: Date()) }
        if hello && pairedWith == nil {
            pairedWith = name
            Haptics.success()
        }
        onLinkChange?()
    }

    /// ~/Downloads/Clipway/<sanitized name>, " 2", " 3"... on a collision, quarantined.
    private func saveFile(_ content: Data, name: String) throws -> URL {
        let folder = Places.downloads
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let clean = FileNames.unique(FileNames.sanitize(name)) {
            FileManager.default.fileExists(atPath: folder.appendingPathComponent($0).path)
        }
        var url = folder.appendingPathComponent(clean)
        try content.write(to: url, options: .withoutOverwriting)
        var values = URLResourceValues()
        values.quarantineProperties = [
            kLSQuarantineAgentNameKey as String: "Clipway",
            kLSQuarantineTypeKey as String: kLSQuarantineTypeOtherDownload as String,
        ]
        try? url.setResourceValues(values)
        return url
    }

    // MARK: History

    private func openHistory() {
        var keyData = Keychain.read(Keychain.historyKey)
        if keyData?.count != 32 {
            let fresh = ClipwayCrypto.randomBytes(32)
            try? Keychain.write(Keychain.historyKey, fresh)
            keyData = fresh
        }
        guard let keyData else { return }
        let store = HistoryStore(directory: Places.support, key: SymmetricKey(data: keyData))
        history = store.load()
        self.store = store
    }

    private func addToHistory(_ entry: HistoryEntry, image: Data?) {
        if store == nil { openHistory() }
        guard let store else { return }
        try? store.add(entry, image: image)
        history = store.entries
    }

    func imageData(_ entry: HistoryEntry) -> Data? { entry.hasImage ? store?.image(entry.id) : nil }

    func thumbnail(_ entry: HistoryEntry, size: CGFloat) -> NSImage? {
        let key = "\(entry.id)-\(Int(size))"
        if let cached = thumbnails[key] { return cached }
        guard let data = imageData(entry), let image = NSImage(data: data) else { return nil }
        let scale = size / max(image.size.width, image.size.height, 1)
        let target = NSSize(width: max(1, image.size.width * scale), height: max(1, image.size.height * scale))
        let small = NSImage(size: target, flipped: false) { rect in
            image.draw(in: rect)
            return true
        }
        thumbnails[key] = small
        return small
    }

    /// Click on a row: texts and images go back to the clipboard (as our own write, so they are
    /// not sent again); files are shown in Finder.
    func use(_ entry: HistoryEntry) {
        switch entry.type {
        case .text:
            guard let text = entry.text else { return }
            pasteboard.write(text: text)
            show("Copied")
        case .image:
            guard let data = imageData(entry) else { return }
            pasteboard.write(image: data, mime: entry.mime)
            show("Copied")
        case .file:
            if let path = entry.path, FileManager.default.fileExists(atPath: path) {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
            } else {
                show("This file is no longer where it was saved")
            }
        case .hello, .offer, .reply:
            break
        }
    }

    func delete(_ entry: HistoryEntry) {
        guard let store, let removed = store.remove(entry.id) else { return }
        history = store.entries
        offerUndo("Item deleted") { [weak self] in
            store.restore([removed])
            self?.history = store.entries
        }
    }

    func clearHistory() {
        guard let store, !store.entries.isEmpty else { return }
        let all = store.clear()
        history = []
        thumbnails = [:]
        offerUndo("History cleared") { [weak self] in
            store.restore(all)
            self?.history = store.entries
        }
    }

    func undoLast() {
        undo?.restore()
        undo = nil
    }

    private func offerUndo(_ label: String, restore: @escaping @MainActor () -> Void) {
        let action = UndoAction(label: label, restore: restore)
        undo = action
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(Tokens.Motion.undoSeconds * 1_000_000_000))
            if self.undo?.id == action.id { self.undo = nil }
        }
    }

    func exportHistory(to url: URL) throws {
        guard let store else { return }
        try store.exportZip().write(to: url, options: .atomic)
    }

    // MARK: Erase everything

    /// Asks the relay to erase the chain, destroys the key and the history key (the history files
    /// become unreadable), deletes the history and the settings, and goes back to the first launch.
    /// Returns whether the relay confirmed.
    func eraseEverything() async -> Bool {
        let erasing = keys
        let relayAddress = relay
        leaveChain()
        var relayErased = false
        if let erasing {
            relayErased = await RelayClient.eraseChain(relay: relayAddress, proofHex: erasing.proofHex)
        }
        Keychain.delete(Keychain.chain)
        Keychain.delete(Keychain.historyKey)
        store?.wipe()
        store = nil
        try? FileManager.default.removeItem(at: Places.support)
        if LoginItem.isOn { LoginItem.set(false) }
        if let id = Bundle.main.bundleIdentifier { defaults.removePersistentDomain(forName: id) }
        history = []
        thumbnails = [:]
        peerName = nil
        pairedWith = nil
        note = nil
        lastStatus = nil
        relayNotice = nil
        undo = nil
        echo = EchoGuard()
        recency = ClipboardRecency()
        relay = ClipwayInfo.defaultRelay
        sendAutomatically = true
        imagesToo = true
        if paused {
            paused = false
            pasteboard.start()
        }
        deviceName = Self.computerName
        deviceId = ClipwayCrypto.randomId()
        defaults.set(deviceId, forKey: Keys.deviceId)
        link = .notPaired
        onLinkChange?()
        return relayErased
    }

    // MARK: Relay status (once a day and when the relay changes)

    func checkRelay(force: Bool) {
        let last = defaults.double(forKey: Keys.relayChecked)
        guard force || Date().timeIntervalSince1970 - last > 86_400 else { return }
        let address = relay
        Task {
            guard let status = await RelayClient.relayStatus(relay: address), address == self.relay else { return }
            self.defaults.set(Date().timeIntervalSince1970, forKey: Keys.relayChecked)
            if let min = status.minMac, Version.isLower(Self.version, than: min) {
                self.relayNotice = "Update Clipway: this relay needs version \(min) or later."
            } else if status.status == "end-of-service" {
                self.relayNotice = "This relay is closing. Choose another one in Settings."
            } else if status.status != "ok" {
                self.relayNotice = "The relay reports a problem. Items may be slow."
            } else {
                self.relayNotice = nil
            }
        }
    }

    // MARK: Notes in the menu

    func show(_ text: String) {
        note = Note(text: text, at: Date())
        trace("note: \(text)")
    }

    /// Debug builds print events (never content) for the local end-to-end test.
    func trace(_ text: @autoclosure () -> String) {
        #if DEBUG
        print("clipway: \(text())")
        fflush(stdout)
        #endif
    }

    var currentNote: String? {
        guard let note, Date().timeIntervalSince(note.at) < Tokens.Motion.noteSeconds else { return nil }
        return note.text
    }

    // MARK: Saved state: (epoch, after), seen item ids, the newest clipboard write

    private struct SavedState: Codable {
        var cursor = SyncEngine.Cursor()
        var guardian = ReceiveGuard()
        var recency = ClipboardRecency()
    }

    private var stateURL: URL { Places.support.appendingPathComponent("state.json") }

    private func loadState() -> SavedState {
        guard let data = try? Data(contentsOf: stateURL), let state = try? JSONDecoder().decode(SavedState.self, from: data) else {
            return SavedState()
        }
        return state
    }

    private func saveState() {
        guard !isPreview, let engine else { return }
        let state = SavedState(cursor: engine.cursor, guardian: engine.guardian, recency: recency)
        try? FileManager.default.createDirectory(at: Places.support, withIntermediateDirectories: true)
        try? JSONEncoder().encode(state).write(to: stateURL, options: .atomic)
    }

    private func resetState() {
        try? FileManager.default.removeItem(at: stateURL)
        recency = ClipboardRecency()
    }

    private func resetCursor() {
        var state = loadState()
        state.cursor = SyncEngine.Cursor()
        try? JSONEncoder().encode(state).write(to: stateURL, options: .atomic)
    }

    // MARK: Previews (screenshots)

    #if DEBUG
    static func preview(linked: Bool = true, pairedWith: String? = nil, nearby: NearbyPairing.Screen? = nil) -> AppModel {
        let suite = UserDefaults(suiteName: "dev.sidali.clipway.preview")!
        suite.removePersistentDomain(forName: "dev.sidali.clipway.preview")
        let model = AppModel(defaults: suite, preview: true)
        model.deviceName = "MacBook Air"
        if let nearby { model.nearby = NearbyPairing.preview(nearby) }
        guard linked else { return model }
        model.keys = try? ChainKeys(secret: ClipwayCrypto.fromHex("000102030405060708090a0b0c0d0e0f"))
        model.link = .connected
        model.peerName = "Pixel 10 Pro"
        model.pairedWith = pairedWith
        model.lastStatus = .delivered
        let now = nowMs()
        model.history = [
            HistoryEntry(id: ClipwayCrypto.randomId(), type: .text, direction: .received, device: "Pixel 10 Pro", kind: .android,
                         ts: now - 40_000, mime: "text/plain", size: 41, fp: "", text: "Meeting moved to 3 pm, room 2B on the left"),
            HistoryEntry(id: ClipwayCrypto.randomId(), type: .file, direction: .received, device: "Pixel 10 Pro", kind: .android,
                         ts: now - 300_000, mime: "application/pdf", name: "Boarding pass.pdf", size: 182_000, fp: ""),
            HistoryEntry(id: ClipwayCrypto.randomId(), type: .text, direction: .sent, device: "MacBook Air", kind: .mac,
                         ts: now - 900_000, mime: "text/plain", size: 36, fp: "", text: "https://sidali.dev/apps", status: .delivered),
            HistoryEntry(id: ClipwayCrypto.randomId(), type: .image, direction: .sent, device: "MacBook Air", kind: .mac,
                         ts: now - 3_600_000, mime: "image/png", name: nil, size: 245_000, fp: "", status: .delivered),
        ]
        return model
    }
    #endif
}
