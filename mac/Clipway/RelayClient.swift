import AppKit
import ClipwayCore
import Foundation
import Network

/// One WebSocket to the relay (URLSessionWebSocketTask), authenticated by the proof in the
/// subprotocols, with reconnection: 1 s, 2 s, 4 s... 60 s plus up to 20 % random, and at once when
/// the network comes back or the Mac wakes. Application ping every 60 s, pong expected within 20 s.
@MainActor
final class RelayClient {
    enum State: Equatable { case idle, connecting, open }

    static let pingEvery: TimeInterval = 60
    static let pongWithin: TimeInterval = 20
    static let maxBackoff: TimeInterval = 60

    private(set) var state: State = .idle
    /// Failed attempts in a row (reset when a connection opens).
    private(set) var failures = 0

    var onOpen: (@MainActor () -> Void)?
    var onText: (@MainActor (String) -> Void)?
    /// The connection closed or failed: the close code when there was one.
    var onClosed: (@MainActor (Int?) -> Void)?
    var onState: (@MainActor () -> Void)?

    private var url: URL?
    private var protocols: [String] = []
    private var running = false
    private var task: URLSessionWebSocketTask?
    /// The task that failed last: its close code may arrive after the failure.
    private var lastFailedTask: Int?
    private var generation = 0
    private var retry: Task<Void, Never>?
    private var heartbeat: Task<Void, Never>?
    private var awaitingPong = false
    private let events = SocketEvents()
    private lazy var session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.httpAdditionalHeaders = Self.headers
        config.waitsForConnectivity = false
        // Above the 60 s application ping: an idle socket is not timed out between pings.
        config.timeoutIntervalForRequest = 120
        return URLSession(configuration: config, delegate: events, delegateQueue: nil)
    }()
    private let monitor = NWPathMonitor()
    private var wakeObserver: NSObjectProtocol?

    /// A fixed User-Agent and language: the relay learns nothing about this Mac from headers.
    static let headers: [String: String] = [
        "User-Agent": "Clipway-mac/\(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0")",
        "Accept-Language": "en",
    ]

    init() {
        events.onOpen = { [weak self] id in Task { @MainActor in self?.opened(id) } }
        events.onClose = { [weak self] id, code in Task { @MainActor in self?.closed(id, code: code) } }
        monitor.pathUpdateHandler = { [weak self] path in
            let up = path.status == .satisfied
            Task { @MainActor in self?.networkChanged(up: up) }
        }
        monitor.start(queue: DispatchQueue(label: "dev.sidali.clipway.path"))
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.reconnectNow() }
        }
    }

    func start(url: URL, protocols: [String]) {
        self.url = url
        self.protocols = protocols
        running = true
        failures = 0
        connect()
    }

    func stop() {
        running = false
        retry?.cancel()
        heartbeat?.cancel()
        generation += 1
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        set(.idle)
    }

    /// Drops the current connection (if any) and connects again now.
    func reconnectNow() {
        guard running else { return }
        retry?.cancel()
        generation += 1
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        failures = 0
        connect()
    }

    func send(_ text: String) {
        guard state == .open, let task else { return }
        let gen = generation
        task.send(.string(text)) { [weak self] error in
            guard error != nil else { return }
            Task { @MainActor in self?.failed(gen, code: nil) }
        }
    }

    /// The relay answered a ping.
    func pong() { awaitingPong = false }

    // MARK: Internals

    private func set(_ s: State) {
        guard state != s else { return }
        state = s
        onState?()
    }

    private func connect() {
        guard running, let url else { return }
        generation += 1
        let gen = generation
        let task = session.webSocketTask(with: url, protocols: protocols)
        // Frames are up to 128 KiB (one item, a 64 KB text at most); room is left above.
        task.maximumMessageSize = 4 * RelayFrame.maxFrame
        self.task = task
        events.current = task.taskIdentifier
        set(.connecting)
        task.resume()
        receive(task, gen)
    }

    private func receive(_ task: URLSessionWebSocketTask, _ gen: Int) {
        task.receive { [weak self] result in
            Task { @MainActor in
                guard let self, gen == self.generation else { return }
                switch result {
                case let .success(message):
                    if case let .string(text) = message {
                        self.awaitingPong = false
                        self.onText?(text)
                    }
                    self.receive(task, gen)
                case .failure:
                    let code = task.closeCode == .invalid ? nil : task.closeCode.rawValue
                    self.failed(gen, code: code)
                }
            }
        }
    }

    private func opened(_ id: Int) {
        guard id == task?.taskIdentifier else { return }
        failures = 0
        set(.open)
        startHeartbeat()
        onOpen?()
    }

    private func closed(_ id: Int, code: Int) {
        if id == task?.taskIdentifier {
            failed(generation, code: code)
        } else if id == lastFailedTask, code == 4001, running {
            // The failed receive can come before the close frame: a late "chain erased" still stops.
            retry?.cancel()
            onClosed?(code)
        }
    }

    private func failed(_ gen: Int, code: Int?) {
        guard gen == generation else { return }
        generation += 1
        lastFailedTask = task?.taskIdentifier
        heartbeat?.cancel()
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        set(.idle)
        onClosed?(code)
        guard running else { return }
        failures += 1
        let base = min(Self.maxBackoff, pow(2, Double(failures - 1)))
        let delay = base * (1 + Double.random(in: 0...0.2))
        retry?.cancel()
        retry = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            self?.connect()
        }
    }

    private func startHeartbeat() {
        heartbeat?.cancel()
        let gen = generation
        heartbeat = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(Self.pingEvery * 1_000_000_000))
                guard let self, !Task.isCancelled, gen == self.generation, self.state == .open else { return }
                self.awaitingPong = true
                self.send(RelayFrame.ping)
                try? await Task.sleep(nanoseconds: UInt64(Self.pongWithin * 1_000_000_000))
                guard !Task.isCancelled, gen == self.generation else { return }
                if self.awaitingPong {
                    self.failed(gen, code: nil)
                    return
                }
            }
        }
    }

    private func networkChanged(up: Bool) {
        guard running, up, state != .open else { return }
        reconnectNow()
    }

    // MARK: HTTP

    /// DELETE /chain with the proof: erases what the relay holds for the chain. Best effort.
    static func eraseChain(relay: String, proofHex: String) async -> Bool {
        guard let url = RelayAddress.httpURL(relay, path: "/chain") else { return false }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 8)
        request.httpMethod = "DELETE"
        request.setValue(proofHex, forHTTPHeaderField: "X-Clipway-Proof")
        let config = URLSessionConfiguration.ephemeral
        config.httpAdditionalHeaders = headers
        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }
        guard let (_, response) = try? await session.data(for: request) else { return false }
        return (response as? HTTPURLResponse)?.statusCode == 204
    }

    struct RelayStatus: Sendable {
        let status: String
        let minMac: String?
    }

    /// GET /.well-known/clipway-relay.json: the relay's status and the oldest Mac app it accepts.
    static func relayStatus(relay: String) async -> RelayStatus? {
        guard let url = RelayAddress.httpURL(relay, path: "/.well-known/clipway-relay.json") else { return nil }
        let config = URLSessionConfiguration.ephemeral
        config.httpAdditionalHeaders = headers
        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }
        guard let (data, _) = try? await session.data(from: url),
              let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        let min = (o["minClient"] as? [String: Any])?["mac"] as? String
        return RelayStatus(status: o["status"] as? String ?? "ok", minMac: min)
    }
}

/// URLSession delegate callbacks, forwarded to the client on the main actor.
private final class SocketEvents: NSObject, URLSessionWebSocketDelegate, @unchecked Sendable {
    var onOpen: (@Sendable (Int) -> Void)?
    var onClose: (@Sendable (Int, Int) -> Void)?
    var current = 0

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        onOpen?(webSocketTask.taskIdentifier)
    }

    func urlSession(
        _ session: URLSession, webSocketTask: URLSessionWebSocketTask,
        didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?
    ) {
        onClose?(webSocketTask.taskIdentifier, closeCode.rawValue)
    }
}
