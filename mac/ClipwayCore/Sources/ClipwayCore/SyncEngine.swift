import Foundation

/// The client side of the relay protocol (docs/PROTOCOL.md, sections 4 and 5), without the socket:
/// the app feeds it the frames it receives and gives it a way to send. Testable without a network.
@MainActor
public final class SyncEngine {
    public enum Phase: Equatable, Sendable {
        case offline
        /// Socket open, waiting for welcome.
        case handshake
        /// sync sent, receiving the backlog.
        case syncing
        /// synced: items can be sent.
        case ready
    }

    /// (epoch, after), saved by the app (section 4.3).
    public struct Cursor: Codable, Equatable, Sendable {
        public var epoch: String
        public var after: Int
        public init(epoch: String = "", after: Int = 0) {
            self.epoch = epoch
            self.after = after
        }
    }

    /// A received item, opened and checked, for the app to write (clipboard, file, history).
    public struct Incoming: Sendable {
        public let seq: Int
        public let head: Head
        public let content: Data?
    }

    struct Outgoing {
        let item: String
        let envelopes: [ClipwayCrypto.Envelope]
        let isHello: Bool
        var ref: Int?
        var retryAt: Int64 = 0
    }

    public static let outboxMax = 50
    public static let retryDelayMs: Int64 = 30_000

    public let keys: ChainKeys
    public let deviceId: String
    public private(set) var cursor: Cursor
    public private(set) var guardian: ReceiveGuard
    public private(set) var phase: Phase = .offline
    /// Open connections of the chain, this one included (welcome, presence).
    public private(set) var devices = 0
    /// Envelopes that could not be opened or items dropped by the receive rules (Diagnostics).
    public private(set) var dropped = 0

    /// Sends one text frame on the current connection.
    public var send: (@MainActor (String) -> Void)?
    /// Writes a received item. Returns false when it could not be written: no ack, it comes back later.
    public var onReceive: (@MainActor (Incoming) -> Bool)?
    /// Status of an item sent by this device: sent, waiting, delivered, failed.
    public var onStatus: (@MainActor (String, HistoryEntry.Status) -> Void)?
    /// cursor or guardian changed: save them.
    public var onPersist: (@MainActor () -> Void)?
    public var onPhase: (@MainActor () -> Void)?
    public var onPong: (@MainActor () -> Void)?
    public var onError: (@MainActor (String) -> Void)?
    public var now: @MainActor () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
    public var schedule: @MainActor (TimeInterval, @escaping @MainActor () -> Void) -> Void = { delay, action in
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(max(0, delay) * 1_000_000_000))
            action()
        }
    }

    var outbox: [Outgoing] = []
    private var nextRef = 1
    private var seqToItem: [Int: String] = [:]
    private var partial: (seq: Int, parts: Int, blobs: [ClipwayCrypto.Envelope])?
    /// The lowest seq that could not be handled on this connection: after stays below it.
    private var holdBelow: Int?
    private var pumpScheduled = false

    public init(keys: ChainKeys, deviceId: String, cursor: Cursor = Cursor(), guardian: ReceiveGuard = ReceiveGuard()) {
        self.keys = keys
        self.deviceId = deviceId
        self.cursor = cursor
        self.guardian = guardian
    }

    /// Items waiting for stored.
    public var pendingCount: Int { outbox.count }

    // MARK: Connection

    public func connected() {
        phase = .handshake
        partial = nil
        holdBelow = nil
        for i in outbox.indices { outbox[i].ref = nil }
        onPhase?()
    }

    public func disconnected() {
        phase = .offline
        devices = 0
        partial = nil
        holdBelow = nil
        // Items in flight go back to the queue: resent whole, with the same item id (section 5.2).
        for i in outbox.indices { outbox[i].ref = nil }
        onPhase?()
    }

    /// Handles one frame from the relay. Returns false for a frame it could not read.
    @discardableResult
    public func receive(_ text: String) -> Bool {
        guard let frame = try? RelayFrame.parse(text) else { return false }
        switch frame {
        case let .welcome(epoch, count):
            devices = count
            send?(RelayFrame.sync(epoch: cursor.epoch, after: cursor.after))
            if epoch != cursor.epoch {
                cursor = Cursor(epoch: epoch, after: 0)
                onPersist?()
            }
            phase = .syncing
            onPhase?()
        case let .item(seq, part, parts, _, blob):
            if part == 0 {
                partial = (seq, parts, [blob])
            } else if var p = partial, p.seq == seq, p.blobs.count == part, p.parts == parts {
                p.blobs.append(blob)
                partial = p
            } else {
                partial = nil
                return false
            }
            if let p = partial, p.blobs.count == p.parts {
                partial = nil
                complete(seq: p.seq, blobs: p.blobs)
            }
        case .synced:
            phase = .ready
            onPhase?()
            pump()
        case let .stored(ref, seq):
            guard let i = outbox.firstIndex(where: { $0.ref == ref }) else { break }
            let sent = outbox.remove(at: i)
            if !sent.isHello {
                seqToItem[seq] = sent.item
                onStatus?(sent.item, devices >= 2 ? .sent : .waiting)
            }
            advance(seq)
            pump()
        case let .delivered(seq):
            if let item = seqToItem.removeValue(forKey: seq) { onStatus?(item, .delivered) }
        case let .presence(count):
            devices = count
            onPhase?()
        case .pong:
            onPong?()
        case let .error(ref, code, _):
            onError?(code)
            guard let ref, let i = outbox.firstIndex(where: { $0.ref == ref }) else { break }
            switch code {
            case "too_big", "bad_request":
                let failed = outbox.remove(at: i)
                if !failed.isHello { onStatus?(failed.item, .failed) }
            default:
                // rate_limited, busy, quota, incomplete: try again later.
                outbox[i].ref = nil
                outbox[i].retryAt = now() + Self.retryDelayMs
            }
            pump()
        }
        return true
    }

    // MARK: Sending

    /// Queues an item until stored arrives. Sent at once when synced.
    public func enqueue(_ built: ItemCodec.Built) {
        outbox.append(Outgoing(item: built.head.item, envelopes: built.envelopes, isHello: built.head.type == .hello, ref: nil))
        // A clipboard is latest wins: beyond the cap, the oldest waiting items are dropped.
        while outbox.count > Self.outboxMax, let i = outbox.firstIndex(where: { $0.ref == nil }) {
            let gone = outbox.remove(at: i)
            if !gone.isHello { onStatus?(gone.item, .failed) }
        }
        pump()
    }

    /// Sends the next queued item: one upload at a time, all its parts in order.
    public func pump() {
        guard phase == .ready, !outbox.contains(where: { $0.ref != nil }), !outbox.isEmpty else { return }
        let t = now()
        guard let i = outbox.firstIndex(where: { $0.retryAt <= t }) else {
            let wait = (outbox.map(\.retryAt).min() ?? t) - t
            if !pumpScheduled {
                pumpScheduled = true
                schedule(Double(wait) / 1000) { [weak self] in
                    self?.pumpScheduled = false
                    self?.pump()
                }
            }
            return
        }
        let ref = nextRef
        nextRef = nextRef >= Int(Int32.max) ? 1 : nextRef + 1
        outbox[i].ref = ref
        let parts = outbox[i].envelopes.count
        for (part, blob) in outbox[i].envelopes.enumerated() {
            send?(RelayFrame.upload(ref: ref, part: part, parts: parts, blob: blob))
        }
    }

    // MARK: Receiving

    private func complete(seq: Int, blobs: [ClipwayCrypto.Envelope]) {
        let read: ItemCodec.Read
        do {
            read = try ItemCodec.read(keys: keys, envelopes: blobs)
        } catch {
            // Never readable: acknowledged so the relay forgets it (section 2).
            dropped += 1
            acknowledge(seq)
            return
        }
        let verdict = guardian.check(read.head, ownDevice: deviceId, now: now())
        switch verdict {
        case .own:
            advance(seq)
        case .stale, .future, .duplicate:
            if verdict != .duplicate { dropped += 1 }
            acknowledge(seq)
        case .accept:
            if onReceive?(Incoming(seq: seq, head: read.head, content: read.content)) ?? false {
                guardian.remember(read.head.item, now: now())
                acknowledge(seq)
            } else {
                holdBelow = min(holdBelow ?? seq, seq)
            }
        }
    }

    private func acknowledge(_ seq: Int) {
        send?(RelayFrame.ack(seq: seq))
        advance(seq)
    }

    private func advance(_ seq: Int) {
        if let hold = holdBelow, seq >= hold { return }
        if seq > cursor.after {
            cursor.after = seq
        }
        onPersist?()
    }
}
