import Foundation

/// The Mac's side of one Pair nearby attempt, between CoreBluetooth and NearbyMacSession, still
/// without radio: it applies the clock (120 seconds from the start, 10 seconds after the first read
/// of the packet), answers a batch of writes once (the first error found), and tells the app what
/// to show and whether to keep advertising. The app's shell only converts CBATTRequest to these
/// calls, answers, then sends the notifications. Time is any monotonic clock, in seconds.
public final class NearbyHost {
    /// What the Mac's window shows.
    public enum Phase: Equatable, Sendable {
        /// Advertising, no phone yet: "Bring your phone near your Mac."
        case open
        /// "Check that your phone shows the same code."
        case code(String, macConfirmed: Bool)
        /// Both pressed Pair: "Finishing on your phone."
        case ready
        case ended(NearbyMacSession.End)
    }

    /// One request of an ATT write. A nil characteristic is one the service does not have.
    public struct Write: Sendable {
        public let central: String
        public let characteristic: Nearby.Characteristic?
        public let offset: Int
        public let value: Data

        public init(central: String, characteristic: Nearby.Characteristic?, offset: Int = 0, value: Data) {
            self.central = central
            self.characteristic = characteristic
            self.offset = offset
            self.value = value
        }
    }

    public struct Reply: Equatable, Sendable {
        public let answer: NearbyMacSession.Answer
        /// Status bytes for the locked phone, sent after the answer.
        public let notify: [UInt8]
    }

    public let session: NearbyMacSession
    /// When the attempt expires unless it is ready.
    public let deadline: TimeInterval
    /// When a ready session stops waiting for the phone to leave.
    public private(set) var graceDeadline: TimeInterval?

    public init(session: NearbyMacSession, now: TimeInterval) {
        self.session = session
        deadline = now + Nearby.sessionSeconds
    }

    public var phase: Phase {
        switch session.state {
        case .open: .open
        case .locked: .code(session.sas ?? "", macConfirmed: session.macConfirmed)
        case .ready: .ready
        case .ended: .ended(session.end ?? .canceled)
        }
    }

    /// Advertise only while no phone key was accepted.
    public var advertises: Bool { session.state == .open }
    public var isOver: Bool { session.state == .ended }
    /// The phone that may receive notifications.
    public var lockedCentral: String? { session.central }

    /// The next time `tick` has something to do.
    public var nextDeadline: TimeInterval? {
        switch session.state {
        case .open, .locked: deadline
        case .ready: graceDeadline
        case .ended: nil
        }
    }

    /// Applies the clock: Status 03 at the deadline, the end of a delivered session after the grace.
    @discardableResult
    public func tick(now: TimeInterval) -> [UInt8] {
        var notify: [UInt8] = []
        if let graceDeadline, now >= graceDeadline { notify += session.graceOver() }
        if now >= deadline { notify += session.expire() }
        return notify
    }

    public func subscribe(_ central: String, now: TimeInterval) -> [UInt8] {
        let due = tick(now: now)
        return due + session.subscribe(central).notify
    }

    public func unsubscribe(_ central: String, now: TimeInterval) -> [UInt8] {
        let due = tick(now: now)
        return due + session.unsubscribe(central).notify
    }

    public func read(_ central: String, _ characteristic: Nearby.Characteristic?, offset: Int, now: TimeInterval) -> Reply {
        let due = tick(now: now)
        guard let characteristic else { return Reply(answer: .error(.readNotPermitted), notify: due) }
        let outcome = session.read(central, characteristic, offset: offset)
        if session.delivered && graceDeadline == nil { graceDeadline = now + Nearby.graceSeconds }
        return Reply(answer: outcome.answer, notify: due + outcome.notify)
    }

    /// One ATT write, possibly several requests (CoreBluetooth hands a prepared write as a batch):
    /// one answer, the first error found. Prepared writes carry an offset and are refused whole.
    public func write(_ batch: [Write], now: TimeInterval) -> Reply {
        var notify = tick(now: now)
        guard !batch.isEmpty else { return Reply(answer: .error(.writeNotPermitted), notify: notify) }
        if batch.count > 1, batch.contains(where: { $0.offset != 0 }) {
            return Reply(answer: .error(.invalidOffset), notify: notify)
        }
        for request in batch {
            guard let characteristic = request.characteristic else { return Reply(answer: .error(.writeNotPermitted), notify: notify) }
            let outcome = session.write(request.central, characteristic, value: request.value, offset: request.offset)
            notify += outcome.notify
            if case .error = outcome.answer { return Reply(answer: outcome.answer, notify: notify) }
        }
        return Reply(answer: .ok, notify: notify)
    }

    /// Pair on the Mac.
    public func pair(now: TimeInterval) -> [UInt8] {
        let due = tick(now: now)
        return due + session.pair()
    }

    /// Cancel, the window closed, or Show a code instead.
    public func cancel(now: TimeInterval) -> [UInt8] {
        let due = tick(now: now)
        return due + session.cancel()
    }
}
