import CryptoKit
import Foundation

/// One advertisement of the Mac's Pair nearby window (docs/PROTOCOL.md, 13.7), without radio: the
/// answer to every Bluetooth request and person's action, as relay/nearby.js gives it. Centrals are
/// named by any string (CoreBluetooth: CBCentral.identifier). Each call returns the answer and the
/// Status bytes to notify to the locked phone afterwards. Replayed against the 8 sessions of
/// docs/VECTORS.json.
public final class NearbyMacSession {
    public enum State: String, Sendable { case open, locked, ready, ended }

    /// Why a session ended.
    public enum End: String, Sendable { case done, left, canceled, expired, failed }

    public enum Answer: Equatable, Sendable {
        case value(Data)
        case ok
        case error(Nearby.ATTError)
    }

    public struct Outcome: Equatable, Sendable {
        public let answer: Answer
        /// Status bytes to notify to the locked phone, after the answer.
        public let notify: [UInt8]
    }

    /// The pairing code the packet carries (the text of the QR code).
    public let code: String
    public let publicKey: Data
    public let commit: Data
    public private(set) var state: State = .open
    public private(set) var status: Nearby.Status = .waiting
    public private(set) var end: End?
    /// The phone whose key was accepted.
    public private(set) var central: String?
    /// The code on the Mac's screen, while it is shown.
    public private(set) var sas: String?
    public private(set) var macConfirmed = false
    public private(set) var phoneConfirmed = false
    /// The locked phone has read Packet at least once.
    public private(set) var delivered = false

    private var subscribed: Set<String> = []
    private var privateKey: Nearby.PrivateKey?
    private var keys: Nearby.Keys?
    private var pkPhone: Data?
    private var packet: Data?
    private let nonce: Data?

    /// A new session with a fresh key pair. privateKey and nonce are for the vectors only.
    /// Throws when the code does not fit in a packet (the Mac then offers only the QR code).
    public init(code: String, privateKey: Data? = nil, nonce: Data? = nil) throws {
        _ = try Nearby.packetPlaintext(code: code)
        let key = try privateKey.map { try Nearby.privateKey(raw: $0) } ?? Nearby.newPrivateKey()
        self.code = code
        self.privateKey = key
        publicKey = key.publicKey.rawRepresentation
        commit = Nearby.commitment(publicKey)
        self.nonce = nonce
    }

    public convenience init(secret: Data, relay: String, privateKey: Data? = nil, nonce: Data? = nil) throws {
        try self.init(code: try ClipwayCrypto.toQr(secret, relay: relay, defaultRelay: ClipwayInfo.defaultRelay),
                      privateKey: privateKey, nonce: nonce)
    }

    /// True once the private key, the derived keys and the packet are forgotten.
    public var forgotten: Bool { privateKey == nil && keys == nil && packet == nil && sas == nil }

    // MARK: Requests

    /// Subscription to Status (CCCD 0x0001).
    public func subscribe(_ central: String) -> Outcome {
        guard state != .ended else { return Outcome(answer: .error(.writeNotPermitted), notify: []) }
        subscribed.insert(central)
        return Outcome(answer: .ok, notify: [])
    }

    /// Unsubscription: also how CoreBluetooth tells a peripheral that a central left.
    public func unsubscribe(_ central: String) -> Outcome {
        subscribed.remove(central)
        if central == self.central && state != .ended { _ = finish(delivered ? .done : .left) }
        return Outcome(answer: .ok, notify: [])
    }

    /// Reads: permission, then offset. The answer holds the bytes from the offset.
    public func read(_ central: String, _ characteristic: Nearby.Characteristic, offset: Int = 0) -> Outcome {
        let bytes: Data
        switch readValue(central, characteristic) {
        case let .failure(error): return Outcome(answer: .error(error), notify: [])
        case let .success(value): bytes = value
        }
        guard offset >= 0, offset <= bytes.count else { return Outcome(answer: .error(.invalidOffset), notify: []) }
        if characteristic == .packet { delivered = true }
        return Outcome(answer: .value(Data(bytes.dropFirst(offset))), notify: [])
    }

    private func readValue(_ central: String, _ characteristic: Nearby.Characteristic) -> Result<Data, Nearby.ATTError> {
        guard state != .ended else { return .failure(.readNotPermitted) }
        let locked = self.central != nil
        let mine = central == self.central
        switch characteristic {
        case .commit:
            return .success(commit)
        case .status:
            return .success(Data([locked && !mine ? Nearby.Status.busy.rawValue : status.rawValue]))
        case .macKey:
            return mine ? .success(publicKey) : .failure(.readNotPermitted)
        case .packet:
            guard mine, state == .ready, let packet else { return .failure(.readNotPermitted) }
            return .success(packet)
        case .phoneKey, .confirm:
            return .failure(.readNotPermitted)
        }
    }

    /// Writes: offset, then length, then permission, then content.
    public func write(_ central: String, _ characteristic: Nearby.Characteristic, value: Data, offset: Int = 0) -> Outcome {
        switch characteristic {
        case .phoneKey:
            guard offset == 0 else { return Outcome(answer: .error(.invalidOffset), notify: []) }
            guard value.count == Nearby.keySize else { return Outcome(answer: .error(.invalidAttributeValueLength), notify: []) }
            guard state == .open, subscribed.contains(central), let privateKey else {
                return Outcome(answer: .error(.writeNotPermitted), notify: [])
            }
            let pkPhone = Data(value)
            let keys: Nearby.Keys
            do {
                try Nearby.checkPeerKey(pkPhone, own: publicKey)
                keys = Nearby.derive(z: try Nearby.sharedSecret(privateKey, pkPhone), pkMac: publicKey, pkPhone: pkPhone)
            } catch {
                // Nothing changes: the advertisement stays open for another try.
                return Outcome(answer: .error(.unlikelyError), notify: [])
            }
            self.central = central
            self.pkPhone = pkPhone
            self.keys = keys
            sas = Nearby.sasCode(kSas: keys.sas, pkMac: publicKey, pkPhone: pkPhone)
            state = .locked
            return Outcome(answer: .ok, notify: [])
        case .confirm:
            guard offset == 0 else { return Outcome(answer: .error(.invalidOffset), notify: []) }
            guard value.count == Nearby.confirmSize else { return Outcome(answer: .error(.invalidAttributeValueLength), notify: []) }
            guard central == self.central, state == .locked, !phoneConfirmed, let keys, let pkPhone else {
                return Outcome(answer: .error(.writeNotPermitted), notify: [])
            }
            guard Nearby.checkConfirm(kSas: keys.sas, pkMac: publicKey, pkPhone: pkPhone, tag: value) else {
                return Outcome(answer: .error(.unlikelyError), notify: finish(.failed))
            }
            phoneConfirmed = true
            return Outcome(answer: .ok, notify: maybeReady())
        case .commit, .macKey, .status, .packet:
            return Outcome(answer: .error(.writeNotPermitted), notify: [])
        }
    }

    // MARK: The person at the Mac, and the clock

    /// Pair on the Mac, only once the code is shown.
    public func pair() -> [UInt8] {
        guard state == .locked, !macConfirmed else { return [] }
        macConfirmed = true
        return maybeReady()
    }

    /// Cancel, the window closed, or Show a code instead.
    public func cancel() -> [UInt8] {
        state == .ended ? [] : finish(.canceled)
    }

    /// 120 seconds passed. A ready session is not cut: it ends when the phone leaves or after the grace.
    public func expire() -> [UInt8] {
        state == .ended || state == .ready ? [] : finish(.expired)
    }

    /// 10 seconds after the first read of the packet.
    public func graceOver() -> [UInt8] {
        state == .ready && delivered ? finish(.done) : []
    }

    // MARK: Internals

    private func maybeReady() -> [UInt8] {
        guard macConfirmed, phoneConfirmed, let keys, let pkPhone,
              let sealed = try? Nearby.sealPacket(kKey: keys.key, pkMac: publicKey, pkPhone: pkPhone, code: code, nonce: nonce)
        else { return [] }
        packet = sealed
        state = .ready
        status = .ready
        return notifyStatus()
    }

    private func finish(_ reason: End) -> [UInt8] {
        end = reason
        var out: [UInt8] = []
        let final: Nearby.Status? = switch reason {
        case .canceled: .canceled
        case .expired: .expired
        case .failed: .failed
        case .done, .left: nil
        }
        if let final {
            status = final
            out = notifyStatus()
        }
        state = .ended
        sas = nil
        privateKey = nil
        keys = nil
        packet = nil
        return out
    }

    private func notifyStatus() -> [UInt8] {
        guard let central, subscribed.contains(central) else { return [] }
        return [status.rawValue]
    }
}
