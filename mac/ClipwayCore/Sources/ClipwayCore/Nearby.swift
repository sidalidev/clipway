import CryptoKit
import Foundation

/// Nearby pairing over Bluetooth (docs/PROTOCOL.md, section 13): the derivations, the packet and
/// the phone's side of the exchange, checked against the nearby block of docs/VECTORS.json (the
/// same vectors as relay/nearby.js and the Android app). CryptoKit only: X25519, HKDF-SHA256,
/// HMAC-SHA256, SHA-256, AES-256-GCM. No radio here: the app connects this to CoreBluetooth.
public enum Nearby {
    /// GATT service of nearby pairing, version 1. A new incompatible version uses a new UUID.
    public static let serviceUUID = "a4985110-4541-4fcc-bcac-ee9b5ce269d0"
    /// Standard descriptor that turns notifications on.
    public static let cccdUUID = "00002902-0000-1000-8000-00805f9b34fb"

    /// Raw X25519 public or private key (RFC 7748).
    public static let keySize = 32
    /// Phone confirmation tag.
    public static let confirmSize = 16
    /// Packet plaintext: padded JSON, always this many bytes.
    public static let plaintextSize = 256
    /// Packet on the air: nonce, ciphertext, tag. Exactly CryptoKit's `SealedBox.combined`.
    public static let packetSize = ClipwayCrypto.nonceSize + plaintextSize + ClipwayCrypto.tagSize
    /// The longest pairing code a packet can carry.
    public static let maxCodeLength = 230
    /// The Mac advertises, and both people confirm, within this many seconds of the window opening.
    public static let sessionSeconds: TimeInterval = 120
    /// After the first read of the packet, the Mac waits this long for the phone to leave, then stops.
    public static let graceSeconds: TimeInterval = 10

    /// The six characteristics of the service (13.2).
    public enum Characteristic: String, CaseIterable, Sendable {
        case commit
        case phoneKey = "phone_key"
        case macKey = "mac_key"
        case confirm
        case status
        case packet

        public var uuid: String {
            let digit: Int
            switch self {
            case .commit: digit = 1
            case .phoneKey: digit = 2
            case .macKey: digit = 3
            case .confirm: digit = 4
            case .status: digit = 5
            case .packet: digit = 6
            }
            return "a498511\(digit)-4541-4fcc-bcac-ee9b5ce269d0"
        }

        /// From a UUID string in any case (CoreBluetooth writes them in uppercase).
        public init?(uuid: String) {
            guard let match = Self.allCases.first(where: { $0.uuid == uuid.lowercased() }) else { return nil }
            self = match
        }
    }

    /// Values of the Status characteristic (one byte).
    public enum Status: UInt8, Sendable {
        case waiting = 0x00, ready = 0x01, canceled = 0x02, expired = 0x03, failed = 0x04, busy = 0x05
    }

    /// ATT errors the Mac answers with: the raw values of CBATTError.Code.
    public enum ATTError: UInt8, Error, Sendable {
        case readNotPermitted = 0x02
        case writeNotPermitted = 0x03
        case invalidOffset = 0x07
        case invalidAttributeValueLength = 0x0D
        case unlikelyError = 0x0E
    }

    public enum Failure: Error, Equatable {
        case keyRefused(String), commitment, codeTooLong, invalidCode, packet(String)
    }

    enum Label {
        static let commit = "clipway-nearby-commit"
        static let secret = "clipway-nearby"
        static let sas = "clipway-nearby-sas"
        static let key = "clipway-nearby-key"
        static let confirm = "clipway-nearby-confirm"
        static let aad = "clipway-nearby"
    }

    public typealias PrivateKey = Curve25519.KeyAgreement.PrivateKey

    // MARK: X25519

    /// A new ephemeral key, for one attempt.
    public static func newPrivateKey() -> PrivateKey { PrivateKey() }

    /// A fixed private key, for the vectors only.
    public static func privateKey(raw: Data) throws -> PrivateKey {
        guard raw.count == keySize else { throw Failure.keyRefused("32 bytes expected") }
        return try PrivateKey(rawRepresentation: raw)
    }

    /// Checks the other side's public key before use (13.4): 32 bytes, the top bit of the last byte
    /// clear, and not our own key sent back.
    public static func checkPeerKey(_ key: Data, own: Data?) throws {
        guard key.count == keySize else { throw Failure.keyRefused("32 bytes expected") }
        guard Data(key)[keySize - 1] & 0x80 == 0 else { throw Failure.keyRefused("top bit set") }
        if let own, Data(own) == Data(key) { throw Failure.keyRefused("our own key") }
    }

    /// Z = X25519(own private key, other public key). A low-order point (Z all zeros, or a library
    /// error) is refused.
    public static func sharedSecret(_ privateKey: PrivateKey, _ peer: Data) throws -> Data {
        let z: Data
        do {
            let secret = try privateKey.sharedSecretFromKeyAgreement(with: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer))
            z = secret.withUnsafeBytes { Data($0) }
        } catch {
            throw Failure.keyRefused("low-order point")
        }
        guard z.count == keySize, z.contains(where: { $0 != 0 }) else { throw Failure.keyRefused("low-order point") }
        return z
    }

    // MARK: Derivations (13.4)

    /// commit = SHA-256("clipway-nearby-commit" || pk_mac).
    public static func commitment(_ pkMac: Data) -> Data {
        ClipwayCrypto.sha256(Data(Label.commit.utf8) + pkMac)
    }

    /// T = pk_mac || pk_phone, always the Mac first.
    public static func transcript(_ pkMac: Data, _ pkPhone: Data) -> Data { Data(pkMac) + Data(pkPhone) }

    /// N, K_sas and K_key: 32 bytes each.
    public struct Keys: Sendable, Equatable {
        public let n: Data
        public let sas: Data
        public let key: Data
    }

    /// HKDF-SHA256 with an empty salt, 32 bytes.
    static func hkdf32(_ ikm: Data, _ info: String) -> Data {
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: Data(), info: Data(info.utf8), outputByteCount: 32)
        return key.withUnsafeBytes { Data($0) }
    }

    /// N = HKDF(Z || T, "clipway-nearby"), K_sas = HKDF(N, "clipway-nearby-sas"), K_key = HKDF(N, "clipway-nearby-key").
    public static func derive(z: Data, pkMac: Data, pkPhone: Data) -> Keys {
        let n = hkdf32(Data(z) + transcript(pkMac, pkPhone), Label.secret)
        return Keys(n: n, sas: hkdf32(n, Label.sas), key: hkdf32(n, Label.key))
    }

    static func hmac(_ key: Data, _ message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    /// The first 6 bytes of HMAC-SHA256(K_sas, T).
    public static func sasBytes(kSas: Data, pkMac: Data, pkPhone: Data) -> Data {
        Data(hmac(kSas, transcript(pkMac, pkPhone)).prefix(6))
    }

    /// 6 bytes read as an unsigned big-endian integer, modulo 10 000, as 4 digits with leading zeros.
    public static func sas(fromBytes bytes: Data) -> String {
        var value: UInt64 = 0
        for byte in Data(bytes).prefix(6) { value = value << 8 | UInt64(byte) }
        let digits = String(value % 10_000)
        return String(repeating: "0", count: 4 - digits.count) + digits
    }

    /// The 4-digit code both screens show.
    public static func sasCode(kSas: Data, pkMac: Data, pkPhone: Data) -> String {
        sas(fromBytes: sasBytes(kSas: kSas, pkMac: pkMac, pkPhone: pkPhone))
    }

    /// confirm = HMAC-SHA256(K_sas, "clipway-nearby-confirm" || T)[0:16], written by the phone after Pair.
    public static func confirmTag(kSas: Data, pkMac: Data, pkPhone: Data) -> Data {
        Data(hmac(kSas, Data(Label.confirm.utf8) + transcript(pkMac, pkPhone)).prefix(confirmSize))
    }

    /// Compares a received confirmation tag in constant time.
    public static func checkConfirm(kSas: Data, pkMac: Data, pkPhone: Data, tag: Data) -> Bool {
        let expected = confirmTag(kSas: kSas, pkMac: pkMac, pkPhone: pkPhone)
        let received = Data(tag)
        guard received.count == confirmSize else { return false }
        var difference: UInt8 = 0
        for i in 0..<confirmSize { difference |= expected[i] ^ received[i] }
        return difference == 0
    }

    /// "clipway-nearby|<hex pk_mac>|<hex pk_phone>", lowercase hex, 144 bytes of UTF-8.
    public static func packetAad(pkMac: Data, pkPhone: Data) -> String {
        "\(Label.aad)|\(ClipwayCrypto.hex(pkMac))|\(ClipwayCrypto.hex(pkPhone))"
    }

    // MARK: Packet (13.5)

    /// {"v":1,"code":"<pairing code>"} serialized like a head and padded to exactly 256 bytes:
    /// ,"pad":"<spaces>" before the final brace. Throws when the code does not fit.
    public static func packetPlaintext(code: String) throws -> String {
        guard code.hasPrefix(ClipwayCrypto.qrPrefix) else { throw Failure.invalidCode }
        let json = "{\"v\":1,\"code\":\(Head.quote(code))}"
        let length = json.utf8.count
        guard length + 9 <= plaintextSize else { throw Failure.codeTooLong }
        return String(json.dropLast()) + ",\"pad\":\"" + String(repeating: " ", count: plaintextSize - length - 9) + "\"}"
    }

    /// True when a pairing code fits in a packet: the Mac offers Pair nearby only then.
    public static func fits(code: String) -> Bool { (try? packetPlaintext(code: code)) != nil }

    /// nonce (12) || AES-256-GCM ciphertext (256) || tag (16) = 284 bytes. Never pass a nonce outside tests.
    public static func sealPacket(kKey: Data, pkMac: Data, pkPhone: Data, code: String, nonce: Data? = nil) throws -> Data {
        let plaintext = Data(try packetPlaintext(code: code).utf8)
        let iv = try AES.GCM.Nonce(data: nonce ?? ClipwayCrypto.randomBytes(ClipwayCrypto.nonceSize))
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: kKey), nonce: iv,
                                   authenticating: Data(packetAad(pkMac: pkMac, pkPhone: pkPhone).utf8))
        guard let combined = box.combined, combined.count == packetSize else { throw Failure.packet("size") }
        return combined
    }

    /// What a packet carries once opened.
    public struct Opened: Equatable, Sendable {
        public let code: String
        public let secret: Data
        /// nil for the default relay.
        public let relay: String?
    }

    /// Opens a packet: exactly 284 bytes, authentication, JSON, v equal to 1, code a string, then
    /// the pairing code itself.
    public static func openPacket(kKey: Data, pkMac: Data, pkPhone: Data, packet: Data) throws -> Opened {
        guard packet.count == packetSize else { throw Failure.packet("284 bytes expected") }
        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: Data(packet))
            plaintext = try AES.GCM.open(box, using: SymmetricKey(data: kKey), authenticating: Data(packetAad(pkMac: pkMac, pkPhone: pkPhone).utf8))
        } catch {
            throw Failure.packet("authentication")
        }
        guard let object = try? JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else { throw Failure.packet("not JSON") }
        guard let v = object["v"] as? NSNumber, CFGetTypeID(v) != CFBooleanGetTypeID(), v.doubleValue == 1 else {
            throw Failure.packet("unknown version")
        }
        guard let code = object["code"] as? String else { throw Failure.packet("code") }
        let read = try ClipwayCrypto.fromQr(code)
        return Opened(code: code, secret: read.secret, relay: read.relay)
    }

    // MARK: The phone's side, without radio (tests and the command line check)

    public struct PhoneHandshake: Sendable {
        public let pkPhone: Data
        public let sas: String
        public let confirm: Data
        public let key: Data
    }

    /// What the phone computes once it has read Commit, written its key and read Mac key: checks the
    /// commitment and the Mac key, then derives the code, the tag and the packet key.
    public static func phoneHandshake(privateKey: PrivateKey, commit: Data, pkMac: Data) throws -> PhoneHandshake {
        let pkPhone = privateKey.publicKey.rawRepresentation
        try checkPeerKey(pkMac, own: pkPhone)
        guard commitment(pkMac) == Data(commit) else { throw Failure.commitment }
        let keys = derive(z: try sharedSecret(privateKey, pkMac), pkMac: pkMac, pkPhone: pkPhone)
        return PhoneHandshake(
            pkPhone: pkPhone, sas: sasCode(kSas: keys.sas, pkMac: pkMac, pkPhone: pkPhone),
            confirm: confirmTag(kSas: keys.sas, pkMac: pkMac, pkPhone: pkPhone), key: keys.key)
    }
}
