import CryptoKit
import Foundation

/// Everything derived from the secret S, computed once (docs/PROTOCOL.md, section 1).
public struct ChainKeys: Sendable {
    public let secret: Data
    public let proof: Data
    /// Chain id: the only thing the relay knows. AAD of every head.
    public let id: String
    public let enc: SymmetricKey
    public let mac: SymmetricKey
    /// Root of the per-transfer keys of the direct transfer (section 14).
    public let direct: SymmetricKey

    public init(secret: Data) throws {
        guard secret.count == ClipwayCrypto.secretSize else { throw ClipwayCrypto.Failure.invalidSecret }
        self.secret = secret
        proof = try ClipwayCrypto.proof(secret)
        id = try ClipwayCrypto.idFromProof(proof)
        enc = try ClipwayCrypto.encKey(secret)
        mac = try ClipwayCrypto.macKey(secret)
        direct = try ClipwayCrypto.directKey(secret)
    }

    public var proofHex: String { ClipwayCrypto.hex(proof) }

    /// Sec-WebSocket-Protocol values: "clipway.v1" and "clipway.p.<hex P>".
    public var subprotocols: [String] { [ClipwayCrypto.subprotocol, "clipway.p." + proofHex] }

    public var words: [String] { (try? ClipwayCrypto.toWords(secret)) ?? [] }

    public func fingerprint(_ content: Data) -> String {
        ClipwayCrypto.fingerprint(macKey: mac, content: content)
    }

    public func pairingCode(relay: String) -> String {
        (try? ClipwayCrypto.toQr(secret, relay: relay, defaultRelay: ClipwayInfo.defaultRelay)) ?? ""
    }
}

/// Facts shown in the app and checked by the tests.
public enum ClipwayInfo {
    /// Reference relay, the default in both apps. Configurable in Settings.
    public static let defaultRelay = "https://clip.sidali.dev"
    /// Date of the newest review in docs/security (a test checks that they match).
    public static let lastSecurityReview = "2026-10-27"
    public static let contact = "contact@sidali.dev"
    public static let website = "https://sidali.dev"
}

extension ClipwayCrypto {
    /// 16 random bytes as 32 lowercase hex: item ids and device ids.
    public static func randomId() -> String { hex(randomBytes(16)) }

    /// True for 32 lowercase hex characters.
    public static func isId(_ text: String) -> Bool {
        text.utf8.count == 32 && text.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }
    }
}
