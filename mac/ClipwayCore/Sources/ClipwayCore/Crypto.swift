import CryptoKit
import Foundation

/// Clipway cryptography, as specified in docs/PROTOCOL.md and checked against docs/VECTORS.json
/// (the same vectors as relay/crypto.js and the Android app). Same construction as the Sonne sync
/// chain, with Clipway labels. CryptoKit only: HKDF-SHA256, HMAC-SHA256, SHA-256, AES-256-GCM.
public enum ClipwayCrypto {
    public static let secretSize = 16
    public static let proofSize = 16
    public static let nonceSize = 12
    public static let tagSize = 16
    public static let fpSize = 16
    public static let padBlock = 512
    /// Largest text: 64 KiB. The relay carries texts only.
    public static let textMax = 65_536
    /// Largest head plaintext: a 64 KiB text with the largest fields, padded (172 x 512).
    public static let headMax = 88_064
    /// Largest image or file, sent directly between the devices (docs/PROTOCOL.md, section 14).
    public static let fileMax = 26_214_400
    public static let qrPrefix = "clipway:"
    public static let subprotocol = "clipway.v1"
    public static let protocolVersion = 1

    public enum Failure: Error, Equatable {
        case invalidSecret, invalidProof, invalidNonce, invalidEnvelope, authentication
        case invalidHead, wordCount, unknownWord(String), checksum, invalidCode(String)
    }

    // MARK: Helpers

    public static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    public static func fromHex(_ text: String) throws -> Data {
        guard text.count % 2 == 0 else { throw Failure.invalidEnvelope }
        var out = Data(capacity: text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else { throw Failure.invalidEnvelope }
            out.append(byte)
            index = next
        }
        return out
    }

    public static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        var generator = SystemRandomNumberGenerator()
        for i in 0..<count { bytes[i] = UInt8.random(in: .min ... .max, using: &generator) }
        return Data(bytes)
    }

    public static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    static func bytes(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

    /// HKDF-SHA256 with an empty salt (RFC 5869: same as 32 zero bytes).
    static func hkdf(_ secret: Data, _ info: String, _ length: Int) throws -> Data {
        guard secret.count == secretSize else { throw Failure.invalidSecret }
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secret), salt: Data(), info: Data(info.utf8), outputByteCount: length)
        return bytes(key)
    }

    // MARK: Secret, proof, chain id and keys

    /// A new secret S: 16 bytes from the system CSPRNG.
    public static func generateSecret() -> Data { randomBytes(secretSize) }

    /// P = HKDF-SHA256(S, empty salt, "clipway-proof", 16). Shown to the relay, never S.
    public static func proof(_ s: Data) throws -> Data { try hkdf(s, "clipway-proof", proofSize) }

    /// Chain id = hex(SHA-256("clipway-id" || P))[0:32]. The relay computes it from P.
    public static func idFromProof(_ p: Data) throws -> String {
        guard p.count == proofSize else { throw Failure.invalidProof }
        return String(hex(sha256(Data("clipway-id".utf8) + p)).prefix(32))
    }

    public static func chainId(_ s: Data) throws -> String { try idFromProof(try proof(s)) }

    /// K_enc = HKDF-SHA256(S, empty salt, "clipway-enc", 32).
    public static func encKey(_ s: Data) throws -> SymmetricKey { SymmetricKey(data: try hkdf(s, "clipway-enc", 32)) }

    /// K_mac = HKDF-SHA256(S, empty salt, "clipway-mac", 32).
    public static func macKey(_ s: Data) throws -> SymmetricKey { SymmetricKey(data: try hkdf(s, "clipway-mac", 32)) }

    /// K_direct = HKDF-SHA256(S, empty salt, "clipway-direct", 32): root of the direct transfer keys.
    public static func directKey(_ s: Data) throws -> SymmetricKey { SymmetricKey(data: try hkdf(s, "clipway-direct", 32)) }

    /// WebSocket subprotocols: "clipway.v1" and "clipway.p.<hex P>". The chain id never goes in a URL.
    public static func subprotocols(_ s: Data) throws -> [String] { [subprotocol, "clipway.p." + hex(try proof(s))] }

    /// fp = hex(HMAC-SHA256(K_mac, content)[0:16]).
    public static func fingerprint(macKey: SymmetricKey, content: Data) -> String {
        hex(Data(HMAC<SHA256>.authenticationCode(for: content, using: macKey)).prefix(fpSize))
    }

    // MARK: Envelope: AES-256-GCM { nonce: hex(12), enc: base64(ciphertext || tag) }

    public struct Envelope: Codable, Equatable, Sendable {
        public let nonce: String
        public let enc: String
        public init(nonce: String, enc: String) {
            self.nonce = nonce
            self.enc = enc
        }
    }

    /// Seals bytes. aad is authenticated as UTF-8. Never pass a fixed nonce outside tests.
    public static func seal(key: SymmetricKey, aad: String, plaintext: Data, nonce: Data? = nil) throws -> Envelope {
        let iv = nonce ?? randomBytes(nonceSize)
        guard iv.count == nonceSize else { throw Failure.invalidNonce }
        let box = try AES.GCM.seal(plaintext, using: key, nonce: try AES.GCM.Nonce(data: iv), authenticating: Data(aad.utf8))
        return Envelope(nonce: hex(iv), enc: (box.ciphertext + box.tag).base64EncodedString())
    }

    /// Opens an envelope. Throws if the key, the aad or the bytes do not match.
    public static func open(key: SymmetricKey, aad: String, envelope: Envelope) throws -> Data {
        let iv = try fromHex(envelope.nonce)
        guard iv.count == nonceSize, let data = Data(base64Encoded: envelope.enc), data.count >= tagSize else {
            throw Failure.invalidEnvelope
        }
        do {
            let box = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: iv), ciphertext: data.prefix(data.count - tagSize), tag: data.suffix(tagSize))
            return try AES.GCM.open(box, using: key, authenticating: Data(aad.utf8))
        } catch {
            throw Failure.authentication
        }
    }

    /// Pads a serialized head: adds "pad" (spaces) before the final "}" so that the UTF-8 length is the
    /// smallest multiple of 512 that is at least the length + 9. Input: JSON without pad, ending with "}".
    public static func padHead(_ json: String) throws -> String {
        guard json.count >= 2, json.hasSuffix("}") else { throw Failure.invalidHead }
        let length = json.utf8.count
        let total = (length + 9 + padBlock - 1) / padBlock * padBlock
        return String(json.dropLast()) + ",\"pad\":\"" + String(repeating: " ", count: total - length - 9) + "\"}"
    }

    // MARK: 12 BIP39 words (128 bits + 4 checksum bits)

    public static func toWords(_ s: Data) throws -> [String] {
        guard s.count == secretSize else { throw Failure.invalidSecret }
        var bits: [UInt8] = []
        for byte in s { for i in (0..<8).reversed() { bits.append((byte >> UInt8(i)) & 1) } }
        let checksum = sha256(s)[0] >> 4
        for i in (0..<4).reversed() { bits.append((checksum >> UInt8(i)) & 1) }
        return (0..<12).map { w in
            var index = 0
            for b in 0..<11 { index = (index << 1) | Int(bits[w * 11 + b]) }
            return bip39English[index]
        }
    }

    /// 12 words to S. Case and extra spaces are ignored.
    public static func fromWords(_ text: String) throws -> Data {
        let words = text.lowercased().split(whereSeparator: { $0.isWhitespace }).map(String.init)
        guard words.count == 12 else { throw Failure.wordCount }
        var bits: [UInt8] = []
        for word in words {
            guard let index = bip39English.firstIndex(of: word) else { throw Failure.unknownWord(word) }
            for i in (0..<11).reversed() { bits.append(UInt8((index >> i) & 1)) }
        }
        var s = Data(count: secretSize)
        for i in 0..<secretSize {
            var byte: UInt8 = 0
            for b in 0..<8 { byte = (byte << 1) | bits[i * 8 + b] }
            s[i] = byte
        }
        var checksum: UInt8 = 0
        for b in 128..<132 { checksum = (checksum << 1) | bits[b] }
        guard checksum == sha256(s)[0] >> 4 else { throw Failure.checksum }
        return s
    }

    // MARK: Pairing QR code: clipway:<base64url(S)>[?relay=<percent-encoded URL>]

    public static func toQr(_ s: Data, relay: String, defaultRelay: String) throws -> String {
        guard s.count == secretSize else { throw Failure.invalidSecret }
        let key = s.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let r = trimSlashes(relay)
        if r.isEmpty || r == trimSlashes(defaultRelay) { return qrPrefix + key }
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.!~*'()")
        return qrPrefix + key + "?relay=" + (r.addingPercentEncoding(withAllowedCharacters: allowed) ?? r)
    }

    /// Reads a pairing code. relay is nil when the code names none (default relay).
    public static func fromQr(_ text: String) throws -> (secret: Data, relay: String?) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.hasPrefix(qrPrefix) else { throw Failure.invalidCode("clipway: expected") }
        let rest = String(t.dropFirst(qrPrefix.count))
        let parts = rest.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        var value = parts[0]
        while value.hasSuffix("=") { value.removeLast() }
        guard value.count == 22, value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else {
            throw Failure.invalidCode("malformed key")
        }
        let b64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "=="
        guard let s = Data(base64Encoded: b64), s.count == secretSize else { throw Failure.invalidCode("key of the wrong size") }
        var relay: String?
        if parts.count == 2 {
            let query = parts[1].split(separator: "&").map(String.init)
            if let raw = query.first(where: { $0.hasPrefix("relay=") })?.dropFirst(6), !raw.isEmpty {
                guard let decoded = String(raw).removingPercentEncoding, let url = URL(string: decoded),
                      url.scheme == "https" || url.scheme == "http"
                else { throw Failure.invalidCode("relay must be http(s)") }
                relay = trimSlashes(decoded)
            }
        }
        return (s, relay)
    }

    static func trimSlashes(_ s: String) -> String {
        var r = s
        while r.hasSuffix("/") { r.removeLast() }
        return r
    }
}
