import Foundation

/// Builds and reads items: one envelope each (docs/PROTOCOL.md, sections 3.1 to 3.3).
public enum ItemCodec {
    public struct Built: Sendable {
        public let head: Head
        /// Always one envelope: the relay refuses anything in parts.
        public let envelopes: [ClipwayCrypto.Envelope]
    }

    public struct Read: Sendable {
        public let head: Head
        /// The content of a text; nil for hello, offer and reply.
        public let content: Data?
    }

    public enum Failure: Error, Equatable {
        case tooBig
        case notATextOrHello
        case noParts
        case wrongPartCount
        case sizeMismatch
        case fingerprintMismatch
    }

    /// Seals a head: padded, one envelope, AAD = chain id. Never larger than a 64 KiB text.
    public static func seal(keys: ChainKeys, head: Head, nonce: Data? = nil) throws -> Built {
        let plaintext = try head.serialized()
        // The same rules a receiver applies: never send what the other side would drop.
        _ = try Head.parse(Data(plaintext.utf8))
        guard plaintext.utf8.count <= ClipwayCrypto.headMax else { throw Failure.tooBig }
        let envelope = try ClipwayCrypto.seal(key: keys.enc, aad: keys.id, plaintext: Data(plaintext.utf8), nonce: nonce)
        return Built(head: head, envelopes: [envelope])
    }

    /// A text (64 KiB at most) or a hello. nonces: a fixed nonce, for the test vectors only.
    public static func build(
        keys: ChainKeys, type: ItemType, item: String = ClipwayCrypto.randomId(), device: Device, ts: Int64,
        content: Data? = nil, nonces: [Data] = []
    ) throws -> Built {
        guard type == .text || type == .hello else { throw Failure.notATextOrHello }
        var head = Head(type: type, item: item, device: device, ts: ts)
        if type == .text {
            let bytes = content ?? Data()
            if bytes.count > ClipwayCrypto.textMax { throw Failure.tooBig }
            head.mime = Head.textMime
            head.size = bytes.count
            head.fp = keys.fingerprint(bytes)
            head.data = bytes.base64EncodedString()
        }
        return try seal(keys: keys, head: head, nonce: nonces.first)
    }

    /// An offer for an image or a file that this device serves directly on `port` (section 14).
    public static func offer(
        keys: ChainKeys, item: String = ClipwayCrypto.randomId(), device: Device, ts: Int64, media: ItemType,
        mime: String, name: String?, content: Data, port: Int, hosts: [String], nonce: Data? = nil
    ) throws -> Built {
        if content.count > ClipwayCrypto.fileMax { throw Failure.tooBig }
        let head = Head(
            type: .offer, item: item, device: device, ts: ts, mime: mime, name: name, size: content.count,
            fp: keys.fingerprint(content), media: media, port: port, hosts: hosts)
        return try seal(keys: keys, head: head, nonce: nonce)
    }

    /// The answer to an offer that could not be delivered directly.
    public static func reply(
        keys: ChainKeys, item: String = ClipwayCrypto.randomId(), device: Device, ts: Int64, offer: String, status: String,
        nonce: Data? = nil
    ) throws -> Built {
        try seal(keys: keys, head: Head(type: .reply, item: item, device: device, ts: ts, offer: offer, status: status), nonce: nonce)
    }

    /// Opens an item: exactly one envelope; checks the size and the fingerprint of a text.
    public static func read(keys: ChainKeys, envelopes: [ClipwayCrypto.Envelope]) throws -> Read {
        guard let first = envelopes.first else { throw Failure.noParts }
        guard envelopes.count == 1 else { throw Failure.wrongPartCount }
        let head = try Head.parse(try ClipwayCrypto.open(key: keys.enc, aad: keys.id, envelope: first))
        guard head.type == .text else { return Read(head: head, content: nil) }
        let content = Data(base64Encoded: head.data ?? "") ?? Data()
        guard content.count == head.size else { throw Failure.sizeMismatch }
        guard keys.fingerprint(content) == head.fp else { throw Failure.fingerprintMismatch }
        return Read(head: head, content: content)
    }
}
