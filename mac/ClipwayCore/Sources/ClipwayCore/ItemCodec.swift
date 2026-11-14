import Foundation

/// Builds and reads items (docs/PROTOCOL.md, sections 3.1 to 3.3 and 15): one envelope each, or
/// the head and its chunks for an image or a file sent through the relay.
public enum ItemCodec {
    public struct Built: Sendable {
        public let head: Head
        /// One envelope, or the head and then the chunks of a chunked item.
        public let envelopes: [ClipwayCrypto.Envelope]
    }

    public struct Read: Sendable {
        public let head: Head
        /// The content of a text or a chunked item; nil for hello, offer and reply.
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

    /// An image or a file of 6 MiB at most sent through the relay (section 15): the padded head
    /// (AAD = chain id), then one envelope per 64 KiB chunk (AAD = clipway-chunk|chain|item|index|count).
    /// nonces: fixed nonces for every part, the head first (test vectors only).
    public static func chunked(
        keys: ChainKeys, item: String = ClipwayCrypto.randomId(), device: Device, ts: Int64, media: ItemType,
        mime: String, name: String?, content: Data, nonces: [Data] = []
    ) throws -> Built {
        if content.count > ClipwayCrypto.relayFileMax { throw Failure.tooBig }
        let chunks = ClipwayCrypto.chunkCount(content.count)
        let head = Head(
            type: .chunked, item: item, device: device, ts: ts, mime: mime, name: name, size: content.count,
            fp: keys.fingerprint(content), media: media, chunks: chunks)
        var envelopes = try seal(keys: keys, head: head, nonce: nonces.first).envelopes
        envelopes.reserveCapacity(1 + chunks)
        for i in 0..<chunks {
            let from = content.startIndex + i * ClipwayCrypto.chunkSize
            let slice = content[from..<min(content.endIndex, from + ClipwayCrypto.chunkSize)]
            let aad = ClipwayCrypto.chunkAad(chainId: keys.id, item: item, index: i, chunks: chunks)
            envelopes.append(try ClipwayCrypto.seal(key: keys.enc, aad: aad, plaintext: Data(slice), nonce: i + 1 < nonces.count ? nonces[i + 1] : nil))
        }
        return Built(head: head, envelopes: envelopes)
    }

    /// The answer to an offer that could not be delivered directly.
    public static func reply(
        keys: ChainKeys, item: String = ClipwayCrypto.randomId(), device: Device, ts: Int64, offer: String, status: String,
        nonce: Data? = nil
    ) throws -> Built {
        try seal(keys: keys, head: Head(type: .reply, item: item, device: device, ts: ts, offer: offer, status: status), nonce: nonce)
    }

    /// Opens an item: one envelope, or the head and its chunks; checks the size and the fingerprint
    /// of a text, or of the content put back together from the chunks.
    public static func read(keys: ChainKeys, envelopes: [ClipwayCrypto.Envelope]) throws -> Read {
        guard let first = envelopes.first else { throw Failure.noParts }
        guard envelopes.count <= ClipwayCrypto.partsMax else { throw Failure.wrongPartCount }
        let head = try Head.parse(try ClipwayCrypto.open(key: keys.enc, aad: keys.id, envelope: first))
        let chunks = head.type == .chunked ? head.chunks ?? 0 : 0
        guard envelopes.count == 1 + chunks else { throw Failure.wrongPartCount }
        let content: Data
        switch head.type {
        case .text:
            content = Data(base64Encoded: head.data ?? "") ?? Data()
        case .chunked:
            let size = head.size ?? 0
            var joined = Data(capacity: size)
            for i in 0..<chunks {
                let aad = ClipwayCrypto.chunkAad(chainId: keys.id, item: head.item, index: i, chunks: chunks)
                let chunk = try ClipwayCrypto.open(key: keys.enc, aad: aad, envelope: envelopes[i + 1])
                // Every chunk is full but the last.
                let expected = i < chunks - 1 ? ClipwayCrypto.chunkSize : size - i * ClipwayCrypto.chunkSize
                guard chunk.count == expected else { throw Failure.sizeMismatch }
                joined.append(chunk)
            }
            content = joined
        default:
            return Read(head: head, content: nil)
        }
        guard content.count == head.size else { throw Failure.sizeMismatch }
        guard keys.fingerprint(content) == head.fp else { throw Failure.fingerprintMismatch }
        return Read(head: head, content: content)
    }
}
