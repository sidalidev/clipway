import Foundation

/// What an item or a history row is. Through the relay, only text, hello, offer and reply travel:
/// image and file are what an offer stands for, and what history shows.
public enum ItemType: String, Sendable, Codable, CaseIterable {
    case text, image, file, hello, offer, reply

    /// Types a head may have (section 3.1).
    public var travels: Bool { self == .text || self == .hello || self == .offer || self == .reply }
}

public enum DeviceKind: String, Sendable, Codable {
    case mac, android
}

/// A device of the chain, as it appears inside envelopes (never seen by the relay).
public struct Device: Equatable, Sendable, Codable {
    public var id: String
    public var name: String
    public var kind: DeviceKind

    public init(id: String, name: String, kind: DeviceKind) {
        self.id = id
        self.name = name
        self.kind = kind
    }

    /// A device name the protocol accepts: 1 to 64 characters, trimmed.
    public static func cleanName(_ raw: String, fallback: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }
        var name = String(String.UnicodeScalarView(trimmed))
        while name.unicodeScalars.count > Head.deviceNameMax { name.removeLast() }
        return name.isEmpty ? fallback : name
    }
}

/// The head of an item: its one envelope's plaintext, a padded JSON object (docs/PROTOCOL.md, section 3.1).
public struct Head: Equatable, Sendable {
    public static let deviceNameMax = 64
    public static let nameMax = 255
    public static let hostsMax = 8
    public static let textMime = "text/plain"
    public static let replyStatus: Set<String> = ["done", "unreachable", "declined", "failed"]
    /// An offer is valid this long: its sender listens that long, then stops.
    public static let offerMs: Int64 = 120_000

    public var v: Int
    public var type: ItemType
    public var item: String
    public var device: Device
    public var ts: Int64
    public var mime: String?
    public var name: String?
    public var size: Int?
    public var fp: String?
    /// text: the content in standard base64.
    public var data: String?
    /// offer: image or file, and where the sender listens.
    public var media: ItemType?
    public var port: Int?
    public var hosts: [String]?
    /// reply: the offer it answers, and why.
    public var offer: String?
    public var status: String?

    public init(
        v: Int = ClipwayCrypto.protocolVersion, type: ItemType, item: String, device: Device, ts: Int64,
        mime: String? = nil, name: String? = nil, size: Int? = nil, fp: String? = nil, data: String? = nil,
        media: ItemType? = nil, port: Int? = nil, hosts: [String]? = nil, offer: String? = nil, status: String? = nil
    ) {
        self.v = v
        self.type = type
        self.item = item
        self.device = device
        self.ts = ts
        self.mime = mime
        self.name = name
        self.size = size
        self.fp = fp
        self.data = data
        self.media = media
        self.port = port
        self.hosts = hosts
        self.offer = offer
        self.status = status
    }

    public enum Invalid: Error, Equatable {
        case notJSON
        case rule(String)
    }

    // MARK: Serialization

    /// JSON in the reference order, serialized like JavaScript's JSON.stringify, without pad:
    /// v, type, item, device{id,name,kind}, ts, then text: mime, size, fp, data; offer: media, mime,
    /// name, size, fp, port, hosts; reply: offer, status.
    public func json() -> String {
        var out = "{\"v\":\(v),\"type\":\(Self.quote(type.rawValue)),\"item\":\(Self.quote(item)),"
        out += "\"device\":{\"id\":\(Self.quote(device.id)),\"name\":\(Self.quote(device.name)),\"kind\":\(Self.quote(device.kind.rawValue))},"
        out += "\"ts\":\(ts)"
        switch type {
        case .text:
            out += ",\"mime\":\(Self.quote(mime ?? ""))"
            out += ",\"size\":\(size ?? 0)"
            out += ",\"fp\":\(Self.quote(fp ?? ""))"
            out += ",\"data\":\(Self.quote(data ?? ""))"
        case .offer:
            out += ",\"media\":\(Self.quote(media?.rawValue ?? ""))"
            out += ",\"mime\":\(Self.quote(mime ?? ""))"
            if let name { out += ",\"name\":\(Self.quote(name))" }
            out += ",\"size\":\(size ?? 0)"
            out += ",\"fp\":\(Self.quote(fp ?? ""))"
            out += ",\"port\":\(port ?? 0)"
            out += ",\"hosts\":[" + (hosts ?? []).map(Self.quote).joined(separator: ",") + "]"
        case .reply:
            out += ",\"offer\":\(Self.quote(offer ?? ""))"
            out += ",\"status\":\(Self.quote(status ?? ""))"
        case .hello, .image, .file:
            break
        }
        return out + "}"
    }

    /// The padded plaintext of the item.
    public func serialized() throws -> String { try ClipwayCrypto.padHead(json()) }

    /// A JSON string literal exactly as JSON.stringify writes it: quote, backslash and control
    /// characters escaped, everything else (including "/" and non-ASCII) as is.
    public static func quote(_ s: String) -> String {
        var out = "\""
        out.reserveCapacity(s.utf8.count + 2)
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }

    // MARK: Parsing and validation

    /// Parses and validates a decrypted head. Unknown fields and pad are ignored.
    public static func parse(_ plaintext: Data) throws -> Head {
        guard let any = try? JSONSerialization.jsonObject(with: plaintext), let o = any as? [String: Any] else {
            throw Invalid.notJSON
        }
        return try validate(o)
    }

    static func validate(_ h: [String: Any]) throws -> Head {
        func fail(_ why: String) -> Invalid { .rule(why) }
        guard let v = integer(h["v"]), v == Int64(ClipwayCrypto.protocolVersion) else { throw fail("unknown version") }
        guard let rawType = h["type"] as? String, let type = ItemType(rawValue: rawType) else { throw fail("unknown type") }
        // Clipway 0.2 sent images and files inside items, in chunks. They travel directly now.
        guard type.travels else { throw fail("images and files travel directly") }
        guard h["chunks"] == nil else { throw fail("chunks") }
        guard let item = h["item"] as? String, ClipwayCrypto.isId(item) else { throw fail("item") }
        guard let d = h["device"] as? [String: Any], let deviceId = d["id"] as? String, ClipwayCrypto.isId(deviceId) else {
            throw fail("device.id")
        }
        guard let deviceName = d["name"] as? String, !deviceName.isEmpty, deviceName.unicodeScalars.count <= deviceNameMax else {
            throw fail("device.name")
        }
        guard let rawKind = d["kind"] as? String, let kind = DeviceKind(rawValue: rawKind) else { throw fail("device.kind") }
        guard let ts = integer(h["ts"]), ts >= 0 else { throw fail("ts") }
        var head = Head(type: type, item: item, device: Device(id: deviceId, name: deviceName, kind: kind), ts: ts)
        switch type {
        case .hello:
            return head
        case .reply:
            guard let offer = h["offer"] as? String, ClipwayCrypto.isId(offer) else { throw fail("offer") }
            guard let status = h["status"] as? String, replyStatus.contains(status) else { throw fail("status") }
            head.offer = offer
            head.status = status
            return head
        default:
            break
        }

        guard let mime = h["mime"] as? String, isMime(mime) else { throw fail("mime") }
        guard let size64 = integer(h["size"]), size64 >= 0 else { throw fail("size") }
        let size = Int(size64)
        guard let fp = h["fp"] as? String, ClipwayCrypto.isId(fp) else { throw fail("fp") }
        head.mime = mime
        head.size = size
        head.fp = fp

        if type == .text {
            if mime != textMime { throw fail("text mime") }
            if size > ClipwayCrypto.textMax { throw fail("too big") }
            if h["name"] != nil { throw fail("text with name") }
            guard let data = h["data"] as? String, isBase64(data), let bytes = Data(base64Encoded: data), bytes.count == size else {
                throw fail("data")
            }
            head.data = data
            return head
        }

        // offer
        guard let rawMedia = h["media"] as? String, let media = ItemType(rawValue: rawMedia), media == .image || media == .file else {
            throw fail("media")
        }
        if media == .image && !mime.hasPrefix("image/") { throw fail("image mime") }
        if size > ClipwayCrypto.fileMax { throw fail("too big") }
        if let raw = h["name"] {
            guard let n = raw as? String, !n.isEmpty, n.unicodeScalars.count <= nameMax else { throw fail("name") }
            head.name = n
        }
        if media == .file && head.name == nil { throw fail("file without name") }
        if h["data"] != nil { throw fail("an offer carries no content") }
        guard let port = integer(h["port"]), (1...65_535).contains(port) else { throw fail("port") }
        guard let hosts = h["hosts"] as? [Any], (1...hostsMax).contains(hosts.count) else { throw fail("hosts") }
        let list = hosts.compactMap { $0 as? String }
        guard list.count == hosts.count, list.allSatisfy(isIPv4) else { throw fail("hosts") }
        head.media = media
        head.port = Int(port)
        head.hosts = list
        return head
    }

    /// A safe integer JSON number (not a boolean, not a fraction).
    static func integer(_ any: Any?) -> Int64? {
        guard let n = any as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
        let d = n.doubleValue
        guard d.isFinite, d == d.rounded(), abs(d) <= 9_007_199_254_740_991 else { return nil }
        return n.int64Value
    }

    /// A dotted IPv4 address, without leading zeros.
    public static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            guard !p.isEmpty, p.count <= 3, p.allSatisfy({ $0.isASCII && $0.isNumber }), let n = Int(p), n <= 255 else { return false }
            return p == "0" || !p.hasPrefix("0")
        }
    }

    /// Lowercase type/subtype, no parameters (the relay crypto's RE_MIME).
    public static func isMime(_ s: String) -> Bool {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return false }
        func ok(_ p: Substring) -> Bool {
            guard let first = p.unicodeScalars.first, p.unicodeScalars.count <= 64 else { return false }
            let alnum: (Unicode.Scalar) -> Bool = { ($0 >= "a" && $0 <= "z") || ($0 >= "0" && $0 <= "9") }
            guard alnum(first) else { return false }
            return p.unicodeScalars.allSatisfy { alnum($0) || "!#$&^_.+-".unicodeScalars.contains($0) }
        }
        return ok(parts[0]) && ok(parts[1])
    }

    static func isBase64(_ s: String) -> Bool {
        guard s.utf8.count % 4 == 0 else { return false }
        var padding = 0
        for c in s.utf8 {
            let isPad = c == 61
            if padding > 0 && !isPad { return false }
            if isPad {
                padding += 1
                if padding > 2 { return false }
                continue
            }
            let ok = (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c == 43 || c == 47
            if !ok { return false }
        }
        return true
    }
}
