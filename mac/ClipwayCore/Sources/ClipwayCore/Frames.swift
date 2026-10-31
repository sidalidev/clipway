import Foundation

/// Relay frames: JSON text WebSocket frames (docs/PROTOCOL.md, section 4.2).
public enum RelayFrame: Equatable, Sendable {
    // Relay to device
    case welcome(epoch: String, devices: Int)
    case synced(last: Int)
    case item(seq: Int, part: Int, parts: Int, ts: Int64, blob: ClipwayCrypto.Envelope)
    case stored(ref: Int, seq: Int)
    case delivered(seq: Int)
    case presence(devices: Int)
    case pong
    case error(ref: Int?, code: String, message: String)

    public static let maxFrame = 131_072

    public enum Invalid: Error, Equatable {
        case notJSON, unknownKind(String), field(String)
    }

    /// Parses a frame sent by the relay.
    public static func parse(_ text: String) throws -> RelayFrame {
        guard let any = try? JSONSerialization.jsonObject(with: Data(text.utf8)), let o = any as? [String: Any] else {
            throw Invalid.notJSON
        }
        guard let kind = o["kind"] as? String else { throw Invalid.field("kind") }
        func int(_ key: String) throws -> Int {
            guard let n = Head.integer(o[key]) else { throw Invalid.field(key) }
            return Int(n)
        }
        switch kind {
        case "welcome":
            guard let epoch = o["epoch"] as? String else { throw Invalid.field("epoch") }
            return .welcome(epoch: epoch, devices: (try? int("devices")) ?? 1)
        case "synced":
            return .synced(last: try int("last"))
        case "item":
            guard let b = o["blob"] as? [String: Any], let nonce = b["nonce"] as? String, let enc = b["enc"] as? String else {
                throw Invalid.field("blob")
            }
            let ts = Head.integer(o["ts"]) ?? 0
            return .item(seq: try int("seq"), part: try int("part"), parts: try int("parts"), ts: ts,
                         blob: ClipwayCrypto.Envelope(nonce: nonce, enc: enc))
        case "stored":
            return .stored(ref: try int("ref"), seq: try int("seq"))
        case "delivered":
            return .delivered(seq: try int("seq"))
        case "presence":
            return .presence(devices: try int("devices"))
        case "pong":
            return .pong
        case "error":
            return .error(ref: Head.integer(o["ref"]).map { Int($0) }, code: o["code"] as? String ?? "",
                          message: o["message"] as? String ?? "")
        default:
            throw Invalid.unknownKind(kind)
        }
    }

    // MARK: Device to relay

    public static func sync(epoch: String, after: Int) -> String {
        "{\"kind\":\"sync\",\"epoch\":\(Head.quote(epoch)),\"after\":\(after)}"
    }

    public static func upload(ref: Int, part: Int, parts: Int, blob: ClipwayCrypto.Envelope) -> String {
        "{\"kind\":\"item\",\"ref\":\(ref),\"part\":\(part),\"parts\":\(parts),\"blob\":{\"nonce\":\(Head.quote(blob.nonce)),\"enc\":\(Head.quote(blob.enc))}}"
    }

    public static func ack(seq: Int) -> String { "{\"kind\":\"ack\",\"seq\":\(seq)}" }

    public static let ping = "{\"kind\":\"ping\"}"
}
