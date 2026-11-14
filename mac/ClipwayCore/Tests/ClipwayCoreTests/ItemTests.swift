import CryptoKit
import Foundation
import XCTest
@testable import ClipwayCore

/// Heads, texts, offers and replies against docs/VECTORS.json, byte for byte.
final class ItemTests: XCTestCase {
    typealias C = ClipwayCrypto

    nonisolated(unsafe) static let vectors: [String: Any] = {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("docs/VECTORS.json")
        return try! JSONSerialization.jsonObject(with: try! Data(contentsOf: url)) as! [String: Any]
    }()

    var v: [String: Any] { Self.vectors }
    func obj(_ key: String, in o: [String: Any]? = nil) -> [String: Any] { (o ?? v)[key] as! [String: Any] }
    var keys: ChainKeys { try! ChainKeys(secret: try! C.fromHex(v["S"] as! String)) }

    func device(_ o: [String: Any]) -> Device {
        Device(id: o["id"] as! String, name: o["name"] as! String, kind: DeviceKind(rawValue: o["kind"] as! String)!)
    }

    func testChainKeysMatchVectors() {
        XCTAssertEqual(keys.id, v["id"] as! String)
        XCTAssertEqual(keys.proofHex, v["P"] as! String)
        XCTAssertEqual(keys.subprotocols.joined(separator: ", "), v["subprotocol"] as! String)
        XCTAssertEqual(keys.words, v["words"] as! [String])
        XCTAssertEqual(keys.pairingCode(relay: ClipwayInfo.defaultRelay), v["qr"] as! String)
    }

    func envelope(_ vector: [String: Any]) -> C.Envelope {
        let e = obj("envelope", in: vector)
        return C.Envelope(nonce: e["nonce"] as! String, enc: e["enc"] as! String)
    }

    /// Builds each vector item from its head fields and content, with the vector nonce: the padded
    /// plaintext and the envelope must be identical, then the item must read back.
    func testItemsAreBuiltByteForByte() throws {
        for name in ["text_item", "hello_item"] {
            let vector = obj(name)
            let h = obj("head", in: vector)
            let type = ItemType(rawValue: h["type"] as! String)!
            let content = (h["data"] as? String).flatMap { Data(base64Encoded: $0) }
            let built = try ItemCodec.build(
                keys: keys, type: type, item: h["item"] as! String, device: device(h["device"] as! [String: Any]),
                ts: (h["ts"] as! NSNumber).int64Value, content: type == .hello ? nil : content,
                nonces: [try C.fromHex(envelope(vector).nonce)])
            XCTAssertEqual(try built.head.serialized(), vector["plaintext"] as! String, name)
            XCTAssertEqual(built.envelopes, [envelope(vector)], name)
            let read = try ItemCodec.read(keys: keys, envelopes: built.envelopes)
            XCTAssertEqual(read.head, built.head, name)
            XCTAssertEqual(read.content, type == .hello ? nil : content, name)
        }
    }

    func testOffersAndRepliesFromVectors() throws {
        let file = obj("offer_file_item")
        let h = obj("head", in: file)
        let content = Data((0..<(h["size"] as! Int)).map { UInt8($0 % 251) })
        let built = try ItemCodec.offer(
            keys: keys, item: h["item"] as! String, device: device(h["device"] as! [String: Any]), ts: (h["ts"] as! NSNumber).int64Value,
            media: .file, mime: h["mime"] as! String, name: h["name"] as? String, content: content, port: h["port"] as! Int,
            hosts: h["hosts"] as! [String], nonce: try C.fromHex(envelope(file).nonce))
        XCTAssertEqual(try built.head.serialized(), file["plaintext"] as! String)
        XCTAssertEqual(built.envelopes, [envelope(file)])

        let image = try ItemCodec.read(keys: keys, envelopes: [envelope(obj("offer_item"))])
        XCTAssertEqual(image.head.type, .offer)
        XCTAssertEqual(image.head.media, .image)
        XCTAssertEqual(image.head.name, "dot.png")
        XCTAssertEqual(image.head.port, 41_234)
        XCTAssertEqual(image.head.hosts, ["192.168.1.23", "10.0.0.7"])
        XCTAssertNil(image.content)
        XCTAssertEqual(try image.head.serialized(), obj("offer_item")["plaintext"] as! String)

        let reply = obj("reply_item")
        let rh = obj("head", in: reply)
        let r = try ItemCodec.reply(
            keys: keys, item: rh["item"] as! String, device: device(rh["device"] as! [String: Any]), ts: (rh["ts"] as! NSNumber).int64Value,
            offer: rh["offer"] as! String, status: rh["status"] as! String, nonce: try C.fromHex(envelope(reply).nonce))
        XCTAssertEqual(r.envelopes, [envelope(reply)])
        XCTAssertEqual(try ItemCodec.read(keys: keys, envelopes: r.envelopes).head.status, "unreachable")
    }

    /// Images and files inside items (Clipway 0.2), chunks and too long a text are refused.
    /// Images and files through the relay: the head and its chunks byte for byte, read back, and
    /// refused when chunks are swapped, missing, extra or from another item.
    func testChunkedItemsFromVectors() throws {
        let big = Data((0..<150_000).map { UInt8($0 % 251) })
        let pngChunk = obj("chunked_item")["chunks"] as! [[String: Any]]
        let pngEnvelope = obj("envelope", in: pngChunk[0])
        let png = try C.open(key: keys.enc, aad: pngChunk[0]["aad"] as! String,
                             envelope: C.Envelope(nonce: pngEnvelope["nonce"] as! String, enc: pngEnvelope["enc"] as! String))
        for (name, content) in [("chunked_item", png), ("chunked_file_item", big), ("chunked_empty_item", Data())] {
            let vector = obj(name)
            let h = obj("head", in: vector)
            let chunks = vector["chunks"] as! [[String: Any]]
            XCTAssertEqual(h["chunks"] as? Int, C.chunkCount(content.count), name)
            XCTAssertEqual(chunks.count, C.chunkCount(content.count), name)
            let nonces = [try C.fromHex(envelope(vector).nonce)] + (try chunks.map { try C.fromHex($0["nonce"] as! String) })
            let built = try ItemCodec.chunked(
                keys: keys, item: h["item"] as! String, device: device(h["device"] as! [String: Any]), ts: (h["ts"] as! NSNumber).int64Value,
                media: ItemType(rawValue: h["media"] as! String)!, mime: h["mime"] as! String, name: h["name"] as? String,
                content: content, nonces: nonces)
            XCTAssertEqual(try built.head.serialized(), vector["plaintext"] as! String, name)
            XCTAssertEqual(built.envelopes.first, envelope(vector), name)
            XCTAssertEqual(built.envelopes.count, 1 + chunks.count, name)
            for (i, c) in chunks.enumerated() {
                XCTAssertEqual(C.chunkAad(chainId: keys.id, item: h["item"] as! String, index: i, chunks: chunks.count), c["aad"] as! String)
                let sha = SHA256.hash(data: Data(built.envelopes[i + 1].enc.utf8)).map { String(format: "%02x", $0) }.joined()
                XCTAssertEqual(sha, c["enc_sha256"] as! String, "\(name) chunk \(i)")
                if let e = c["envelope"] as? [String: Any] {
                    XCTAssertEqual(built.envelopes[i + 1], C.Envelope(nonce: e["nonce"] as! String, enc: e["enc"] as! String))
                }
            }
            let read = try ItemCodec.read(keys: keys, envelopes: built.envelopes)
            XCTAssertEqual(read.head, built.head, name)
            XCTAssertEqual(read.content, content, name)
        }
        let me = Device(id: C.randomId(), name: "Mac", kind: .mac)
        let p = try ItemCodec.chunked(keys: keys, device: me, ts: 1, media: .file, mime: "application/octet-stream", name: "b.bin", content: big).envelopes
        let other = try ItemCodec.chunked(keys: keys, device: me, ts: 1, media: .file, mime: "application/octet-stream", name: "b.bin", content: big).envelopes
        XCTAssertThrowsError(try ItemCodec.read(keys: keys, envelopes: [p[0], p[2], p[1], p[3]]))
        XCTAssertThrowsError(try ItemCodec.read(keys: keys, envelopes: Array(p.prefix(3))))
        XCTAssertThrowsError(try ItemCodec.read(keys: keys, envelopes: p + [p[3]]))
        XCTAssertThrowsError(try ItemCodec.read(keys: keys, envelopes: [p[0], other[1], p[2], p[3]]))
        // The largest one: 65 parts under the relay's envelope limit; one byte more is refused.
        let largest = try ItemCodec.chunked(keys: keys, device: me, ts: 1, media: .file, mime: "application/zip", name: "z.zip", content: Data(count: C.relayFileMax))
        XCTAssertEqual(largest.envelopes.count, obj("limits")["parts"] as! Int)
        XCTAssertTrue(largest.envelopes.allSatisfy { $0.enc.count <= obj("limits")["enc"] as! Int })
        XCTAssertThrowsError(try ItemCodec.chunked(keys: keys, device: me, ts: 1, media: .file, mime: "application/zip", name: "z.zip", content: Data(count: C.relayFileMax + 1)))
        XCTAssertEqual(C.chunkSize, obj("limits")["chunk"] as! Int)
        XCTAssertEqual(C.relayFileMax, obj("limits")["relay_file"] as! Int)
        XCTAssertEqual(C.partsMax, obj("limits")["parts"] as! Int)
    }

    func testRefusedHeads() throws {
        for c in obj("refused_heads")["cases"] as! [[String: Any]] {
            let e = obj("envelope", in: c)
            XCTAssertThrowsError(try ItemCodec.read(keys: keys, envelopes: [C.Envelope(nonce: e["nonce"] as! String, enc: e["enc"] as! String)]),
                                 c["why"] as! String)
        }
    }

    func testSizes() throws {
        let me = Device(id: C.randomId(), name: "Mac", kind: .mac)
        let max = try ItemCodec.build(keys: keys, type: .text, device: me, ts: 1, content: Data(repeating: 0x61, count: C.textMax))
        XCTAssertEqual(max.envelopes.count, 1)
        XCTAssertLessThanOrEqual(max.envelopes[0].enc.count, obj("limits")["enc"] as! Int)
        XCTAssertThrowsError(try ItemCodec.build(keys: keys, type: .text, device: me, ts: 1, content: Data(count: C.textMax + 1)))
        XCTAssertThrowsError(try ItemCodec.build(keys: keys, type: .image, device: me, ts: 1, content: Data(count: 10)))
        let offer = try ItemCodec.offer(keys: keys, device: me, ts: 1, media: .file, mime: "application/zip", name: "big.zip",
                                        content: Data(count: C.fileMax), port: 40_000, hosts: ["192.168.1.10"])
        XCTAssertEqual(try C.open(key: keys.enc, aad: keys.id, envelope: offer.envelopes[0]).count, 512)
        XCTAssertThrowsError(try ItemCodec.offer(keys: keys, device: me, ts: 1, media: .file, mime: "application/zip", name: "big.zip",
                                                 content: Data(count: C.fileMax + 1), port: 40_000, hosts: ["192.168.1.10"]))
        XCTAssertThrowsError(try ItemCodec.read(keys: keys, envelopes: max.envelopes + max.envelopes))
        let wrongChain = try ChainKeys(secret: C.generateSecret())
        XCTAssertThrowsError(try ItemCodec.read(keys: wrongChain, envelopes: max.envelopes))
    }

    func testHeadSerializationEscapesLikeJavaScript() throws {
        XCTAssertEqual(Head.quote("a/b \"q\" \\ \n\t\u{01} café 👋"), "\"a/b \\\"q\\\" \\\\ \\n\\t\\u0001 café 👋\"")
        let me = Device(id: C.randomId(), name: "Sid's \"Mac\"", kind: .mac)
        let built = try ItemCodec.build(keys: keys, type: .text, device: me, ts: 5, content: Data("line 1\nline 2 </script>".utf8))
        let plaintext = try built.head.serialized()
        XCTAssertEqual(plaintext.utf8.count % C.padBlock, 0)
        let reparsed = try JSONSerialization.jsonObject(with: Data(plaintext.utf8)) as! [String: Any]
        XCTAssertEqual((reparsed["device"] as! [String: Any])["name"] as! String, "Sid's \"Mac\"")
        XCTAssertEqual(try ItemCodec.read(keys: keys, envelopes: built.envelopes).head.device.name, "Sid's \"Mac\"")
    }

    func testHeadRulesRefuseBadHeads() {
        func refuses(_ json: String, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertThrowsError(try Head.parse(Data(json.utf8)), file: file, line: line)
        }
        let dev = "\"device\":{\"id\":\"f0e1d2c3b4a5968778695a4b3c2d1e0f\",\"name\":\"M\",\"kind\":\"mac\"}"
        let item = "\"item\":\"00112233445566778899aabbccddeeff\""
        let fp = "\"fp\":\"963175147d5b7e6d67e6f296258e84b5\""
        XCTAssertNoThrow(try Head.parse(Data("{\"v\":1,\"type\":\"hello\",\(item),\(dev),\"ts\":1,\"pad\":\"  \",\"later\":3}".utf8)))
        refuses("{\"v\":2,\"type\":\"hello\",\(item),\(dev),\"ts\":1}")
        refuses("{\"v\":true,\"type\":\"hello\",\(item),\(dev),\"ts\":1}")
        refuses("{\"v\":1,\"type\":\"note\",\(item),\(dev),\"ts\":1}")
        refuses("{\"v\":1,\"type\":\"hello\",\"item\":\"XYZ\",\(dev),\"ts\":1}")
        refuses("{\"v\":1,\"type\":\"hello\",\(item),\(dev),\"ts\":1.5}")
        refuses("{\"v\":1,\"type\":\"text\",\(item),\(dev),\"ts\":1,\"mime\":\"text/html\",\"size\":1,\(fp),\"data\":\"YQ==\"}")
        refuses("{\"v\":1,\"type\":\"text\",\(item),\(dev),\"ts\":1,\"mime\":\"text/plain\",\"name\":\"a\",\"size\":1,\(fp),\"data\":\"YQ==\"}")
        refuses("{\"v\":1,\"type\":\"file\",\(item),\(dev),\"ts\":1,\"mime\":\"application/pdf\",\"name\":\"a\",\"size\":1,\(fp),\"data\":\"YQ==\"}")
        refuses("{\"v\":1,\"type\":\"text\",\(item),\(dev),\"ts\":1,\"mime\":\"text/plain\",\"size\":2,\(fp),\"data\":\"YQ==\"}")
        refuses("{\"v\":1,\"type\":\"text\",\(item),\(dev),\"ts\":1,\"mime\":\"text/plain\",\"size\":1,\(fp)}")
        refuses("{\"v\":1,\"type\":\"text\",\(item),\(dev),\"ts\":1,\"mime\":\"text/plain\",\"size\":1,\(fp),\"data\":\"YQ==\",\"chunks\":1}")
        refuses("{\"v\":1,\"type\":\"image\",\(item),\(dev),\"ts\":1,\"mime\":\"image/png\",\"size\":1,\(fp),\"data\":\"YQ==\"}")
        let offer = "\"type\":\"offer\",\(item),\(dev),\"ts\":1,\"size\":1,\(fp)"
        XCTAssertNoThrow(try Head.parse(Data("{\"v\":1,\(offer),\"media\":\"image\",\"mime\":\"image/png\",\"port\":1,\"hosts\":[\"10.0.0.1\"]}".utf8)))
        refuses("{\"v\":1,\(offer),\"media\":\"video\",\"mime\":\"video/mp4\",\"port\":1,\"hosts\":[\"10.0.0.1\"]}")
        refuses("{\"v\":1,\(offer),\"media\":\"image\",\"mime\":\"application/pdf\",\"port\":1,\"hosts\":[\"10.0.0.1\"]}")
        refuses("{\"v\":1,\(offer),\"media\":\"file\",\"mime\":\"application/pdf\",\"port\":1,\"hosts\":[\"10.0.0.1\"]}")
        refuses("{\"v\":1,\(offer),\"media\":\"image\",\"mime\":\"image/png\",\"port\":0,\"hosts\":[\"10.0.0.1\"]}")
        refuses("{\"v\":1,\(offer),\"media\":\"image\",\"mime\":\"image/png\",\"port\":1,\"hosts\":[]}")
        refuses("{\"v\":1,\(offer),\"media\":\"image\",\"mime\":\"image/png\",\"port\":1,\"hosts\":[\"mac.local\"]}")
        refuses("{\"v\":1,\(offer),\"media\":\"image\",\"mime\":\"image/png\",\"port\":1,\"hosts\":[\"10.0.0.01\"]}")
        refuses("{\"v\":1,\(offer),\"media\":\"image\",\"mime\":\"image/png\",\"port\":1,\"hosts\":[\"10.0.0.1\"],\"data\":\"YQ==\"}")
        refuses("{\"v\":1,\(offer),\"media\":\"image\",\"mime\":\"image/png\",\"port\":1,\"hosts\":[\"10.0.0.1\"],\"chunks\":1}")
        let chunked = "\"type\":\"chunked\",\(item),\(dev),\"ts\":1,\(fp)"
        XCTAssertEqual(try Head.parse(Data("{\"v\":1,\(chunked),\"media\":\"image\",\"mime\":\"image/png\",\"size\":70000,\"chunks\":2}".utf8)).chunks, 2)
        refuses("{\"v\":1,\(chunked),\"media\":\"image\",\"mime\":\"image/png\",\"size\":70000,\"chunks\":1}")
        refuses("{\"v\":1,\(chunked),\"media\":\"image\",\"mime\":\"image/png\",\"size\":70000}")
        refuses("{\"v\":1,\(chunked),\"media\":\"image\",\"mime\":\"text/plain\",\"size\":70000,\"chunks\":2}")
        refuses("{\"v\":1,\(chunked),\"media\":\"file\",\"mime\":\"text/plain\",\"size\":70000,\"chunks\":2}")
        refuses("{\"v\":1,\(chunked),\"media\":\"image\",\"mime\":\"image/png\",\"size\":4194305,\"chunks\":65}")
        refuses("{\"v\":1,\(chunked),\"media\":\"image\",\"mime\":\"image/png\",\"size\":1,\"chunks\":1,\"data\":\"YQ==\"}")
        refuses("{\"v\":1,\"type\":\"reply\",\(item),\(dev),\"ts\":1,\"offer\":\"00112233445566778899aabbccddeeff\",\"status\":\"maybe\"}")
        refuses("not json")
    }

    func testFrames() throws {
        let f = obj("frames")
        func text(_ key: String) -> String { String(decoding: try! JSONSerialization.data(withJSONObject: f[key]!), as: UTF8.self) }
        XCTAssertEqual(try RelayFrame.parse(text("welcome")), .welcome(epoch: "5f3a9c0d1e2b4a68", devices: 2, parts: 65))
        XCTAssertEqual(try RelayFrame.parse("{\"kind\":\"welcome\",\"epoch\":\"e\",\"devices\":1}"), .welcome(epoch: "e", devices: 1, parts: 1))
        XCTAssertEqual(try RelayFrame.parse(text("synced")), .synced(last: 42))
        XCTAssertEqual(try RelayFrame.parse(text("stored")), .stored(ref: 7, seq: 43))
        XCTAssertEqual(try RelayFrame.parse(text("delivered")), .delivered(seq: 43))
        XCTAssertEqual(try RelayFrame.parse(text("presence")), .presence(devices: 1))
        XCTAssertEqual(try RelayFrame.parse(text("pong")), .pong)
        XCTAssertEqual(try RelayFrame.parse(text("error")), .error(ref: 7, code: "too_big", message: f["error"].flatMap { ($0 as? [String: Any])?["message"] as? String } ?? ""))
        let blob = obj("blob", in: obj("delivery", in: f))
        XCTAssertEqual(
            try RelayFrame.parse(text("delivery")),
            .item(seq: 43, part: 0, parts: 1, ts: 1_792_300_000_005, blob: C.Envelope(nonce: blob["nonce"] as! String, enc: blob["enc"] as! String)))
        XCTAssertThrowsError(try RelayFrame.parse("{\"kind\":\"later\"}"))

        func same(_ mine: String, _ key: String) {
            let a = try! JSONSerialization.jsonObject(with: Data(mine.utf8)) as! NSDictionary
            XCTAssertEqual(a, f[key] as! NSDictionary, key)
        }
        same(RelayFrame.sync(epoch: "5f3a9c0d1e2b4a68", after: 41), "sync")
        same(RelayFrame.ack(seq: 43), "ack")
        same(RelayFrame.ping, "ping")
        let up = obj("blob", in: obj("upload", in: f))
        same(RelayFrame.upload(ref: 7, part: 0, parts: 1, blob: C.Envelope(nonce: up["nonce"] as! String, enc: up["enc"] as! String)), "upload")
        let chunk = obj("blob", in: obj("upload_chunked", in: f))
        same(RelayFrame.upload(ref: 8, part: 1, parts: 2, blob: C.Envelope(nonce: chunk["nonce"] as! String, enc: chunk["enc"] as! String)), "upload_chunked")
    }
}
