import Foundation
import XCTest
@testable import ClipwayCore

/// The client protocol state machine against scripted relay frames.
@MainActor
final class SyncEngineTests: XCTestCase {
    typealias C = ClipwayCrypto

    let keys = try! ChainKeys(secret: C.generateSecret())
    let mac = Device(id: C.randomId(), name: "Mac", kind: .mac)
    let phone = Device(id: C.randomId(), name: "Pixel", kind: .android)
    var clock: Int64 = 1_792_300_000_000
    var sent: [[String: Any]] = []
    var received: [SyncEngine.Incoming] = []
    var statuses: [(String, HistoryEntry.Status)] = []
    var accept = true

    func makeEngine(cursor: SyncEngine.Cursor = .init()) -> SyncEngine {
        let e = SyncEngine(keys: keys, deviceId: mac.id, cursor: cursor)
        e.now = { [unowned self] in self.clock }
        e.send = { [unowned self] text in
            self.sent.append(try! JSONSerialization.jsonObject(with: Data(text.utf8)) as! [String: Any])
        }
        e.onReceive = { [unowned self] item in
            self.received.append(item)
            return self.accept
        }
        e.onStatus = { [unowned self] item, status in self.statuses.append((item, status)) }
        e.schedule = { _, _ in }
        return e
    }

    func deliver(_ e: SyncEngine, seq: Int, _ built: ItemCodec.Built) {
        for (i, blob) in built.envelopes.enumerated() {
            let frame = "{\"kind\":\"item\",\"seq\":\(seq),\"part\":\(i),\"parts\":\(built.envelopes.count),\"ts\":\(clock),\"blob\":{\"nonce\":\"\(blob.nonce)\",\"enc\":\"\(blob.enc)\"}}"
            XCTAssertTrue(e.receive(frame))
        }
    }

    func text(_ s: String, from device: Device, ts: Int64? = nil) throws -> ItemCodec.Built {
        try ItemCodec.build(keys: keys, type: .text, device: device, ts: ts ?? clock, content: Data(s.utf8))
    }

    func kinds() -> [String] { sent.map { $0["kind"] as! String } }

    func testHandshakeBacklogAcksAndCursor() throws {
        let e = makeEngine(cursor: .init(epoch: "aaaa", after: 7))
        e.connected()
        e.receive("{\"kind\":\"welcome\",\"v\":1,\"epoch\":\"bbbb\",\"devices\":2,\"limits\":{}}")
        XCTAssertEqual(sent.first?["kind"] as? String, "sync")
        XCTAssertEqual(sent.first?["epoch"] as? String, "aaaa", "the last epoch seen is sent")
        XCTAssertEqual(sent.first?["after"] as? Int, 7)
        XCTAssertEqual(e.cursor, .init(epoch: "bbbb", after: 0), "a new epoch restarts from 0")
        XCTAssertEqual(e.phase, .syncing)

        // Nothing is sent before synced.
        e.enqueue(try text("from the Mac", from: mac))
        XCTAssertEqual(kinds(), ["sync"])

        deliver(e, seq: 1, try text("one", from: phone))
        deliver(e, seq: 2, try text("two", from: phone))
        XCTAssertEqual(received.map { String(decoding: $0.content!, as: UTF8.self) }, ["one", "two"])
        XCTAssertEqual(kinds(), ["sync", "ack", "ack"])
        XCTAssertEqual(e.cursor.after, 2)

        e.receive("{\"kind\":\"synced\",\"last\":2}")
        XCTAssertEqual(e.phase, .ready)
        XCTAssertEqual(kinds(), ["sync", "ack", "ack", "item"])
        XCTAssertEqual(sent.last?["part"] as? Int, 0)
        let ref = sent.last?["ref"] as! Int

        e.receive("{\"kind\":\"stored\",\"ref\":\(ref),\"seq\":3}")
        XCTAssertEqual(statuses.last?.1, .sent)
        XCTAssertEqual(e.cursor.after, 3)
        XCTAssertEqual(e.pendingCount, 0)
        e.receive("{\"kind\":\"delivered\",\"seq\":3}")
        XCTAssertEqual(statuses.last?.1, .delivered)
    }

    func testDuplicatesStaleAndOwnItems() throws {
        let e = makeEngine()
        e.connected()
        e.receive("{\"kind\":\"welcome\",\"v\":1,\"epoch\":\"e1\",\"devices\":2}")
        let item = try text("hi", from: phone)
        deliver(e, seq: 1, item)
        deliver(e, seq: 2, item)
        XCTAssertEqual(received.count, 1, "a replayed item is dropped")
        XCTAssertEqual(kinds(), ["sync", "ack", "ack"], "and acknowledged")

        deliver(e, seq: 3, try text("old", from: phone, ts: clock - 25 * 3_600_000))
        XCTAssertEqual(received.count, 1)
        XCTAssertEqual(kinds().last, "ack")

        deliver(e, seq: 4, try text("mine", from: mac))
        XCTAssertEqual(received.count, 1)
        XCTAssertEqual(kinds().filter { $0 == "ack" }.count, 3, "own items are never acknowledged")
        XCTAssertEqual(e.cursor.after, 4)

        // A part from another chain: unreadable, acknowledged so the relay forgets it.
        let other = try ChainKeys(secret: C.generateSecret())
        deliver(e, seq: 5, try ItemCodec.build(keys: other, type: .text, device: phone, ts: clock, content: Data("x".utf8)))
        XCTAssertEqual(received.count, 1)
        XCTAssertEqual(e.dropped, 2)
        XCTAssertEqual(kinds().last, "ack")
    }

    func testUnwrittenItemsAreNotAcknowledgedAndHoldTheCursor() throws {
        let e = makeEngine()
        e.connected()
        e.receive("{\"kind\":\"welcome\",\"v\":1,\"epoch\":\"e1\",\"devices\":2}")
        accept = false
        deliver(e, seq: 1, try text("disk full", from: phone))
        XCTAssertEqual(kinds(), ["sync"])
        accept = true
        deliver(e, seq: 2, try text("fine", from: phone))
        XCTAssertEqual(kinds(), ["sync", "ack"])
        XCTAssertEqual(e.cursor.after, 0, "after never passes an item still being handled")
    }

    func testOneEnvelopePerItemAndResendAfterReconnect() throws {
        let e = makeEngine()
        e.connected()
        e.receive("{\"kind\":\"welcome\",\"v\":1,\"epoch\":\"e1\",\"devices\":1}")
        e.receive("{\"kind\":\"synced\",\"last\":0}")
        let big = Data(repeating: 0x7A, count: C.textMax)
        let built = try ItemCodec.build(keys: keys, type: .text, device: mac, ts: clock, content: big)
        e.enqueue(built)
        XCTAssertEqual(kinds(), ["sync", "item"], "the largest text is one envelope")
        XCTAssertEqual(sent.last?["parts"] as? Int, 1)

        // Connection lost before stored: the item is sent again, same item id.
        e.disconnected()
        sent = []
        e.connected()
        e.receive("{\"kind\":\"welcome\",\"v\":1,\"epoch\":\"e1\",\"devices\":1}")
        e.receive("{\"kind\":\"synced\",\"last\":0}")
        XCTAssertEqual(kinds(), ["sync", "item"])
        let ref = sent.last?["ref"] as! Int
        e.receive("{\"kind\":\"stored\",\"ref\":\(ref),\"seq\":1}")
        XCTAssertEqual(statuses.last?.0, built.head.item)
        XCTAssertEqual(statuses.last?.1, .waiting, "one device connected: waiting for the phone")

        // An offer from the phone is handed over without content; an old one is dropped and acknowledged.
        let offer = try ItemCodec.offer(keys: keys, device: phone, ts: clock, media: .image, mime: "image/png", name: nil,
                                        content: Data(count: 10), port: 41_234, hosts: ["192.168.1.23"])
        deliver(e, seq: 2, offer)
        XCTAssertEqual(received.last?.head.type, .offer)
        XCTAssertNil(received.last?.content)
        let old = try ItemCodec.offer(keys: keys, device: phone, ts: clock - Head.offerMs - 1, media: .file, mime: "application/pdf",
                                      name: "a.pdf", content: Data(count: 10), port: 41_234, hosts: ["192.168.1.23"])
        let count = received.count
        deliver(e, seq: 3, old)
        XCTAssertEqual(received.count, count)
        XCTAssertEqual(kinds().last, "ack")
    }

    func testRelayErrors() throws {
        let e = makeEngine()
        e.connected()
        e.receive("{\"kind\":\"welcome\",\"v\":1,\"epoch\":\"e1\",\"devices\":2}")
        e.receive("{\"kind\":\"synced\",\"last\":0}")
        let a = try text("a", from: mac)
        e.enqueue(a)
        let ref = sent.last?["ref"] as! Int
        e.receive("{\"kind\":\"error\",\"ref\":\(ref),\"code\":\"rate_limited\",\"message\":\"slow down\"}")
        XCTAssertEqual(e.pendingCount, 1, "kept for later")
        clock += SyncEngine.retryDelayMs
        e.pump()
        let again = sent.last?["ref"] as! Int
        XCTAssertNotEqual(again, ref)
        e.receive("{\"kind\":\"error\",\"ref\":\(again),\"code\":\"too_big\",\"message\":\"no\"}")
        XCTAssertEqual(e.pendingCount, 0)
        XCTAssertEqual(statuses.last?.1, .failed)
    }

    func testHelloIsSentButNotShown() throws {
        let e = makeEngine()
        e.connected()
        e.receive("{\"kind\":\"welcome\",\"v\":1,\"epoch\":\"e1\",\"devices\":2}")
        e.receive("{\"kind\":\"synced\",\"last\":0}")
        e.enqueue(try ItemCodec.build(keys: keys, type: .hello, device: mac, ts: clock))
        let ref = sent.last?["ref"] as! Int
        e.receive("{\"kind\":\"stored\",\"ref\":\(ref),\"seq\":1}")
        XCTAssertTrue(statuses.isEmpty)
        deliver(e, seq: 2, try ItemCodec.build(keys: keys, type: .hello, device: phone, ts: clock))
        XCTAssertEqual(received.last?.head.type, .hello)
        XCTAssertEqual(received.last?.head.device.name, "Pixel")
    }
}
