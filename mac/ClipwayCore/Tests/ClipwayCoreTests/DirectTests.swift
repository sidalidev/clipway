import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import ClipwayCore

/// Direct transfer (docs/PROTOCOL.md, section 14): the vectors, then a real transfer on the loopback interface.
final class DirectTests: XCTestCase {
    typealias C = ClipwayCrypto

    var v: [String: Any] { ItemTests.vectors }
    var d: [String: Any] { v["direct"] as! [String: Any] }
    func obj(_ key: String, in o: [String: Any]) -> [String: Any] { o[key] as! [String: Any] }
    var keys: ChainKeys { try! ChainKeys(secret: try! C.fromHex(v["S"] as! String)) }
    var transfer: String { d["transfer"] as! String }
    var kT: SymmetricKey { try! Direct.transferKey(direct: keys.direct, transfer: transfer) }
    func content() -> Data { Data((0..<(d["size"] as! Int)).map { UInt8($0 % 251) }) }

    func testKeysAndPreamble() throws {
        XCTAssertEqual(C.hex(C.bytes(keys.direct)), d["K_direct"] as! String)
        XCTAssertEqual(C.hex(C.bytes(kT)), d["K_t"] as! String)
        XCTAssertEqual(C.hex(try Direct.preamble(transfer)), d["preamble"] as! String)
        XCTAssertEqual(Direct.readPreamble(try Direct.preamble(transfer)), transfer)
        XCTAssertNil(Direct.readPreamble(Data("CWD2".utf8) + Data(count: 16)))
        XCTAssertEqual(Direct.recordData, d["record_data"] as! Int)
        XCTAssertEqual(Direct.recordMax, d["record_max"] as! Int)
    }

    func testRecords() throws {
        let get0 = obj("get0", in: d)
        let sealed = try Direct.sealRecord(key: kT, transfer: transfer, dir: "get", index: 0,
                                           plaintext: Data((get0["plaintext_utf8"] as! String).utf8), nonce: try C.fromHex(get0["nonce"] as! String))
        XCTAssertEqual(C.hex(sealed), get0["bytes"] as! String)
        XCTAssertEqual(Direct.getRequest(transfer), get0["plaintext_utf8"] as! String)
        let data = content()
        XCTAssertEqual(C.hex(C.sha256(data)), d["content_sha256"] as! String)
        let puts = d["puts"] as! [[String: Any]]
        XCTAssertEqual(Direct.recordCount(data.count), puts.count)
        for (i, r) in puts.enumerated() {
            let slice = data.subdata(in: (i * Direct.recordData)..<min(data.count, (i + 1) * Direct.recordData))
            let bytes = try Direct.sealRecord(key: kT, transfer: transfer, dir: "put", index: i, plaintext: slice, nonce: try C.fromHex(r["nonce"] as! String))
            XCTAssertEqual(bytes.count, r["length"] as! Int)
            XCTAssertEqual(C.hex(C.sha256(bytes)), r["sha256"] as! String)
            if i == 0 { XCTAssertEqual(C.hex(bytes.prefix(64)), d["put0_head"] as! String) }
        }
        let get1 = try C.fromHex(obj("get1", in: d)["bytes"] as! String)
        XCTAssertEqual(String(decoding: try Direct.openRecord(key: kT, transfer: transfer, dir: "get", index: 1, body: get1.dropFirst(4)), as: UTF8.self),
                       Direct.getStatus("done"))
        let body = try C.fromHex(get0["bytes"] as! String).dropFirst(4)
        XCTAssertThrowsError(try Direct.openRecord(key: kT, transfer: transfer, dir: "put", index: 0, body: body))
        XCTAssertThrowsError(try Direct.openRecord(key: kT, transfer: transfer, dir: "get", index: 1, body: body))
        let other = obj("head", in: v["offer_item"] as! [String: Any])["item"] as! String
        XCTAssertThrowsError(try Direct.openRecord(key: try Direct.transferKey(direct: keys.direct, transfer: other), transfer: other, dir: "get", index: 0, body: body))
        let tampered = try C.fromHex(obj("negative", in: d)["tampered_get0"] as! String)
        XCTAssertThrowsError(try Direct.openRecord(key: kT, transfer: transfer, dir: "get", index: 0, body: tampered.dropFirst(4)))
    }

    func testAddresses() {
        let h = obj("private_hosts", in: d)
        for host in h["allowed"] as! [String] { XCTAssertTrue(Direct.isPrivate(host), host) }
        for host in h["refused"] as! [String] { XCTAssertFalse(Direct.isPrivate(host), host) }
        XCTAssertFalse(Direct.mayConnect("127.0.0.1", debug: false))
        XCTAssertTrue(Direct.mayConnect("127.0.0.1", debug: true))
        for host in Direct.localHosts() { XCTAssertTrue(Direct.isPrivate(host)) }
    }

    final class Box: @unchecked Sendable {
        let done = XCTestExpectation(description: "outcome")
        var outcome: Direct.Outcome?
        func set(_ o: Direct.Outcome) {
            outcome = o
            done.fulfill()
        }
    }

    func head(_ item: String, _ data: Data, _ port: Int) -> Head {
        Head(type: .offer, item: item, device: Device(id: C.randomId(), name: "Mac", kind: .mac), ts: 1, mime: "application/octet-stream",
             name: "a.bin", size: data.count, fp: keys.fingerprint(data), media: .file, port: port, hosts: ["127.0.0.1"])
    }

    func testAFileGoesOnceFromSenderToReceiver() throws {
        let server = Direct.Server()
        let data = C.randomBytes(1_000_003)
        let item = C.randomId()
        let box = Box()
        let port = try server.offer(transfer: item, key: try Direct.transferKey(direct: keys.direct, transfer: item), content: data) { box.set($0) }
        var saved: Data?
        XCTAssertEqual(Direct.fetch(keys: keys, head: head(item, data, port), debug: true) { saved = $0 }, .ok(data))
        XCTAssertEqual(saved, data)
        wait(for: [box.done], timeout: 10)
        XCTAssertEqual(box.outcome, .done)
        XCTAssertNotEqual(Direct.fetch(keys: keys, head: head(item, data, port), debug: true) { _ in }, .ok(data))
    }

    func testTheReferenceVectorTransfers() throws {
        let server = Direct.Server()
        let box = Box()
        let data = content()
        let port = try server.offer(transfer: transfer, key: kT, content: data) { box.set($0) }
        XCTAssertEqual(Direct.fetch(keys: keys, head: head(transfer, data, port), debug: true) { _ in }, .ok(data))
        wait(for: [box.done], timeout: 10)
        XCTAssertEqual(box.outcome, .done)
    }

    func testStrangersGetNothing() throws {
        let server = Direct.Server()
        let data = C.randomBytes(5_000)
        let item = C.randomId()
        let box = Box()
        let port = try server.offer(transfer: item, key: try Direct.transferKey(direct: keys.direct, transfer: item), content: data) { box.set($0) }
        let other = try ChainKeys(secret: C.generateSecret())
        XCTAssertEqual(Direct.fetch(keys: other, head: head(item, data, port), debug: true) { _ in }, .failed)
        let raw = Direct.connect(host: "127.0.0.1", port: port, ms: 1000)!
        try raw.write(try Direct.preamble(item) + Data([0, 0, 0, 40]) + Data(count: 40))
        raw.timeout(ms: 3000)
        XCTAssertThrowsError(try raw.read(1))
        raw.close()
        XCTAssertEqual(Direct.fetch(keys: keys, head: head(item, data, port), debug: true) { _ in }, .ok(data))
        wait(for: [box.done], timeout: 10)
        XCTAssertEqual(box.outcome, .done)
    }

    func testAWrongFingerprintIsNotSaved() throws {
        let server = Direct.Server()
        let data = C.randomBytes(70_000)
        let item = C.randomId()
        let box = Box()
        let port = try server.offer(transfer: item, key: try Direct.transferKey(direct: keys.direct, transfer: item), content: data) { box.set($0) }
        var h = head(item, data, port)
        h.fp = String(repeating: "0", count: 32)
        var saved = false
        XCTAssertEqual(Direct.fetch(keys: keys, head: h, debug: true) { _ in saved = true }, .failed)
        XCTAssertFalse(saved)
        wait(for: [box.done], timeout: 20)
        XCTAssertEqual(box.outcome, .failed)
    }

    func testUnreachableAndExpired() throws {
        var h = head(C.randomId(), Data(count: 10), 9)
        h.hosts = ["127.0.0.1", "8.8.8.8"]
        XCTAssertEqual(Direct.fetch(keys: keys, head: h, debug: false) { _ in }, .unreachable)
        let server = Direct.Server(ttlMs: 100)
        let box = Box()
        let item = C.randomId()
        _ = try server.offer(transfer: item, key: try Direct.transferKey(direct: keys.direct, transfer: item), content: Data(count: 10)) { box.set($0) }
        wait(for: [box.done], timeout: 5)
        XCTAssertEqual(box.outcome, .expired)
        let box2 = Box()
        let item2 = C.randomId()
        _ = try server.offer(transfer: item2, key: try Direct.transferKey(direct: keys.direct, transfer: item2), content: Data(count: 10)) { box2.set($0) }
        server.cancel(item2, outcome: .unreachable)
        wait(for: [box2.done], timeout: 5)
        XCTAssertEqual(box2.outcome, .unreachable)
        XCTAssertFalse(server.isOpen(item2))
    }
}
