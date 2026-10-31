import CryptoKit
import Foundation
import XCTest
@testable import ClipwayCore

/// Nearby pairing (docs/PROTOCOL.md, section 13) against the nearby block of docs/VECTORS.json,
/// shared with relay/nearby.js and the Android app.
final class NearbyTests: XCTestCase {
    typealias C = ClipwayCrypto

    nonisolated(unsafe) private static let file: Data = {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("docs/VECTORS.json")
        return try! Data(contentsOf: url)
    }()

    nonisolated(unsafe) private static let root: [String: Any] = try! JSONSerialization.jsonObject(with: file) as! [String: Any]

    private var n: [String: Any] { Self.root["nearby"] as! [String: Any] }
    private func str(_ key: String, in o: [String: Any]? = nil) -> String { (o ?? n)[key] as! String }
    private func bytes(_ key: String, in o: [String: Any]? = nil) -> Data { try! C.fromHex(str(key, in: o)) }
    private func obj(_ key: String, in o: [String: Any]? = nil) -> [String: Any] { (o ?? n)[key] as! [String: Any] }
    private var s: Data { try! C.fromHex(Self.root["S"] as! String) }
    private var pkMac: Data { bytes("mac_public") }
    private var pkPhone: Data { bytes("phone_public") }
    private func key(_ name: String, in o: [String: Any]? = nil) throws -> Nearby.PrivateKey { try Nearby.privateKey(raw: bytes(name, in: o)) }

    func testServiceAndCharacteristics() {
        XCTAssertEqual(Nearby.serviceUUID, str("service"))
        XCTAssertEqual(Nearby.cccdUUID, str("cccd"))
        let characteristics = obj("characteristics") as! [String: String]
        XCTAssertEqual(characteristics.count, 6)
        for c in Nearby.Characteristic.allCases {
            XCTAssertEqual(c.uuid, characteristics[c.rawValue], c.rawValue)
            XCTAssertEqual(Nearby.Characteristic(uuid: c.uuid.uppercased()), c)
        }
        XCTAssertNil(Nearby.Characteristic(uuid: Nearby.serviceUUID))
        let status = obj("status") as! [String: Int]
        XCTAssertEqual(status["ready"], Int(Nearby.Status.ready.rawValue))
        XCTAssertEqual(status["busy"], Int(Nearby.Status.busy.rawValue))
        let att = obj("att_errors") as! [String: Int]
        XCTAssertEqual(att["invalidAttributeValueLength"], Int(Nearby.ATTError.invalidAttributeValueLength.rawValue))
        XCTAssertEqual(att["unlikelyError"], Int(Nearby.ATTError.unlikelyError.rawValue))
        XCTAssertEqual(Nearby.packetSize, 284)
        XCTAssertEqual(n["max_code_length"] as? Int, Nearby.maxCodeLength)
    }

    func testRFC7748KeyPair() throws {
        let mac = try key("mac_private")
        let phone = try key("phone_private")
        XCTAssertEqual(C.hex(mac.publicKey.rawRepresentation), str("mac_public"))
        XCTAssertEqual(C.hex(phone.publicKey.rawRepresentation), str("phone_public"))
        XCTAssertEqual(C.hex(try Nearby.sharedSecret(mac, pkPhone)), str("shared"))
        XCTAssertEqual(C.hex(try Nearby.sharedSecret(phone, pkMac)), str("shared"))
        XCTAssertEqual(str("shared"), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    }

    func testCommitmentKeysCodeAndConfirmation() throws {
        XCTAssertEqual(C.hex(Nearby.commitment(pkMac)), str("commit"))
        XCTAssertEqual(C.hex(Nearby.transcript(pkMac, pkPhone)), str("transcript"))
        let k = Nearby.derive(z: bytes("shared"), pkMac: pkMac, pkPhone: pkPhone)
        XCTAssertEqual(C.hex(k.n), str("N"))
        XCTAssertEqual(C.hex(k.sas), str("K_sas"))
        XCTAssertEqual(C.hex(k.key), str("K_key"))
        XCTAssertEqual(C.hex(Nearby.sasBytes(kSas: k.sas, pkMac: pkMac, pkPhone: pkPhone)), str("sas_bytes"))
        XCTAssertEqual(Nearby.sasCode(kSas: k.sas, pkMac: pkMac, pkPhone: pkPhone), "5456")
        XCTAssertEqual(str("sas"), "5456")
        XCTAssertEqual(C.hex(Nearby.confirmTag(kSas: k.sas, pkMac: pkMac, pkPhone: pkPhone)), "728d99b4c5f2a3e067b4e71d736d7948")
        XCTAssertTrue(Nearby.checkConfirm(kSas: k.sas, pkMac: pkMac, pkPhone: pkPhone, tag: bytes("confirm")))
        XCTAssertEqual(Nearby.packetAad(pkMac: pkMac, pkPhone: pkPhone), str("aad"))
        XCTAssertEqual(Nearby.packetAad(pkMac: pkMac, pkPhone: pkPhone).utf8.count, 144)
        // The order is fixed by role: swapping the keys changes the code.
        XCTAssertNotEqual(Nearby.sasCode(kSas: k.sas, pkMac: pkPhone, pkPhone: pkMac), str("sas"))

        let phone = try Nearby.phoneHandshake(privateKey: try key("phone_private"), commit: bytes("commit"), pkMac: pkMac)
        XCTAssertEqual(phone.pkPhone, pkPhone)
        XCTAssertEqual(phone.sas, str("sas"))
        XCTAssertEqual(C.hex(phone.confirm), str("confirm"))
        XCTAssertEqual(C.hex(phone.key), str("K_key"))
    }

    func testCodeDigitsAndLeadingZero() throws {
        for sample in n["sas_samples"] as! [[String: Any]] {
            XCTAssertEqual(Nearby.sas(fromBytes: bytes("bytes", in: sample)), str("sas", in: sample), str("bytes", in: sample))
        }
        let zero = obj("leading_zero")
        let note = str("note", in: zero)
        let index = note.range(of: #"vector-(\d+)"#, options: .regularExpression).map { String(note[$0].dropFirst(7)) } ?? ""
        XCTAssertEqual(C.hex(C.sha256(Data("clipway-nearby-vector-\(index)".utf8))), str("phone_private", in: zero))
        let phone = try key("phone_private", in: zero)
        XCTAssertEqual(C.hex(phone.publicKey.rawRepresentation), str("phone_public", in: zero))
        let z = try Nearby.sharedSecret(try key("mac_private"), phone.publicKey.rawRepresentation)
        XCTAssertEqual(C.hex(z), str("shared", in: zero))
        let k = Nearby.derive(z: z, pkMac: pkMac, pkPhone: phone.publicKey.rawRepresentation)
        XCTAssertEqual(C.hex(k.sas), str("K_sas", in: zero))
        XCTAssertEqual(C.hex(k.key), str("K_key", in: zero))
        XCTAssertEqual(Nearby.sasCode(kSas: k.sas, pkMac: pkMac, pkPhone: phone.publicKey.rawRepresentation), "0195")
        XCTAssertEqual(C.hex(Nearby.confirmTag(kSas: k.sas, pkMac: pkMac, pkPhone: phone.publicKey.rawRepresentation)), str("confirm", in: zero))
    }

    func testPacketsExactBytesAndReadBack() throws {
        for name in ["packet", "packet_with_relay"] {
            let p = obj(name)
            let code = try C.toQr(s, relay: str("relay", in: p), defaultRelay: ClipwayInfo.defaultRelay)
            XCTAssertEqual(code, str("code", in: p), name)
            let plaintext = try Nearby.packetPlaintext(code: code)
            XCTAssertEqual(plaintext, str("plaintext", in: p), name)
            XCTAssertEqual(plaintext.utf8.count, 256, name)
            let sealed = try Nearby.sealPacket(kKey: bytes("K_key"), pkMac: pkMac, pkPhone: pkPhone, code: code, nonce: bytes("nonce", in: p))
            XCTAssertEqual(C.hex(sealed), str("bytes", in: p), name)
            XCTAssertEqual(sealed.count, 284)
            XCTAssertEqual(C.hex(sealed.prefix(12)), str("nonce", in: p))
            // CryptoKit's combined box is exactly the packet on the air.
            let box = try AES.GCM.SealedBox(combined: sealed)
            XCTAssertEqual(box.ciphertext.count, 256)
            let opened = try Nearby.openPacket(kKey: bytes("K_key"), pkMac: pkMac, pkPhone: pkPhone, packet: bytes("bytes", in: p))
            XCTAssertEqual(opened.code, code)
            XCTAssertEqual(opened.secret, s)
            XCTAssertEqual(opened.relay, obj("opened", in: p)["relay"] as? String)
        }
        XCTAssertNil(try Nearby.openPacket(kKey: bytes("K_key"), pkMac: pkMac, pkPhone: pkPhone, packet: bytes("bytes", in: obj("packet"))).relay)
        // A random nonce each time otherwise.
        let a = try Nearby.sealPacket(kKey: bytes("K_key"), pkMac: pkMac, pkPhone: pkPhone, code: str("code", in: obj("packet")))
        let b = try Nearby.sealPacket(kKey: bytes("K_key"), pkMac: pkMac, pkPhone: pkPhone, code: str("code", in: obj("packet")))
        XCTAssertNotEqual(a.prefix(12), b.prefix(12))
    }

    func testLongestCodeThatFits() throws {
        let fits = "clipway:" + String(repeating: "A", count: 222)
        XCTAssertEqual(fits.count, 230)
        XCTAssertEqual(try Nearby.packetPlaintext(code: fits).utf8.count, 256)
        XCTAssertTrue(Nearby.fits(code: fits))
        XCTAssertFalse(Nearby.fits(code: fits + "A"))
        XCTAssertThrowsError(try Nearby.packetPlaintext(code: fits + "A")) { XCTAssertEqual($0 as? Nearby.Failure, .codeTooLong) }
        XCTAssertFalse(Nearby.fits(code: "https://example.com"))
        // A Mac whose relay address is too long does not offer nearby pairing.
        XCTAssertThrowsError(try NearbyMacSession(secret: s, relay: "https://" + String(repeating: "a", count: 200) + ".example"))
    }

    func testNegativeCasesAreRefused() throws {
        let neg = obj("negative")
        for low in obj("low_order_keys", in: neg)["keys"] as! [String] {
            XCTAssertThrowsError(try Nearby.sharedSecret(try key("mac_private"), try C.fromHex(low)), low)
            XCTAssertThrowsError(try Nearby.sharedSecret(try key("phone_private"), try C.fromHex(low)), low)
        }
        XCTAssertThrowsError(try Nearby.checkPeerKey(bytes("key", in: obj("high_bit_key", in: neg)), own: pkMac)) {
            XCTAssertEqual($0 as? Nearby.Failure, .keyRefused("top bit set"))
        }
        XCTAssertThrowsError(try Nearby.checkPeerKey(bytes("key", in: obj("own_key", in: neg)), own: pkMac))
        XCTAssertThrowsError(try Nearby.checkPeerKey(pkPhone.prefix(31), own: pkMac))
        let wrong = obj("wrong_commitment", in: neg)
        XCTAssertThrowsError(try Nearby.phoneHandshake(privateKey: try key("phone_private"), commit: bytes("commit", in: wrong), pkMac: bytes("mac_public", in: wrong))) {
            XCTAssertEqual($0 as? Nearby.Failure, .commitment)
        }
        XCTAssertThrowsError(try Nearby.phoneHandshake(privateKey: try key("phone_private"), commit: bytes("commit"), pkMac: pkPhone))
        XCTAssertFalse(Nearby.checkConfirm(kSas: bytes("K_sas"), pkMac: pkMac, pkPhone: pkPhone, tag: bytes("confirm", in: obj("wrong_confirm", in: neg))))
        XCTAssertFalse(Nearby.checkConfirm(kSas: bytes("K_sas"), pkMac: pkMac, pkPhone: pkPhone, tag: bytes("confirm").prefix(15)))
        let packet = bytes("bytes", in: obj("packet"))
        XCTAssertThrowsError(try Nearby.openPacket(kKey: bytes("K_key"), pkMac: pkMac, pkPhone: pkPhone, packet: bytes("bytes", in: obj("tampered_packet", in: neg))))
        XCTAssertEqual(str("aad", in: obj("swapped_aad", in: neg)), Nearby.packetAad(pkMac: pkPhone, pkPhone: pkMac))
        XCTAssertThrowsError(try Nearby.openPacket(kKey: bytes("K_key"), pkMac: pkPhone, pkPhone: pkMac, packet: packet))
        XCTAssertThrowsError(try Nearby.openPacket(kKey: bytes("K_key"), pkMac: pkMac, pkPhone: pkPhone, packet: packet.prefix(283))) {
            XCTAssertEqual($0 as? Nearby.Failure, .packet("284 bytes expected"))
        }
        // A packet sealed for another phone key cannot be opened with that key.
        let zero = obj("leading_zero")
        XCTAssertThrowsError(try Nearby.openPacket(kKey: bytes("K_key", in: zero), pkMac: pkMac, pkPhone: bytes("phone_public", in: zero), packet: packet))
    }

    func testManInTheMiddleGetsTwoCodes() throws {
        let a = try Nearby.privateKey(raw: C.sha256(Data("attacker-a".utf8)))
        let b = try Nearby.privateKey(raw: C.sha256(Data("attacker-b".utf8)))
        let pkA = a.publicKey.rawRepresentation
        let pkB = b.publicKey.rawRepresentation
        let onMac = Nearby.sasCode(kSas: Nearby.derive(z: try Nearby.sharedSecret(try key("mac_private"), pkA), pkMac: pkMac, pkPhone: pkA).sas,
                                   pkMac: pkMac, pkPhone: pkA)
        let onPhone = try Nearby.phoneHandshake(privateKey: try key("phone_private"), commit: Nearby.commitment(pkB), pkMac: pkB).sas
        XCTAssertNotEqual(onMac, onPhone)
        XCTAssertThrowsError(try Nearby.phoneHandshake(privateKey: try key("phone_private"), commit: Nearby.commitment(pkB), pkMac: pkA))
    }

    func testRandomKeysAgree() throws {
        var seen = Set<Data>()
        for _ in 0..<40 {
            let mac = Nearby.newPrivateKey()
            let phone = Nearby.newPrivateKey()
            let pkM = mac.publicKey.rawRepresentation
            let pkP = phone.publicKey.rawRepresentation
            XCTAssertEqual(pkM.count, 32)
            XCTAssertEqual(pkM[31] & 0x80, 0)
            let k = Nearby.derive(z: try Nearby.sharedSecret(mac, pkP), pkMac: pkM, pkPhone: pkP)
            let p = try Nearby.phoneHandshake(privateKey: phone, commit: Nearby.commitment(pkM), pkMac: pkM)
            XCTAssertEqual(p.sas, Nearby.sasCode(kSas: k.sas, pkMac: pkM, pkPhone: pkP))
            XCTAssertEqual(p.key, k.key)
            let packet = try Nearby.sealPacket(kKey: k.key, pkMac: pkM, pkPhone: pkP, code: try C.toQr(s, relay: "", defaultRelay: ClipwayInfo.defaultRelay))
            XCTAssertEqual(try Nearby.openPacket(kKey: p.key, pkMac: pkM, pkPhone: pkP, packet: packet).secret, s)
            seen.insert(pkM)
        }
        XCTAssertEqual(seen.count, 40)
    }

    /// Every step of the 8 sessions: answer, notifications, state, the code on the Mac, the end.
    func testMacSessionsOfTheVectors() throws {
        let sessions = n["sessions"] as! [[String: Any]]
        XCTAssertEqual(sessions.count, 8)
        for session in sessions {
            let name = session["name"] as! String
            let mac = try NearbyMacSession(secret: s, relay: ClipwayInfo.defaultRelay, privateKey: bytes("mac_private"), nonce: bytes("nonce", in: obj("packet")))
            for (i, step) in (session["steps"] as! [[String: Any]]).enumerated() {
                let at = "\(name), step \(i + 1)"
                let by = step["by"] as! String
                let c = (step["char"] as? String).flatMap(Nearby.Characteristic.init(rawValue:))
                let offset = step["offset"] as? Int ?? 0
                var outcome: NearbyMacSession.Outcome?
                var notify: [UInt8] = []
                switch step["op"] as! String {
                case "subscribe": outcome = mac.subscribe(by)
                case "unsubscribe": outcome = mac.unsubscribe(by)
                case "read": outcome = mac.read(by, c!, offset: offset)
                case "write": outcome = mac.write(by, c!, value: bytes("value", in: step), offset: offset)
                case "pair": notify = mac.pair()
                case "cancel": notify = mac.cancel()
                case "expire": notify = mac.expire()
                case "grace_over": notify = mac.graceOver()
                default: XCTFail("unknown op in \(at)")
                }
                if let outcome { notify = outcome.notify }
                if let expect = step["expect"] as? [String: Any] {
                    if let value = expect["value"] as? String {
                        XCTAssertEqual(outcome?.answer, .value(try C.fromHex(value)), at)
                    } else if let error = expect["error"] as? Int {
                        XCTAssertEqual(outcome?.answer, .error(Nearby.ATTError(rawValue: UInt8(error))!), at)
                    } else {
                        XCTAssertEqual(outcome?.answer, .ok, at)
                    }
                }
                XCTAssertEqual(notify.map { String(format: "%02x", $0) }, step["notify"] as! [String], at)
                XCTAssertEqual(mac.state.rawValue, step["state"] as! String, at)
                XCTAssertEqual(mac.sas, step["mac_shows"] as? String, at)
                XCTAssertEqual(mac.end?.rawValue, step["end"] as? String, at)
            }
        }
    }

    func testFreshKeysAndNothingKeptAfterTheEnd() throws {
        let a = try NearbyMacSession(secret: s, relay: ClipwayInfo.defaultRelay)
        let b = try NearbyMacSession(secret: s, relay: ClipwayInfo.defaultRelay)
        XCTAssertNotEqual(a.publicKey, b.publicKey)
        XCTAssertNotEqual(a.commit, b.commit)
        _ = a.subscribe("p")
        XCTAssertEqual(a.write("p", .phoneKey, value: pkPhone).answer, .ok)
        XCTAssertEqual(a.sas?.count, 4)
        XCTAssertFalse(a.forgotten)
        XCTAssertEqual(a.cancel(), [Nearby.Status.canceled.rawValue])
        XCTAssertTrue(a.forgotten)
        XCTAssertNil(a.sas)
    }

    /// The command line check (`Clipway --debug-nearby-vectors`) passes on the shared vectors.
    func testCommandLineReplayPasses() {
        let report = NearbyReplay.run(vectors: Self.file)
        for line in report.lines where line.hasPrefix("FAIL") { XCTFail(line) }
        XCTAssertTrue(report.passed)
        XCTAssertGreaterThan(report.checks, 200)
    }
}
