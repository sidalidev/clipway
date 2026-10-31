import CryptoKit
import Foundation
import XCTest
@testable import ClipwayCore

/// Reproduces docs/VECTORS.json, shared with relay/crypto.js and the Android app.
final class CryptoTests: XCTestCase {
    typealias C = ClipwayCrypto

    nonisolated(unsafe) private static let vectors: [String: Any] = {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("docs/VECTORS.json")
        let data = try! Data(contentsOf: url)
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }()

    private var v: [String: Any] { Self.vectors }
    private func str(_ key: String, in o: [String: Any]? = nil) -> String { (o ?? v)[key] as! String }
    private func obj(_ key: String, in o: [String: Any]? = nil) -> [String: Any] { (o ?? v)[key] as! [String: Any] }
    private func env(_ o: [String: Any]) -> C.Envelope { C.Envelope(nonce: o["nonce"] as! String, enc: o["enc"] as! String) }
    private var s: Data { try! C.fromHex(str("S")) }
    private var id: String { str("id") }

    func testOfficialWordList() {
        XCTAssertEqual(bip39English.count, 2048)
        XCTAssertEqual(C.hex(C.sha256(Data((bip39English.joined(separator: "\n") + "\n").utf8))), str("wordlist_sha256"))
    }

    func testProofChainIdAndKeys() throws {
        XCTAssertEqual(C.hex(try C.proof(s)), str("P"))
        XCTAssertEqual(try C.chainId(s), id)
        XCTAssertEqual(try C.idFromProof(try C.fromHex(str("P"))), id)
        XCTAssertEqual(C.hex(C.bytes(try C.encKey(s))), str("K_enc"))
        XCTAssertEqual(C.hex(C.bytes(try C.macKey(s))), str("K_mac"))
        XCTAssertEqual(try C.subprotocols(s).joined(separator: ", "), str("subprotocol"))
    }

    func testWordsAndQrCode() throws {
        let words = v["words"] as! [String]
        XCTAssertEqual(try C.toWords(s), words)
        XCTAssertEqual(try C.fromWords(words.joined(separator: "  ").uppercased()), s)
        XCTAssertThrowsError(try C.fromWords(words.dropFirst().joined(separator: " ")))
        XCTAssertThrowsError(try C.fromWords(([words[1], words[0]] + words.dropFirst(2)).joined(separator: " ")))

        let def = "https://clip.sidali.dev"
        XCTAssertEqual(try C.toQr(s, relay: def, defaultRelay: def), str("qr"))
        let withRelay = obj("qr_with_relay")
        XCTAssertEqual(try C.toQr(s, relay: str("relay", in: withRelay), defaultRelay: def), str("text", in: withRelay))
        let bare = try C.fromQr(str("qr"))
        XCTAssertEqual(bare.secret, s)
        XCTAssertNil(bare.relay)
        XCTAssertEqual(try C.fromQr(str("text", in: withRelay)).relay, str("relay", in: withRelay))
        XCTAssertThrowsError(try C.fromQr("https://example.com/#s=AAECAwQFBgcICQoLDA0ODw"))
        XCTAssertThrowsError(try C.fromQr("clipway:AAECAwQFBgcICQoLDA0O"))
    }

    func testFingerprintAndEnvelope() throws {
        let f = obj("fingerprint")
        XCTAssertEqual(C.fingerprint(macKey: try C.macKey(s), content: Data(str("content_utf8", in: f).utf8)), str("fp", in: f))
        let e = obj("envelope")
        let sealed = try C.seal(
            key: try C.encKey(s), aad: str("aad", in: e), plaintext: Data(str("plaintext_utf8", in: e).utf8),
            nonce: try C.fromHex(str("nonce", in: e)))
        XCTAssertEqual(sealed, env(obj("envelope", in: e)))
        XCTAssertEqual(String(decoding: try C.open(key: try C.encKey(s), aad: str("aad", in: e), envelope: sealed), as: UTF8.self), "hello")
        let neg = obj("negative")
        XCTAssertThrowsError(try C.open(key: try C.encKey(s), aad: id, envelope: env(obj("tampered_envelope", in: neg))))
        XCTAssertThrowsError(try C.open(key: try C.encKey(s), aad: str("wrong_aad", in: neg), envelope: env(obj("envelope", in: obj("text_item")))))
    }

    func testPaddingAndItems() throws {
        let p = obj("padding")
        XCTAssertEqual(try C.padHead(str("unpadded", in: p)), str("padded", in: p))
        for name in ["text_item", "hello_item", "offer_item", "offer_file_item", "reply_item"] {
            let item = obj(name)
            let plaintext = str("plaintext", in: item)
            XCTAssertEqual(plaintext.utf8.count % C.padBlock, 0, name)
            let e = env(obj("envelope", in: item))
            XCTAssertEqual(try C.seal(key: try C.encKey(s), aad: id, plaintext: Data(plaintext.utf8), nonce: try C.fromHex(e.nonce)), e, name)
            XCTAssertEqual(String(decoding: try C.open(key: try C.encKey(s), aad: id, envelope: e), as: UTF8.self), plaintext, name)
        }
    }

    func testLimitsAndDirectKey() throws {
        let l = obj("limits")
        XCTAssertEqual(l["text"] as! Int, C.textMax)
        XCTAssertEqual(l["head"] as! Int, C.headMax)
        XCTAssertEqual(l["file"] as! Int, C.fileMax)
        XCTAssertEqual(C.hex(C.bytes(try C.directKey(s))), str("K_direct", in: obj("direct")))
    }

    func testRandomSecretsRoundTrip() throws {
        for _ in 0..<50 {
            let r = C.generateSecret()
            XCTAssertEqual(try C.fromWords(try C.toWords(r).joined(separator: " ")), r)
            XCTAssertEqual(try C.fromQr(try C.toQr(r, relay: "", defaultRelay: "https://clip.sidali.dev")).secret, r)
        }
    }
}
