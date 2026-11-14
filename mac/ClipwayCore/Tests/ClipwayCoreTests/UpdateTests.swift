import CryptoKit
import XCTest
@testable import ClipwayCore

/// Automatic updates: update.json, the checks on the zip, the checks on the unpacked app.
final class UpdateTests: XCTestCase {
    private let key = Curve25519.Signing.PrivateKey()
    private var publicKey: String { key.publicKey.rawRepresentation.base64EncodedString() }
    private let zip = Data((0..<5000).map { UInt8($0 % 251) })

    private func manifest(version: String = "0.4.2", build: Int = 8, url: String? = nil, size: Int? = nil,
                          sha: String? = nil, signature: String? = nil, minimum: String = "14.0") -> Data {
        let mac: [String: Any] = [
            "version": version, "build": build,
            "url": url ?? "https://clip.sidali.dev/download/clipway-mac-\(version).zip",
            "sha256": sha ?? Update.sha256Hex(zip), "size": size ?? zip.count,
            "ed25519": signature ?? (try! key.signature(for: zip)).base64EncodedString(),
            "minimumSystemVersion": minimum,
        ]
        let root: [String: Any] = ["version": version, "mac": mac, "android": ["version": version], "notes": "Fixes."]
        return try! JSONSerialization.data(withJSONObject: root)
    }

    func testVersionsCompare() {
        XCTAssertEqual(Update.compare("0.4.1", "0.4.0"), 1)
        XCTAssertEqual(Update.compare("0.4.0", "0.4.0"), 0)
        XCTAssertEqual(Update.compare("0.10.0", "0.9.9"), 1)
        XCTAssertEqual(Update.compare("14", "14.0"), 0)
        XCTAssertEqual(Update.compare("13.6", "14.0"), -1)
        XCTAssertEqual(Update.compare("1.0.0-beta", "1.0.0"), 0)
    }

    func testANewerBuildIsOffered() throws {
        let r = try XCTUnwrap(Update.parse(manifest(), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertEqual(r.version, "0.4.2")
        XCTAssertEqual(r.build, 8)
        XCTAssertEqual(r.fileName, "clipway-mac-0.4.2.zip")
        XCTAssertEqual(r.notes, "Fixes.")
    }

    func testTheSameOrAnOlderBuildIsNot() {
        XCTAssertNil(Update.parse(manifest(), installedBuild: 8, systemVersion: "15.1"))
        XCTAssertNil(Update.parse(manifest(), installedBuild: 9, systemVersion: "15.1"))
    }

    func testAnOlderMacOSIsNotOffered() {
        XCTAssertNil(Update.parse(manifest(minimum: "16.0"), installedBuild: 7, systemVersion: "15.1"))
    }

    func testOnlyTheReferenceHostAndTheExactFileName() {
        for url in [
            "http://clip.sidali.dev/download/clipway-mac-0.4.2.zip",
            "https://example.org/download/clipway-mac-0.4.2.zip",
            "https://clip.sidali.dev.example.org/download/clipway-mac-0.4.2.zip",
            "https://clip.sidali.dev:8443/download/clipway-mac-0.4.2.zip",
            "https://user@clip.sidali.dev/download/clipway-mac-0.4.2.zip",
            "https://clip.sidali.dev/download/clipway-mac-0.4.3.zip",
            "https://clip.sidali.dev/download/clipway-0.4.2.apk",
            "https://clip.sidali.dev/download/../clipway-mac-0.4.2.zip",
            "https://clip.sidali.dev/download/clipway-mac-0.4.2.zip?x=1",
            "https://clip.sidali.dev/download/clipway-mac-0.4.2.zip#x",
            "https://CLIP.sidali.dev/download/clipway-mac-0.4.2.zip",
        ] {
            XCTAssertNil(Update.parse(manifest(url: url), installedBuild: 7, systemVersion: "15.1"), url)
        }
    }

    func testMalformedManifestsAreIgnored() {
        XCTAssertNil(Update.parse(Data("{".utf8), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertNil(Update.parse(Data("[]".utf8), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertNil(Update.parse(Data(#"{"android":{}}"#.utf8), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertNil(Update.parse(manifest(version: "0.4"), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertNil(Update.parse(manifest(sha: "zz"), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertNil(Update.parse(manifest(signature: "c2hvcnQ="), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertNil(Update.parse(manifest(size: Update.zipMax + 1), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertNil(Update.parse(Data(repeating: 32, count: Update.manifestMax + 1), installedBuild: 7, systemVersion: "15.1"))
    }

    func testTheZipMustHaveTheSizeChecksumAndSignature() throws {
        let r = try XCTUnwrap(Update.parse(manifest(), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertNil(Update.check(zip, against: r, publicKey: publicKey))
        var changed = zip
        changed[10] ^= 1
        XCTAssertEqual(Update.check(changed, against: r, publicKey: publicKey), .checksum)
        XCTAssertEqual(Update.check(zip + Data([0]), against: r, publicKey: publicKey), .size)
        // Right checksum, signed by another key: refused.
        let other = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
        XCTAssertEqual(Update.check(zip, against: r, publicKey: other), .signature)
        // A changed zip with a matching checksum in the manifest, but the old signature: refused.
        let forged = try XCTUnwrap(Update.parse(manifest(sha: Update.sha256Hex(changed), signature: r.ed25519), installedBuild: 7, systemVersion: "15.1"))
        XCTAssertEqual(Update.check(changed, against: forged, publicKey: publicKey), .signature)
    }

    /// RFC 8032, section 7.1, test 1: the signature tools/update-manifest.mjs (node:crypto) makes
    /// for this key verifies here (CryptoKit), so a release signed by the script installs.
    func testSignaturesFromTheReleaseScriptVerify() {
        let pub = Data(hexString: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")!.base64EncodedString()
        let sig = Data(hexString: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")!.base64EncodedString()
        XCTAssertTrue(Update.signatureValid(Data(), signature: sig, publicKey: pub))
        XCTAssertFalse(Update.signatureValid(Data([0]), signature: sig, publicKey: pub))
    }

    func testTheReferencePublicKeyIsWellFormed() {
        XCTAssertEqual(Data(base64Encoded: Update.publicKey)?.count, 32)
        XCTAssertNotNil(try? Curve25519.Signing.PublicKey(rawRepresentation: Data(base64Encoded: Update.publicKey)!))
    }

    func testTheUnpackedAppMustBeClipwayAndNewer() {
        let installed: [String: Any] = ["CFBundleIdentifier": "dev.sidali.clipway", "CFBundleVersion": "7", "CFBundleShortVersionString": "0.4.1"]
        let good: [String: Any] = ["CFBundleIdentifier": "dev.sidali.clipway", "CFBundleVersion": "8", "CFBundleShortVersionString": "0.4.2"]
        XCTAssertNil(Update.checkBundle(newInfo: good, installedInfo: installed, version: "0.4.2", build: 8))
        var other = good
        other["CFBundleIdentifier"] = "dev.sidali.clipway.debug"
        XCTAssertEqual(Update.checkBundle(newInfo: other, installedInfo: installed, version: "0.4.2", build: 8), .bundle)
        XCTAssertEqual(Update.checkBundle(newInfo: good, installedInfo: installed, version: "0.4.3", build: 8), .version)
        XCTAssertEqual(Update.checkBundle(newInfo: good, installedInfo: installed, version: "0.4.2", build: 9), .version)
        XCTAssertEqual(Update.checkBundle(newInfo: installed, installedInfo: installed, version: "0.4.1", build: 7), .version)
    }

    func testTheServiceReceivesTheReleaseAsJSON() throws {
        let r = try XCTUnwrap(Update.parse(manifest(), installedBuild: 7, systemVersion: "15.1"))
        let back = try JSONDecoder().decode(Update.Release.self, from: JSONEncoder().encode(r))
        XCTAssertEqual(back, r)
    }
}
