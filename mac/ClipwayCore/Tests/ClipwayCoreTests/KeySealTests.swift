import CryptoKit
import XCTest
@testable import ClipwayCore

/// The chain key at rest: sealed to the enclave key, readable by any version of the app on this
/// Mac, by nothing without that key. Tests use a software P-256 key in place of the enclave.
final class KeySealTests: XCTestCase {
    private let holder = P256.KeyAgreement.PrivateKey()
    private let secret = Data((0..<16).map { UInt8($0 * 7) })

    private func open(_ sealed: Data, account: String = "chain", with key: P256.KeyAgreement.PrivateKey? = nil) throws -> Data {
        try KeySeal.open(sealed, account: account) { try (key ?? holder).sharedSecretFromKeyAgreement(with: $0) }
    }

    func testRoundTrip() throws {
        let sealed = try KeySeal.seal(secret, account: "chain", to: holder.publicKey)
        XCTAssertEqual(sealed.first, 1)
        XCTAssertEqual(sealed.count, 1 + 65 + 12 + secret.count + 16)
        XCTAssertEqual(try open(sealed), secret)
    }

    func testTheSecretNeverAppearsInTheFile() throws {
        let sealed = try KeySeal.seal(secret, account: "chain", to: holder.publicKey)
        XCTAssertNil(sealed.range(of: secret))
        // Two seals of the same secret differ (a fresh ephemeral key each time).
        XCTAssertNotEqual(sealed, try KeySeal.seal(secret, account: "chain", to: holder.publicKey))
    }

    func testAnotherKeyOrAccountCannotOpen() throws {
        let sealed = try KeySeal.seal(secret, account: "chain", to: holder.publicKey)
        XCTAssertThrowsError(try open(sealed, with: P256.KeyAgreement.PrivateKey())) { XCTAssertEqual($0 as? KeySeal.Failure, .open) }
        XCTAssertThrowsError(try open(sealed, account: "history-key")) { XCTAssertEqual($0 as? KeySeal.Failure, .open) }
    }

    func testAChangedOrTruncatedFileIsRefused() throws {
        var sealed = try KeySeal.seal(secret, account: "chain", to: holder.publicKey)
        XCTAssertThrowsError(try open(sealed.prefix(60)))
        XCTAssertThrowsError(try open(Data([2]) + sealed.dropFirst()))
        sealed[sealed.count - 1] ^= 1
        XCTAssertThrowsError(try open(sealed)) { XCTAssertEqual($0 as? KeySeal.Failure, .open) }
    }
}
