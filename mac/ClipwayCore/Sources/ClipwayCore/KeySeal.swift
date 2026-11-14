import CryptoKit
import Foundation

/// How the Mac app keeps the chain key and the history key at rest (docs/UPDATES.md, "Keeping the
/// pairing across updates"): sealed to a P-256 key held by this Mac's Secure Enclave.
///
/// Why not the login Keychain alone: the app is signed ad hoc, and macOS ties a Keychain item to
/// the code directory hash of the app that created it. Every new version has another hash, so it
/// could not read the key without a password prompt, and lost the pairing. A Secure Enclave key is
/// tied to this Mac, not to the app's signature: every version can unseal, and a copy of the file
/// on another computer (a backup, a stolen disk) cannot.
///
/// Format of a sealed file: 0x01, the ephemeral P-256 public key (65 bytes, X9.63), then the
/// AES-256-GCM box (nonce, ciphertext, tag). The AES key is HKDF-SHA256 of the ECDH secret between
/// the ephemeral key and the enclave key, salt "clipway-mac-keyseal-v1", info the account name.
public enum KeySeal {
    public static let version: UInt8 = 1
    static let salt = Data("clipway-mac-keyseal-v1".utf8)

    public enum Failure: Error, Equatable { case format, open }

    /// Seals `secret` for the holder of `recipient` (the enclave key's public half).
    public static func seal(_ secret: Data, account: String, to recipient: P256.KeyAgreement.PublicKey) throws -> Data {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let key = symmetricKey(shared, account: account)
        let box = try AES.GCM.seal(secret, using: key)
        guard let combined = box.combined else { throw Failure.format }
        return Data([version]) + ephemeral.publicKey.x963Representation + combined
    }

    /// Opens a sealed file. `agree` runs the key agreement with the enclave key (or, in tests, a
    /// software key) and the ephemeral public key found in the file.
    public static func open(_ sealed: Data, account: String,
                            agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret) throws -> Data {
        guard sealed.count > 1 + 65 + 12 + 16, sealed.first == version else { throw Failure.format }
        let body = sealed.dropFirst()
        guard let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: body.prefix(65)) else { throw Failure.format }
        let key = symmetricKey(try agree(ephemeral), account: account)
        do {
            return try AES.GCM.open(AES.GCM.SealedBox(combined: body.dropFirst(65)), using: key)
        } catch {
            throw Failure.open
        }
    }

    static func symmetricKey(_ shared: SharedSecret, account: String) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(account.utf8), outputByteCount: 32)
    }
}
