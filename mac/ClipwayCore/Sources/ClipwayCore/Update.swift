import CryptoKit
import Foundation

/// Automatic updates of the Mac app (docs/UPDATES.md): reading `update.json`, and the checks made
/// on the downloaded zip before anything is unpacked. Used by the app and again, independently, by
/// its installer service (ClipwayUpdater.xpc), which trusts nothing the app tells it.
public enum Update {
    /// The only host updates come from, whatever relay the app uses.
    public static let host = "clip.sidali.dev"
    public static let origin = "https://\(host)"
    public static let manifestURL = URL(string: "\(origin)/update.json")!
    /// Ed25519 public key of Clipway's update key (raw 32 bytes, base64). The private half signs
    /// releases on the publisher's computer and is never in the repository or on the server.
    public static let publicKey = "UxhFUIq3/gngOvPb31KTZV5p0kQOTPMaGRhG7eqBxik="
    /// The manifest is a small file; the zip a few MB.
    public static let manifestMax = 64 * 1024
    public static let zipMax = 200 * 1024 * 1024
    /// Check at launch, then once a day; after a failure, again an hour later.
    public static let interval: TimeInterval = 86_400
    public static let retry: TimeInterval = 3_600

    /// The Mac entry of update.json, validated.
    public struct Release: Equatable, Sendable, Codable {
        public let version: String
        public let build: Int
        public let url: URL
        public let sha256: String
        public let size: Int
        public let ed25519: String
        public let minimumSystemVersion: String
        public let notes: String

        public init(version: String, build: Int, url: URL, sha256: String, size: Int, ed25519: String, minimumSystemVersion: String, notes: String) {
            self.version = version
            self.build = build
            self.url = url
            self.sha256 = sha256
            self.size = size
            self.ed25519 = ed25519
            self.minimumSystemVersion = minimumSystemVersion
            self.notes = notes
        }

        /// The name the zip must have: clipway-mac-<version>.zip.
        public var fileName: String { "clipway-mac-\(version).zip" }
    }

    /// Why an update is refused.
    public enum Refusal: Error, Equatable, Sendable {
        case size, checksum, signature, bundle, version, codeSignature, location, unpack, install

        public var message: String {
            switch self {
            case .size: "The download does not have the announced size."
            case .checksum: "The download does not match the published checksum."
            case .signature: "The download is not signed with Clipway's key."
            case .bundle: "The download does not contain Clipway."
            case .version: "The download is not a newer version."
            case .codeSignature: "The new app's code signature is not valid."
            case .location: "Clipway cannot replace itself in this folder. Move it to Applications, or download the new version by hand."
            case .unpack: "The download could not be unpacked."
            case .install: "The new version could not be put in place."
            }
        }
    }

    // MARK: Versions

    /// Compares "x.y.z" versions part by part (a missing part is 0, a suffix after "-" or "+" is ignored).
    public static func compare(_ a: String, _ b: String) -> Int {
        func parts(_ v: String) -> [Int] {
            let core = v.trimmingCharacters(in: .whitespaces).split(whereSeparator: { $0 == "-" || $0 == "+" }).first.map(String.init) ?? ""
            return core.split(separator: ".").map { Int($0.prefix { $0.isNumber }) ?? 0 }
        }
        let x = parts(a), y = parts(b)
        for i in 0..<max(x.count, y.count) {
            let d = (i < x.count ? x[i] : 0) - (i < y.count ? y[i] : 0)
            if d != 0 { return d < 0 ? -1 : 1 }
        }
        return 0
    }

    // MARK: Manifest

    /// Reads update.json and returns the Mac release if it is valid and newer than the installed
    /// build (CFBundleVersion, which is authoritative), and runs on this macOS; nil otherwise.
    /// `origin`: where the zip must come from (tests of debug builds use a local relay).
    public static func parse(_ data: Data, installedBuild: Int, systemVersion: String, origin: String = Update.origin) -> Release? {
        guard data.count <= manifestMax,
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let mac = root["mac"] as? [String: Any],
              let version = mac["version"] as? String, isVersion(version),
              let build = mac["build"] as? Int, build > 0,
              let urlText = mac["url"] as? String, let url = URL(string: urlText),
              let sha = (mac["sha256"] as? String)?.lowercased(), isHex64(sha),
              let size = mac["size"] as? Int, size > 0, size <= zipMax,
              let signature = mac["ed25519"] as? String, let raw = Data(base64Encoded: signature), raw.count == 64
        else { return nil }
        let minimum = (mac["minimumSystemVersion"] as? String) ?? "14.0"
        let notes = String(((root["notes"] as? String) ?? "").prefix(2000))
        let release = Release(version: version, build: build, url: url, sha256: sha, size: size, ed25519: signature,
                              minimumSystemVersion: minimum, notes: notes)
        guard urlAllowed(url, fileName: release.fileName, origin: origin) else { return nil }
        guard build > installedBuild else { return nil }
        guard compare(systemVersion, minimum) >= 0 else { return nil }
        return release
    }

    /// https://clip.sidali.dev/download/clipway-mac-<version>.zip, exactly: never another address
    /// slipped into the manifest.
    public static func urlAllowed(_ url: URL, fileName: String, origin: String = Update.origin) -> Bool {
        url.user == nil && url.password == nil && url.query == nil && url.fragment == nil
            && url.path == "/download/\(fileName)" && url.absoluteString == "\(origin)/download/\(fileName)"
    }

    static func isVersion(_ v: String) -> Bool {
        let parts = v.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 3 && parts.allSatisfy { !$0.isEmpty && $0.count <= 4 && $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber) }
    }

    static func isHex64(_ s: String) -> Bool {
        s.utf8.count == 64 && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    // MARK: Checks on the downloaded zip

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Ed25519 signature of the whole zip, by the key whose public half is `publicKey`.
    public static func signatureValid(_ data: Data, signature: String, publicKey: String = Update.publicKey) -> Bool {
        guard let raw = Data(base64Encoded: publicKey), raw.count == 32,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw),
              let sig = Data(base64Encoded: signature), sig.count == 64
        else { return false }
        return key.isValidSignature(sig, for: data)
    }

    /// The announced size, then the SHA-256, then the Ed25519 signature. nil when all pass.
    public static func check(_ data: Data, against release: Release, publicKey: String = Update.publicKey) -> Refusal? {
        guard data.count == release.size, data.count <= zipMax else { return .size }
        let digest = Data(SHA256.hash(data: data))
        guard let expected = Data(hexString: release.sha256), digest.count == expected.count,
              zip(digest, expected).reduce(UInt8(0), { $0 | ($1.0 ^ $1.1) }) == 0
        else { return .checksum }
        guard signatureValid(data, signature: release.ed25519, publicKey: publicKey) else { return .signature }
        return nil
    }

    /// What the unpacked app must be: the same bundle id as the installed one, the announced
    /// version and build, and a build higher than the installed one. nil when all pass.
    public static func checkBundle(newInfo: [String: Any], installedInfo: [String: Any], version: String, build: Int) -> Refusal? {
        guard let id = newInfo["CFBundleIdentifier"] as? String, id == installedInfo["CFBundleIdentifier"] as? String else { return .bundle }
        guard let newBuild = (newInfo["CFBundleVersion"] as? String).flatMap(Int.init),
              let oldBuild = (installedInfo["CFBundleVersion"] as? String).flatMap(Int.init),
              newBuild == build, newBuild > oldBuild,
              newInfo["CFBundleShortVersionString"] as? String == version
        else { return .version }
        return nil
    }
}

extension Data {
    /// Lowercase or uppercase hex, even length; nil otherwise.
    init?(hexString: String) {
        guard hexString.utf8.count % 2 == 0 else { return nil }
        var out = Data(capacity: hexString.utf8.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        self = out
    }
}

/// The installer service's interface (ClipwayUpdater.xpc). The app downloads and checks the zip,
/// then asks the service to install it; the service checks everything again on its own.
@objc public protocol UpdaterService {
    /// Installs the zip at `zipPath` in place of the app that embeds the service. `release` is the
    /// JSON of an `Update.Release`. Replies nil on success, or the message of the refusal.
    func install(zipPath: String, release: Data, reply: @escaping @Sendable (String?) -> Void)
}
