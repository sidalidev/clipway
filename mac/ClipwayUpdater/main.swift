import ClipwayCore
import Darwin
import Foundation

// ClipwayUpdater.xpc: the installer of Clipway's automatic updates (docs/UPDATES.md).
//
// The app is sandboxed: it can neither unpack an app nor replace itself, and everything it writes
// is quarantined. This service, embedded in Clipway.app and reachable only by it, runs outside the
// sandbox with one job: replace the Clipway.app that embeds it with a newer one signed by
// Clipway's update key. It trusts nothing the app sends: it reads the zip itself and checks, in
// this order, the size, the SHA-256 and the Ed25519 signature (key compiled in ClipwayCore), then
// unpacks into a hidden folder next to the app, checks the new app's bundle id, version and build
// (higher than the installed one), and its code signature, and swaps both apps in one atomic
// rename. The old app is then deleted. Any failure leaves the installed app untouched.

final class Installer: NSObject, UpdaterService, @unchecked Sendable {
    /// Clipway.app, three levels above this service: Clipway.app/Contents/XPCServices/ClipwayUpdater.xpc.
    private var hostApp: URL {
        Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private var publicKey: String {
        #if DEBUG
        // Debug builds only: tests sign with a throwaway key, named in the Debug app's Info.plist.
        if let key = Bundle(url: hostApp)?.object(forInfoDictionaryKey: "ClipwayUpdateTestKey") as? String { return key }
        #endif
        return Update.publicKey
    }

    func install(zipPath: String, release: Data, reply: @escaping @Sendable (String?) -> Void) {
        do {
            let r = try JSONDecoder().decode(Update.Release.self, from: release)
            try run(zip: URL(fileURLWithPath: zipPath), release: r)
            reply(nil)
        } catch let refusal as Update.Refusal {
            reply(refusal.message)
        } catch {
            reply(Update.Refusal.install.message)
        }
    }

    private func run(zip: URL, release: Update.Release) throws {
        let host = hostApp
        guard host.pathExtension == "app",
              let installedInfo = NSDictionary(contentsOf: host.appendingPathComponent("Contents/Info.plist")) as? [String: Any]
        else { throw Update.Refusal.location }

        // 1. The zip, read here: size, SHA-256, Ed25519.
        let attributes = try? FileManager.default.attributesOfItem(atPath: zip.path)
        guard let size = attributes?[.size] as? Int, size == release.size, size <= Update.zipMax else { throw Update.Refusal.size }
        let data = try Data(contentsOf: zip, options: .mappedIfSafe)
        if let refusal = Update.check(data, against: release, publicKey: publicKey) { throw refusal }

        // 2. Unpacked next to the app (same volume, so the swap is one rename), never quarantined.
        let parent = host.deletingLastPathComponent()
        guard FileManager.default.isWritableFile(atPath: parent.path) else { throw Update.Refusal.location }
        let staging = parent.appendingPathComponent(".Clipway-update-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: staging) }
        do {
            try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false)
        } catch {
            throw Update.Refusal.location
        }
        guard Self.tool("/usr/bin/ditto", ["-x", "-k", "--noqtn", zip.path, staging.path]) else { throw Update.Refusal.unpack }
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: staging.path)) ?? []
        guard entries == ["Clipway.app"] else { throw Update.Refusal.bundle }
        let fresh = staging.appendingPathComponent("Clipway.app", isDirectory: true)

        // 3. The new app: same bundle id, announced version and build, higher build, valid code signature.
        guard let newInfo = NSDictionary(contentsOf: fresh.appendingPathComponent("Contents/Info.plist")) as? [String: Any]
        else { throw Update.Refusal.bundle }
        if let refusal = Update.checkBundle(newInfo: newInfo, installedInfo: installedInfo, version: release.version, build: release.build) {
            throw refusal
        }
        guard Self.tool("/usr/bin/codesign", ["--verify", "--deep", "--strict", fresh.path]) else { throw Update.Refusal.codeSignature }
        _ = Self.tool("/usr/bin/xattr", ["-dr", "com.apple.quarantine", fresh.path])

        // 4. One atomic swap: Clipway.app is the new app; the old one is left in the staging folder,
        //    deleted with it.
        guard renamex_np(fresh.path, host.path, UInt32(RENAME_SWAP)) == 0 else { throw Update.Refusal.install }
    }

    /// Runs a system tool, quietly. True when it exits with 0.
    private static func tool(_ path: String, _ arguments: [String]) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = arguments
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            p.waitUntilExit()
            return p.terminationStatus == 0
        } catch {
            return false
        }
    }
}

final class Listener: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: UpdaterService.self)
        connection.exportedObject = Installer()
        connection.resume()
        return true
    }
}

let delegate = Listener()
let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
