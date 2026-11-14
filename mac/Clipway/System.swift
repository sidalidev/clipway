import AppKit
import ClipwayCore
import CryptoKit
import CoreImage
import CoreImage.CIFilterBuiltins
import LocalAuthentication
import Security
import ServiceManagement
@preconcurrency import UserNotifications

/// Where the chain key (account "chain", the secret S) and the history key ("history-key") live.
///
/// Sealed to a key of this Mac's Secure Enclave (KeySeal), in Application Support/Clipway/keys
/// inside the app's container: every version of Clipway can open them, so an update keeps the
/// pairing; a copy of the files on another computer cannot. Never in clear on disk, never synced.
///
/// Before 0.4.1 they were in the login Keychain, where macOS ties an item to the code directory
/// hash of the app that created it: each new ad hoc build needed the user's password, or lost the
/// pairing. On the first read, 0.4.1 moves them from the Keychain into sealed files (macOS may ask
/// once, "Always Allow"), then deletes the Keychain item when macOS lets it. A Mac without a Secure
/// Enclave keeps using the Keychain.
/// Debug builds have their own bundle id, container and Keychain service: tests never touch the real key.
enum Keychain {
    static let service = Bundle.main.bundleIdentifier ?? "dev.sidali.clipway"
    static let chain = "chain"
    static let historyKey = "history-key"

    private static var folder: URL { Places.support.appendingPathComponent("keys", isDirectory: true) }
    private static var enclaveFile: URL { folder.appendingPathComponent("enclave-key") }
    private static func file(_ account: String) -> URL { folder.appendingPathComponent(account + ".sealed") }

    static func read(_ account: String) -> Data? {
        if let sealed = try? Data(contentsOf: file(account)), let key = enclaveKey(create: false),
           let secret = try? KeySeal.open(sealed, account: account, agree: { try key.sharedSecretFromKeyAgreement(with: $0) }) {
            return secret
        }
        // Moving from the Keychain (0.4.0 and earlier), once.
        guard let legacy = Legacy.read(service: service, account: account) else { return nil }
        if SecureEnclave.isAvailable, (try? seal(account, legacy)) != nil {
            Legacy.delete(service: service, account: account)
        }
        return legacy
    }

    static func write(_ account: String, _ data: Data) throws {
        guard SecureEnclave.isAvailable else {
            try Legacy.write(service: service, account: account, data)
            return
        }
        try seal(account, data)
        Legacy.delete(service: service, account: account)
    }

    /// Deletes the sealed file and any Keychain item. Without both keys' files, nothing sealed can
    /// be opened again (the enclave key itself goes with Erase everything, see deleteAll).
    static func delete(_ account: String) {
        try? FileManager.default.removeItem(at: file(account))
        Legacy.delete(service: service, account: account)
    }

    /// Erase everything: the sealed files and the enclave key.
    static func deleteAll() {
        delete(chain)
        delete(historyKey)
        try? FileManager.default.removeItem(at: folder)
    }

    private static func seal(_ account: String, _ data: Data) throws {
        guard let key = enclaveKey(create: true) else { throw CocoaError(.fileWriteUnknown) }
        let sealed = try KeySeal.seal(data, account: account, to: key.publicKey)
        try write(sealed, to: file(account))
    }

    /// The enclave key: created once, kept as the Secure Enclave's own wrapped blob, which only this
    /// Mac's enclave can use.
    private static func enclaveKey(create: Bool) -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
        guard SecureEnclave.isAvailable else { return nil }
        if let blob = try? Data(contentsOf: enclaveFile),
           let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob) {
            return key
        }
        guard create, let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey() else { return nil }
        do {
            try write(key.dataRepresentation, to: enclaveFile)
        } catch {
            return nil
        }
        return key
    }

    /// Owner-only file, written in one rename.
    private static func write(_ data: Data, to url: URL) throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// The login Keychain, as 0.4.0 and earlier used it (file based, never synced to iCloud).
    enum Legacy {
        static func read(service: String, account: String) -> Data? {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: false,
                kSecUseDataProtectionKeychain as String: false,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ]
            var out: CFTypeRef?
            guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
            return out as? Data
        }

        static func write(service: String, account: String, _ data: Data) throws {
            delete(service: service, account: account)
            let item: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrLabel as String: account == chain ? "Clipway key" : "Clipway history key",
                kSecAttrSynchronizable as String: false,
                kSecUseDataProtectionKeychain as String: false,
                kSecValueData as String: data,
            ]
            let status = SecItemAdd(item as CFDictionary, nil)
            guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        }

        static func delete(service: String, account: String) {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecUseDataProtectionKeychain as String: false,
            ]
            SecItemDelete(query as CFDictionary)
        }
    }
}

/// QR codes drawn on this Mac with Core Image (error correction M). Nothing leaves the app.
enum QRCode {
    static func image(_ text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        guard let cg = CIContext(options: [.useSoftwareRenderer: false]).createCGImage(scaled, from: scaled.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: scaled.extent.width, height: scaled.extent.height))
    }
}

/// Touch ID or the Mac password before showing the key.
enum OwnerCheck {
    static func confirm(reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            // No password on this Mac: nothing stronger to ask for.
            return (error as? LAError)?.code == .passcodeNotSet
        }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }
}

/// Open at login, through SMAppService.
enum LoginItem {
    static var isOn: Bool { SMAppService.mainApp.status == .enabled }

    @discardableResult
    static func set(_ on: Bool) -> Bool {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            return false
        }
        return true
    }
}

/// Show in Dock: a Dock icon and a place in Cmd Tab, or the menu bar only. On by default.
/// Info.plist keeps LSUIElement, so the app never appears in the Dock before this is read: with
/// the setting on, the icon appears once at launch; with it off, it never appears.
enum DockIcon {
    static let key = "showInDock"

    static func isOn(_ defaults: UserDefaults = .standard) -> Bool {
        defaults.object(forKey: key) as? Bool ?? true
    }

    /// Applies the setting, at launch and when it changes, without a restart.
    @MainActor
    static func apply(_ on: Bool) {
        let policy: NSApplication.ActivationPolicy = on ? .regular : .accessory
        guard NSApp.activationPolicy() != policy else { return }
        let front = NSApp.keyWindow
        NSApp.setActivationPolicy(policy)
        guard NSApp.isRunning else { return }
        // Leaving the Dock deactivates the app: the open window comes back in front.
        DispatchQueue.main.async {
            NSApp.activate()
            front?.makeKeyAndOrderFront(nil)
        }
    }
}

/// The signature of the running app, read at run time, for About.
enum CodeSignature {
    struct Info {
        let adHoc: Bool
        let cdhash: String
    }

    static func current() -> Info? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any], let unique = dict[kSecCodeInfoUnique as String] as? Data
        else { return nil }
        let flags = (dict[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let hex = unique.map { String(format: "%02x", $0) }.joined()
        return Info(adHoc: flags & SecCodeSignatureFlags.adhoc.rawValue != 0, cdhash: hex)
    }

    /// First 8 and last 4 characters, to compare with SECURITY.md.
    static func short(_ hex: String) -> String {
        guard hex.count > 12 else { return hex }
        return "\(hex.prefix(8))…\(hex.suffix(4))"
    }
}

/// Where received files go: ~/Downloads/Clipway (the real home, also from the sandbox container).
enum Places {
    static var home: URL {
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            return URL(fileURLWithPath: String(cString: dir), isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
    }

    static var downloads: URL { home.appendingPathComponent("Downloads/Clipway", isDirectory: true) }

    /// History and state: Application Support/Clipway (inside the app's container when sandboxed).
    static var support: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? home.appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("Clipway", isDirectory: true)
    }
}

/// Notifications: "Copied from <phone>", "Received <file> from <phone>". Asked after pairing.
@MainActor
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()
    private var center: UNUserNotificationCenter? {
        Bundle.main.bundleIdentifier == nil ? nil : UNUserNotificationCenter.current()
    }

    func setUp() { center?.delegate = self }

    func ask() {
        center?.requestAuthorization(options: [.alert]) { _, _ in }
    }

    /// From Settings, Permissions: macOS's prompt, then whether notifications are allowed.
    func askNow() async -> Bool {
        guard let center else { return false }
        return (try? await center.requestAuthorization(options: [.alert])) ?? false
    }

    func status() async -> UNAuthorizationStatus {
        guard let center else { return .denied }
        return await center.notificationSettings().authorizationStatus
    }

    /// `lasting`: stays in Notification Center (an update), instead of going away after 4 seconds.
    func post(_ title: String, body: String? = nil, reveal path: String? = nil, replacing id: String = "copied", lasting: Bool = false) {
        guard let center else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        if let body { content.body = body }
        if let path { content.userInfo = ["reveal": path] }
        content.interruptionLevel = .passive
        let request = UNNotificationRequest(identifier: path == nil ? id : UUID().uuidString, content: content, trigger: nil)
        center.add(request)
        if path == nil, !lasting {
            // A copy notice is only useful for a moment.
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                center.removeDeliveredNotifications(withIdentifiers: [id])
            }
        }
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .list]
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        guard let path = response.notification.request.content.userInfo["reveal"] as? String else { return }
        await MainActor.run {
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
        }
    }
}
