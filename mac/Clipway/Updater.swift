import AppKit
import ClipwayCore
import Observation

/// Automatic updates (docs/UPDATES.md).
///
/// - Check: `https://clip.sidali.dev/update.json` at launch and then once a day (again an hour
///   after a failure), when Automatic updates is on, the default. The request carries no
///   identifier: no cookie, no device id, a fixed User-Agent "Clipway-mac/<version>".
/// - A newer build: the menu offers it, Settings too, and a notification says so once.
/// - Install, after a click: the zip is downloaded into the app's container, its size, SHA-256 and
///   Ed25519 signature are checked (Update.check), then ClipwayUpdater.xpc checks it all again,
///   swaps Clipway.app for the new one, and the new version opens. Nothing installs on its own.
@MainActor
@Observable
final class Updater {
    static let shared = Updater()

    enum State: Equatable {
        case idle
        case checking
        case upToDate
        case available(Update.Release)
        case downloading
        case installing
        case failed(String)
    }

    private enum Keys {
        static let automatic = "automaticUpdates"
        static let lastCheck = "updatesLastCheck"
        static let lastAttempt = "updatesLastAttempt"
        static let notified = "updatesNotifiedBuild"
    }

    /// Automatic updates, on by default. Turned on again: checks at once.
    var automatic: Bool {
        didSet {
            guard automatic != oldValue else { return }
            defaults.set(automatic, forKey: Keys.automatic)
            if automatic { check(manual: false) } else if case .available = state { state = .idle }
        }
    }

    private(set) var state: State = .idle

    /// The newer release found, if any.
    var available: Update.Release? {
        switch state {
        case .available(let r): r
        default: release
        }
    }

    @ObservationIgnored private let defaults = UserDefaults.standard
    @ObservationIgnored private var release: Update.Release?
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private lazy var session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.timeoutIntervalForRequest = 30
        c.timeoutIntervalForResource = 600
        c.httpAdditionalHeaders = ["User-Agent": "Clipway-mac/\(AppModel.version)", "Accept-Language": "en"]
        return URLSession(configuration: c)
    }()

    private init() {
        automatic = defaults.object(forKey: Keys.automatic) as? Bool ?? true
    }

    static var installedBuild: Int {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String).flatMap(Int.init) ?? 0
    }

    static var systemVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    /// The manifest address. Debug builds accept `--debug-update-manifest <url>` (local tests).
    static var manifestURL: URL {
        #if DEBUG
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--debug-update-manifest"), i + 1 < args.count, let url = URL(string: args[i + 1]) { return url }
        #endif
        return Update.manifestURL
    }

    /// Where zips come from: the reference relay, or the origin of the debug manifest.
    static var origin: String {
        #if DEBUG
        if let scheme = manifestURL.scheme, let host = manifestURL.host {
            return "\(scheme)://\(host)" + (manifestURL.port.map { ":\($0)" } ?? "")
        }
        #endif
        return Update.origin
    }

    /// At launch: a first check a few seconds later, then a look every hour at whether one is due.
    func start() {
        guard timer == nil else { return }
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            if self.automatic { self.check(manual: false) }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 3_600, repeats: true) { _ in
            Task { @MainActor in Updater.shared.checkIfDue() }
        }
    }

    func checkIfDue() {
        guard automatic else { return }
        let now = Date().timeIntervalSince1970
        guard now - defaults.double(forKey: Keys.lastCheck) >= Update.interval,
              now - defaults.double(forKey: Keys.lastAttempt) >= Update.retry
        else { return }
        check(manual: false)
    }

    /// Asks update.json. `manual`: Check for Updates…, which also says "up to date".
    func check(manual: Bool) {
        switch state {
        case .checking, .downloading, .installing: return
        default: break
        }
        if manual { state = .checking }
        defaults.set(Date().timeIntervalSince1970, forKey: Keys.lastAttempt)
        var request = URLRequest(url: Self.manifestURL)
        request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        Task { @MainActor in
            do {
                let (data, response) = try await session.data(for: request)
                let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                guard status == 200 || status == 404 else { throw URLError(.badServerResponse) }
                defaults.set(Date().timeIntervalSince1970, forKey: Keys.lastCheck)
                let found = status == 200
                    ? Update.parse(data, installedBuild: Self.installedBuild, systemVersion: Self.systemVersion, origin: Self.origin)
                    : nil
                release = found
                if let found {
                    state = .available(found)
                    #if DEBUG
                    // Debug builds only: `--debug-update-install` installs without asking (local end-to-end test).
                    if CommandLine.arguments.contains("--debug-update-install") {
                        print("clipway: update \(found.version) (\(found.build)) found, installing")
                        fflush(stdout)
                        install(found)
                        return
                    }
                    #endif
                    if defaults.integer(forKey: Keys.notified) < found.build {
                        defaults.set(found.build, forKey: Keys.notified)
                        Notifier.shared.post("Clipway \(found.version) is available",
                                             body: "Install it from the Clipway menu.", replacing: "update", lasting: true)
                    }
                } else {
                    #if DEBUG
                    print("clipway: update check: no newer version (HTTP \(status))")
                    fflush(stdout)
                    #endif
                    state = manual ? .upToDate : .idle
                }
            } catch {
                #if DEBUG
                print("clipway: update check failed: \(error.localizedDescription)")
                fflush(stdout)
                #endif
                state = manual ? .failed("Couldn't reach clip.sidali.dev. Check your connection and try again.") : (release.map { .available($0) } ?? .idle)
            }
        }
    }

    /// Install: confirm, download, check, hand over to the installer service, open the new version.
    func offer() {
        guard let release = available else {
            check(manual: true)
            return
        }
        NSApp.activate()
        let alert = NSAlert()
        alert.messageText = "Clipway \(release.version) is available"
        alert.informativeText = (release.notes.isEmpty ? "" : Self.plainNotes(release.notes) + "\n\n")
            + "You have \(AppModel.version). Clipway checks the update's signature, replaces itself and opens again."
        alert.addButton(withTitle: "Install")
        alert.addButton(withTitle: "Later")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        install(release)
    }

    private func install(_ release: Update.Release) {
        state = .downloading
        Task { @MainActor in
            do {
                let zip = try await download(release)
                state = .installing
                try await installService(zip: zip, release: release)
                relaunch()
            } catch let refusal as Update.Refusal {
                fail(refusal.message)
            } catch let message as InstallError {
                fail(message.text)
            } catch {
                fail("The download did not finish. Check your connection and try again.")
            }
        }
    }

    private struct InstallError: Error { let text: String }

    private func fail(_ message: String) {
        state = .failed(message)
        #if DEBUG
        print("clipway: update failed: \(message)")
        fflush(stdout)
        if CommandLine.arguments.contains("--debug-update-install") { return }
        #endif
        NSApp.activate()
        let alert = NSAlert()
        alert.messageText = "Update not installed"
        alert.informativeText = message + " Clipway keeps working with the current version."
        alert.runModal()
        if let release { state = .available(release) }
    }

    /// Downloads into the app's temporary folder and checks size, SHA-256 and signature.
    private func download(_ release: Update.Release) async throws -> URL {
        let (temp, response) = try await session.download(from: release.url)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("update", isDirectory: true)
        try? FileManager.default.removeItem(at: folder)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let zip = folder.appendingPathComponent(release.fileName)
        try FileManager.default.moveItem(at: temp, to: zip)
        let data = try Data(contentsOf: zip, options: .mappedIfSafe)
        #if DEBUG
        // Debug builds only: hand the zip to the installer service unchecked, to test its own checks.
        if CommandLine.arguments.contains("--debug-update-skip-app-check") { return zip }
        #endif
        if let refusal = Update.check(data, against: release, publicKey: Self.publicKey) {
            try? FileManager.default.removeItem(at: folder)
            throw refusal
        }
        return zip
    }

    private static var publicKey: String {
        #if DEBUG
        if let key = Bundle.main.object(forInfoDictionaryKey: "ClipwayUpdateTestKey") as? String { return key }
        #endif
        return Update.publicKey
    }

    /// ClipwayUpdater.xpc checks the zip again and swaps the apps.
    private func installService(zip: URL, release: Update.Release) async throws {
        let payload = try JSONEncoder().encode(release)
        let name = (Bundle.main.bundleIdentifier ?? "dev.sidali.clipway") + ".updater"
        let message: String? = try await withCheckedThrowingContinuation { continuation in
            nonisolated(unsafe) let connection = NSXPCConnection(serviceName: name)
            connection.remoteObjectInterface = NSXPCInterface(with: UpdaterService.self)
            connection.resume()
            let once = Once()
            let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
                if once.take() { continuation.resume(throwing: InstallError(text: Update.Refusal.install.message)) }
                connection.invalidate()
            } as? UpdaterService
            guard let proxy else {
                if once.take() { continuation.resume(throwing: InstallError(text: Update.Refusal.install.message)) }
                return
            }
            proxy.install(zipPath: zip.path, release: payload) { result in
                if once.take() { continuation.resume(returning: result) }
                connection.invalidate()
            }
        }
        try? FileManager.default.removeItem(at: zip.deletingLastPathComponent())
        if let message { throw InstallError(text: message) }
    }

    /// Opens the new Clipway.app, which waits for this one to quit, then quits.
    private func relaunch() {
        #if DEBUG
        print("clipway: update installed, opening the new version")
        fflush(stdout)
        #endif
        let config = NSWorkspace.OpenConfiguration()
        config.createsNewApplicationInstance = true
        config.arguments = ["--updated-from", String(getpid())]
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: config) { _, _ in
            Task { @MainActor in NSApp.terminate(nil) }
        }
    }

    /// Started by relaunch(): waits (5 s at most) for the previous Clipway to quit.
    nonisolated static func waitForPreviousInstance(arguments: [String] = CommandLine.arguments) {
        guard let i = arguments.firstIndex(of: "--updated-from"), i + 1 < arguments.count,
              let pid = pid_t(arguments[i + 1]), pid > 0, pid != getpid() else { return }
        for _ in 0..<50 where kill(pid, 0) == 0 { usleep(100_000) }
    }

    /// CHANGELOG notes without Markdown marks, for the alert.
    static func plainNotes(_ markdown: String) -> String {
        markdown.replacingOccurrences(of: "**", with: "").replacingOccurrences(of: "`", with: "")
            .split(separator: "\n", omittingEmptySubsequences: false).map { line in
                line.hasPrefix("- ") ? "• " + line.dropFirst(2) : Substring(line)
            }.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines).prefix(700).description
    }
}

/// True the first time only: an XPC reply and an error handler can both fire.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func take() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}
