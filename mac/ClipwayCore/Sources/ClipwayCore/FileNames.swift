import Foundation

/// Names of received files (docs/PROTOCOL.md, section 3.5). The name in a head is never trusted as a path.
public enum FileNames {
    public static let maxLength = 120

    /// Path separators, control and direction characters and leading dots removed, 120 characters
    /// at most (the extension is kept when it is short), "file" if nothing is left.
    public static func sanitize(_ raw: String) -> String {
        let removed: Set<Unicode.Scalar> = ["/", "\\", ":"]
        // Direction overrides can disguise an extension ("invoice\u{202E}fdp.exe").
        let direction = (0x200E...0x200F).map { $0 } + (0x202A...0x202E).map { $0 } + (0x2066...0x2069).map { $0 }
        var scalars = String.UnicodeScalarView()
        for s in raw.unicodeScalars {
            if removed.contains(s) || s.value < 0x20 || (0x7F...0x9F).contains(s.value) || direction.contains(Int(s.value)) {
                continue
            }
            scalars.append(s)
        }
        var name = String(scalars).trimmingCharacters(in: .whitespacesAndNewlines)
        while name.hasPrefix(".") { name.removeFirst() }
        name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.count > maxLength {
            let ext = (name as NSString).pathExtension
            if !ext.isEmpty && ext.count <= 16 {
                let base = String((name as NSString).deletingPathExtension.prefix(maxLength - ext.count - 1))
                name = base.trimmingCharacters(in: .whitespaces) + "." + ext
            } else {
                name = String(name.prefix(maxLength)).trimmingCharacters(in: .whitespaces)
            }
        }
        return name.isEmpty ? "file" : name
    }

    /// "name.ext", then "name 2.ext", "name 3.ext"... until exists returns false.
    public static func unique(_ name: String, exists: (String) -> Bool) -> String {
        guard exists(name) else { return name }
        let ns = name as NSString
        let ext = ns.pathExtension
        let base = ext.isEmpty ? name : ns.deletingPathExtension
        var n = 2
        while true {
            let candidate = ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)"
            if !exists(candidate) { return candidate }
            n += 1
        }
    }
}

/// The relay setting (section 5.1): https://host becomes wss://host/ws.
public enum RelayAddress {
    public enum Problem: Error, Equatable {
        case malformed
        /// http:// outside a debug build, or to a host other than this computer.
        case notHTTPS
    }

    public static let localHosts: Set<String> = ["127.0.0.1", "localhost", "10.0.2.2"]

    /// Trims, drops trailing slashes, checks the scheme. allowLocalHTTP: debug builds only.
    public static func normalize(_ text: String, allowLocalHTTP: Bool) throws -> String {
        var t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        while t.hasSuffix("/") { t.removeLast() }
        // Scheme and host are case-insensitive ("Https://Clip.sidali.dev" from autocapitalization); the path is not.
        if let r = t.range(of: "://"), r.lowerBound > t.startIndex {
            let rest = t[r.upperBound...]
            let end = rest.firstIndex(of: "/") ?? rest.endIndex
            t = t[..<r.lowerBound].lowercased() + "://" + rest[..<end].lowercased() + rest[end...]
        }
        guard let url = URL(string: t), let scheme = url.scheme?.lowercased(), let host = url.host, !host.isEmpty,
              url.query == nil, url.fragment == nil, url.user == nil
        else { throw Problem.malformed }
        switch scheme {
        case "https": return t
        case "http":
            guard allowLocalHTTP, localHosts.contains(host.lowercased()) else { throw Problem.notHTTPS }
            return t
        default: throw Problem.malformed
        }
    }

    public static func webSocketURL(_ relay: String) -> URL? {
        guard var c = URLComponents(string: relay) else { return nil }
        c.scheme = c.scheme?.lowercased() == "http" ? "ws" : "wss"
        c.path = (c.path.hasSuffix("/") ? String(c.path.dropLast()) : c.path) + "/ws"
        return c.url
    }

    public static func httpURL(_ relay: String, path: String) -> URL? {
        URL(string: relay + path)
    }

    public static func host(_ relay: String) -> String { URL(string: relay)?.host ?? relay }
}

/// Semantic versions "1.2.3", compared numerically.
public enum Version {
    public static func isLower(_ a: String, than b: String) -> Bool {
        let x = a.split(separator: ".").map { Int($0) ?? 0 }
        let y = b.split(separator: ".").map { Int($0) ?? 0 }
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : 0
            let r = i < y.count ? y[i] : 0
            if l != r { return l < r }
        }
        return false
    }
}
