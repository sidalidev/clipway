import CryptoKit
import Foundation

/// One row of history (docs/PROTOCOL.md, section 9).
public struct HistoryEntry: Codable, Equatable, Identifiable, Sendable {
    public enum Direction: String, Codable, Sendable { case sent, received }

    public enum Status: String, Codable, Sendable {
        case sending, sent, waiting, delivered, failed
        /// An image or a file the other device could not fetch directly: not on the same network.
        case unreachable
    }

    /// The item id.
    public var id: String
    public var type: ItemType
    public var direction: Direction
    public var device: String
    public var kind: DeviceKind
    public var ts: Int64
    public var mime: String
    public var name: String?
    public var size: Int
    public var fp: String
    /// Full text of a text item, until its content is removed to save space.
    public var text: String?
    /// The image content is in the history folder.
    public var hasImage: Bool
    /// Where a file is (received: Downloads/Clipway; sent: where it was picked). Files are not copied.
    public var path: String?
    /// Items sent from this device.
    public var status: Status?
    public var contentRemoved: Bool

    public init(
        id: String, type: ItemType, direction: Direction, device: String, kind: DeviceKind, ts: Int64, mime: String,
        name: String? = nil, size: Int, fp: String, text: String? = nil, hasImage: Bool = false, path: String? = nil,
        status: Status? = nil
    ) {
        self.id = id
        self.type = type
        self.direction = direction
        self.device = device
        self.kind = kind
        self.ts = ts
        self.mime = mime
        self.name = name
        self.size = size
        self.fp = fp
        self.text = text
        self.hasImage = hasImage
        self.path = path
        self.status = status
        contentRemoved = false
    }

    /// Bytes this row keeps in history (texts and images; files are not copied).
    public var contentBytes: Int {
        if contentRemoved { return 0 }
        if type == .text { return text?.utf8.count ?? 0 }
        if hasImage { return size }
        return 0
    }

    /// First 200 characters of a text, on one line.
    public var preview: String {
        switch type {
        case .text:
            guard let text else { return "Text" }
            let flat = text.prefix(400).split(whereSeparator: \.isNewline).joined(separator: " ")
                .trimmingCharacters(in: .whitespaces)
            return flat.isEmpty ? "Blank text" : String(flat.prefix(200))
        case .image: return name ?? "Image"
        case .file: return name ?? "File"
        case .hello, .offer, .reply: return device
        }
    }
}

/// The encrypted history: history.bin (rows and texts) and items/<id>.bin (images), each sealed with
/// AES-256-GCM under a 32-byte key kept in the Keychain. Erasing the key makes them unreadable.
public final class HistoryStore {
    public static let maxItems = 50
    public static let maxBytes = 200 * 1_048_576
    static let magic = Data("CLWH1".utf8)

    public let directory: URL
    private let key: SymmetricKey
    private let byteLimit: Int
    public private(set) var entries: [HistoryEntry] = []

    public init(directory: URL, key: SymmetricKey, byteLimit: Int = HistoryStore.maxBytes) {
        self.directory = directory
        self.key = key
        self.byteLimit = byteLimit
    }

    var indexURL: URL { directory.appendingPathComponent("history.bin") }
    func imageURL(_ id: String) -> URL { directory.appendingPathComponent("items").appendingPathComponent(id + ".bin") }

    // MARK: Loading and saving

    /// Reads history.bin. An unreadable file (key erased, damage) is set aside and history starts empty.
    @discardableResult
    public func load() -> [HistoryEntry] {
        entries = []
        guard let blob = try? Data(contentsOf: indexURL) else { return entries }
        do {
            let plain = try open(blob, aad: "history")
            entries = try JSONDecoder().decode([HistoryEntry].self, from: plain)
        } catch {
            // Unreadable without its key: the images sealed with the same key go too.
            try? FileManager.default.removeItem(at: indexURL)
            try? FileManager.default.removeItem(at: directory.appendingPathComponent("items"))
        }
        return entries
    }

    public func save() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let sealed = try seal(try encoder.encode(entries), aad: "history")
        try sealed.write(to: indexURL, options: [.atomic])
    }

    // MARK: Changes

    /// Adds a row (newest first), with the image content for images, then applies the limits.
    public func add(_ entry: HistoryEntry, image: Data? = nil) throws {
        var row = entry
        entries.removeAll { $0.id == entry.id }
        if let image, entry.type == .image {
            try writeImage(image, id: entry.id)
            row.hasImage = true
        }
        entries.insert(row, at: 0)
        entries.sort { $0.ts > $1.ts }
        applyLimits()
        try save()
    }

    public func update(_ id: String, _ change: (inout HistoryEntry) -> Void) {
        guard let i = entries.firstIndex(where: { $0.id == id }) else { return }
        change(&entries[i])
        try? save()
    }

    /// Removes one row. Returns what Undo needs.
    public func remove(_ id: String) -> (HistoryEntry, Data?)? {
        guard let i = entries.firstIndex(where: { $0.id == id }) else { return nil }
        let row = entries.remove(at: i)
        let image = row.hasImage ? self.image(row.id) : nil
        try? FileManager.default.removeItem(at: imageURL(row.id))
        try? save()
        return (row, image)
    }

    /// Removes every row. Returns what Undo needs.
    public func clear() -> [(HistoryEntry, Data?)] {
        let all = entries.map { ($0, $0.hasImage ? image($0.id) : nil) }
        entries = []
        try? FileManager.default.removeItem(at: directory.appendingPathComponent("items"))
        try? save()
        return all
    }

    public func restore(_ rows: [(HistoryEntry, Data?)]) {
        for (row, image) in rows {
            var r = row
            if let image, r.hasImage { try? writeImage(image, id: r.id) } else { r.hasImage = false }
            entries.removeAll { $0.id == r.id }
            entries.append(r)
        }
        entries.sort { $0.ts > $1.ts }
        applyLimits()
        try? save()
    }

    public func image(_ id: String) -> Data? {
        guard let blob = try? Data(contentsOf: imageURL(id)) else { return nil }
        return try? open(blob, aad: "item|" + id)
    }

    /// 50 rows at most; content above 200 MiB is dropped from the oldest rows first.
    func applyLimits() {
        while entries.count > Self.maxItems {
            let dropped = entries.removeLast()
            try? FileManager.default.removeItem(at: imageURL(dropped.id))
        }
        var total = entries.reduce(0) { $0 + $1.contentBytes }
        var i = entries.count - 1
        while total > byteLimit && i >= 0 {
            let bytes = entries[i].contentBytes
            if bytes > 0 {
                total -= bytes
                entries[i].text = nil
                if entries[i].hasImage { try? FileManager.default.removeItem(at: imageURL(entries[i].id)) }
                entries[i].hasImage = false
                entries[i].contentRemoved = true
            }
            i -= 1
        }
    }

    /// Deletes the history folder.
    public func wipe() {
        entries = []
        try? FileManager.default.removeItem(at: directory)
    }

    // MARK: Export

    /// A ZIP that opens without Clipway: history.json and items/ with the images, named by item id.
    public func exportZip() throws -> Data {
        var zip = ZipWriter()
        var rows: [[String: Any]] = []
        for e in entries {
            var o: [String: Any] = [
                "type": e.type.rawValue, "direction": e.direction.rawValue, "device": e.device, "ts": e.ts, "mime": e.mime,
                "size": e.size,
            ]
            if let name = e.name { o["name"] = name }
            if let text = e.text { o["text"] = text }
            if e.type == .file, let path = e.path { o["path"] = path }
            if e.hasImage, let data = image(e.id) {
                let file = "items/\(e.id).\(Self.fileExtension(e.mime))"
                zip.add(path: file, data: data, date: Date(timeIntervalSince1970: Double(e.ts) / 1000))
                o["image"] = file
            }
            if e.contentRemoved { o["contentRemoved"] = true }
            rows.append(o)
        }
        let json = try JSONSerialization.data(withJSONObject: rows, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        zip.add(path: "history.json", data: json, date: Date())
        return zip.finish()
    }

    static func fileExtension(_ mime: String) -> String {
        switch mime {
        case "image/png": return "png"
        case "image/jpeg": return "jpg"
        case "image/gif": return "gif"
        case "image/webp": return "webp"
        case "image/heic": return "heic"
        case "image/tiff": return "tiff"
        default: return "bin"
        }
    }

    // MARK: Encryption at rest

    private func writeImage(_ data: Data, id: String) throws {
        let folder = directory.appendingPathComponent("items")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try seal(data, aad: "item|" + id).write(to: imageURL(id), options: [.atomic])
    }

    private func seal(_ data: Data, aad: String) throws -> Data {
        let box = try AES.GCM.seal(data, using: key, authenticating: Data(("clipway-history-1|" + aad).utf8))
        guard let combined = box.combined else { throw ClipwayCrypto.Failure.invalidEnvelope }
        return Self.magic + combined
    }

    private func open(_ blob: Data, aad: String) throws -> Data {
        guard blob.count > Self.magic.count + 28, blob.prefix(Self.magic.count) == Self.magic else {
            throw ClipwayCrypto.Failure.invalidEnvelope
        }
        let box = try AES.GCM.SealedBox(combined: Data(blob.dropFirst(Self.magic.count)))
        return try AES.GCM.open(box, using: key, authenticating: Data(("clipway-history-1|" + aad).utf8))
    }
}
