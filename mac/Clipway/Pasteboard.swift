import AppKit
import ClipwayCore
import UniformTypeIdentifiers

/// Watches NSPasteboard.general every 300 ms (its changeCount; the content is read only on a change)
/// and writes received items to it. Its own writes are remembered and never sent back (section 5.5).
@MainActor
final class Pasteboard {
    static let interval: TimeInterval = 0.3
    static let sourceMarker = "dev.sidali.clipway"

    private let board = NSPasteboard.general
    private var timer: Timer?
    private var lastCount: Int
    private var ownCounts: [Int] = []
    /// Called on a change made by another app.
    var onChange: (@MainActor (NSPasteboard) -> Void)?

    init() {
        lastCount = NSPasteboard.general.changeCount
    }

    func start() {
        guard timer == nil else { return }
        lastCount = board.changeCount
        let timer = Timer(timeInterval: Self.interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        timer.tolerance = 0.05
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    private func tick() {
        let count = board.changeCount
        guard count != lastCount else { return }
        lastCount = count
        if ownCounts.contains(count) { return }
        // Another clipboard tool may copy what we wrote, with our marker. Types are read first:
        // reading types never counts as reading the content.
        let source = NSPasteboard.PasteboardType(PasteboardRule.source)
        if board.types?.contains(source) == true, board.string(forType: source) == Self.sourceMarker { return }
        onChange?(board)
    }

    /// The types of each item of the current change, for PasteboardRule.decide.
    func types() -> [[String]] {
        (board.pasteboardItems ?? []).map { $0.types.map(\.rawValue) }
    }

    // MARK: Writing (received items, and copies back from history)

    func write(text: String) {
        let item = NSPasteboardItem()
        item.setString(text, forType: .string)
        record(item)
    }

    /// An image as its own type plus a TIFF representation for older apps.
    func write(image data: Data, mime: String) {
        let item = NSPasteboardItem()
        if let type = UTType(mimeType: mime) {
            item.setData(data, forType: NSPasteboard.PasteboardType(type.identifier))
        }
        if mime != "image/tiff", let tiff = NSImage(data: data)?.tiffRepresentation {
            item.setData(tiff, forType: .tiff)
        }
        record(item)
    }

    private func record(_ item: NSPasteboardItem) {
        item.setString(Self.sourceMarker, forType: NSPasteboard.PasteboardType(PasteboardRule.source))
        board.clearContents()
        board.writeObjects([item])
        let count = board.changeCount
        ownCounts.append(count)
        if ownCounts.count > 20 { ownCounts.removeFirst() }
        lastCount = count
    }

    /// PNG from PNG or TIFF data (off the main thread for large images).
    nonisolated static func png(from data: Data, type: String) -> Data? {
        if type == PasteboardRule.png { return data }
        guard let rep = NSBitmapImageRep(data: data) else { return nil }
        return rep.representation(using: .png, properties: [:])
    }
}
