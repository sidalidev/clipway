// Draws the app icon from the charter: Clipway's color, Lac (#2E7FA1), flat (no gradient, no
// shine), and the two opposite arrows in cream (#FBF7EF), drawn on a 24 grid with a 2.1 stroke,
// round caps and round joins: the same drawing as the Android adaptive icon (res/drawable/ic_fg.xml).
// Vector paths only (no symbol font), so the icon is ours to publish.
// Usage, from mac/: swift tools/make-icon.swift Clipway/Assets.xcassets/AppIcon.appiconset
import AppKit

let out = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

let lac = NSColor(srgbRed: 0x2E / 255.0, green: 0x7F / 255.0, blue: 0xA1 / 255.0, alpha: 1)
let cream = NSColor(srgbRed: 0xFB / 255.0, green: 0xF7 / 255.0, blue: 0xEF / 255.0, alpha: 1)
let arrows: [[(CGFloat, CGFloat)]] = [
    [(5, 9.5), (17.5, 9.5)],
    [(14.5, 6.5), (17.5, 9.5), (14.5, 12.5)],
    [(19, 14.5), (6.5, 14.5)],
    [(9.5, 11.5), (6.5, 14.5), (9.5, 17.5)],
]

func draw(_ size: CGFloat) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8, samplesPerPixel: 4,
        hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = size / 1024
    // macOS icon grid: an 824 pt rounded square centered in 1024, macOS corners. Flat.
    let tile = NSRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s)
    lac.setFill()
    NSBezierPath(roundedRect: tile, xRadius: 185 * s, yRadius: 185 * s).fill()
    // The 24 grid becomes 600 pt, centered: the drawing is 44 % of the tile, like on Android.
    let grid: CGFloat = 600 * s
    let origin = NSPoint(x: 512 * s - grid / 2, y: 512 * s + grid / 2)
    let unit = grid / 24
    cream.setStroke()
    for line in arrows {
        let path = NSBezierPath()
        path.lineWidth = 2.1 * unit
        path.lineCapStyle = .round
        path.lineJoinStyle = .round
        for (i, p) in line.enumerated() {
            let point = NSPoint(x: origin.x + p.0 * unit, y: origin.y - p.1 * unit)
            if i == 0 { path.move(to: point) } else { path.line(to: point) }
        }
        path.stroke()
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

var images: [[String: String]] = []
for (points, scales) in [(16, [1, 2]), (32, [1, 2]), (128, [1, 2]), (256, [1, 2]), (512, [1, 2])] {
    for scale in scales {
        let name = "icon_\(points)x\(points)\(scale == 2 ? "@2x" : "").png"
        try draw(CGFloat(points * scale)).write(to: out.appendingPathComponent(name))
        images.append(["idiom": "mac", "size": "\(points)x\(points)", "scale": "\(scale)x", "filename": name])
    }
}
let contents: [String: Any] = ["images": images, "info": ["version": 1, "author": "xcode"]]
try JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys])
    .write(to: out.appendingPathComponent("Contents.json"))
let catalog = out.deletingLastPathComponent().appendingPathComponent("Contents.json")
try Data("{\n  \"info\" : {\n    \"author\" : \"xcode\",\n    \"version\" : 1\n  }\n}\n".utf8).write(to: catalog)
print("icon written to \(out.path)")
