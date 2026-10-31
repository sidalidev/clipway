import Foundation

/// A minimal ZIP writer (stored entries, UTF-8 names), enough for the history export.
/// Readable by unzip, Finder and any ZIP tool. No ZIP64: the export stays far below 4 GiB.
public struct ZipWriter {
    private var body = Data()
    private var central = Data()
    private var count: UInt16 = 0

    public init() {}

    public mutating func add(path: String, data: Data, date: Date) {
        let name = Data(path.utf8)
        let crc = CRC32.checksum(data)
        let (time, day) = Self.dosDateTime(date)
        let offset = UInt32(body.count)
        // Local file header
        body.append(le32: 0x0403_4b50)
        body.append(le16: 20)          // version needed
        body.append(le16: 0x0800)      // UTF-8 names
        body.append(le16: 0)           // stored
        body.append(le16: time)
        body.append(le16: day)
        body.append(le32: crc)
        body.append(le32: UInt32(data.count))
        body.append(le32: UInt32(data.count))
        body.append(le16: UInt16(name.count))
        body.append(le16: 0)
        body.append(name)
        body.append(data)
        // Central directory entry
        central.append(le32: 0x0201_4b50)
        central.append(le16: 0x0314)   // made by: Unix, 2.0
        central.append(le16: 20)
        central.append(le16: 0x0800)
        central.append(le16: 0)
        central.append(le16: time)
        central.append(le16: day)
        central.append(le32: crc)
        central.append(le32: UInt32(data.count))
        central.append(le32: UInt32(data.count))
        central.append(le16: UInt16(name.count))
        central.append(le16: 0)        // extra
        central.append(le16: 0)        // comment
        central.append(le16: 0)        // disk
        central.append(le16: 0)        // internal attributes
        central.append(le32: 0o100644 << 16) // -rw-r--r--
        central.append(le32: offset)
        central.append(name)
        count += 1
    }

    public func finish() -> Data {
        var out = body
        let start = UInt32(out.count)
        out.append(central)
        out.append(le32: 0x0605_4b50)
        out.append(le16: 0)
        out.append(le16: 0)
        out.append(le16: count)
        out.append(le16: count)
        out.append(le32: UInt32(central.count))
        out.append(le32: start)
        out.append(le16: 0)
        return out
    }

    static func dosDateTime(_ date: Date) -> (UInt16, UInt16) {
        let c = Calendar(identifier: .gregorian).dateComponents(in: .current, from: date)
        let year: Int = max(1980, c.year ?? 1980)
        let hour: Int = c.hour ?? 0
        let minute: Int = c.minute ?? 0
        let second: Int = c.second ?? 0
        let month: Int = c.month ?? 1
        let dayOfMonth: Int = c.day ?? 1
        let timeBits: Int = (hour << 11) | (minute << 5) | (second / 2)
        let dayBits: Int = ((year - 1980) << 9) | (month << 5) | dayOfMonth
        return (UInt16(timeBits), UInt16(dayBits))
    }
}

/// CRC-32 (IEEE 802.3), as ZIP requires.
public enum CRC32 {
    static let table: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    public static func checksum(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        data.withUnsafeBytes { raw in
            for byte in raw.bindMemory(to: UInt8.self) {
                crc = table[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
            }
        }
        return crc ^ 0xFFFF_FFFF
    }
}

extension Data {
    mutating func append(le16 v: UInt16) { Swift.withUnsafeBytes(of: v.littleEndian) { append(contentsOf: $0) } }
    mutating func append(le32 v: UInt32) { Swift.withUnsafeBytes(of: v.littleEndian) { append(contentsOf: $0) } }
}
