import Foundation
import Compression

/// A zip whose bytes depend only on the entries given: no timestamps, no
/// extra fields, no comment, no directory entries, entries in path order.
/// The same files make the same archive, so a code whose sources did not
/// change keeps its DID from one release to the next.
///
/// `git archive` cannot promise that: the commit id goes into the archive
/// comment, and archiving a tree stamps the current time.
public enum DeterministicZip {

    public struct Entry: Sendable {
        public var path: String
        public var data: Data
        public var executable: Bool

        public init(path: String, data: Data, executable: Bool = false) {
            self.path = path
            self.data = data
            self.executable = executable
        }
    }

    /// 1980-01-01 00:00, the earliest DOS date.
    static let dosTime: UInt16 = 0
    static let dosDate: UInt16 = (0 << 9) | (1 << 5) | 1

    public static func archive(_ entries: [Entry]) -> Data {
        let sorted = entries.sorted { $0.path.utf8.lexicographicallyPrecedes($1.path.utf8) }
        var out = Data()
        var central = Data()
        for entry in sorted {
            let name = Data(entry.path.utf8)
            let crc = CRC32.checksum(entry.data)
            // Deflate only when it pays; a stored entry is just as valid.
            let deflated = deflate(entry.data)
            let (method, body): (UInt16, Data) = (deflated.map { $0.count < entry.data.count } ?? false)
                ? (8, deflated!) : (0, entry.data)
            let offset = UInt32(out.count)
            let flags: UInt16 = 1 << 11 // names are UTF-8

            out.le32(0x0403_4b50)
            out.le16(20); out.le16(flags); out.le16(method)
            out.le16(dosTime); out.le16(dosDate)
            out.le32(crc); out.le32(UInt32(body.count)); out.le32(UInt32(entry.data.count))
            out.le16(UInt16(name.count)); out.le16(0)
            out.append(name)
            out.append(body)

            let mode: UInt32 = entry.executable ? 0o100755 : 0o100644
            central.le32(0x0201_4b50)
            central.le16((3 << 8) | 20) // made by Unix, spec 2.0
            central.le16(20); central.le16(flags); central.le16(method)
            central.le16(dosTime); central.le16(dosDate)
            central.le32(crc); central.le32(UInt32(body.count)); central.le32(UInt32(entry.data.count))
            central.le16(UInt16(name.count)); central.le16(0); central.le16(0)
            central.le16(0); central.le16(0)
            central.le32(mode << 16)
            central.le32(offset)
            central.append(name)
        }
        let centralOffset = UInt32(out.count)
        out.append(central)
        out.le32(0x0605_4b50)
        out.le16(0); out.le16(0)
        out.le16(UInt16(sorted.count)); out.le16(UInt16(sorted.count))
        out.le32(UInt32(central.count)); out.le32(centralOffset)
        out.le16(0)
        return out
    }

    /// Raw deflate (RFC 1951). Apple's `COMPRESSION_ZLIB` is zlib at level
    /// 5, a fixed encoder, so the output is a function of the input.
    static func deflate(_ data: Data) -> Data? {
        guard !data.isEmpty else { return nil }
        let capacity = data.count + data.count / 10 + 64
        var output = Data(count: capacity)
        let written = output.withUnsafeMutableBytes { dst in
            data.withUnsafeBytes { src in
                compression_encode_buffer(
                    dst.bindMemory(to: UInt8.self).baseAddress!, capacity,
                    src.bindMemory(to: UInt8.self).baseAddress!, data.count,
                    nil, COMPRESSION_ZLIB
                )
            }
        }
        guard written > 0 else { return nil }
        return output.prefix(written)
    }
}

enum CRC32 {
    static let table: [UInt32] = (0..<256).map { i in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    static func checksum(_ data: Data) -> UInt32 {
        var c: UInt32 = 0xFFFF_FFFF
        for byte in data { c = table[Int((c ^ UInt32(byte)) & 0xFF)] ^ (c >> 8) }
        return c ^ 0xFFFF_FFFF
    }
}

private extension Data {
    mutating func le16(_ v: UInt16) { Swift.withUnsafeBytes(of: v.littleEndian) { append(contentsOf: $0) } }
    mutating func le32(_ v: UInt32) { Swift.withUnsafeBytes(of: v.littleEndian) { append(contentsOf: $0) } }
}
