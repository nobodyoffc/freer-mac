import Foundation

/// The SSH binary encoding (RFC 4251 §5), just the two types this app
/// needs: `uint32` and `string`.
///
/// Every SSH structure — public key blobs, signature blobs, agent
/// messages — is a concatenation of these, so one tiny codec serves
/// all three rather than each call site reaching for
/// `withUnsafeBytes` and getting the byte order wrong.
///
/// `string` is **not** a text type. It is a length-prefixed byte
/// string that happens to carry UTF-8 when the field is a name like
/// `"ssh-ed25519"`. Nothing here validates or transcodes; a `String`
/// goes in as its UTF-8 bytes and comes back out the same way.
public enum SshWire {

    /// Refuse to allocate for a length field a peer made up. OpenSSH's
    /// own agent client caps a message at 256 KiB; every structure we
    /// parse is under 100 bytes, so this is pure damage control on a
    /// socket any local process can connect to.
    public static let maxStringLength = 256 * 1024

    public enum Failure: Error, CustomStringConvertible {
        case truncated(needed: Int, available: Int)
        case tooLong(Int)

        public var description: String {
            switch self {
            case let .truncated(needed, available):
                return "SshWire: need \(needed) more bytes, have \(available)"
            case let .tooLong(n):
                return "SshWire: declared length \(n) exceeds the \(SshWire.maxStringLength)-byte cap"
            }
        }
    }

    // MARK: - Encoding

    public static func uint32(_ value: UInt32) -> Data {
        Data([
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value)
        ])
    }

    public static func string(_ bytes: Data) -> Data {
        uint32(UInt32(bytes.count)) + bytes
    }

    public static func string(_ text: String) -> Data {
        string(Data(text.utf8))
    }

    // MARK: - Decoding

    /// A cursor over a buffer. Every read either advances or throws —
    /// there is no partial-read state to get wrong.
    public struct Reader {

        private let bytes: [UInt8]
        private var offset: Int

        public init(_ data: Data) {
            self.bytes = [UInt8](data)
            self.offset = 0
        }

        public var remaining: Int { bytes.count - offset }
        public var isAtEnd: Bool { remaining == 0 }

        public mutating func readByte() throws -> UInt8 {
            guard remaining >= 1 else { throw Failure.truncated(needed: 1, available: remaining) }
            defer { offset += 1 }
            return bytes[offset]
        }

        public mutating func readUInt32() throws -> UInt32 {
            guard remaining >= 4 else { throw Failure.truncated(needed: 4, available: remaining) }
            defer { offset += 4 }
            return (UInt32(bytes[offset]) << 24)
                 | (UInt32(bytes[offset + 1]) << 16)
                 | (UInt32(bytes[offset + 2]) << 8)
                 |  UInt32(bytes[offset + 3])
        }

        public mutating func readString() throws -> Data {
            let declared = try readUInt32()
            guard declared <= UInt32(maxStringLength) else {
                throw Failure.tooLong(Int(declared))
            }
            let n = Int(declared)
            guard remaining >= n else { throw Failure.truncated(needed: n, available: remaining) }
            defer { offset += n }
            return Data(bytes[offset ..< offset + n])
        }

        /// Everything not yet consumed. Used to check a message had no
        /// trailing junk.
        public mutating func readRest() -> Data {
            defer { offset = bytes.count }
            return Data(bytes[offset...])
        }
    }
}
