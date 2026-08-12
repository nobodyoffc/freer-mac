import Foundation

/// Keccak-256 (the original Keccak submission, as used by Ethereum and
/// BouncyCastle's `Keccak.Digest256`) — **not** NIST SHA3-256, which
/// differs only in the domain-separation padding byte (0x01 here vs
/// NIST's 0x06).
///
/// Pure-Swift sponge over Keccak-f[1600]: rate 136 bytes (1088 bits),
/// capacity 512 bits, 24 rounds.
enum Keccak256 {

    private static let rate = 136 // bytes; (1600 - 2*256) / 8

    private static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082,
        0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088,
        0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B,
        0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080,
        0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080,
        0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ]

    /// Rotation offsets for the ρ step, indexed x + 5y.
    private static let rho: [Int] = [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ]

    static func digest(_ message: Data) -> Data {
        var state = [UInt64](repeating: 0, count: 25)

        // Absorb full blocks, then the padded final block. Keccak (pre-NIST)
        // pads with 0x01 …0x80 (multi-rate padding, domain bit 0x01).
        var padded = message
        let padLen = rate - (message.count % rate)
        padded.append(contentsOf: [UInt8](repeating: 0, count: padLen))
        padded[padded.endIndex - padLen] = 0x01
        padded[padded.endIndex - 1] |= 0x80

        padded.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            var offset = 0
            while offset < raw.count {
                for lane in 0..<(rate / 8) {
                    var word: UInt64 = 0
                    for b in 0..<8 {
                        word |= UInt64(raw[offset + lane * 8 + b]) << (8 * UInt64(b))
                    }
                    state[lane] ^= word
                }
                keccakF(&state)
                offset += rate
            }
        }

        // Squeeze: 32 bytes fit in the first rate block.
        var out = Data(capacity: 32)
        for lane in 0..<4 {
            var word = state[lane]
            for _ in 0..<8 {
                out.append(UInt8(truncatingIfNeeded: word))
                word >>= 8
            }
        }
        return out
    }

    private static func keccakF(_ a: inout [UInt64]) {
        for rc in roundConstants {
            // θ
            var c = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
            }
            for x in 0..<5 {
                let d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
                for y in stride(from: 0, to: 25, by: 5) {
                    a[x + y] ^= d
                }
            }

            // ρ and π
            var b = [UInt64](repeating: 0, count: 25)
            for x in 0..<5 {
                for y in 0..<5 {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], rho[x + 5 * y])
                }
            }

            // χ
            for x in 0..<5 {
                for y in stride(from: 0, to: 25, by: 5) {
                    a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y])
                }
            }

            // ι
            a[0] ^= rc
        }
    }

    @inline(__always)
    private static func rotl(_ v: UInt64, _ n: Int) -> UInt64 {
        n == 0 ? v : (v << UInt64(n)) | (v >> UInt64(64 - n))
    }
}
