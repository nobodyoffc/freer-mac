import Foundation

/// Pure-Swift RIPEMD-160 implementation.
///
/// Reference: Dobbertin, Bosselaers, Preneel — "RIPEMD-160: A Strengthened
/// Version of RIPEMD", Fast Software Encryption (1996). Spec and test
/// vectors: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
///
/// Not constant-time. RIPEMD-160 in this project is only applied to data
/// that is either already public (e.g. Hash-160 of a public key) or to a
/// commitment that does not leak its input. If a side-channel-sensitive
/// call site is added, this implementation must be re-audited.
enum RIPEMD160 {

    static func digest(_ message: Data) -> Data {
        var h: (UInt32, UInt32, UInt32, UInt32, UInt32) = (
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
        )

        let bytes = [UInt8](pad(message))
        let blockCount = bytes.count / 64

        for blockIdx in 0..<blockCount {
            var x = [UInt32](repeating: 0, count: 16)
            let offset = blockIdx * 64
            for i in 0..<16 {
                let p = offset + i * 4
                x[i] = UInt32(bytes[p])
                    | (UInt32(bytes[p + 1]) << 8)
                    | (UInt32(bytes[p + 2]) << 16)
                    | (UInt32(bytes[p + 3]) << 24)
            }
            compress(state: &h, x: x)
        }

        var out = Data(capacity: 20)
        for word in [h.0, h.1, h.2, h.3, h.4] {
            out.append(UInt8(word & 0xff))
            out.append(UInt8((word >> 8) & 0xff))
            out.append(UInt8((word >> 16) & 0xff))
            out.append(UInt8((word >> 24) & 0xff))
        }
        return out
    }

    private static func pad(_ message: Data) -> Data {
        var padded = message
        let bitLen = UInt64(message.count) &* 8
        padded.append(0x80)
        while padded.count % 64 != 56 {
            padded.append(0x00)
        }
        for i in 0..<8 {
            padded.append(UInt8((bitLen >> (8 * UInt64(i))) & 0xff))
        }
        return padded
    }

    private static func compress(state: inout (UInt32, UInt32, UInt32, UInt32, UInt32), x: [UInt32]) {
        var aL = state.0, bL = state.1, cL = state.2, dL = state.3, eL = state.4
        var aR = state.0, bR = state.1, cR = state.2, dR = state.3, eR = state.4

        for j in 0..<80 {
            let k = j / 16

            var t = aL &+ f(j, bL, cL, dL) &+ x[rL[j]] &+ constants[k]
            t = rotl(t, sL[j]) &+ eL
            aL = eL
            eL = dL
            dL = rotl(cL, 10)
            cL = bL
            bL = t

            t = aR &+ f(79 - j, bR, cR, dR) &+ x[rR[j]] &+ constantsPrime[k]
            t = rotl(t, sR[j]) &+ eR
            aR = eR
            eR = dR
            dR = rotl(cR, 10)
            cR = bR
            bR = t
        }

        let t = state.1 &+ cL &+ dR
        state.1 = state.2 &+ dL &+ eR
        state.2 = state.3 &+ eL &+ aR
        state.3 = state.4 &+ aL &+ bR
        state.4 = state.0 &+ bL &+ cR
        state.0 = t
    }

    @inline(__always)
    private static func f(_ j: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        switch j {
        case 0..<16:  return x ^ y ^ z
        case 16..<32: return (x & y) | (~x & z)
        case 32..<48: return (x | ~y) ^ z
        case 48..<64: return (x & z) | (y & ~z)
        case 64..<80: return x ^ (y | ~z)
        default: fatalError("RIPEMD-160 f() out of range: \(j)")
        }
    }

    @inline(__always)
    private static func rotl(_ x: UInt32, _ n: Int) -> UInt32 {
        (x &<< UInt32(n)) | (x &>> UInt32(32 - n))
    }

    private static let constants: [UInt32] = [
        0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e
    ]
    private static let constantsPrime: [UInt32] = [
        0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000
    ]

    private static let rL: [Int] = [
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
        7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
        3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
        1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
        4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
    ]

    private static let sL: [Int] = [
        11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
         7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
        11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
         9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
    ]

    private static let rR: [Int] = [
         5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
         6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
        15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
         8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
        12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
    ]

    private static let sR: [Int] = [
         8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
         9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
         9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
         8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
    ]
}
