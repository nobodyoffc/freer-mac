import Foundation
import FCCore

/// Hash-based proof of work for FUDP's DDoS defense, mirroring
/// `FC-AJDK/.../fudp/security/ProofOfWork.java`.
///
/// The server issues a 16-byte random `nonce` plus a `difficulty` (in
/// leading-zero bits). The client must find an 8-byte `solution` such
/// that `SHA-256(nonce ‖ solution)` has at least `difficulty` leading
/// zero bits.
///
/// **Determinism.** The reference solver scans solutions starting from
/// 0 and incrementing as a big-endian Int64, returning the first valid
/// candidate. Our solver does the same, so for any fixed
/// `(nonce, difficulty)` Swift produces byte-identical bytes to
/// FC-JDK / FC-AJDK.
public enum ProofOfWork {

    public static let minDifficulty = 4
    public static let maxDifficulty = 24
    public static let defaultDifficulty = 12
    public static let nonceLength = 16
    public static let solutionLength = 8

    public enum Failure: Error, CustomStringConvertible {
        case invalidNonceLength(got: Int)
        case invalidSolutionLength(got: Int)
        case invalidDifficulty(got: Int)
        case nonPositiveTimeout(got: Int)
        case timeout

        public var description: String {
            switch self {
            case .invalidNonceLength(let n):     return "PoW: nonce must be \(ProofOfWork.nonceLength) bytes, got \(n)"
            case .invalidSolutionLength(let n):  return "PoW: solution must be \(ProofOfWork.solutionLength) bytes, got \(n)"
            case .invalidDifficulty(let d):      return "PoW: difficulty must be in [\(ProofOfWork.minDifficulty), \(ProofOfWork.maxDifficulty)], got \(d)"
            case .nonPositiveTimeout(let t):     return "PoW: timeoutMs must be > 0, got \(t)"
            case .timeout:                       return "PoW: solve timed out"
            }
        }
    }

    /// `true` iff `SHA-256(nonce ‖ solution)` has ≥ `difficulty` leading zero bits.
    public static func verify(nonce: Data, solution: Data, difficulty: Int) -> Bool {
        guard nonce.count == nonceLength else { return false }
        guard solution.count == solutionLength else { return false }
        guard (minDifficulty...maxDifficulty).contains(difficulty) else { return false }
        let hash = Hash.sha256(nonce + solution)
        return leadingZeroBits(hash) >= difficulty
    }

    /// Find the first solution (scanning from 0 upward, BE Int64
    /// encoding) such that `verify(nonce, solution, difficulty)` is
    /// true. Returns the 8-byte solution; throws `Failure.timeout` if
    /// not found within `timeoutMs`.
    public static func solve(nonce: Data, difficulty: Int, timeoutMs: Int) throws -> Data {
        guard nonce.count == nonceLength else { throw Failure.invalidNonceLength(got: nonce.count) }
        guard (minDifficulty...maxDifficulty).contains(difficulty) else { throw Failure.invalidDifficulty(got: difficulty) }
        guard timeoutMs > 0 else { throw Failure.nonPositiveTimeout(got: timeoutMs) }

        let deadlineNs = DispatchTime.now().uptimeNanoseconds + UInt64(timeoutMs) * 1_000_000
        // Check the clock periodically rather than every iteration —
        // saves a syscall per hash. Matches the Java solveInterruptible
        // strategy.
        let checkInterval = 4096

        var solution: UInt64 = 0
        var solutionBytes = Data(count: solutionLength)

        while true {
            // BE Int64 → 8 bytes.
            solutionBytes[0] = UInt8(truncatingIfNeeded: solution >> 56)
            solutionBytes[1] = UInt8(truncatingIfNeeded: solution >> 48)
            solutionBytes[2] = UInt8(truncatingIfNeeded: solution >> 40)
            solutionBytes[3] = UInt8(truncatingIfNeeded: solution >> 32)
            solutionBytes[4] = UInt8(truncatingIfNeeded: solution >> 24)
            solutionBytes[5] = UInt8(truncatingIfNeeded: solution >> 16)
            solutionBytes[6] = UInt8(truncatingIfNeeded: solution >> 8)
            solutionBytes[7] = UInt8(truncatingIfNeeded: solution)

            let hash = Hash.sha256(nonce + solutionBytes)
            if leadingZeroBits(hash) >= difficulty {
                return solutionBytes
            }
            solution &+= 1

            if solution.isMultiple(of: UInt64(checkInterval)) {
                if DispatchTime.now().uptimeNanoseconds > deadlineNs {
                    throw Failure.timeout
                }
            }

            if solution == 0 {
                // 64-bit wrap (essentially never happens at sane difficulty).
                throw Failure.timeout
            }
        }
    }

    /// Count consecutive zero bits from the most significant end.
    /// Returns `data.count * 8` for an all-zero buffer.
    public static func leadingZeroBits(_ data: Data) -> Int {
        var count = 0
        for byte in data {
            if byte == 0 {
                count += 8
            } else {
                count += Int(byte.leadingZeroBitCount)
                break
            }
        }
        return count
    }
}
