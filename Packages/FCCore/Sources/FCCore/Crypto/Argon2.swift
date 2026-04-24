import Foundation
import CArgon2

/// Argon2id key derivation — the project-wide password KDF.
///
/// Freer's locked parameters (``Params/freer``) produce 32-byte keys and
/// must match the Android reference (`FC-AJDK/.../core/crypto/Kdf.java`):
/// iterations = 3, memory = 65 536 KiB, parallelism = 1, output = 32 bytes.
public enum Argon2 {

    /// Argon2id cost parameters.
    public struct Params: Sendable, Equatable {
        public let iterations: UInt32
        public let memoryKiB: UInt32
        public let parallelism: UInt32
        public let outputLength: Int

        public init(iterations: UInt32, memoryKiB: UInt32, parallelism: UInt32, outputLength: Int) {
            self.iterations = iterations
            self.memoryKiB = memoryKiB
            self.parallelism = parallelism
            self.outputLength = outputLength
        }

        /// Freer's locked parameters. Do not change without updating the
        /// Android constants in lockstep — derived keys would stop matching.
        public static let freer = Params(
            iterations: 3,
            memoryKiB: 65_536,
            parallelism: 1,
            outputLength: 32
        )
    }

    public enum Failure: Error, CustomStringConvertible {
        case argon2(code: Int32, message: String)

        public var description: String {
            switch self {
            case let .argon2(code, message):
                return "Argon2 failed (\(code)): \(message)"
            }
        }
    }

    /// Derive a key with Argon2id.
    ///
    /// - Parameters:
    ///   - password: Password bytes (typically UTF-8 of the passphrase).
    ///   - salt: Salt bytes. Argon2 requires at least 8 bytes.
    ///   - params: Cost parameters. Defaults to ``Params/freer``.
    /// - Returns: `params.outputLength` bytes of derived key material.
    public static func hashID(password: Data, salt: Data, params: Params = .freer) throws -> Data {
        var out = Data(count: params.outputLength)
        let rc: Int32 = out.withUnsafeMutableBytes { outBuf in
            password.withUnsafeBytes { pwdBuf in
                salt.withUnsafeBytes { saltBuf in
                    argon2id_hash_raw(
                        params.iterations,
                        params.memoryKiB,
                        params.parallelism,
                        pwdBuf.baseAddress,
                        password.count,
                        saltBuf.baseAddress,
                        salt.count,
                        outBuf.baseAddress,
                        params.outputLength
                    )
                }
            }
        }
        guard rc == ARGON2_OK.rawValue else {
            let message = argon2_error_message(rc).map { String(cString: $0) } ?? "unknown"
            throw Failure.argon2(code: rc, message: message)
        }
        return out
    }
}
