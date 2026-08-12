import Foundation

/// RFC 6238 TOTP with the RFC 4226 dynamic-truncation step — HMAC-SHA1,
/// 30-second time step, matching the Android `TOTPUtil` (and Google
/// Authenticator's defaults).
public enum Totp {

    public static let timeStep: TimeInterval = 30

    /// Generate a TOTP code.
    /// - Parameters:
    ///   - secret: the raw key bytes (typically `Base32.decode` of the
    ///     shared secret).
    ///   - unixTime: seconds since the epoch.
    ///   - digits: code length; Android passes 6.
    public static func generate(secret: Data, unixTime: Int64, digits: Int = 6) -> String {
        var counter = UInt64(unixTime / Int64(timeStep)).bigEndian
        let message = withUnsafeBytes(of: &counter) { Data($0) }
        let hash = Hash.hmacSha1(message, key: secret)

        let offset = Int(hash[hash.index(hash.startIndex, offsetBy: hash.count - 1)] & 0x0F)
        let idx = { (i: Int) in hash[hash.index(hash.startIndex, offsetBy: offset + i)] }
        let binary = (UInt32(idx(0) & 0x7F) << 24)
            | (UInt32(idx(1)) << 16)
            | (UInt32(idx(2)) << 8)
            | UInt32(idx(3))

        let modulus = UInt32(pow(10.0, Double(digits)))
        return String(format: "%0\(digits)d", binary % modulus)
    }

    /// Seconds remaining until the current code rotates.
    public static func secondsRemaining(unixTime: Int64) -> Int {
        Int(Int64(timeStep)) - Int(unixTime % Int64(timeStep))
    }
}
