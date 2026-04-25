import Foundation

/// Test-only hex helpers, mirroring the version in FCCoreTests/
/// FCTransportTests support folders. Aborts on malformed input — the
/// test bundle is trusted.
extension Data {
    init(fromHex hex: String) {
        precondition(hex.count % 2 == 0, "hex string has odd length: \(hex)")
        var data = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<next], radix: 16) else {
                preconditionFailure("invalid hex byte: \(hex[idx..<next])")
            }
            data.append(byte)
            idx = next
        }
        self = data
    }

    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
