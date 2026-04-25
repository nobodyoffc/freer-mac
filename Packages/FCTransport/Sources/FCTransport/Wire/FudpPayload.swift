import Foundation

/// Plaintext FUDP packet payload — the bytes the AEAD encrypts to make
/// the on-the-wire encrypted-payload portion of a packet.
///
/// Layout:
/// ```
///   8 B  timestamp     (BE Int64, only if header.flags.hasTimestamp)
///   8 B  sessionEpoch  (BE Int64, only if header.flags.hasEpoch)
///   N B  frames        (concatenated, each varint-typed)
/// ```
///
/// Conditional fields save bytes on ACK-only / steady-state packets. The
/// caller must set the corresponding header flags so the receiver knows
/// to read the same shape — and so that the header (= AEAD AAD) reflects
/// what was actually encrypted.
public enum FudpPayload {

    public static func assemble(
        includeTimestamp: Bool,
        timestamp: Int64,
        includeEpoch: Bool,
        sessionEpoch: Int64,
        frameBytes: [Data]
    ) -> Data {
        var out = Data()
        if includeTimestamp {
            var ts = UInt64(bitPattern: timestamp).bigEndian
            out.append(Data(bytes: &ts, count: 8))
        }
        if includeEpoch {
            var ep = UInt64(bitPattern: sessionEpoch).bigEndian
            out.append(Data(bytes: &ep, count: 8))
        }
        for frame in frameBytes {
            out.append(frame)
        }
        return out
    }
}
