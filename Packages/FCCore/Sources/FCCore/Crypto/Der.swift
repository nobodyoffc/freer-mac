import Foundation

/// A minimal DER *writer* — just the handful of ASN.1 types that an
/// X.509 certificate, a PKCS#8 wrapper and a PKCS#12 keystore are built
/// from. There is no reader: everything this app parses in ASN.1 comes
/// through CryptoKit or Security, and the output here is checked by
/// `keytool`, `openssl` and `apksigner` in the tests' provenance notes.
///
/// Each function returns one complete TLV, so structures compose as
/// plain nested calls: `Der.sequence([Der.oid("…"), Der.null])`.
enum Der {

    // MARK: - Framing

    static func tlv(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        out.append(length(content.count))
        out.append(content)
        return out
    }

    /// Short form below 128, long form (minimal byte count) above.
    static func length(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    // MARK: - Constructed

    static func sequence(_ items: [Data]) -> Data { tlv(0x30, items.reduce(Data(), +)) }

    /// A SET OF. DER requires the elements sorted by their encodings;
    /// every set this file writes has at most two elements of different
    /// types, but sorting keeps that true by construction.
    static func set(_ items: [Data]) -> Data {
        let sorted = items.sorted { $0.lexicographicallyPrecedes($1) }
        return tlv(0x31, sorted.reduce(Data(), +))
    }

    /// `[n] EXPLICIT` — a constructed context-specific wrapper.
    static func explicit(_ n: UInt8, _ inner: Data) -> Data { tlv(0xa0 | n, inner) }

    // MARK: - Primitive

    static let null = Data([0x05, 0x00])

    static func octetString(_ data: Data) -> Data { tlv(0x04, data) }

    /// A BIT STRING with no unused bits.
    static func bitString(_ data: Data) -> Data { tlv(0x03, Data([0x00]) + data) }

    static func utf8String(_ s: String) -> Data { tlv(0x0c, Data(s.utf8)) }

    /// BMPString: big-endian UTF-16, as PKCS#12 `friendlyName` wants.
    static func bmpString(_ s: String) -> Data {
        var out = Data()
        for unit in s.utf16 { out.append(UInt8(unit >> 8)); out.append(UInt8(unit & 0xff)) }
        return tlv(0x1e, out)
    }

    static func utcTime(_ s: String) -> Data { tlv(0x17, Data(s.utf8)) }
    static func generalizedTime(_ s: String) -> Data { tlv(0x18, Data(s.utf8)) }

    static func integer(_ value: Int) -> Data {
        precondition(value >= 0, "Der.integer: negative values are never written")
        var bytes: [UInt8] = []
        var v = value
        repeat { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 } while v > 0
        return unsignedInteger(Data(bytes))
    }

    /// A non-negative INTEGER from big-endian magnitude bytes: leading
    /// zeros stripped, one 0x00 put back if the top bit would read as a
    /// sign.
    static func unsignedInteger(_ magnitude: Data) -> Data {
        var bytes = Array(magnitude.drop { $0 == 0 })
        if bytes.isEmpty { bytes = [0] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        return tlv(0x02, Data(bytes))
    }

    /// An OBJECT IDENTIFIER from its dotted form.
    static func oid(_ dotted: String) -> Data {
        let arcs = dotted.split(separator: ".").map { UInt64($0)! }
        precondition(arcs.count >= 2, "Der.oid: \(dotted) has fewer than two arcs")
        var out = Data()
        out.append(contentsOf: base128(arcs[0] * 40 + arcs[1]))
        for arc in arcs.dropFirst(2) { out.append(contentsOf: base128(arc)) }
        return tlv(0x06, out)
    }

    private static func base128(_ value: UInt64) -> [UInt8] {
        var bytes = [UInt8(value & 0x7f)]
        var v = value >> 7
        while v > 0 { bytes.insert(UInt8(v & 0x7f) | 0x80, at: 0); v >>= 7 }
        return bytes
    }

    /// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`
    static func algorithm(_ oid: String, _ parameters: Data? = nil) -> Data {
        sequence([Der.oid(oid)] + (parameters.map { [$0] } ?? []))
    }
}
