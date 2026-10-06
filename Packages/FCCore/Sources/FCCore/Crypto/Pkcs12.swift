import Foundation
import CryptoKit
import CommonCrypto

/// A PKCS#12 (RFC 7292) *writer* for one private key and its
/// certificate — the modern profile that Java 17+ `KeyStore`, OpenSSL 3
/// and `apksigner` all read:
///
///   - key bag: PBES2 = PBKDF2-HMAC-SHA256 + AES-256-CBC (RFC 8018),
///   - cert bag: in the clear, as a certificate is public anyway,
///   - integrity: HMAC-SHA256 keyed by the RFC 7292 Appendix B KDF.
///
/// Both bags carry the same `localKeyId`, which is how Java pairs a key
/// with its chain, and the alias as `friendlyName`.
enum Pkcs12 {

    /// One count for both KDFs. They must match: the MAC is checked
    /// with the same password, so the cheaper of the two is the one an
    /// attacker would grind.
    static let iterations = 100_000

    enum Failure: Error, CustomStringConvertible {
        case kdf(Int32)
        case cipher(Int32)

        var description: String {
            switch self {
            case let .kdf(status): return "Pkcs12: PBKDF2 failed (\(status))"
            case let .cipher(status): return "Pkcs12: AES-CBC failed (\(status))"
            }
        }
    }

    static func build(
        privateKeyPkcs8: Data,
        certificate: Data,
        alias: String,
        password: String
    ) throws -> Data {
        let attributes = Der.set([
            Der.sequence([Der.oid("1.2.840.113549.1.9.20"), Der.set([Der.bmpString(alias)])]),  // friendlyName
            Der.sequence([
                Der.oid("1.2.840.113549.1.9.21"),  // localKeyId
                Der.set([Der.octetString(Data(SHA256.hash(data: certificate)))]),
            ]),
        ])

        // pkcs8ShroudedKeyBag
        let salt = random(16)
        let iv = random(16)
        let aesKey = try pbkdf2(password: Data(password.utf8), salt: salt, length: 32)
        let encrypted = try aes256Cbc(privateKeyPkcs8, key: aesKey, iv: iv)
        let pbes2 = Der.algorithm("1.2.840.113549.1.5.13", Der.sequence([
            Der.algorithm("1.2.840.113549.1.5.12", Der.sequence([   // PBKDF2
                Der.octetString(salt),
                Der.integer(iterations),
                Der.algorithm("1.2.840.113549.2.9", Der.null),       // hmacWithSHA256
            ])),
            Der.algorithm("2.16.840.1.101.3.4.1.42", Der.octetString(iv)),  // aes256-CBC
        ]))
        let keyBag = Der.sequence([
            Der.oid("1.2.840.113549.1.12.10.1.2"),
            Der.explicit(0, Der.sequence([pbes2, Der.octetString(encrypted)])),
            attributes,
        ])

        // certBag
        let certBag = Der.sequence([
            Der.oid("1.2.840.113549.1.12.10.1.3"),
            Der.explicit(0, Der.sequence([
                Der.oid("1.2.840.113549.1.9.22.1"),  // x509Certificate
                Der.explicit(0, Der.octetString(certificate)),
            ])),
            attributes,
        ])

        func dataContent(_ bytes: Data) -> Data {
            Der.sequence([Der.oid("1.2.840.113549.1.7.1"), Der.explicit(0, Der.octetString(bytes))])
        }
        let authenticatedSafe = Der.sequence([
            dataContent(Der.sequence([keyBag])),
            dataContent(Der.sequence([certBag])),
        ])

        let macSalt = random(16)
        let macKey = macKdf(password: password, salt: macSalt)
        let mac = Data(HMAC<SHA256>.authenticationCode(
            for: authenticatedSafe, using: SymmetricKey(data: macKey)
        ))
        let macData = Der.sequence([
            Der.sequence([Der.algorithm("2.16.840.1.101.3.4.2.1", Der.null), Der.octetString(mac)]),
            Der.octetString(macSalt),
            Der.integer(iterations),
        ])

        return Der.sequence([Der.integer(3), dataContent(authenticatedSafe), macData])
    }

    // MARK: - RFC 7292 Appendix B, ID 3 (MAC key), SHA-256

    /// The legacy PKCS#12 KDF. Only one output block (32 bytes) is ever
    /// needed for an HMAC-SHA256 key, so the I-update step of B.2 #6C,
    /// which only feeds later blocks, is not implemented.
    static func macKdf(password: String, salt: Data) -> Data {
        let v = 64
        func stretch(_ d: Data) -> Data {
            guard !d.isEmpty else { return Data() }
            let length = v * ((d.count + v - 1) / v)
            return Data((0 ..< length).map { d[d.startIndex + $0 % d.count] })
        }
        // BMPString, big-endian, with the two-byte terminator.
        var p = Data()
        for unit in password.utf16 { p.append(UInt8(unit >> 8)); p.append(UInt8(unit & 0xff)) }
        p.append(contentsOf: [0, 0])

        var a = Data(repeating: 3, count: v) + stretch(salt) + stretch(p)
        for _ in 0 ..< iterations { a = Data(SHA256.hash(data: a)) }
        return a
    }

    // MARK: - CommonCrypto

    private static func pbkdf2(password: Data, salt: Data, length: Int) throws -> Data {
        var out = Data(count: length)
        let status = out.withUnsafeMutableBytes { outPtr in
            password.withUnsafeBytes { pw in
                salt.withUnsafeBytes { s in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pw.baseAddress?.assumingMemoryBound(to: CChar.self), password.count,
                        s.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                        outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), length
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw Failure.kdf(status) }
        return out
    }

    private static func aes256Cbc(_ plain: Data, key: Data, iv: Data) throws -> Data {
        var out = Data(count: plain.count + kCCBlockSizeAES128)
        var moved = 0
        let capacity = out.count
        let status = out.withUnsafeMutableBytes { o in
            plain.withUnsafeBytes { p in
                key.withUnsafeBytes { k in
                    iv.withUnsafeBytes { i in
                        CCCrypt(
                            CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            k.baseAddress, key.count, i.baseAddress,
                            p.baseAddress, plain.count,
                            o.baseAddress, capacity, &moved
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw Failure.cipher(status) }
        return out.prefix(moved)
    }

    private static func random(_ count: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0 ..< count).map { _ in UInt8.random(in: .min ... .max, using: &g) })
    }
}
