import Foundation
import CryptoKit
import BigInt

/// The Android app-signing identity belonging to an FCH main FID: a
/// NIST P-256 keypair derived one-way from the main prikey, and a
/// self-signed certificate over it that comes out byte-identical every
/// time.
///
/// **Why a derived key and not the FID key itself.** Android verifies
/// APK signatures with RSA, DSA, or EC on the NIST curves only; a
/// secp256k1 signature never verifies on a device. So, as with
/// ``SshEd25519Key``, the FID key seeds one instead. P-256 is the
/// strongest of the three that every Android version since minSdk 28
/// verifies, and the cheapest to make deterministic.
///
/// **Why the certificate has to be deterministic too.** Android pins an
/// app's identity to its signing *certificate*, byte for byte — not to
/// the public key inside it. A fresh certificate over the same key,
/// with a different serial, date or signature, is a different signer
/// and every installed copy refuses the update. So every field is
/// fixed or derived, and the self-signature uses RFC 6979 deterministic
/// ECDSA rather than CryptoKit's randomised one. The result: restoring
/// the same main FID on any Mac rebuilds the exact certificate, and
/// there is no keystore to back up or lose.
///
/// **Bound to the FID, not just the key**, exactly as ``SshEd25519Key``
/// is: `mainFid` is the HKDF `info`, and it is also the certificate's
/// CN. Change the main identity and the app's signer changes with it.
public struct ApkSigningKey {

    /// Bump the trailing version only together with an APK key
    /// rotation — every app ever signed with this key is pinned to the
    /// certificate it produces, so this string is effectively frozen.
    public static let derivationSalt = "fc.freer.apk.p256.v1"

    /// The default keystore alias, and the PKCS#12 `friendlyName`.
    public static let defaultAlias = "freer"

    public enum Failure: Error, CustomStringConvertible {
        case badPrivkeyLength(Int)
        case emptyFid
        case emptyPassword
        case nonAsciiPassword

        public var description: String {
            switch self {
            case let .badPrivkeyLength(n):
                return "ApkSigningKey: expected a 32-byte prikey, got \(n)"
            case .emptyFid:
                return "ApkSigningKey: the main FID is empty"
            case .emptyPassword:
                return "ApkSigningKey: a keystore needs a password — Gradle will not open one without"
            case .nonAsciiPassword:
                return "ApkSigningKey: the keystore password must be plain ASCII — Java refuses to open a PKCS#12 with any other"
            }
        }
    }

    // MARK: - Frozen certificate fields
    //
    // Part of the derivation as much as the salt is: change any of them
    // and the certificate, and so the app's signer, changes.

    /// UTCTime. Any fixed date works; this one predates every release.
    static let notBefore = "250101000000Z"
    /// RFC 5280 §4.1.2.5's "no well-defined expiration date". Google
    /// Play asks for validity past 2033, and Android never checks it.
    static let notAfter = "99991231235959Z"
    public static let organizationName = "Freer"

    /// The P-256 group order.
    static let order = BigUInt(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", radix: 16
    )!

    private let key: P256.Signing.PrivateKey

    /// The FID this key belongs to — also the certificate's CN.
    public let mainFid: String

    /// The X.509 certificate, DER.
    public let certificate: Data

    /// - Parameters:
    ///   - mainPrikey: the 32-byte secp256k1 scalar from
    ///     `ActiveSession.mainPrikey()`. Not retained.
    ///   - mainFid: the FID that key belongs to.
    public init(mainPrikey: Data, mainFid: String) throws {
        guard mainPrikey.count == 32 else { throw Failure.badPrivkeyLength(mainPrikey.count) }
        guard !mainFid.isEmpty else { throw Failure.emptyFid }

        // 48 bytes reduced into [1, n-1] (FIPS 186-5 A.2.1): no rejection
        // loop, and a bias of about 2^-128.
        var okm = Hkdf.sha256(
            ikm: mainPrikey,
            salt: Data(Self.derivationSalt.utf8),
            info: Data(mainFid.utf8),
            outputLength: 48
        )
        defer { okm.resetBytes(in: 0 ..< okm.count) }
        var scalar = Self.to32(BigUInt(okm) % (Self.order - 1) + 1)
        defer { scalar.resetBytes(in: 0 ..< scalar.count) }

        let key = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        self.key = key
        self.mainFid = mainFid
        self.certificate = try Self.selfSignedCertificate(key: key, scalar: scalar, cn: mainFid)
    }

    // MARK: - Public parts

    /// The SubjectPublicKeyInfo, DER.
    public var publicKeyDer: Data { key.publicKey.derRepresentation }

    /// SHA-256 of the certificate — what `apksigner verify
    /// --print-certs`, `keytool -list` and the Play Console all show as
    /// the signer's digest.
    public var certificateSha256: Data { Data(SHA256.hash(data: certificate)) }

    /// `AB:CD:…`, the way `keytool` prints it.
    public var fingerprint: String {
        certificateSha256.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    public var certificatePem: String { Self.pem(certificate, label: "CERTIFICATE") }

    // MARK: - Private parts

    /// The private key as unencrypted PKCS#8 DER — the `--key` that
    /// `apksigner sign` takes alongside `--cert`.
    public var pkcs8: Data { key.derRepresentation }

    /// A PKCS#12 keystore holding the key and the certificate, ready for
    /// a Gradle `signingConfig` (`storeType` is inferred from the
    /// `.p12` extension) or `apksigner --ks`.
    ///
    /// The store and key share one password, because PKCS#12 as Java
    /// writes it has only one. The salts are random, so the file differs
    /// each export; the certificate inside never does.
    ///
    /// The password must be printable ASCII: Java's PKCS#12 loader
    /// throws "Password is not ASCII" on anything else, after which
    /// Gradle reports only a failed integrity check.
    public func keystore(password: String, alias: String = defaultAlias) throws -> Data {
        guard !password.isEmpty else { throw Failure.emptyPassword }
        guard Self.isKeystorePassword(password) else { throw Failure.nonAsciiPassword }
        return try Pkcs12.build(
            privateKeyPkcs8: pkcs8,
            certificate: certificate,
            alias: alias,
            password: password
        )
    }

    /// Printable ASCII, space through tilde.
    public static func isKeystorePassword(_ password: String) -> Bool {
        password.unicodeScalars.allSatisfy { (0x20 ... 0x7e).contains($0.value) }
    }

    // MARK: - Certificate

    private static func name(cn: String) -> Data {
        func rdn(_ oid: String, _ value: String) -> Data {
            Der.set([Der.sequence([Der.oid(oid), Der.utf8String(value)])])
        }
        return Der.sequence([
            rdn("2.5.4.10", organizationName),  // O
            rdn("2.5.4.3", cn),             // CN
        ])
    }

    private static func selfSignedCertificate(
        key: P256.Signing.PrivateKey, scalar: Data, cn: String
    ) throws -> Data {
        let spki = key.publicKey.derRepresentation
        let ecdsaWithSha256 = Der.algorithm("1.2.840.10045.4.3.2")

        // A positive 16-byte serial from the key itself, so it is fixed
        // without being a constant every derived certificate shares.
        var serial = Data(SHA256.hash(data: spki).prefix(16))
        serial[0] = (serial[0] & 0x7f) | 0x40

        // v1: no extensions, so the version field is omitted (RFC 5280
        // §4.1.2.1). apksigner and the platform never look for any.
        let subject = name(cn: cn)
        let tbs = Der.sequence([
            Der.unsignedInteger(serial),
            ecdsaWithSha256,
            subject,
            Der.sequence([Der.utcTime(notBefore), Der.generalizedTime(notAfter)]),
            subject,
            spki,
        ])

        let (r, s) = try rfc6979Sign(digest: Data(SHA256.hash(data: tbs)), scalar: scalar)
        let signature = Der.sequence([Der.unsignedInteger(r), Der.unsignedInteger(s)])

        // A wrong signature here would only surface as a cryptic install
        // failure on a phone, so check it while it is still a Swift error.
        let check = try P256.Signing.ECDSASignature(derRepresentation: signature)
        guard key.publicKey.isValidSignature(check, for: SHA256.hash(data: tbs)) else {
            throw CryptoKitError.authenticationFailure
        }

        return Der.sequence([tbs, ecdsaWithSha256, Der.bitString(signature)])
    }

    // MARK: - RFC 6979 ECDSA over P-256 / SHA-256

    /// Deterministic ECDSA (RFC 6979 §3.2) with HMAC-SHA256. Returns
    /// `(r, s)` as 32-byte big-endian values, s not normalised — the
    /// RFC's own vectors aren't, and nothing verifying an X.509
    /// signature cares.
    ///
    /// The point multiply is CryptoKit's: `k·G` is just the public key
    /// of the scalar `k`. Only the scalar arithmetic is done here.
    static func rfc6979Sign(digest: Data, scalar: Data) throws -> (r: Data, s: Data) {
        let n = order
        let d = BigUInt(scalar)
        let e = BigUInt(digest) % n          // bits2int, then bits2octets
        let x = to32(d)
        let h = to32(e)

        var v = Data(repeating: 0x01, count: 32)
        var k = Data(repeating: 0x00, count: 32)
        func mac(_ key: Data, _ parts: Data...) -> Data {
            var hmac = HMAC<SHA256>(key: SymmetricKey(data: key))
            for p in parts { hmac.update(data: p) }
            return Data(hmac.finalize())
        }
        k = mac(k, v, Data([0x00]), x, h); v = mac(k, v)
        k = mac(k, v, Data([0x01]), x, h); v = mac(k, v)

        while true {
            v = mac(k, v)
            let candidate = BigUInt(v)
            if candidate >= 1, candidate < n {
                let point = try P256.Signing.PrivateKey(rawRepresentation: to32(candidate))
                    .publicKey.rawRepresentation   // X ‖ Y
                let r = BigUInt(point.prefix(32)) % n
                if r != 0, let kInv = candidate.inverse(n) {
                    let s = (kInv * ((e + r * d) % n)) % n
                    if s != 0 { return (to32(r), to32(s)) }
                }
            }
            k = mac(k, v, Data([0x00])); v = mac(k, v)
        }
    }

    // MARK: - Helpers

    static func to32(_ value: BigUInt) -> Data {
        let raw = value.serialize()
        return Data(repeating: 0, count: max(0, 32 - raw.count)) + raw.suffix(32)
    }

    static func pem(_ der: Data, label: String) -> String {
        let b64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN \(label)-----\n\(b64)\n-----END \(label)-----\n"
    }
}
