import XCTest
@testable import FCCore

/// Tests for the Phase 8 tool primitives: Base32, TOTP, the extra hash
/// functions, and Bitcoin-style signed messages.
///
/// Keccak-256 and SignedMessage expectations were generated against the
/// Java reference (BouncyCastle 1.77 `Keccak.Digest256`, freecashj v0.16
/// `ECKey.signMessage`) via jshell; the rest are RFC vectors.
final class ToolPrimitivesTests: XCTestCase {

    // MARK: - Base32 (RFC 4648, unpadded)

    func testBase32Rfc4648Vectors() throws {
        let vectors: [(String, String)] = [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ]
        for (plain, encoded) in vectors {
            XCTAssertEqual(Base32.encode(Data(plain.utf8)), encoded)
            XCTAssertEqual(try Base32.decode(encoded), Data(plain.utf8))
        }
    }

    func testBase32DecodeIsCaseInsensitive() throws {
        XCTAssertEqual(try Base32.decode("mzxw6ytboi"), Data("foobar".utf8))
    }

    func testBase32RejectsInvalidCharacters() {
        XCTAssertThrowsError(try Base32.decode("MZXW1"))  // '1' not in alphabet
        XCTAssertThrowsError(try Base32.decode("MZ=XW"))  // padding unsupported
    }

    func testBase32RoundTripsBinary() throws {
        let data = Data((0..<64).map { UInt8($0 * 4 % 256) })
        XCTAssertEqual(try Base32.decode(Base32.encode(data)), data)
    }

    // MARK: - TOTP (RFC 6238, SHA-1 rows)

    func testTotpRfc6238Vectors() {
        let secret = Data("12345678901234567890".utf8)
        let vectors: [(Int64, String)] = [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ]
        for (time, expected) in vectors {
            XCTAssertEqual(Totp.generate(secret: secret, unixTime: time, digits: 8), expected)
        }
    }

    func testTotpSixDigitsTruncates() {
        let secret = Data("12345678901234567890".utf8)
        // 6-digit code is the last 6 digits of the 8-digit RFC output.
        XCTAssertEqual(Totp.generate(secret: secret, unixTime: 59, digits: 6), "287082")
    }

    func testTotpSecondsRemaining() {
        XCTAssertEqual(Totp.secondsRemaining(unixTime: 0), 30)
        XCTAssertEqual(Totp.secondsRemaining(unixTime: 29), 1)
        XCTAssertEqual(Totp.secondsRemaining(unixTime: 30), 30)
    }

    // MARK: - Hashes

    func testMd5Sha1KnownVectors() {
        XCTAssertEqual(
            Hash.md5(Data("abc".utf8)).hex,
            "900150983cd24fb0d6963f7d28e17f72"
        )
        XCTAssertEqual(
            Hash.sha1(Data("abc".utf8)).hex,
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        )
    }

    func testHmacSha256Rfc4231Vector() {
        // RFC 4231 test case 1.
        let key = Data(repeating: 0x0b, count: 20)
        XCTAssertEqual(
            Hash.hmacSha256(Data("Hi There".utf8), key: key).hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
    }

    func testHmacSha1Rfc2202Vector() {
        let key = Data(repeating: 0x0b, count: 20)
        XCTAssertEqual(
            Hash.hmacSha1(Data("Hi There".utf8), key: key).hex,
            "b617318655057264e28bc0b6fb378c8ef146be00"
        )
    }

    func testKeccak256MatchesBouncyCastle() {
        XCTAssertEqual(
            Hash.keccak256(Data()).hex,
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        )
        XCTAssertEqual(
            Hash.keccak256(Data("abc".utf8)).hex,
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        )
        XCTAssertEqual(
            Hash.keccak256(Data("The quick brown fox jumps over the lazy dog".utf8)).hex,
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
        )
        // 200 bytes — crosses the 136-byte rate boundary (multi-block absorb).
        let big = Data((0..<200).map { UInt8($0 & 0xFF) })
        XCTAssertEqual(
            Hash.keccak256(big).hex,
            "bfb0aa97863e797943cf7c33bb7e880bb4543f3d2703c0923c6901c2af57b890"
        )
    }

    // MARK: - SignedMessage (freecashj ECKey.signMessage parity)

    private let privkey1 = Data(fromHex: "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725")
    private let pubkey1 = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    private let javaSig1 = "IMs2aXAV/uP0LV7+r7wGvXvE63FLKDQCTzMR7skCa8V2BylSaQF2ep3l8KUT++OlqOBi3iiPJb5pEiwxEbT0uoY="

    private let privkey2 = Data(fromHex: "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4")
    private let pubkey2 = "030947751e3022ecf3016be03ec77ab0ce3c2662b4843898cb068d74f698ccc8ad"
    private let javaSig2 = "HxL+98eqH7FB9O0XLidoce0vqI138U8OBjQU0PP8bng5ABII77bSW+scROGDdbEbboiCMq+sVmq0b/E8RLlILHY="

    func testRecoversPubkeyFromJavaSignature() throws {
        // Signatures produced by freecashj must recover to the signing key
        // here — this is the cross-implementation parity anchor.
        let recovered1 = try SignedMessage.recoverPublicKey(
            message: "hello freer", signatureBase64: javaSig1
        )
        XCTAssertEqual(recovered1.hex, pubkey1)

        let recovered2 = try SignedMessage.recoverPublicKey(
            message: "The quick brown fox jumps over the lazy dog", signatureBase64: javaSig2
        )
        XCTAssertEqual(recovered2.hex, pubkey2)
    }

    func testSignMatchesJavaByteForByte() throws {
        // RFC 6979 nonces: libsecp256k1 and BouncyCastle both implement the
        // spec; for message signing they agree (unlike the HMAC-DRBG
        // corner freecashj's tx signing hits), so the Base64 matches.
        XCTAssertEqual(
            try SignedMessage.sign(message: "hello freer", privateKey: privkey1),
            javaSig1
        )
        XCTAssertEqual(
            try SignedMessage.sign(
                message: "The quick brown fox jumps over the lazy dog",
                privateKey: privkey2
            ),
            javaSig2
        )
    }

    func testSignVerifyRoundTrip() throws {
        let message = "多字节 UTF-8 メッセージ round trip"
        let signature = try SignedMessage.sign(message: message, privateKey: privkey1)
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey1)
        let fid = try FchAddress(publicKey: pubkey).fid

        XCTAssertTrue(SignedMessage.verify(message: message, signatureBase64: signature, fid: fid))
        XCTAssertFalse(SignedMessage.verify(message: message + "!", signatureBase64: signature, fid: fid))

        let otherFid = try FchAddress(
            publicKey: Secp256k1.publicKey(fromPrivateKey: privkey2)
        ).fid
        XCTAssertFalse(SignedMessage.verify(message: message, signatureBase64: signature, fid: otherFid))
    }

    func testVerifyRejectsGarbage() {
        XCTAssertFalse(SignedMessage.verify(message: "x", signatureBase64: "not base64!", fid: "F"))
        XCTAssertFalse(SignedMessage.verify(
            message: "x",
            signatureBase64: Data(repeating: 7, count: 65).base64EncodedString(),
            fid: "F"
        ))
    }
}
