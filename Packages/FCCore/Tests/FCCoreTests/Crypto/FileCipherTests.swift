import XCTest
@testable import FCCore

/// Parity tests for the FAPI DISK cipher-file format.
///
/// The golden vectors are produced by the REAL FC-AJDK
/// `Encryptor`/`Decryptor` (see `tools/vector-gen/FileCipherRef.java`),
/// not by a re-implementation, so these assertions check the Swift port
/// against the code the Android app actually runs.
final class FileCipherTests: XCTestCase {

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("filecipher-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    // MARK: - byte parity with FC-AJDK

    func testEncryptMatchesJavaCipherFileByteForByte() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.diskCipherFile.isEmpty)

        for v in vectors.diskCipherFile {
            let dir = try tempDir()
            let plain = dir.appendingPathComponent("plain.bin")
            let cipher = dir.appendingPathComponent("cipher.bin")
            try Data(fromHex: v.plaintextHex).write(to: plain)

            try FileCipher.encrypt(
                plaintextAt: plain,
                to: cipher,
                symkey: Data(fromHex: v.symkeyHex),
                iv: Data(fromHex: v.ivHex)
            )

            let produced = try Data(contentsOf: cipher)
            XCTAssertEqual(produced.hex, v.cipherFileHex,
                           "cipher file bytes for '\(v.label)'")
        }
    }

    func testDecryptsJavaProducedCipherFiles() throws {
        let vectors = try TestVectors.load()
        for v in vectors.diskCipherFile {
            let dir = try tempDir()
            let cipher = dir.appendingPathComponent("cipher.bin")
            let out = dir.appendingPathComponent("out.bin")
            try Data(fromHex: v.cipherFileHex).write(to: cipher)

            let header = try FileCipher.decrypt(
                cipherAt: cipher, to: out, symkey: Data(fromHex: v.symkeyHex))

            XCTAssertEqual(header.iv.hex, v.ivHex, "iv for '\(v.label)'")
            XCTAssertEqual(header.byteLength, v.headerLength, "header length for '\(v.label)'")
            XCTAssertEqual(try Data(contentsOf: out).hex, v.plaintextHex,
                           "recovered plaintext for '\(v.label)'")
        }
    }

    func testHeaderParsingMatchesVectors() throws {
        let vectors = try TestVectors.load()
        for v in vectors.diskCipherFile {
            let file = Data(fromHex: v.cipherFileHex)
            let header = try FileCipher.parseHeader(file)

            XCTAssertEqual(header.type, "Symkey", "type for '\(v.label)'")
            XCTAssertEqual(header.alg, "AesGcm256@No1_NrC7", "alg for '\(v.label)'")
            XCTAssertEqual(header.byteLength, v.headerLength, "header length for '\(v.label)'")

            let headerText = String(data: file.prefix(header.byteLength), encoding: .utf8)
            XCTAssertEqual(headerText, v.headerJson, "header text for '\(v.label)'")
        }
    }

    /// The header we generate must be byte-identical to Gson's output
    /// (field order, no spaces), or a Swift-written file would not be
    /// readable at the same offsets on the Java side.
    func testHeaderJsonMatchesGsonOutput() throws {
        let vectors = try TestVectors.load()
        for v in vectors.diskCipherFile {
            let produced = FileCipher.headerJson(iv: Data(fromHex: v.ivHex))
            XCTAssertEqual(String(data: produced, encoding: .utf8), v.headerJson,
                           "header JSON for '\(v.label)'")
        }
    }

    /// Body is exactly ciphertext ‖ 16-byte tag, with ciphertext the
    /// same length as the plaintext (GCM is a stream cipher — no padding).
    func testBodyIsCiphertextPlusTag() throws {
        let vectors = try TestVectors.load()
        for v in vectors.diskCipherFile {
            let plaintextLen = v.plaintextHex.count / 2
            let bodyLen = v.bodyHex.count / 2
            XCTAssertEqual(bodyLen, plaintextLen + FileCipher.tagLength,
                           "body length for '\(v.label)'")
        }
    }

    // MARK: - round-trip

    func testRoundTripWithRandomKeyAndIv() throws {
        let dir = try tempDir()
        let plain = dir.appendingPathComponent("plain.bin")
        let cipher = dir.appendingPathComponent("cipher.bin")
        let out = dir.appendingPathComponent("out.bin")

        // ~1 MB spanning many GCM blocks, plus a non-block-aligned tail.
        var content = Data(capacity: 1_000_003)
        var x: UInt8 = 7
        for _ in 0..<1_000_003 {
            content.append(x)
            x = x &* 31 &+ 17
        }
        try content.write(to: plain)

        let key = FileCipher.randomSymkey()
        let header = try FileCipher.encrypt(plaintextAt: plain, to: cipher, symkey: key)
        XCTAssertEqual(header.iv.count, FileCipher.ivLength)

        try FileCipher.decrypt(cipherAt: cipher, to: out, symkey: key)
        XCTAssertEqual(try Data(contentsOf: out), content)
    }

    func testEmptyFileRoundTrips() throws {
        let dir = try tempDir()
        let plain = dir.appendingPathComponent("empty.bin")
        let cipher = dir.appendingPathComponent("cipher.bin")
        let out = dir.appendingPathComponent("out.bin")
        try Data().write(to: plain)

        let key = FileCipher.randomSymkey()
        try FileCipher.encrypt(plaintextAt: plain, to: cipher, symkey: key)
        try FileCipher.decrypt(cipherAt: cipher, to: out, symkey: key)
        XCTAssertEqual(try Data(contentsOf: out).count, 0)
    }

    func testRandomIvsDiffer() {
        // A repeated (key, iv) pair breaks GCM outright, so the default
        // iv must never be constant.
        let ivs = (0..<32).map { _ in FileCipher.randomIv().hex }
        XCTAssertEqual(Set(ivs).count, ivs.count)
    }

    // MARK: - tamper detection and error paths

    func testTamperedCiphertextFailsAuthentication() throws {
        let vectors = try TestVectors.load()
        let v = try XCTUnwrap(vectors.diskCipherFile.first { $0.plaintextHex.count > 8 })
        let dir = try tempDir()
        let cipher = dir.appendingPathComponent("cipher.bin")
        let out = dir.appendingPathComponent("out.bin")

        var bytes = Data(fromHex: v.cipherFileHex)
        bytes[v.headerLength + 1] ^= 0x01     // flip one ciphertext bit
        try bytes.write(to: cipher)

        XCTAssertThrowsError(
            try FileCipher.decrypt(cipherAt: cipher, to: out, symkey: Data(fromHex: v.symkeyHex))
        ) { error in
            guard case FileCipher.Failure.authenticationFailed = error else {
                return XCTFail("expected authenticationFailed, got \(error)")
            }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: out.path),
                       "no output file may be left behind when authentication fails")
    }

    func testTamperedTagFailsAuthentication() throws {
        let vectors = try TestVectors.load()
        let v = try XCTUnwrap(vectors.diskCipherFile.first)
        let dir = try tempDir()
        let cipher = dir.appendingPathComponent("cipher.bin")
        let out = dir.appendingPathComponent("out.bin")

        var bytes = Data(fromHex: v.cipherFileHex)
        bytes[bytes.count - 1] ^= 0x80
        try bytes.write(to: cipher)

        XCTAssertThrowsError(
            try FileCipher.decrypt(cipherAt: cipher, to: out, symkey: Data(fromHex: v.symkeyHex)))
    }

    func testWrongKeyFails() throws {
        let vectors = try TestVectors.load()
        let v = try XCTUnwrap(vectors.diskCipherFile.first)
        let dir = try tempDir()
        let cipher = dir.appendingPathComponent("cipher.bin")
        let out = dir.appendingPathComponent("out.bin")
        try Data(fromHex: v.cipherFileHex).write(to: cipher)

        var wrongKey = Data(fromHex: v.symkeyHex)
        wrongKey[0] ^= 0xff
        XCTAssertThrowsError(try FileCipher.decrypt(cipherAt: cipher, to: out, symkey: wrongKey))
    }

    func testRejectsWrongKeyLength() throws {
        let dir = try tempDir()
        let plain = dir.appendingPathComponent("p.bin")
        try Data([1, 2, 3]).write(to: plain)
        XCTAssertThrowsError(
            try FileCipher.encrypt(plaintextAt: plain,
                                   to: dir.appendingPathComponent("c.bin"),
                                   symkey: Data(count: 16))
        ) { error in
            guard case FileCipher.Failure.invalidKeyLength = error else {
                return XCTFail("expected invalidKeyLength, got \(error)")
            }
        }
    }

    func testRejectsWrongIvLength() throws {
        let dir = try tempDir()
        let plain = dir.appendingPathComponent("p.bin")
        try Data([1, 2, 3]).write(to: plain)
        XCTAssertThrowsError(
            try FileCipher.encrypt(plaintextAt: plain,
                                   to: dir.appendingPathComponent("c.bin"),
                                   symkey: Data(count: 32),
                                   iv: Data(count: 16))
        ) { error in
            guard case FileCipher.Failure.invalidIvLength = error else {
                return XCTFail("expected invalidIvLength, got \(error)")
            }
        }
    }

    func testNonCipherFileIsRejected() throws {
        let dir = try tempDir()
        let notCipher = dir.appendingPathComponent("plain.txt")
        try Data("just some text, no json header".utf8).write(to: notCipher)

        XCTAssertThrowsError(
            try FileCipher.decrypt(cipherAt: notCipher,
                                   to: dir.appendingPathComponent("out.bin"),
                                   symkey: Data(count: 32))
        ) { error in
            guard case FileCipher.Failure.headerNotFound = error else {
                return XCTFail("expected headerNotFound, got \(error)")
            }
        }
    }

    func testTruncatedBodyIsRejected() throws {
        let vectors = try TestVectors.load()
        let v = try XCTUnwrap(vectors.diskCipherFile.first)
        let dir = try tempDir()
        let cipher = dir.appendingPathComponent("cipher.bin")
        // Header plus only 4 body bytes — shorter than the 16-byte tag.
        let bytes = Data(fromHex: v.cipherFileHex).prefix(v.headerLength + 4)
        try bytes.write(to: cipher)

        XCTAssertThrowsError(
            try FileCipher.decrypt(cipherAt: cipher,
                                   to: dir.appendingPathComponent("out.bin"),
                                   symkey: Data(fromHex: v.symkeyHex))
        ) { error in
            guard case FileCipher.Failure.bodyTooShort = error else {
                return XCTFail("expected bodyTooShort, got \(error)")
            }
        }
    }

    // MARK: - header scanner parity

    /// The Java reader stops at the first balanced brace pair and is not
    /// string-aware. We must behave identically, including on inputs
    /// that trip it — otherwise the two sides would disagree on where
    /// the ciphertext begins.
    ///
    /// Every expectation below was checked against the real
    /// `JsonUtils.readOneJsonFromInputStream` (same inputs, same
    /// results — including the two desync cases).
    func testHeaderLengthCountsBracesWithoutStringAwareness() throws {
        // Normal header: closes at the balanced pair, body follows.
        // Java: len=26.
        let file = Data(#"{"type":"Symkey","iv":"x"}BODY"#.utf8)
        XCTAssertEqual(try FileCipher.headerLength(of: file), 26)

        // A '}' inside a string closes the count early, yielding a
        // truncated "header". Java: len=7 ({"a":"} ). Reproduced, not
        // "fixed" — matching the producer is the whole point.
        let closeBraceInString = Data(#"{"a":"}"}tail"#.utf8)
        XCTAssertEqual(try FileCipher.headerLength(of: closeBraceInString), 7)

        // An unmatched '{' inside a string leaves the depth stuck above
        // zero, so no header is ever found. Java: null.
        let openBraceInString = Data(#"{"a":"{"}tail"#.utf8)
        XCTAssertThrowsError(try FileCipher.headerLength(of: openBraceInString))

        // Nested objects are counted by depth. Java: len=13.
        let nested = Data(#"{"a":{"b":1}}rest"#.utf8)
        XCTAssertEqual(try FileCipher.headerLength(of: nested), 13)
    }

    func testHeaderLengthThrowsWhenUnterminated() {
        // Java returns null here; we surface it as headerNotFound.
        let file = Data(#"{"type":"Symkey""#.utf8)
        XCTAssertThrowsError(try FileCipher.headerLength(of: file))
    }
}
