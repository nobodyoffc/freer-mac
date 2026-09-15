import XCTest
@testable import FCCore

final class Argon2Tests: XCTestCase {

    /// A cheap profile for structural tests — runs in ~1 ms instead of ~300 ms.
    /// Do NOT use outside tests; production code must use `.freer`.
    private static let quick = Argon2.Params(
        iterations: 1,
        memoryKiB: 32,
        parallelism: 1,
        outputLength: 32
    )

    func testFreerParamsProduces32BytesAndIsNotAllZero() throws {
        let out = try Argon2.hashID(
            password: Data("password".utf8),
            salt: Data("01234567".utf8)
        )
        XCTAssertEqual(out.count, 32)
        XCTAssertFalse(out.allSatisfy { $0 == 0 })
    }

    func testDeterministic() throws {
        let pwd = Data("hunter2".utf8)
        let salt = Data("01234567".utf8)
        let first = try Argon2.hashID(password: pwd, salt: salt, params: Self.quick)
        let second = try Argon2.hashID(password: pwd, salt: salt, params: Self.quick)
        XCTAssertEqual(first, second)
    }

    func testDifferentPasswordsDiffer() throws {
        let salt = Data("01234567".utf8)
        let alpha = try Argon2.hashID(password: Data("password1".utf8), salt: salt, params: Self.quick)
        let beta = try Argon2.hashID(password: Data("password2".utf8), salt: salt, params: Self.quick)
        XCTAssertNotEqual(alpha, beta)
    }

    func testDifferentSaltsDiffer() throws {
        let pwd = Data("password".utf8)
        let alpha = try Argon2.hashID(password: pwd, salt: Data("saltAAAA".utf8), params: Self.quick)
        let beta = try Argon2.hashID(password: pwd, salt: Data("saltBBBB".utf8), params: Self.quick)
        XCTAssertNotEqual(alpha, beta)
    }

    /// FTSP28 derives phrase keys over an empty salt, so the vendored library's
    /// 8-byte minimum is relaxed (see CArgon2/UPSTREAM.md). An empty salt must
    /// work and match BouncyCastle, which FC-JDK and the Android wallets use.
    func testAcceptsEmptySaltLikeBouncyCastle() throws {
        let key = try Argon2.hashID(password: Data("Hello world!".utf8), salt: Data())
        XCTAssertEqual(key.hex, "3107f02758ff375bfed40885d7e7a24239e4a3bf55caa9cbea7ffeddfd7ddbf6")
    }

    func testCustomOutputLength() throws {
        let params = Argon2.Params(iterations: 1, memoryKiB: 32, parallelism: 1, outputLength: 64)
        let out = try Argon2.hashID(
            password: Data("password".utf8),
            salt: Data("01234567".utf8),
            params: params
        )
        XCTAssertEqual(out.count, 64)
    }

    /// Golden-vector parity against freecashj + BouncyCastle's Argon2BytesGenerator.
    /// Every Swift output must match the Java-produced hex byte-for-byte.
    func testMatchesFreecashjVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.argon2id.isEmpty, "no Argon2id vectors in testVectors.json")
        for vector in vectors.argon2id {
            let params = Argon2.Params(
                iterations: vector.iterations,
                memoryKiB: vector.memoryKib,
                parallelism: vector.parallelism,
                outputLength: vector.outputLength
            )
            let out = try Argon2.hashID(
                password: Data(fromHex: vector.passwordHex),
                salt: Data(fromHex: vector.saltHex),
                params: params
            )
            XCTAssertEqual(out.hex, vector.outputHex, "Argon2 case '\(vector.label)'")
        }
    }
}
