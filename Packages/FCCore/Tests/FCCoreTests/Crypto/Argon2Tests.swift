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

    func testRejectsShortSalt() {
        XCTAssertThrowsError(
            try Argon2.hashID(
                password: Data("password".utf8),
                salt: Data([0x00]),
                params: Self.quick
            )
        ) { error in
            guard case Argon2.Failure.argon2(_, _) = error else {
                XCTFail("Expected Argon2.Failure.argon2, got \(error)")
                return
            }
        }
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
}
