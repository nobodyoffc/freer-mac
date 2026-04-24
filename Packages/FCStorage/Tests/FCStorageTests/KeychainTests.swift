import XCTest
@testable import FCStorage

final class KeychainTests: XCTestCase {

    /// Each test gets its own service string so concurrent runs (and
    /// aborted earlier runs) don't collide. `tearDown` still wipes
    /// known accounts in case the test itself exited mid-write.
    private var testService = ""
    private let accounts = ["alpha", "beta", "gamma"]

    override func setUpWithError() throws {
        testService = "cash.freer.mac.test.\(UUID().uuidString)"
    }

    override func tearDownWithError() throws {
        for account in accounts {
            _ = try? Keychain.delete(service: testService, account: account)
        }
    }

    func testSetAndGetRoundTrip() throws {
        let value = Data("hello keychain".utf8)
        try Keychain.set(value, service: testService, account: "alpha")
        XCTAssertEqual(try Keychain.get(service: testService, account: "alpha"), value)
    }

    func testSetOverwritesExistingItem() throws {
        try Keychain.set(Data("first".utf8), service: testService, account: "alpha")
        try Keychain.set(Data("second".utf8), service: testService, account: "alpha")
        let read = try Keychain.get(service: testService, account: "alpha")
        XCTAssertEqual(String(data: read, encoding: .utf8), "second")
    }

    func testGetMissingItemThrows() {
        XCTAssertThrowsError(
            try Keychain.get(service: testService, account: "alpha")
        ) { error in
            guard case Keychain.Failure.itemNotFound = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testDeleteReturnsTrueWhenItemExisted() throws {
        try Keychain.set(Data([0x01]), service: testService, account: "alpha")
        XCTAssertTrue(try Keychain.delete(service: testService, account: "alpha"))
        XCTAssertFalse(try Keychain.exists(service: testService, account: "alpha"))
    }

    func testDeleteReturnsFalseWhenItemMissing() throws {
        XCTAssertFalse(try Keychain.delete(service: testService, account: "alpha"))
    }

    func testExistsReflectsReality() throws {
        XCTAssertFalse(try Keychain.exists(service: testService, account: "alpha"))
        try Keychain.set(Data([0x01]), service: testService, account: "alpha")
        XCTAssertTrue(try Keychain.exists(service: testService, account: "alpha"))
        try Keychain.delete(service: testService, account: "alpha")
        XCTAssertFalse(try Keychain.exists(service: testService, account: "alpha"))
    }

    /// Items in one `(service, account)` namespace must not leak into
    /// another — without this property, two identities would share keys.
    func testAccountIsolation() throws {
        try Keychain.set(Data("alpha-val".utf8), service: testService, account: "alpha")
        try Keychain.set(Data("beta-val".utf8), service: testService, account: "beta")
        XCTAssertEqual(
            String(data: try Keychain.get(service: testService, account: "alpha"), encoding: .utf8),
            "alpha-val"
        )
        XCTAssertEqual(
            String(data: try Keychain.get(service: testService, account: "beta"), encoding: .utf8),
            "beta-val"
        )
    }

    func testServiceIsolation() throws {
        let otherService = testService + ".other"
        try Keychain.set(Data("in-original".utf8), service: testService, account: "alpha")

        XCTAssertThrowsError(try Keychain.get(service: otherService, account: "alpha")) { error in
            guard case Keychain.Failure.itemNotFound = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
        // Defensive: make sure we didn't leave anything in otherService either
        _ = try? Keychain.delete(service: otherService, account: "alpha")
    }

    /// Stores a 32-byte value (the exact size of the AES-GCM vault key
    /// EncryptedKVStore will use) to confirm binary blob handling.
    func testHandles32ByteBinaryValue() throws {
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { bytes[i] = UInt8(i) }
        let value = Data(bytes)
        try Keychain.set(value, service: testService, account: "alpha")
        XCTAssertEqual(try Keychain.get(service: testService, account: "alpha"), value)
    }
}
