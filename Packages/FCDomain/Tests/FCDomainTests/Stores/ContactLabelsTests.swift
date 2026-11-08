import XCTest
import FCCore
import FCTransport
@testable import FCDomain

final class ContactLabelsTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var session: ActiveSession!

    private let alice = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private let bob = "FTqiqAyXHnK7uDTXzMap3acvqADK4ZGzts"

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ContactLabelsTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
        let configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    func testTheFirstTitleIsTheLabel() throws {
        try session.contacts.upsert(Contact(id: alice, cid: "alice_1234", titles: ["", "Accountant", "Friend"]))
        XCTAssertEqual(session.contacts.labels.label(for: alice), "Accountant")
        XCTAssertNil(session.contacts.labels.label(for: bob))
    }

    func testATitleThatOnlyRepeatsTheCidSaysNothing() throws {
        try session.contacts.upsert(Contact(id: alice, cid: "alice_1234", titles: ["alice_1234"]))
        XCTAssertNil(session.contacts.labels.label(for: alice))
    }

    /// Every copy of the store shares one table, and every write clears it.
    func testWritesThroughAnyCopyAreSeen() throws {
        let labels = session.contacts.labels
        XCTAssertNil(labels.label(for: alice))

        let copy = session.contacts
        try copy.upsert(Contact(id: alice, titles: ["Accountant"]))
        XCTAssertEqual(labels.label(for: alice), "Accountant")

        try copy.upsert(Contact(id: alice, titles: ["Lawyer"]))
        XCTAssertEqual(labels.label(for: alice), "Lawyer")

        _ = try copy.remove(fid: alice)
        XCTAssertNil(labels.label(for: alice))
    }

    func testAContactOnItsWayOutHasNoLabel() throws {
        var contact = Contact(id: alice, titles: ["Accountant"])
        contact.deletePendingTxid = "txid"
        try session.contacts.upsert(contact)
        XCTAssertNil(session.contacts.labels.label(for: alice))
    }

    func testParen() throws {
        try session.contacts.upsert(Contact(id: alice, titles: ["Accountant"]))
        XCTAssertEqual(session.contacts.labels.paren("alice_1234", for: alice), "alice_1234 (Accountant)")
        XCTAssertEqual(session.contacts.labels.paren("bob", for: bob), "bob")
    }
}
