import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// On-chain contact sync against a staged `base.search`: merge path
/// (carveId capture) and the deletion-cleanup path (newest carve
/// inactive → chain-sourced local row removed, local-only row kept).
final class ContactSyncTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ContactSyncTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession(fapi: any FapiCalling) throws -> ActiveSession {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("sync-tests".utf8), kdfKind: .legacySha256
        )
        let priv = Hash.sha256(Data("owner".utf8))
        let info = try configure.addMain(privkey: priv, label: "owner")
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func realFid(byte: UInt8) throws -> String {
        let priv = Data(repeating: byte, count: 32)
        return try FchAddress(publicKey: try Secp256k1.publicKey(fromPrivateKey: priv)).fid
    }

    /// Build one on-chain contact record dict whose cipher is a real
    /// AsyOneWay envelope encrypted to `ownerPriv`'s pubkey — the
    /// decrypt in `syncOnChainContacts` runs for real.
    private func record(
        id: String,
        contactFid: String,
        ownerFid: String,
        ownerPriv: Data,
        lastHeight: Int64,
        active: Bool,
        memo: String? = nil
    ) throws -> [String: Any] {
        var contact = Contact(id: contactFid)
        contact.memo = memo
        let detail = try ContactFeip.detailJson(for: contact)
        let ownerPub = try Secp256k1.publicKey(fromPrivateKey: ownerPriv)
        let cipher = try AsyOneWayCipher.encrypt(
            plaintext: Data(detail.utf8), toPubkey: ownerPub
        )
        return [
            "id": id,
            "cipher": cipher,
            "owner": ownerFid,
            "birthTime": 1_700_000_000,
            "lastHeight": lastHeight,
            "active": active
        ]
    }

    func testSyncMergesActiveAndRemovesDeleted() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let ownerPriv = try session.livePrikey()

        let aliveFid = try realFid(byte: 0xD1)     // newest carve active
        let deletedFid = try realFid(byte: 0xD2)   // newest carve inactive, row is chain-sourced
        let localOnlyFid = try realFid(byte: 0xD3) // inactive carve but row is local-only

        // Pre-seed: deletedFid came from a previous sync; localOnlyFid
        // was added by hand and must survive the on-chain delete.
        try session.contacts.upsert(Contact(id: deletedFid, onChain: true))
        try session.contacts.upsert(Contact(id: localOnlyFid, cid: nil, memo: "local note"))

        let records: [[String: Any]] = [
            // Sorted lastHeight desc, as the server would return.
            try record(id: "carve-3", contactFid: localOnlyFid, ownerFid: session.liveFid,
                       ownerPriv: ownerPriv, lastHeight: 300, active: false),
            try record(id: "carve-2", contactFid: deletedFid, ownerFid: session.liveFid,
                       ownerPriv: ownerPriv, lastHeight: 200, active: false),
            try record(id: "carve-1", contactFid: aliveFid, ownerFid: session.liveFid,
                       ownerPriv: ownerPriv, lastHeight: 100, active: true, memo: "hi"),
            // An older duplicate carve of aliveFid — must lose to carve-1.
            try record(id: "carve-0", contactFid: aliveFid, ownerFid: session.liveFid,
                       ownerPriv: ownerPriv, lastHeight: 50, active: true, memo: "stale")
        ]

        mock.responder = { call in
            switch call.api {
            case "base.search":
                return try makeResponse(data: records)
            case "base.freerByIds":
                return try makeResponse(data: [aliveFid: ["cid": "ALICE"]])
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }

        let result = try await session.directory.syncOnChainContacts(
            owner: session.liveFid,
            privkey: ownerPriv,
            into: session.contacts
        )

        XCTAssertEqual(result.total, 4)
        XCTAssertEqual(result.merged, 1)
        XCTAssertEqual(result.removed, 1)
        XCTAssertEqual(result.undecryptable, 0)

        // Alive contact: merged with newest detail, freer enrichment,
        // and the carve id captured for future update/delete ops.
        let alive = try XCTUnwrap(session.contacts.get(fid: aliveFid))
        XCTAssertEqual(alive.memo, "hi")
        XCTAssertEqual(alive.cid, "ALICE")
        XCTAssertEqual(alive.carveId, "carve-1")
        XCTAssertEqual(alive.onChain, true)

        // Chain-sourced row whose newest carve is a delete → gone.
        XCTAssertNil(try session.contacts.get(fid: deletedFid))

        // Local-only row survives an on-chain delete of the same FID.
        let localOnly = try XCTUnwrap(session.contacts.get(fid: localOnlyFid))
        XCTAssertEqual(localOnly.memo, "local note")

        // The freerByIds enrichment only asked about live FIDs.
        let freerCall = try XCTUnwrap(mock.recorded.first { $0.api == "base.freerByIds" })
        let ids = try XCTUnwrap(
            (JSONSerialization.jsonObject(with: freerCall.fcdsl!) as? [String: Any])?["ids"] as? [String]
        )
        XCTAssertEqual(ids, [aliveFid])
    }

    /// A row wrongly claiming `onChain` (old builds flipped it on a
    /// directory lookup) is demoted when the owner's exhaustive carve
    /// fetch has no record of it. Rows that are local-only stay
    /// untouched.
    func testSyncDemotesStaleOnChainMarking() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)

        let staleFid = try realFid(byte: 0xE1)
        let localFid = try realFid(byte: 0xE2)
        try session.contacts.upsert(Contact(id: staleFid, onChain: true))
        try session.contacts.upsert(Contact(id: localFid, memo: "plain local"))

        // Chain: no carves at all for this owner.
        mock.responder = { call in
            switch call.api {
            case "base.search": return FapiResponse(code: 404, message: "NOT_FOUND")
            default: return try makeResponse(data: [String: Any]())
            }
        }

        let result = try await session.directory.syncOnChainContacts(
            owner: session.liveFid,
            privkey: try session.livePrikey(),
            into: session.contacts
        )

        XCTAssertEqual(result.demoted, 1)
        let stale = try XCTUnwrap(session.contacts.get(fid: staleFid))
        XCTAssertEqual(stale.onChain, false)
        XCTAssertNil(stale.carveId)
        let local = try XCTUnwrap(session.contacts.get(fid: localFid))
        XCTAssertNil(local.onChain)
    }

    /// When any record fails to decrypt its contact FID is unknown, so
    /// the demote pass must not run — it could unmark a legitimately
    /// carved row.
    func testSyncSkipsDemoteWhenRecordsUndecryptable() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)

        let markedFid = try realFid(byte: 0xE3)
        try session.contacts.upsert(Contact(id: markedFid, onChain: true))

        mock.responder = { call in
            switch call.api {
            case "base.search":
                // One record whose cipher can't be decrypted.
                return try makeResponse(data: [[
                    "id": "carve-x",
                    "cipher": "not-a-real-envelope",
                    "owner": session.liveFid,
                    "lastHeight": 100,
                    "active": true
                ]])
            default:
                return try makeResponse(data: [String: Any]())
            }
        }

        let result = try await session.directory.syncOnChainContacts(
            owner: session.liveFid,
            privkey: try session.livePrikey(),
            into: session.contacts
        )

        XCTAssertEqual(result.undecryptable, 1)
        XCTAssertEqual(result.demoted, 0)
        let marked = try XCTUnwrap(session.contacts.get(fid: markedFid))
        XCTAssertEqual(marked.onChain, true)
    }

    /// The search FCDSL must not filter on `active` — deletions are
    /// only visible when inactive records come back too.
    func testFetchQueriesBothActiveAndInactive() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await session.directory.fetchOnChainContactRecords(owner: session.liveFid)

        let call = try XCTUnwrap(mock.recorded.first { $0.api == "base.search" })
        let fcdsl = try XCTUnwrap(
            JSONSerialization.jsonObject(with: call.fcdsl!) as? [String: Any]
        )
        XCTAssertEqual(fcdsl["entity"] as? String, "contact")
        let query = try XCTUnwrap(fcdsl["query"] as? [String: Any])
        XCTAssertNil(query["terms"], "active filter must be gone so deletions sync")
        let equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["owner"])
    }
}
