import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The media write path through `ActiveSession`, asserted on the
/// broadcast raw hex, **for all three kinds**.
///
/// Image, Sound and Video are one implementation with three
/// configurations, so the risk the tests have to cover is not that the
/// lifecycle is wrong — Text proved that — but that a kind carves
/// somebody else's serial number or subject key. Every carve assertion
/// below therefore checks the expected value *and* the absence of the
/// other two.
final class MediaCarveTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MediaCarveTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
    }

    override func tearDownWithError() throws {
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - fixtures

    private func makeSession(fapi: any FapiCalling, tag: String) throws -> ActiveSession {
        let configure = try manager.createConfigure(
            password: Data("media-tests-\(tag)".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(
            privkey: Hash.sha256(Data("publisher-\(tag)".utf8)), label: "publisher"
        )
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func cashDict(owner: String, txid: String, value: Int64) throws -> [String: Any] {
        let h160 = try FchAddress(fid: owner).hash160
        return [
            "id": try Cash.makeId(birthTxId: txid, birthIndex: 0),
            "owner": owner,
            "value": value,
            "type": "P2PKH",
            "birthTxId": txid,
            "birthIndex": 0,
            // Aged enough for the CD rule, which `bestHeight` below
            // deliberately puts in force rather than dodging.
            "cd": 5,
            "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
        ]
    }

    private func stage(
        _ mock: MockFapiClient,
        senderFid: String,
        txid: String = "media-txid-001",
        onBroadcast: @escaping @Sendable (String) -> Void = { _ in }
    ) throws {
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: senderFid,
                        txid: String(repeating: "cd", count: 32),
                        value: 10_000_000
                    )],
                    bestHeight: 4_100_000
                )
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                onBroadcast((params?["rawTx"] as? String) ?? "")
                return try makeResponse(data: txid)
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }
    }

    /// The two things every media assertion needs: what this kind must
    /// say, and what it must not.
    private func others(_ kind: MediaKind) -> [MediaKind] {
        MediaKind.allCases.filter { $0 != kind }
    }

    // MARK: - publish

    /// Each kind carves its own serial number, its own envelope name
    /// and its own subject key — and none of the other two's.
    func testEachKindCarvesItsOwnProtocolAndNobodyElses() async throws {
        for kind in MediaKind.allCases {
            let mock = MockFapiClient()
            let session = try makeSession(fapi: mock, tag: kind.rawValue)
            let broadcast = Captured()
            try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

            let did = String(repeating: "ab", count: 32)
            let record = try await session.carveMediaPublishOnChain(
                kind: kind, title: "Work", did: did, lang: "en",
                authors: ["FIDA"], format: "application/octet-stream", summary: "A work."
            )

            let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
            XCTAssertNotNil(raw.range(of: Data(#""sn":"\#(kind.sn)""#.utf8)), "\(kind) sn")
            XCTAssertNotNil(
                raw.range(of: Data(#""name":"\#(kind.protocolName)""#.utf8)), "\(kind) name")
            XCTAssertNotNil(raw.range(of: Data(#""did":"\#(did)""#.utf8)))

            for other in others(kind) {
                XCTAssertNil(
                    raw.range(of: Data(#""sn":"\#(other.sn)""#.utf8)),
                    "\(kind) must not carve \(other)'s sn")
                XCTAssertNil(
                    raw.range(of: Data(#""name":"\#(other.protocolName)""#.utf8)),
                    "\(kind) must not carve \(other)'s name")
            }
            // Rule 1: the id is the txid, so a publish never names one.
            for anyKind in MediaKind.allCases {
                XCTAssertNil(raw.range(of: Data(anyKind.subjectKey.utf8)))
            }
            XCTAssertEqual(
                String(data: raw, encoding: .isoLatin1)?
                    .components(separatedBy: #""type""#).count, 2,
                "a media carve has no type of its own")

            XCTAssertEqual(record.id, "media-txid-001")
            XCTAssertEqual(record.kind, kind)
            XCTAssertEqual(record.ver, "1")
            XCTAssertNil(record.onChain, "broadcast, not confirmed")
            XCTAssertEqual(try session.media(kind).get(id: "media-txid-001")?.title, "Work")
        }
    }

    /// Three kinds, three namespaces. A publish lands in exactly one of
    /// them — a shared store would have each kind's refresh delete the
    /// others, since a refresh drops what the chain did not return.
    func testAPublishLandsInItsOwnStoreAndNoOther() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock, tag: "stores")
        try stage(mock, senderFid: session.mainFid)

        _ = try await session.carveMediaPublishOnChain(kind: .sound, title: "Track", did: "abc")

        XCTAssertNotNil(try session.media(.sound).get(id: "media-txid-001"))
        XCTAssertNil(try session.media(.image).get(id: "media-txid-001"))
        XCTAssertNil(try session.media(.video).get(id: "media-txid-001"))
        XCTAssertNil(try session.texts.get(id: "media-txid-001"))
    }

    /// A row filed in a store belongs to that store's kind whatever the
    /// caller believed, so a draft cannot end up in the wrong pane.
    func testTheStoreIsTheAuthorityOnKind() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock, tag: "authority")

        var mislabelled = MediaRecord.createLocal(
            kind: .image, title: "Track", publisher: session.liveFid)
        mislabelled.kind = .image
        try session.media(.sound).upsert(mislabelled)

        XCTAssertEqual(try session.media(.sound).get(id: mislabelled.id)?.kind, .sound)
    }

    func testCarvingADraftRekeysItToTheTxid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock, tag: "draft")
        try stage(mock, senderFid: session.mainFid)

        let draft = MediaRecord.createLocal(
            kind: .video, title: "Clip", did: "abc", publisher: session.liveFid)
        try session.media(.video).upsert(draft)

        let carved = try await session.carveMediaPublishOnChain(
            kind: .video, title: "Clip", did: "abc", draftId: draft.id)
        XCTAssertEqual(carved.id, "media-txid-001")
        XCTAssertNil(try session.media(.video).get(id: draft.id))
        XCTAssertEqual(carved.kind, .video)
        XCTAssertTrue(try session.media(.video).drafts().isEmpty)
    }

    /// The same title and did under two different kinds are two
    /// different drafts — the collision the envelope-hashed id fixed.
    func testDraftIdsDifferAcrossKinds() {
        let ids = MediaKind.allCases.map {
            MediaRecord.createLocal(kind: $0, title: "Same", did: "abc", publisher: "FID").id
        }
        XCTAssertEqual(Set(ids).count, MediaKind.allCases.count)
    }

    // MARK: - update / delete

    func testUpdateNamesItsOwnSubjectKeyAndBumpsTheEdition() async throws {
        for kind in MediaKind.allCases {
            let mock = MockFapiClient()
            let session = try makeSession(fapi: mock, tag: "upd-\(kind.rawValue)")
            let broadcast = Captured()
            try stage(mock, senderFid: session.mainFid, txid: "upd", onBroadcast: { broadcast.value = $0 })

            try session.media(kind).upsert(MediaRecord(
                id: "M1", kind: kind, title: "Work", ver: "1",
                publisher: session.liveFid, onChain: true))

            _ = try await session.carveMediaUpdateOnChain(
                kind: kind, mediaId: "M1", title: "Work v2", did: "deadbeef",
                lang: "en", authors: ["FIDA"], format: "x/y", summary: "Redone.")

            let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
            XCTAssertNotNil(raw.range(of: Data(#""\#(kind.subjectKey)":"M1""#.utf8)))
            for other in others(kind) {
                XCTAssertNil(raw.range(of: Data(other.subjectKey.utf8)),
                             "\(kind) must not name \(other)'s subject")
            }
            for fragment in [#""did":"deadbeef""#, #""lang":"en""#,
                             #""authors":["FIDA"]"#, #""summary":"Redone.""#] {
                XCTAssertNotNil(raw.range(of: Data(fragment.utf8)), "missing \(fragment)")
            }
            XCTAssertEqual(try session.media(kind).get(id: "M1")?.ver, "2")
        }
    }

    func testDeleteAndRecoverUseThePluralSubjectKey() async throws {
        for kind in MediaKind.allCases {
            let mock = MockFapiClient()
            let session = try makeSession(fapi: mock, tag: "del-\(kind.rawValue)")
            let broadcast = Captured()
            try stage(mock, senderFid: session.mainFid, txid: "del", onBroadcast: { broadcast.value = $0 })

            try session.media(kind).upsert(MediaRecord(
                id: "M1", kind: kind, title: "a", publisher: session.liveFid, onChain: true))
            _ = try await session.carveMediaDeleteOnChain(kind: kind, mediaIds: ["M1"])

            let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
            XCTAssertNotNil(raw.range(of: Data(#""\#(kind.subjectsKey)":["M1"]"#.utf8)))
            for other in others(kind) {
                XCTAssertNil(raw.range(of: Data(other.subjectsKey.utf8)))
            }
            XCTAssertEqual(try session.media(kind).get(id: "M1")?.deleted, true)
        }
    }

    // MARK: - remarks

    /// A remark anchors to a sound or a video exactly as it does to a
    /// text or an image: `onDid` is the target's record id, whatever
    /// kind of record that is. This is what lets one
    /// `RemarkThreadView` serve the whole family.
    func testARemarkAnchorsToEveryMediaKindTheSameWay() async throws {
        for kind in MediaKind.allCases {
            let mock = MockFapiClient()
            let session = try makeSession(fapi: mock, tag: "rem-\(kind.rawValue)")
            let broadcast = Captured()
            try stage(mock, senderFid: session.mainFid, txid: "r-\(kind.rawValue)",
                      onBroadcast: { broadcast.value = $0 })

            let target = "\(kind.rawValue)-txid-001"
            let remark = try await session.carveRemarkPublishOnChain(
                title: "Well made", onDid: target, summary: "Nicely done.")

            let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
            XCTAssertNotNil(raw.range(of: Data(#""sn":"22""#.utf8)))
            XCTAssertNotNil(raw.range(of: Data(#""onDid":"\#(target)""#.utf8)))
            XCTAssertEqual(remark.onDid, target)
            XCTAssertEqual(try session.remarks.all(on: target).count, 1)
        }
    }
}

private final class Captured: @unchecked Sendable {
    var value: String?
}
