import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Private BASE and DISK entries: sealed to the FID's own pubkey in
/// Android's `DiskHomeManager` format, and carved only when the service or
/// its privacy actually changes.
final class HomePrivacyTests: XCTestCase {

    private let sid = String(repeating: "a", count: 64)
    private let otherSid = String(repeating: "b", count: 64)
    private let prikey = Data(repeating: 7, count: 32)
    private var pubkey: Data { try! Secp256k1.publicKey(fromPrivateKey: prikey) }

    func testSealedOpensToTheServiceIdForItsOwnerOnly() throws {
        let sealed = try HomePrivacy.seal("(sid)" + sid, toPubkey: pubkey)
        XCTAssertTrue(HomePrivacy.isSealed(sealed))
        XCTAssertTrue(sealed.contains(#""type":"AsyOneWay""#))
        XCTAssertTrue(sealed.contains("EccK1AesGcm256@No1_NrC7"), "the algorithm Android's DiskHomeManager seals with")
        XCTAssertEqual(HomePrivacy.open(sealed, prikey: prikey), "(sid)" + sid)
        XCTAssertNil(HomePrivacy.open(sealed, prikey: Data(repeating: 8, count: 32)))
        XCTAssertNil(HomePrivacy.open(sealed, prikey: nil))
    }

    func testTheSealedPayloadIsTheRawServiceIdBytes() throws {
        // Android's reader hex-encodes what it decrypts and expects 64 hex
        // characters back, so the plaintext must be the 32 bytes, not text.
        let sealed = try HomePrivacy.seal(sid, toPubkey: pubkey)
        let plain = try AsyOneWayCipher.decrypt(cipherString: sealed, privkey: prikey)
        XCTAssertEqual(plain, Hex.decodeOrNil(sid))
    }

    func testPublicValuesOpenToThemselves() {
        XCTAssertEqual(HomePrivacy.open("(sid)" + sid, prikey: nil), "(sid)" + sid)
        XCTAssertEqual(HomePrivacy.open("fudp://d.example:8500", prikey: nil), "fudp://d.example:8500")
        XCTAssertNil(HomePrivacy.open("  ", prikey: prikey))
    }

    func testAnAddressCannotBeSealed() {
        XCTAssertThrowsError(try HomePrivacy.seal("fudp://d.example:8500", toPubkey: pubkey))
        XCTAssertFalse(HomeFeip.wouldChange(
            over: nil, base: HomeEntry("fudp://d.example:8500", sealed: true), dock: nil, disk: nil, prikey: prikey
        ))
    }

    // MARK: - what a carve writes

    func testResealingTheSameServiceIsNoChange() throws {
        let stored = [ServiceName.disk: try HomePrivacy.seal(sid, toPubkey: pubkey)]
        XCTAssertFalse(HomeFeip.wouldChange(over: stored, base: nil, dock: nil, disk: HomeEntry(sid, sealed: true), prikey: prikey),
                       "sealing again would be a paid carve that says nothing new")
        XCTAssertNil(try HomeFeip.planned(over: stored, base: nil, dock: nil, disk: HomeEntry(sid, sealed: true), prikey: prikey, pubkey: pubkey))
    }

    func testMakingAnEntryPublicOrPrivateIsAChange() throws {
        let sealedStore = [ServiceName.disk: try HomePrivacy.seal(sid, toPubkey: pubkey)]
        let madePublic = try XCTUnwrap(HomeFeip.planned(
            over: sealedStore, base: nil, dock: nil, disk: HomeEntry(sid, sealed: false), prikey: prikey, pubkey: pubkey
        ))
        XCTAssertEqual(madePublic[ServiceName.disk], "(sid)" + sid)

        let plainStore = [ServiceName.disk: "(sid)" + sid]
        let madePrivate = try XCTUnwrap(HomeFeip.planned(
            over: plainStore, base: nil, dock: nil, disk: HomeEntry(sid, sealed: true), prikey: prikey, pubkey: pubkey
        ))
        XCTAssertEqual(HomePrivacy.open(madePrivate[ServiceName.disk], prikey: prikey), "(sid)" + sid)
        XCTAssertTrue(HomePrivacy.isSealed(madePrivate[ServiceName.disk]))
    }

    func testOnlyTheChangedEntryIsResealed() throws {
        let sealedDisk = try HomePrivacy.seal(sid, toPubkey: pubkey)
        let stored = [ServiceName.disk: sealedDisk, ServiceName.dock: "(sid)d"]
        let planned = try XCTUnwrap(HomeFeip.planned(
            over: stored, base: HomeEntry(otherSid, sealed: true), dock: nil,
            disk: HomeEntry(sid, sealed: true), prikey: prikey, pubkey: pubkey
        ))
        XCTAssertEqual(planned[ServiceName.disk], sealedDisk, "the unchanged DISK keeps its bytes")
        XCTAssertEqual(planned[ServiceName.dock], "(sid)d")
        XCTAssertEqual(HomePrivacy.open(planned[ServiceName.base], prikey: prikey), "(sid)" + otherSid)
    }

    func testAPublicBaseIsWrittenPlain() throws {
        let planned = try XCTUnwrap(HomeFeip.planned(
            over: nil, base: HomeEntry(sid, sealed: false), dock: nil, disk: nil, prikey: prikey, pubkey: pubkey
        ))
        XCTAssertEqual(planned, [ServiceName.base: "(sid)" + sid])
    }

    // MARK: - everyone else

    func testOthersResolveAPrivateEntryToNothing() async throws {
        let resolver = HomeServiceResolver(fapi: ThrowingFapi())
        let sealed = try HomePrivacy.seal(sid, toPubkey: pubkey)
        let url = await resolver.resolve(sealed)
        XCTAssertNil(url, "sealed is private, not a service id to look up")
    }

    private struct ThrowingFapi: FapiCalling {
        func call(
            api: String, params: Data?, fcdsl: Data?, binary: Data?,
            sid: String?, via: String?, maxCost: Int64?, timeoutMs: Int
        ) async throws -> FapiClient.Reply {
            XCTFail("a sealed entry must not be looked up")
            throw CancellationError()
        }
    }
}
