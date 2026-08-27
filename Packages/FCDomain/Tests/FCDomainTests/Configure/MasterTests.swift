import XCTest
import FCCore
@testable import FCDomain

/// The Master relationship: the FEIP builder that carves it, and the
/// guards on ``ActiveSession/carveMasterOnChain(masterFid:masterPubkey:feePerByte:timeoutMs:)``.
///
/// The guards get more attention than the happy path here, and on
/// purpose: this is the one carve in the app that publishes a private
/// key, so every way of aiming it at the wrong party is worth a test.
final class MasterTests: XCTestCase {

    private var baseDir: URL!

    /// A real key, so the FID/pubkey pair below is internally
    /// consistent rather than two unrelated constants.
    private let mainPriv = Data(
        fromHex: "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575"
    )
    private let masterPriv = Data(repeating: 0x5C, count: 32)
    /// A third party, so "not the main and not the master" is a real
    /// FID rather than a made-up string that happens to collide.
    private let strangerPriv = Data(repeating: 0x77, count: 32)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MasterTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeActiveSession() throws -> ActiveSession {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let cs = try mgr.createConfigure(
            password: Data("master".utf8), kdfKind: .legacySha256
        )
        let main = try cs.addMain(privkey: mainPriv, label: "main")
        return try cs.unlockMain(fid: main.fid, fapi: MockFapiClient())
    }

    private func masterPair() throws -> (fid: String, pubkey: Data) {
        try pair(for: masterPriv)
    }

    private func pair(for privkey: Data) throws -> (fid: String, pubkey: Data) {
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        return (try FchAddress(publicKey: pubkey).fid, pubkey)
    }

    // MARK: - FEIP builder

    /// The promise is protocol text hashed into a permanent record, so
    /// it is asserted character for character. A reworded or
    /// re-punctuated sentence is a different carve.
    func testPromiseIsExactProtocolText() {
        XCTAssertEqual(MasterFeip.promise, "The master owns all my rights.")
    }

    func testEnvelopeCarriesMasterPromiseAndCipher() throws {
        let opJson = try MasterFeip.setOp(master: "FMaster", cipherPriKey: "CIPHER")
        let feip = MasterFeip.envelope(opJson: opJson)

        let decoded = try JSONSerialization.jsonObject(
            with: Data(feip.utf8)
        ) as? [String: Any]
        XCTAssertEqual(decoded?["type"] as? String, "FEIP")
        XCTAssertEqual(decoded?["sn"] as? String, "6")
        XCTAssertEqual(decoded?["ver"] as? String, "1")
        XCTAssertEqual(decoded?["name"] as? String, "Master")

        let data = decoded?["data"] as? [String: Any]
        XCTAssertEqual(data?["master"] as? String, "FMaster")
        XCTAssertEqual(data?["promise"] as? String, MasterFeip.promise)
        XCTAssertEqual(data?["cipherPriKey"] as? String, "CIPHER")
        // Matches MasterOpData's unset `alg` — Gson omits a null field.
        XCTAssertNil(data?["alg"])
        // And no `op`: the Master protocol has no verb, unlike every
        // other FEIP builder in this package.
        XCTAssertNil(data?["op"])
    }

    func testEnvelopeIncludesAlgWhenGiven() throws {
        let opJson = try MasterFeip.setOp(
            master: "FMaster", cipherPriKey: "CIPHER", alg: "FC_EccK1AesGcm256_No1_NrC7"
        )
        let data = try JSONSerialization.jsonObject(with: Data(opJson.utf8)) as? [String: Any]
        XCTAssertEqual(data?["alg"] as? String, "FC_EccK1AesGcm256_No1_NrC7")
    }

    // MARK: - carve guards

    /// The security-critical one. A FID and a pubkey that don't belong
    /// together would seal the main's private key to whoever holds
    /// *that* key, while the on-chain record names someone else — so
    /// the carve would look right and have handed the identity to a
    /// stranger. Refuse before any encryption happens.
    func testCarveRefusesAPubkeyThatIsNotTheMastersOwn() async throws {
        let session = try makeActiveSession()
        let (_, realPubkey) = try masterPair()
        let strangerFid = try pair(for: strangerPriv).fid

        do {
            _ = try await session.carveMasterOnChain(
                masterFid: strangerFid, masterPubkey: realPubkey
            )
            XCTFail("expected a mismatch to be refused")
        } catch let e as ActiveSession.Failure {
            guard case .masterPubkeyMismatch(let fid, let derived) = e else {
                return XCTFail("wrong failure: \(e)")
            }
            XCTAssertEqual(fid, strangerFid)
            XCTAssertEqual(derived, try masterPair().fid)
        }
        XCTAssertNil(session.mainKeyInfo.master, "nothing recorded locally")
    }

    func testCarveRefusesTheFidAsItsOwnMaster() async throws {
        let session = try makeActiveSession()
        let ownPubkey = try Secp256k1.publicKey(fromPrivateKey: mainPriv)

        do {
            _ = try await session.carveMasterOnChain(
                masterFid: session.mainFid, masterPubkey: ownPubkey
            )
            XCTFail("expected self-mastery to be refused")
        } catch let e as ActiveSession.Failure {
            guard case .masterIsSelf = e else { return XCTFail("wrong failure: \(e)") }
        }
    }

    /// A master belongs to the main FID: its key is what gets sealed
    /// and its coins pay. Carving while living as a sub-identity would
    /// take the wrong key.
    func testCarveRefusesWhileLivingAsASubIdentity() async throws {
        let session = try makeActiveSession()
        let (masterFid, masterPubkey) = try masterPair()
        let watched = try session.addWatchedFid(try pair(for: strangerPriv).fid)
        try session.switchLive(fid: watched.fid)

        do {
            _ = try await session.carveMasterOnChain(
                masterFid: masterFid, masterPubkey: masterPubkey
            )
            XCTFail("expected a sub-identity to be refused")
        } catch let e as ActiveSession.Failure {
            guard case .masterNeedsMain(let live) = e else {
                return XCTFail("wrong failure: \(e)")
            }
            XCTAssertEqual(live, watched.fid)
        }
    }

    /// What the carve would seal, checked without carving: the main's
    /// private key, openable by the master and nobody else.
    func testTheSealedPayloadIsTheMainsPrivateKey() throws {
        let (_, masterPubkey) = try masterPair()
        let cipher = try AsyOneWayCipher.encrypt(
            plaintext: mainPriv, toPubkey: masterPubkey
        )
        let opened = try AsyOneWayCipher.decrypt(cipherString: cipher, privkey: masterPriv)
        XCTAssertEqual(opened, mainPriv, "the master can open it")

        let stranger = Data(repeating: 0x11, count: 32)
        XCTAssertThrowsError(
            try AsyOneWayCipher.decrypt(cipherString: cipher, privkey: stranger),
            "and nobody else can"
        )
    }

    // MARK: - servants

    func testAddServantFidRecordsKindAndPointsBackAtTheMain() throws {
        let session = try makeActiveSession()
        let servantFid = try pair(for: strangerPriv).fid

        let info = try session.addServantFid(servantFid, label: "phone")
        XCTAssertEqual(info.kind, .servant)
        XCTAssertEqual(info.label, "phone")
        XCTAssertEqual(info.master, session.mainFid, "a servant's master is us")
        XCTAssertEqual(session.setting.keyInfoMap[servantFid]?.kind, .servant)

        // The kind may sign, but this entry holds no key cipher — so
        // living as it must still land on the watch-only path.
        XCTAssertTrue(KeyKind.servant.canSign)
        XCTAssertFalse(info.hasPrivkey)
        try session.switchLive(fid: servantFid)
        XCTAssertFalse(session.canSign, "no cipher, so nothing to sign with")
    }

    // MARK: - multisig registration

    private func multisigGroup(includingMain: Bool) throws -> Multisig {
        let mainPub = Hex.encode(try Secp256k1.publicKey(fromPrivateKey: mainPriv))
        let masterPub = Hex.encode(try Secp256k1.publicKey(fromPrivateKey: masterPriv))
        let strangerPub = Hex.encode(try Secp256k1.publicKey(fromPrivateKey: strangerPriv))
        return try Multisig(
            pubkeys: includingMain
                ? [mainPub, masterPub, strangerPub]
                : [masterPub, strangerPub],
            m: 2
        )
    }

    func testRegisteringAMultisigGroupKeepsItsRedeemScript() throws {
        let session = try makeActiveSession()
        let group = try multisigGroup(includingMain: true)

        let info = try session.addMultisigFid(group, label: "house")
        XCTAssertEqual(info.kind, .multisig)
        XCTAssertEqual(info.fid, group.id)
        // Without the script the address is unspendable, so this is the
        // field that makes the entry worth having.
        XCTAssertEqual(info.multisig?.redeemScript, group.redeemScript)
        XCTAssertEqual(session.multisigGroup(for: try XCTUnwrap(group.id))?.m, 2)
        XCTAssertFalse(info.hasPrivkey, "a group holds no key of its own")
    }

    /// Registering a group we are not in would list an identity that
    /// can never be signed for, and the failure would only surface at
    /// signing time as "not a member".
    func testRegisteringAGroupWeAreNotInIsRefused() throws {
        let session = try makeActiveSession()
        let group = try multisigGroup(includingMain: false)

        XCTAssertThrowsError(try session.addMultisigFid(group)) { error in
            guard case ActiveSession.Failure.notAMultisigMember = error else {
                return XCTFail("wrong failure: \(error)")
            }
        }
        XCTAssertNil(session.multisigGroup(for: try XCTUnwrap(group.id)))
    }

    /// A group's coins are watch-only from any single wallet, so the
    /// live-FID gate must keep saying so: the signature that spends the
    /// group comes from a member, collected through the co-sign flow.
    func testLivingAsAGroupStillCannotSign() throws {
        let session = try makeActiveSession()
        let group = try multisigGroup(includingMain: true)
        let info = try session.addMultisigFid(group)

        try session.switchLive(fid: info.fid)
        XCTAssertFalse(session.canSign)
        XCTAssertFalse(KeyKind.multisig.canSign)
    }

    /// An input that arrived without its redeem script is repaired from
    /// the group and its own lock time — otherwise it cannot be signed.
    func testMissingRedeemScriptsAreRepairedFromTheGroup() throws {
        let group = try multisigGroup(includingMain: true)
        let bare = RawTxInfo.Slot(
            owner: try group.address(), value: 5_000,
            birthTxId: String(repeating: "22", count: 32), birthIndex: 0
        )
        let locked = RawTxInfo.Slot(
            owner: try group.address(lockTime: 700_000), value: 5_000,
            birthTxId: String(repeating: "33", count: 32), birthIndex: 1,
            lockTime: 700_000
        )
        let repaired = try ActiveSession.repairMultisigRedeemScripts(
            [bare, locked], group: group
        )
        XCTAssertEqual(repaired[0].redeemScript, group.redeemScript)
        XCTAssertEqual(
            repaired[1].redeemScript, try group.redeemScript(lockTime: 700_000),
            "a locked input needs the time-locked script, not the bare one"
        )
        XCTAssertNotEqual(repaired[0].redeemScript, repaired[1].redeemScript)
    }

    func testRemovingTheLiveSubIdentityFallsBackToTheMain() throws {
        let session = try makeActiveSession()
        let servantFid = try pair(for: strangerPriv).fid
        try session.addServantFid(servantFid)
        try session.switchLive(fid: servantFid)

        XCTAssertTrue(try session.removeSubIdentity(fid: servantFid))
        XCTAssertEqual(session.liveFid, session.mainFid)
        XCTAssertNil(session.setting.keyInfoMap[servantFid])
    }
}
