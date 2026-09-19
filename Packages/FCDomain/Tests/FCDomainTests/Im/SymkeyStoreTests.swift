import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// ``SymkeyStore``: versions that outlive their rotation, the overwrite
/// rule that keeps a member from bricking a room, and the share
/// round trip that gets a key to a joiner.
final class SymkeyStoreTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let room = "b4c9a1f2e8d73065b4c9a1f2e8d73065"
    private let team = "0f0e0d0c0b0a09080706050403020100"

    /// Alice is the store's owner; Bob is the joiner she shares with;
    /// Mallory is neither.
    private let alice = Data(repeating: 0xA1, count: 32)
    private let bob = Data(repeating: 0xB2, count: 32)
    private let mallory = Data(repeating: 0xC3, count: 32)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("SymkeyStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: alice, label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        configure = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var store: SymkeyStore { session.symkeys }
    private func pubkey(_ privkey: Data) throws -> Data {
        try Secp256k1.publicKey(fromPrivateKey: privkey)
    }

    // MARK: - minting

    func testMintProducesAStoredThirtyTwoByteKey() throws {
        let entry = try store.mint(for: room)
        XCTAssertEqual(entry.key.count, 32)
        XCTAssertEqual(entry.entityId, room)
        XCTAssertEqual(try store.keys(for: room, version: entry.version), [entry.key])
        XCTAssertEqual(try store.currentKey(for: room), entry.key)
        XCTAssertNotEqual(entry.key, try store.mint(for: team).key)
    }

    /// A version is the second it was minted in, so a fresh key is
    /// stamped with the clock rather than with 1.
    func testAMintedVersionIsTheClock() throws {
        let at = Date(timeIntervalSince1970: 1_789_813_689)
        let entry = try store.mint(for: room, now: at)
        XCTAssertEqual(entry.version, 1_789_813_689)
        XCTAssertTrue(SymkeyStore.isTimestamp(entry.version))
    }

    /// **The floor, case one.** Two mints inside one second used to be a
    /// collision waiting to happen; the floor makes it arithmetic.
    func testTwoMintsInOneSecondGetDifferentVersions() throws {
        let at = Date(timeIntervalSince1970: 1_789_813_689)
        let first = try store.mint(for: room, now: at)
        let second = try store.mint(for: room, now: at)

        XCTAssertEqual(first.version, 1_789_813_689)
        XCTAssertEqual(second.version, 1_789_813_690, "the second mint is forced past the first")
        XCTAssertNotEqual(first.key, second.key)
        XCTAssertEqual(try store.versions(for: room), [first.version, second.version])
    }

    /// **The floor, case two, and the dangerous one.** A clock that steps
    /// backwards must not be able to mint a key that sorts below one we
    /// hold: "current" would then select the retired key, so an owner who
    /// rotated after removing a member would keep sealing under the key
    /// that member still holds, with nothing on screen to say so.
    func testABackwardsClockCannotMintBelowWhatWeHold() throws {
        let late = try store.mint(for: room, now: Date(timeIntervalSince1970: 1_789_813_689))
        let early = try store.mint(for: room, now: Date(timeIntervalSince1970: 1_000_000_000))

        XCTAssertEqual(early.version, late.version + 1)
        XCTAssertEqual(try store.currentKey(for: room), early.key)
        XCTAssertEqual(try store.currentVersion(for: room), early.version)
    }

    /// An entity we hold no key for reports version 0 — Android's answer,
    /// and the one `currentVersion(for:) >= minimumVersion` tests against.
    func testUnknownEntityHasNoKey() throws {
        XCTAssertEqual(try store.currentVersion(for: room), 0)
        XCTAssertNil(try store.currentKey(for: room))
        XCTAssertTrue(try store.keys(for: room, version: 1).isEmpty)
        XCTAssertFalse(try store.has(entityId: room))
        XCTAssertFalse(try store.has(entityId: room, version: 1))
        XCTAssertTrue(try store.versions(for: room).isEmpty)
    }

    /// A rotation adds a version, it does not replace one. The old key
    /// has to survive: it is the only thing that can still open what was
    /// said before the rotation.
    func testRotationKeepsTheOldKey() throws {
        let first = try store.mint(for: room, now: Date(timeIntervalSince1970: 1_700_000_000))
        let second = try store.mint(for: room, now: Date(timeIntervalSince1970: 1_800_000_000))
        XCTAssertNotEqual(second.key, first.key)

        XCTAssertEqual(try store.currentVersion(for: room), second.version)
        XCTAssertEqual(try store.currentKey(for: room), second.key)
        XCTAssertEqual(try store.keys(for: room, version: first.version), [first.key])
        XCTAssertEqual(try store.versions(for: room), [first.version, second.version])
    }

    /// The padded storage key is what makes version order and text order
    /// the same thing — v10 must not sort before v9, and a timestamp must
    /// not sort before a pre-spec counter.
    func testVersionsSortNumericallyPastTen() throws {
        for version in [3, 11, 9, 10, 1, 1_789_813_689] as [Int64] {
            try store.store(Data(repeating: UInt8(version % 251), count: 32), for: room, version: version)
        }
        XCTAssertEqual(try store.versions(for: room), [1, 3, 9, 10, 11, 1_789_813_689])
        XCTAssertEqual(try store.currentVersion(for: room), 1_789_813_689)
    }

    /// A store holding both a pre-spec counter and a timestamp needs no
    /// cutover: the two cannot collide, and the timestamp is always the
    /// newer key.
    func testLegacyCountersAndTimestampsCoexist() throws {
        let legacy = Data(repeating: 0x0C, count: 32)
        try store.store(legacy, for: room, version: 3)
        XCTAssertFalse(SymkeyStore.isTimestamp(3))
        XCTAssertEqual(try store.currentKey(for: room), legacy)

        let minted = try store.mint(for: room)
        XCTAssertTrue(SymkeyStore.isTimestamp(minted.version))
        XCTAssertEqual(try store.currentKey(for: room), minted.key)
        XCTAssertEqual(try store.keys(for: room, version: 3), [legacy], "the counter's key is still there")
    }

    /// Entities do not see each other's keys, and an entity id with
    /// underscores in it still parses — the row name is read from the end
    /// by fixed widths, not split on a separator.
    func testEntitiesAreSeparate() throws {
        let odd = "team_with_underscores"
        try store.mint(for: room)
        try store.mint(for: team)
        let oddEntry = try store.mint(for: odd)

        XCTAssertEqual(try store.versions(for: room).count, 1)
        XCTAssertEqual(try store.versions(for: team).count, 1)
        XCTAssertEqual(try store.versions(for: odd), [oddEntry.version])
        XCTAssertEqual(Set(try store.entityIds()), [room, team, odd])

        let rowKey = SymkeyStore.storageKey(
            entityId: odd, version: oddEntry.version, keyId: oddEntry.keyId
        )
        let parsed = try XCTUnwrap(SymkeyStore.parse(storageKey: rowKey))
        XCTAssertEqual(parsed.entityId, odd)
        XCTAssertEqual(parsed.version, oddEntry.version)
        XCTAssertEqual(parsed.keyId, oddEntry.keyId)
    }

    // MARK: - identity

    /// The id is the key's own hash, so two stores computing it from the
    /// same key agree without exchanging anything — which is why it never
    /// travels.
    func testKeyIdIsTheKeysOwnHash() throws {
        let key = Data(repeating: 0x5A, count: 32)
        let entry = SymkeyEntry(entityId: room, version: 1, key: key)
        XCTAssertEqual(entry.keyId, SymkeyStore.keyId(of: key))
        XCTAssertEqual(entry.keyId.count, SymkeyStore.keyIdLength)
        XCTAssertTrue(entry.keyId.allSatisfy(\.isHexDigit))
        XCTAssertNotEqual(entry.keyId, SymkeyStore.keyId(of: Data(repeating: 0x5B, count: 32)))
    }

    // MARK: - validation

    /// `ImMessage.symkeyVersion` is a 64-bit field the wire carries in 32
    /// bits, so a peer really can name a version this side of zero.
    /// Storing a key there would put it where no honest mint could reach.
    func testNonPositiveVersionsAreRefused() throws {
        for bad: Int64 in [0, -1, -2_147_483_647] {
            XCTAssertThrowsError(
                try store.store(Data(repeating: 1, count: 32), for: room, version: bad)
            ) { XCTAssertEqual($0 as? SymkeyStore.Failure, .badVersion(bad)) }
        }
    }

    func testKeyLengthAndEntityIdAreChecked() throws {
        XCTAssertThrowsError(
            try store.store(Data(repeating: 1, count: 16), for: room, version: 1)
        ) { XCTAssertEqual($0 as? SymkeyStore.Failure, .badKeyLength(16)) }

        XCTAssertThrowsError(
            try store.store(Data(repeating: 1, count: 32), for: "", version: 1)
        ) { XCTAssertEqual($0 as? SymkeyStore.Failure, .noEntityId) }
    }

    // MARK: - nothing is overwritten

    /// The rule this replaces was the only thing that could destroy
    /// history: an owner's key at a version we held overwrote the row,
    /// and every message sealed under the displaced key became unreadable
    /// with no other copy anywhere. Both keys are kept now, whoever sent
    /// the second one.
    func testADifferentKeyAtOneVersionIsKeptBesideTheFirst() throws {
        let original = try store.mint(for: room).key
        let version = try store.currentVersion(for: room)
        let other = Data(repeating: 0xEE, count: 32)

        XCTAssertTrue(try store.store(other, for: room, version: version))
        XCTAssertEqual(Set(try store.keys(for: room, version: version)), [original, other])
        XCTAssertEqual(try store.versions(for: room), [version], "still one version")
        XCTAssertEqual(try store.count(for: room), 2)
    }

    /// Re-storing a key we already hold is a no-op rather than an error:
    /// two members answering one request is the normal case.
    func testTheSameKeyTwiceIsANoOp() throws {
        let key = Data(repeating: 0x11, count: 32)
        XCTAssertTrue(try store.store(key, for: room, version: 4))
        XCTAssertFalse(try store.store(key, for: room, version: 4))
        XCTAssertEqual(try store.keys(for: room, version: 4), [key])
        XCTAssertEqual(try store.count(for: room), 1)
    }

    /// A bound on a misbehaving peer. A key we already hold must not be
    /// able to fail on a full store, since storing it changes nothing.
    func testTheKeyCapIsEnforcedButNotAgainstANoOp() throws {
        for i in 0 ..< SymkeyStore.maxKeysPerEntity {
            var key = Data(repeating: 0, count: 32)
            key[0] = UInt8(i % 256)
            key[1] = UInt8(i / 256)
            try store.store(key, for: room, version: 1)
        }
        XCTAssertEqual(try store.count(for: room), SymkeyStore.maxKeysPerEntity)

        var overflow = Data(repeating: 0xFF, count: 32)
        overflow[0] = 0xFE
        XCTAssertThrowsError(try store.store(overflow, for: room, version: 1)) {
            XCTAssertEqual(
                $0 as? SymkeyStore.Failure,
                .tooManyKeys(entityId: room, limit: SymkeyStore.maxKeysPerEntity)
            )
        }
        var held = Data(repeating: 0, count: 32)
        held[0] = 7
        XCTAssertFalse(try store.store(held, for: room, version: 1), "a no-op, not a failure")
    }

    // MARK: - migrating

    /// Pre-spec rows are named `<entityId>_<version>`. Moving them needs
    /// no network and decides nothing: the id comes from the key already
    /// in the row.
    func testLegacyRowsAreMovedUnderTheirKeyId() throws {
        let legacy = Data(repeating: 0x3C, count: 32)
        let legacyRow = room + "_" + String(format: "%019lld", Int64(2))
        try session.storage.put(
            SymkeyEntry(entityId: room, version: 2, key: legacy),
            namespace: SymkeyStore.namespace,
            key: legacyRow
        )
        XCTAssertTrue(try store.keys(for: room, version: 2).isEmpty, "not visible under the old name")

        XCTAssertEqual(try store.migrateLegacyRowKeys(), 1)
        XCTAssertEqual(try store.keys(for: room, version: 2), [legacy])
        XCTAssertEqual(try store.migrateLegacyRowKeys(), 0, "idempotent")
    }

    // MARK: - sharing

    /// The joiner's round trip: Alice seals her room key to Bob's
    /// pubkey, Bob opens it with his privkey and can then read the room.
    func testShareCipherReachesTheRecipientAndNobodyElse() throws {
        let entry = try store.mint(for: room)
        let ciphers = try store.shareCiphers(for: room, version: entry.version, to: pubkey(bob))
        let cipher = try XCTUnwrap(ciphers.first)
        XCTAssertEqual(ciphers.count, 1)

        // Bob's side, with his own store.
        let bobsStore = try otherStore()
        XCTAssertTrue(
            try bobsStore.receiveShared(
                cipher: cipher, for: room, version: entry.version, privkey: bob
            )
        )
        XCTAssertEqual(try bobsStore.keys(for: room, version: entry.version), [entry.key])

        // Mallory holds the same ciphertext and gets nothing from it.
        XCTAssertFalse(
            try bobsStore.receiveShared(
                cipher: cipher, for: team, version: entry.version, privkey: mallory
            )
        )
        XCTAssertTrue(try bobsStore.keys(for: team, version: entry.version).isEmpty)
    }

    /// Sending our favourite of two keys at one version would leave the
    /// asker exactly where they started — a key stored, nothing opened,
    /// and no way to ask for the other one.
    func testEveryKeyAtAVersionIsShared() throws {
        let mine = try store.mint(for: room)
        let other = Data(repeating: 0xEE, count: 32)
        try store.store(other, for: room, version: mine.version)

        let ciphers = try store.shareCiphers(for: room, version: mine.version, to: pubkey(bob))
        XCTAssertEqual(ciphers.count, 2)

        let bobsStore = try otherStore()
        for cipher in ciphers {
            try bobsStore.receiveShared(
                cipher: cipher, for: room, version: mine.version, privkey: bob
            )
        }
        XCTAssertEqual(Set(try bobsStore.keys(for: room, version: mine.version)), [mine.key, other])
    }

    func testShareCiphersIsEmptyForAVersionWeDoNotHold() throws {
        XCTAssertTrue(try store.shareCiphers(for: room, version: 9, to: pubkey(bob)).isEmpty)
    }

    func testReceivingGarbageIsFalseNotAThrow() throws {
        XCTAssertFalse(
            try store.receiveShared(
                cipher: "not an envelope", for: room, version: 1, privkey: alice
            )
        )
        XCTAssertFalse(try store.has(entityId: room))
    }

    // MARK: - the SYMKEY payload

    /// The payload is `entityId:cipher` and the cipher is JSON, so it is
    /// full of colons. Splitting anywhere but the first one hands back a
    /// mangled key.
    func testPayloadSplitsOnTheFirstColonOnly() throws {
        let cipher = "{\"type\":\"AsyOneWay\",\"alg\":\"EccK1AesGcm256@No1_NrC7\",\"cipher\":\"c2FtcGxl\"}"
        let payload = SymkeyShare.payload(entityId: room, cipher: cipher)
        let parsed = try XCTUnwrap(SymkeyShare.parse(payload))
        XCTAssertEqual(parsed.entityId, room)
        XCTAssertEqual(parsed.cipher, cipher)
    }

    func testMalformedPayloadsParseToNil() {
        XCTAssertNil(SymkeyShare.parse("no-colon-here"))
        XCTAssertNil(SymkeyShare.parse(":cipher-with-no-entity"))
        XCTAssertNil(SymkeyShare.parse("entity-with-no-cipher:"))
    }

    /// A request names its entity either bare or with a suffix; Android
    /// accepts both.
    func testRequestedEntityIdAcceptsBothForms() {
        XCTAssertEqual(SymkeyShare.requestedEntityId(room), room)
        XCTAssertEqual(SymkeyShare.requestedEntityId("\(room):anything"), room)
        XCTAssertNil(SymkeyShare.requestedEntityId(nil))
        XCTAssertNil(SymkeyShare.requestedEntityId(""))
        XCTAssertNil(SymkeyShare.requestedEntityId(":only-a-suffix"))
    }

    /// FIMP4V3 §5.1: `"<id>"` asks for the current version, `"<id>:<v>"`
    /// for a named one. The version used to be parsed off and discarded,
    /// which made asking for an older key impossible to express.
    func testARequestCarriesTheVersionItNames() {
        XCTAssertEqual(SymkeyShare.requested(room)?.entityId, room)
        XCTAssertNil(SymkeyShare.requested(room)?.version)

        XCTAssertEqual(SymkeyShare.requested("\(room):1")?.version, 1)
        XCTAssertEqual(SymkeyShare.requested("\(room):42")?.version, 42)
        XCTAssertEqual(SymkeyShare.requested("\(room):42")?.entityId, room)
    }

    /// Anything unparseable after the colon reads as "no version named",
    /// not as a bad request. Android sent the literal `":latest"` for
    /// years, and answering those with the current key is what the
    /// protocol did before versions could be named.
    func testAnUnreadableVersionFallsBackToTheCurrentOne() {
        for tail in ["latest", "", "0", "-3", "1.5", "v2", "9999999999999999999999"] {
            let asked = SymkeyShare.requested("\(room):\(tail)")
            XCTAssertEqual(asked?.entityId, room, "entity still parses from ':\(tail)'")
            XCTAssertNil(asked?.version, "':\(tail)' is not a version")
        }
        XCTAssertNil(SymkeyShare.requested(":1"), "no entity is no request")
        XCTAssertNil(SymkeyShare.requested(nil))
        XCTAssertNil(SymkeyShare.requested(""))
    }

    /// FIMP4V3 §5.2 / FIMP2V3 §5.3: `"<id>:<v1>,<v2>,…"`.
    func testAHistoryRequestNamesEveryVersionItWants() {
        XCTAssertEqual(
            SymkeyShare.historyRequest(entityId: room, versions: [3, 1, 2]), "\(room):1,2,3",
            "de-duplicated and sorted, so one set is one request"
        )

        let asked = SymkeyShare.requestedHistory("\(room):1,2,3")
        XCTAssertEqual(asked?.entityId, room)
        XCTAssertEqual(asked?.versions, [1, 2, 3])
    }

    /// A duplicate names one version, not two.
    func testAHistoryRequestDeduplicates() {
        XCTAssertEqual(SymkeyShare.historyRequest(entityId: room, versions: [2, 2, 1]), "\(room):1,2")
        XCTAssertEqual(SymkeyShare.requestedHistory("\(room):2,2,1")?.versions, [1, 2])
    }

    /// One unreadable entry does not sink the request: the other seven
    /// are still keys somebody needs.
    func testAHistoryRequestSkipsWhatItCannotRead() {
        let asked = SymkeyShare.requestedHistory("\(room):1,nonsense,,3, 4 ,0,-2")
        XCTAssertEqual(asked?.versions, [1, 3, 4])
    }

    /// Nothing readable is nothing to answer.
    func testAnEmptyHistoryRequestIsNil() {
        XCTAssertNil(SymkeyShare.requestedHistory("\(room):nonsense,0,-1"))
        XCTAssertNil(SymkeyShare.requestedHistory(room), "a batch has to name versions")
        XCTAssertNil(SymkeyShare.requestedHistory(":1,2"))
        XCTAssertNil(SymkeyShare.requestedHistory(nil))
        XCTAssertNil(SymkeyShare.historyRequest(entityId: room, versions: []))
        XCTAssertNil(SymkeyShare.historyRequest(entityId: room, versions: [0, -1]))
    }

    /// **The cap is a security property.** Every version named costs the
    /// responder a seal and a message it pays to send, so an unbounded
    /// list would be an amplifier.
    func testAHistoryRequestIsCapped() throws {
        let many = Array(Int64(1) ... 500)
        let content = SymkeyShare.historyRequest(entityId: room, versions: many)
        let asked = try XCTUnwrap(SymkeyShare.requestedHistory(content))
        XCTAssertEqual(asked.versions.count, SymkeyShare.maxHistoryVersions)
        XCTAssertEqual(asked.versions.first, 1, "the oldest are the ones worth keeping")

        // And a request built elsewhere is capped on the way in too.
        let overlong = room + ":" + many.map(String.init).joined(separator: ",")
        XCTAssertEqual(
            SymkeyShare.requestedHistory(overlong)?.versions.count,
            SymkeyShare.maxHistoryVersions,
            "a responder caps what it will answer, whoever built the request"
        )
    }

    /// The form we emit is the form we read back.
    func testRequestContentRoundTrips() {
        XCTAssertEqual(SymkeyShare.request(entityId: room), room)
        XCTAssertEqual(SymkeyShare.request(entityId: room, version: nil), room)
        XCTAssertEqual(SymkeyShare.request(entityId: room, version: 7), "\(room):7")
        // Below the minimum is not a version, so it names none.
        XCTAssertEqual(SymkeyShare.request(entityId: room, version: 0), room)

        for version in [nil, Int64(1), Int64(6)] {
            let asked = SymkeyShare.requested(SymkeyShare.request(entityId: room, version: version))
            XCTAssertEqual(asked?.entityId, room)
            XCTAssertEqual(asked?.version, version)
        }
    }

    // MARK: - message bodies

    func testSealAndOpenARoomMessage() throws {
        let entry = try store.mint(for: room)
        var message = ImMessage.text(type: .room, from: "F-alice", to: room, "the usual place, 8pm")
        message.id = "0000000000000001"

        XCTAssertEqual(try store.seal(&message, for: room), entry.version)
        XCTAssertNil(message.content)
        XCTAssertEqual(message.symkeyVersion, entry.version)
        XCTAssertTrue(message.isSealed)

        XCTAssertTrue(try store.open(&message, for: room))
        XCTAssertEqual(message.content, "the usual place, 8pm")
        XCTAssertFalse(message.isSealed)
    }

    /// Opening uses the version the message names, not the current one —
    /// which is the entire reason old versions are kept.
    func testAMessageSealedBeforeARotationStillOpens() throws {
        let first = try store.mint(for: room, now: Date(timeIntervalSince1970: 1_700_000_000))
        var old = ImMessage.text(type: .room, from: "F-alice", to: room, "said before the rotation")
        old.id = "0000000000000001"
        try store.seal(&old, for: room)
        XCTAssertEqual(old.symkeyVersion, first.version)

        let second = try store.mint(for: room, now: Date(timeIntervalSince1970: 1_800_000_000))
        var new = ImMessage.text(type: .room, from: "F-alice", to: room, "said after")
        new.id = "0000000000000002"
        XCTAssertEqual(try store.seal(&new, for: room), second.version)

        XCTAssertTrue(try store.open(&old, for: room))
        XCTAssertEqual(old.content, "said before the rotation")
        XCTAssertTrue(try store.open(&new, for: room))
        XCTAssertEqual(new.content, "said after")
    }

    /// A message we have no key for is a row to show as locked and a key
    /// to go and ask for — not an error that stops a batch.
    func testOpeningWithoutTheVersionIsFalseNotAThrow() throws {
        try store.mint(for: room)
        var message = ImMessage.text(type: .room, from: "F-them", to: room, "sealed to a key we lack")
        message.id = "0000000000000001"
        try store.seal(&message, for: room)
        message.symkeyVersion = 5

        XCTAssertFalse(try store.open(&message, for: room))
        XCTAssertNil(message.content)
        XCTAssertTrue(message.isSealed)
    }

    /// Sealing must fail loudly. The alternative to a thrown error here
    /// is a plaintext body on the wire.
    func testSealingWithoutAKeyThrows() throws {
        var message = ImMessage.text(type: .team, from: "F-alice", to: team, "secret")
        message.id = "0000000000000001"
        XCTAssertThrowsError(try store.seal(&message, for: team)) { error in
            XCTAssertEqual(error as? SymkeyStore.Failure, .noKey(entityId: team))
        }
        XCTAssertEqual(message.content, "secret", "an unsealable message keeps its plaintext, unsent")
    }

    func testSealingAnEmptyBodyThrows() throws {
        try store.mint(for: room)
        var message = ImMessage.make(type: .room, from: "F-alice", to: room, contentType: .text)
        XCTAssertThrowsError(try store.seal(&message, for: room)) { error in
            XCTAssertEqual(error as? ImMessage.BodyFailure, .noContent)
        }
    }

    /// The wrong key does not open a body, and does not corrupt it
    /// either.
    func testAWrongKeyOpensNothing() throws {
        try store.mint(for: room)
        var message = ImMessage.text(type: .room, from: "F-alice", to: room, "private")
        message.id = "0000000000000001"
        try store.seal(&message, for: room)

        XCTAssertFalse(message.openBody(symkey: Data(repeating: 0xEE, count: 32)))
        XCTAssertNil(message.content)
    }

    // MARK: - p2p bodies

    /// The AsyTwoWay property that 9.1.1 exists for: the *sender* can
    /// reread what they sent. Without it a sent message would be
    /// write-only.
    func testP2PBodyOpensForTheRecipient() throws {
        var message = ImMessage.text(type: .p2p, from: "F-alice", to: "F-bob", "just between us")
        message.id = "0000000000000001"
        try message.sealBody(privkey: alice, recipientPubkey: pubkey(bob))
        XCTAssertNil(message.content)

        var recipientCopy = message
        XCTAssertTrue(recipientCopy.openBody(privkey: bob))
        XCTAssertEqual(recipientCopy.content, "just between us")

        // The bundle carries only pubkeyA, so unlike the JSON envelope it
        // cannot be reopened by its sender. `MessagesStore` keeps our own
        // messages as plaintext, so nothing asks it to.
        var senderCopy = message
        XCTAssertFalse(senderCopy.openBody(privkey: alice))
        XCTAssertNil(senderCopy.content)

        var strangerCopy = message
        XCTAssertFalse(strangerCopy.openBody(privkey: mallory))
        XCTAssertNil(strangerCopy.content)
    }

    /// A note to self goes AsyOneWay, because an AsyTwoWay envelope with
    /// the same pubkey on both sides is one the side-selection cannot
    /// resolve.
    func testNoteToSelfIsOneWayAndStillOpens() throws {
        var message = ImMessage.text(type: .p2p, from: "F-alice", to: "F-alice", "remember the milk")
        message.id = "0000000000000001"
        try message.sealBody(privkey: alice, recipientPubkey: pubkey(alice))

        let bundle = try XCTUnwrap(message.body)
        XCTAssertEqual(CryptoBundle.encryptType(of: bundle), "asyOneWay")
        XCTAssertTrue(message.openBody(privkey: alice))
        XCTAssertEqual(message.content, "remember the milk")
    }

    // MARK: - deleting

    func testRemoveAllForgetsEveryVersion() throws {
        try store.mint(for: room)
        try store.mint(for: room)
        try store.mint(for: team)

        XCTAssertEqual(try store.removeAll(for: room), 2)
        XCTAssertFalse(try store.has(entityId: room))
        XCTAssertTrue(try store.has(entityId: team), "another entity's keys are untouched")
        XCTAssertEqual(try store.removeAll(for: room), 0)
    }

    func testRemoveOneVersion() throws {
        let first = try store.mint(for: room, now: Date(timeIntervalSince1970: 1_700_000_000))
        let second = try store.mint(for: room, now: Date(timeIntervalSince1970: 1_800_000_000))
        XCTAssertEqual(try store.remove(entityId: room, version: first.version), 1)
        XCTAssertEqual(try store.remove(entityId: room, version: first.version), 0)
        XCTAssertEqual(try store.versions(for: room), [second.version])
    }

    /// Removing by key id takes one of two keys sharing a version and
    /// leaves the other.
    func testRemoveOneKeyOfTwoAtOneVersion() throws {
        let mine = try store.mint(for: room)
        let other = Data(repeating: 0xEE, count: 32)
        try store.store(other, for: room, version: mine.version)

        XCTAssertEqual(
            try store.remove(entityId: room, version: mine.version, keyId: mine.keyId), 1
        )
        XCTAssertEqual(try store.keys(for: room, version: mine.version), [other])
        XCTAssertEqual(try store.versions(for: room), [mine.version])
    }

    // MARK: - helpers

    /// A second, independent store — the joiner's device.
    private func otherStore() throws -> SymkeyStore {
        let dir = baseDir.appendingPathComponent("bob-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let kv = try EncryptedKVStore(
            databasePath: dir.appendingPathComponent("store.sqlite").path,
            vaultKey: Data(repeating: 0x7B, count: 32)
        )
        return SymkeyStore(kv: kv)
    }
}
