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

    // MARK: - generating and rotating

    func testGenerateProducesAStoredThirtyTwoByteKey() throws {
        let entry = try store.generate(for: room, version: 1)
        XCTAssertEqual(entry.key.count, 32)
        XCTAssertEqual(entry.version, 1)
        XCTAssertEqual(entry.entityId, room)
        XCTAssertEqual(try store.key(for: room, version: 1), entry.key)
        XCTAssertEqual(try store.currentKey(for: room), entry.key)
        XCTAssertNotEqual(entry.key, try store.generate(for: team, version: 1).key)
    }

    /// An entity we hold no key for reports version 0 — Android's answer,
    /// and the one `currentVersion(for:) >= minimumVersion` tests against.
    func testUnknownEntityHasNoKey() throws {
        XCTAssertEqual(try store.currentVersion(for: room), 0)
        XCTAssertNil(try store.currentKey(for: room))
        XCTAssertNil(try store.key(for: room, version: 1))
        XCTAssertFalse(try store.has(entityId: room))
        XCTAssertTrue(try store.versions(for: room).isEmpty)
    }

    /// A rotation adds a version, it does not replace one. The old key
    /// has to survive: it is the only thing that can still open what was
    /// said before the rotation.
    func testRotationKeepsTheOldKey() throws {
        let first = try store.rotate(for: room)
        XCTAssertEqual(first.version, 1)

        let second = try store.rotate(for: room)
        XCTAssertEqual(second.version, 2)
        XCTAssertNotEqual(second.key, first.key)

        XCTAssertEqual(try store.currentVersion(for: room), 2)
        XCTAssertEqual(try store.currentKey(for: room), second.key)
        XCTAssertEqual(try store.key(for: room, version: 1), first.key)
        XCTAssertEqual(try store.versions(for: room), [1, 2])
    }

    /// The padded storage key is what makes version order and text order
    /// the same thing — v10 must not sort before v9.
    func testVersionsSortNumericallyPastTen() throws {
        for version in [3, 11, 9, 10, 1] as [Int64] {
            try store.generate(for: room, version: version)
        }
        XCTAssertEqual(try store.versions(for: room), [1, 3, 9, 10, 11])
        XCTAssertEqual(try store.currentVersion(for: room), 11)
    }

    /// Entities do not see each other's keys, and an entity id with an
    /// underscore in it still parses — the storage key splits on the
    /// last one.
    func testEntitiesAreSeparate() throws {
        let odd = "team_with_underscores"
        try store.generate(for: room, version: 1)
        try store.generate(for: team, version: 7)
        try store.generate(for: odd, version: 2)

        XCTAssertEqual(try store.versions(for: room), [1])
        XCTAssertEqual(try store.versions(for: team), [7])
        XCTAssertEqual(try store.versions(for: odd), [2])
        XCTAssertEqual(Set(try store.entityIds()), [room, team, odd])
        XCTAssertEqual(
            SymkeyStore.parse(storageKey: SymkeyStore.storageKey(entityId: odd, version: 2))?.entityId,
            odd
        )
    }

    // MARK: - validation

    /// `ImMessage.symkeyVersion` is a 64-bit field the wire carries in 32
    /// bits and sign-extends coming back, so a peer really can name a
    /// negative version. Storing a key there would put it where no
    /// honest rotation could reach.
    func testNonPositiveVersionsAreRefused() throws {
        for bad: Int64 in [0, -1, -2_147_483_647] {
            XCTAssertThrowsError(try store.generate(for: room, version: bad)) { error in
                XCTAssertEqual(error as? SymkeyStore.Failure, .badVersion(bad))
            }
            XCTAssertThrowsError(
                try store.store(Data(repeating: 1, count: 32), for: room, version: bad, allowOverwrite: true)
            )
        }
    }

    func testKeyLengthAndEntityIdAreChecked() throws {
        XCTAssertThrowsError(
            try store.store(Data(repeating: 1, count: 16), for: room, version: 1, allowOverwrite: true)
        ) { XCTAssertEqual($0 as? SymkeyStore.Failure, .badKeyLength(16)) }

        XCTAssertThrowsError(
            try store.store(Data(repeating: 1, count: 32), for: "", version: 1, allowOverwrite: true)
        ) { XCTAssertEqual($0 as? SymkeyStore.Failure, .noEntityId) }
    }

    // MARK: - the overwrite rule

    /// Without this rule any member could push a bogus key for a version
    /// everyone already holds and make the room's history unreadable.
    func testAKeyIsNotOverwrittenUnlessTheCallerVouchesForTheSender() throws {
        let original = try store.generate(for: room, version: 1).key
        let impostor = Data(repeating: 0xEE, count: 32)

        XCTAssertFalse(
            try store.store(impostor, for: room, version: 1, allowOverwrite: false),
            "a non-owner's key must not land on a version we already hold"
        )
        XCTAssertEqual(try store.key(for: room, version: 1), original)

        XCTAssertTrue(try store.store(impostor, for: room, version: 1, allowOverwrite: true))
        XCTAssertEqual(try store.key(for: room, version: 1), impostor)
    }

    /// Refusing an overwrite is an ordinary outcome, not an error: two
    /// members answering the same request is the normal case.
    func testStoringAFreshVersionSucceedsEitherWay() throws {
        let key = Data(repeating: 0x11, count: 32)
        XCTAssertTrue(try store.store(key, for: room, version: 4, allowOverwrite: false))
        XCTAssertEqual(try store.key(for: room, version: 4), key)
    }

    // MARK: - sharing

    /// The joiner's round trip: Alice seals her room key to Bob's
    /// pubkey, Bob opens it with his privkey and can then read the room.
    func testShareCipherReachesTheRecipientAndNobodyElse() throws {
        let key = try store.generate(for: room, version: 3).key
        let cipher = try XCTUnwrap(try store.shareCipher(for: room, version: 3, to: pubkey(bob)))

        // Bob's side, with his own store.
        let bobsStore = try otherStore()
        XCTAssertTrue(
            try bobsStore.receiveShared(
                cipher: cipher, for: room, version: 3, privkey: bob, allowOverwrite: false
            )
        )
        XCTAssertEqual(try bobsStore.key(for: room, version: 3), key)

        // Mallory holds the same ciphertext and gets nothing from it.
        XCTAssertFalse(
            try bobsStore.receiveShared(
                cipher: cipher, for: team, version: 3, privkey: mallory, allowOverwrite: false
            )
        )
        XCTAssertNil(try bobsStore.key(for: team, version: 3))
    }

    func testShareCipherIsNilForAVersionWeDoNotHold() throws {
        XCTAssertNil(try store.shareCipher(for: room, version: 9, to: pubkey(bob)))
    }

    func testReceivingGarbageIsFalseNotAThrow() throws {
        XCTAssertFalse(
            try store.receiveShared(
                cipher: "not an envelope", for: room, version: 1, privkey: alice, allowOverwrite: true
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

    // MARK: - message bodies

    func testSealAndOpenARoomMessage() throws {
        try store.generate(for: room, version: 1)
        var message = ImMessage.text(type: .room, from: "F-alice", to: room, "the usual place, 8pm")
        message.id = "0000000000000001"

        XCTAssertEqual(try store.seal(&message, for: room), 1)
        XCTAssertNil(message.content)
        XCTAssertEqual(message.symkeyVersion, 1)
        XCTAssertTrue(message.isSealed)

        XCTAssertTrue(try store.open(&message, for: room))
        XCTAssertEqual(message.content, "the usual place, 8pm")
        XCTAssertFalse(message.isSealed)
    }

    /// Opening uses the version the message names, not the current one —
    /// which is the entire reason old versions are kept.
    func testAMessageSealedBeforeARotationStillOpens() throws {
        try store.rotate(for: room)
        var old = ImMessage.text(type: .room, from: "F-alice", to: room, "said before the rotation")
        old.id = "0000000000000001"
        try store.seal(&old, for: room)
        XCTAssertEqual(old.symkeyVersion, 1)

        try store.rotate(for: room)
        var new = ImMessage.text(type: .room, from: "F-alice", to: room, "said after")
        new.id = "0000000000000002"
        XCTAssertEqual(try store.seal(&new, for: room), 2)

        XCTAssertTrue(try store.open(&old, for: room))
        XCTAssertEqual(old.content, "said before the rotation")
        XCTAssertTrue(try store.open(&new, for: room))
        XCTAssertEqual(new.content, "said after")
    }

    /// A message we have no key for is a row to show as locked and a key
    /// to go and ask for — not an error that stops a batch.
    func testOpeningWithoutTheVersionIsFalseNotAThrow() throws {
        try store.generate(for: room, version: 1)
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
        try store.generate(for: room, version: 1)
        var message = ImMessage.make(type: .room, from: "F-alice", to: room, contentType: .text)
        XCTAssertThrowsError(try store.seal(&message, for: room)) { error in
            XCTAssertEqual(error as? ImMessage.BodyFailure, .noContent)
        }
    }

    /// The wrong key does not open a body, and does not corrupt it
    /// either.
    func testAWrongKeyOpensNothing() throws {
        try store.generate(for: room, version: 1)
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
        try store.rotate(for: room)
        try store.rotate(for: room)
        try store.generate(for: team, version: 1)

        XCTAssertEqual(try store.removeAll(for: room), 2)
        XCTAssertFalse(try store.has(entityId: room))
        XCTAssertTrue(try store.has(entityId: team), "another entity's keys are untouched")
        XCTAssertEqual(try store.removeAll(for: room), 0)
    }

    func testRemoveOneVersion() throws {
        try store.rotate(for: room)
        try store.rotate(for: room)
        XCTAssertTrue(try store.remove(entityId: room, version: 1))
        XCTAssertFalse(try store.remove(entityId: room, version: 1))
        XCTAssertEqual(try store.versions(for: room), [2])
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
