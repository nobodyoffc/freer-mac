import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// The stranger gate: who gets through, who is held, who is dropped, and
/// what accepting someone actually does to the transcript.
final class ContactPolicyTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let myPriv = Data(repeating: 0x11, count: 32)
    private let theirPriv = Data(repeating: 0x22, count: 32)
    private var me = ""
    private let stranger = "F-stranger"
    private let friend = "F-friend"

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ContactPolicyTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: myPriv, label: "me")
        me = info.fid
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        configure = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - the rule

    func testBlacklistBeatsEverything() {
        var policy = ContactPolicy(strategy: .askAboutStrangers)
        policy.allow(stranger)
        policy.block(stranger)
        // Blocking removes them from the whitelist, so there is no state
        // in which both apply.
        XCTAssertEqual(policy.decide(sender: stranger, isContact: true), .drop)
        XCTAssertFalse(policy.isAllowed(stranger))
    }

    func testAllowingSomeoneUnblocksThem() {
        var policy = ContactPolicy()
        policy.block(stranger)
        policy.allow(stranger)
        XCTAssertEqual(policy.decide(sender: stranger, isContact: false), .deliver)
        XCTAssertFalse(policy.isBlocked(stranger))
    }

    /// The default. A stranger is *held and asked about* — not accepted,
    /// which is what Android's own name for this setting implies and is
    /// why it is not called that here.
    func testDefaultHoldsAStrangerAndAsks() {
        let policy = ContactPolicy(strategy: .askAboutStrangers)
        XCTAssertEqual(policy.decide(sender: stranger, isContact: false), .hold(prompt: true))
    }

    /// Someone already in the address book is let in on their first
    /// message, and remembered — that second half is what stops the same
    /// question being asked on every message they send.
    func testAContactIsAcceptedOnFirstContact() {
        for strategy in [ContactPolicy.Strategy.askAboutStrangers, .contactsOnly] {
            let policy = ContactPolicy(strategy: strategy)
            XCTAssertEqual(
                policy.decide(sender: friend, isContact: true), .acceptAndDeliver,
                "\(strategy)"
            )
        }
    }

    /// Under the two strict settings, being in Contacts is not consent.
    func testStrictStrategiesHoldEvenAContact() {
        for strategy in [ContactPolicy.Strategy.whitelistOnly, .acceptNone] {
            let policy = ContactPolicy(strategy: strategy)
            XCTAssertEqual(
                policy.decide(sender: friend, isContact: true), .hold(prompt: false),
                "\(strategy)"
            )
        }
    }

    /// Quiet strategies still hold rather than drop — the user chose not
    /// to be interrupted, not to lose mail.
    func testQuietStrategiesHoldWithoutPrompting() {
        for strategy in [ContactPolicy.Strategy.contactsOnly, .whitelistOnly, .acceptNone] {
            XCTAssertEqual(
                ContactPolicy(strategy: strategy).decide(sender: stranger, isContact: false),
                .hold(prompt: false),
                "\(strategy)"
            )
        }
    }

    // MARK: - the store

    /// A note to self must never arrive as a message request.
    func testOwnFidIsAlwaysWhitelisted() throws {
        let policy = try session.contactPolicy.load(liveFid: me)
        XCTAssertTrue(policy.isAllowed(me))
        XCTAssertEqual(policy.decide(sender: me, isContact: false), .deliver)
    }

    func testPolicySurvivesAReload() throws {
        try session.contactPolicy.mutate(liveFid: me) {
            $0.strategy = .whitelistOnly
            $0.block(stranger)
        }
        let reloaded = try session.contactPolicy.load(liveFid: me)
        XCTAssertEqual(reloaded.strategy, .whitelistOnly)
        XCTAssertTrue(reloaded.isBlocked(stranger))
    }

    /// The stored values are Android's, so the two clients could ever
    /// compare or export a policy without translating it.
    func testStrategyRawValuesMatchAndroid() {
        XCTAssertEqual(ContactPolicy.Strategy.askAboutStrangers.rawValue, "ACCEPT_ALL")
        XCTAssertEqual(ContactPolicy.Strategy.contactsOnly.rawValue, "CONTACTS_ONLY")
        XCTAssertEqual(ContactPolicy.Strategy.whitelistOnly.rawValue, "WHITELIST_ONLY")
        XCTAssertEqual(ContactPolicy.Strategy.acceptNone.rawValue, "ACCEPT_NONE")
    }

    // MARK: - the receive path

    private func incoming(_ text: String, from sender: String, at seconds: TimeInterval) -> ImMessage {
        var m = ImMessage.text(type: .p2p, from: sender, to: me, text, now: at(seconds))
        m.id = ImMessage.hexId(fudpId: Int64(seconds) &+ 1_000)
        return m
    }

    /// **The gap this closes.** A message from an unknown FID used to be
    /// filed straight into the thread list. Now it is held: stored, but
    /// belonging to no conversation, so nothing about it is on screen
    /// until someone says yes.
    func testAStrangersMessageIsHeldAndCreatesNoThread() throws {
        let received = try session.chat.receive(
            incoming("hello?", from: stranger, at: 10), as: me, now: at(10)
        )
        guard case .held(_, let prompt) = received else {
            return XCTFail("expected the message to be held, got \(received)")
        }
        XCTAssertTrue(prompt, "the default strategy asks")

        XCTAssertTrue(try session.conversations.visible().isEmpty, "no thread")
        XCTAssertEqual(try session.conversations.totalUnread(), 0, "no unread count")
        XCTAssertEqual(try session.messageRequests.count(from: stranger), 1)
    }

    func testHeldMessagesKeepTheQuarantinedStatus() throws {
        _ = try session.chat.receive(incoming("one", from: stranger, at: 10), as: me, now: at(10))
        let held = try session.messageRequests.held(from: stranger)
        XCTAssertEqual(held.count, 1)
        XCTAssertEqual(held.first?.status, .quarantined)
    }

    /// Accepting is not just "start a thread": everything they said
    /// while they were waiting has to be in it, or the request queue
    /// would swallow the very message that made the user look.
    func testAcceptingAStrangerPromotesEverythingTheySaid() throws {
        for i in 0..<3 {
            _ = try session.chat.receive(
                incoming("message \(i)", from: stranger, at: TimeInterval(10 + i)),
                as: me, now: at(TimeInterval(10 + i))
            )
        }
        let promoted = try session.messageRequests.promote(stranger, as: me, now: at(60))
        XCTAssertEqual(promoted, 3)

        let conversationId = Conversation.id(type: .p2p, targetId: stranger)
        let page = try session.chat.page(conversationId)
        XCTAssertEqual(page.messages.count, 3)
        XCTAssertEqual(page.messages.map(\.content), ["message 0", "message 1", "message 2"])
        XCTAssertTrue(page.messages.allSatisfy { $0.status == .delivered })

        let thread = try XCTUnwrap(try session.conversations.get(id: conversationId))
        XCTAssertEqual(thread.unreadCount, 3)
        XCTAssertEqual(thread.lastMessageContent, "message 2")
        XCTAssertNil(try session.messageRequests.pending().first, "the request is gone")
    }

    /// Accepting them once has to be enough: the *next* message must not
    /// ask the same question again.
    func testAcceptingAndThenAllowingLetsLaterMessagesThrough() throws {
        _ = try session.chat.receive(incoming("hi", from: stranger, at: 10), as: me, now: at(10))
        _ = try session.messageRequests.promote(stranger, as: me, now: at(20))
        try session.contactPolicy.mutate(liveFid: me) { $0.allow(stranger) }

        let received = try session.chat.receive(
            incoming("again", from: stranger, at: 30), as: me, now: at(30)
        )
        guard case .message = received else {
            return XCTFail("expected delivery, got \(received)")
        }
    }

    /// Rejecting is not blocking. The batch goes; the sender is not made
    /// unreachable, because most of these are someone writing to the
    /// wrong FID rather than an attacker.
    func testRejectingDropsTheMessagesAndNotTheSender() throws {
        _ = try session.chat.receive(incoming("hi", from: stranger, at: 10), as: me, now: at(10))
        XCTAssertEqual(try session.messageRequests.reject(stranger), 1)
        XCTAssertTrue(try session.messageRequests.held(from: stranger).isEmpty)
        XCTAssertTrue(try session.messageRequests.pending().isEmpty)

        let policy = try session.contactPolicy.load(liveFid: me)
        XCTAssertFalse(policy.isBlocked(stranger), "rejecting a batch is not blocking a person")
    }

    /// A blocked sender leaves no trace at all — no request, no held
    /// message, nothing to see.
    func testABlockedSenderLeavesNothingBehind() throws {
        try session.contactPolicy.mutate(liveFid: me) { $0.block(stranger) }
        let received = try session.chat.receive(
            incoming("let me in", from: stranger, at: 10), as: me, now: at(10)
        )
        guard case .ignored = received else {
            return XCTFail("expected the message to be dropped, got \(received)")
        }
        XCTAssertTrue(try session.messageRequests.pending().isEmpty)
        XCTAssertTrue(try session.messageRequests.held(from: stranger).isEmpty)
        XCTAssertTrue(try session.conversations.visible().isEmpty)
    }

    /// Without the cap, anyone holding our FID could fill the disk of a
    /// device that never agreed to hear from them.
    func testTheCapStopsAStrangerFillingTheDisk() throws {
        for i in 0..<(MessageRequests.maxHeldPerSender + 5) {
            _ = try session.chat.receive(
                incoming("spam \(i)", from: stranger, at: TimeInterval(i)),
                as: me, now: at(TimeInterval(i))
            )
        }
        XCTAssertEqual(
            try session.messageRequests.count(from: stranger),
            MessageRequests.maxHeldPerSender
        )
        XCTAssertEqual(
            try session.messageRequests.held(from: stranger).count,
            MessageRequests.maxHeldPerSender
        )
    }

    /// **Group traffic is exempt.** A square is open by definition and
    /// being in a team or a room already means the conversation was
    /// accepted; running group messages through a per-sender gate would
    /// quarantine a group chat one member at a time.
    func testGroupMessagesFromStrangersAreNotHeld() throws {
        for type in [ImType.team, .square, .room] {
            let targetId = "G-\(type.rawValue)"
            var m = ImMessage.text(
                type: type, from: stranger, to: targetId, "in the group", now: at(10)
            )
            m.id = ImMessage.hexId(fudpId: Int64(type.rawValue.count) &+ 7_000)
            let received = try session.chat.receive(m, as: me, now: at(10))
            guard case .message = received else {
                return XCTFail("\(type) should be delivered, got \(received)")
            }
        }
        XCTAssertTrue(try session.messageRequests.pending().isEmpty)
    }

    /// Our own message coming back to us — a second device collecting
    /// what this one sent — is not a stranger's.
    func testOurOwnOutgoingMessageIsNeverHeld() throws {
        var m = ImMessage.text(type: .p2p, from: me, to: stranger, "mine", now: at(10))
        m.id = ImMessage.hexId(fudpId: 4_242)
        let received = try session.chat.receive(m, as: me, now: at(10))
        guard case .message = received else {
            return XCTFail("expected delivery, got \(received)")
        }
    }
}
