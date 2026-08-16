import XCTest
@testable import FCDomain

/// The send gate — every branch of ``ChatGate/decide(_:)``, one test
/// each, because each branch is a different fix for the user and getting
/// two of them confused is how a composer ends up accepting text it
/// cannot send.
final class ChatGateTests: XCTestCase {

    // MARK: - P2P

    /// A P2P chat asks nobody's permission. Nothing about membership,
    /// keys or servers applies to it.
    func testP2pIsAlwaysOpen() {
        XCTAssertEqual(ChatGate.decide(.init(type: .p2p)), .open)
    }

    /// Having no DOCK of our own stops replies *arriving*; it does not
    /// stop a message going out, because a P2P send goes to the
    /// recipient's DOCK. Android leaves the composer enabled here on
    /// purpose — it is how a newcomer with no server yet asks for their
    /// first coins.
    func testP2pStaysOpenWithNoDockOfOurOwn() {
        XCTAssertEqual(ChatGate.decide(.init(type: .p2p, hasDock: false)), .open)
    }

    /// A watch-only identity holds no private key, so there is nothing
    /// to seal with — in any flavour, before any other question.
    func testWatchOnlyIsBlockedEverywhere() {
        for type in [ImType.p2p, .room, .team, .square] {
            let verdict = ChatGate.decide(.init(type: type, canSign: false))
            XCTAssertFalse(verdict.canSend, "\(type) should be blocked")
            XCTAssertTrue(verdict.showsComposer, "\(type) keeps the composer, disabled")
        }
    }

    // MARK: - membership

    /// A non-member gets no composer at all. There is no message worth
    /// writing and no state in which writing one would help — which is
    /// exactly the case the old pane got wrong, letting you type into a
    /// team you are not in until `ChatService` refused to seal it.
    func testNonMemberLosesTheComposer() {
        for type in [ImType.room, .team, .square] {
            let verdict = ChatGate.decide(.init(type: type, isMember: false))
            XCTAssertFalse(verdict.showsComposer, "\(type) should hide the composer")
            XCTAssertNotNil(verdict.reason)
        }
    }

    /// The three flavours are joined in three different ways, so the
    /// reason says which — a team and a square are transactions, a room
    /// is an invitation only its owner can extend.
    func testNonMemberReasonNamesHowJoiningWorks() {
        func reason(_ type: ImType) -> String {
            ChatGate.decide(.init(type: type, isMember: false)).reason ?? ""
        }
        XCTAssertTrue(reason(.team).contains("chain"))
        XCTAssertTrue(reason(.square).contains("Anyone may join"))
        XCTAssertTrue(reason(.room).contains("owner"))
    }

    /// Having left is not the same as never having been there, and the
    /// transcript stays either way.
    func testLeftGroupHidesTheComposerEvenForAMember() {
        let verdict = ChatGate.decide(.init(type: .team, isMember: true, leftGroup: true))
        XCTAssertFalse(verdict.showsComposer)
        XCTAssertTrue(verdict.reason?.contains("transcript stays") == true)
    }

    /// An owner is a member. Asking the two questions separately is what
    /// lets the key branch below tell them apart.
    func testOwnerIsTreatedAsAMember() {
        let verdict = ChatGate.decide(.init(type: .room, isMember: true, isOwner: true))
        XCTAssertEqual(verdict, .open)
    }

    // MARK: - DOCK

    /// A group with nowhere for its messages to rest is a conversation
    /// that cannot happen — but it is the group's problem, not ours, so
    /// the composer stays visible and says so.
    func testGroupWithNoDockIsBlockedNotHidden() {
        let verdict = ChatGate.decide(.init(type: .team, hasDock: false))
        XCTAssertFalse(verdict.canSend)
        XCTAssertTrue(verdict.showsComposer)
        XCTAssertTrue(verdict.reason?.contains("DOCK") == true)
    }

    /// Membership is asked before the server: being thrown out of a team
    /// is a different message from that team having no DOCK, and the
    /// first is the one that matters to the reader.
    func testMembershipIsCheckedBeforeTheDock() {
        let verdict = ChatGate.decide(.init(type: .team, isMember: false, hasDock: false))
        XCTAssertFalse(verdict.showsComposer)
    }

    // MARK: - symkeys

    func testTeamAndRoomRequireASymkeyAndSquareDoesNot() {
        XCTAssertTrue(ChatGate.requiresSymkey(.team))
        XCTAssertTrue(ChatGate.requiresSymkey(.room))
        XCTAssertFalse(ChatGate.requiresSymkey(.square))
        XCTAssertFalse(ChatGate.requiresSymkey(.p2p))
    }

    /// A member without the key can only go and ask for it, so the
    /// composer is disabled and the wait is named.
    func testMemberWithoutTheKeyIsBlocked() {
        for type in [ImType.team, .room] {
            let verdict = ChatGate.decide(.init(type: type, hasSymkey: false))
            XCTAssertFalse(verdict.canSend, "\(type)")
            XCTAssertTrue(verdict.showsComposer)
            XCTAssertNotEqual(verdict, .ownerNeedsKey(reason: verdict.reason ?? ""))
        }
    }

    /// An owner without the key has two ways out a member does not —
    /// make one, or ask the members who already hold it — so it is its
    /// own verdict rather than another blocked reason.
    func testOwnerWithoutTheKeyGetsTheOwnerFork() {
        for type in [ImType.team, .room] {
            let verdict = ChatGate.decide(
                .init(type: type, isMember: true, isOwner: true, hasSymkey: false)
            )
            guard case .ownerNeedsKey = verdict else {
                return XCTFail("\(type) owner should get the key fork, got \(verdict)")
            }
            XCTAssertFalse(verdict.canSend)
        }
    }

    /// **A square must never report a missing key.** It has none by
    /// design, and a prompt to go and fetch one would advertise a
    /// privacy the flavour does not have.
    func testSquareIgnoresAMissingSymkey() {
        XCTAssertEqual(ChatGate.decide(.init(type: .square, hasSymkey: false)), .open)
    }

    /// The DOCK is asked before the key: with nowhere to send, the key
    /// is not the thing standing in the way.
    func testDockIsCheckedBeforeTheKey() {
        let verdict = ChatGate.decide(
            .init(type: .room, isOwner: true, hasDock: false, hasSymkey: false)
        )
        XCTAssertTrue(verdict.reason?.contains("DOCK") == true)
    }

    // MARK: - declaresDock

    func testDeclaresDockMatchesAnyDockPrefixedKey() {
        XCTAssertTrue(ChatGate.declaresDock(home: ["DOCK": "https://dock.example"]))
        XCTAssertTrue(ChatGate.declaresDock(home: ["DOCK@No1_NrC7": "(sid)abc"]))
        // Services register their keys in either case, exactly as the
        // `API` key does in `HomeServiceResolver`.
        XCTAssertTrue(ChatGate.declaresDock(home: ["dock": "fudp://1.2.3.4:5678"]))
    }

    func testDeclaresDockRejectsEmptyAndAbsent() {
        XCTAssertFalse(ChatGate.declaresDock(home: nil))
        XCTAssertFalse(ChatGate.declaresDock(home: [:]))
        XCTAssertFalse(ChatGate.declaresDock(home: ["DOCK": "   "]))
        XCTAssertFalse(ChatGate.declaresDock(home: ["DISK": "https://disk.example"]))
    }
}
