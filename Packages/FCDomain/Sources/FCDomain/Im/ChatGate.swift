import Foundation

/// Whether this identity may send into this conversation, and if not,
/// what to say about it — the decision half of Android's
/// `ChatActivity.setupGroupState` / `isOwnerOrMember` /
/// `checkGroupHasDock` / `hideInputForNonMember`, lifted out of the view
/// the same way ``DeliveryPolicy`` was lifted out of the sending code.
///
/// **The four flavours differ here more than anywhere else**, which is
/// why this is a decision and not a view condition. A P2P chat needs
/// nothing but a key to sign with. A square needs membership. A team and
/// a room need membership *and* a symkey, and when the key is the thing
/// missing the answer depends on who is asking: an owner can make one,
/// while a member can only go and ask for it.
///
/// The previous pane checked `leftGroup` and nothing else, so it was
/// possible to type a message into a team this identity does not belong
/// to and discover the problem when ``ChatService`` refused to seal it.
/// A composer that accepts text it cannot send is worse than one that
/// says why up front, and every reason below is a different fix.
///
/// Facts in, verdict out: no stores, no clock, no network, so each
/// branch is a test with no fixtures.
public enum ChatGate {

    /// What the caller knows about this conversation right now.
    ///
    /// Every field is a stated fact rather than a source to consult, so
    /// a verdict is always traceable to one of them — and gathering them
    /// (which needs the room, team, square and symkey stores) stays out
    /// of the rule.
    public struct Facts: Equatable, Sendable {
        public var type: ImType
        /// Whether this identity holds the private key. A watch-only or
        /// unlocked-for-reading session cannot seal anything.
        public var canSign: Bool
        /// Owner counts as a member; ``isOwner`` is the finer question.
        public var isMember: Bool
        public var isOwner: Bool
        /// The chain (team, square) or the owner (room) says we are out.
        public var leftGroup: Bool
        /// Whether the group publishes a DOCK in its `home` map. Ignored
        /// for P2P, which travels to the *recipient's* DOCK.
        public var hasDock: Bool
        /// Whether ``SymkeyStore`` holds a key for this entity. Ignored
        /// where no key is required.
        public var hasSymkey: Bool

        public init(
            type: ImType,
            canSign: Bool = true,
            isMember: Bool = true,
            isOwner: Bool = false,
            leftGroup: Bool = false,
            hasDock: Bool = true,
            hasSymkey: Bool = true
        ) {
            self.type = type
            self.canSign = canSign
            self.isMember = isMember
            self.isOwner = isOwner
            self.leftGroup = leftGroup
            self.hasDock = hasDock
            self.hasSymkey = hasSymkey
        }
    }

    /// What the composer should do.
    ///
    /// The difference between ``blocked(reason:)`` and
    /// ``notMember(reason:)`` is deliberate and comes straight from
    /// Android: a blocked composer is *this conversation is not ready*,
    /// so it stays on screen greyed out with the reason under it, while
    /// a non-member's composer is removed entirely — there is no message
    /// to write and no state in which writing one would help.
    public enum Verdict: Equatable, Sendable {
        case open
        /// Composer visible and disabled, with `reason` under it.
        case blocked(reason: String)
        /// Composer gone. The transcript stays: we were there once, and
        /// the history is ours.
        case notMember(reason: String)
        /// A team or room whose owner holds no key. Composer disabled,
        /// with the two ways out — make one, or ask the members who
        /// already have it.
        case ownerNeedsKey(reason: String)

        public var canSend: Bool { self == .open }

        /// Whether the composer is drawn at all.
        public var showsComposer: Bool {
            if case .notMember = self { return false }
            return true
        }

        public var reason: String? {
            switch self {
            case .open: return nil
            case .blocked(let r), .notMember(let r), .ownerNeedsKey(let r): return r
            }
        }
    }

    /// Whether a flavour's traffic is sealed with a group symkey.
    ///
    /// A square is **not** on this list and that is the whole point of a
    /// square: anyone may join, so a key shared with everyone who asks
    /// is a formality implying a privacy the square does not have.
    public static func requiresSymkey(_ type: ImType) -> Bool {
        switch type {
        case .team, .room: return true
        case .p2p, .square: return false
        }
    }

    /// Android's `checkGroupHasDock`: a `home` map counts as publishing
    /// a DOCK when it carries a non-empty `DOCK`-prefixed key.
    ///
    /// The prefix rather than an exact match, because a `home` may name
    /// several (`DOCK@…`) and any one of them is somewhere to collect
    /// from. Note this asks only what the group *claims* — whether that
    /// value resolves to a reachable server is ``DockRegistry``'s
    /// question, and a transient SID lookup failure must not silence a
    /// conversation that is otherwise fine.
    public static func declaresDock(home: [String: String]?) -> Bool {
        guard let home else { return false }
        return home.contains { key, value in
            key.uppercased().hasPrefix("DOCK") && !value.trimmingCharacters(in: .whitespaces).isEmpty
        }
    }

    public static func decide(_ facts: Facts) -> Verdict {
        // Before anything about membership: without a private key there
        // is nothing to seal a message with, in any flavour.
        guard facts.canSign else {
            return .blocked(reason: "This identity is unlocked for reading only. Unlock it to send.")
        }

        // A P2P chat asks nobody's permission. Having no DOCK of our own
        // stops us *receiving* replies, not sending — which is why
        // Android leaves the composer enabled and says so in a notice
        // instead, and why a newcomer with no server yet can still ask
        // for their first coins.
        guard facts.type != .p2p else { return .open }

        let noun = facts.type.rawValue.lowercased()

        if facts.leftGroup {
            return .notMember(
                reason: "You are not in this \(noun) any more. The transcript stays; sending does not."
            )
        }
        if !facts.isMember {
            return .notMember(reason: notMemberReason(facts.type))
        }
        if !facts.hasDock {
            return .blocked(reason: noDockReason(facts.type))
        }
        if Self.requiresSymkey(facts.type), !facts.hasSymkey {
            if facts.isOwner {
                return .ownerNeedsKey(
                    reason: "This \(noun) has no key on this device. Generate one, or ask a member for the key they hold."
                )
            }
            return .blocked(
                reason: "Waiting for this \(noun)'s key. Until it arrives nothing here can be sealed or read."
            )
        }
        return .open
    }

    // MARK: - wording

    /// Why we cannot write here, and — since the three flavours are
    /// joined in three different ways — what joining would mean.
    private static func notMemberReason(_ type: ImType) -> String {
        switch type {
        case .team:
            return "You are not a member of this team. Membership is on the chain: joining is a transaction, and who is in it is public."
        case .square:
            return "You are not a member of this square. Anyone may join, and joining is a transaction."
        case .room:
            return "You are not a member of this room. A room is invitation-only, and only its owner can add you."
        case .p2p:
            return "This chat is not open."
        }
    }

    private static func noDockReason(_ type: ImType) -> String {
        switch type {
        case .team:
            return "This team publishes no DOCK server, so there is nowhere for its messages to rest. Its owner has to set one."
        case .square:
            return "This square publishes no DOCK server, so there is nowhere for its messages to rest."
        case .room:
            return "This room publishes no DOCK server, so there is nowhere for its messages to rest. Its owner has to set one."
        case .p2p:
            return "No DOCK."
        }
    }
}
