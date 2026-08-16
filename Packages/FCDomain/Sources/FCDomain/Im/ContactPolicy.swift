import Foundation
import FCStorage

/// Who is allowed to start a conversation with this identity.
///
/// **Until now, anybody was.** Every inbound P2P message was filed
/// straight into the transcript and put a row in the thread list, from
/// any FID that knew ours — no filter, no queue, nothing to say no to.
/// An FID is public by construction, so that is an open door.
///
/// Android runs every inbound P2P message through this gate
/// (`ImManager.handleIncoming`), and its shape is worth keeping exactly:
/// an unknown sender's message is **held**, not dropped and not
/// delivered. Dropping it would silently lose a first contact from
/// someone perfectly legitimate — which is most of them — while
/// delivering it hands a stranger a row in the list they can keep
/// writing into. Held is the only honest third answer.
///
/// **Group traffic never comes through here.** A square is open by
/// definition, and being in a team or a room already means the
/// conversation was accepted; filtering those by sender would mean
/// quarantining half of a group chat's messages one member at a time.
public struct ContactPolicy: Codable, Equatable, Sendable {

    /// What to do about someone we have never heard from.
    ///
    /// The raw values match Android's enum so the two can be compared
    /// or exported without translation; the case names say what the
    /// setting actually does, which in one case Android's does not.
    /// `ACCEPT_ALL` still holds a stranger's first message and asks —
    /// it does not accept it — so here it is called what it is.
    public enum Strategy: String, Codable, CaseIterable, Sendable, Identifiable {
        /// Hold a stranger's messages and ask about them. The default.
        case askAboutStrangers = "ACCEPT_ALL"
        /// Hold them, but only ask about people already in Contacts —
        /// in practice, deliver contacts and hold everyone else quietly.
        case contactsOnly = "CONTACTS_ONLY"
        /// Nobody gets through who is not explicitly allowed.
        case whitelistOnly = "WHITELIST_ONLY"
        /// Hold everything from everyone new, and never ask.
        case acceptNone = "ACCEPT_NONE"

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .askAboutStrangers: return "Ask me about strangers"
            case .contactsOnly:      return "Contacts get through"
            case .whitelistOnly:     return "Only people I've allowed"
            case .acceptNone:        return "Nobody new"
            }
        }

        public var detail: String {
            switch self {
            case .askAboutStrangers:
                return "A first message from an unknown FID is held as a request and you are asked about it."
            case .contactsOnly:
                return "Someone already in Contacts is let through on their first message. Everyone else is held quietly."
            case .whitelistOnly:
                return "Only FIDs you have accepted before get through. Everyone else is held quietly."
            case .acceptNone:
                return "Everything from someone new is held. Nothing is ever accepted automatically."
            }
        }
    }

    /// What should happen to one inbound message.
    ///
    /// ``acceptAndDeliver`` is separate from ``deliver`` so that
    /// whitelisting a sender for the first time is a decision this rule
    /// makes, and not a side effect the caller has to remember —
    /// Android's `acceptStranger` is exactly that side effect.
    public enum Decision: Equatable, Sendable {
        /// A known sender. File it.
        case deliver
        /// A first message from someone the policy lets in: remember
        /// them, then file it.
        case acceptAndDeliver
        /// Hold it as a message request. `prompt` asks the UI to raise
        /// this now rather than only badging it.
        case hold(prompt: Bool)
        /// Blacklisted: nothing is kept and nothing is shown.
        case drop
    }

    public var strategy: Strategy
    /// FIDs whose messages go straight through. Our own FID is always
    /// here — a note to self is not a stranger.
    public var whitelist: Set<String>
    /// FIDs whose messages are discarded on arrival.
    public var blacklist: Set<String>

    public init(
        strategy: Strategy = .askAboutStrangers,
        whitelist: Set<String> = [],
        blacklist: Set<String> = []
    ) {
        self.strategy = strategy
        self.whitelist = whitelist
        self.blacklist = blacklist
    }

    /// The gate. `isContact` is asked of the address book by the caller,
    /// because this type has no business reaching into another store.
    public func decide(sender: String, isContact: Bool) -> Decision {
        // Blacklist first, and it beats everything — including being a
        // contact, since blocking someone you know is the main reason to
        // block anyone.
        if blacklist.contains(sender) { return .drop }
        if whitelist.contains(sender) { return .deliver }

        switch strategy {
        case .askAboutStrangers:
            return isContact ? .acceptAndDeliver : .hold(prompt: true)
        case .contactsOnly:
            return isContact ? .acceptAndDeliver : .hold(prompt: false)
        case .whitelistOnly, .acceptNone:
            // A contact who has never written is still someone we have
            // not agreed to hear from under these two settings, which is
            // the whole point of choosing them.
            return .hold(prompt: false)
        }
    }

    // MARK: - list edits

    /// Allowing someone un-blocks them. Holding both at once is a state
    /// with no meaning, and the last thing the user said should win.
    public mutating func allow(_ fid: String) {
        whitelist.insert(fid)
        blacklist.remove(fid)
    }

    public mutating func block(_ fid: String) {
        blacklist.insert(fid)
        whitelist.remove(fid)
    }

    public mutating func unblock(_ fid: String) {
        blacklist.remove(fid)
    }

    public func isAllowed(_ fid: String) -> Bool { whitelist.contains(fid) }
    public func isBlocked(_ fid: String) -> Bool { blacklist.contains(fid) }
}

/// Where the policy is kept.
///
/// One row, not one per entry: the lists are human-scale, they are read
/// on every inbound message, and loading them as a unit means the gate
/// costs one decrypt instead of one per FID. Android keeps a row per
/// entry and then holds the whole thing in three in-memory caches, which
/// is the same answer arrived at twice.
public struct ContactPolicyStore {

    public static let namespace = "im.policy.v1"
    private static let key = "policy"

    private let inner: TypedStore<ContactPolicy>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    /// The stored policy, with `liveFid` whitelisted.
    ///
    /// Whitelisting ourselves on every load rather than once at setup:
    /// the identity a session runs as can change, and a note to self
    /// arriving as a message request would be a puzzle with no good
    /// explanation.
    public func load(liveFid: String?) throws -> ContactPolicy {
        var policy = try inner.get(Self.key) ?? ContactPolicy()
        if let liveFid, !liveFid.isEmpty { policy.whitelist.insert(liveFid) }
        return policy
    }

    public func save(_ policy: ContactPolicy) throws {
        try inner.put(policy, key: Self.key)
    }

    /// Read, change, write — so a caller cannot lose a concurrent edit
    /// to the other list by writing back a stale copy.
    @discardableResult
    public func mutate(
        liveFid: String?, _ change: (inout ContactPolicy) -> Void
    ) throws -> ContactPolicy {
        var policy = try load(liveFid: liveFid)
        change(&policy)
        try save(policy)
        return policy
    }
}
