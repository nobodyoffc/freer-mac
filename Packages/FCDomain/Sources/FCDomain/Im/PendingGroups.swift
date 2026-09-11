import Foundation
import FCStorage

/// A team or square this identity has broadcast a carve for and the
/// chain has not shown yet — Android's "pending" rows at the top of its
/// team and square lists.
///
/// **Why a row at all.** Creating, joining or taking over is paid for the
/// moment it is broadcast, and then nothing happens on screen until the
/// transaction confirms *and* the list is refreshed — which reads exactly
/// like a carve that did nothing. A row saying "waiting for the chain",
/// with the txid, is the difference.
///
/// **Not a conversation.** Nothing can be said in a group the chain does
/// not yet list us in, so these are kept apart from ``ConversationsStore``
/// rather than being threads with a composer that has to explain itself.
/// A row goes away on its own once the chain shows the act landed.
public struct PendingGroup: Codable, Equatable, Sendable, Identifiable {

    public enum Act: String, Codable, Sendable {
        case create
        case join
        case takeOver
    }

    public var fid: String
    public var type: ImType
    /// The group's id. For a `create` this is the carve's own txid,
    /// which is what the indexer names the new group.
    public var groupId: String
    public var name: String?
    public var act: Act
    public var txid: String
    /// Epoch ms.
    public var broadcastAt: Int64

    public var id: String { PendingGroupsStore.key(fid: fid, type: type, groupId: groupId) }

    public init(
        fid: String, type: ImType, groupId: String, name: String?,
        act: Act, txid: String, broadcastAt: Int64
    ) {
        self.fid = fid
        self.type = type
        self.groupId = groupId
        self.name = name
        self.act = act
        self.txid = txid
        self.broadcastAt = broadcastAt
    }

    /// Long enough that a carve which should have confirmed has not.
    /// Blocks come every minute; a day without one is a failed or
    /// rejected transaction, and the row says so instead of waiting on.
    public func isOverdue(now: Date) -> Bool {
        Int64(now.timeIntervalSince1970 * 1000) - broadcastAt >= PendingGroupsStore.overdueMs
    }
}

public struct PendingGroupsStore {

    public static let namespace = "im.groups.pending.v1"
    public static let overdueMs: Int64 = 24 * 60 * 60 * 1000

    private let inner: TypedStore<PendingGroup>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    static func key(fid: String, type: ImType, groupId: String) -> String {
        "\(fid)|\(type.rawValue)|\(groupId)"
    }

    public func record(_ pending: PendingGroup) throws {
        guard !pending.groupId.isEmpty, !pending.fid.isEmpty else { throw GroupStoreFailure.noId }
        try inner.put(pending, key: pending.id)
    }

    /// Oldest first, for one identity and one flavour.
    public func all(fid: String, type: ImType) throws -> [PendingGroup] {
        try inner.all().map(\.value)
            .filter { $0.fid == fid && $0.type == type }
            .sorted { $0.broadcastAt < $1.broadcastAt }
    }

    @discardableResult
    public func remove(_ pending: PendingGroup) throws -> Bool {
        guard try inner.exists(pending.id) else { return false }
        try inner.delete(pending.id)
        return true
    }

    /// Drop the rows whose act the local stores now show as done: a
    /// create or a join once the group's thread is open and not left, a
    /// take-over once we own the team. Returns how many were cleared.
    ///
    /// The thread is asked as well as the record for a join, because a
    /// square left from this Mac is still listed with us in it until the
    /// next sync — and rejoining it must not look done before it is.
    @discardableResult
    public func reconcile(
        fid: String, teams: TeamsStore, squares: SquaresStore, conversations: ConversationsStore
    ) throws -> Int {
        func threadOpen(_ type: ImType, _ id: String) throws -> Bool {
            guard let thread = try conversations.get(id: Conversation.id(type: type, targetId: id)) else {
                return false
            }
            return thread.leftGroup != true
        }
        var cleared = 0
        for pending in try inner.all().map(\.value) where pending.fid == fid {
            let done: Bool
            switch (pending.type, pending.act) {
            case (.team, .takeOver):
                done = (try teams.get(id: pending.groupId))?.isOwner(fid) ?? false
            case (.team, _):
                let member = (try teams.get(id: pending.groupId))?.isMember(fid) ?? false
                done = try member && threadOpen(.team, pending.groupId)
            case (.square, _):
                let member = (try squares.get(id: pending.groupId))?.isMember(fid) ?? false
                done = try member && threadOpen(.square, pending.groupId)
            case (.p2p, _), (.room, _):
                // Neither is carved, so neither is ever pending.
                done = true
            }
            if done {
                try inner.delete(pending.id)
                cleared += 1
            }
        }
        return cleared
    }
}

/// Why a square join was refused before it was paid for.
public enum SquareJoinFailure: Error, Equatable, CustomStringConvertible {
    case noSuchSquare(String)
    case alreadyAMember(String)

    public var description: String {
        switch self {
        case .noSuchSquare:
            return "The chain has no square with this id. It may not have confirmed yet, or the id is mistyped."
        case .alreadyAMember:
            return "You are already a member of this square. A second join would be paid for and ignored."
        }
    }
}
