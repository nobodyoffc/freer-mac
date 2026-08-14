import Foundation
import FCCore
import FCTransport

/// On-chain sync for the two group flavours whose membership lives on
/// the chain — the port of Android's `TeamSyncManager` and
/// `SquareSyncManager`.
///
/// **The membership is not ours to decide.** Where ``RoomService`` spends
/// its length checking who is allowed to claim what, this does none of
/// that: `base.search` returns what the chain says, and the chain is the
/// arbiter. A peer cannot lie about a team's members because a peer is
/// not asked.
///
/// **The sort runs ascending here**, `lastHeight asc, id asc`, where
/// mail and contacts sort descending. That is not an inconsistency but a
/// different question: a mailbox sync wants the newest first and can
/// stop as soon as it reaches what it already has, while a group sync
/// resumes from a saved cursor and walks *forward* through everything
/// that changed since. Ascending plus a cursor is what makes "carry on
/// from where I stopped" mean anything.
///
/// **Leaving is not forgetting.** When the chain says we are no longer a
/// member, the conversation is kept and flagged
/// (``Conversation/leftGroup``) rather than deleted: the transcript is
/// ours, we paid to be there, and rejoining should not look like meeting
/// strangers.
public struct GroupService {

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "GroupService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "GroupService: \(e)"
            }
        }
    }

    public struct SyncResult: Equatable, Sendable {
        /// Rows written to the store.
        public let merged: Int
        /// Conversations opened for a group we are newly in.
        public let joined: Int
        /// Conversations flagged because the chain says we are out.
        public let left: Int
        public let total: Int
    }

    /// How far below the local watermark an incremental sync re-reads,
    /// to survive a reorg rewriting recent heights. Same window the mail
    /// and cash syncs use.
    public static let reorgWindow: Int64 = 30

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    // MARK: - fetch

    /// One page-walking `base.search` over an entity whose `members`
    /// field contains `fid`.
    ///
    /// `terms` rather than `equals`: the field is an array, and we are
    /// asking whether it *contains* our FID rather than whether it
    /// equals it.
    func fetch<T: Decodable>(
        _ type: T.Type,
        entity: String,
        fid: String,
        newerThanHeight: Int64?,
        pageSize: Int,
        maxPages: Int,
        timeoutMs: Int
    ) async throws -> [T] {
        var all: [T] = []
        var after: [String]? = nil
        let floor = newerThanHeight.map { max(0, $0 - Self.reorgWindow) }

        for _ in 0..<maxPages {
            // `terms` because `members` is an array — the question is
            // whether it *contains* our FID, not whether it equals it.
            var query: [String: Any] = [
                "terms": ["fields": ["members"], "values": [fid]],
            ]
            // Ascending order means an incremental sync cannot stop
            // early the way a descending walk can, so the watermark goes
            // to the server as a range floor instead. Same clause shape
            // the wallet's incremental refresh uses: a `fields` array
            // and a comparator, not a field-keyed object.
            if let floor {
                query["range"] = ["fields": ["lastHeight"], "gt": String(floor)]
            }
            var dict: [String: Any] = [
                "entity": entity,
                "query": query,
                "sort": [
                    ["field": "lastHeight", "order": "asc"],
                    ["field": "id",         "order": "asc"],
                ],
                "size": String(pageSize),
            ]
            if let after, !after.isEmpty { dict["after"] = after }

            let body = try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
            let reply = try await fapi.call(
                api: "base.search",
                params: nil, fcdsl: body, binary: nil,
                sid: nil, via: nil, maxCost: nil,
                timeoutMs: timeoutMs
            )
            let resp = reply.response
            if let code = resp.code, code != 0 {
                // 404 = no such rows. Normal for a FID in no groups.
                if code == 404 { break }
                throw Failure.fapiNonZeroCode(api: "base.search", code: code, message: resp.message)
            }
            guard let data = resp.data else { break }
            let page: [T]
            do {
                page = try JSONDecoder().decode([T].self, from: data)
            } catch {
                throw Failure.underlying(error)
            }
            all.append(contentsOf: page)

            if page.count < pageSize { break }
            guard let next = resp.last, !next.isEmpty else { break }
            after = next
        }
        return all
    }

    public func fetchTeams(
        fid: String, newerThanHeight: Int64? = nil,
        pageSize: Int = 200, maxPages: Int = 200, timeoutMs: Int = 15_000
    ) async throws -> [Team] {
        try await fetch(
            Team.self, entity: "team", fid: fid, newerThanHeight: newerThanHeight,
            pageSize: pageSize, maxPages: maxPages, timeoutMs: timeoutMs
        )
    }

    public func fetchSquares(
        fid: String, newerThanHeight: Int64? = nil,
        pageSize: Int = 200, maxPages: Int = 200, timeoutMs: Int = 15_000
    ) async throws -> [Square] {
        try await fetch(
            Square.self, entity: "square", fid: fid, newerThanHeight: newerThanHeight,
            pageSize: pageSize, maxPages: maxPages, timeoutMs: timeoutMs
        )
    }

    // MARK: - sync

    /// Pull `fid`'s teams and fold them into the store and the
    /// conversation list.
    @discardableResult
    public func syncTeams(
        fid: String,
        into store: TeamsStore,
        conversations: ConversationsStore? = nil,
        incremental: Bool = true,
        timeoutMs: Int = 15_000
    ) async throws -> SyncResult {
        let watermark = incremental ? (try? store.highestKnownHeight()) ?? nil : nil
        let teams = try await fetchTeams(fid: fid, newerThanHeight: watermark, timeoutMs: timeoutMs)

        var merged = 0, joined = 0, left = 0
        for team in teams {
            guard let id = team.id, !id.isEmpty else { continue }
            try store.upsert(team)
            merged += 1

            guard let conversations else { continue }
            let belongs = team.isMember(fid) && team.isActive
            switch try updateConversation(
                id: Conversation.id(type: .team, targetId: id),
                type: .team, targetId: id,
                displayName: team.displayName,
                memberNum: team.memberNum ?? Int64(team.members?.count ?? 0),
                createdAt: team.birthTime,
                belongs: belongs,
                tCdd: team.tCdd, tRate: team.tRate,
                in: conversations
            ) {
            case .joined: joined += 1
            case .left: left += 1
            case .unchanged: break
            }
        }
        return SyncResult(merged: merged, joined: joined, left: left, total: teams.count)
    }

    /// Pull `fid`'s squares. Same shape as ``syncTeams(fid:into:conversations:incremental:timeoutMs:)``,
    /// with one field missing: a square has no `active`, because nobody
    /// owns one and so nobody can close one.
    @discardableResult
    public func syncSquares(
        fid: String,
        into store: SquaresStore,
        conversations: ConversationsStore? = nil,
        incremental: Bool = true,
        timeoutMs: Int = 15_000
    ) async throws -> SyncResult {
        let watermark = incremental ? (try? store.highestKnownHeight()) ?? nil : nil
        let squares = try await fetchSquares(fid: fid, newerThanHeight: watermark, timeoutMs: timeoutMs)

        var merged = 0, joined = 0, left = 0
        for square in squares {
            guard let id = square.id, !id.isEmpty else { continue }
            try store.upsert(square)
            merged += 1

            guard let conversations else { continue }
            switch try updateConversation(
                id: Conversation.id(type: .square, targetId: id),
                type: .square, targetId: id,
                displayName: square.displayName,
                memberNum: square.memberNum ?? Int64(square.members?.count ?? 0),
                createdAt: square.birthTime,
                belongs: square.isMember(fid),
                tCdd: square.tCdd, tRate: nil,
                in: conversations
            ) {
            case .joined: joined += 1
            case .left: left += 1
            case .unchanged: break
            }
        }
        return SyncResult(merged: merged, joined: joined, left: left, total: squares.count)
    }

    private enum ConversationChange { case joined, left, unchanged }

    /// Open, update, or flag one group conversation.
    ///
    /// A conversation is opened only for a group we are *in*: a team
    /// that merely invited us, or one we have left, is a row in the
    /// group store and not a thread in the chat list. But once opened it
    /// is never closed — leaving flags ``Conversation/leftGroup`` and
    /// stops there.
    private func updateConversation(
        id: String,
        type: ImType,
        targetId: String,
        displayName: String?,
        memberNum: Int64,
        createdAt: Int64?,
        belongs: Bool,
        tCdd: Int64?,
        tRate: Double?,
        in conversations: ConversationsStore
    ) throws -> ConversationChange {
        if var existing = try conversations.get(id: id) {
            let wasIn = existing.leftGroup != true
            existing.displayName = displayName
            existing.memberNum = memberNum
            existing.tCdd = tCdd
            existing.tRate = tRate
            existing.leftGroup = !belongs
            try conversations.upsert(existing)
            if wasIn, !belongs { return .left }
            if !wasIn, belongs { return .joined }
            return .unchanged
        }
        guard belongs else { return .unchanged }

        var fresh = Conversation(id: id, targetId: targetId, type: type)
        fresh.displayName = displayName
        fresh.memberNum = memberNum
        fresh.tCdd = tCdd
        fresh.tRate = tRate
        fresh.leftGroup = false
        fresh.unreadCount = 0
        fresh.createdAt = createdAt
        // `lastActiveAt` is left unset on purpose: nothing has been said
        // in this thread yet, and stamping the chain's birth time here
        // would sort a decade-old team above this morning's chat.
        try conversations.upsert(fresh)
        return .joined
    }
}
