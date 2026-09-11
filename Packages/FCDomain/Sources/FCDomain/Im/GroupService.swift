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
        /// Teams now waiting on this identity's `agree consensus`.
        /// Always zero for squares, which have no consensus to agree to.
        public let awaitingSignature: Int

        public init(
            merged: Int, joined: Int, left: Int, total: Int, awaitingSignature: Int = 0
        ) {
            self.merged = merged
            self.joined = joined
            self.left = left
            self.total = total
            self.awaitingSignature = awaitingSignature
        }
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

    /// One page-walking `base.search` over an entity where any of
    /// `fields` contains `fid`.
    ///
    /// `terms` rather than `equals`: the field is an array, and we are
    /// asking whether it *contains* our FID rather than whether it
    /// equals it. Several fields are OR'd — the server builds one
    /// `should` clause per field.
    func fetch<T: Decodable>(
        _ type: T.Type,
        entity: String,
        fid: String,
        fields: [String] = ["members"],
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
                "terms": ["fields": fields, "values": [fid]],
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

    /// Teams `fid` is in **or has been in**.
    ///
    /// `exMembers` is not nostalgia. A dismissal removes the member from
    /// `members`, so a query on `members` alone never returns that team
    /// to them again — the conversation stayed open, the composer kept
    /// offering to send, and nothing ever said they were out. Leaving by
    /// your own carve hid this, because the pane flags the thread when
    /// it broadcasts; being dismissed has no such moment. Android's sync
    /// has the same blind spot.
    public func fetchTeams(
        fid: String, newerThanHeight: Int64? = nil,
        pageSize: Int = 200, maxPages: Int = 200, timeoutMs: Int = 15_000
    ) async throws -> [Team] {
        try await fetch(
            Team.self, entity: "team", fid: fid, fields: ["members", "exMembers"],
            newerThanHeight: newerThanHeight,
            pageSize: pageSize, maxPages: maxPages, timeoutMs: timeoutMs
        )
    }

    /// Teams that invited `fid`, and teams being handed to it — the two
    /// lists Android's `JoinTeamActivity` reads.
    ///
    /// **Not written to ``TeamsStore``.** That store's highest
    /// `lastHeight` is the member sync's watermark, and a team we are
    /// merely invited to can carry a later height than a team we are in
    /// whose change has not been synced yet — storing it would step the
    /// watermark over that change for good.
    public func fetchTeamOffers(
        fid: String, pageSize: Int = 50, maxPages: Int = 4, timeoutMs: Int = 15_000
    ) async throws -> (invited: [Team], transfers: [Team]) {
        let invited = try await fetch(
            Team.self, entity: "team", fid: fid, fields: ["invitees"],
            newerThanHeight: nil, pageSize: pageSize, maxPages: maxPages, timeoutMs: timeoutMs
        )
        let transfers = try await fetch(
            Team.self, entity: "team", fid: fid, fields: ["transferee"],
            newerThanHeight: nil, pageSize: pageSize, maxPages: maxPages, timeoutMs: timeoutMs
        )
        return (invited, transfers)
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

    /// Teams whose name contains `term` — Android's "all teams" search.
    /// Read-only: finding a team is not being invited to it.
    public func searchTeams(
        named term: String, size: Int = 20, timeoutMs: Int = 15_000
    ) async throws -> [Team] {
        try await search(Team.self, entity: "team", field: "stdName", term: term, size: size, timeoutMs: timeoutMs)
    }

    /// Squares whose name contains `term` — Android's `JoinSquareActivity`.
    public func searchSquares(
        named term: String, size: Int = 20, timeoutMs: Int = 15_000
    ) async throws -> [Square] {
        try await search(Square.self, entity: "square", field: "name", term: term, size: size, timeoutMs: timeoutMs)
    }

    private func search<T: Decodable>(
        _ type: T.Type, entity: String, field: String, term: String, size: Int, timeoutMs: Int
    ) async throws -> [T] {
        let needle = term.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return [] }
        let dict: [String: Any] = [
            "entity": entity,
            "query": ["part": ["fields": [field], "value": needle]],
            "size": String(size),
        ]
        let body = try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
        let reply = try await fapi.call(
            api: "base.search",
            params: nil, fcdsl: body, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        if let code = resp.code, code != 0 {
            if code == 404 { return [] }
            throw Failure.fapiNonZeroCode(api: "base.search", code: code, message: resp.message)
        }
        guard let data = resp.data else { return [] }
        do {
            return try JSONDecoder().decode([T].self, from: data)
        } catch {
            throw Failure.underlying(error)
        }
    }

    /// Records by id, keyed by id. **An id missing from the answer is
    /// one the chain does not hold** — a 404 says that of all of them —
    /// which is different from a failed call, and the callers depend on
    /// the difference: a throw decides nothing.
    public func fetchByIds<T: Decodable>(
        _ type: T.Type, entity: String, ids: [String], timeoutMs: Int = 15_000
    ) async throws -> [String: T] {
        var found: [String: T] = [:]
        let unique = Array(Set(ids.filter { !$0.isEmpty })).sorted()
        var start = 0
        while start < unique.count {
            let chunk = Array(unique[start..<min(start + 100, unique.count)])
            start += chunk.count
            let body = try JSONSerialization.data(
                withJSONObject: ["entity": entity, "ids": chunk], options: [.sortedKeys]
            )
            let reply = try await fapi.call(
                api: DirectoryService.getByIdsApi,
                params: nil, fcdsl: body, binary: nil,
                sid: nil, via: nil, maxCost: nil,
                timeoutMs: timeoutMs
            )
            let resp = reply.response
            if let code = resp.code, code != 0 {
                if code == 404 { continue }
                throw Failure.fapiNonZeroCode(api: DirectoryService.getByIdsApi, code: code, message: resp.message)
            }
            guard let data = resp.data else { continue }
            let map: [String: T]
            do {
                map = try JSONDecoder().decode([String: T].self, from: data)
            } catch {
                throw Failure.underlying(error)
            }
            found.merge(map) { _, new in new }
        }
        return found
    }

    // MARK: - sync

    /// Pull `fid`'s teams and fold them into the store and the
    /// conversation list.
    ///
    /// **`signatures` is where a member finds out they owe one.** Pass
    /// it wherever a freshly-fetched team is stored — which is here, on
    /// every refresh path — and the "your team changed its consensus"
    /// prompt appears, disappears when the obligation is gone, and
    /// captures the outgoing `consensusId` at the only instant that
    /// value exists on this device. See ``ConsensusSignaturesStore``.
    @discardableResult
    public func syncTeams(
        fid: String,
        into store: TeamsStore,
        conversations: ConversationsStore? = nil,
        signatures: ConsensusSignaturesStore? = nil,
        incremental: Bool = true,
        timeoutMs: Int = 15_000
    ) async throws -> SyncResult {
        let watermark = incremental ? (try? store.highestKnownHeight()) ?? nil : nil
        let teams = try await fetchTeams(fid: fid, newerThanHeight: watermark, timeoutMs: timeoutMs)

        var merged = 0, joined = 0, left = 0, awaiting = 0
        for team in teams {
            guard let id = team.id, !id.isEmpty else { continue }
            // Read the row we are about to replace *first*: it carries
            // the consensus id the chain is discarding, and after the
            // upsert nothing anywhere holds it.
            let cached = try? store.get(id: id)
            try store.upsert(team)
            merged += 1

            if let signatures {
                let request = try? signatures.reconcile(team: team, cached: cached, as: fid)
                if let request, !request.isPostponed { awaiting += 1 }
            }

            guard let conversations else { continue }
            let belongs = team.isMember(fid) && team.isActive
            switch try updateConversation(
                id: Conversation.id(type: .team, targetId: id),
                type: .team, targetId: id,
                displayName: team.displayName,
                avatarDid: team.owner,
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
        return SyncResult(
            merged: merged, joined: joined, left: left,
            total: teams.count, awaitingSignature: awaiting
        )
    }

    /// Pull `fid`'s squares. Same shape as ``syncTeams(fid:into:conversations:signatures:incremental:timeoutMs:)``,
    /// with one field missing: a square has no `active`, because nobody
    /// owns one and so nobody can close one.
    ///
    /// **Then it asks after the squares it did not hear about.** The
    /// query is "squares whose members contain me", so a square left
    /// from another device — or deleted when its last member left — is
    /// never returned again, and the thread here stayed open as if
    /// nothing had happened. A square has no `exMembers` to query the
    /// way a team does, so every square this store still counts us in,
    /// and the query did not return, is read back by id. An id the
    /// chain does not hold is a square that no longer exists. A read
    /// that fails decides nothing: it is tried again next sync. Android
    /// has the same blind spot.
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
        func count(_ change: ConversationChange) {
            switch change {
            case .joined: joined += 1
            case .left: left += 1
            case .unchanged: break
            }
        }
        var returned: Set<String> = []
        for square in squares {
            guard let id = square.id, !id.isEmpty else { continue }
            returned.insert(id)
            try store.upsert(square)
            merged += 1
            guard let conversations else { continue }
            count(try fold(square, id: id, fid: fid, into: conversations))
        }

        let unheard = try store.joined(by: fid).compactMap(\.id).filter { !returned.contains($0) }
        if !unheard.isEmpty,
           let current = try? await fetchByIds(Square.self, entity: "square", ids: unheard, timeoutMs: timeoutMs) {
            for id in unheard {
                if var square = current[id] {
                    if square.id == nil || square.id?.isEmpty == true { square.id = id }
                    try store.upsert(square)
                    merged += 1
                    guard let conversations else { continue }
                    count(try fold(square, id: id, fid: fid, into: conversations))
                } else {
                    // Gone from the chain: the last member left, and the
                    // parser deletes an empty square.
                    try store.remove(id: id)
                    let conversationId = Conversation.id(type: .square, targetId: id)
                    if let conversations, var existing = try conversations.get(id: conversationId),
                       existing.leftGroup != true {
                        existing.leftGroup = true
                        try conversations.upsert(existing)
                        left += 1
                    }
                }
            }
        }
        return SyncResult(merged: merged, joined: joined, left: left, total: squares.count)
    }

    /// Put a square this identity is already in on the list, now —
    /// for a search that turns up a square we belong to and have no
    /// thread for. Returns the conversation id.
    @discardableResult
    public func adopt(_ square: Square, fid: String, into store: SquaresStore, conversations: ConversationsStore) throws -> String? {
        guard let id = square.id, !id.isEmpty, square.isMember(fid) else { return nil }
        try store.upsert(square)
        _ = try fold(square, id: id, fid: fid, into: conversations)
        return Conversation.id(type: .square, targetId: id)
    }

    private func fold(_ square: Square, id: String, fid: String, into conversations: ConversationsStore) throws -> ConversationChange {
        try updateConversation(
            id: Conversation.id(type: .square, targetId: id),
            type: .square, targetId: id,
            displayName: square.displayName,
            // A square has no owner to badge, so it badges whoever
            // named it last — not a role, just the member who most
            // recently outbid the standing coin-day price, and the
            // only one the chain singles out at all.
            avatarDid: square.namers?.last,
            memberNum: square.memberNum ?? Int64(square.members?.count ?? 0),
            createdAt: square.birthTime,
            belongs: square.isMember(fid),
            tCdd: square.tCdd, tRate: nil,
            in: conversations
        )
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
        /// The FID the avatar badges — a team's owner, a square's last
        /// namer. Not the avatar itself: the tile is drawn from
        /// `targetId`, so this changing repaints a badge and nothing more.
        avatarDid: String?,
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
            existing.avatarDid = avatarDid
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
        fresh.avatarDid = avatarDid
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
