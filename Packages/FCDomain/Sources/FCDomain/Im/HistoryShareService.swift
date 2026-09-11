import Foundation
import FCCore

/// The three things a person does with a history share — ask, approve,
/// and receive — over the stores ``HistoryShare`` describes.
///
/// Routing is ``SignalRouter``'s: it files an incoming ask for a person
/// and an answer for ``importReceived(as:retrying:now:)``. What is here is
/// everything that needs a key, a file, or the network.
///
/// **Both messages are sealed before they reach the outbox.** Android
/// seals every P2P body at its transport; this app's courier does not,
/// and the answer carries the file key in its content — so an answer in
/// the clear would be the whole transcript to anyone who can read a
/// DOCK. The ask is sealed too: which conversation someone wants, and
/// for when, is not nothing either.
public struct HistoryShareService {

    private let messages: MessagesStore
    private let conversations: ConversationsStore
    private let symkeys: SymkeyStore
    private let outbox: MessageQueue
    private let shares: HistorySharesStore
    private let files: FileVault
    private let hats: HatsStore
    private let sync: HatSyncService
    /// Where an export is written for as long as its upload takes.
    private let exportDirectory: URL

    public init(
        messages: MessagesStore,
        conversations: ConversationsStore,
        symkeys: SymkeyStore,
        outbox: MessageQueue,
        shares: HistorySharesStore,
        files: FileVault,
        hats: HatsStore,
        sync: HatSyncService,
        exportDirectory: URL
    ) {
        self.messages = messages
        self.conversations = conversations
        self.symkeys = symkeys
        self.outbox = outbox
        self.shares = shares
        self.files = files
        self.hats = hats
        self.sync = sync
        self.exportDirectory = exportDirectory
    }

    // MARK: - asking

    /// Ask `fid` for `conversation`'s messages in `[since, before)`, and
    /// remember the ask so the answer can be matched.
    ///
    /// `fid` may be **our own**: the ask then reaches every other device
    /// signed in as this identity, which is how a second Mac gets the
    /// first one's transcript — the same route
    /// ``KeyExchange/requests(entityId:kind:from:to:now:)`` uses for a key.
    @discardableResult
    public func ask(
        about conversation: Conversation,
        of fid: String,
        since: Int64,
        before: Int64,
        as liveFid: String,
        privkey: Data,
        recipientPubkey: Data,
        now: Date = Date()
    ) throws -> OutgoingHistoryRequest {
        guard before > since else { throw Failure.emptyRange }
        let nonce = HistoryShare.newNonce()
        let payload = HistoryRequestPayload(
            imType: conversation.type, targetId: conversation.targetId,
            since: since, before: before
        )

        var message = ImMessage.request(
            type: .p2p, from: liveFid, to: fid,
            requestType: .history, data: payload.json(), now: now
        ).named()
        message.requestId = nonce
        try message.sealBody(privkey: privkey, recipientPubkey: recipientPubkey)

        let ask = OutgoingHistoryRequest(
            nonce: nonce, askedFid: fid, conversationId: conversation.id,
            since: since, before: before, sentAt: Self.millis(now)
        )
        // Remembered first: an ask that left without being remembered
        // would have its answer thrown away as unsolicited.
        try shares.recordAsk(ask)
        do {
            try outbox.enqueue(message, in: Conversation.id(type: .p2p, targetId: fid), now: now)
        } catch {
            try? shares.removeAsk(nonce: nonce)
            throw error
        }
        return ask
    }

    // MARK: - approving

    /// How many messages an approval would hand over — said before the
    /// person agrees, because "share your history" means something very
    /// different at 3 messages and at 3 000.
    public func messageCount(for request: IncomingHistoryRequest) throws -> Int {
        try exportable(request).count
    }

    /// Export, upload and answer.
    ///
    /// Returns how many messages went. Nothing is sent for an empty
    /// range — it would cost a DISK upload to say nothing, and the
    /// request stays for the person to decline.
    ///
    /// **No copy is left behind.** The export is plaintext JSONL of a
    /// transcript that otherwise exists only inside the encrypted store,
    /// so the file is deleted once uploaded and so are the HAT records
    /// the upload made: nothing here needs them again, and the file key
    /// went to the asker.
    @discardableResult
    public func approve(
        _ request: IncomingHistoryRequest,
        as liveFid: String,
        privkey: Data,
        requesterPubkey: Data,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil,
        now: Date = Date()
    ) async throws -> Int {
        let rows = try exportable(request)
        guard !rows.isEmpty else { throw Failure.nothingInRange }

        let meta = HistoryExportMeta(
            fid: liveFid,
            exportTime: Self.millis(now),
            imType: request.type.rawValue,
            targetId: request.requestedTargetId,
            sinceTs: request.since,
            beforeTs: request.before,
            sharedTo: request.from
        )
        try FileManager.default.createDirectory(at: exportDirectory, withIntermediateDirectories: true)
        let url = exportDirectory.appendingPathComponent(
            HistoryShare.exportFileName(
                type: request.type, targetId: request.targetId, liveFid: liveFid,
                since: request.since, before: request.before
            )
        )
        try Data(HistoryFile.export(rows, meta: meta).utf8).write(to: url, options: .atomic)
        defer { try? FileManager.default.removeItem(at: url) }

        let registered = try files.registerFile(
            at: url, name: url.lastPathComponent,
            desc: "Message history shared with \(request.from)",
            types: ["application/x-ndjson"]
        )
        guard let hatId = registered.id else { throw Failure.exportNotRegistered }
        var cipherId: String?
        defer {
            _ = try? files.delete(hatId: hatId)
            if let cipherId { _ = try? hats.remove(id: cipherId) }
        }

        let ownPubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        let uploaded = try await sync.upload(hatId: hatId, ownPubkey: ownPubkey, progress: progress)
        cipherId = uploaded.cipherHat.id
        var shareable = try sync.shareableHat(from: uploaded)
        // Paths on this Mac name nothing on theirs.
        shareable.removeLocalLocas()

        var answer = ImMessage.history(
            type: .p2p, from: liveFid, to: request.from,
            hatJson: shareable.wireJson(), kCipher: nil, now: now
        ).named()
        answer.requestId = request.nonce
        try answer.sealBody(privkey: privkey, recipientPubkey: requesterPubkey)
        try outbox.enqueue(answer, in: Conversation.id(type: .p2p, targetId: request.from), now: now)

        try shares.removeIncoming(id: request.id)
        return rows.count
    }

    /// Say no. Nothing is sent — Android's Deny sends nothing either, and
    /// a refusal on the wire would only tell the asker to try someone
    /// else sooner.
    public func decline(_ request: IncomingHistoryRequest) throws {
        try shares.removeIncoming(id: request.id)
    }

    /// What an approval exports: the range, minus receipts (Android
    /// skips them too) and minus anything still held as a message
    /// request, which is not in the conversation yet.
    private func exportable(_ request: IncomingHistoryRequest) throws -> [ImMessage] {
        try messages.messages(in: request.conversationId, since: request.since, before: request.before)
            .filter { $0.contentType != .receipt && $0.status != .quarantined }
    }

    // MARK: - receiving

    public struct ImportResult: Equatable, Sendable {
        public let nonce: String
        public let from: String
        public let conversationId: String
        /// Nil when the attempt failed; see `error`.
        public let imported: Int?
        public let error: String?
    }

    /// Fetch and file every answer waiting.
    ///
    /// Run after each collect. A share that has failed
    /// ``ReceivedHistoryShare/automaticAttempts`` times is skipped unless
    /// `retrying` names it — that is a person pressing Retry.
    @discardableResult
    public func importReceived(
        as liveFid: String,
        retrying: String? = nil,
        now: Date = Date()
    ) async -> [ImportResult] {
        var results: [ImportResult] = []
        for var share in (try? shares.received()) ?? [] {
            guard !share.waitsForRetry || share.nonce == retrying else { continue }
            do {
                let count = try await fetchAndImport(share, as: liveFid)
                try? shares.removeReceived(nonce: share.nonce)
                results.append(.init(
                    nonce: share.nonce, from: share.from,
                    conversationId: share.conversationId, imported: count, error: nil
                ))
            } catch {
                share.attempts += 1
                share.lastError = String(describing: error)
                try? shares.recordReceived(share)
                results.append(.init(
                    nonce: share.nonce, from: share.from,
                    conversationId: share.conversationId, imported: nil, error: share.lastError
                ))
            }
        }
        return results
    }

    /// Forget an answer without importing it.
    public func dismiss(_ share: ReceivedHistoryShare) throws {
        try shares.removeReceived(nonce: share.nonce)
    }

    private func fetchAndImport(_ share: ReceivedHistoryShare, as liveFid: String) async throws -> Int {
        guard var offered = try? Hat.fromJson(share.hatJson), let hatId = offered.id, !hatId.isEmpty else {
            throw Failure.notAHat
        }
        guard !(offered.key ?? "").isEmpty else { throw Failure.noFileKey }
        offered.removeLocalLocas()

        // Merged the way a shared file is (``FileShareService/accept(_:)``)
        // — the download is by id, so the record has to be in the store.
        let existing = try hats.hat(id: hatId)
        if var existing {
            if existing.key == nil { existing.key = offered.key }
            for loca in offered.locas ?? [] { existing.addLoca(loca) }
            for cipherId in offered.cipherIds ?? [] { existing.addCipherId(cipherId) }
            try hats.upsert(existing)
        } else {
            try hats.upsert(offered)
        }
        // The same reasoning as the approver's cleanup: once filed, the
        // plaintext file is a second copy of the transcript outside the
        // encrypted store. Only a record this import created is removed.
        defer { if existing == nil { _ = try? files.delete(hatId: hatId) } }

        let url = try await sync.download(hatId: hatId)
        let text = try String(contentsOf: url, encoding: .utf8)
        return try importFile(text, share: share, as: liveFid)
    }

    /// File a history file's messages into the thread that was asked
    /// about, and nowhere else.
    ///
    /// A line naming any other conversation, or a time outside the range
    /// asked for, is skipped: the file was written by somebody else, and
    /// what we asked is the only part of this exchange we wrote. A
    /// message we already hold keeps our copy — it has our delivery
    /// facts on it, and theirs are no better.
    ///
    /// Imported rows are never unread. The thread's count is put back as
    /// it was, since ``ConversationsStore/record(_:myFid:)`` counts every
    /// incoming message and a backfill is not news.
    func importFile(_ jsonl: String, share: ReceivedHistoryShare, as liveFid: String) throws -> Int {
        var known = try messages.messageIds(in: share.conversationId)
        let unreadBefore = try conversations.get(id: share.conversationId)?.unreadCount ?? 0
        var imported = 0

        for line in HistoryFile.messages(in: jsonl) {
            guard line.hasFudpId, let id = line.id, !known.contains(id),
                  line.contentType != .receipt,
                  line.conversationId(for: liveFid) == share.conversationId,
                  let ts = line.timestamp, ts >= share.since, ts < share.before
            else { continue }

            var row = HistoryFile.stripped(line)
            row.status = .imported
            row.unread = false
            if row.isSealed, row.type == .team || row.type == .room, let entity = row.targetId {
                if (try? symkeys.open(&row, for: entity)) == true { row.body = nil }
            }
            try messages.put(row, in: share.conversationId)
            try conversations.record(row, myFid: liveFid)
            known.insert(id)
            imported += 1
        }

        if imported > 0 {
            try conversations.mutate(id: share.conversationId) { $0.unreadCount = unreadBefore }
        }
        return imported
    }

    // MARK: - helpers

    static func millis(_ date: Date) -> Int64 {
        Int64(date.timeIntervalSince1970 * 1000)
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case emptyRange
        case nothingInRange
        case exportNotRegistered
        case notAHat
        case noFileKey

        public var description: String {
            switch self {
            case .emptyRange:
                return "The start of the range has to be before its end."
            case .nothingInRange:
                return "This Mac holds no messages from that conversation in that range, so there is nothing to share. Decline it, or ask them for a different range."
            case .exportNotRegistered:
                return "The history export could not be registered for upload."
            case .notAHat:
                return "The history share does not point at a file."
            case .noFileKey:
                return "The history share carries no key to open the file with."
            }
        }
    }
}
