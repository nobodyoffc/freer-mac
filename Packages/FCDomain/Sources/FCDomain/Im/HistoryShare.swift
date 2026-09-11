import Foundation
import FCStorage

/// Asking another member for a conversation's messages, and handing them
/// over — the port of Android's `ImManager.requestHistory`,
/// `approveHistoryRequest` and `importConversation`.
///
/// The exchange is three P2P messages' worth of protocol and one file:
///
/// 1. **Ask.** A `REQUEST` of type `HISTORY` whose content is
///    `{"imType","targetId","since","before"}` and whose `requestId` is a
///    nonce the asker remembers.
/// 2. **Approve.** A person on the other side agrees. Their client
///    exports the range as JSONL — an ``HistoryExportMeta`` line, then one
///    ``ImMessage/wireJson()`` per message — uploads it to their DISK
///    under a fresh file key, and answers with a `HISTORY` message whose
///    content is the HAT *with that key in it* and whose `requestId`
///    echoes the nonce.
/// 3. **Import.** The asker matches the nonce, fetches and decrypts the
///    file, and files each message as ``MessageStatus/imported``.
///
/// **Three things here are deliberately stricter than Android**, and each
/// is a hole rather than a style choice:
///
/// - **P2P names the wrong thread on Android.** A P2P ask's `targetId` is
///   the conversation as the *asker* sees it, which is the responder's own
///   FID. Android's responder looks that id up directly and exports its
///   note-to-self thread instead of the conversation with the asker.
///   ``HistoryRequestPayload/responderConversation(requester:as:)`` turns
///   it round.
/// - **An import may only fill the thread that was asked about.** Android
///   files each line under whatever conversation the line itself names,
///   so an answer could plant messages in any thread on the asker's
///   device. Here a line naming any other conversation is skipped.
/// - **The asks survive a restart.** Android keeps its nonces in memory,
///   so an answer that arrives after the app was closed — the ordinary
///   case, since a person has to approve it — is thrown away as
///   unsolicited. Here they are stored, as is an incoming ask waiting for
///   a person, for the reason ``RoomInvite`` gives.
public enum HistoryShare {

    /// How long an unanswered ask is remembered. Longer than a DOCK
    /// holds anything, so an answer that could still arrive is still
    /// matched; short enough that a list of forgotten asks does not
    /// accumulate forever.
    public static let askLifetimeMs: Int64 = 30 * 24 * 60 * 60 * 1000

    /// A fresh nonce, shaped like Android's `generateSymkeyNonce` — 16
    /// hex characters.
    public static func newNonce() -> String {
        (0..<8).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
    }

    /// The file name Android gives an export:
    /// `<type>_<a>_<b>_<since>_<before>.imhist` for P2P (the two FIDs in
    /// order, so both sides name the same thread the same way) and
    /// `<type>_<target>_<since>_<before>.imhist` otherwise.
    public static func exportFileName(
        type: ImType, targetId: String, liveFid: String, since: Int64, before: Int64
    ) -> String {
        let who: String
        if type == .p2p {
            who = [liveFid, targetId].sorted().joined(separator: "_")
        } else {
            who = targetId
        }
        return "\(type.rawValue.lowercased())_\(who)_\(since)_\(before).imhist"
    }
}

// MARK: - the ask

/// What a `HISTORY` request's content says.
///
/// `targetId` is the conversation **as the asker sees it**: a group's id,
/// or for P2P the FID the asker is talking to. That is Android's shape,
/// and it is why a P2P responder has to turn it round before looking
/// anything up — see ``responderConversation(requester:as:)``.
public struct HistoryRequestPayload: Equatable, Sendable {
    public var imType: ImType
    public var targetId: String
    /// Inclusive, milliseconds.
    public var since: Int64
    /// Exclusive, milliseconds — Android's `getMessages` drops
    /// `ts >= before`.
    public var before: Int64

    public init(imType: ImType, targetId: String, since: Int64, before: Int64) {
        self.imType = imType
        self.targetId = targetId
        self.since = since
        self.before = before
    }

    /// Android builds this from a `HashMap`, so its key order is whatever
    /// the hash says and nothing on either side depends on it. Sorted
    /// keys are the reproducible choice.
    public func json() -> String {
        GsonCompatibleWriter.object([
            ("before", .int(before)),
            ("imType", .string(imType.rawValue)),
            ("since", .int(since)),
            ("targetId", .string(targetId)),
        ], htmlSafe: false)
    }

    /// Read a request's content. Nil for anything that is not one.
    ///
    /// Numbers are taken however they arrive: Gson reads a `HashMap`'s
    /// numbers back as doubles, and a client that round-trips one could
    /// write `1.7551E12`.
    public static func parse(_ content: String?) -> HistoryRequestPayload? {
        guard let content, let data = content.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let typeName = object["imType"] as? String,
              let type = ImType(javaName: typeName),
              let targetId = object["targetId"] as? String, !targetId.isEmpty
        else { return nil }
        let since = (object["since"] as? NSNumber)?.int64Value ?? 0
        let before = (object["before"] as? NSNumber)?.int64Value ?? Int64.max
        guard before > since else { return nil }
        return HistoryRequestPayload(imType: type, targetId: targetId, since: since, before: before)
    }

    /// The conversation on **this** device that the ask is about, or nil
    /// when the asker has no part in it.
    ///
    /// - A group is the group.
    /// - P2P from somebody else names *us* as its target, and the thread
    ///   is the one with them. A P2P ask from somebody else naming a
    ///   third party is refused: a conversation between us and Carol is
    ///   not Bob's to ask for.
    /// - P2P from **our own FID** is our other device, which is in every
    ///   thread we are in, so its target is taken as named.
    ///
    /// Whether the asker is actually in a *group* is not decided here —
    /// that needs the group's record, which ``SignalRouter`` holds.
    public func responderConversation(requester: String, as liveFid: String) -> (type: ImType, targetId: String)? {
        guard imType == .p2p else { return (imType, targetId) }
        if requester == liveFid { return (.p2p, targetId) }
        guard targetId == liveFid else { return nil }
        return (.p2p, requester)
    }
}

// MARK: - the file

/// The first line of an export — Android's `ExportMeta`, in its field
/// order, nulls omitted.
///
/// Written by the side that exported and read back only to recognise
/// the line as not-a-message: an importer takes the thread it files into
/// from its own record of what it asked, never from this, because this
/// was written by the other side.
public struct HistoryExportMeta: Equatable, Sendable {
    public var version: String = "1.0"
    public var fid: String
    public var exportTime: Int64
    public var count: Int?
    public var appName: String = "Freer"
    public var entityType: String = "imMessage"
    public var imType: String?
    public var targetId: String?
    public var sinceTs: Int64?
    public var beforeTs: Int64?
    public var sharedTo: String?

    public init(
        fid: String, exportTime: Int64, count: Int? = nil,
        imType: String? = nil, targetId: String? = nil,
        sinceTs: Int64? = nil, beforeTs: Int64? = nil, sharedTo: String? = nil
    ) {
        self.fid = fid
        self.exportTime = exportTime
        self.count = count
        self.imType = imType
        self.targetId = targetId
        self.sinceTs = sinceTs
        self.beforeTs = beforeTs
        self.sharedTo = sharedTo
    }

    public func json() -> String {
        var fields: [(String, GsonCompatibleWriter.Value)] = [
            ("version", .string(version)),
            ("fid", .string(fid)),
            ("exportTime", .int(exportTime)),
        ]
        if let count { fields.append(("count", .int(Int64(count)))) }
        fields.append(("appName", .string(appName)))
        fields.append(("entityType", .string(entityType)))
        if let imType { fields.append(("imType", .string(imType))) }
        if let targetId { fields.append(("targetId", .string(targetId))) }
        if let sinceTs { fields.append(("sinceTs", .int(sinceTs))) }
        if let beforeTs { fields.append(("beforeTs", .int(beforeTs))) }
        if let sharedTo { fields.append(("sharedTo", .string(sharedTo))) }
        return GsonCompatibleWriter.object(fields, htmlSafe: false)
    }

    /// Android's own test for the line: a JSON object carrying both
    /// `version` and `entityType`. No message has either field.
    static func isMetaLine(_ line: String) -> Bool {
        guard let data = line.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return false }
        return object["version"] is String && object["entityType"] is String
    }
}

public enum HistoryFile {

    /// The JSONL an approver uploads: the meta line, then one message
    /// per line, oldest first.
    ///
    /// **What describes our relationship to a message is left out** —
    /// status, when it reached us, which DOCK held it, whether we read
    /// it. The same rule ``ImMessage/toWireBytes()`` follows: those are
    /// this device's facts, and the importer marks every row imported
    /// anyway. A body we opened travels open and without its cipher,
    /// since the file is encrypted as a whole and the cipher would be a
    /// second copy of the same words.
    public static func export(_ messages: [ImMessage], meta: HistoryExportMeta) -> String {
        var lines = [meta.json()]
        for message in messages {
            lines.append(stripped(message).wireJson())
        }
        return lines.joined(separator: "\n") + "\n"
    }

    static func stripped(_ message: ImMessage) -> ImMessage {
        var out = message
        if out.content != nil || out.data != nil { out.body = nil }
        out.status = nil
        out.sequence = nil
        out.roadIds = nil
        out.dockId = nil
        out.deliveryMethod = nil
        out.deliveredAt = nil
        out.readAt = nil
        out.unread = nil
        return out
    }

    /// The messages in a history file. The meta line and anything that
    /// does not decode are skipped rather than failing the file — a
    /// newer client's line is not a reason to lose the rest.
    public static func messages(in jsonl: String) -> [ImMessage] {
        jsonl.split(whereSeparator: \.isNewline).compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !HistoryExportMeta.isMetaLine(line) else { return nil }
            return try? ImMessage.fromJson(line)
        }
    }
}

// MARK: - what is waiting

/// An ask we sent and have not had answered.
public struct OutgoingHistoryRequest: Codable, Equatable, Sendable, Identifiable {
    /// The `requestId` the answer must echo.
    public var nonce: String
    /// Who was asked. An answer from anybody else is not an answer.
    public var askedFid: String
    /// The thread on this device the answer fills.
    public var conversationId: String
    public var since: Int64
    public var before: Int64
    public var sentAt: Int64

    public var id: String { nonce }

    public init(nonce: String, askedFid: String, conversationId: String, since: Int64, before: Int64, sentAt: Int64) {
        self.nonce = nonce
        self.askedFid = askedFid
        self.conversationId = conversationId
        self.since = since
        self.before = before
        self.sentAt = sentAt
    }
}

/// Somebody asked us, and a person has to say yes.
public struct IncomingHistoryRequest: Codable, Equatable, Sendable, Identifiable {
    public var nonce: String
    public var from: String
    /// The thread on **this** device, already turned round for P2P.
    public var type: ImType
    public var targetId: String
    public var since: Int64
    public var before: Int64
    public var receivedAt: Int64
    /// The ask's content exactly as it arrived, echoed in the export's
    /// meta line so the asker's client sees its own words.
    public var requestedTargetId: String

    /// Keyed by asker *and* nonce: the nonce is the asker's to choose,
    /// so on its own it would let one asker overwrite another's ask.
    public var id: String { from + "|" + nonce }

    public var conversationId: String { Conversation.id(type: type, targetId: targetId) }

    public init(
        nonce: String, from: String, type: ImType, targetId: String,
        since: Int64, before: Int64, receivedAt: Int64, requestedTargetId: String
    ) {
        self.nonce = nonce
        self.from = from
        self.type = type
        self.targetId = targetId
        self.since = since
        self.before = before
        self.receivedAt = receivedAt
        self.requestedTargetId = requestedTargetId
    }
}

/// An answer that matched one of our asks, waiting to be fetched and
/// filed. Routing a signal is synchronous and fetching a file is not, so
/// the two are split by this row.
public struct ReceivedHistoryShare: Codable, Equatable, Sendable, Identifiable {
    public var nonce: String
    public var from: String
    public var conversationId: String
    public var since: Int64
    public var before: Int64
    /// The HAT as it arrived, file key included.
    public var hatJson: String
    public var receivedAt: Int64
    public var attempts: Int
    public var lastError: String?

    public var id: String { nonce }

    /// After this many failed fetches it waits for a person to press
    /// Retry, rather than asking a DISK that has said no on every poll.
    public static let automaticAttempts = 3

    public var waitsForRetry: Bool { attempts >= Self.automaticAttempts }

    public init(
        nonce: String, from: String, conversationId: String, since: Int64, before: Int64,
        hatJson: String, receivedAt: Int64, attempts: Int = 0, lastError: String? = nil
    ) {
        self.nonce = nonce
        self.from = from
        self.conversationId = conversationId
        self.since = since
        self.before = before
        self.hatJson = hatJson
        self.receivedAt = receivedAt
        self.attempts = attempts
        self.lastError = lastError
    }
}

/// The three lists above. Human-scale.
public struct HistorySharesStore {

    public static let outgoingNamespace = "im.history.outgoing.v1"
    public static let incomingNamespace = "im.history.incoming.v1"
    public static let receivedNamespace = "im.history.received.v1"

    private let outgoingRows: TypedStore<OutgoingHistoryRequest>
    private let incomingRows: TypedStore<IncomingHistoryRequest>
    private let receivedRows: TypedStore<ReceivedHistoryShare>

    public init(kv: EncryptedKVStore) {
        outgoingRows = TypedStore(kv: kv, namespace: Self.outgoingNamespace)
        incomingRows = TypedStore(kv: kv, namespace: Self.incomingNamespace)
        receivedRows = TypedStore(kv: kv, namespace: Self.receivedNamespace)
    }

    // MARK: outgoing

    public func recordAsk(_ ask: OutgoingHistoryRequest) throws {
        try outgoingRows.put(ask, key: ask.nonce)
    }

    public func ask(nonce: String) throws -> OutgoingHistoryRequest? {
        try outgoingRows.get(nonce)
    }

    /// Unanswered asks, newest first — and the expired ones forgotten
    /// on the way past.
    public func asks(now: Date = Date()) throws -> [OutgoingHistoryRequest] {
        let cutoff = Int64(now.timeIntervalSince1970 * 1000) - HistoryShare.askLifetimeMs
        var live: [OutgoingHistoryRequest] = []
        for (key, ask) in try outgoingRows.all() {
            if ask.sentAt < cutoff { try outgoingRows.delete(key) } else { live.append(ask) }
        }
        return live.sorted { $0.sentAt > $1.sentAt }
    }

    @discardableResult
    public func removeAsk(nonce: String) throws -> Bool {
        guard try outgoingRows.exists(nonce) else { return false }
        try outgoingRows.delete(nonce)
        return true
    }

    // MARK: incoming

    public func recordIncoming(_ request: IncomingHistoryRequest) throws {
        try incomingRows.put(request, key: request.id)
    }

    public func incoming(id: String) throws -> IncomingHistoryRequest? {
        try incomingRows.get(id)
    }

    /// Newest first.
    public func incoming() throws -> [IncomingHistoryRequest] {
        try incomingRows.all().map(\.value).sorted { $0.receivedAt > $1.receivedAt }
    }

    @discardableResult
    public func removeIncoming(id: String) throws -> Bool {
        guard try incomingRows.exists(id) else { return false }
        try incomingRows.delete(id)
        return true
    }

    // MARK: received

    public func recordReceived(_ share: ReceivedHistoryShare) throws {
        try receivedRows.put(share, key: share.nonce)
    }

    /// Oldest first — the order they are worked through.
    public func received() throws -> [ReceivedHistoryShare] {
        try receivedRows.all().map(\.value).sorted { $0.receivedAt < $1.receivedAt }
    }

    @discardableResult
    public func removeReceived(nonce: String) throws -> Bool {
        guard try receivedRows.exists(nonce) else { return false }
        try receivedRows.delete(nonce)
        return true
    }
}
