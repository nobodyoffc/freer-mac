import Foundation
import FCCore
import FCTransport

/// One item parked at a DOCK, mirroring
/// `FC-AJDK/.../data/fcData/DockItem.java`.
public struct DockItem: Codable, Equatable, Sendable, Identifiable {

    /// Who put it there.
    public var sender: String?
    /// Who it is for — FIDs, or a team/square/room id.
    public var recipients: [String]?
    public var size: Int64?
    public var dataHash: String?
    public var createHeight: Int64?
    public var expireHeight: Int64?
    public var createTime: Int64?
    public var maxDays: Int?
    public var storageFee: Int64?
    public var ingressFee: Int64?
    /// What kind of payload it is — `"IM"` for a chat message.
    public var dataType: String?
    /// The payload itself, present on the `dock.fetch` path, absent on
    /// the `dock.put` receipt.
    public var dataBase64: String?

    public var id: String?

    public init(
        sender: String? = nil,
        recipients: [String]? = nil,
        size: Int64? = nil,
        dataHash: String? = nil,
        createHeight: Int64? = nil,
        expireHeight: Int64? = nil,
        createTime: Int64? = nil,
        maxDays: Int? = nil,
        storageFee: Int64? = nil,
        ingressFee: Int64? = nil,
        dataType: String? = nil,
        dataBase64: String? = nil,
        id: String? = nil
    ) {
        self.sender = sender
        self.recipients = recipients
        self.size = size
        self.dataHash = dataHash
        self.createHeight = createHeight
        self.expireHeight = expireHeight
        self.createTime = createTime
        self.maxDays = maxDays
        self.storageFee = storageFee
        self.ingressFee = ingressFee
        self.dataType = dataType
        self.dataBase64 = dataBase64
        self.id = id
    }

    /// The payload, decoded.
    public var data: Data? {
        guard let dataBase64 else { return nil }
        return Data(base64Encoded: dataBase64)
    }
}

/// Store-and-forward: the route that works for a recipient who is not
/// there. The port of Android's `dockPut` / `dockFetch` / `dockDelete`.
///
/// **This is the route that matters.** FUDP direct and ROAD relay are
/// latency optimisations, and Android has both behind settings that are
/// off by default; a DOCK put works whether or not the recipient is
/// online, which makes it the default channel and the last resort at
/// once. A client that spoke only DOCK would be slower and complete.
///
/// The asymmetry worth knowing: **putting costs money and fetching does
/// not**. The sender pays the recipient DOCK's ingress and storage, so
/// the preference order in ``DeliveryPolicy`` — the recipient's own DOCK
/// before our own DOCK's forwarding — is about who pays for how many
/// hops, not about reliability.
public struct DockService {

    /// The `dataType` a chat message is filed under, so a fetch can ask
    /// for messages without dragging down every HAT and symkey the DOCK
    /// is holding.
    public static let imDataType = "IM"

    public let fapi: any FapiCalling
    /// The DOCK this client talks to. `nil` targets whatever server the
    /// `fapi` connection already points at — our own DOCK.
    public let sid: String?

    public init(fapi: any FapiCalling, sid: String? = nil) {
        self.fapi = fapi
        self.sid = sid
    }

    // MARK: - put

    /// Park `envelope` at this DOCK for `recipients`.
    ///
    /// `targetDockUrl` asks the connected DOCK to **forward** to another
    /// one, which is how a message reaches someone whose DOCK is not
    /// ours. Android drops the field when it equals the server's own
    /// URL — forwarding to yourself is just storing — and so does this,
    /// which is why the caller may pass it unconditionally.
    ///
    /// **The hash is a single SHA-256**, and that is not a typo: the
    /// file endpoints (`disk.put`, `disk.carve`) hash *twice*, and this
    /// one hashes once. Android does the same, and since the server
    /// checks the payload against whichever it expects, matching the
    /// endpoint is the only thing that matters — hashing twice here
    /// would have every put rejected.
    @discardableResult
    public func put(
        _ envelope: Data,
        recipients: [String],
        targetDockUrl: String? = nil,
        ownDockUrl: String? = nil,
        dataType: String? = imDataType,
        maxDays: Int? = nil,
        timeoutMs: Int = 15_000
    ) async throws -> DockItem {
        guard !envelope.isEmpty else { throw Failure.emptyPayload }
        guard !recipients.isEmpty else { throw Failure.noRecipients }

        var params: [String: Any] = ["recipients": recipients]
        if let maxDays { params["maxDays"] = maxDays }
        if let dataType, !dataType.isEmpty { params["dataType"] = dataType }
        if let targetDockUrl, !targetDockUrl.isEmpty, targetDockUrl != ownDockUrl {
            params["targetDockUrl"] = targetDockUrl
        }

        let body = try JSONSerialization.data(withJSONObject: params, options: [.sortedKeys])
        let hash = Hash.sha256(envelope).map { String(format: "%02x", $0) }.joined()

        let reply = try await fapi.callWithHashedBinary(
            api: "dock.put",
            params: body,
            binary: envelope,
            dataHash: hash,
            sid: sid,
            via: nil,
            maxCost: nil,
            timeoutMs: timeoutMs
        )
        return try decodeItem(api: "dock.put", reply: reply)
    }

    // MARK: - fetch

    /// Collect what is waiting for `recipientIds`, payloads included.
    ///
    /// The recipients are plural because one fetch covers every identity
    /// this device answers for at once — our FID, and every team, square
    /// and room we belong to, since a group's messages are addressed to
    /// the group.
    ///
    /// Fetching does **not** delete. An item stays until
    /// ``delete(id:timeoutMs:)`` removes it or its TTL expires, which is
    /// what makes a fetch interrupted halfway lose nothing.
    public func fetch(
        recipientIds: [String],
        after: [String]? = nil,
        size: Int = 50,
        dataType: String? = imDataType,
        timeoutMs: Int = 15_000
    ) async throws -> (items: [DockItem], cursor: [String]?) {
        guard !recipientIds.isEmpty else { return ([], nil) }

        var params: [String: Any] = ["recipientIds": recipientIds]
        if let dataType, !dataType.isEmpty { params["dataType"] = dataType }

        var query: [String: Any] = ["size": String(size)]
        if let after, !after.isEmpty { query["after"] = after }

        let reply = try await fapi.call(
            api: "dock.fetch",
            params: try JSONSerialization.data(withJSONObject: params, options: [.sortedKeys]),
            fcdsl: try JSONSerialization.data(withJSONObject: query, options: [.sortedKeys]),
            binary: nil,
            sid: sid, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        if let code = resp.code, code != 0 {
            // 404 = nothing waiting, which is the normal answer most of
            // the time.
            if code == 404 { return ([], nil) }
            throw Failure.fapiNonZeroCode(api: "dock.fetch", code: code, message: resp.message)
        }
        guard let data = resp.data else { return ([], nil) }
        do {
            let items = try JSONDecoder().decode([DockItem].self, from: data)
            return (items, resp.last)
        } catch {
            throw Failure.underlying(error)
        }
    }

    /// Drop an item we have taken delivery of.
    ///
    /// Deleting is the *receiver's* half of the bargain: the sender paid
    /// for storage, and leaving read items to expire on their own would
    /// spend their money on nothing. It is also what stops the next
    /// fetch handing back the same message forever.
    @discardableResult
    public func delete(id: String, timeoutMs: Int = 10_000) async throws -> Bool {
        let reply = try await fapi.call(
            api: "dock.delete",
            params: try JSONSerialization.data(withJSONObject: ["id": id], options: [.sortedKeys]),
            fcdsl: nil, binary: nil,
            sid: sid, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        if let code = resp.code, code != 0 {
            // Already gone is the outcome we wanted.
            if code == 404 { return false }
            throw Failure.fapiNonZeroCode(api: "dock.delete", code: code, message: resp.message)
        }
        return true
    }

    /// Metadata for one item without downloading it.
    public func check(id: String, timeoutMs: Int = 10_000) async throws -> DockItem? {
        let reply = try await fapi.call(
            api: "dock.check",
            params: try JSONSerialization.data(withJSONObject: ["id": id], options: [.sortedKeys]),
            fcdsl: nil, binary: nil,
            sid: sid, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        if let code = resp.code, code != 0 {
            if code == 404 { return nil }
            throw Failure.fapiNonZeroCode(api: "dock.check", code: code, message: resp.message)
        }
        guard let data = resp.data else { return nil }
        return try? JSONDecoder().decode(DockItem.self, from: data)
    }

    // MARK: - helpers

    private func decodeItem(api: String, reply: FapiClient.Reply) throws -> DockItem {
        let resp = reply.response
        if let code = resp.code, code != 0 {
            throw Failure.fapiNonZeroCode(api: api, code: code, message: resp.message)
        }
        guard let data = resp.data else { throw Failure.noData(api: api) }
        do {
            return try JSONDecoder().decode(DockItem.self, from: data)
        } catch {
            throw Failure.underlying(error)
        }
    }

    public enum Failure: Error, CustomStringConvertible {
        case emptyPayload
        case noRecipients
        case noData(api: String)
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case .emptyPayload:
                return "DockService: nothing to store"
            case .noRecipients:
                return "DockService: an item with no recipients would be addressed to nobody"
            case .noData(let api):
                return "DockService: \(api) returned no data"
            case let .fapiNonZeroCode(api, code, message):
                return "DockService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "DockService: \(e)"
            }
        }
    }
}
