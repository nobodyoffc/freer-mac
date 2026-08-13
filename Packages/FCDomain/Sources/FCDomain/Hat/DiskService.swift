import Foundation
import FCCore
import FCTransport

/// One item stored on a FAPI DISK service. Mirror of
/// `FC-AJDK/.../data/fcData/DiskItem.java` (which inherits `id` — the
/// content DID — from `FcObject`).
public struct DiskItem: Codable, Equatable, Sendable {
    /// The DID (hex `sha256x2` of the stored bytes).
    public var id: String?
    /// Stored-since time, epoch ms.
    public var since: Int64?
    /// Expiry, epoch ms. Absent for permanently carved data.
    public var expire: Int64?
    public var size: Int64?

    public init(id: String? = nil, since: Int64? = nil, expire: Int64? = nil, size: Int64? = nil) {
        self.id = id
        self.since = since
        self.expire = expire
        self.size = size
    }

    private enum CodingKeys: String, CodingKey {
        case id, did, since, expire, size
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // The server's index calls this field `did` while the Java
        // model calls it `id`; accept either.
        id = try c.decodeIfPresent(String.self, forKey: .id)
            ?? c.decodeIfPresent(String.self, forKey: .did)
        since = try c.decodeIfPresent(Int64.self, forKey: .since)
        expire = try c.decodeIfPresent(Int64.self, forKey: .expire)
        size = try c.decodeIfPresent(Int64.self, forKey: .size)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(id, forKey: .id)
        try c.encodeIfPresent(since, forKey: .since)
        try c.encodeIfPresent(expire, forKey: .expire)
        try c.encodeIfPresent(size, forKey: .size)
    }
}

/// Thin typed wrapper over the DISK endpoints of one FAPI service.
///
/// Deliberately dumb: it moves bytes and parses metadata. Everything
/// about *what* the bytes mean — the two-HAT cipher model, DID
/// verification, which key path to try — lives in ``HatSyncService``.
public struct DiskService {

    public enum Failure: Error, CustomStringConvertible {
        case serverError(code: Int, message: String?)
        case emptyResponse(api: String)
        case malformedResponse(api: String, underlying: Error)
        case fileMissing(URL)

        public var description: String {
            switch self {
            case let .serverError(code, message):
                return "DiskService: server returned code \(code)\(message.map { " — \($0)" } ?? "")"
            case .emptyResponse(let api):
                return "DiskService: \(api) returned no data"
            case let .malformedResponse(api, underlying):
                return "DiskService: \(api) response could not be decoded — \(underlying)"
            case .fileMissing(let url):
                return "DiskService: no file at \(url.path)"
            }
        }
    }

    /// Batch size for `disk.check`, matching the Java client's chunking.
    public static let checkBatchSize = 200

    public let fapi: any FapiCalling
    /// Routing sid for a specific DISK service; nil uses the session's
    /// default server.
    public let sid: String?

    public init(fapi: any FapiCalling, sid: String? = nil) {
        self.fapi = fapi
        self.sid = sid
    }

    // MARK: - store

    /// Store with expiry (`disk.put`). `dataLifeDays` nil takes the
    /// server default.
    @discardableResult
    public func put(
        fileURL: URL,
        dataLifeDays: Int64? = nil,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil
    ) async throws -> DiskItem {
        var params: [String: Any] = [:]
        if let dataLifeDays { params["dataLifeDays"] = dataLifeDays }
        return try await store(api: "disk.put", fileURL: fileURL, params: params, progress: progress)
    }

    /// Store permanently (`disk.carve`).
    @discardableResult
    public func carve(
        fileURL: URL,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil
    ) async throws -> DiskItem {
        try await store(api: "disk.carve", fileURL: fileURL, params: [:], progress: progress)
    }

    private func store(
        api: String,
        fileURL: URL,
        params: [String: Any],
        progress: (@Sendable (Int64, Int64) -> Void)?
    ) async throws -> DiskItem {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            throw Failure.fileMissing(fileURL)
        }
        let body = params.isEmpty ? nil : try JSONSerialization.data(withJSONObject: params)
        let reply = try await fapi.callUploadingFile(
            api: api,
            params: body,
            sid: sid,
            via: nil,
            maxCost: nil,
            fileURL: fileURL,
            idleTimeoutMs: FapiClient.transferIdleTimeoutMs,
            progress: progress
        )
        return try decodeItem(api: api, reply: reply)
    }

    // MARK: - fetch

    /// Download by DID into `outputURL` (`disk.get`, params `{id}`).
    @discardableResult
    public func get(
        did: String,
        to outputURL: URL,
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> DiskItem {
        let body = try JSONSerialization.data(withJSONObject: ["id": did])
        let reply = try await fapi.callDownloadingToFile(
            api: "disk.get",
            params: body,
            fcdsl: nil,
            sid: sid,
            via: nil,
            maxCost: nil,
            outputURL: outputURL,
            idleTimeoutMs: FapiClient.transferIdleTimeoutMs,
            progress: progress
        )
        // The metadata header is advisory; the bytes are already on
        // disk and the caller verifies them against the DID.
        return (try? decodeItem(api: "disk.get", reply: reply)) ?? DiskItem(id: did)
    }

    // MARK: - existence

    /// Whether one DID is on this service.
    public func check(did: String, timeoutMs: Int = 8_000) async throws -> DiskItem? {
        try await check(dids: [did], timeoutMs: timeoutMs)[did]
    }

    /// Batch existence check, chunked at ``checkBatchSize`` like the
    /// Java client. Missing DIDs are simply absent from the result.
    public func check(dids: [String], timeoutMs: Int = 8_000) async throws -> [String: DiskItem] {
        guard !dids.isEmpty else { return [:] }
        var out: [String: DiskItem] = [:]
        for chunk in stride(from: 0, to: dids.count, by: Self.checkBatchSize).map({
            Array(dids[$0..<min($0 + Self.checkBatchSize, dids.count)])
        }) {
            let body = try JSONSerialization.data(withJSONObject: ["ids": chunk])
            let reply = try await fapi.call(
                api: "disk.check",
                params: body,
                fcdsl: nil,
                binary: nil,
                sid: sid,
                via: nil,
                maxCost: nil,
                timeoutMs: timeoutMs
            )
            try throwIfServerError(reply)
            guard let data = reply.response.data else { continue }
            // The server may answer with a map keyed by DID, or a bare
            // list of items; accept both.
            if let map = try? JSONDecoder().decode([String: DiskItem].self, from: data) {
                out.merge(map) { a, _ in a }
            } else if let list = try? JSONDecoder().decode([DiskItem].self, from: data) {
                for item in list {
                    if let id = item.id { out[id] = item }
                }
            }
        }
        return out
    }

    // MARK: - helpers

    private func decodeItem(api: String, reply: FapiClient.Reply) throws -> DiskItem {
        try throwIfServerError(reply)
        guard let data = reply.response.data else { throw Failure.emptyResponse(api: api) }
        do {
            return try JSONDecoder().decode(DiskItem.self, from: data)
        } catch {
            throw Failure.malformedResponse(api: api, underlying: error)
        }
    }

    private func throwIfServerError(_ reply: FapiClient.Reply) throws {
        if let code = reply.response.code, code != 0 {
            throw Failure.serverError(code: code, message: reply.response.message)
        }
    }
}
