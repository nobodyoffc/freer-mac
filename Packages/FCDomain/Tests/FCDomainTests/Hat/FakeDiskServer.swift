import Foundation
import FCCore
import FCTransport
@testable import FCDomain

/// An in-process stand-in for a FAPI DISK service.
///
/// Stores blobs keyed by their content DID, exactly as the real server
/// does, and implements the four endpoints ``DiskService`` uses. Because
/// it is content-addressed, the tests can exercise the parts that
/// matter — the two-HAT flows and, above all, the verification that
/// rejects wrong bytes — without a socket.
///
/// Knobs let a test make the server misbehave (`corruptOnGet`,
/// `substituteOnGet`, `failGet`), which is the only way to prove the
/// integrity checks are load-bearing rather than decorative.
final class FakeDiskServer: FapiCalling, @unchecked Sendable {

    private let lock = NSLock()
    private var blobs: [String: Data] = [:]

    /// Return `n` flipped bytes instead of the stored blob.
    var corruptOnGet = false
    /// Return this blob for ANY get — a server swapping content.
    var substituteOnGet: Data?
    /// Fail every get with a server error.
    var failGet = false
    /// Fail every store with a server error.
    var failStore = false

    private(set) var putCount = 0
    private(set) var carveCount = 0
    private(set) var getCount = 0
    private(set) var checkBatches: [[String]] = []

    // MARK: - inspection

    var storedDids: Set<String> {
        lock.lock(); defer { lock.unlock() }
        return Set(blobs.keys)
    }

    func blob(did: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return blobs[did]
    }

    /// Seed a blob directly (simulating data another client uploaded).
    @discardableResult
    func seed(_ data: Data) -> String {
        let did = Self.did(of: data)
        lock.lock(); blobs[did] = data; lock.unlock()
        return did
    }

    static func did(of data: Data) -> String {
        Hash.doubleSha256(data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - FapiCalling

    func call(
        api: String,
        params: Data?,
        fcdsl: Data?,
        binary: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        timeoutMs: Int
    ) async throws -> FapiClient.Reply {
        switch api {
        case "disk.check":
            let ids = (try? JSONSerialization.jsonObject(with: params ?? Data()) as? [String: Any])?
                .flatMap { $0["ids"] as? [String] } ?? []
            lock.lock()
            checkBatches.append(ids)
            let found = ids.compactMap { id -> (String, DiskItem)? in
                guard let blob = blobs[id] else { return nil }
                return (id, DiskItem(id: id, since: 1, expire: nil, size: Int64(blob.count)))
            }
            lock.unlock()
            let map = Dictionary(uniqueKeysWithValues: found)
            let data = try JSONEncoder().encode(map)
            return reply(FapiResponse(code: 0, data: data))
        default:
            return reply(FapiResponse(code: 0, message: "ok"))
        }
    }

    func callUploadingFile(
        api: String,
        params: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        fileURL: URL,
        idleTimeoutMs: Int64,
        progress: (@Sendable (Int64, Int64) -> Void)?
    ) async throws -> FapiClient.Reply {
        if failStore {
            return reply(FapiResponse(code: 1, message: "storage full"))
        }
        let content = try Data(contentsOf: fileURL)
        let did = Self.did(of: content)
        lock.lock()
        blobs[did] = content
        if api == "disk.carve" { carveCount += 1 } else { putCount += 1 }
        lock.unlock()

        progress?(Int64(content.count), Int64(content.count))
        let item = DiskItem(id: did, since: 1, expire: nil, size: Int64(content.count))
        return reply(FapiResponse(code: 0, data: try JSONEncoder().encode(item)))
    }

    func callDownloadingToFile(
        api: String,
        params: Data?,
        fcdsl: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        outputURL: URL,
        idleTimeoutMs: Int64,
        progress: (@Sendable (Int64) -> Void)?
    ) async throws -> FapiClient.Reply {
        lock.lock(); getCount += 1; lock.unlock()
        if failGet {
            return reply(FapiResponse(code: 404, message: "not found"))
        }
        let requested = (try? JSONSerialization.jsonObject(with: params ?? Data()) as? [String: Any])?
            .flatMap { $0["id"] as? String } ?? ""

        var payload: Data
        if let substituteOnGet {
            payload = substituteOnGet
        } else {
            lock.lock()
            let stored = blobs[requested]
            lock.unlock()
            guard let stored else {
                return reply(FapiResponse(code: 404, message: "no such did"))
            }
            payload = stored
        }
        if corruptOnGet, !payload.isEmpty {
            payload[payload.startIndex] ^= 0xff
        }

        try FileManager.default.createDirectory(
            at: outputURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try payload.write(to: outputURL)
        progress?(Int64(payload.count))

        let item = DiskItem(id: requested, since: 1, expire: nil, size: Int64(payload.count))
        return reply(FapiResponse(code: 0, data: try JSONEncoder().encode(item)))
    }

    private func reply(_ response: FapiResponse) -> FapiClient.Reply {
        FapiClient.Reply(response: response, binary: nil, messageId: 1)
    }
}
