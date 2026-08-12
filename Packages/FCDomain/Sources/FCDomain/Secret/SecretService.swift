import Foundation
import FCCore
import FCTransport

/// One row of the on-chain `secret` index as returned by `base.search`
/// — the Java `feipData.Secret` wire shape before `parseDetail` runs:
/// the human-readable detail (`type/title/content/memo`) is inside
/// `cipher`, encrypted to the owner's own pubkey when carved.
public struct OnChainSecretRecord: Decodable, Sendable {
    /// The carve record id (txid-derived) — the merge key.
    public var id: String?
    public var alg: String?
    public var cipher: String?
    public var owner: String?
    public var birthTime: Int64?
    public var lastHeight: Int64?
    public var active: Bool?
}

/// The decrypted payload of an ``OnChainSecretRecord/cipher``.
struct OnChainSecretDetail: Decodable {
    var type: String?
    var title: String?
    var content: String?
    var memo: String?
}

/// On-chain secret sync — the read path mirroring Android's
/// `SecretManager.refreshSecretsFromAPI` → `makeEntityDetails`, plus
/// the record fetch that backs it. Carving (the write path) lives on
/// ``ActiveSession`` next to the contact carve, since it reuses the
/// wallet's send pipeline.
public struct SecretService {

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case noContentCipher
        case contentNotUtf8
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "SecretService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .noContentCipher:
                return "SecretService: secret has no contentCipher to decrypt"
            case .contentNotUtf8:
                return "SecretService: decrypted content is not UTF-8 — wrong key?"
            case .underlying(let e):
                return "SecretService: \(e)"
            }
        }
    }

    public struct SyncResult: Sendable {
        public let merged: Int
        public let removed: Int
        public let undecryptable: Int
        public let total: Int
        /// First few failure descriptions, for a diagnosable UI banner.
        public let failureReasons: [String]
    }

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    /// Fetch every on-chain SECRET record carved by `owner` — active
    /// AND deleted (Android's refresh passes `active = null`), sorted
    /// `lastHeight desc, id desc`, cursor-paginated. Mirrors
    /// `SecretManager.secretSearchFcdsl` (whose owner condition rides
    /// in `terms`; `equals` is what the server applies for exact
    /// single-value matches and matches the contact fetch here).
    public func fetchOnChainSecretRecords(
        owner fid: String,
        pageSize: Int = 200,
        maxPages: Int = 200,
        timeoutMs: Int = 15_000
    ) async throws -> [OnChainSecretRecord] {
        var all: [OnChainSecretRecord] = []
        var after: [String]? = nil
        for _ in 0..<maxPages {
            let query: [String: Any] = [
                "terms": ["fields": ["owner"], "values": [fid]]
            ]
            var dict: [String: Any] = [
                "entity": "secret",
                "query": query,
                "sort": [
                    ["field": "lastHeight", "order": "desc"],
                    ["field": "id",         "order": "desc"]
                ],
                "size": String(pageSize)
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
            // 404 = no carved secrets. Normal for a fresh FID.
            if let code = resp.code, code != 0 {
                if code == 404 { break }
                throw Failure.fapiNonZeroCode(
                    api: "base.search", code: code, message: resp.message
                )
            }
            guard let data = resp.data else { break }
            let page: [OnChainSecretRecord]
            do {
                page = try JSONDecoder().decode([OnChainSecretRecord].self, from: data)
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

    /// Pull `owner`'s carved secrets, decrypt each record's cipher with
    /// `privkey`, re-encrypt the content to the owner's own pubkey as
    /// ``Secret/contentCipher`` (Pattern B — plaintext never persisted),
    /// and upsert into `store` keyed by the carve id.
    ///
    /// **Deletion cleanup.** A record whose newest carve is
    /// `active == false` gets its chain-sourced local row removed;
    /// local-only rows (ids that are `sha256x2` of local details, never
    /// carved) are untouched.
    @discardableResult
    public func syncOnChainSecrets(
        owner fid: String,
        privkey: Data,
        into store: SecretsStore,
        timeoutMs: Int = 15_000
    ) async throws -> SyncResult {
        let ownPubkey: Data
        do {
            ownPubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        } catch {
            throw Failure.underlying(error)
        }
        let records = try await fetchOnChainSecretRecords(owner: fid, timeoutMs: timeoutMs)

        // Newest-first sort: the first occurrence of a record id is the
        // freshest state of that carve.
        var seen = Set<String>()
        var merged = 0
        var removed = 0
        var undecryptable = 0
        var failureReasons: [String] = []
        func noteFailure(_ record: OnChainSecretRecord, _ reason: String) {
            undecryptable += 1
            if failureReasons.count < 3 {
                let rid = record.id.map { id in
                    id.count <= 16 ? id : "\(id.prefix(8))…\(id.suffix(8))"
                } ?? "?"
                failureReasons.append("[\(rid)] \(reason)")
            }
        }

        for record in records {
            guard let recordId = record.id, !recordId.isEmpty else {
                noteFailure(record, "record has no id")
                continue
            }
            guard seen.insert(recordId).inserted else { continue }

            if record.active == false {
                // Newest state is deleted → drop the chain-sourced row.
                if let existing = try? store.get(id: recordId),
                   existing.onChain,
                   (try? store.remove(id: recordId)) == true {
                    removed += 1
                }
                continue
            }

            guard let cipherString = record.cipher, !cipherString.isEmpty else {
                noteFailure(record, "record has no cipher field")
                continue
            }
            let plain: Data
            do {
                plain = try AsyOneWayCipher.decrypt(cipherString: cipherString, privkey: privkey)
            } catch {
                noteFailure(record, String(describing: error))
                continue
            }
            guard let detail = try? JSONDecoder().decode(OnChainSecretDetail.self, from: plain),
                  let content = detail.content else {
                noteFailure(record, "decrypted plaintext is not a secret detail JSON")
                continue
            }

            var secret = (try? store.get(id: recordId)) ?? Secret(id: recordId)
            secret.type = detail.type
            secret.title = detail.title
            secret.memo = detail.memo
            do {
                secret.contentCipher = try AsyOneWayCipher.encrypt(
                    plaintext: Data(content.utf8), toPubkey: ownPubkey
                )
            } catch {
                noteFailure(record, String(describing: error))
                continue
            }
            secret.birthTime = record.birthTime
            if let h = record.lastHeight { secret.lastHeight = h }
            secret.active = record.active
            secret.onChain = true
            secret.carveId = recordId
            do {
                try store.upsert(secret)
                merged += 1
            } catch {
                noteFailure(record, String(describing: error))
            }
        }

        return SyncResult(
            merged: merged,
            removed: removed,
            undecryptable: undecryptable,
            total: records.count,
            failureReasons: failureReasons
        )
    }
}
