import Foundation
import FCCore
import FCTransport

/// On-chain mail sync — the read path mirroring Android's
/// `MailManager.refreshMailsFromAPI` → `makeEntityDetails`. Sending
/// lives on ``ActiveSession`` next to the other carves, since it rides
/// the wallet's send pipeline.
///
/// Two things separate this from the contact and secret syncs it
/// otherwise resembles:
///
/// - **One query covers both directions.** A mail is indexed with a
///   public `from` and `to`, so `equals` over *both* fields against our
///   own FID returns the inbox and the outbox together. Contacts and
///   secrets are carved to yourself and only ever have an `owner`.
/// - **An unreadable row is kept, not dropped.** A contact whose cipher
///   won't open is unusable — the FID it describes is *inside* the
///   ciphertext. A mail's correspondent is on the outside, so a row we
///   cannot decrypt still truthfully says who wrote to you and when.
///   Dropping it would quietly hide mail; keeping it flagged lets the
///   UI say "this needs a key you don't have here".
public struct MailService {

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "MailService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "MailService: \(e)"
            }
        }
    }

    public struct SyncResult: Sendable {
        /// Rows written to the store, decrypted or not.
        public let merged: Int
        /// Of those, ones whose newest carve is a delete.
        public let deleted: Int
        /// Of those, ones whose body could not be opened.
        public let undecryptable: Int
        /// Incoming mail that was not already in the store — the badge
        /// number.
        public let newUnread: Int
        public let total: Int
        /// First few failure descriptions, for a diagnosable UI banner.
        public let failureReasons: [String]
    }

    /// How far below the local watermark an incremental sync re-reads,
    /// to survive a reorg rewriting recent heights. Same window the
    /// cash cache uses.
    public static let reorgWindow: Int64 = 30

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    // MARK: - fetch

    /// Fetch on-chain `mail` records where `fid` is the sender **or** the
    /// recipient — active AND deleted, sorted `lastHeight desc, id desc`,
    /// cursor-paginated. Mirrors `MailManager.makeFcdsl` with
    /// `active = null`.
    ///
    /// `newerThanHeight` stops the walk once the page drops below it.
    /// Because the sort is height-descending that is a safe early exit,
    /// and it is what makes a re-sync cheap on a mailbox with years in
    /// it. Pass nil to walk everything (the first sync on a new device).
    public func fetchOnChainMailRecords(
        fid: String,
        newerThanHeight: Int64? = nil,
        pageSize: Int = 200,
        maxPages: Int = 200,
        timeoutMs: Int = 15_000
    ) async throws -> [Mail] {
        var all: [Mail] = []
        var after: [String]? = nil
        let floor = newerThanHeight.map { $0 - Self.reorgWindow }

        for _ in 0..<maxPages {
            // `equals` with two fields and one value: match rows where
            // either `from` or `to` is us.
            let query: [String: Any] = [
                "equals": ["fields": ["from", "to"], "values": [fid]]
            ]
            var dict: [String: Any] = [
                "entity": "mail",
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
            // 404 = no mail. Normal for a fresh FID.
            if let code = resp.code, code != 0 {
                if code == 404 { break }
                throw Failure.fapiNonZeroCode(
                    api: "base.search", code: code, message: resp.message
                )
            }
            guard let data = resp.data else { break }
            let page: [Mail]
            do {
                page = try JSONDecoder().decode([Mail].self, from: data)
            } catch {
                throw Failure.underlying(error)
            }
            all.append(contentsOf: page)

            // Everything from here down is older than we already hold.
            if let floor, let last = page.last?.lastHeight, last < floor { break }
            if page.count < pageSize { break }
            guard let next = resp.last, !next.isEmpty else { break }
            after = next
        }
        return all
    }

    // MARK: - sync

    /// Pull `fid`'s mail, decrypt each body with `privkey`, and merge
    /// into `store` keyed by the carve txid.
    ///
    /// **Deletion.** A mail whose newest carve is a delete op arrives
    /// with `active == false`. Unlike the contact and secret syncs,
    /// which remove the local row, the row is *kept* and flagged: the
    /// chain can recover it, and Recover would have nothing to act on if
    /// the row were gone. ``MailsStore/deleted()`` is the Deleted view.
    ///
    /// **Unread.** Incoming mail we have not seen before is marked
    /// unread. Android's `markEntityAsNew` marks *everything* new,
    /// including mail you sent yourself from another device, which
    /// leaves your own outbox lit up; we only mark what someone else
    /// sent us. Rows already in the store keep whatever read state they
    /// have, so a re-sync never re-lights a mail you have read.
    ///
    /// `contacts`, when given, fills the cached `fromName`/`toName` so a
    /// list can show names without a lookup per row.
    @discardableResult
    public func syncOnChainMails(
        fid: String,
        privkey: Data?,
        into store: MailsStore,
        contacts: ContactsStore? = nil,
        incremental: Bool = true,
        timeoutMs: Int = 15_000
    ) async throws -> SyncResult {
        let watermark = incremental ? (try? store.highestKnownHeight()) ?? nil : nil
        let records = try await fetchOnChainMailRecords(
            fid: fid, newerThanHeight: watermark, timeoutMs: timeoutMs
        )

        var seen = Set<String>()
        var merged = 0
        var deleted = 0
        var undecryptable = 0
        var newUnread = 0
        var failureReasons: [String] = []

        func noteFailure(_ id: String?, _ reason: String) {
            if failureReasons.count < 3 {
                let rid = id.map { $0.count <= 16 ? $0 : "\($0.prefix(8))…\($0.suffix(8))" } ?? "?"
                failureReasons.append("[\(rid)] \(reason)")
            }
        }

        for record in records {
            guard let recordId = record.id, !recordId.isEmpty else {
                noteFailure(nil, "record has no id")
                continue
            }
            // Sorted newest-first, so the first sighting of an id is its
            // freshest state.
            guard seen.insert(recordId).inserted else { continue }

            let existing = try? store.get(id: recordId)
            var mail = record
            mail.id = recordId
            mail.onChain = true
            // A mail from yourself to yourself comes back with `to`
            // unset on some indexers; Android patches it the same way.
            if mail.to == nil { mail.to = mail.from }

            // Decrypting here is a trial run: the store drops the
            // plaintext again, and all we keep is the `decrypted` flag,
            // so the UI can tell "not opened yet" from "cannot be
            // opened with this identity's key". Rows already known to
            // open are not re-tried — that would spend an ECDH per mail
            // on every sync for an answer we have — but a row that
            // failed *is*, since it may have failed only because the
            // last sync ran watch-only.
            if existing?.decrypted == true {
                mail.decrypted = true
            } else if mail.cipher != nil {
                if let privkey {
                    if !mail.parseDetail(privkey: privkey) {
                        undecryptable += 1
                        noteFailure(recordId, "body could not be decrypted with this identity's key")
                    }
                } else {
                    mail.decrypted = false
                }
            }

            if mail.isDeleted { deleted += 1 }

            // Read state is local: never let the chain relight a mail.
            if let existing {
                mail.unread = existing.unread
            } else if mail.isIncoming(for: fid), !mail.isDeleted {
                mail.unread = true
                newUnread += 1
            } else {
                mail.unread = false
            }

            if let contacts {
                mail.fromName = displayName(for: mail.from, in: contacts)
                mail.toName = displayName(for: mail.to, in: contacts)
            }

            do {
                try store.upsert(mail)
                merged += 1
            } catch {
                noteFailure(recordId, String(describing: error))
            }
        }

        return SyncResult(
            merged: merged,
            deleted: deleted,
            undecryptable: undecryptable,
            newUnread: newUnread,
            total: records.count,
            failureReasons: failureReasons
        )
    }

    /// A contact's CID, or nil. Deliberately not the FID: the row
    /// already shows that, and ``Mail/counterpartyName(for:)`` falls
    /// back to it. Caching the FID here would just duplicate it into
    /// every stored row.
    private func displayName(for fid: String?, in contacts: ContactsStore) -> String? {
        guard let fid, let contact = try? contacts.get(fid: fid) else { return nil }
        guard let cid = contact.cid, !cid.isEmpty else { return nil }
        return cid
    }
}
