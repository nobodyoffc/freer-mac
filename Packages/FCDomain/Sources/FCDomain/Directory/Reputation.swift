import Foundation
import FCCore
import FCTransport

/// A rating, as FEIP16 spells it. Only these two strings carry a
/// reputation delta — the reference parser leaves the delta undefined
/// for anything else, so the protocol's own words are "clients MUST use
/// only `good` or `bad`". Making it an enum is how this app can't.
public enum Rate: String, Codable, CaseIterable, Sendable {
    case good
    case bad

    /// Which way this rating moves the ratee's score. The magnitude is
    /// the transaction's CoinDays destroyed; the sign is this.
    public var sign: Int64 { self == .good ? 1 : -1 }
}

/// One row of the `reputation_history` index — a single rating, as it
/// landed. Port of FC-AJDK's `data/feipData/RepuHist.java`.
///
/// **The two numbers are not the same thing, and the difference is the
/// point of the protocol.** ``hot`` is this transaction's CoinDays
/// destroyed and is always positive: it measures attention, and a
/// scathing rating raises it exactly as much as a glowing one.
/// ``reputation`` is that same magnitude *signed* — `+cdd` for
/// ``Rate/good``, `−cdd` for ``Rate/bad``. A FID with a large `hot` and
/// a `reputation` near zero is not unknown; it is fought over.
///
/// Every field is optional because the indexer omits keys it has no
/// value for, the same contract as ``Freer`` and ``News``.
public struct RepuHist: Codable, Hashable, Sendable, Identifiable {

    /// The rating transaction's txid, which is this document's id.
    public var id: String?
    public var height: Int64?
    /// Position of the transaction within its block.
    public var index: Int?
    /// Block timestamp, in **seconds**.
    public var time: Int64?

    /// Who was rated — the `fid` the carve's `data` names.
    public var ratee: String?
    /// Who rated — the transaction's signer.
    public var rater: String?

    /// Signed delta this row contributed to the ratee's score:
    /// `+hot` for a good rating, `−hot` for a bad one.
    public var reputation: Int64?
    /// CoinDays destroyed by this transaction — the rating's weight.
    public var hot: Int64?

    /// `good` or `bad` as it arrived. Kept as the raw string so a row
    /// carrying something else still renders; read ``kind`` for the
    /// cases this app understands.
    public var rate: String?
    /// Free text the rater attached. Optional in the protocol and
    /// usually absent.
    public var cause: String?

    public init() {}

    /// The rating as a case, or nil for a value outside the protocol's
    /// two. Such a row exists on chain but moved no score.
    public var kind: Rate? { rate.flatMap(Rate.init(rawValue:)) }

    /// Cursor for the `height, id` sort ``ReputationService`` pages by.
    /// Nil when the row is missing either half, in which case the walk
    /// restarts from the top rather than paging into nonsense.
    public var cursor: [String]? {
        guard let height, let id else { return nil }
        return [String(height), id]
    }
}

/// Builder for the FEIP `Reputation` protocol (sn 16, ver 1) — the
/// OP_RETURN JSON that records one FID's opinion of another:
///
/// ```json
/// {"type":"FEIP","sn":"16","ver":"1","name":"Reputation",
///  "data":{"fid":"FBBB…","rate":"good","cause":"Helpful contributor"}}
/// ```
///
/// **The ratee is `data.fid`, and nothing else.** Worth stating flatly,
/// because the two other places it has been put are both wrong and both
/// fail quietly:
///
/// - The **transaction's recipient output.** A rating is an opinion,
///   not a payment; making the payee carry the meaning means you cannot
///   rate anyone without paying them, cannot rate in a transaction that
///   pays someone for another reason, and lose the rating entirely if
///   the output is dropped or reordered. When no such output exists the
///   parser has to invent one, and the sentinel it invents (`"nobody"`)
///   has no `Freer`, so the carve confirms and changes nothing.
/// - The envelope's **`did`**, which is FEIP0's *document* id — an
///   identifier for an on-chain record, not for a party. Android's
///   `RateFreerActivity` puts the ratee there.
///
/// A protocol field says what it means and costs nothing to carry, so
/// the ratee goes in `data` beside the verdict it belongs to. This
/// builder emits no `did`, and
/// ``ActiveSession/rateOnChain(ratee:rate:cause:weightCd:feePerByte:timeoutMs:)``
/// pays nobody: a rating's only costs are the miner fee and the
/// CoinDays that give it its weight.
public enum ReputationFeip {

    public static let sn = "16"
    public static let ver = "1"
    public static let protocolName = "Reputation"

    /// Same OP_RETURN ceiling every carve in this app is held to.
    public static let maxOpReturnSize = MailFeip.maxOpReturnSize

    public enum Failure: Error, CustomStringConvertible {
        case tooLarge(bytes: Int)
        case rateeNotAnFid(String, underlying: Error?)
        case encoding(underlying: Error)

        public var description: String {
            switch self {
            case .tooLarge(let bytes):
                return "ReputationFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit — shorten the cause"
            case let .rateeNotAnFid(value, underlying):
                let tail = underlying.map { " — \($0)" } ?? ""
                return "ReputationFeip: \"\(value)\" is not an FCH address, so there is nobody to rate\(tail)"
            case .encoding(let e):
                return "ReputationFeip: JSON encoding failed — \(e)"
            }
        }
    }

    /// The complete OP_RETURN payload for one rating.
    ///
    /// `ratee` is checked to be a real FCH address before anything is
    /// built. A carve naming a FID that cannot exist would confirm and
    /// cost its sender the fee and the CoinDays while matching no
    /// `Freer` — the same silent nothing the recipient-output reading
    /// produced, and just as worth refusing here rather than on chain.
    ///
    /// `cause` is trimmed, and an empty one is omitted rather than
    /// carved as `""` — Android's `makeRate` passes null for a blank
    /// box and Gson drops null fields, so an empty string here would be
    /// a shape no other client writes.
    public static func carve(ratee: String, rate: Rate, cause: String? = nil) throws -> String {
        let fid = ratee.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fid.isEmpty else { throw Failure.rateeNotAnFid(ratee, underlying: nil) }
        do {
            _ = try FchAddress(fid: fid)
        } catch {
            throw Failure.rateeNotAnFid(fid, underlying: error)
        }

        var data: [String: Any] = ["fid": fid, "rate": rate.rawValue]
        if let trimmed = cause?.trimmingCharacters(in: .whitespacesAndNewlines),
           !trimmed.isEmpty {
            data["cause"] = trimmed
        }
        let dataJson = try jsonString(data)
        let json = #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(dataJson)}"#
        let bytes = json.utf8.count
        guard bytes <= maxOpReturnSize else { throw Failure.tooLarge(bytes: bytes) }
        return json
    }

    /// The bytes a `cause` may occupy, for a UI that wants to show a
    /// budget rather than only report a failure.
    ///
    /// It is the envelope's own size — the ratee's FID included, since
    /// that is now part of the payload — subtracted from the limit, so
    /// it counts the *encoded* cause: a character that JSON escapes,
    /// and any character outside ASCII, spends more than one. ``carve``
    /// is the authority; this is what to draw a counter against, not
    /// what to decide by.
    public static func maxCauseBytes(ratee: String, rate: Rate) -> Int {
        guard let empty = try? carve(ratee: ratee, rate: rate).utf8.count else { return 0 }
        // `"cause":"…",` plus room for the shortest possible body.
        let overhead = #""cause":"","#.utf8.count
        return max(0, maxOpReturnSize - empty - overhead)
    }

    private static func jsonString(_ object: [String: Any]) throws -> String {
        do {
            let data = try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys]
            )
            guard let s = String(data: data, encoding: .utf8) else {
                throw Failure.encoding(underlying: NSError(
                    domain: "ReputationFeip", code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "non-utf8 JSON output"]
                ))
            }
            return s
        } catch let e as Failure {
            throw e
        } catch {
            throw Failure.encoding(underlying: error)
        }
    }
}

/// How a FID's ``Freer/weight`` is arrived at — port of FC-AJDK's
/// `core/fch/Weight.java`, which FEIP16 calls `reCalcWeight()`.
///
/// Here only to be *shown*, never to be trusted over the server's own
/// number: the indexer computes weight at parse time and the ratios
/// below are the reference implementation's, not consensus. The details
/// sheet uses it to explain what the number is made of.
public enum WeightMethod {

    public static let cdPercent: Int64 = 40
    public static let cddPercent: Int64 = 10
    public static let reputationPercent: Int64 = 50

    public static func weight(cd: Int64, cdd: Int64, reputation: Int64) -> Int64 {
        (cd * cdPercent + cdd * cddPercent + reputation * reputationPercent) / 100
    }
}

/// Reads the `reputation_history` index — the per-transaction record
/// FEIP16 writes beside every rating it accepts.
///
/// **Why the history and not just ``Freer/reputation``.** The Freer
/// carries the running totals, which say how a FID stands but nothing
/// about how it got there: one whale's opinion and a hundred small
/// agreeing ones produce the same score. The history is where that
/// difference lives, and it is also the only way to answer "have I
/// rated this FID before" — the protocol has no update op, so rating
/// someone twice simply adds a second row.
///
/// Stateless, like ``DirectoryService`` and ``NewsService``: nothing is
/// cached, because a rating is cheap to re-read and expensive to be
/// wrong about.
public struct ReputationService: Sendable {

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "ReputationService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "ReputationService: \(e)"
            }
        }
    }

    /// One page of ratings, newest first.
    public struct Page: Sendable {
        public let ratings: [RepuHist]
        /// The server's cursor for the next page.
        public let last: [String]?
        /// How many rows match server-side, when reported — the
        /// "showing 25 of 300" half of a list footer.
        public let total: Int64?

        public init(ratings: [RepuHist], last: [String]?, total: Int64?) {
            self.ratings = ratings
            self.last = last
            self.total = total
        }
    }

    public static let index = "reputation_history"

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    /// Ratings **received** by `fid`, newest first. Mirrors Android's
    /// `RateHistoryActivity.fetchFromApi`: a `terms` query on `ratee`,
    /// sorted `height, id` descending, paged by the row cursor.
    public func received(
        by fid: String,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        try await page(field: "ratee", value: fid, after: after, size: size, timeoutMs: timeoutMs)
    }

    /// Ratings **given** by `fid`. Same index, the other side of the
    /// row — what a person's own rating history looks like to them.
    public func given(
        by fid: String,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        try await page(field: "rater", value: fid, after: after, size: size, timeoutMs: timeoutMs)
    }

    /// The ratings `rater` has carved against `ratee` — usually none,
    /// occasionally one, and worth knowing before somebody carves
    /// another. FEIP16 has no update op: a second rating does not
    /// replace the first, it adds to it.
    ///
    /// Narrowed server-side with a `filter` beside the query rather
    /// than fetched-and-sieved, so the answer does not depend on how
    /// many pages of the ratee's history we happened to pull.
    public func ratings(
        by rater: String,
        of ratee: String,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        guard !rater.isEmpty, !ratee.isEmpty else {
            return Page(ratings: [], last: nil, total: 0)
        }
        return try await page(
            field: "ratee", value: ratee,
            filter: ("rater", rater),
            after: nil, size: size, timeoutMs: timeoutMs
        )
    }

    private func page(
        field: String,
        value: String,
        filter: (field: String, value: String)? = nil,
        after: [String]?,
        size: Int,
        timeoutMs: Int
    ) async throws -> Page {
        guard !value.isEmpty else { return Page(ratings: [], last: nil, total: 0) }
        var dict: [String: Any] = [
            "entity": Self.index,
            "query": ["terms": ["fields": [field], "values": [value]]],
            "sort": [
                ["field": "height", "order": "desc"],
                ["field": "id", "order": "desc"]
            ],
            "size": String(size)
        ]
        if let filter {
            dict["filter"] = ["terms": ["fields": [filter.field], "values": [filter.value]]]
        }
        if let after, !after.isEmpty { dict["after"] = after }

        let body: Data
        do {
            body = try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
        } catch {
            throw Failure.underlying(error)
        }
        let reply = try await fapi.call(
            api: "base.search",
            params: nil, fcdsl: body, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        // 404 is "nobody has ever rated this FID", which is the normal
        // state of most FIDs and not a failure.
        if let code = resp.code, code != 0 {
            if code == 404 { return Page(ratings: [], last: nil, total: 0) }
            throw Failure.fapiNonZeroCode(
                api: "base.search", code: code, message: resp.message
            )
        }
        guard let data = resp.data else {
            return Page(ratings: [], last: resp.last, total: resp.total)
        }
        do {
            let rows = try JSONDecoder().decode([RepuHist].self, from: data)
            return Page(ratings: rows, last: resp.last, total: resp.total)
        } catch {
            throw Failure.underlying(error)
        }
    }
}
