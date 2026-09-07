import Foundation
import FCCore
import FCTransport

/// Which ratable record a rating is about.
///
/// **Ten protocols, one rating mechanism.** FEIP 1, 2, 5, 15, 18, 21,
/// 22, 23, 24 and 25 each define a `rate` op with the same shape: a
/// 0–5 score, an optional `cause`, weighted by the transaction's
/// CoinDays destroyed, folded into the record's `tRate` / `tCdd` as a
/// CDD-weighted mean, and recorded on a `*_history` row. What differs
/// between them is a serial number, an index name, and how the subject
/// field is spelled — `pid` / `codeId` / `sid` / `aid` / `tid` /
/// `textId` / `remarkId` / `soundId` / `imageId` / `videoId`.
///
/// So this is the ``MediaKind`` argument taken one level further out:
/// the differences are named once, here, and every rating sheet,
/// history list and carve reads them from this enum rather than
/// respelling them. A subject key applied to the wrong index produces a
/// carve the client accepts, the parser rejects, and the chain keeps
/// the fee for.
///
/// **This is not FEIP16.** A `Reputation` rating is `good`/`bad` about
/// a *person*, signed, and covered by ``Rate`` and ``RepuHist``. These
/// ten are numeric ratings of *records*. They share the CoinDay
/// weighting and nothing else.
public enum RatableKind: String, CaseIterable, Sendable, Identifiable, Codable {
    case protocolSpec
    case code
    case service
    case app
    case team
    case text
    case remark
    case image
    case sound
    case video

    public var id: String { rawValue }

    /// The FEIP registry entry, so a protocol bump has one place to
    /// happen rather than ten.
    public var feip: FeipProtocol {
        switch self {
        case .protocolSpec: return .protocolMeta
        case .code:         return .code
        case .service:      return .service
        case .app:          return .app
        case .team:         return .team
        case .text:         return .text
        case .remark:       return .remark
        case .image:        return .image
        case .sound:        return .sound
        case .video:        return .video
        }
    }

    /// The record index — Java's `IndicesNames` value.
    public var index: String {
        switch self {
        case .protocolSpec: return "protocol"
        default:            return rawValue
        }
    }

    /// The history index the `rate` rows land in.
    public var historyIndex: String { "\(index)_history" }

    /// The op field naming one record. **The whole hazard**, as
    /// ``MediaKind/subjectKey`` puts it: the ten spellings are not
    /// interchangeable, and using the wrong one loses the rating.
    public var subjectKey: String {
        switch self {
        case .protocolSpec: return "pid"
        case .code:         return "codeId"
        case .service:      return "sid"
        case .app:          return "aid"
        case .team:         return "tid"
        case .text:         return "textId"
        case .remark:       return "remarkId"
        case .image:        return "imageId"
        case .sound:        return "soundId"
        case .video:        return "videoId"
        }
    }

    /// What to call one of these on screen.
    public var label: String {
        switch self {
        case .protocolSpec: return "Protocol"
        case .code:         return "Code"
        case .service:      return "Service"
        case .app:          return "App"
        case .team:         return "Team"
        case .text:         return "Text"
        case .remark:       return "Remark"
        case .image:        return "Image"
        case .sound:        return "Sound"
        case .video:        return "Video"
        }
    }

    /// The field naming whoever may not rate their own record: the
    /// Construct four and Team call it `owner`, the Publish five call
    /// it `publisher`. Only used in prose, but the two words are not
    /// synonyms in the specs and the sheets should not blur them.
    public var ownerNoun: String {
        switch self {
        case .protocolSpec, .code, .service, .app, .team: return "owner"
        case .text, .remark, .image, .sound, .video:      return "publisher"
        }
    }

    /// The equivalent ``MediaKind``, for the three that have one.
    public var mediaKind: MediaKind? {
        switch self {
        case .image: return .image
        case .sound: return .sound
        case .video: return .video
        default:     return nil
        }
    }

    public init(mediaKind: MediaKind) {
        switch mediaKind {
        case .image: self = .image
        case .sound: self = .sound
        case .video: self = .video
        }
    }
}

/// The scores the protocols accept: **0 through 5**.
///
/// A closed set rather than an `Int`, because 0 and 5 are not the ends
/// of an open scale — they are the ends of *this* scale, and the
/// reference parser drops anything outside it for the Construct four
/// and Team while silently indexing it for the Publish five. Making the
/// range unrepresentable is how this app cannot be the client that
/// writes a 7 into somebody's `tRate`.
///
/// **0 is a verdict, not a blank.** Android has always offered a 0
/// button and the parser accepts it; the Mac builders used to refuse 0,
/// which quietly made 1 the worst thing this app could say.
public enum RateScore: Int, CaseIterable, Sendable, Identifiable, Codable, Comparable {
    case zero = 0
    case one = 1
    case two = 2
    case three = 3
    case four = 4
    case five = 5

    public var id: Int { rawValue }

    public static func < (a: RateScore, b: RateScore) -> Bool { a.rawValue < b.rawValue }

    /// The words Android puts beside each radio button.
    public var label: String {
        switch self {
        case .zero:  return "Very bad"
        case .one:   return "Bad"
        case .two:   return "Poor"
        case .three: return "Fair"
        case .four:  return "Good"
        case .five:  return "Excellent"
        }
    }
}

/// One `rate` row of a `*_history` index — a single rating, as it
/// landed.
///
/// Deliberately the common subset of the ten history documents rather
/// than ten types: every one of them carries the block context, the
/// signer, the score, the CDD weight and now the cause, and the only
/// field that differs is the subject key — which the caller already
/// knows, because it asked for that subject.
///
/// Every field is optional because the indexer omits keys it has no
/// value for, the same contract as ``RepuHist`` and ``Freer``.
public struct RatingHist: Codable, Hashable, Sendable, Identifiable {

    /// The rating transaction's txid, which is this document's id.
    public var id: String?
    public var height: Int64?
    /// Position of the transaction within its block.
    public var index: Int?
    /// Block timestamp, in **seconds**.
    public var time: Int64?

    /// Who rated — the transaction's signer.
    public var signer: String?

    /// The score as it arrived. Kept as `Int` rather than ``RateScore``
    /// so a row carrying something outside 0–5 still renders; read
    /// ``score`` for the values this app understands. Such rows can
    /// exist: the Publish five bounded `rate` only recently, and
    /// anything indexed before that is still on chain.
    public var rate: Int?

    /// Free text the rater attached. Optional in the protocol and, on
    /// anything carved before this field existed, absent.
    public var cause: String?

    /// CoinDays destroyed by this transaction — the rating's weight in
    /// the record's `tRate` mean.
    public var cdd: Int64?

    /// Which op the row records. Only `rate` rows are ratings; the same
    /// index holds `publish`, `update` and the rest.
    public var op: String?

    public init() {}

    /// The score as a case, or nil for a value outside the protocol's
    /// range.
    public var score: RateScore? { rate.flatMap(RateScore.init(rawValue:)) }

    /// Cursor for the `height, id` sort ``RatingService`` pages by. Nil
    /// when the row is missing either half, in which case the walk
    /// restarts from the top rather than paging into nonsense.
    public var cursor: [String]? {
        guard let height, let id else { return nil }
        return [String(height), id]
    }
}

/// Reads the `rate` rows of the ten ratable protocols' history indices.
///
/// **The record carries the average; the history carries the ratings.**
/// A `Protocol` or a `TextRecord` knows its `tRate` and `tCdd` and
/// nothing else — not who rated it, not what they said, not whether you
/// already have. All of that is in `*_history`, which is why this
/// exists, and it is also the only way to answer "have I rated this
/// before": none of the ten protocols has an un-rate op, so rating a
/// record twice simply adds a second row and moves the mean again.
///
/// Stateless, like ``ReputationService``, and for the same reason.
public struct RatingService: Sendable {

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "RatingService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "RatingService: \(e)"
            }
        }
    }

    /// One page of ratings, newest first.
    public struct Page: Sendable {
        public let ratings: [RatingHist]
        /// The server's cursor for the next page.
        public let last: [String]?
        /// How many rows match server-side, when reported.
        public let total: Int64?

        public init(ratings: [RatingHist], last: [String]?, total: Int64?) {
            self.ratings = ratings
            self.last = last
            self.total = total
        }
    }

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    /// Every rating carved against one record, newest first.
    public func ratings(
        of kind: RatableKind,
        subjectId: String,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        try await page(
            kind: kind, subjectId: subjectId,
            rater: nil, after: after, size: size, timeoutMs: timeoutMs
        )
    }

    /// The ratings `rater` has already carved against this record —
    /// usually none, and worth knowing before they carve another.
    ///
    /// Narrowed server-side rather than fetched-and-sieved, so the
    /// answer does not depend on how many pages we happened to pull.
    public func ratings(
        by rater: String,
        of kind: RatableKind,
        subjectId: String,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        guard !rater.isEmpty else { return Page(ratings: [], last: nil, total: 0) }
        return try await page(
            kind: kind, subjectId: subjectId,
            rater: rater, after: nil, size: size, timeoutMs: timeoutMs
        )
    }

    private func page(
        kind: RatableKind,
        subjectId: String,
        rater: String?,
        after: [String]?,
        size: Int,
        timeoutMs: Int
    ) async throws -> Page {
        guard !subjectId.isEmpty else { return Page(ratings: [], last: nil, total: 0) }

        // `op` is narrowed server-side alongside the subject: these
        // indices hold every operation on the record, and a publish row
        // carries no rate at all. Sieving client-side would spend the
        // page budget on rows that can never be ratings.
        //
        // The two clauses use different keys on purpose. An FCDSL
        // `filter` is one object whose keys are clause types, ANDed —
        // so two `terms` clauses cannot coexist in it, the second would
        // simply replace the first and the rater narrowing would vanish
        // without an error.
        var filter: [String: Any] = [
            "equals": ["fields": ["op"], "values": ["rate"]]
        ]
        if let rater, !rater.isEmpty {
            filter["terms"] = ["fields": ["signer"], "values": [rater]]
        }

        var dict: [String: Any] = [
            "entity": kind.historyIndex,
            "query": ["terms": ["fields": [kind.subjectKey], "values": [subjectId]]],
            "filter": filter,
            "sort": [
                ["field": "height", "order": "desc"],
                ["field": "id", "order": "desc"]
            ],
            "size": String(size)
        ]
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
        // 404 is "nobody has ever rated this record", which is the
        // normal state of most records and not a failure.
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
            let rows = try JSONDecoder().decode([RatingHist].self, from: data)
            return Page(ratings: rows, last: resp.last, total: resp.total)
        } catch {
            throw Failure.underlying(error)
        }
    }
}
