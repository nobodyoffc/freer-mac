import Foundation

/// Builders for the FEIP `Service` protocol (sn 5, ver 3) — the
/// OP_RETURN JSON that registers, amends and retires a service record
/// on the FCH chain. Mirrors the Java `Feip.fromName(SERVICE)` +
/// `ServiceOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"5","ver":"3","name":"Service",
///  "data":{"op":"publish","stdName":"DOCK@No1_NrC7",
///          "type":"FAPI@No1_NrC7","components":["DOCK@No1_NrC7"],
///          "home":{"API":"https://cid.cash/APIP"},
///          "codes":["<code id>"],"pricePerKB":"0.0001",
///          "currency":"FCH","maxDataSize":"262144"}}
/// ```
///
/// **The record is named by `sid`, not `pid` or `codeId`.** Each of the
/// four Construct records spells its subject differently — `pid`,
/// `codeId`, `sid`, and App's own — which is the one field a port
/// copies wrong, so it is named in full at every call site here.
///
/// **The pricing fields are flat, not nested.** ``Pricing`` groups the
/// thirteen of them so a call signature stays readable; the JSON puts
/// every one at the top level of `data`, next to `stdName`. Java has a
/// `params` object that *looks* like where they would live — they were
/// moved out of it and it is now always null. This builder does not
/// emit `params` at all.
///
/// **Nothing here is encrypted.** A published service record is a public
/// registration, which is why the carves enforce the OP_RETURN size
/// limit before anything is signed — and on this record that limit is
/// the tightest of the four: a service can carry five id lists, a
/// language map, a URL map and thirteen prices, and 4096 bytes is not
/// as much as it sounds.
public enum ServiceFeip {

    public static let sn = FeipProtocol.service.sn
    public static let ver = FeipProtocol.service.ver
    public static let protocolName = FeipProtocol.service.protocolName

    /// The largest OP_RETURN the chain accepts.
    public static let maxOpReturnSize = MailFeip.maxOpReturnSize

    /// The six ops the protocol defines. Everything except `rate` is
    /// owner-only, and `stop` and `close` are not the same retirement.
    public enum Op: String, CaseIterable, Sendable {
        case publish
        case update
        case stop
        case recover
        case close
        case rate
    }

    public enum Failure: Error, CustomStringConvertible {
        case encoding(underlying: Error)
        case emptyStdName
        case noSid
        case noSids
        case rateOutOfRange(Int)
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "ServiceFeip: JSON encoding failed — \(e)"
            case .emptyStdName:
                return "ServiceFeip: a service needs a standard name"
            case .noSid:
                return "ServiceFeip: no service given"
            case .noSids:
                return "ServiceFeip: no services given"
            case .rateOutOfRange(let r):
                return "ServiceFeip: a rating is 1 to 5, not \(r)"
            case .tooLarge(let bytes):
                return "ServiceFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. A registration is not compressed or encrypted — shorten the description, drop a component, a protocol or a code id, or leave prices you are not charging unset."
            }
        }
    }

    // MARK: - pricing

    /// The thirteen pricing and configuration fields, grouped.
    ///
    /// **Strings, not numbers, all the way through.** The chain carries
    /// every one of them as a decimal string, and parsing them into
    /// `Decimal` here would mean re-serialising the operator's `"0.10"`
    /// as `0.1` — a different record from the one they typed. The sheet
    /// validates that they *look* numeric and leaves the text alone.
    public struct Pricing: Equatable, Sendable {
        public var pricePerKB: String?
        public var pricePerKBIn: String?
        public var pricePerKBOut: String?
        public var pricePerKBDay: String?
        public var minPayment: String?
        public var pricePerRequest: String?
        public var sessionDays: String?
        public var consumeViaShare: String?
        public var orderViaShare: String?
        public var currency: String?
        public var minCredit: String?
        public var maxDataSize: String?
        public var dataExpiresInDays: String?

        public init(
            pricePerKB: String? = nil,
            pricePerKBIn: String? = nil,
            pricePerKBOut: String? = nil,
            pricePerKBDay: String? = nil,
            minPayment: String? = nil,
            pricePerRequest: String? = nil,
            sessionDays: String? = nil,
            consumeViaShare: String? = nil,
            orderViaShare: String? = nil,
            currency: String? = nil,
            minCredit: String? = nil,
            maxDataSize: String? = nil,
            dataExpiresInDays: String? = nil
        ) {
            self.pricePerKB = pricePerKB
            self.pricePerKBIn = pricePerKBIn
            self.pricePerKBOut = pricePerKBOut
            self.pricePerKBDay = pricePerKBDay
            self.minPayment = minPayment
            self.pricePerRequest = pricePerRequest
            self.sessionDays = sessionDays
            self.consumeViaShare = consumeViaShare
            self.orderViaShare = orderViaShare
            self.currency = currency
            self.minCredit = minCredit
            self.maxDataSize = maxDataSize
            self.dataExpiresInDays = dataExpiresInDays
        }

        /// Wire key → value, in the order Java declares them. Empties
        /// dropped: an absent price and an empty one read the same, and
        /// every omitted byte is budget the description can use.
        public var wirePairs: [(String, String)] {
            let all: [(String, String?)] = [
                ("pricePerKB", pricePerKB),
                ("pricePerKBIn", pricePerKBIn),
                ("pricePerKBOut", pricePerKBOut),
                ("pricePerKBDay", pricePerKBDay),
                ("minPayment", minPayment),
                ("pricePerRequest", pricePerRequest),
                ("sessionDays", sessionDays),
                ("consumeViaShare", consumeViaShare),
                ("orderViaShare", orderViaShare),
                ("currency", currency),
                ("minCredit", minCredit),
                ("maxDataSize", maxDataSize),
                ("dataExpiresInDays", dataExpiresInDays)
            ]
            return all.compactMap { key, value in
                guard let value else { return nil }
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                return trimmed.isEmpty ? nil : (key, trimmed)
            }
        }

        /// Whether anything at all is set.
        public var isEmpty: Bool { wirePairs.isEmpty }

        /// The same bag with blanks turned to nil and the rest trimmed
        /// — what a draft should store, so what it shows is what it
        /// will carve.
        public var pruned: Pricing {
            var out = Pricing()
            for (key, value) in wirePairs {
                switch key {
                case "pricePerKB":        out.pricePerKB = value
                case "pricePerKBIn":      out.pricePerKBIn = value
                case "pricePerKBOut":     out.pricePerKBOut = value
                case "pricePerKBDay":     out.pricePerKBDay = value
                case "minPayment":        out.minPayment = value
                case "pricePerRequest":   out.pricePerRequest = value
                case "sessionDays":       out.sessionDays = value
                case "consumeViaShare":   out.consumeViaShare = value
                case "orderViaShare":     out.orderViaShare = value
                case "currency":          out.currency = value
                case "minCredit":         out.minCredit = value
                case "maxDataSize":       out.maxDataSize = value
                case "dataExpiresInDays": out.dataExpiresInDays = value
                default: break
                }
            }
            return out
        }
    }

    // MARK: - op payloads

    /// `{"op":"publish",…}` — register a running service.
    ///
    /// Empty values are omitted rather than sent as `""` or `[]`.
    ///
    /// **`rate` is not emitted, and here Android agrees.**
    /// `ServiceOpData.rate` is a boxed `Integer`, so Gson drops it;
    /// `ProtocolOpData.rate` is a primitive `int` and Gson writes
    /// `"rate":0` into every protocol op instead (**Android issue
    /// C20**). Two of the four Construct records have the bug and two do
    /// not, which is a good reason to say so on each copy.
    public static func publishOp(
        stdName: String?,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        pricing: Pricing = .init()
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.publish.rawValue]
        fill(&dict, stdName: stdName, localNames: localNames, desc: desc,
             type: type, components: components, ver: ver, home: home,
             waiters: waiters, protocols: protocols, codes: codes,
             services: services, pricing: pricing)
        return try jsonString(dict)
    }

    /// `{"op":"update","sid":…}` — amend a registration you own.
    ///
    /// Every field is resent, not just the changed ones: the op
    /// replaces the record's mutable half, so a field omitted here is a
    /// field cleared on chain. That matters more on a service than on
    /// the other three — clearing `home` by omission takes the endpoint
    /// off the chain and every client resolving that SID stops finding
    /// it.
    public static func updateOp(
        sid: String,
        stdName: String?,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        pricing: Pricing = .init()
    ) throws -> String {
        guard !sid.isEmpty else { throw Failure.noSid }
        var dict: [String: Any] = ["op": Op.update.rawValue, "sid": sid]
        fill(&dict, stdName: stdName, localNames: localNames, desc: desc,
             type: type, components: components, ver: ver, home: home,
             waiters: waiters, protocols: protocols, codes: codes,
             services: services, pricing: pricing)
        return try jsonString(dict)
    }

    /// `{"op":"stop","sids":[…]}` — take services out of force,
    /// reversibly. A list, because the protocol takes one and that is
    /// the difference between one miner fee and several.
    public static func stopOp(sids: [String]) throws -> String {
        try idListOp(.stop, sids: sids)
    }

    /// `{"op":"recover","sids":[…]}` — put stopped services back in
    /// force. The only op that undoes another, and it does not undo
    /// `close`.
    public static func recoverOp(sids: [String]) throws -> String {
        try idListOp(.recover, sids: sids)
    }

    /// `{"op":"close","sids":[…],"closeStatement":…}` — retire services
    /// permanently, with an optional reason.
    public static func closeOp(
        sids: [String], closeStatement: String? = nil
    ) throws -> String {
        let clean = sids.filter { !$0.isEmpty }
        guard !clean.isEmpty else { throw Failure.noSids }
        var dict: [String: Any] = ["op": Op.close.rawValue, "sids": clean]
        if let closeStatement,
           !closeStatement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dict["closeStatement"] = closeStatement
        }
        return try jsonString(dict)
    }

    /// `{"op":"rate","sid":…,"rate":n}` — score a service 1–5.
    ///
    /// The score's *weight* is not in this payload: the chain counts the
    /// coin-days the rating transaction destroys. Selecting those inputs
    /// is Phase 8.7.5; the builder is here because the payload is part
    /// of the protocol, not because a caller exists.
    public static func rateOp(sid: String, rate: Int) throws -> String {
        guard !sid.isEmpty else { throw Failure.noSid }
        guard (1...5).contains(rate) else { throw Failure.rateOutOfRange(rate) }
        return try jsonString(["op": Op.rate.rawValue, "sid": sid, "rate": rate])
    }

    // MARK: - complete carves

    /// The full OP_RETURN payload for a `publish`, with the name guard
    /// and the size check applied before a caller can spend anything on
    /// it.
    public static func publishCarve(
        stdName: String,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        pricing: Pricing = .init()
    ) throws -> String {
        guard !stdName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyStdName
        }
        return try sized(envelope(opJson: publishOp(
            stdName: stdName, localNames: localNames, desc: desc, type: type,
            components: components, ver: ver, home: home, waiters: waiters,
            protocols: protocols, codes: codes, services: services, pricing: pricing
        )))
    }

    /// The full OP_RETURN payload for an `update`, same guards.
    public static func updateCarve(
        sid: String,
        stdName: String,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        pricing: Pricing = .init()
    ) throws -> String {
        guard !stdName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyStdName
        }
        return try sized(envelope(opJson: updateOp(
            sid: sid, stdName: stdName, localNames: localNames, desc: desc,
            type: type, components: components, ver: ver, home: home,
            waiters: waiters, protocols: protocols, codes: codes,
            services: services, pricing: pricing
        )))
    }

    public static func stopCarve(sids: [String]) throws -> String {
        try sized(envelope(opJson: stopOp(sids: sids)))
    }

    public static func recoverCarve(sids: [String]) throws -> String {
        try sized(envelope(opJson: recoverOp(sids: sids)))
    }

    public static func closeCarve(
        sids: [String], closeStatement: String? = nil
    ) throws -> String {
        try sized(envelope(opJson: closeOp(sids: sids, closeStatement: closeStatement)))
    }

    /// How many more UTF-8 bytes of `desc` a carve can take before it
    /// exceeds the OP_RETURN limit, given everything else already filled
    /// in. Negative once over.
    ///
    /// **The budget matters most on this record.** A service can name
    /// five id lists — components, waiters, protocols, codes, services —
    /// where protocol and code ids are 64 hex characters each, plus a
    /// URL map, a name map and thirteen prices. Four code ids and four
    /// protocol ids are already 550-odd bytes before a word of prose.
    /// Android checks nothing at all: you fill the form, press Publish,
    /// and the transaction fails at broadcast.
    ///
    /// Measured on the encoded envelope rather than estimated, with the
    /// `desc` key present even when the description is empty — the op
    /// builders omit empty fields, so measuring an empty draft directly
    /// would count the `"desc":""` overhead as free.
    public static func remainingDescBytes(
        sid: String? = nil,
        stdName: String,
        localNames: [String: String]? = nil,
        desc: String,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        pricing: Pricing = .init()
    ) -> Int {
        let probe = desc.isEmpty ? "x" : desc
        let op: String?
        if let sid, !sid.isEmpty {
            op = try? updateOp(
                sid: sid, stdName: stdName, localNames: localNames, desc: probe,
                type: type, components: components, ver: ver, home: home,
                waiters: waiters, protocols: protocols, codes: codes,
                services: services, pricing: pricing
            )
        } else {
            op = try? publishOp(
                stdName: stdName, localNames: localNames, desc: probe,
                type: type, components: components, ver: ver, home: home,
                waiters: waiters, protocols: protocols, codes: codes,
                services: services, pricing: pricing
            )
        }
        let json = op.map { envelope(opJson: $0) } ?? ""
        let used = Data(json.utf8).count - (desc.isEmpty ? 1 : 0)
        return maxOpReturnSize - used
    }

    // MARK: - envelope

    public static func envelope(opJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(opJson)}"#
    }

    // MARK: - shared

    /// The fields `publish` and `update` share, empties omitted.
    private static func fill(
        _ dict: inout [String: Any],
        stdName: String?, localNames: [String: String]?, desc: String?,
        type: String?, components: [String]?, ver: String?,
        home: [String: String]?, waiters: [String]?, protocols: [String]?,
        codes: [String]?, services: [String]?, pricing: Pricing
    ) {
        func put(_ key: String, _ value: String?) {
            guard let value else { return }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            dict[key] = trimmed
        }
        func putList(_ key: String, _ value: [String]?) {
            guard let value else { return }
            let clean = value
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            guard !clean.isEmpty else { return }
            dict[key] = clean
        }
        put("stdName", stdName)
        if let localNames, !localNames.isEmpty { dict["localNames"] = localNames }
        // Not trimmed to a single line, but not sent empty either — the
        // description is prose and its internal whitespace is the
        // author's.
        if let desc, !desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dict["desc"] = desc
        }
        put("type", type)
        putList("components", components)
        put("ver", ver)
        if let home, !home.isEmpty { dict["home"] = home }
        putList("waiters", waiters)
        putList("protocols", protocols)
        putList("codes", codes)
        putList("services", services)
        for (key, value) in pricing.wirePairs { dict[key] = value }
    }

    private static func idListOp(_ op: Op, sids: [String]) throws -> String {
        let clean = sids.filter { !$0.isEmpty }
        guard !clean.isEmpty else { throw Failure.noSids }
        return try jsonString(["op": op.rawValue, "sids": clean])
    }

    private static func sized(_ json: String) throws -> String {
        let bytes = Data(json.utf8).count
        guard bytes <= maxOpReturnSize else { throw Failure.tooLarge(bytes: bytes) }
        return json
    }

    private static func jsonString(_ object: [String: Any]) throws -> String {
        do {
            let data = try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]
            )
            guard let s = String(data: data, encoding: .utf8) else {
                throw Failure.encoding(underlying: NSError(
                    domain: "ServiceFeip", code: -1,
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
