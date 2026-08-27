import Foundation

/// Builders for the FEIP `APP` protocol (sn 15, ver 1) — the OP_RETURN
/// JSON that registers, amends and retires an app record on the FCH
/// chain. Mirrors the Java `Feip.fromName(APP)` + `AppOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"15","ver":"1","name":"APP",
///  "data":{"op":"publish","stdName":"Freer","ver":"1.4.2",
///          "types":["wallet","im"],"home":{"site":"https://…"},
///          "downloads":[{"did":"…","link":"https://…","os":"macos"}],
///          "codes":["<code id>"],"services":["<sid>"]}}
/// ```
///
/// **The protocol name is `APP`, in capitals.** The other three
/// Construct records are `FeipProtocol`, `Code` and `Service` — title
/// case, spelled the way the type is — so `App` is exactly what a port
/// writes here, and it would be wrong. Java's enum says `APP("15","1",
/// "APP")` and the indexer matches on that string.
///
/// **The record is named by `aid`, not `pid`, `codeId` or `sid`.** One
/// subject field per record, four different spellings, and the one
/// thing a port copies wrong — so it is named in full at every call
/// site here.
///
/// **`downloads` is a list of objects, not of strings.** It is the only
/// nested structure anywhere in the family, and the only field Android
/// never implemented: both its activities pass `null` there, so an
/// update carved from Android **erases whatever downloads were already
/// on the record** (**Android issue C23**).
///
/// **Nothing here is encrypted.** A published app record is a public
/// registration, which is why the carves enforce the OP_RETURN size
/// limit before anything is signed.
public enum AppFeip {

    public static let sn = FeipProtocol.app.sn
    public static let ver = FeipProtocol.app.ver
    /// `"APP"` — see the type note. Read from the registry rather than
    /// spelled here, so the two cannot drift.
    public static let protocolName = FeipProtocol.app.protocolName

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
        case noAid
        case noAids
        case rateOutOfRange(Int)
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "AppFeip: JSON encoding failed — \(e)"
            case .emptyStdName:
                return "AppFeip: an app needs a standard name"
            case .noAid:
                return "AppFeip: no app given"
            case .noAids:
                return "AppFeip: no apps given"
            case .rateOutOfRange(let r):
                return "AppFeip: a rating is 1 to 5, not \(r)"
            case .tooLarge(let bytes):
                return "AppFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. A registration is not compressed or encrypted — shorten the description, drop a download, or drop a code or protocol id."
            }
        }
    }

    // MARK: - op payloads

    /// `{"op":"publish",…}` — register an app.
    ///
    /// Empty values are omitted rather than sent as `""` or `[]`: an
    /// absent key and an empty one read the same to the indexer, and
    /// every omitted byte is OP_RETURN budget the description can use.
    ///
    /// **`rate` is not emitted, and here Android agrees.**
    /// `AppOpData.rate` is a boxed `Integer`, so Gson drops it;
    /// `ProtocolOpData.rate` is a primitive `int` and Gson writes
    /// `"rate":0` into every protocol op instead (**Android issue
    /// C20**). Three of the four Construct records are clean and one is
    /// not, which is why each says so.
    public static func publishOp(
        stdName: String?,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [AppRecord.Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.publish.rawValue]
        fill(&dict, stdName: stdName, localNames: localNames, types: types,
             desc: desc, ver: ver, home: home, downloads: downloads,
             waiters: waiters, protocols: protocols, codes: codes, services: services)
        return try jsonString(dict)
    }

    /// `{"op":"update","aid":…}` — amend a registration you own.
    ///
    /// Every field is resent, not just the changed ones: the op
    /// replaces the record's mutable half, so a field omitted here is a
    /// field cleared on chain. That is exactly how Android erases
    /// `downloads` — it omits them because it never had them.
    public static func updateOp(
        aid: String,
        stdName: String?,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [AppRecord.Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil
    ) throws -> String {
        guard !aid.isEmpty else { throw Failure.noAid }
        var dict: [String: Any] = ["op": Op.update.rawValue, "aid": aid]
        fill(&dict, stdName: stdName, localNames: localNames, types: types,
             desc: desc, ver: ver, home: home, downloads: downloads,
             waiters: waiters, protocols: protocols, codes: codes, services: services)
        return try jsonString(dict)
    }

    /// `{"op":"stop","aids":[…]}` — take app records out of force,
    /// reversibly. A list, because the protocol takes one and that is
    /// the difference between one miner fee and several.
    public static func stopOp(aids: [String]) throws -> String {
        try idListOp(.stop, aids: aids)
    }

    /// `{"op":"recover","aids":[…]}` — put stopped app records back in
    /// force. The only op that undoes another, and it does not undo
    /// `close`.
    public static func recoverOp(aids: [String]) throws -> String {
        try idListOp(.recover, aids: aids)
    }

    /// `{"op":"close","aids":[…],"closeStatement":…}` — retire app
    /// records permanently, with an optional reason.
    public static func closeOp(
        aids: [String], closeStatement: String? = nil
    ) throws -> String {
        let clean = aids.filter { !$0.isEmpty }
        guard !clean.isEmpty else { throw Failure.noAids }
        var dict: [String: Any] = ["op": Op.close.rawValue, "aids": clean]
        if let closeStatement,
           !closeStatement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dict["closeStatement"] = closeStatement
        }
        return try jsonString(dict)
    }

    /// `{"op":"rate","aid":…,"rate":n}` — score an app 1–5.
    ///
    /// The score's *weight* is not in this payload: the chain counts the
    /// coin-days the rating transaction destroys. Selecting those inputs
    /// is Phase 8.7.5; the builder is here because the payload is part
    /// of the protocol, not because a caller exists.
    public static func rateOp(aid: String, rate: Int) throws -> String {
        guard !aid.isEmpty else { throw Failure.noAid }
        guard (1...5).contains(rate) else { throw Failure.rateOutOfRange(rate) }
        return try jsonString(["op": Op.rate.rawValue, "aid": aid, "rate": rate])
    }

    // MARK: - complete carves

    /// The full OP_RETURN payload for a `publish`, with the name guard
    /// and the size check applied before a caller can spend anything on
    /// it.
    public static func publishCarve(
        stdName: String,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [AppRecord.Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil
    ) throws -> String {
        guard !stdName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyStdName
        }
        return try sized(envelope(opJson: publishOp(
            stdName: stdName, localNames: localNames, types: types, desc: desc,
            ver: ver, home: home, downloads: downloads, waiters: waiters,
            protocols: protocols, codes: codes, services: services
        )))
    }

    /// The full OP_RETURN payload for an `update`, same guards.
    public static func updateCarve(
        aid: String,
        stdName: String,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [AppRecord.Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil
    ) throws -> String {
        guard !stdName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyStdName
        }
        return try sized(envelope(opJson: updateOp(
            aid: aid, stdName: stdName, localNames: localNames, types: types,
            desc: desc, ver: ver, home: home, downloads: downloads,
            waiters: waiters, protocols: protocols, codes: codes, services: services
        )))
    }

    public static func stopCarve(aids: [String]) throws -> String {
        try sized(envelope(opJson: stopOp(aids: aids)))
    }

    public static func recoverCarve(aids: [String]) throws -> String {
        try sized(envelope(opJson: recoverOp(aids: aids)))
    }

    public static func closeCarve(
        aids: [String], closeStatement: String? = nil
    ) throws -> String {
        try sized(envelope(opJson: closeOp(aids: aids, closeStatement: closeStatement)))
    }

    /// How many more UTF-8 bytes of `desc` a carve can take before it
    /// exceeds the OP_RETURN limit, given everything else already filled
    /// in. Negative once over.
    ///
    /// **A download row is the most expensive thing on this form.** Each
    /// carries a URL and usually a 64-character digest, so three
    /// platforms cost more than the whole rest of a typical record.
    /// Measured on the encoded envelope rather than estimated, with the
    /// `desc` key present even when the description is empty — the op
    /// builders omit empty fields, so measuring an empty draft directly
    /// would count the `"desc":""` overhead as free.
    public static func remainingDescBytes(
        aid: String? = nil,
        stdName: String,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [AppRecord.Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil
    ) -> Int {
        let probe = desc.isEmpty ? "x" : desc
        let op: String?
        if let aid, !aid.isEmpty {
            op = try? updateOp(
                aid: aid, stdName: stdName, localNames: localNames, types: types,
                desc: probe, ver: ver, home: home, downloads: downloads,
                waiters: waiters, protocols: protocols, codes: codes, services: services
            )
        } else {
            op = try? publishOp(
                stdName: stdName, localNames: localNames, types: types,
                desc: probe, ver: ver, home: home, downloads: downloads,
                waiters: waiters, protocols: protocols, codes: codes, services: services
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
        stdName: String?, localNames: [String: String]?, types: [String]?,
        desc: String?, ver: String?, home: [String: String]?,
        downloads: [AppRecord.Download]?, waiters: [String]?,
        protocols: [String]?, codes: [String]?, services: [String]?
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
        putList("types", types)
        // Not trimmed to a single line, but not sent empty either — the
        // description is prose and its internal whitespace is the
        // author's.
        if let desc, !desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dict["desc"] = desc
        }
        put("ver", ver)
        if let home, !home.isEmpty { dict["home"] = home }
        // Pruned per row and then as a whole: a row that names an OS and
        // offers neither a link nor a digest is bytes spent to say
        // nothing.
        if let downloads {
            let kept = downloads.compactMap(\.pruned).map(\.wireObject).filter { !$0.isEmpty }
            if !kept.isEmpty { dict["downloads"] = kept }
        }
        putList("waiters", waiters)
        putList("protocols", protocols)
        putList("codes", codes)
        putList("services", services)
    }

    private static func idListOp(_ op: Op, aids: [String]) throws -> String {
        let clean = aids.filter { !$0.isEmpty }
        guard !clean.isEmpty else { throw Failure.noAids }
        return try jsonString(["op": op.rawValue, "aids": clean])
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
                    domain: "AppFeip", code: -1,
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
