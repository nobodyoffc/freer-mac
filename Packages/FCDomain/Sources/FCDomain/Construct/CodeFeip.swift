import Foundation

/// Builders for the FEIP `Code` protocol (sn 2, ver 1) — the OP_RETURN
/// JSON that registers, amends and retires a code record on the FCH
/// chain. Mirrors the Java `Feip.fromName(CODE)` + `CodeOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"2","ver":"1","name":"Code",
///  "data":{"op":"publish","name":"freer-mac","ver":"1.4.2",
///          "did":"…","langs":["swift"],"protocols":["<pid>"],
///          "home":{"git":"https://…"},"waiters":["…"]}}
/// ```
///
/// **The record is named by `codeId`, not `pid`.** ``ProtocolFeip``
/// spells its subject `pid`/`pids`; this one spells the same idea
/// `codeId`/`codeIds` (Java `FieldNames.CODE_ID` / `CODE_IDS`). The two
/// records are otherwise the same shape, which makes the one field that
/// differs exactly the sort of thing a port copies wrong — so it is
/// named in full at every call site here.
///
/// **Nothing here is encrypted.** A published code record is a public
/// registration — that is the point of putting it on a chain — which is
/// why ``publishCarve(name:ver:did:desc:langs:home:protocols:waiters:)``
/// enforces the OP_RETURN size limit *before* anything is signed.
public enum CodeFeip {

    public static let sn = FeipProtocol.code.sn
    public static let ver = FeipProtocol.code.ver
    public static let protocolName = FeipProtocol.code.protocolName

    /// The largest OP_RETURN the chain accepts — the same limit
    /// ``MailFeip/maxOpReturnSize`` enforces, and for the same reason.
    public static let maxOpReturnSize = MailFeip.maxOpReturnSize

    /// The six ops the protocol defines.
    ///
    /// `stop` and `close` are not the same retirement: a stopped record
    /// is out of force until `recover` puts it back, a closed one is
    /// finished and nothing undoes it. Everything except `rate` is
    /// owner-only.
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
        case emptyName
        case noCodeId
        case noCodeIds
        case rateOutOfRange(Int)
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "CodeFeip: JSON encoding failed — \(e)"
            case .emptyName:
                return "CodeFeip: a code record needs a name"
            case .noCodeId:
                return "CodeFeip: no code given"
            case .noCodeIds:
                return "CodeFeip: no codes given"
            case .rateOutOfRange(let r):
                return "CodeFeip: a rating is 1 to 5, not \(r)"
            case .tooLarge(let bytes):
                return "CodeFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. A registration is not compressed or encrypted — shorten the description, drop a protocol or a waiter, or publish the long form under `home` and carve its DID."
            }
        }
    }

    // MARK: - op payloads

    /// `{"op":"publish",…}` — register an implementation.
    ///
    /// Empty values are omitted rather than sent as `""` or `[]`: an
    /// absent key and an empty one read the same to the indexer, and
    /// every omitted byte is OP_RETURN budget the description can use.
    ///
    /// **`rate` is not emitted, and here Android agrees.**
    /// `ProtocolOpData.rate` is a primitive `int`, so Gson writes
    /// `"rate":0` into every protocol op it sends (**Android issue
    /// C20**); `CodeOpData.rate` is a boxed `Integer`, so it stays null
    /// and Gson drops it. The same bug is one keyword away in the file
    /// next door, which is why this note exists on the copy that does
    /// *not* have it.
    public static func publishOp(
        name: String?,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        langs: [String]? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        waiters: [String]? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.publish.rawValue]
        fill(&dict, name: name, ver: ver, did: did, desc: desc,
             langs: langs, home: home, protocols: protocols, waiters: waiters)
        return try jsonString(dict)
    }

    /// `{"op":"update","codeId":…}` — amend a registration you own.
    ///
    /// Every field is resent, not just the changed ones: the op
    /// replaces the record's mutable half, so a field omitted here is a
    /// field cleared on chain.
    public static func updateOp(
        codeId: String,
        name: String?,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        langs: [String]? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        waiters: [String]? = nil
    ) throws -> String {
        guard !codeId.isEmpty else { throw Failure.noCodeId }
        var dict: [String: Any] = ["op": Op.update.rawValue, "codeId": codeId]
        fill(&dict, name: name, ver: ver, did: did, desc: desc,
             langs: langs, home: home, protocols: protocols, waiters: waiters)
        return try jsonString(dict)
    }

    /// `{"op":"stop","codeIds":[…]}` — take code records out of force,
    /// reversibly. Takes a list because the protocol does, and for a
    /// paid operation that is the difference between one miner fee and
    /// several.
    public static func stopOp(codeIds: [String]) throws -> String {
        try idListOp(.stop, codeIds: codeIds)
    }

    /// `{"op":"recover","codeIds":[…]}` — put stopped code records back
    /// in force. The only op that undoes another, and it does not undo
    /// `close`.
    public static func recoverOp(codeIds: [String]) throws -> String {
        try idListOp(.recover, codeIds: codeIds)
    }

    /// `{"op":"close","codeIds":[…],"closeStatement":…}` — retire code
    /// records permanently, with an optional reason.
    public static func closeOp(
        codeIds: [String], closeStatement: String? = nil
    ) throws -> String {
        let clean = codeIds.filter { !$0.isEmpty }
        guard !clean.isEmpty else { throw Failure.noCodeIds }
        var dict: [String: Any] = ["op": Op.close.rawValue, "codeIds": clean]
        if let closeStatement,
           !closeStatement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dict["closeStatement"] = closeStatement
        }
        return try jsonString(dict)
    }

    /// `{"op":"rate","codeId":…,"rate":n}` — score a code record 1–5.
    ///
    /// The score's *weight* is not in this payload: the chain counts the
    /// coin-days the rating transaction destroys, so what a rating is
    /// worth is decided by which coins pay for it. Building that input
    /// selection is its own piece of work and is not wired yet (Phase
    /// 8.7.5) — the builder is here because the payload is part of the
    /// protocol, not because a caller exists.
    public static func rateOp(codeId: String, rate: Int) throws -> String {
        guard !codeId.isEmpty else { throw Failure.noCodeId }
        guard (1...5).contains(rate) else { throw Failure.rateOutOfRange(rate) }
        return try jsonString(["op": Op.rate.rawValue, "codeId": codeId, "rate": rate])
    }

    // MARK: - complete carves

    /// The full OP_RETURN payload for a `publish`, with the name guard
    /// and the size check applied before a caller can spend anything on
    /// it.
    public static func publishCarve(
        name: String,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        langs: [String]? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        waiters: [String]? = nil
    ) throws -> String {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyName
        }
        return try sized(envelope(opJson: publishOp(
            name: name, ver: ver, did: did, desc: desc,
            langs: langs, home: home, protocols: protocols, waiters: waiters
        )))
    }

    /// The full OP_RETURN payload for an `update`, same guards.
    public static func updateCarve(
        codeId: String,
        name: String,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        langs: [String]? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        waiters: [String]? = nil
    ) throws -> String {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyName
        }
        return try sized(envelope(opJson: updateOp(
            codeId: codeId, name: name, ver: ver, did: did, desc: desc,
            langs: langs, home: home, protocols: protocols, waiters: waiters
        )))
    }

    public static func stopCarve(codeIds: [String]) throws -> String {
        try sized(envelope(opJson: stopOp(codeIds: codeIds)))
    }

    public static func recoverCarve(codeIds: [String]) throws -> String {
        try sized(envelope(opJson: recoverOp(codeIds: codeIds)))
    }

    public static func closeCarve(
        codeIds: [String], closeStatement: String? = nil
    ) throws -> String {
        try sized(envelope(opJson: closeOp(codeIds: codeIds, closeStatement: closeStatement)))
    }

    /// How many more UTF-8 bytes of `desc` a carve can take before it
    /// exceeds the OP_RETURN limit, given everything else already filled
    /// in. Negative once over.
    ///
    /// Exists so the publish form can show a live budget instead of
    /// letting the user write three paragraphs, add six protocol ids and
    /// discover at the Publish button that none of it fits. Measured on
    /// the encoded envelope rather than estimated, because JSON escaping
    /// makes a character count wrong by an unpredictable margin — and
    /// because a code record's protocol list is 64 hex characters per
    /// entry, which eats the budget faster than anything the user types.
    ///
    /// **Measured with the `desc` key present even when the description
    /// is empty.** ``publishOp(name:ver:did:desc:langs:home:protocols:waiters:)``
    /// omits empty fields, so measuring an empty draft directly would
    /// count the `"desc":""` overhead as free and promise a dozen bytes
    /// that the first keystroke immediately spends.
    public static func remainingDescBytes(
        codeId: String? = nil,
        name: String,
        ver: String? = nil,
        did: String? = nil,
        desc: String,
        langs: [String]? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        waiters: [String]? = nil
    ) -> Int {
        let probe = desc.isEmpty ? "x" : desc
        let op: String?
        if let codeId, !codeId.isEmpty {
            op = try? updateOp(
                codeId: codeId, name: name, ver: ver, did: did, desc: probe,
                langs: langs, home: home, protocols: protocols, waiters: waiters
            )
        } else {
            op = try? publishOp(
                name: name, ver: ver, did: did, desc: probe,
                langs: langs, home: home, protocols: protocols, waiters: waiters
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

    /// The eight fields `publish` and `update` share, empties omitted.
    private static func fill(
        _ dict: inout [String: Any],
        name: String?, ver: String?, did: String?, desc: String?,
        langs: [String]?, home: [String: String]?,
        protocols: [String]?, waiters: [String]?
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
        put("name", name)
        put("ver", ver)
        put("did", did)
        // Not trimmed to a single line, but not sent empty either — the
        // description is prose and its internal whitespace is the
        // author's.
        if let desc, !desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dict["desc"] = desc
        }
        putList("langs", langs)
        if let home, !home.isEmpty { dict["home"] = home }
        putList("protocols", protocols)
        putList("waiters", waiters)
    }

    private static func idListOp(_ op: Op, codeIds: [String]) throws -> String {
        let clean = codeIds.filter { !$0.isEmpty }
        guard !clean.isEmpty else { throw Failure.noCodeIds }
        return try jsonString(["op": op.rawValue, "codeIds": clean])
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
                    domain: "CodeFeip", code: -1,
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
