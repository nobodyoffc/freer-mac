import Foundation

/// Builders for the FEIP `FeipProtocol` protocol (sn 1, ver 7) — the
/// OP_RETURN JSON that registers, amends and retires a protocol on the
/// FCH chain. Mirrors the Java `Feip.fromName(PROTOCOL)` +
/// `ProtocolOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"1","ver":"7","name":"FeipProtocol",
///  "data":{"op":"publish","name":"…","sn":"12","ver":"3",
///          "did":"…","home":{"spec":"https://…"},"waiters":["…"]}}
/// ```
///
/// **The envelope's `sn` is 1 and the payload's `sn` is the publisher's
/// own.** A record registering FEIP-12 carries `"sn":"12"` inside a
/// `"sn":"1"` envelope. The two are different numbers with the same
/// name; see ``ProtocolSpec/sn``.
///
/// **Nothing here is encrypted.** A published protocol is a public
/// registration — that is the point of putting it on a chain — which is
/// why ``publishCarve(sn:name:type:ver:did:desc:lang:home:preDid:waiters:)``
/// enforces the OP_RETURN size limit *before* anything is signed.
public enum ProtocolFeip {

    public static let sn = FeipProtocol.protocolMeta.sn
    public static let ver = FeipProtocol.protocolMeta.ver
    public static let protocolName = FeipProtocol.protocolMeta.protocolName

    /// The largest OP_RETURN the chain accepts — the same limit
    /// ``MailFeip/maxOpReturnSize`` enforces, and for the same reason.
    public static let maxOpReturnSize = MailFeip.maxOpReturnSize

    /// The six ops the protocol defines.
    ///
    /// `stop` and `close` are not the same retirement: a stopped
    /// protocol is out of force until `recover` puts it back, a closed
    /// one is finished and nothing undoes it. Everything except `rate`
    /// is owner-only.
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
        case noProtocolId
        case noProtocolIds
        case rateOutOfRange(Int)
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "ProtocolFeip: JSON encoding failed — \(e)"
            case .emptyName:
                return "ProtocolFeip: a protocol needs a name"
            case .noProtocolId:
                return "ProtocolFeip: no protocol given"
            case .noProtocolIds:
                return "ProtocolFeip: no protocols given"
            case .rateOutOfRange(let r):
                return "ProtocolFeip: a rating is 1 to 5, not \(r)"
            case .tooLarge(let bytes):
                return "ProtocolFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. A registration is not compressed or encrypted — shorten the description, or publish the long form under `home` and carve its DID."
            }
        }
    }

    // MARK: - op payloads

    /// `{"op":"publish",…}` — register a protocol.
    ///
    /// **`preDid` on the way out, `prePid` on the way back.** The op
    /// field is spelled `preDid` (Java `FieldNames.PRE_DID`) while the
    /// indexed record calls the same link `prePid`
    /// (``ProtocolSpec/prePid``). Both clients have to spell it the
    /// wire's way, so the asymmetry is preserved rather than tidied.
    ///
    /// Empty values are omitted rather than sent as `""` or `[]`: an
    /// absent key and an empty one read the same to the indexer, and
    /// every omitted byte is OP_RETURN budget the description can use.
    ///
    /// **`rate` is not emitted.** Android's `ProtocolOpData.rate` is a
    /// primitive `int`, so Gson writes `"rate":0` into every publish,
    /// update, stop, close and recover it sends — a field those ops do
    /// not define, costing bytes on a payload that is size-capped
    /// (**Android issue C20**).
    public static func publishOp(
        sn: String? = nil,
        name: String?,
        type: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        lang: String? = nil,
        home: [String: String]? = nil,
        preDid: String? = nil,
        waiters: [String]? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.publish.rawValue]
        fill(&dict, sn: sn, name: name, type: type, ver: ver, did: did,
             desc: desc, lang: lang, home: home, preDid: preDid, waiters: waiters)
        return try jsonString(dict)
    }

    /// `{"op":"update","pid":…}` — amend a registration you own.
    ///
    /// Every field is resent, not just the changed ones: the op
    /// replaces the record's mutable half, so a field omitted here is a
    /// field cleared on chain.
    public static func updateOp(
        pid: String,
        sn: String? = nil,
        name: String?,
        type: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        lang: String? = nil,
        home: [String: String]? = nil,
        preDid: String? = nil,
        waiters: [String]? = nil
    ) throws -> String {
        guard !pid.isEmpty else { throw Failure.noProtocolId }
        var dict: [String: Any] = ["op": Op.update.rawValue, "pid": pid]
        fill(&dict, sn: sn, name: name, type: type, ver: ver, did: did,
             desc: desc, lang: lang, home: home, preDid: preDid, waiters: waiters)
        return try jsonString(dict)
    }

    /// `{"op":"stop","pids":[…]}` — take protocols out of force,
    /// reversibly. Takes a list because the protocol does, and for a
    /// paid operation that is the difference between one miner fee and
    /// several.
    public static func stopOp(pids: [String]) throws -> String {
        try idListOp(.stop, pids: pids)
    }

    /// `{"op":"recover","pids":[…]}` — put stopped protocols back in
    /// force. The only op that undoes another, and it does not undo
    /// `close`.
    public static func recoverOp(pids: [String]) throws -> String {
        try idListOp(.recover, pids: pids)
    }

    /// `{"op":"close","pids":[…],"closeStatement":…}` — retire
    /// protocols permanently, with an optional reason.
    public static func closeOp(pids: [String], closeStatement: String? = nil) throws -> String {
        let clean = pids.filter { !$0.isEmpty }
        guard !clean.isEmpty else { throw Failure.noProtocolIds }
        var dict: [String: Any] = ["op": Op.close.rawValue, "pids": clean]
        if let closeStatement, !closeStatement.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dict["closeStatement"] = closeStatement
        }
        return try jsonString(dict)
    }

    /// `{"op":"rate","pid":…,"rate":n}` — score a protocol 1–5.
    ///
    /// The score's *weight* is not in this payload: the chain counts the
    /// coin-days the rating transaction destroys, so what a rating is
    /// worth is decided by which coins pay for it. Building that input
    /// selection is its own piece of work and is not wired yet — the
    /// builder is here because the payload is part of the protocol, not
    /// because a caller exists.
    public static func rateOp(pid: String, rate: Int) throws -> String {
        guard !pid.isEmpty else { throw Failure.noProtocolId }
        guard (1...5).contains(rate) else { throw Failure.rateOutOfRange(rate) }
        return try jsonString(["op": Op.rate.rawValue, "pid": pid, "rate": rate])
    }

    // MARK: - complete carves

    /// The full OP_RETURN payload for a `publish`, with the name guard
    /// and the size check applied before a caller can spend anything on
    /// it.
    public static func publishCarve(
        sn: String? = nil,
        name: String,
        type: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        lang: String? = nil,
        home: [String: String]? = nil,
        preDid: String? = nil,
        waiters: [String]? = nil
    ) throws -> String {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyName
        }
        return try sized(envelope(opJson: publishOp(
            sn: sn, name: name, type: type, ver: ver, did: did,
            desc: desc, lang: lang, home: home, preDid: preDid, waiters: waiters
        )))
    }

    /// The full OP_RETURN payload for an `update`, same guards.
    public static func updateCarve(
        pid: String,
        sn: String? = nil,
        name: String,
        type: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        lang: String? = nil,
        home: [String: String]? = nil,
        preDid: String? = nil,
        waiters: [String]? = nil
    ) throws -> String {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyName
        }
        return try sized(envelope(opJson: updateOp(
            pid: pid, sn: sn, name: name, type: type, ver: ver, did: did,
            desc: desc, lang: lang, home: home, preDid: preDid, waiters: waiters
        )))
    }

    public static func stopCarve(pids: [String]) throws -> String {
        try sized(envelope(opJson: stopOp(pids: pids)))
    }

    public static func recoverCarve(pids: [String]) throws -> String {
        try sized(envelope(opJson: recoverOp(pids: pids)))
    }

    public static func closeCarve(pids: [String], closeStatement: String? = nil) throws -> String {
        try sized(envelope(opJson: closeOp(pids: pids, closeStatement: closeStatement)))
    }

    /// How many more UTF-8 bytes of `desc` a publish carve can take
    /// before it exceeds the OP_RETURN limit, given everything else
    /// already filled in. Negative once over.
    ///
    /// Exists so the publish form can show a live budget instead of
    /// letting the user write three paragraphs and discover at the Carve
    /// button that none of it fits. Measured on the encoded envelope
    /// rather than estimated, because JSON escaping makes a character
    /// count wrong by an unpredictable margin.
    ///
    /// **Measured with the `desc` key present even when the description
    /// is empty.** ``publishOp(sn:name:type:ver:did:desc:lang:home:preDid:waiters:)``
    /// omits empty fields, so measuring an empty draft directly would
    /// count the `"desc":""` overhead as free and promise a dozen bytes
    /// that the first keystroke immediately spends.
    public static func remainingDescBytes(
        pid: String? = nil,
        sn: String? = nil,
        name: String,
        type: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        desc: String,
        lang: String? = nil,
        home: [String: String]? = nil,
        preDid: String? = nil,
        waiters: [String]? = nil
    ) -> Int {
        let probe = desc.isEmpty ? "x" : desc
        let op: String?
        if let pid, !pid.isEmpty {
            op = try? updateOp(
                pid: pid, sn: sn, name: name, type: type, ver: ver, did: did,
                desc: probe, lang: lang, home: home, preDid: preDid, waiters: waiters
            )
        } else {
            op = try? publishOp(
                sn: sn, name: name, type: type, ver: ver, did: did,
                desc: probe, lang: lang, home: home, preDid: preDid, waiters: waiters
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

    /// The ten fields `publish` and `update` share, empties omitted.
    private static func fill(
        _ dict: inout [String: Any],
        sn: String?, name: String?, type: String?, ver: String?, did: String?,
        desc: String?, lang: String?, home: [String: String]?,
        preDid: String?, waiters: [String]?
    ) {
        func put(_ key: String, _ value: String?) {
            guard let value else { return }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            dict[key] = trimmed
        }
        put("sn", sn)
        put("name", name)
        put("type", type)
        put("ver", ver)
        put("did", did)
        // Not trimmed to a single line, but not sent empty either — the
        // description is prose and its internal whitespace is the
        // author's.
        if let desc, !desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            dict["desc"] = desc
        }
        put("lang", lang)
        if let home, !home.isEmpty { dict["home"] = home }
        put("preDid", preDid)
        if let waiters {
            let clean = waiters.filter { !$0.isEmpty }
            if !clean.isEmpty { dict["waiters"] = clean }
        }
    }

    private static func idListOp(_ op: Op, pids: [String]) throws -> String {
        let clean = pids.filter { !$0.isEmpty }
        guard !clean.isEmpty else { throw Failure.noProtocolIds }
        return try jsonString(["op": op.rawValue, "pids": clean])
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
                    domain: "ProtocolFeip", code: -1,
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
