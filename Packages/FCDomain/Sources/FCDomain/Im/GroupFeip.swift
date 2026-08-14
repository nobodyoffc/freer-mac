import Foundation

/// Builders for the FEIP `Team` protocol (**sn 18, ver 1**) — the
/// OP_RETURN JSON that changes a team's on-chain state. Mirrors
/// `Feip.fromName("Team")` + `TeamOpData`:
///
/// ```json
/// {"type":"FEIP","sn":"18","ver":"1","name":"Team",
///  "data":{"op":"join","tid":"<txid>","consensusId":"<did>",
///          "confirm":"I join the team and agree with the team consensus."}}
/// ```
///
/// **The `confirm` sentences are part of the protocol, not decoration.**
/// A join, a take-over, a transfer and a consensus agreement each carry
/// a fixed English sentence, and it is carved into a transaction the
/// member signed. That is the whole mechanism: agreement to a team's
/// consensus document is a signed statement on a public ledger, and the
/// exact wording is what makes two clients' carves the same act. They
/// are reproduced here verbatim, and must not be reworded, localised, or
/// "improved".
///
/// **The multi-word op names carry a space.** Java builds them as
/// `Op.TAKE_OVER.toLowerCase()`, which lowercases `FeipOp.TAKE_OVER`'s
/// *value* — and that value is `"take over"`, not `"TakeOver"`. So the
/// wire strings are `take over`, `agree consensus`, `withdraw
/// invitation` and `cancel appointment`, spaces and all. Every instinct
/// says to camel-case them, and doing so would produce carves the
/// indexer silently ignores.
public enum TeamFeip {

    public static let sn = "18"
    public static let ver = "1"
    public static let protocolName = "Team"

    /// The sentence a joiner signs.
    public static let joinConfirm = "I join the team and agree with the team consensus."
    /// The sentence an owner signs to hand a team over.
    public static let transferConfirm = "I transfer the team to the transferee."
    /// The sentence a transferee signs to complete a hand-over.
    public static let takeOverConfirm = "I take over the team and agree with the team consensus."
    /// The sentence a member signs to accept a new consensus document.
    public static let agreeConsensusConfirm = "I agree with the new consensus."

    // MARK: - op payloads

    public static func createOp(
        stdName: String,
        consensusId: String? = nil,
        desc: String? = nil,
        home: [String: String]? = nil
    ) throws -> String {
        try FeipJson.object([
            ("op", .string("create")),
            ("stdName", .string(stdName)),
            ("consensusId", .optionalString(consensusId)),
            ("desc", .optionalString(desc)),
            ("home", .optionalMap(home)),
        ])
    }

    public static func updateOp(
        tid: String,
        stdName: String? = nil,
        consensusId: String? = nil,
        desc: String? = nil,
        home: [String: String]? = nil
    ) throws -> String {
        try FeipJson.object([
            ("op", .string("update")),
            ("tid", .string(tid)),
            ("stdName", .optionalString(stdName)),
            ("consensusId", .optionalString(consensusId)),
            ("desc", .optionalString(desc)),
            ("home", .optionalMap(home)),
        ])
    }

    /// Join a team, quoting the consensus document being agreed to.
    public static func joinOp(tid: String, consensusId: String?) throws -> String {
        try FeipJson.object([
            ("op", .string("join")),
            ("tid", .string(tid)),
            ("consensusId", .optionalString(consensusId)),
            ("confirm", .string(joinConfirm)),
        ])
    }

    /// Leave teams. Plural, and that is the protocol's shape: one carve
    /// can walk out of several teams at once, which for a paid operation
    /// is the difference between one fee and several.
    public static func leaveOp(tids: [String]) throws -> String {
        try FeipJson.object([
            ("op", .string("leave")),
            ("tids", .stringArray(tids)),
        ])
    }

    public static func disbandOp(tids: [String]) throws -> String {
        try FeipJson.object([
            ("op", .string("disband")),
            ("tids", .stringArray(tids)),
        ])
    }

    public static func transferOp(tid: String, transferee: String) throws -> String {
        try FeipJson.object([
            ("op", .string("transfer")),
            ("tid", .string(tid)),
            ("transferee", .string(transferee)),
            ("confirm", .string(transferConfirm)),
        ])
    }

    public static func takeOverOp(tid: String, consensusId: String?) throws -> String {
        try FeipJson.object([
            ("op", .string("take over")),
            ("tid", .string(tid)),
            ("consensusId", .optionalString(consensusId)),
            ("confirm", .string(takeOverConfirm)),
        ])
    }

    public static func agreeConsensusOp(tid: String, consensusId: String) throws -> String {
        try FeipJson.object([
            ("op", .string("agree consensus")),
            ("tid", .string(tid)),
            ("consensusId", .string(consensusId)),
            ("confirm", .string(agreeConsensusConfirm)),
        ])
    }

    public static func inviteOp(tid: String, fids: [String]) throws -> String {
        try listOp("invite", tid: tid, fids: fids)
    }

    public static func withdrawInvitationOp(tid: String, fids: [String]) throws -> String {
        try listOp("withdraw invitation", tid: tid, fids: fids)
    }

    /// Remove members — the on-chain equivalent of a room's
    /// `ROOM_REMOVED`, except that here the chain settles it and nobody
    /// has to be believed.
    public static func dismissOp(tid: String, fids: [String]) throws -> String {
        try listOp("dismiss", tid: tid, fids: fids)
    }

    public static func appointOp(tid: String, fids: [String]) throws -> String {
        try listOp("appoint", tid: tid, fids: fids)
    }

    public static func cancelAppointmentOp(tid: String, fids: [String]) throws -> String {
        try listOp("cancel appointment", tid: tid, fids: fids)
    }

    public static func rateOp(tid: String, rate: Int) throws -> String {
        try FeipJson.object([
            ("op", .string("rate")),
            ("tid", .string(tid)),
            ("rate", .int(Int64(rate))),
        ])
    }

    private static func listOp(_ op: String, tid: String, fids: [String]) throws -> String {
        try FeipJson.object([
            ("op", .string(op)),
            ("tid", .string(tid)),
            ("list", .stringArray(fids)),
        ])
    }

    // MARK: - envelope

    public static func envelope(opJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(opJson)}"#
    }
}

/// Builders for the FEIP `Square` protocol (**sn 19, ver 4**), mirroring
/// `SquareOpData`.
///
/// Four ops, and the shortness of the list is the design: there is no
/// invite, no dismiss, no transfer, no disband, and no `confirm`
/// sentence anywhere. A square is open, so joining is a unilateral act
/// that needs nobody's agreement and nothing to agree *to*.
///
/// The protocol name on the wire is `Square`; Android notes that the API
/// kept the name for compatibility while the UI moved to "Square", so
/// the two agree here.
public enum SquareFeip {

    public static let sn = "19"
    public static let ver = "4"
    public static let protocolName = "Square"

    public static func createOp(
        name: String, desc: String? = nil, home: [String: String]? = nil
    ) throws -> String {
        try FeipJson.object([
            ("op", .string("create")),
            ("name", .string(name)),
            ("desc", .optionalString(desc)),
            ("home", .optionalMap(home)),
        ])
    }

    public static func updateOp(
        squareId: String, name: String? = nil, desc: String? = nil, home: [String: String]? = nil
    ) throws -> String {
        try FeipJson.object([
            ("op", .string("update")),
            ("squareId", .string(squareId)),
            ("name", .optionalString(name)),
            ("desc", .optionalString(desc)),
            ("home", .optionalMap(home)),
        ])
    }

    public static func joinOp(squareId: String) throws -> String {
        try FeipJson.object([
            ("op", .string("join")),
            ("squareId", .string(squareId)),
        ])
    }

    public static func leaveOp(squareIds: [String]) throws -> String {
        try FeipJson.object([
            ("op", .string("leave")),
            ("squareIds", .stringArray(squareIds)),
        ])
    }

    public static func envelope(opJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(opJson)}"#
    }
}

/// Ordered JSON for FEIP op payloads.
///
/// The other FEIP builders here hand a dictionary to `JSONSerialization`
/// with `.sortedKeys`, which is fine when every field is required. These
/// ops are not: most fields are optional, and a nil one must be
/// *absent* rather than null, so the fields are listed explicitly and
/// nils drop out. Declaration order is kept because a carve is easier to
/// read in a block explorer with `op` first.
enum FeipJson {

    enum Value {
        case string(String)
        case optionalString(String?)
        case int(Int64)
        case stringArray([String])
        case optionalMap([String: String]?)
    }

    enum Failure: Error, CustomStringConvertible {
        case encoding

        var description: String { "FeipJson: could not encode the op payload" }
    }

    static func object(_ fields: [(String, Value)]) throws -> String {
        var parts: [String] = []
        for (key, value) in fields {
            guard let rendered = try render(value) else { continue }
            parts.append("\(try quoted(key)):\(rendered)")
        }
        return "{" + parts.joined(separator: ",") + "}"
    }

    private static func render(_ value: Value) throws -> String? {
        switch value {
        case .string(let s):
            return try quoted(s)
        case .optionalString(let s):
            guard let s else { return nil }
            return try quoted(s)
        case .int(let i):
            return String(i)
        case .stringArray(let list):
            return "[" + (try list.map(quoted).joined(separator: ",")) + "]"
        case .optionalMap(let map):
            guard let map, !map.isEmpty else { return nil }
            // Sorted, for the same reason `GsonCompatibleWriter` sorts:
            // a map has no natural order and a carve should be
            // reproducible.
            let items = try map.keys.sorted().map { key in
                "\(try quoted(key)):\(try quoted(map[key] ?? ""))"
            }
            return "{" + items.joined(separator: ",") + "}"
        }
    }

    /// JSON string escaping via `JSONSerialization`, so the escaping
    /// rules are the platform's rather than ours.
    private static func quoted(_ s: String) throws -> String {
        guard let data = try? JSONSerialization.data(
            withJSONObject: [s], options: [.withoutEscapingSlashes]
        ),
            let text = String(data: data, encoding: .utf8),
            text.count >= 2
        else { throw Failure.encoding }
        return String(text.dropFirst().dropLast())
    }
}
