import Foundation

/// One payout line of an `issue` or `transfer` carve: who gets paid,
/// and how much.
///
/// **The amount is digits, not a `Double`.** Android parses the typed
/// amount into a `double` and lets Gson print whatever that rounds to,
/// so a user asking to send `0.1` can sign a carve that says
/// `0.1000000000000000055511151231257827`-adjacent nonsense the moment
/// the value survives one arithmetic step. Keeping the user's own
/// digits all the way to the OP_RETURN means the carve says exactly
/// what the form said, and ``normalizedAmount(scale:)`` is the only
/// place a value is ever rewritten — deliberately, with the token's own
/// decimal scale in hand.
public struct TokenTransfer: Equatable, Sendable, Identifiable {

    public var fid: String
    /// The amount as typed: decimal digits, optionally with one point.
    /// Validated by ``normalizedAmount(scale:)``, never by the setter,
    /// so a half-typed value in a form is representable.
    public var amount: String

    public var id: String { fid + "\u{1F}" + amount }

    public init(fid: String, amount: String) {
        self.fid = fid
        self.amount = amount
    }

    public enum Invalid: Error, CustomStringConvertible, Equatable {
        case emptyFid
        case emptyAmount
        case notANumber(String)
        case notPositive(String)
        /// More decimal places than the token allows. The parser
        /// rejects these outright, so catching it here is the
        /// difference between a message and a wasted miner fee.
        case tooManyDecimals(typed: Int, allowed: Int)

        public var description: String {
            switch self {
            case .emptyFid:
                return "a recipient FID is required"
            case .emptyAmount:
                return "an amount is required"
            case .notANumber(let s):
                return "\"\(s)\" is not a number"
            case .notPositive(let s):
                return "\(s) is not greater than zero"
            case let .tooManyDecimals(typed, allowed):
                return allowed == 0
                    ? "this token has no decimal places, but the amount has \(typed)"
                    : "this token allows \(allowed) decimal place\(allowed == 1 ? "" : "s"), but the amount has \(typed)"
            }
        }
    }

    /// How many digits follow the decimal point, trailing zeros
    /// stripped. `1.50` counts as one place, not two: the parser
    /// compares value scale, and refusing `1.50` on a one-decimal token
    /// would reject an amount it accepts written as `1.5`.
    public static func decimalPlaces(in amount: String) -> Int {
        let trimmed = amount.trimmingCharacters(in: .whitespaces)
        guard let dot = trimmed.firstIndex(of: ".") else { return 0 }
        var frac = Substring(trimmed[trimmed.index(after: dot)...])
        while frac.last == "0" { frac = frac.dropLast() }
        return frac.count
    }

    /// The amount as a number the carve can carry, or a reason it
    /// cannot be one.
    ///
    /// `scale` is the token's ``Token/decimalPlaces``. Returns an
    /// `NSDecimalNumber` because that is the one numeric type
    /// `JSONSerialization` writes out digit-for-digit — a `Double` here
    /// would undo the whole point of holding the amount as text.
    public func normalizedAmount(scale: Int) throws -> NSDecimalNumber {
        let fid = self.fid.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fid.isEmpty else { throw Invalid.emptyFid }
        let text = amount.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { throw Invalid.emptyAmount }
        // Reject exponent forms and stray signs before handing the
        // string to NSDecimalNumber, whose parser is lenient enough to
        // turn "12abc" into 12 rather than complaining.
        let allowed = CharacterSet(charactersIn: "0123456789.")
        guard text.unicodeScalars.allSatisfy({ allowed.contains($0) }),
              text.filter({ $0 == "." }).count <= 1,
              text.contains(where: { $0.isNumber })
        else { throw Invalid.notANumber(text) }

        let value = NSDecimalNumber(string: text, locale: Locale(identifier: "en_US_POSIX"))
        guard value != .notANumber else { throw Invalid.notANumber(text) }
        guard value.compare(NSDecimalNumber.zero) == .orderedDescending else {
            throw Invalid.notPositive(text)
        }
        let places = Self.decimalPlaces(in: text)
        guard places <= scale else {
            throw Invalid.tooManyDecimals(typed: places, allowed: scale)
        }
        return value
    }

    /// The trimmed FID, which is what goes on the wire.
    public var normalizedFid: String {
        fid.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// Builders for the FEIP `Token` protocol (sn 20, ver 1) — the
/// OP_RETURN JSON that deploys a token and moves it. Mirrors the Java
/// `Feip.fromName(TOKEN)` + `TokenOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"20","ver":"1","name":"Token",
///  "data":{"op":"transfer","tokenId":"…",
///          "transferTo":[{"amount":1.5,"fid":"F…"}]}}
/// ```
///
/// **Nothing here is encrypted, and nothing here pays anybody.** Unlike
/// a proof `transfer` — where the payment output *is* the addressing —
/// a token transfer names its recipients in the payload, so all five
/// ops go through the plain carve path and cost only the miner fee.
/// That also means a token transfer to a FID that does not exist is a
/// carve that succeeds and moves value nowhere; the recipient is
/// checked by the form, because the chain will not check it for you.
public enum TokenFeip {

    public static let sn = "20"
    public static let ver = "1"
    public static let protocolName = "Token"

    /// The largest OP_RETURN the chain accepts. Shared with every other
    /// carve, and load-bearing here: an `issue` naming a hundred
    /// recipients is one carve, and it either fits or it does not.
    public static let maxOpReturnSize = MailFeip.maxOpReturnSize

    /// The five ops the protocol defines.
    ///
    /// `destroy` and `close` are not the same thing and the difference
    /// matters: **destroy burns the signer's own balance**, and
    /// **close retires the token for everybody**. Only the deployer of
    /// a `closable` token can do the second.
    public enum Op: String, CaseIterable, Sendable, Identifiable {
        case deploy
        case issue
        case transfer
        case destroy
        case close

        public var id: String { rawValue }

        /// Display label. English only for now; Phase 11 localises.
        public var label: String {
            switch self {
            case .deploy:   return "Deploy"
            case .issue:    return "Issue"
            case .transfer: return "Transfer"
            case .destroy:  return "Destroy"
            case .close:    return "Close"
            }
        }
    }

    public enum Failure: Error, CustomStringConvertible {
        case encoding(underlying: Error)
        case emptyName
        case noTokenId
        case noTokenIds
        case noRecipients
        case invalidAmount(fid: String, reason: TokenTransfer.Invalid)
        case duplicateRecipient(fid: String)
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "TokenFeip: JSON encoding failed — \(e)"
            case .emptyName:
                return "TokenFeip: a token needs a name"
            case .noTokenId:
                return "TokenFeip: no token id given"
            case .noTokenIds:
                return "TokenFeip: no token ids given"
            case .noRecipients:
                return "TokenFeip: no recipients — an issue or transfer with an empty list moves nothing and still costs a fee"
            case let .invalidAmount(fid, reason):
                return "TokenFeip: \(fid.isEmpty ? "a recipient" : fid) — \(reason)"
            case .duplicateRecipient(let fid):
                return "TokenFeip: \(fid) appears twice. Which line the parser keeps is its business, not something to find out by carving — merge them into one amount."
            case .tooLarge(let bytes):
                return "TokenFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. Split the recipients across more than one carve."
            }
        }
    }

    // MARK: - op payloads

    /// `{"op":"deploy",…}` — mint a new token's rule set.
    ///
    /// **The token's id is the deploy carve's txid**, so it is never in
    /// this payload; there is nothing to put there yet.
    ///
    /// Empty optional fields are omitted rather than sent as `""`: an
    /// absent key and an empty string read the same to the parser, and
    /// every omitted byte is OP_RETURN budget.
    ///
    /// **The three issue limits are dropped when `openIssue` is
    /// false.** The parser only applies them in the open-issue case, so
    /// carving them otherwise writes a rule into the permanent record
    /// that nothing will ever enforce — a lie in the one document that
    /// is supposed to say what the token's rules are.
    public static func deployOp(
        name: String,
        desc: String? = nil,
        consensusId: String? = nil,
        capacity: String? = nil,
        decimal: String? = nil,
        transferable: Bool? = nil,
        closable: Bool? = nil,
        openIssue: Bool? = nil,
        maxAmtPerIssue: String? = nil,
        minCddPerIssue: String? = nil,
        maxIssuesPerAddr: String? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.deploy.rawValue]
        func put(_ key: String, _ value: String?) {
            guard let value else { return }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            dict[key] = trimmed
        }
        put("name", name)
        put("desc", desc)
        put("consensusId", consensusId)
        put("capacity", capacity)
        put("decimal", decimal)
        if let transferable { dict["transferable"] = transferable }
        if let closable { dict["closable"] = closable }
        if let openIssue { dict["openIssue"] = openIssue }
        if openIssue == true {
            put("maxAmtPerIssue", maxAmtPerIssue)
            put("minCddPerIssue", minCddPerIssue)
            put("maxIssuesPerAddr", maxIssuesPerAddr)
        }
        return try jsonString(dict)
    }

    /// `{"op":"issue","tokenId":…,"issueTo":[…]}` — mint supply into
    /// the named FIDs' balances.
    public static func issueOp(
        tokenId: String,
        issueTo: [TokenTransfer],
        scale: Int
    ) throws -> String {
        try allocationOp(op: .issue, key: "issueTo", tokenId: tokenId, lines: issueTo, scale: scale)
    }

    /// `{"op":"transfer","tokenId":…,"transferTo":[…]}` — move balance
    /// from the signer to the named FIDs.
    public static func transferOp(
        tokenId: String,
        transferTo: [TokenTransfer],
        scale: Int
    ) throws -> String {
        try allocationOp(op: .transfer, key: "transferTo", tokenId: tokenId, lines: transferTo, scale: scale)
    }

    /// `{"op":"destroy","tokenIds":[…]}` — burn **the signer's whole
    /// balance** of one token. There is no partial destroy and no
    /// amount field: the op takes ids, not quantities.
    ///
    /// Takes one id, wrapped in a list, because the protocol's field is
    /// a list — Java's `makeDestroy` does the same, and its own comment
    /// says the list has to hold exactly one.
    public static func destroyOp(tokenId: String) throws -> String {
        let trimmed = tokenId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw Failure.noTokenId }
        return try jsonString(["op": Op.destroy.rawValue, "tokenIds": [trimmed]])
    }

    /// `{"op":"close","tokenIds":[…]}` — retire tokens you deployed,
    /// for everyone, permanently.
    ///
    /// Takes a list because the protocol does, and for a paid operation
    /// that is the difference between one miner fee and several.
    public static func closeOp(tokenIds: [String]) throws -> String {
        let ids = tokenIds
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !ids.isEmpty else { throw Failure.noTokenIds }
        return try jsonString(["op": Op.close.rawValue, "tokenIds": ids])
    }

    // MARK: - complete carves

    /// The full OP_RETURN payload for a `deploy`, with the name guard
    /// and the size check applied before a caller can spend anything.
    public static func deployCarve(
        name: String,
        desc: String? = nil,
        consensusId: String? = nil,
        capacity: String? = nil,
        decimal: String? = nil,
        transferable: Bool? = nil,
        closable: Bool? = nil,
        openIssue: Bool? = nil,
        maxAmtPerIssue: String? = nil,
        minCddPerIssue: String? = nil,
        maxIssuesPerAddr: String? = nil
    ) throws -> String {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyName
        }
        return try sized(envelope(opJson: deployOp(
            name: name, desc: desc, consensusId: consensusId,
            capacity: capacity, decimal: decimal,
            transferable: transferable, closable: closable, openIssue: openIssue,
            maxAmtPerIssue: maxAmtPerIssue, minCddPerIssue: minCddPerIssue,
            maxIssuesPerAddr: maxIssuesPerAddr
        )))
    }

    public static func issueCarve(
        tokenId: String, issueTo: [TokenTransfer], scale: Int
    ) throws -> String {
        try sized(envelope(opJson: issueOp(tokenId: tokenId, issueTo: issueTo, scale: scale)))
    }

    public static func transferCarve(
        tokenId: String, transferTo: [TokenTransfer], scale: Int
    ) throws -> String {
        try sized(envelope(opJson: transferOp(tokenId: tokenId, transferTo: transferTo, scale: scale)))
    }

    public static func destroyCarve(tokenId: String) throws -> String {
        try sized(envelope(opJson: destroyOp(tokenId: tokenId)))
    }

    public static func closeCarve(tokenIds: [String]) throws -> String {
        try sized(envelope(opJson: closeOp(tokenIds: tokenIds)))
    }

    /// How many more recipients an issue or transfer carve can take
    /// before it exceeds the OP_RETURN limit, given the lines already
    /// entered.
    ///
    /// Measured on the encoded envelope rather than estimated, for the
    /// same reason ``ProofFeip/remainingContentBytes(title:content:cosigners:transferable:allSignsRequired:)``
    /// is: a FID is 34 characters but a JSON line holding one is not,
    /// and the amount's own digits vary. Returns nil when the lines
    /// already there do not encode at all — the form has a validation
    /// error to show first, and a capacity number next to it would be
    /// answering a question nobody asked.
    public static func remainingRecipients(
        op: Op,
        tokenId: String,
        lines: [TokenTransfer],
        scale: Int
    ) -> Int? {
        // A 34-character FID with a 4-digit amount — a representative
        // line rather than a worst case, which is all a "how many more"
        // number can honestly be when the next FID's length is unknown.
        //
        // Two of them, differing in one character, because the builders
        // reject a repeated FID: measuring the cost of "one more line"
        // by appending the *same* probe would trip the duplicate guard
        // and report no budget at all.
        func probe(_ tag: String) -> TokenTransfer {
            TokenTransfer(fid: tag + String(repeating: "F", count: 33), amount: "1000")
        }
        let first = probe("A")
        let second = probe("B")
        func size(_ rows: [TokenTransfer]) -> Int? {
            let json: String?
            switch op {
            case .issue:
                json = try? envelope(opJson: issueOp(tokenId: tokenId, issueTo: rows, scale: scale))
            case .transfer:
                json = try? envelope(opJson: transferOp(tokenId: tokenId, transferTo: rows, scale: scale))
            default:
                return nil
            }
            return json.map { Data($0.utf8).count }
        }
        let base = lines.isEmpty ? [first] : lines
        guard let used = size(base), let withOneMore = size(base + [second]) else {
            return nil
        }
        let perLine = max(withOneMore - used, 1)
        // With no lines yet, `used` measured a list of one probe — so
        // subtract that probe back out to get the empty-carve baseline.
        let baseline = lines.isEmpty ? used - perLine : used
        return max((maxOpReturnSize - baseline) / perLine, 0)
    }

    // MARK: - envelope

    public static func envelope(opJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(opJson)}"#
    }

    // MARK: - internals

    /// The shared body of `issue` and `transfer`: same shape, same
    /// validation, different key.
    private static func allocationOp(
        op: Op, key: String, tokenId: String, lines: [TokenTransfer], scale: Int
    ) throws -> String {
        let id = tokenId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !id.isEmpty else { throw Failure.noTokenId }
        guard !lines.isEmpty else { throw Failure.noRecipients }

        var seen = Set<String>()
        var rows: [[String: Any]] = []
        for line in lines {
            let fid = line.normalizedFid
            let amount: NSDecimalNumber
            do {
                amount = try line.normalizedAmount(scale: scale)
            } catch let reason as TokenTransfer.Invalid {
                throw Failure.invalidAmount(fid: fid, reason: reason)
            }
            // Two lines for one FID is ambiguous, and which one the
            // parser honours is not worth a miner fee to discover.
            guard seen.insert(fid).inserted else {
                throw Failure.duplicateRecipient(fid: fid)
            }
            rows.append(["fid": fid, "amount": amount])
        }
        return try jsonString(["op": op.rawValue, "tokenId": id, key: rows])
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
                    domain: "TokenFeip", code: -1,
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
