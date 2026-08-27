import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - amount formatting

/// Rendering token amounts at the token's own scale.
///
/// Every balance on this path arrives from the indexer as a `Double`
/// (see ``TokenHolder/balance``), and a double printed by Swift's
/// default description says `0.30000000000000004` often enough to
/// matter. Rounding to the token's declared decimal places is not
/// cosmetic: showing more precision than the token *has* invites the
/// user to type an amount the parser will reject.
enum TokenAmount {

    /// `value` at `scale` decimal places, trailing zeros trimmed and
    /// thousands separated.
    static func string(_ value: Double?, scale: Int) -> String {
        guard let value else { return "—" }
        let f = NumberFormatter()
        f.numberStyle = .decimal
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = max(0, min(scale, 18))
        f.usesGroupingSeparator = true
        return f.string(from: NSNumber(value: value)) ?? String(value)
    }

    /// The same value with no grouping separators — what a text field
    /// gets seeded with, because a Max button that fills the box with
    /// `1,234.5` produces an amount the carve builder then refuses.
    static func plain(_ value: Double?, scale: Int) -> String {
        guard let value else { return "" }
        let f = NumberFormatter()
        f.numberStyle = .decimal
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = max(0, min(scale, 18))
        f.usesGroupingSeparator = false
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: NSNumber(value: value)) ?? String(value)
    }
}

// MARK: - deploy

/// Deploy a token — the Mac port of Android's `CreateTokenActivity`.
///
/// **Everything on this form is permanent.** There is no op to rename a
/// token, raise its cap, make a non-transferable one transferable or
/// make a non-closable one closable. The only field that ever changes
/// after this sheet is `closed`, and only in one direction. That is
/// what the warning at the top is for, and why there is no Save-draft
/// button: a token's id *is* its deploy transaction, so a token that
/// has not been carved does not exist to be drafted.
struct DeployTokenSheet: View {
    let session: ActiveSession
    let onDone: (Token?) -> Void

    @State private var name = ""
    @State private var desc = ""
    @State private var consensusId = ""
    @State private var capacity = ""
    @State private var decimal = ""
    @State private var transferable = true
    @State private var closable = true
    @State private var openIssue = false
    @State private var maxAmtPerIssue = ""
    @State private var minCddPerIssue = ""
    @State private var maxIssuesPerAddr = ""

    @State private var busy = false
    @State private var error: String?
    @State private var confirming = false

    /// Local validation, in the order the fields appear, so the first
    /// complaint is about the first bad field rather than whichever
    /// check happens to run first.
    private var validationError: String? {
        if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "A token needs a name."
        }
        if !decimal.isEmpty, !Self.isNonNegativeInteger(decimal) {
            return "Decimal places must be a whole number — 0 for an integer token, 8 for one divisible like FCH."
        }
        if !capacity.isEmpty, !Self.isPositiveNumber(capacity) {
            return "Capacity must be a positive number, or blank for no cap."
        }
        if openIssue {
            if !maxAmtPerIssue.isEmpty, !Self.isPositiveNumber(maxAmtPerIssue) {
                return "Max amount per issue must be a positive number."
            }
            if !minCddPerIssue.isEmpty, !Self.isNonNegativeInteger(minCddPerIssue) {
                return "Min CDD per issue must be a whole number."
            }
            if !maxIssuesPerAddr.isEmpty, !Self.isNonNegativeInteger(maxIssuesPerAddr) {
                return "Max issues per address must be a whole number."
            }
        }
        if carveSize > TokenFeip.maxOpReturnSize {
            return "The rules are \(carveSize) bytes, over the \(TokenFeip.maxOpReturnSize)-byte limit. Shorten the description."
        }
        return nil
    }

    /// The encoded size of the carve as it currently stands, or zero
    /// while the form does not encode at all.
    private var carveSize: Int {
        guard let json = try? TokenFeip.deployCarve(
            name: name.isEmpty ? "x" : name, desc: desc, consensusId: consensusId,
            capacity: capacity, decimal: decimal,
            transferable: transferable, closable: closable, openIssue: openIssue,
            maxAmtPerIssue: maxAmtPerIssue, minCddPerIssue: minCddPerIssue,
            maxIssuesPerAddr: maxIssuesPerAddr
        ) else { return 0 }
        return Data(json.utf8).count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Deploy a token")
                .font(.title3.bold())
                .padding(.bottom, 4)

            Text("Everything below is fixed the moment this is carved. There is no op to rename a token, raise its cap, or change any of these switches later — the only thing that can change afterwards is closing it, and only if you allow that here.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.bottom, 12)

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    field("Name") {
                        TextField("What the token is called", text: $name)
                            .textFieldStyle(.roundedBorder)
                    }

                    field("Description") {
                        TextField("What it is for (optional)", text: $desc)
                            .textFieldStyle(.roundedBorder)
                    }

                    field("Consensus FID") {
                        TextField("Whose word settles disputes (optional)", text: $consensusId)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                        Text("Declarative only — the chain enforces nothing about it.")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }

                    HStack(alignment: .top, spacing: 12) {
                        field("Capacity") {
                            TextField("No cap", text: $capacity)
                                .textFieldStyle(.roundedBorder)
                            Text("Total supply ceiling.")
                                .font(.caption2).foregroundStyle(.tertiary)
                        }
                        field("Decimal places") {
                            TextField("0", text: $decimal)
                                .textFieldStyle(.roundedBorder)
                            Text("How finely it divides.")
                                .font(.caption2).foregroundStyle(.tertiary)
                        }
                    }

                    Divider()

                    Toggle("Transferable — holders can send it to each other", isOn: $transferable)
                    Text(transferable
                         ? "Balances move freely between FIDs."
                         : "Balances can never move. Whoever you issue to keeps it — this makes a badge, not a currency.")
                        .font(.caption2)
                        .foregroundStyle(transferable ? Color.secondary : Color.orange)
                        .fixedSize(horizontal: false, vertical: true)

                    Toggle("Closable — you can retire it later", isOn: $closable)
                    Text(closable
                         ? "You, and only you, can close it: no further issue or transfer, balances frozen where they sit."
                         : "Nobody can ever close it. That is a guarantee to your holders, and it cannot be taken back.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)

                    Toggle("Open issue — anyone can mint more", isOn: $openIssue)
                    Text(openIssue
                         ? "Anyone may issue this token, so the three limits below are the only thing standing between it and infinite supply."
                         : "Only you can issue it.")
                        .font(.caption2)
                        .foregroundStyle(openIssue ? Color.orange : Color.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    if openIssue {
                        HStack(alignment: .top, spacing: 12) {
                            field("Max per issue") {
                                TextField("Unlimited", text: $maxAmtPerIssue)
                                    .textFieldStyle(.roundedBorder)
                            }
                            field("Min CDD per issue") {
                                TextField("None", text: $minCddPerIssue)
                                    .textFieldStyle(.roundedBorder)
                            }
                            field("Max issues per FID") {
                                TextField("Unlimited", text: $maxIssuesPerAddr)
                                    .textFieldStyle(.roundedBorder)
                            }
                        }
                        Text("Coin-days destroyed is the cost the issuer pays in held time — the anti-spam lever for an open-issue token.")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                .padding(.trailing, 2)
            }
            .frame(maxHeight: 380)

            Divider().padding(.vertical, 10)

            if let error {
                CopyableText(error, font: .caption)
                    .foregroundStyle(.red)
                    .padding(.bottom, 6)
            } else if let v = validationError, !name.isEmpty {
                Text(v).font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, 6)
            }

            HStack {
                Text("\(carveSize) of \(TokenFeip.maxOpReturnSize) bytes")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.tertiary)
                Spacer()
                Button("Cancel") { onDone(nil) }
                if busy { ProgressView().controlSize(.small) }
                Button("Deploy…") { confirming = true }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(validationError != nil || busy || !session.canSign)
            }
        }
        .padding(20)
        .frame(width: 560)
        .alert("Deploy “\(name)” permanently?", isPresented: $confirming) {
            Button("Cancel", role: .cancel) { }
            Button("Deploy") { Task { await deploy() } }
        } message: {
            Text("This carves the token's rules onto the chain, where they cannot be edited or withdrawn. \(closable ? "You will be able to close it later, which stops issue and transfer but does not erase it." : "It can never be closed.")")
        }
    }

    private func deploy() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            let token = try await session.carveTokenDeployOnChain(
                name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                desc: desc, consensusId: consensusId,
                capacity: capacity, decimal: decimal,
                transferable: transferable, closable: closable, openIssue: openIssue,
                maxAmtPerIssue: maxAmtPerIssue, minCddPerIssue: minCddPerIssue,
                maxIssuesPerAddr: maxIssuesPerAddr
            )
            onDone(token)
        } catch {
            self.error = "Couldn't deploy: \(error)"
        }
    }

    private static func isNonNegativeInteger(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, t.allSatisfy(\.isNumber) else { return false }
        return true
    }

    private static func isPositiveNumber(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, t.filter({ $0 == "." }).count <= 1,
              t.allSatisfy({ $0.isNumber || $0 == "." })
        else { return false }
        return (Double(t) ?? 0) > 0
    }

    private func field(_ label: String, @ViewBuilder value: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            value()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - issue

/// Mint supply of a token into other people's balances — the Mac port
/// of Android's `IssueTokenActivity`.
///
/// **One carve, many recipients.** The op takes a list, so issuing to
/// twenty FIDs costs one miner fee rather than twenty. What bounds the
/// list is the OP_RETURN, and the budget is counted live off the
/// encoded payload rather than estimated.
struct IssueTokenSheet: View {
    let session: ActiveSession
    let token: Token
    let onDone: (String?) -> Void

    /// One editable row. Identified by a `UUID` rather than by its
    /// contents so that clearing a FID field does not re-identify the
    /// row and lose what was typed in the amount next to it.
    private struct Line: Identifiable {
        let id = UUID()
        var fid: String = ""
        var cid: String?
        var amount: String = ""
    }

    @State private var lines: [Line] = [Line()]
    @State private var pickingFor: UUID?
    @State private var pick: FidPickerRequest?
    @State private var busy = false
    @State private var error: String?

    private var transfers: [TokenTransfer] {
        lines
            .filter { !$0.fid.trimmingCharacters(in: .whitespaces).isEmpty
                      || !$0.amount.trimmingCharacters(in: .whitespaces).isEmpty }
            .map { TokenTransfer(fid: $0.fid, amount: $0.amount) }
    }

    /// The carve builder is the single source of truth about whether
    /// this is issuable — the sheet asks it rather than re-deriving the
    /// rules, so the button and the broadcast can never disagree.
    private var buildError: String? {
        guard !transfers.isEmpty else { return nil }
        do {
            _ = try TokenFeip.issueCarve(
                tokenId: token.id, issueTo: transfers, scale: token.decimalPlaces
            )
            return nil
        } catch let e as TokenFeip.Failure {
            return e.description
        } catch {
            return String(describing: error)
        }
    }

    private var total: Double {
        transfers.reduce(0) { $0 + (Double($1.amount.trimmingCharacters(in: .whitespaces)) ?? 0) }
    }

    private var canCarve: Bool {
        !transfers.isEmpty && buildError == nil && !busy && session.canSign
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Issue \(token.displayName)")
                .font(.title3.bold())

            Text(token.openIssue == true
                 ? "This token is open-issue: anyone may mint it, within the limits its deployer set. Every issue is public and permanent."
                 : "Only you can issue this token, because you deployed it. Every issue is public and permanent.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 12) {
                labelled("Circulating", TokenAmount.string(token.circulating, scale: token.decimalPlaces))
                if let cap = token.capacity, !cap.isEmpty {
                    labelled("Capacity", cap)
                }
                labelled("Decimals", "\(token.decimalPlaces)")
            }

            Divider()

            ScrollView {
                VStack(spacing: 8) {
                    ForEach($lines) { $line in
                        HStack(spacing: 8) {
                            Button {
                                pickingFor = line.id
                                pick = .one(
                                    title: "Issue to",
                                    subtitle: "They receive newly minted \(token.displayName).",
                                    excluded: []
                                )
                            } label: {
                                Image(systemName: "person.crop.circle.badge.plus")
                            }
                            .buttonStyle(.borderless)
                            .help("Pick a FID from contacts or the chain")

                            VStack(alignment: .leading, spacing: 2) {
                                TextField("Recipient FID", text: $line.fid)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(.body, design: .monospaced))
                                if let cid = line.cid, !cid.isEmpty {
                                    Text(cid).font(.caption2).foregroundStyle(.secondary)
                                }
                            }

                            TextField("Amount", text: $line.amount)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 130)
                                .multilineTextAlignment(.trailing)

                            Button {
                                lines.removeAll { $0.id == line.id }
                                if lines.isEmpty { lines = [Line()] }
                            } label: {
                                Image(systemName: "minus.circle")
                            }
                            .buttonStyle(.borderless)
                            .disabled(lines.count == 1 && line.fid.isEmpty && line.amount.isEmpty)
                        }
                    }
                }
            }
            .frame(maxHeight: 220)

            HStack {
                Button {
                    lines.append(Line())
                } label: {
                    Label("Add recipient", systemImage: "plus")
                }
                .controlSize(.small)

                Spacer()

                if let room = TokenFeip.remainingRecipients(
                    op: .issue, tokenId: token.id, lines: transfers,
                    scale: token.decimalPlaces
                ) {
                    Text("room for about \(room) more")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(room < 3 ? Color.orange : Color.secondary)
                }
            }

            Divider()

            HStack {
                Text("Total to issue")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text(TokenAmount.string(total, scale: token.decimalPlaces))
                    .font(.body.monospacedDigit().bold())
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            } else if let b = buildError {
                Text(b).font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Cancel") { onDone(nil) }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Issue") { Task { await issue() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canCarve)
            }
        }
        .padding(20)
        .frame(width: 620)
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                if let target = pickingFor, let first = picked.first,
                   let index = lines.firstIndex(where: { $0.id == target }) {
                    lines[index].fid = first.fid
                    lines[index].cid = first.cid
                }
                pickingFor = nil
                pick = nil
            } onCancel: { pickingFor = nil; pick = nil }
        }
    }

    private func issue() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            let txid = try await session.carveTokenIssueOnChain(
                tokenId: token.id, issueTo: transfers, scale: token.decimalPlaces
            )
            onDone(txid)
        } catch {
            self.error = "Couldn't issue: \(error)"
        }
    }

    private func labelled(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption2).foregroundStyle(.tertiary)
            Text(value).font(.caption.monospacedDigit())
        }
    }
}

// MARK: - send

/// Move part of a holding to someone else — the Mac port of Android's
/// `SendTokenActivity`.
///
/// **The recipient is in the payload, not in a payment.** Nothing about
/// this carve pays the recipient any FCH, so nothing bounces if the FID
/// is wrong: the balance lands on an address nobody holds a key for and
/// stays there. That is why the FID goes through the picker by default
/// and why the confirmation names it back.
struct SendTokenSheet: View {
    let session: ActiveSession
    let token: Token
    let holder: TokenHolder
    let onDone: (String?) -> Void

    @State private var recipient: PickedFid?
    @State private var manualFid = ""
    @State private var amount = ""
    @State private var pick: FidPickerRequest?
    @State private var busy = false
    @State private var error: String?
    /// The balance as of opening this sheet, re-read from the chain.
    /// The row the sheet was opened from may be minutes old, and the
    /// difference is the difference between a carve and a rejection.
    @State private var freshBalance: Double?
    @State private var checking = false

    private var balance: Double { freshBalance ?? holder.balance ?? 0 }
    private var scale: Int { token.decimalPlaces }

    private var targetFid: String {
        recipient?.fid ?? manualFid.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var transfer: TokenTransfer {
        TokenTransfer(fid: targetFid, amount: amount)
    }

    /// Everything wrong with the form, cheapest check first. The carve
    /// builder owns the amount rules; the balance check is this sheet's,
    /// because the builder does not know what the holder has.
    private var validationError: String? {
        guard !targetFid.isEmpty else { return nil }
        guard !amount.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        do {
            _ = try TokenFeip.transferCarve(
                tokenId: token.id, transferTo: [transfer], scale: scale
            )
        } catch let e as TokenFeip.Failure {
            return e.description
        } catch {
            return String(describing: error)
        }
        if let typed = Double(amount.trimmingCharacters(in: .whitespaces)), typed > balance {
            return "That is more than the \(TokenAmount.string(balance, scale: scale)) you hold."
        }
        if targetFid == session.liveFid {
            return "That is your own FID — the carve would cost a fee and move nothing."
        }
        return nil
    }

    private var canSend: Bool {
        !targetFid.isEmpty
            && !amount.trimmingCharacters(in: .whitespaces).isEmpty
            && validationError == nil
            && !busy
            && session.canSign
            && token.canTransfer
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Send \(token.displayName)")
                .font(.title3.bold())

            if !token.canTransfer {
                warning(token.isClosed
                        ? "This token is closed. Balances are frozen where they sit and nothing can move."
                        : "This token was deployed non-transferable. Balances can never move.")
            }

            HStack {
                Text("You hold").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if checking {
                    ProgressView().controlSize(.small)
                }
                Text(TokenAmount.string(balance, scale: scale))
                    .font(.body.monospacedDigit().bold())
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Recipient").font(.caption).foregroundStyle(.secondary)
                if let recipient {
                    HStack(spacing: 8) {
                        FidAvatarView(fid: recipient.fid, size: 28)
                        VStack(alignment: .leading, spacing: 2) {
                            if let cid = recipient.cid, !cid.isEmpty {
                                Text(cid).font(.body)
                            }
                            CopyableText.elidingMiddle(
                                recipient.fid, head: 10, tail: 10,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                        Spacer()
                        Button("Change") { openPicker() }
                            .controlSize(.small)
                    }
                } else {
                    HStack(spacing: 8) {
                        TextField("Paste a FID, or choose", text: $manualFid)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                        Button {
                            openPicker()
                        } label: {
                            Image(systemName: "person.crop.circle.badge.plus")
                        }
                        .help("Pick from contacts or the chain")
                    }
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Amount").font(.caption).foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    TextField(scale == 0 ? "Whole units only" : "Up to \(scale) decimal places",
                              text: $amount)
                        .textFieldStyle(.roundedBorder)
                        .multilineTextAlignment(.trailing)
                    Button("Max") { amount = TokenAmount.plain(balance, scale: scale) }
                        .controlSize(.small)
                        .disabled(balance <= 0)
                }
            }

            Text("Nothing about this carve pays the recipient any FCH — the token protocol reads their FID out of the payload. If the FID is wrong the balance lands somewhere nobody holds a key for, and no part of that can be undone.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            } else if let v = validationError {
                Text(v).font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Cancel") { onDone(nil) }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Send") { Task { await send() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSend)
            }
        }
        .padding(20)
        .frame(width: 480)
        .task { await refreshBalance() }
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                recipient = picked.first
                pick = nil
            } onCancel: { pick = nil }
        }
    }

    private func openPicker() {
        pick = .one(
            title: "Send to",
            subtitle: "They receive the \(token.displayName) once the carve confirms.",
            initialQuery: manualFid,
            excluded: [session.liveFid]
        )
    }

    /// Re-read the balance from the chain rather than trusting the row
    /// this sheet was opened from.
    private func refreshBalance() async {
        checking = true
        defer { checking = false }
        if let fresh = try? await session.tokenService.fetchHolder(
            fid: session.liveFid, tokenId: token.id
        ) {
            freshBalance = fresh.balance
            try? session.tokens.upsertHolder(fresh)
        }
    }

    private func send() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            let txid = try await session.carveTokenTransferOnChain(
                tokenId: token.id, transferTo: [transfer], scale: scale
            )
            onDone(txid)
        } catch {
            self.error = "Couldn't send: \(error)"
        }
    }

    private func warning(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
            Text(text).font(.caption).foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - detail

/// Everything the chain says about one token, plus who holds it — the
/// Mac port of Android's token card expansion and
/// `TokenHistoryActivity`'s per-token view, as one sheet.
struct TokenDetailSheet: View {
    let session: ActiveSession
    let token: Token
    let onClose: () -> Void

    private enum Tab: String, CaseIterable, Identifiable {
        case rules = "Rules"
        case holders = "Holders"
        case history = "History"
        var id: String { rawValue }
    }

    @State private var tab: Tab = .rules
    @State private var holders: [TokenHolder] = []
    @State private var history: [TokenHistory] = []
    @State private var loading = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(token.displayName).font(.title3.bold())
                    CopyableText.elidingMiddle(
                        token.id, head: 12, tail: 12,
                        font: .system(.caption, design: .monospaced)
                    )
                    .foregroundStyle(.secondary)
                }
                Spacer()
                if token.isClosed { chip("Closed", color: .red) }
                if token.openIssue == true { chip("Open issue", color: .orange) }
                if token.transferable == true { chip("Transferable", color: .indigo) }
            }

            if let desc = token.desc, !desc.isEmpty {
                Text(desc).font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Picker("", selection: $tab) {
                ForEach(Tab.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            ScrollView {
                switch tab {
                case .rules:   rulesView
                case .holders: holdersView
                case .history: historyView
                }
            }
            .frame(minHeight: 260, maxHeight: 340)

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            HStack {
                if loading { ProgressView().controlSize(.small) }
                Spacer()
                Button("Close") { onClose() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 560)
        .onChange(of: tab) { _, new in Task { await load(new) } }
    }

    private var rulesView: some View {
        VStack(alignment: .leading, spacing: 0) {
            row("Deployer", token.deployer, mono: true)
            row("Consensus FID", token.consensusId, mono: true)
            row("Capacity", token.capacity?.isEmpty == false ? token.capacity : "no cap")
            row("Decimal places", "\(token.decimalPlaces)")
            row("Circulating", TokenAmount.string(token.circulating, scale: token.decimalPlaces))
            row("Transferable", flag(token.transferable))
            row("Closable", flag(token.closable))
            row("Closed", flag(token.closed) )
            row("Open issue", flag(token.openIssue))
            if token.openIssue == true {
                row("Max per issue", token.maxAmtPerIssue ?? "unlimited")
                row("Min CDD per issue", token.minCddPerIssue ?? "none")
                row("Max issues per FID", token.maxIssuesPerAddr ?? "unlimited")
            }
            row("Created", token.birthTime.map(Self.dateString))
            row("Last activity", token.lastTime.map(Self.dateString))
            row("Height", token.lastHeight.map(String.init))
        }
    }

    @ViewBuilder
    private var holdersView: some View {
        if holders.isEmpty {
            Text(loading ? "Loading holders…" : "Nobody holds this token yet.")
                .font(.callout).foregroundStyle(.secondary)
                .padding(.vertical, 8)
        } else {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(holders) { h in
                    HStack(spacing: 8) {
                        FidAvatarView(fid: h.fid ?? "", size: 22)
                        CopyableText.elidingMiddle(
                            h.fid ?? "—", head: 8, tail: 8,
                            font: .system(.caption, design: .monospaced)
                        )
                        if h.fid == session.liveFid { chip("You", color: .blue) }
                        Spacer()
                        Text(TokenAmount.string(h.balance, scale: token.decimalPlaces))
                            .font(.caption.monospacedDigit())
                    }
                    .padding(.vertical, 5)
                    Divider()
                }
            }
        }
    }

    @ViewBuilder
    private var historyView: some View {
        if history.isEmpty {
            Text(loading ? "Loading history…" : "No operations recorded yet.")
                .font(.callout).foregroundStyle(.secondary)
                .padding(.vertical, 8)
        } else {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(history) { h in
                    TokenHistoryRow(entry: h, scale: token.decimalPlaces, liveFid: session.liveFid)
                        .padding(.vertical, 6)
                    Divider()
                }
            }
        }
    }

    private func load(_ tab: Tab) async {
        guard tab != .rules else { return }
        loading = true
        defer { loading = false }
        do {
            switch tab {
            case .holders where holders.isEmpty:
                holders = try await session.tokenService
                    .fetchHolders(ofToken: token.id, size: 50).rows
            case .history where history.isEmpty:
                history = try await session.tokenService
                    .fetchHistory(tokenId: token.id, size: 50).rows
            default:
                break
            }
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    private func flag(_ value: Bool?) -> String {
        guard let value else { return "—" }
        return value ? "yes" : "no"
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String?, mono: Bool = false) -> some View {
        if let value, !value.isEmpty, value != "—" {
            HStack(alignment: .top) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                    .frame(width: 140, alignment: .leading)
                if mono {
                    CopyableText(value, font: .system(.caption, design: .monospaced))
                } else {
                    CopyableText(value, font: .caption)
                }
                Spacer()
            }
            .padding(.vertical, 4)
            Divider()
        }
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    static func dateString(_ seconds: Int64) -> String {
        let f = DateFormatter()
        f.dateFormat = "yy-MM-dd HH:mm"
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }
}

// MARK: - history row

/// One op from the `token_history` index, rendered so the five ops read
/// differently at a glance — a `close` and a `transfer` are not the same
/// kind of event and should not look like one.
struct TokenHistoryRow: View {
    let entry: TokenHistory
    let scale: Int
    let liveFid: String
    /// Token id → display name, when the caller has resolved them.
    var names: [String: String] = [:]

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(entry.operation?.label ?? entry.op ?? "Unknown")
                        .font(.caption.bold())
                        .foregroundStyle(color)
                    if let name = entry.name, !name.isEmpty {
                        Text(name).font(.caption)
                    } else if let tid = entry.affectedTokenIds.first {
                        Text(names[tid] ?? tid.elidingMiddle(head: 6, tail: 6))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    if entry.involves(liveFid) {
                        Text("you").font(.caption2)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Capsule().fill(Color.blue.opacity(0.15)))
                            .foregroundStyle(.blue)
                    }
                    Spacer(minLength: 6)
                    if let t = entry.time {
                        Text(TokenDetailSheet.dateString(t))
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }

                if let signer = entry.signer, !signer.isEmpty {
                    HStack(spacing: 4) {
                        Text("by").font(.caption2).foregroundStyle(.tertiary)
                        CopyableText.elidingMiddle(
                            signer, head: 6, tail: 6,
                            font: .system(.caption2, design: .monospaced)
                        )
                        .foregroundStyle(.secondary)
                    }
                }

                ForEach(Array(entry.allocations.enumerated()), id: \.offset) { _, line in
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.right")
                            .font(.caption2).foregroundStyle(.tertiary)
                        CopyableText.elidingMiddle(
                            line.fid ?? "—", head: 6, tail: 6,
                            font: .system(.caption2, design: .monospaced)
                        )
                        .foregroundStyle(.secondary)
                        Text(TokenAmount.string(line.amount, scale: scale))
                            .font(.caption2.monospacedDigit())
                    }
                }

                // A destroy or close names its targets in `tokenIds`,
                // and there is no allocation line to carry them.
                if entry.allocations.isEmpty, entry.affectedTokenIds.count > 1 {
                    Text("\(entry.affectedTokenIds.count) tokens")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            }
        }
    }

    private var icon: String {
        switch entry.operation {
        case .deploy:   return "sparkles"
        case .issue:    return "plus.circle"
        case .transfer: return "arrow.right.circle"
        case .destroy:  return "flame"
        case .close:    return "lock"
        case nil:       return "questionmark.circle"
        }
    }

    private var color: Color {
        switch entry.operation {
        case .deploy:   return .purple
        case .issue:    return .green
        case .transfer: return .blue
        case .destroy:  return .red
        case .close:    return .orange
        case nil:       return .secondary
        }
    }
}
