import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - Merge / Split

/// Reshape the selected cashes — the Mac port of Android's
/// `ReorgCashActivity`.
///
/// **Two optional fields decide the whole operation**, which is
/// Android's design and worth keeping: leaving both blank merges
/// everything into one bill, filling in one of them splits, and
/// filling in both demands an exact result. Presenting four named
/// modes instead would be four screens for what is really one
/// question — how many bills, and how big.
///
/// The preview under the fields is the real plan, priced by
/// ``CashReorg`` with the same fee model that will build the
/// transaction. It updates on every keystroke, so an amount the
/// inputs can't cover says so before the user commits rather than
/// after.
struct CashReorgSheet: View {
    let session: ActiveSession
    let inputs: [Cash]
    let onDone: (CashActionOutcome) -> Void

    @State private var countText = ""
    @State private var amountText = ""
    @State private var feePerByte = "1"

    @State private var working = false
    @State private var actionError: String?
    @State private var unsigned: WalletService.UnsignedReorgResult?
    @State private var showUnsigned = false
    @State private var showConfirm = false

    private var totalIn: Int64 { inputs.reduce(0) { $0 + $1.value } }
    private var totalCd: Int64 { inputs.reduce(0) { $0 + ($1.cd ?? 0) } }

    private var feeRate: Int64? {
        guard let n = Int64(feePerByte), n > 0 else { return nil }
        return n
    }

    /// Blank means "not specified" — that is how the shape is chosen,
    /// so an unparsable entry has to be distinguishable from an empty
    /// one. A partially-typed "0." is neither, and reads as invalid.
    private var count: Int? {
        let t = countText.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return nil }
        return Int(t)
    }

    private var amountSats: Int64? {
        let t = amountText.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, let fch = Double(t), fch > 0, fch < 21_000_000 else { return nil }
        return Int64((fch * Double(Cash.satoshisPerBch)).rounded())
    }

    private var countIsValid: Bool { (count ?? 0) > 0 }

    private var shape: CashReorg.Shape? {
        let countGiven = !countText.trimmingCharacters(in: .whitespaces).isEmpty
        let amountGiven = !amountText.trimmingCharacters(in: .whitespaces).isEmpty
        switch (countGiven, amountGiven) {
        case (false, false): return .consolidate
        case (true, false):  return count.map { .byCount($0) }
        case (false, true):  return amountSats.map { .byAmount($0) }
        case (true, true):
            guard let count, let amountSats else { return nil }
            return .exact(count: count, amount: amountSats)
        }
    }

    /// The priced plan, or the reason there isn't one. Computed, not
    /// stored: any input change has to re-price, and a stale preview
    /// beside fresh fields is worse than no preview.
    private var planResult: Result<CashReorg.Plan, Error>? {
        guard let shape, let feeRate else { return nil }
        do {
            return .success(try CashReorg.plan(inputs: inputs, shape: shape, feePerByte: feeRate))
        } catch {
            return .failure(error)
        }
    }

    private var plan: CashReorg.Plan? {
        if case .success(let p) = planResult { return p }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    spending
                    form
                    preview
                    if let actionError {
                        CopyableText(actionError, font: .caption)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(16)
            }
            Divider()
            buttons
        }
        .frame(minWidth: 540, minHeight: 480)
        .sheet(isPresented: $showUnsigned) {
            if let unsigned {
                UnsignedTxSheet(
                    info: unsigned.info,
                    summary: summaryLine(unsigned.plan)
                ) {
                    showUnsigned = false
                    onDone(.exported)
                }
            }
        }
        .alert("Reshape \(formatFch(totalIn)) into \(plan?.outputs.count ?? 0) cash(es)?",
               isPresented: $showConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Reorganize", role: .destructive) { Task { await run() } }
        } message: {
            Text("""
            The money stays yours — every new cash pays your own address. The miner fee of \(plan?.fee ?? 0) sat is what it costs.

            This broadcasts immediately and cannot be undone.
            """)
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.triangle.merge").font(.title2)
            VStack(alignment: .leading, spacing: 2) {
                Text("Merge / Split cash").font(.title3).bold()
                Text("Pay yourself, changing the denominations")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var spending: some View {
        HStack(spacing: 18) {
            stat("Spending", "\(inputs.count) cash(es)")
            stat("Amount", formatFch(totalIn))
            stat("CoinDays", "\(totalCd)")
            Spacer()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var form: some View {
        Form {
            Section {
                LabeledField(
                    "How many cashes",
                    hint: countText.isEmpty
                        ? "Leave blank to let the amount decide."
                        : (countIsValid ? nil : "Whole number, 1 or more."),
                    hintIsError: !countText.isEmpty && !countIsValid
                ) {
                    TextField("", text: $countText, prompt: Text("e.g. 4"))
                        .fieldInputStyle()
                        .frame(maxWidth: 120)
                }

                LabeledField(
                    "Each worth",
                    hint: amountText.isEmpty
                        ? "Leave blank to split the total evenly."
                        : (amountSats.map { "= \($0) sat" } ?? "Not a valid amount."),
                    hintIsError: !amountText.isEmpty && amountSats == nil
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $amountText, prompt: Text("e.g. 0.5"))
                            .fieldInputStyle()
                            .frame(maxWidth: 160)
                        Text("FCH").foregroundStyle(.secondary)
                    }
                }

                LabeledField("Fee rate") {
                    HStack(spacing: 8) {
                        TextField("", text: $feePerByte, prompt: Text("1"))
                            .fieldInputStyle()
                            .frame(maxWidth: 80)
                        Text("sat/byte").foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text(shapeName)
            } footer: {
                Text("Blank + blank merges everything into one cash. A count alone splits evenly. An amount alone issues as many cashes of that size as fit. Both together issues exactly that many, and the remainder comes back as change.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(minHeight: 240)
    }

    private var shapeName: String {
        switch shape {
        case .consolidate?:      return "Merge into one"
        case .byCount?:          return "Split evenly"
        case .byAmount?:         return "Split into fixed denominations"
        case .exact?:            return "Exact bills plus change"
        case nil:                return "Check the fields"
        }
    }

    @ViewBuilder
    private var preview: some View {
        switch planResult {
        case .success(let plan):
            VStack(alignment: .leading, spacing: 6) {
                Text("You will get").font(.caption.bold()).foregroundStyle(.secondary)
                ForEach(Array(billLines(plan).enumerated()), id: \.offset) { _, line in
                    Text(line).font(.callout.monospacedDigit())
                }
                Text(summaryLine(plan))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.green.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 8))

        case .failure(let error):
            Label(describe(error), systemImage: "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)

        case nil:
            Label("Fill in the fields above to see what this produces.",
                  systemImage: "info.circle")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    /// Group identical bills so "19 × 1 FCH" doesn't print nineteen
    /// times, and name the change bill for what it is.
    private func billLines(_ plan: CashReorg.Plan) -> [String] {
        var lines: [String] = []
        let bills = plan.hasChange ? Array(plan.outputs.dropLast()) : plan.outputs
        var run: (value: Int64, count: Int)?
        for value in bills {
            if var current = run, current.value == value {
                current.count += 1
                run = current
            } else {
                if let current = run {
                    lines.append("\(current.count) × \(formatFch(current.value))")
                }
                run = (value, 1)
            }
        }
        if let current = run {
            lines.append("\(current.count) × \(formatFch(current.value))")
        }
        if plan.hasChange, let change = plan.outputs.last {
            lines.append("1 × \(formatFch(change))  (change)")
        }
        return lines
    }

    private var buttons: some View {
        HStack(spacing: 8) {
            Button("Cancel") { onDone(.cancelled) }
                .keyboardShortcut(.cancelAction)
            Spacer()
            if session.canSign {
                Button {
                    actionError = nil
                    // See SendView: when the global confirmation is
                    // on it shows the real transaction a moment from
                    // now, so this one would only be noise.
                    if session.confirmBeforeSigning {
                        Task { await run() }
                    } else {
                        showConfirm = true
                    }
                } label: {
                    if working {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Working…")
                        }.frame(width: 150)
                    } else {
                        Text("Reorganize").frame(width: 150)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(plan == nil || working)
            } else {
                Button {
                    buildUnsigned()
                } label: {
                    Text("Build unsigned tx").frame(width: 160)
                }
                .buttonStyle(.borderedProminent)
                .disabled(plan == nil)
                .help("Watch-only identity — build the transaction here and sign it where the key lives.")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - run

    @MainActor
    private func run() async {
        guard let shape, let feeRate else { return }
        working = true
        actionError = nil
        defer { working = false }
        do {
            let result = try await session.reorganizeFromLive(
                inputs: inputs, shape: shape, feePerByte: feeRate
            )
            onDone(.broadcast(
                txid: result.remoteTxid,
                note: "Reorganized \(inputs.count) cash(es) into \(result.plan.outputs.count) — txid \(result.remoteTxid.elidingMiddle())"
            ))
        } catch {
            actionError = describe(error)
        }
    }

    private func buildUnsigned() {
        guard let shape, let feeRate else { return }
        actionError = nil
        do {
            unsigned = try session.buildUnsignedReorgFromLive(
                inputs: inputs, shape: shape, feePerByte: feeRate
            )
            showUnsigned = true
        } catch {
            actionError = describe(error)
        }
    }

    // MARK: - format

    private func stat(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.callout.monospacedDigit().bold())
        }
    }

    private func summaryLine(_ plan: CashReorg.Plan) -> String {
        "\(plan.inputs.count) in · \(plan.outputs.count) out · fee \(plan.fee) sat · \(plan.estimatedSize) B"
    }

    private func formatFch(_ sats: Int64) -> String {
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        let value = Double(sats) / Double(Cash.satoshisPerBch)
        return (f.string(from: NSNumber(value: value)) ?? "0") + " FCH"
    }

    private func describe(_ error: Error) -> String {
        if let e = error as? CashReorg.Failure { return e.description }
        if let e = error as? WalletService.Failure { return e.description }
        if let e = error as? CoinSelector.Failure { return e.description }
        return String(describing: error)
    }
}

// MARK: - Send from chosen cashes

/// Pay someone using exactly the ticked cashes — Android's send
/// button on the Cash screen, which hands its selection to
/// `CreateTxActivity` as pre-chosen inputs.
///
/// The difference from the Send pane is only in where the inputs come
/// from, and it is a real difference: here the whole selection is
/// spent whatever the amount, so the remainder comes back as change.
/// That is what makes this the way to spend a *specific* cash — an
/// old one whose CoinDays you want to destroy, say — instead of
/// whichever the selector happened to like.
struct CashSendSheet: View {
    let session: ActiveSession
    let inputs: [Cash]
    let onDone: (CashActionOutcome) -> Void

    @State private var recipient = ""
    @State private var amountText = ""
    @State private var feePerByte = "1"

    @State private var working = false
    @State private var actionError: String?
    @State private var unsigned: WalletService.UnsignedSendResult?
    @State private var showUnsigned = false
    @State private var showConfirm = false
    @State private var showScan = false
    @State private var pick: FidPickerRequest?

    private var totalIn: Int64 { inputs.reduce(0) { $0 + $1.value } }

    private var recipientLooksValid: Bool {
        (try? FchAddress(fid: recipient)) != nil
    }

    private var amountSats: Int64? {
        guard !amountText.isEmpty, let fch = Double(amountText), fch > 0, fch < 21_000_000
        else { return nil }
        return Int64((fch * Double(Cash.satoshisPerBch)).rounded())
    }

    private var feeRate: Int64? {
        guard let n = Int64(feePerByte), n > 0 else { return nil }
        return n
    }

    private var planResult: Result<CoinSelector.Plan, Error>? {
        guard let amountSats, let feeRate else { return nil }
        do {
            return .success(try CoinSelector.fixed(
                cashes: inputs, amount: amountSats, feePerByte: feeRate
            ))
        } catch {
            return .failure(error)
        }
    }

    private var plan: CoinSelector.Plan? {
        if case .success(let p) = planResult { return p }
        return nil
    }

    private var canSubmit: Bool { !working && recipientLooksValid && plan != nil }

    /// What happens to the part of the selection the payment doesn't
    /// use — the question a fixed input set raises and an ordinary
    /// send doesn't.
    private var changeSentence: String {
        guard let plan, plan.hasChange else { return "the remainder goes to the miner" }
        return "\(plan.change) sat comes back as change"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    spending
                    form
                    preview
                    if let actionError {
                        CopyableText(actionError, font: .caption)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(16)
            }
            Divider()
            buttons
        }
        .frame(minWidth: 560, minHeight: 480)
        .sheet(isPresented: $showScan) {
            QrScanSheet(title: "Scan recipient FID") { scanned in
                recipient = scanned
                showScan = false
            } onCancel: {
                showScan = false
            }
        }
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                if let one = picked.first { recipient = one.fid }
                pick = nil
            } onCancel: {
                pick = nil
            }
        }
        .sheet(isPresented: $showUnsigned) {
            if let unsigned {
                UnsignedTxSheet(result: unsigned) {
                    showUnsigned = false
                    onDone(.exported)
                }
            }
        }
        .alert("Send \(formatFch(amountSats ?? 0))?", isPresented: $showConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Send", role: .destructive) { Task { await run() } }
        } message: {
            Text("""
            To: \(recipient)
            Funded by all \(inputs.count) selected cash(es); \(changeSentence).

            This broadcasts immediately and cannot be undone.
            """)
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "paperplane").font(.title2)
            VStack(alignment: .leading, spacing: 2) {
                Text("Send from selected cash").font(.title3).bold()
                Text("These cashes fund the payment — all of them")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var spending: some View {
        HStack(spacing: 18) {
            stat("Spending", "\(inputs.count) cash(es)")
            stat("Available", formatFch(totalIn))
            Spacer()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var form: some View {
        Form {
            Section("To") {
                LabeledField(
                    "Recipient FID",
                    hint: (!recipient.isEmpty && !recipientLooksValid)
                        ? "Not a valid FCH mainnet address."
                        : nil,
                    hintIsError: true
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $recipient, prompt: Text("F…"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                        Button {
                            pick = .one(
                                title: "Who is this payment for?",
                                subtitle: "Search your contacts, or look up a FID or CID on chain. A payment cannot be undone."
                            )
                        } label: {
                            Image(systemName: "person.text.rectangle")
                        }
                        .help("Find the recipient in contacts or on chain")
                        Button {
                            showScan = true
                        } label: {
                            Image(systemName: "qrcode.viewfinder")
                        }
                        .help("Scan the recipient FID from a QR code")
                    }
                }
            }

            Section("Amount") {
                LabeledField("Amount", hint: amountSats.map { "= \($0) sat" }) {
                    HStack(spacing: 8) {
                        TextField("", text: $amountText, prompt: Text("0.001"))
                            .fieldInputStyle()
                            .frame(maxWidth: 200)
                        Text("FCH").foregroundStyle(.secondary)
                        Button("Max") { fillMax() }
                            .help("Pay out everything the selected cashes hold, less the fee")
                    }
                }
                LabeledField("Fee rate") {
                    HStack(spacing: 8) {
                        TextField("", text: $feePerByte, prompt: Text("1"))
                            .fieldInputStyle()
                            .frame(maxWidth: 80)
                        Text("sat/byte").foregroundStyle(.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .frame(minHeight: 260)
    }

    @ViewBuilder
    private var preview: some View {
        switch planResult {
        case .success(let plan):
            Text("\(plan.selected.count) input(s) · fee \(plan.fee) sat · \(plan.estimatedSize) B" +
                 (plan.hasChange ? " · change \(plan.change) sat" : " · no change (remainder becomes fee)"))
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
        case .failure(let error):
            Label(describe(error), systemImage: "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        case nil:
            EmptyView()
        }
    }

    private var buttons: some View {
        HStack(spacing: 8) {
            Button("Cancel") { onDone(.cancelled) }
                .keyboardShortcut(.cancelAction)
            Spacer()
            if session.canSign {
                Button {
                    actionError = nil
                    if session.confirmBeforeSigning {
                        Task { await run() }
                    } else {
                        showConfirm = true
                    }
                } label: {
                    if working {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Sending…")
                        }.frame(width: 140)
                    } else {
                        Text("Send").frame(width: 140)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canSubmit)
            } else {
                Button {
                    buildUnsigned()
                } label: {
                    Text("Build unsigned tx").frame(width: 160)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canSubmit)
                .help("Watch-only identity — build the transaction here and sign it where the key lives.")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    /// Everything, less the fee for a one-output transaction. Uses
    /// the same size formula the plan does, so the resulting amount
    /// prices to a plan with no change rather than one that is one
    /// satoshi short.
    private func fillMax() {
        guard let feeRate else { return }
        let fee = Int64(CoinSelector.sizeFor(nIn: inputs.count, nOut: 1)) * feeRate
        let max = totalIn - fee
        guard max > 0 else { return }
        amountText = String(format: "%.8f", Double(max) / Double(Cash.satoshisPerBch))
    }

    // MARK: - run

    @MainActor
    private func run() async {
        guard let amountSats, let feeRate else { return }
        working = true
        actionError = nil
        defer { working = false }
        do {
            let result = try await session.sendFromLive(
                to: recipient, amount: amountSats,
                feePerByte: feeRate, using: inputs
            )
            onDone(.broadcast(
                txid: result.remoteTxid,
                note: "Sent \(formatFch(amountSats)) from \(inputs.count) cash(es) — txid \(result.remoteTxid.elidingMiddle())"
            ))
        } catch {
            actionError = describe(error)
        }
    }

    private func buildUnsigned() {
        guard let amountSats, let feeRate else { return }
        actionError = nil
        Task { @MainActor in
            do {
                unsigned = try await session.buildUnsignedSendFromLive(
                    to: recipient, amount: amountSats,
                    feePerByte: feeRate, using: inputs
                )
                showUnsigned = true
            } catch {
                actionError = describe(error)
            }
        }
    }

    // MARK: - format

    private func stat(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.callout.monospacedDigit().bold())
        }
    }

    private func formatFch(_ sats: Int64) -> String {
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        let value = Double(sats) / Double(Cash.satoshisPerBch)
        return (f.string(from: NSNumber(value: value)) ?? "0") + " FCH"
    }

    private func describe(_ error: Error) -> String {
        if let e = error as? WalletService.Failure { return e.description }
        if let e = error as? CoinSelector.Failure { return e.description }
        return String(describing: error)
    }
}
