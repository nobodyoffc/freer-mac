import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Compose — the Mac port of Android's `CreateTxActivity`.
///
/// **Send is for paying someone; this is for building a transaction.**
/// The Send pane asks two questions (who, how much) and decides
/// everything else: which coins to spend, how many outputs, what the
/// change looks like. That is the right shape for the ninety-nine
/// percent case and the wrong shape for the rest — paying twelve
/// people in one transaction, spending one particular cash, writing a
/// message alongside a payment, or locking a payment until a block
/// height. Here every part of the transaction is an editable list, and
/// nothing is chosen on your behalf.
///
/// **Inputs left empty means "choose for me."** An empty input list is
/// not an error: it falls back to the same coin selection Send uses,
/// so composing several outputs and pressing Send works without ever
/// opening the cash picker. Naming inputs turns that off — the coins
/// you ticked are the instruction.
///
/// **Time locks.** With the lock toggle on, each output is paid to a
/// CLTV script instead of an address: `<height> OP_CHECKLOCKTIMEVERIFY
/// OP_DROP` in front of the usual body, so the coins exist immediately
/// but cannot move until the chain reaches that height. The redeem
/// scripts are published in the transaction's OP_RETURN, which is what
/// lets the recipient reconstruct how to spend them later — and is why
/// the lock toggle takes the OP_RETURN field away: there is only one
/// such output to go around. Paying a `3…` multisig group with a lock
/// needs the group's keys, which are fetched from the chain on demand.
struct CreateTxView: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession

    // The document under construction.
    @State private var inputSlots: [RawTxInfo.Slot] = []
    @State private var outputSlots: [RawTxInfo.Slot] = []
    @State private var opReturn: String = ""
    @State private var feePerByte: String = "1"

    // The add-an-output row.
    @State private var payeeFid: String = ""
    @State private var payeeAmount: String = ""
    @State private var lockMode: Bool = false
    @State private var lockDays: String = ""

    // Wallet state the composer reads.
    @State private var snapshot: CashSnapshot?
    @State private var loading = false

    // Cash rows behind the picked inputs, keyed by outpoint. Manual and
    // imported inputs have no row here; ``inputCashes`` synthesizes one
    // so the preview and the post-send cache update see a full set.
    @State private var pickedCashes: [String: Cash] = [:]

    @State private var busy = false
    @State private var status: Status?
    @State private var result: WalletService.SendResult?
    @State private var unsigned: WalletService.UnsignedSendResult?

    @State private var showCashPicker = false
    @State private var showManualInput = false
    @State private var showImport = false
    @State private var importKind: ImportKind = .transaction
    @State private var showUnsigned = false
    @State private var showScan = false
    @State private var pick: FidPickerRequest?
    @State private var batchFids: [String] = []
    @State private var showBatch = false

    private enum Status: Identifiable {
        case ok(String)
        case bad(String)
        var id: String { text }
        var text: String {
            switch self { case .ok(let t), .bad(let t): return t }
        }
        var isError: Bool { if case .bad = self { return true }; return false }
    }

    enum ImportKind { case transaction, payees }

    // MARK: - derived

    private var feeRate: Int64 { max(1, Int64(feePerByte) ?? 1) }

    private var bestHeight: Int64 { snapshot?.bestHeight ?? 0 }

    /// The document as it currently stands. Rebuilt on every read
    /// rather than cached: it is cheap, and a stale copy would price a
    /// transaction the user is no longer looking at.
    private var info: RawTxInfo {
        RawTxInfo(
            sender: session.liveFid,
            feeRate: RawTxInfo.feeRate(satsPerByte: feeRate),
            inputs: inputSlots.isEmpty ? nil : inputSlots,
            outputs: outputSlots.isEmpty ? nil : outputSlots,
            opReturn: opReturn.isEmpty ? nil : opReturn,
            changeTo: session.liveFid
        )
    }

    private var quote: WalletService.AdvancedQuote {
        session.wallet.quoteAdvanced(info)
    }

    /// Full cash rows for the picked inputs, in slot order.
    private var inputCashes: [Cash] {
        inputSlots.compactMap { slot in
            pickedCashes[Self.key(slot)] ?? Cash(slot: slot)
        }
    }

    private var spendableCashes: [Cash] {
        guard let h160 = try? FchAddress(fid: session.liveFid).hash160 else { return [] }
        return (snapshot?.cashes ?? []).filter {
            !$0.pendingSpend && $0.withinUnconfirmedChainLimit && $0.locksToP2PKH(hash160: h160)
        }
    }

    private var payeeIsValid: Bool {
        (try? FchAddress(fid: payeeFid.trimmed, expectedVersionByte: nil)) != nil
    }

    private var payeeAmountSats: Int64? {
        guard let coins = Double(payeeAmount.trimmed),
              coins >= TxFee.minAmountCoins, coins <= TxFee.maxAmountCoins
        else { return nil }
        return Int64((coins * Double(Cash.satoshisPerBch)).rounded())
    }

    private var lockDaysValue: Int? {
        guard let n = Int(lockDays.trimmed), n > 0 else { return nil }
        return n
    }

    private var canAddOutput: Bool {
        payeeIsValid && payeeAmountSats != nil && (!lockMode || lockDaysValue != nil)
    }

    /// Something has to be in the transaction. Outputs alone are
    /// enough (coin selection can fund them); a message alone needs
    /// inputs, because the automatic path pays one payee and carries
    /// no OP_RETURN.
    private var canSubmit: Bool {
        guard !busy else { return false }
        if !outputSlots.isEmpty { return true }
        return !inputSlots.isEmpty && !opReturn.isEmpty
    }

    private static func key(_ slot: RawTxInfo.Slot) -> String {
        "\(slot.birthTxId ?? "?"):\(slot.birthIndex ?? 0)"
    }

    // MARK: - body

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            PaneHeader(session: session)
            Divider()
            toolbar

            ScrollView {
                // Priced once per render and handed down: every
                // section reads the same numbers, and the fee is not
                // recomputed six times on the way through.
                let quote = self.quote
                VStack(alignment: .leading, spacing: 14) {
                    inputsSection(quote)
                    outputsSection(quote)
                    if !lockMode { opReturnSection }
                    settingsSection
                    if let status { statusRow(status) }
                    if let result { resultRows(result) }
                }
                .padding(.bottom, 12)
            }
        }
        .padding()
        .frame(minWidth: 580)
        .task { await load() }
        .onChange(of: session.liveFid) { _, _ in
            clearAll()
            Task { await load() }
        }
        .sheet(isPresented: $showCashPicker) {
            CashPickerSheet(
                cashes: spendableCashes,
                alreadyPicked: Set(inputSlots.map(Self.key)),
                bestHeight: bestHeight
            ) { chosen in
                addInputs(chosen)
                showCashPicker = false
            } onCancel: { showCashPicker = false }
        }
        .sheet(isPresented: $showManualInput) {
            ManualInputSheet { slot in
                appendInput(slot)
                showManualInput = false
            } onCancel: { showManualInput = false }
        }
        .sheet(isPresented: $showImport) {
            ImportTxSheet(kind: importKind) { text in
                showImport = false
                applyImport(text)
            } onCancel: { showImport = false }
        }
        .sheet(isPresented: $showUnsigned) {
            if let unsigned {
                UnsignedTxSheet(result: unsigned) { showUnsigned = false }
            }
        }
        .sheet(isPresented: $showScan) {
            QrScanSheet(title: "Scan payee FID") { scanned in
                payeeFid = scanned
                showScan = false
            } onCancel: { showScan = false }
        }
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                pick = nil
                handlePicked(picked.map(\.fid))
            } onCancel: { pick = nil }
        }
        .sheet(isPresented: $showBatch) {
            BatchOutputSheet(fids: batchFids, suggested: max(0, quote.rest)) { amount in
                showBatch = false
                Task { await addBatchOutputs(fids: batchFids, amount: amount) }
            } onCancel: { showBatch = false }
        }
    }

    // MARK: - toolbar

    private var toolbar: some View {
        HStack(spacing: 8) {
            Button {
                clearAll()
            } label: {
                Label("Clear", systemImage: "trash")
            }
            .help("Empty every field and start again")
            .disabled(isEmptyDraft)

            Button {
                copyDocument()
            } label: {
                Label("Copy JSON", systemImage: "doc.on.doc")
            }
            .help("Copy the unsigned document — paste it into the Android app, or into a signer")
            .disabled(inputSlots.isEmpty && outputSlots.isEmpty)

            Menu {
                Button("Transaction JSON…") {
                    importKind = .transaction
                    showImport = true
                }
                Button("Payee list…") {
                    importKind = .payees
                    showImport = true
                }
            } label: {
                Label("Import", systemImage: "square.and.arrow.down")
            }
            .fixedSize()
            .help("Load a document composed elsewhere, or a list of payees to pay in one go")

            Toggle(isOn: $lockMode) {
                Label("Time lock", systemImage: lockMode ? "lock" : "lock.open")
            }
            .toggleStyle(.button)
            .tint(.orange)
            .help(lockMode
                  ? "Outputs are locked until a block height. The OP_RETURN carries the redeem scripts, so your own text can't share it."
                  : "Lock each new output until a block height")
            .onChange(of: lockMode) { _, on in
                if !on { lockDays = "" }
            }

            Spacer()

            if loading { ProgressView().controlSize(.small) }

            submitButton
        }
    }

    private var submitButton: some View {
        Group {
            if session.canSign {
                Button {
                    Task { await submit() }
                } label: {
                    if busy {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Sending…")
                        }
                        .frame(width: 110)
                    } else {
                        Text(inputSlots.isEmpty ? "Select & Send" : "Send")
                            .frame(width: 110)
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!canSubmit)
                .help(inputSlots.isEmpty
                      ? "No inputs named — the wallet will choose coins the way the Send pane does"
                      : "Sign and broadcast, spending exactly the inputs listed")
            } else {
                Button {
                    Task { await buildUnsigned() }
                } label: {
                    Text(busy ? "Building…" : "Build unsigned").frame(width: 130)
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!canSubmit || inputSlots.isEmpty)
                .help("Watch-only: build the document here and sign it where the key lives. Name the inputs first — nothing can be selected without a key to spend with.")
            }
        }
    }

    // MARK: - inputs

    private func inputsSection(_ quote: WalletService.AdvancedQuote) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    Text("Spending")
                        .font(.callout.bold())
                        .foregroundStyle(.secondary)
                    Text("\(inputSlots.count) cash")
                        .font(.callout.monospacedDigit())
                    Text(fch(quote.totalIn))
                        .font(.callout.monospacedDigit().bold())
                    Text("\(quote.totalCd) CD")
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)

                    Spacer()

                    Button {
                        showCashPicker = true
                    } label: {
                        Label("Choose cash…", systemImage: "banknote")
                    }
                    .disabled(spendableCashes.isEmpty)

                    Button {
                        showManualInput = true
                    } label: {
                        Label("Outpoint…", systemImage: "plus.rectangle.on.rectangle")
                    }
                    .help("Add an input by txid and index — a cash this wallet has never seen")
                }

                if inputSlots.isEmpty {
                    Text("No inputs named. The wallet will pick coins itself, the way the Send pane does.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(Array(inputSlots.enumerated()), id: \.offset) { index, slot in
                        inputRow(slot, at: index)
                        if index < inputSlots.count - 1 { Divider() }
                    }
                }
            }
            .padding(6)
        }
    }

    private func inputRow(_ slot: RawTxInfo.Slot, at index: Int) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                CopyableText(
                    display: "\((slot.birthTxId ?? "?").elidingMiddle(head: 10, tail: 8)):\(slot.birthIndex ?? 0)",
                    copy: "\(slot.birthTxId ?? ""):\(slot.birthIndex ?? 0)",
                    font: .system(.caption, design: .monospaced)
                )
                if let lockTime = slot.lockTime, lockTime > 0 {
                    lockBadge(lockTime)
                }
            }
            Spacer(minLength: 8)
            Text("\(slot.cd ?? 0) CD")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            Text(fch(slot.value ?? 0))
                .font(.body.monospacedDigit())
            Button(role: .destructive) {
                removeInput(at: index)
            } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            .help("Remove this input")
        }
    }

    // MARK: - outputs

    private func outputsSection(_ quote: WalletService.AdvancedQuote) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    Text("Paying")
                        .font(.callout.bold())
                        .foregroundStyle(.secondary)
                    Text(fch(quote.totalOut))
                        .font(.callout.monospacedDigit().bold())
                    Text("Fee")
                        .font(.callout.bold())
                        .foregroundStyle(.secondary)
                    Text(quote.unpriced ? "—" : fch(quote.fee ?? 0))
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(quote.unpriced ? .orange : .primary)
                    if !quote.unpriced {
                        Text("\(quote.estimatedSize) B")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                ForEach(Array(outputSlots.enumerated()), id: \.offset) { index, slot in
                    outputRow(slot, at: index)
                    Divider()
                }

                addOutputRow(quote)
            }
            .padding(6)
        }
    }

    private func restButton(_ quote: WalletService.AdvancedQuote) -> some View {
        Button {
            fillRest()
        } label: {
            Text("Rest \(quote.unpriced ? "—" : fch(quote.rest))")
                .font(.caption.monospacedDigit())
        }
        .buttonStyle(.link)
        .disabled(quote.unpriced || quote.rest <= 0 || !payeeIsValid)
        .help(payeeIsValid
              ? "Put everything that's left into the amount above — the transaction then balances with no change"
              : "Enter a payee first: what's left depends on the size of the output that would carry it")
    }

    private func outputRow(_ slot: RawTxInfo.Slot, at index: Int) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                CopyableText(
                    display: (slot.owner ?? "?").elidingMiddle(head: 10, tail: 8),
                    copy: slot.owner ?? "",
                    font: .system(.caption, design: .monospaced)
                )
                if let p2sh = slot.p2sh {
                    HStack(spacing: 6) {
                        if let lockTime = slot.lockTime, lockTime > 0 { lockBadge(lockTime) }
                        CopyableText(
                            display: "→ \(p2sh.address.elidingMiddle(head: 8, tail: 6))",
                            copy: p2sh.address,
                            font: .caption2.monospaced()
                        )
                        .foregroundStyle(.secondary)
                        .help("The P2SH address the coins actually go to — the hash of the redeem script")
                        if p2sh.kind != .cltv, let m = p2sh.m, let n = p2sh.n {
                            Text("\(m)-of-\(n)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Spacer(minLength: 8)
            Text(fch(slot.value ?? 0))
                .font(.body.monospacedDigit())
            Button(role: .destructive) {
                outputSlots.remove(at: index)
            } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            .help("Remove this output")
        }
    }

    /// The add-an-output form, as one short line per question:
    /// **who**, **how much**, and — only with the lock on — **how
    /// long**. The Add button rides the last line, whichever that is.
    ///
    /// It began as a single row and the tail fell off the edge of the
    /// pane. An address field wide enough to read, two icon buttons, an
    /// amount, a day count and the block height it lands on came to
    /// roughly 615pt of a 490pt pane, so switching the lock on pushed
    /// its own day field and the Add button off screen — the control
    /// you needed appeared only in the mode where it did not fit. One
    /// question per line has no width at which it breaks, which is
    /// worth more here than saving two rows of height.
    ///
    /// "Rest" sits beside the amount because that is the field it
    /// fills; in the section header it was a button acting on
    /// something a hundred points away.
    private func addOutputRow(_ quote: WalletService.AdvancedQuote) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                TextField("", text: $payeeFid, prompt: Text("Pay to  F… or 3…"))
                    .font(.system(.body, design: .monospaced))
                    .fieldInputStyle()
                    .frame(minWidth: 200)

                Button {
                    pick = .many(
                        title: "Who is this paying?",
                        subtitle: "Pick one to fill the field, or several to pay them all the same amount.",
                        initialQuery: payeeFid.trimmed
                    )
                } label: {
                    Image(systemName: "person.text.rectangle")
                }
                .help("Find payees in contacts or on chain — picking several pays them all at once")

                Button { showScan = true } label: { Image(systemName: "qrcode.viewfinder") }
                    .help("Scan the payee FID from a QR code")
            }

            HStack(spacing: 8) {
                TextField("", text: $payeeAmount, prompt: Text("0.001"))
                    .fieldInputStyle()
                    .frame(width: 110)
                Text("F").foregroundStyle(.secondary)
                restButton(quote)
                if !lockMode {
                    Spacer()
                    addOutputButton
                }
            }

            if lockMode {
                HStack(spacing: 8) {
                    Image(systemName: "lock").foregroundStyle(.orange)
                    Text("Locked for").foregroundStyle(.secondary)
                    TextField("", text: $lockDays, prompt: Text("days"))
                        .fieldInputStyle()
                        .frame(width: 70)
                    if let days = lockDaysValue, bestHeight > 0 {
                        Text("days → block \(bestHeight + Int64(days) * 24 * 60)")
                            .font(.callout.monospacedDigit())
                            .foregroundStyle(.secondary)
                            .help("A lock is a block height, not a date. Blocks are about a minute apart, so this is where the chain has to reach before the payee can move the coins.")
                    } else {
                        Text("days")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    addOutputButton
                }
            }
        }
    }

    private var addOutputButton: some View {
        Button {
            Task { await addOutput() }
        } label: {
            Label("Add", systemImage: "plus.circle.fill")
        }
        .disabled(!canAddOutput || busy)
        .help(addOutputHelp)
    }

    /// Why the Add button is off, said in the tooltip rather than left
    /// to be guessed — with the lock on there are three fields to fill
    /// and a disabled button says nothing about which one is missing.
    private var addOutputHelp: String {
        if payeeFid.trimmed.isEmpty { return "Enter who to pay" }
        if !payeeIsValid { return "\(payeeFid.trimmed) is not a valid FCH address" }
        if payeeAmountSats == nil { return "Enter an amount to pay" }
        if lockMode && lockDaysValue == nil { return "Enter how many days to lock this payment for" }
        return "Add this output"
    }

    // MARK: - opReturn / settings

    private var opReturnSection: some View {
        GroupBox {
            LabeledField(
                "On chain message",
                hint: opReturn.isEmpty
                    ? "Optional. Written as OP_RETURN — public, permanent, and it costs a little extra fee."
                    : "\(opReturn.utf8.count) bytes"
            ) {
                TextField("", text: $opReturn, prompt: Text("Text carved into the chain"), axis: .vertical)
                    .lineLimit(1...4)
                    .fieldInputStyle()
            }
            .padding(6)
        }
    }

    private var settingsSection: some View {
        GroupBox {
            HStack(spacing: 16) {
                LabeledField("Fee rate") {
                    HStack(spacing: 6) {
                        TextField("", text: $feePerByte, prompt: Text("1"))
                            .fieldInputStyle()
                            .frame(width: 60)
                        Text("sat/byte").foregroundStyle(.secondary)
                    }
                }
                if bestHeight > 0 {
                    Text("Chain at block \(bestHeight)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task { await load(force: true) }
                } label: {
                    Label("Refresh cash", systemImage: "arrow.clockwise")
                }
                .disabled(loading)
            }
            .padding(6)
        }
    }

    private func statusRow(_ status: Status) -> some View {
        CopyableText(status.text, font: .callout)
            .foregroundStyle(status.isError ? .red : .green)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder
    private func resultRows(_ r: WalletService.SendResult) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                Text("Broadcast accepted").bold()
            }
            CopyableText(
                display: "txid: \(r.remoteTxid)",
                copy: r.remoteTxid,
                font: .system(.caption, design: .monospaced)
            )
            .lineLimit(1)
            .truncationMode(.middle)
            CopyableText(
                "\(r.plan.selected.count) input(s) · fee \(r.plan.fee) sat · \(r.plan.estimatedSize) B"
                    + (r.plan.hasChange ? " · change \(r.plan.change) sat" : " · no change"),
                font: .caption.monospaced()
            )
            .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func lockBadge(_ lockTime: Int64) -> some View {
        let unlocked = TxFee.isLockTimeUnlocked(lockTime, bestHeight: bestHeight)
        let remaining = max(0, lockTime - bestHeight)
        HStack(spacing: 3) {
            Image(systemName: unlocked ? "lock.open" : "lock")
            Text(bestHeight > 0 && !unlocked
                 ? "\(remaining / (24 * 60))d (\(remaining) blocks @ \(lockTime))"
                 : "block \(lockTime)")
        }
        .font(.caption2.monospacedDigit())
        .foregroundStyle(unlocked ? Color.green : Color.orange)
        .help(unlocked
              ? "The lock has expired — this can be spent now"
              : "Locked until block \(lockTime)")
    }

    // MARK: - actions

    private var isEmptyDraft: Bool {
        inputSlots.isEmpty && outputSlots.isEmpty && opReturn.isEmpty
            && payeeFid.isEmpty && payeeAmount.isEmpty
    }

    private func clearAll() {
        inputSlots = []
        outputSlots = []
        pickedCashes = [:]
        opReturn = ""
        payeeFid = ""
        payeeAmount = ""
        lockDays = ""
        lockMode = false
        status = nil
        result = nil
    }

    @MainActor
    private func load(force: Bool = false) async {
        loading = true
        defer { loading = false }
        if !force, let cached = try? session.wallet.cachedSnapshot(forAddress: session.liveFid) {
            snapshot = cached
        }
        snapshot = (try? await session.wallet.refreshCashes(forFid: session.liveFid)) ?? snapshot
    }

    private func addInputs(_ cashes: [Cash]) {
        for cash in cashes {
            let slot = RawTxInfo.Slot.input(from: cash)
            guard !inputSlots.contains(where: { Self.key($0) == Self.key(slot) }) else { continue }
            pickedCashes[Self.key(slot)] = cash
            inputSlots.append(slot)
        }
        result = nil
    }

    private func appendInput(_ slot: RawTxInfo.Slot) {
        guard !inputSlots.contains(where: { Self.key($0) == Self.key(slot) }) else {
            status = .bad("That outpoint is already an input.")
            return
        }
        inputSlots.append(slot)
        result = nil
    }

    private func removeInput(at index: Int) {
        pickedCashes.removeValue(forKey: Self.key(inputSlots[index]))
        inputSlots.remove(at: index)
    }

    /// Turn the add-output row into a slot and append it.
    ///
    /// Async only because a time-locked payment to a `3…` group has to
    /// look the group up on chain first — the CLTV script wraps the
    /// members' public keys, and an address does not carry them.
    @MainActor
    private func addOutput() async {
        guard let amount = payeeAmountSats else {
            status = .bad("Amount must be between \(TxFee.minAmountCoins) and \(Int(TxFee.maxAmountCoins)) F.")
            return
        }
        let fid = payeeFid.trimmed
        guard payeeIsValid else {
            status = .bad("\(fid) is not a valid FCH address.")
            return
        }
        status = nil

        guard lockMode, let days = lockDaysValue else {
            outputSlots.append(.output(to: fid, amount: amount))
            clearOutputRow()
            return
        }
        guard let lockTime = await lockHeight(daysFromNow: days) else { return }

        do {
            let multisig = FchAddress.isP2sh(fid: fid) ? try await multisig(for: fid) : nil
            outputSlots.append(
                try RawTxInfo.Slot.lockedOutput(
                    to: fid, amount: amount, lockTime: lockTime, multisig: multisig
                )
            )
            clearOutputRow()
        } catch {
            status = .bad(String(describing: error))
        }
    }

    private func clearOutputRow() {
        payeeFid = ""
        payeeAmount = ""
        if lockMode { lockDays = "" }
        result = nil
    }

    private func handlePicked(_ fids: [String]) {
        guard !fids.isEmpty else { return }
        if fids.count == 1 {
            payeeFid = fids[0]
            return
        }
        batchFids = fids
        showBatch = true
    }

    @MainActor
    private func addBatchOutputs(fids: [String], amount: Int64) async {
        status = nil
        var lockTime: Int64?
        if lockMode, let days = lockDaysValue {
            guard let height = await lockHeight(daysFromNow: days) else { return }
            lockTime = height
        }
        for fid in fids {
            do {
                if let lockTime {
                    let group = FchAddress.isP2sh(fid: fid) ? try await multisig(for: fid) : nil
                    outputSlots.append(try RawTxInfo.Slot.lockedOutput(
                        to: fid, amount: amount, lockTime: lockTime, multisig: group
                    ))
                } else {
                    outputSlots.append(.output(to: fid, amount: amount))
                }
            } catch {
                status = .bad("\(fid): \(error)")
                return
            }
        }
        status = .ok("Added \(fids.count) output(s).")
    }

    /// The block height `days` from now. Blocks are about a minute
    /// apart, and the chain's current height has to come from
    /// somewhere — without it a lock height would be a guess, and a
    /// wrong guess locks money for the wrong length of time.
    @MainActor
    private func lockHeight(daysFromNow days: Int) async -> Int64? {
        if bestHeight <= 0 { await load(force: true) }
        guard bestHeight > 0 else {
            status = .bad("The chain height is unknown, so a lock height can't be worked out. Refresh and try again.")
            return nil
        }
        // Android's `daysToHeights` currently returns the day count
        // unchanged rather than `days * 24 * 60`, so a "1 day" lock is
        // one block there. Matching the honest reading here: one block
        // per minute.
        return bestHeight + Int64(days) * 24 * 60
    }

    @MainActor
    private func multisig(for fid: String) async throws -> Multisig? {
        if let contact = ((try? session.contacts.get(fid: fid)) ?? nil), let group = contact.multisig {
            return group
        }
        let fetched = try await session.wallet.multisigsByIds([fid])
        guard let group = fetched[fid] else {
            throw CreateTxFailure.unknownMultisig(fid)
        }
        return group
    }

    private func fillRest() {
        let fid = payeeFid.trimmed
        guard payeeIsValid else { return }
        var candidate = RawTxInfo.Slot.output(to: fid, amount: 0)
        if lockMode, let days = lockDaysValue, bestHeight > 0 {
            // Only a local guess is needed here: the script's *size*
            // is what moves the fee, and that is the same for any lock
            // height. The real height is resolved when the output is
            // actually added.
            candidate = (try? RawTxInfo.Slot.lockedOutput(
                to: fid, amount: 0, lockTime: bestHeight + Int64(days) * 24 * 60
            )) ?? candidate
        }
        guard let value = session.wallet.maxValueForOutput(in: info, adding: candidate) else {
            status = .bad("Nothing is left to spend.")
            return
        }
        payeeAmount = trimmedCoins(value)
    }

    private func copyDocument() {
        do {
            var doc = info
            doc.senderMultisig = nil
            let json = try doc.exportJson()
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(json, forType: .string)
            status = .ok("Transaction JSON copied.")
        } catch {
            status = .bad(String(describing: error))
        }
    }

    private func applyImport(_ text: String) {
        let trimmed = text.trimmed
        switch importKind {
        case .transaction:
            do {
                let imported = try RawTxInfo.fromJson(trimmed)
                inputSlots = imported.inputs ?? []
                outputSlots = imported.outputs ?? []
                opReturn = imported.opReturn ?? ""
                pickedCashes = [:]
                // Re-attach any wallet rows we recognise, so the
                // imported inputs are claimed and reconciled like
                // picked ones rather than treated as strangers.
                for cash in spendableCashes {
                    let key = "\(cash.birthTxId):\(cash.birthIndex)"
                    if inputSlots.contains(where: { Self.key($0) == key }) {
                        pickedCashes[key] = cash
                    }
                }
                result = nil
                status = .ok("Imported \(inputSlots.count) input(s) and \(outputSlots.count) output(s).")
            } catch {
                status = .bad("That is not a transaction document: \(error)")
            }
        case .payees:
            do {
                let slots = try JSONDecoder().decode([RawTxInfo.Slot].self, from: Data(trimmed.utf8))
                let usable = slots.filter { ($0.owner?.isEmpty == false) && ($0.value ?? 0) > 0 }
                guard !usable.isEmpty else {
                    status = .bad("No payees in that list — each entry needs an `owner` and a `value`.")
                    return
                }
                outputSlots.append(contentsOf: usable)
                status = .ok("Added \(usable.count) output(s).")
            } catch {
                status = .bad("That is not a payee list: \(error)")
            }
        }
    }

    // MARK: - submit

    @MainActor
    private func submit() async {
        busy = true
        status = nil
        result = nil
        defer { busy = false }
        do {
            // Empty inputs is the "choose for me" path: fall back to
            // the ordinary send, which selects coins the same way the
            // Send pane does. Only a single-payee, no-lock draft can
            // take it — anything richer needs the composed builder.
            if inputSlots.isEmpty {
                result = try await autoSelectedSend()
            } else {
                result = try await session.sendAdvancedFromLive(
                    info: info,
                    inputCashes: inputCashes,
                    bestHeight: bestHeight
                )
            }
            clearDraftAfterSend()
            await load(force: true)
            await appState.refreshLiveFidInfo()
        } catch {
            status = .bad(String(describing: error))
        }
    }

    /// The no-inputs path. Coin selection only knows how to fund one
    /// payment, so a draft with several outputs is asked to name its
    /// inputs rather than quietly funding only the first.
    @MainActor
    private func autoSelectedSend() async throws -> WalletService.SendResult {
        guard outputSlots.count == 1,
              let only = outputSlots.first,
              let fid = only.owner,
              only.redeemScript == nil,
              opReturn.isEmpty
        else {
            throw CreateTxFailure.needsExplicitInputs
        }
        return try await session.sendFromLive(
            to: fid,
            amount: only.value ?? 0,
            feePerByte: feeRate
        )
    }

    private func clearDraftAfterSend() {
        inputSlots = []
        outputSlots = []
        pickedCashes = [:]
        opReturn = ""
        payeeFid = ""
        payeeAmount = ""
        lockDays = ""
    }

    @MainActor
    private func buildUnsigned() async {
        busy = true
        status = nil
        defer { busy = false }
        do {
            unsigned = try session.buildUnsignedAdvancedFromLive(
                info: info, bestHeight: bestHeight
            )
            showUnsigned = true
        } catch {
            status = .bad(String(describing: error))
        }
    }

    // MARK: - formatting

    private func fch(_ sats: Int64) -> String { "\(trimmedCoins(sats)) F" }

    /// Coins with trailing zeros trimmed — `0.5 F`, not `0.50000000 F`.
    private func trimmedCoins(_ sats: Int64) -> String {
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        f.numberStyle = .decimal
        f.usesGroupingSeparator = false
        let coins = Double(sats) / Double(Cash.satoshisPerBch)
        return f.string(from: NSNumber(value: coins)) ?? "0"
    }
}

enum CreateTxFailure: Error, CustomStringConvertible {
    case unknownMultisig(String)
    case needsExplicitInputs

    var description: String {
        switch self {
        case .unknownMultisig(let fid):
            return "\(fid) is a P2SH address with no multisig record on chain, so a time-locked payment to it can't be built. Ask the group for their redeem script, or pay it without a lock."
        case .needsExplicitInputs:
            return "Automatic coin selection funds a single plain payment. This draft has more than that — choose the cash to spend, and the exact transaction will be built from it."
        }
    }
}

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
