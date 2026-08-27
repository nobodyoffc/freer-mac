import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - pick cash to spend

/// Tick the cashes a composed transaction should spend — Android's
/// `CashActivity` in select mode.
///
/// Only spendable rows are offered. A `pendingSpend` or too-deeply
/// unconfirmed cash is left out rather than shown-and-disabled,
/// because in this sheet there is nothing to learn from a row you
/// cannot pick; the Cash pane is where those are explained.
struct CashPickerSheet: View {
    let cashes: [Cash]
    let alreadyPicked: Set<String>
    let bestHeight: Int64
    let onDone: ([Cash]) -> Void
    let onCancel: () -> Void

    @State private var selection: Set<String> = []
    @State private var sortByValue = true

    private func key(_ cash: Cash) -> String { "\(cash.birthTxId):\(cash.birthIndex)" }

    private var available: [Cash] {
        cashes
            .filter { !alreadyPicked.contains(key($0)) }
            .sorted { sortByValue ? $0.value > $1.value : ($0.cd ?? 0) > ($1.cd ?? 0) }
    }

    private var chosen: [Cash] { available.filter { selection.contains(key($0)) } }
    private var chosenValue: Int64 { chosen.reduce(0) { $0 + $1.value } }
    private var chosenCd: Int64 { chosen.reduce(0) { $0 + ($1.cd ?? 0) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "banknote").font(.title2)
                Text("Choose cash to spend").font(.title3).bold()
                Spacer()
                Picker("", selection: $sortByValue) {
                    Text("Amount").tag(true)
                    Text("CoinDays").tag(false)
                }
                .pickerStyle(.segmented)
                .frame(width: 180)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            if available.isEmpty {
                Text("Every spendable cash is already an input.")
                    .foregroundStyle(.secondary)
                    .padding(24)
                    .frame(maxWidth: .infinity, alignment: .center)
            } else {
                List {
                    ForEach(available, id: \.self) { cash in
                        row(cash)
                    }
                }
                .listStyle(.inset)
                .frame(minHeight: 240)
            }

            Divider()

            HStack {
                Text("\(chosen.count) selected · \(coins(chosenValue)) F · \(chosenCd) CD")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("Add") { onDone(chosen) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(chosen.isEmpty)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 560, minHeight: 400)
    }

    private func row(_ cash: Cash) -> some View {
        let k = key(cash)
        return HStack(spacing: 10) {
            Toggle(isOn: Binding(
                get: { selection.contains(k) },
                set: { on in
                    if on { selection.insert(k) } else { selection.remove(k) }
                }
            )) { EmptyView() }
                .labelsHidden()

            VStack(alignment: .leading, spacing: 2) {
                Text(coins(cash.value) + " F")
                    .font(.body.monospacedDigit().bold())
                CopyableText(
                    display: "\(cash.birthTxId.elidingMiddle(head: 10, tail: 8)):\(cash.birthIndex)",
                    copy: "\(cash.birthTxId):\(cash.birthIndex)",
                    font: .system(.caption, design: .monospaced)
                )
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Text("\(cash.cd ?? 0) CD")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            if let h = cash.birthHeight, h > 0 {
                Text("Block \(h)")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.tertiary)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            if selection.contains(k) { selection.remove(k) } else { selection.insert(k) }
        }
    }
}

// MARK: - manual outpoint

/// Add an input this wallet has never seen — Android's
/// `AddTxInputDialog`, plus the two fields that dialog leaves out.
///
/// Android asks only for txid, index and amount, which is enough for
/// a plain P2PKH input. A time-locked input needs more: the lock
/// height (so the transaction's own locktime can clear it) and the
/// redeem script (so it can be signed at all). Both are optional, and
/// the redeem script can be left blank when the owner is given —
/// a single-sig CLTV script is reconstructible from those two.
struct ManualInputSheet: View {
    let onDone: (RawTxInfo.Slot) -> Void
    let onCancel: () -> Void

    @State private var txid = ""
    @State private var index = "0"
    @State private var amount = ""
    @State private var owner = ""
    @State private var lockTime = ""
    @State private var redeemScript = ""
    @State private var error: String?

    private var amountSats: Int64? {
        guard let coins = Double(amount.trimmed), coins > 0 else { return nil }
        return Int64((coins * Double(Cash.satoshisPerBch)).rounded())
    }

    private var txidLooksValid: Bool {
        let t = txid.trimmed
        return t.count == 64 && Hex.isHex(t)
    }

    private var canAdd: Bool {
        txidLooksValid && Int(index.trimmed) != nil && amountSats != nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "plus.rectangle.on.rectangle").font(.title2)
                Text("Add an input").font(.title3).bold()
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            Form {
                Section {
                    LabeledField(
                        "Txid",
                        hint: (!txid.isEmpty && !txidLooksValid)
                            ? "A txid is 64 hex characters." : nil,
                        hintIsError: true
                    ) {
                        TextField("", text: $txid, prompt: Text("64 hex characters"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                    }
                    LabeledField("Index") {
                        TextField("", text: $index, prompt: Text("0"))
                            .fieldInputStyle()
                            .frame(width: 80)
                    }
                    LabeledField("Amount", hint: amountSats.map { "= \($0) sat" }) {
                        HStack(spacing: 6) {
                            TextField("", text: $amount, prompt: Text("0.001"))
                                .fieldInputStyle()
                                .frame(width: 140)
                            Text("F").foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("The output being spent")
                }

                Section {
                    LabeledField("Owner") {
                        TextField("", text: $owner, prompt: Text("F… (optional)"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                    }
                    LabeledField("Lock height") {
                        TextField("", text: $lockTime, prompt: Text("blank if not time-locked"))
                            .fieldInputStyle()
                            .frame(width: 180)
                    }
                    LabeledField(
                        "Redeem script",
                        hint: "Leave blank for a single-sig time lock — it is rebuilt from the owner and the lock height."
                    ) {
                        TextField("", text: $redeemScript, prompt: Text("hex (optional)"), axis: .vertical)
                            .font(.system(.caption, design: .monospaced))
                            .lineLimit(1...3)
                            .fieldInputStyle()
                    }
                } header: {
                    Text("Time lock")
                }

                if let error {
                    Section {
                        CopyableText(error, font: .callout)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("Add") { add() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canAdd)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 520)
    }

    private func add() {
        guard let value = amountSats, let idx = Int(index.trimmed) else { return }
        let lock = Int64(lockTime.trimmed)
        var script: String? = redeemScript.trimmed.isEmpty ? nil : redeemScript.trimmed
        if let script, !Hex.isHex(script) {
            error = "The redeem script must be hex."
            return
        }
        let ownerFid = owner.trimmed
        // Rebuild the script when we can, so the input is signable
        // rather than merely listed.
        if script == nil, let lock, lock > 0, !ownerFid.isEmpty,
           let p2sh = try? P2sh(fid: ownerFid, lockTime: lock) {
            script = p2sh.redeemScriptHex
        }
        onDone(RawTxInfo.Slot(
            owner: ownerFid.isEmpty ? nil : ownerFid,
            value: value,
            birthTxId: txid.trimmed,
            birthIndex: idx,
            redeemScript: script,
            lockTime: lock
        ))
    }
}

// MARK: - batch payees

/// One amount, paid to every FID picked — Android's
/// `AddOutputFromFidListDialog`.
struct BatchOutputSheet: View {
    let fids: [String]
    /// What is currently unspent, offered as a starting point: split
    /// evenly, it is the largest amount that still balances.
    let suggested: Int64
    let onDone: (Int64) -> Void
    let onCancel: () -> Void

    @State private var amount = ""

    private var amountSats: Int64? {
        guard let coins = Double(amount.trimmed),
              coins >= TxFee.minAmountCoins, coins <= TxFee.maxAmountCoins
        else { return nil }
        return Int64((coins * Double(Cash.satoshisPerBch)).rounded())
    }

    private var total: Int64 { (amountSats ?? 0) * Int64(fids.count) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "person.2").font(.title2)
                Text("Pay \(fids.count) payees").font(.title3).bold()
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            VStack(alignment: .leading, spacing: 10) {
                Text("Each gets the same amount. Remove or edit any of them afterwards in the output list.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 6) {
                    TextField("", text: $amount, prompt: Text("0.001"))
                        .fieldInputStyle()
                        .frame(width: 140)
                    Text("F each").foregroundStyle(.secondary)
                    if suggested > 0 {
                        Button("Split what's left") {
                            let each = suggested / Int64(max(1, fids.count))
                            amount = String(
                                format: "%.8f", Double(each) / Double(Cash.satoshisPerBch)
                            )
                        }
                        .buttonStyle(.link)
                        .help("Divide the unspent remainder equally — the fee still comes off the top, so trim it if the total does not fit")
                    }
                }

                if amountSats != nil {
                    Text("Total \(String(format: "%.8f", Double(total) / Double(Cash.satoshisPerBch))) F")
                        .font(.callout.monospacedDigit())
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(fids, id: \.self) { fid in
                            CopyableText(
                                display: fid.elidingMiddle(head: 12, tail: 8),
                                copy: fid,
                                font: .system(.caption, design: .monospaced)
                            )
                            .foregroundStyle(.secondary)
                        }
                    }
                }
                .frame(maxHeight: 140)
            }
            .padding(16)

            Divider()

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("Add outputs") {
                    if let sats = amountSats { onDone(sats) }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(amountSats == nil)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 460)
    }
}

// MARK: - import

/// Paste a document composed elsewhere: a whole transaction, or a
/// list of payees to append to the outputs.
struct ImportTxSheet: View {
    let kind: CreateTxView.ImportKind
    let onDone: (String) -> Void
    let onCancel: () -> Void

    @State private var text = ""

    private var title: String {
        kind == .transaction ? "Import a transaction" : "Import a payee list"
    }

    private var explanation: String {
        kind == .transaction
            ? "The unsigned document Compose copies, or the one the Android app exports. Inputs, outputs and the on-chain message are replaced by what it contains."
            : "A JSON array of `{\"owner\": \"F…\", \"value\": 100000}` entries — values in satoshis. They are appended to the outputs."
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "square.and.arrow.down").font(.title2)
                Text(title).font(.title3).bold()
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            VStack(alignment: .leading, spacing: 10) {
                Text(explanation)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                TextEditor(text: $text)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 200)
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color.secondary.opacity(0.3))
                    )

                Button {
                    if let pasted = NSPasteboard.general.string(forType: .string) {
                        text = pasted
                    }
                } label: {
                    Label("Paste from clipboard", systemImage: "doc.on.clipboard")
                }
                .buttonStyle(.link)
            }
            .padding(16)

            Divider()

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("Import") { onDone(text) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(text.trimmed.isEmpty)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 540)
    }
}

// MARK: - shared formatting

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

/// Satoshis as coins, trailing zeros trimmed.
private func coins(_ sats: Int64) -> String {
    let f = NumberFormatter()
    f.numberStyle = .decimal
    f.minimumFractionDigits = 0
    f.maximumFractionDigits = 8
    f.usesGroupingSeparator = false
    return f.string(from: NSNumber(value: Double(sats) / Double(Cash.satoshisPerBch))) ?? "0"
}
