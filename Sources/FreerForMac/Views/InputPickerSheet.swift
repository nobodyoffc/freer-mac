import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Pick the cash a transaction should spend instead of what the wallet
/// chose — opened from ``TxConfirmSheet`` while it is asking.
///
/// **Why it exists.** Automatic selection is a guess at what the user
/// is willing to spend, and the approval dialog is the first moment the
/// guess is visible. A carve that needs one CoinDay can still land on a
/// cash the user was keeping for its age; this is where they say so.
///
/// **Nothing is signed from here.** The choice goes back to the wallet,
/// which releases the old claim, claims these, rebuilds the same
/// transaction and asks again — so what gets signed is still only what
/// the dialog showed. The outputs and the cost below the list are
/// repriced on every tick with ``TxPreview/repriced(spending:)``, which
/// prices through the function the wallet itself uses, so "Use these"
/// is enabled only for a choice the wallet will build — and what it
/// will build is on screen before the user commits to it.
///
/// **The transaction's own inputs stay tickable** although the cache
/// marks them `pendingSpend`: that flag is this transaction's claim,
/// and it is the claim being traded.
struct InputPickerSheet: View {
    let preview: TxPreview
    let session: ActiveSession
    let onCancel: () -> Void
    let onPick: ([Cash]) -> Void

    @State private var rows: [Cash] = []
    @State private var selection: Set<String> = []
    @State private var sort: SortField = .cd
    @State private var loadError: String?

    private enum SortField: String, CaseIterable, Identifiable {
        case cd = "CoinDays"
        case value = "Amount"
        case age = "Newest"
        var id: String { rawValue }
    }

    // MARK: - derived

    private func key(_ cash: Cash) -> String {
        "\(cash.birthTxId):\(cash.birthIndex)"
    }

    private var currentKeys: Set<String> { Set(preview.inputs.map(key)) }

    /// Same rule the wallet applies to named inputs, except that this
    /// transaction's own claim doesn't count against a row.
    private func isSpendable(_ cash: Cash, ownerHash160: Data?) -> Bool {
        guard cash.withinUnconfirmedChainLimit else { return false }
        guard !cash.pendingSpend || currentKeys.contains(key(cash)) else { return false }
        guard let ownerHash160 else { return false }
        return cash.locksToP2PKH(hash160: ownerHash160)
    }

    private var spendableRows: [Cash] {
        let ownerHash160 = try? FchAddress(fid: preview.from).hash160
        return rows.filter { isSpendable($0, ownerHash160: ownerHash160) }.sorted { a, b in
            switch sort {
            case .cd:
                if (a.cd ?? 0) != (b.cd ?? 0) { return (a.cd ?? 0) < (b.cd ?? 0) }
            case .value:
                if a.value != b.value { return a.value > b.value }
            case .age:
                // No birth time yet means unconfirmed, which is newest.
                let ta = a.birthTime ?? .max, tb = b.birthTime ?? .max
                if ta != tb { return ta > tb }
            }
            return key(a) < key(b)
        }
    }

    private var selectedRows: [Cash] { spendableRows.filter { selection.contains(key($0)) } }
    private var selectedValue: Int64 { selectedRows.reduce(0) { $0 + $1.value } }
    private var selectedCd: Int64 { selectedRows.reduce(0) { $0 + ($1.cd ?? 0) } }

    /// The transaction the choice would build, or why it can't be; nil
    /// while nothing is ticked.
    private var pricing: Result<TxPreview, Error>? {
        guard !selectedRows.isEmpty else { return nil }
        do {
            guard let repriced = try preview.repriced(spending: selectedRows) else { return nil }
            return .success(repriced)
        } catch {
            return .failure(error)
        }
    }

    /// The last choice that priced, so the outputs and cost stay on
    /// screen (dimmed) while the ticks are momentarily short.
    private var shown: TxPreview {
        if case .success(let repriced)? = pricing { return repriced }
        return preview
    }

    private var isPriced: Bool {
        if case .success? = pricing { return true }
        return false
    }

    private var canUse: Bool {
        guard case .success = pricing else { return false }
        return selection != currentKeys
    }

    // MARK: - body

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            toolbar
            Divider()
            list
            Divider()
            forecast
            Divider()
            footer
        }
        .frame(minWidth: 600, minHeight: 600)
        .onAppear(perform: load)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Choose the cash to spend").font(.title3).bold()
            Text(requirementText)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var requirementText: String {
        let paying = preview.payments.reduce(Int64(0)) { $0 + $1.amount }
        var text = paying > 0
            ? "It must cover \(formatFch(paying)) plus the miner fee"
            : "It must cover the miner fee"
        if preview.requiredCd > 0 {
            text += " and destroy at least \(preview.requiredCd) CoinDays"
        }
        return text + ". The transaction is rebuilt and shown to you again before anything is signed."
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            Picker("Sort", selection: $sort) {
                ForEach(SortField.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 260)
            Spacer()
            Button("Back to the wallet's choice") { selection = currentKeys }
                .controlSize(.small)
                .disabled(selection == currentKeys)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    @ViewBuilder
    private var list: some View {
        if let loadError {
            CopyableText(loadError)
                .foregroundStyle(.red)
                .padding(16)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else if spendableRows.isEmpty {
            Text("No spendable cash for this identity in the local cache.")
                .foregroundStyle(.secondary)
                .padding(16)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            List(spendableRows, id: \.self) { cash in
                row(cash)
            }
        }
    }

    private func row(_ cash: Cash) -> some View {
        let id = key(cash)
        return HStack(spacing: 12) {
            Toggle(isOn: Binding(
                get: { selection.contains(id) },
                set: { on in
                    if on { selection.insert(id) } else { selection.remove(id) }
                }
            )) { EmptyView() }
                .toggleStyle(.checkbox)
                .labelsHidden()

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(formatFch(cash.value)).font(.body.monospacedDigit().bold())
                    if currentKeys.contains(id) {
                        chip("in this transaction", color: .blue)
                    }
                    if cash.unconfirmedDepth > 0 {
                        chip("unconfirmed", color: .orange)
                    }
                }
                Text("\(cash.birthTxId.elidingMiddle(head: 10, tail: 8)):\(cash.birthIndex)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 0) {
                Text(cash.cd.map { "\($0)" } ?? "—")
                    .font(.body.monospacedDigit().bold())
                    .foregroundStyle((cash.cd ?? 0) > 0 ? Color.primary : Color.secondary)
                Text("CD").font(.caption2).foregroundStyle(.secondary)
            }
            .frame(minWidth: 62, alignment: .trailing)
        }
    }

    // MARK: - forecast

    /// Outputs and cost of the transaction the ticks would build, side
    /// by side — the two cards of the approval dialog, kept current
    /// while the choice changes. Dimmed when the ticks can't fund it:
    /// the numbers are then the wallet's choice, not this one.
    private var forecast: some View {
        HStack(alignment: .top, spacing: 12) {
            forecastCard("Outputs", systemImage: "arrow.up.right") {
                ForEach(Array(shown.outputs.enumerated()), id: \.offset) { _, out in
                    outputRow(out)
                }
            }
            forecastCard("Cost", systemImage: "tag") {
                costRow("Leaves this identity", formatFch(shown.leaving),
                        changed: shown.leaving != preview.leaving)
                costRow("Miner fee", "\(shown.fee) sat", changed: shown.fee != preview.fee)
                costRow("Size", "\(shown.estimatedSize) B at \(shown.feePerByte) sat/B",
                        changed: shown.estimatedSize != preview.estimatedSize)
                costRow(
                    "CoinDays destroyed",
                    shown.requiredCd > 0
                        ? "\(shown.coinDaysDestroyed) of \(shown.requiredCd) needed"
                        : "\(shown.coinDaysDestroyed)",
                    changed: shown.coinDaysDestroyed != preview.coinDaysDestroyed
                )
            }
        }
        .opacity(isPriced ? 1 : 0.45)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private func outputRow(_ out: TxPreview.Output) -> some View {
        HStack(spacing: 8) {
            if out.isOpReturn {
                Text("OP_RETURN — data")
                    .font(.caption)
                    .foregroundStyle(.purple)
            } else if let fid = out.fid {
                FidAvatarView(fid: fid, size: 18)
                CopyableText.elidingMiddle(
                    fid, head: 6, tail: 6,
                    font: .system(.caption, design: .monospaced)
                )
                .lineLimit(1)
                if out.isSelf {
                    chip(preview.kind == .reorg ? "yours" : "change", color: .blue)
                }
            }
            Spacer(minLength: 6)
            Text(formatFch(out.amount))
                .font(.caption.monospacedDigit().bold())
                .foregroundStyle(out.isSelf || out.isOpReturn ? .secondary : .primary)
        }
    }

    private func costRow(_ label: String, _ value: String, changed: Bool) -> some View {
        HStack(spacing: 8) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Spacer(minLength: 6)
            Text(value)
                .font(.caption.monospacedDigit())
                .fontWeight(changed ? .bold : .regular)
                .foregroundStyle(changed ? Color.accentColor : Color.primary)
        }
        .help(changed ? "Differs from the transaction you were shown" : "")
    }

    @ViewBuilder
    private func forecastCard(
        _ title: String,
        systemImage: String,
        @ViewBuilder _ content: () -> some View
    ) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Label(title, systemImage: systemImage)
                .font(.caption.bold())
                .foregroundStyle(.secondary)
            content()
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var footer: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(selectedRows.count) cash(es) · \(formatFch(selectedValue)) · \(selectedCd) CD")
                    .font(.callout.monospacedDigit())
                pricingLine
            }
            Spacer()
            Button("Cancel", action: onCancel)
                .keyboardShortcut(.cancelAction)
            Button("Use these") { onPick(selectedRows) }
                .buttonStyle(.borderedProminent)
                .disabled(!canUse)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    @ViewBuilder
    private var pricingLine: some View {
        switch pricing {
        case nil:
            Text("Tick the cash to spend.")
                .font(.caption)
                .foregroundStyle(.secondary)
        case .success?:
            Text(selection == currentKeys
                 ? "The wallet's choice, as you were shown it."
                 : "Rebuilt from these and shown again before signing.")
                .font(.caption)
                .foregroundStyle(.secondary)
        case .failure(let error)?:
            CopyableText(explain(error))
                .font(.caption)
                .foregroundStyle(.red)
        }
    }

    private func explain(_ error: Error) -> String {
        switch error as? CoinSelector.Failure {
        case let .insufficientFunds(needed, have)?:
            return "Short by \(formatFch(needed - have)) — tick more cash."
        case let .insufficientCoinDays(required, have)?:
            return "Destroys \(have) CoinDays; this transaction needs \(required)."
        default:
            return String(describing: error)
        }
    }

    // MARK: - actions

    private func load() {
        do {
            rows = try session.wallet.cachedSnapshot(forAddress: preview.from)?.cashes ?? []
        } catch {
            loadError = "Couldn't read the cash cache: \(error)"
        }
        // Inputs named from outside the cache (the Cash pane's Send can
        // pass rows the cache no longer has) still belong on the list.
        for input in preview.inputs where !rows.contains(where: { key($0) == key(input) }) {
            rows.append(input)
        }
        selection = currentKeys
    }

    // MARK: - bits

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    private func formatFch(_ sats: Int64) -> String {
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        let value = Double(sats) / Double(Cash.satoshisPerBch)
        return (f.string(from: NSNumber(value: value)) ?? "0") + " FCH"
    }
}
