import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Cash — the Mac port of Android's `CashActivity` (with
/// `ReorgCashActivity` as its Merge / Split sheet).
///
/// **A balance is a number; this is the money itself.** Overview says
/// how much the live FID has and Transactions says how it got there,
/// but neither shows the *bills* — the individual unspent outputs the
/// balance is made of. That matters because a wallet spends bills, not
/// amounts: one 10 F cash and ten 1 F cashes buy the same coffee at
/// very different transaction sizes, and a payment can only ever be
/// funded by whole bills. This pane is where you see them and change
/// their shape.
///
/// **Three things you can do with a selection**, all of which take the
/// ticked rows as an instruction rather than a hint:
/// - **Merge / Split** — pay yourself, changing denominations
///   (``CashReorg``). Consolidating cuts the fee of every future send;
///   splitting means a small payment need not move a large cash.
/// - **Send** — pay someone else from exactly these bills, where the
///   Send pane would have chosen for you.
/// - **Export** — the outpoints as JSON / QR, for a signer elsewhere.
///
/// **The list is the cache, not the chain.** Rows come from the same
/// ``CashSnapshot`` the wallet spends from, so what you see is what a
/// send would pick — including the local annotations the server knows
/// nothing about: a `pendingSpend` row is held back because we already
/// used it in a broadcast that hasn't confirmed, and an `.unknown` row
/// is one we minted optimistically after our own send. Both are shown,
/// both are labelled, and neither can be ticked, because a transaction
/// built on them would be rejected or double-spent.
struct CashView: View {
    let session: ActiveSession

    @State private var snapshot: CashSnapshot?
    @State private var loading = false
    @State private var loadError: String?
    @State private var banner: Banner?

    @State private var selection: Set<String> = []
    @State private var sort: SortField = .value
    @State private var ascending = false

    @State private var showReorg = false
    @State private var showSend = false
    @State private var showExport = false
    @State private var pendingPurge = false

    /// Sort keys, and which way "natural" runs for each. Android
    /// offers value and coin-days as two independent tri-state
    /// buttons; a single field + direction is the same three states
    /// without the "which one is active?" ambiguity.
    private enum SortField: String, CaseIterable, Identifiable {
        case value = "Amount"
        case cd = "CoinDays"
        case age = "Age"
        var id: String { rawValue }
    }

    private struct Banner: Identifiable {
        enum Kind { case success, failure }
        let id = UUID()
        let kind: Kind
        let text: String
        var copyValue: String?
    }

    // MARK: - derived

    private var rows: [Cash] { snapshot?.cashes ?? [] }

    /// A row can be spent only if it locks to us as plain P2PKH and
    /// isn't already committed to an unconfirmed spend. The optional
    /// `type` string is not consulted — the server populates it
    /// opportunistically, and trusting it is how a multisig output
    /// ends up in a transaction no node will accept.
    private func isSpendable(_ cash: Cash) -> Bool {
        guard !cash.pendingSpend, cash.withinUnconfirmedChainLimit else { return false }
        guard let h160 = try? FchAddress(fid: session.liveFid).hash160 else { return false }
        return cash.locksToP2PKH(hash160: h160)
    }

    private var sortedRows: [Cash] {
        rows.sorted { a, b in
            let lhs: Int64, rhs: Int64
            switch sort {
            case .value: lhs = a.value;            rhs = b.value
            case .cd:    lhs = a.cd ?? 0;          rhs = b.cd ?? 0
            case .age:   lhs = a.birthTime ?? 0;   rhs = b.birthTime ?? 0
            }
            if lhs == rhs { return key(a) < key(b) }   // stable tiebreak
            return ascending ? lhs < rhs : lhs > rhs
        }
    }

    private var selectedRows: [Cash] {
        // Take them in the order shown, so the transaction's inputs
        // match the list the user was looking at.
        sortedRows.filter { selection.contains(key($0)) }
    }

    private var selectedValue: Int64 { selectedRows.reduce(0) { $0 + $1.value } }
    private var selectedCd: Int64 { selectedRows.reduce(0) { $0 + ($1.cd ?? 0) } }
    private var spendableRows: [Cash] { sortedRows.filter(isSpendable) }

    private func key(_ cash: Cash) -> String {
        if let id = cash.id, !id.isEmpty { return id }
        return "\(cash.birthTxId):\(cash.birthIndex)"
    }

    // MARK: - body

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            toolbar
            if let banner { bannerView(banner) }
            summaryBar
            content
        }
        .padding()
        .frame(minWidth: 620)
        .onAppear {
            loadCache()
            Task { await refresh() }
        }
        .sheet(isPresented: $showReorg) {
            CashReorgSheet(session: session, inputs: selectedRows) { outcome in
                showReorg = false
                handle(outcome)
            }
        }
        .sheet(isPresented: $showSend) {
            CashSendSheet(session: session, inputs: selectedRows) { outcome in
                showSend = false
                handle(outcome)
            }
        }
        .sheet(isPresented: $showExport) {
            QrDisplaySheet(title: "Export cash", content: exportJson) { showExport = false }
        }
        .alert("Rebuild the cash list from the server?", isPresented: $pendingPurge) {
            Button("Cancel", role: .cancel) {}
            Button("Rebuild", role: .destructive) { Task { await rebuild() } }
        } message: {
            Text("""
            The local list is dropped and fetched again from scratch.

            Nothing on chain changes, but local annotations are lost with it: any cash you are holding back as “spending” goes back to being spendable, so do this only when the list itself looks wrong.
            """)
        }
    }

    // MARK: - toolbar

    private var toolbar: some View {
        HStack(spacing: 12) {
            Picker("", selection: $sort) {
                ForEach(SortField.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 260)

            Button {
                ascending.toggle()
            } label: {
                Image(systemName: ascending ? "arrow.up" : "arrow.down")
            }
            .help(ascending ? "Smallest first" : "Largest first")

            Spacer()

            if let when = snapshot?.snapshotAt {
                Text("Updated \(when.formatted(.relative(presentation: .named)))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Button {
                Task { await refresh() }
            } label: {
                if loading {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
            .disabled(loading)

            Menu {
                Button("Export selected…") { showExport = true }
                    .disabled(selection.isEmpty)
                Divider()
                Button("Rebuild from server…", role: .destructive) { pendingPurge = true }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help("Export the selected cashes, or rebuild the list from scratch")
        }
    }

    // MARK: - summary

    /// What is ticked, and what can be done with it. Android puts the
    /// same three totals in a card above the list; the difference is
    /// that here the actions sit next to the numbers they act on
    /// rather than in a bottom button bar.
    private var summaryBar: some View {
        HStack(spacing: 14) {
            Toggle(isOn: Binding(
                get: { !spendableRows.isEmpty && selection.count == spendableRows.count },
                set: { on in
                    selection = on ? Set(spendableRows.map(key)) : []
                }
            )) {
                Text("All")
            }
            .toggleStyle(.checkbox)
            .disabled(spendableRows.isEmpty)
            .help("Select every spendable cash")

            statistic("Selected", "\(selection.count) of \(rows.count)")
            statistic("Amount", formatFch(selectedValue))
            statistic("CoinDays", formatLargeNumber(selectedCd))
                .help("\(formatExactNumber(selectedCd)) CoinDays in the ticked cashes")

            Spacer()

            Button {
                showSend = true
            } label: {
                Label("Send…", systemImage: "paperplane")
            }
            .disabled(selection.isEmpty)
            .help("Pay someone using exactly these cashes")

            Button {
                showReorg = true
            } label: {
                Label("Merge / Split…", systemImage: "arrow.triangle.merge")
            }
            .buttonStyle(.borderedProminent)
            .disabled(selection.isEmpty)
            .help("Pay yourself, reshaping these cashes into different denominations")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private func statistic(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.callout.monospacedDigit().bold())
        }
    }

    // MARK: - list

    @ViewBuilder
    private var content: some View {
        if let loadError {
            card {
                Label("Couldn't load cashes", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
                CopyableText(loadError, font: .callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        } else if rows.isEmpty && !loading {
            card {
                Label("No cash yet", systemImage: "banknote")
                    .foregroundStyle(.secondary)
                Text("This FID owns no unspent outputs the server knows about. Once someone pays it — or you receive change from your own send — the individual cashes appear here.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(sortedRows, id: \.self) { cash in
                        row(cash)
                            .padding(.vertical, 9)
                            .padding(.horizontal, 14)
                        Divider()
                    }
                    footer
                }
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    @ViewBuilder
    private func row(_ cash: Cash) -> some View {
        let id = key(cash)
        let spendable = isSpendable(cash)

        HStack(alignment: .center, spacing: 12) {
            Toggle(isOn: Binding(
                get: { selection.contains(id) },
                set: { on in
                    if on { selection.insert(id) } else { selection.remove(id) }
                }
            )) { EmptyView() }
                .toggleStyle(.checkbox)
                .labelsHidden()
                .disabled(!spendable)
                .help(spendable ? "" : "This cash can't be spent from here")

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(formatFch(cash.value))
                        .font(.body.monospacedDigit().bold())
                    ForEach(badges(for: cash), id: \.text) { badge in
                        chip(badge.text, color: badge.color).help(badge.help)
                    }
                }
                CopyableText(
                    display: "\(cash.birthTxId.elidingMiddle(head: 10, tail: 8)):\(cash.birthIndex)",
                    copy: "\(cash.birthTxId):\(cash.birthIndex)",
                    font: .system(.caption, design: .monospaced)
                )
                .foregroundStyle(.secondary)
            }

            Spacer(minLength: 8)

            cdColumn(cash)

            VStack(alignment: .trailing, spacing: 2) {
                if let ts = cash.birthTime, ts > 0 {
                    Text(Date(timeIntervalSince1970: TimeInterval(ts))
                        .formatted(date: .abbreviated, time: .shortened))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                if let h = cash.birthHeight, h > 0 {
                    Text("Block \(h)")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .contentShape(Rectangle())
        .contextMenu {
            Button("Copy outpoint") {
                copy("\(cash.birthTxId):\(cash.birthIndex)")
            }
            if let cid = cash.id, !cid.isEmpty {
                Button("Copy cash id") { copy(cid) }
            }
            if cash.pendingSpend, let cid = cash.id, !cid.isEmpty {
                Divider()
                Button("Recover — the spend never confirmed") { recover(cashId: cid) }
            }
        }
    }

    /// CoinDays, carrying the same weight as the amount rather than
    /// trailing it as a footnote. A cash is two quantities at once:
    /// what it pays, and what it can *say* — carving a FEIP record
    /// spends CD, and unlike value, CD can't be got back by reshaping
    /// the bills. So it has to be legible before a Merge / Split, not
    /// discovered afterwards.
    ///
    /// Nil means the server didn't report it (an optimistically minted
    /// cash, typically); that's shown as an em-dash rather than a zero,
    /// because "not told" and "none" would lead to different decisions.
    @ViewBuilder
    private func cdColumn(_ cash: Cash) -> some View {
        VStack(alignment: .trailing, spacing: 0) {
            Text(cash.cd.map(formatLargeNumber) ?? "—")
                .font(.body.monospacedDigit().bold())
                .foregroundStyle((cash.cd ?? 0) > 0 ? Color.primary : Color.secondary)
            Text("CD")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(minWidth: 62, alignment: .trailing)
        .help(cdHelp(cash))
    }

    private func cdHelp(_ cash: Cash) -> String {
        guard let cd = cash.cd else {
            return "CoinDays unknown — the server hasn't reported this cash yet."
        }
        return "\(formatExactNumber(cd)) CoinDays — value × days held. "
             + "Carving a FEIP record destroys some, and merging resets the clock on what's merged."
    }

    private struct Badge {
        let text: String
        let color: Color
        let help: String
    }

    /// Why a row may not be tickable. Each of these is a *local* fact
    /// the server's copy of the cash doesn't carry, which is exactly
    /// why they have to be shown: from the chain's point of view all
    /// three rows look identical.
    private func badges(for cash: Cash) -> [Badge] {
        var out: [Badge] = []
        if cash.pendingSpend {
            out.append(Badge(
                text: "Spending",
                color: .orange,
                help: "Already an input of a transaction we broadcast but haven't seen confirmed. Right-click to recover it if that transaction never lands."
            ))
        }
        if cash.localState == .unknown || cash.unconfirmedDepth > 0 {
            let depth = max(cash.unconfirmedDepth, 1)
            let atLimit = !cash.withinUnconfirmedChainLimit
            out.append(Badge(
                text: atLimit ? "Chain limit \(depth)/\(Cash.maxUnconfirmedChain)"
                              : "Unconfirmed ×\(depth)",
                color: atLimit ? .red : .blue,
                help: atLimit
                    ? "This cash is \(depth) unconfirmed spends deep. The network carries at most \(Cash.maxUnconfirmedChain) links in a mempool chain, so it can't be spent again until a block confirms the ones ahead of it."
                    : "Minted by one of your own transactions that hasn't confirmed yet, \(depth) link(s) behind the last block. It can be spent right now — up to \(Cash.maxUnconfirmedChain) links — but if the transaction that made it is ever dropped, this goes with it."
            ))
        }
        if !cash.pendingSpend && cash.withinUnconfirmedChainLimit && !isSpendable(cash) {
            out.append(Badge(
                text: "Not spendable here",
                color: .gray,
                help: "This output doesn't pay the live FID as plain P2PKH — CLTV and multisig signing aren't wired up yet, so it can be seen but not spent."
            ))
        }
        return out
    }

    /// Android prints "above / local / on-chain" counts under the
    /// list. Only two of those three are honest here: the pane shows
    /// the whole cache, so "above" and "local" are the same number,
    /// and the chain total is whatever the last sync saw.
    private var footer: some View {
        let heldBack = rows.filter(\.pendingSpend)
        return HStack(spacing: 14) {
            Text("\(spendableRows.count) spendable · \(formatFch(spendableRows.reduce(0) { $0 + $1.value }))")
            if !heldBack.isEmpty {
                // Spent-but-unconfirmed cashes are out of the
                // spendable set already; they are still listed because
                // Recover needs something to act on, and a total that
                // silently included them would overstate the wallet.
                Text("\(heldBack.count) held back by a broadcast in flight")
                    .foregroundStyle(.orange)
            }
            if let h = snapshot?.bestHeight {
                Text("synced through block \(h)")
            }
            Spacer()
        }
        .font(.caption)
        .foregroundStyle(.tertiary)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private func bannerView(_ banner: Banner) -> some View {
        HStack(spacing: 6) {
            Image(systemName: banner.kind == .success ? "checkmark.seal" : "exclamationmark.triangle")
            if let copyValue = banner.copyValue {
                CopyableText(display: banner.text, copy: copyValue, font: .caption)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                CopyableText(banner.text, font: .caption)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            Button { self.banner = nil } label: { Image(systemName: "xmark.circle.fill") }
                .buttonStyle(.borderless)
        }
        .foregroundStyle(banner.kind == .success ? Color.green : Color.orange)
    }

    private func card(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8, content: content)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    // MARK: - actions

    private func loadCache() {
        do {
            snapshot = try session.wallet.cachedSnapshot(forAddress: session.liveFid)
        } catch {
            // Silent — the live refresh surfaces its own error.
        }
    }

    @MainActor
    private func refresh() async {
        loading = true
        loadError = nil
        defer { loading = false }
        do {
            snapshot = try await session.wallet.refreshCashes(forFid: session.liveFid)
            pruneSelection()
        } catch {
            loadError = describe(error)
        }
    }

    @MainActor
    private func rebuild() async {
        loading = true
        loadError = nil
        defer { loading = false }
        do {
            try session.wallet.purgeCashes(forFid: session.liveFid)
            snapshot = try await session.wallet.refreshCashes(forFid: session.liveFid)
            selection = []
            banner = Banner(kind: .success, text: "Rebuilt: \(rows.count) cash(es) from the server.")
        } catch {
            loadError = describe(error)
        }
    }

    private func recover(cashId: String) {
        do {
            let changed = try session.wallet.recoverPendingSpend(
                cashId: cashId, forFid: session.liveFid
            )
            if changed {
                loadCache()
                banner = Banner(kind: .success, text: "Recovered — the cash is selectable again.")
            }
        } catch {
            banner = Banner(kind: .failure, text: describe(error))
        }
    }

    /// A refresh can retire rows that were ticked (someone else spent
    /// them, or our own send confirmed). Leaving their keys in the set
    /// would let a later action build a plan around cashes that no
    /// longer exist.
    private func pruneSelection() {
        let live = Set(rows.filter(isSpendable).map(key))
        selection.formIntersection(live)
    }

    private func handle(_ outcome: CashActionOutcome) {
        switch outcome {
        case .cancelled:
            break
        case let .broadcast(txid, note):
            selection = []
            banner = Banner(kind: .success, text: note, copyValue: txid)
            loadCache()
            Task { await refresh() }
        case .exported:
            banner = Banner(kind: .success, text: "Unsigned transaction built — sign it where the key lives.")
        }
    }

    /// Android's Export: the four fields a signer actually needs from
    /// each cash, one JSON object per line. Deliberately not the full
    /// ``Cash`` — `localState` and `pendingSpend` are this Mac's
    /// bookkeeping and mean nothing to anyone else.
    private var exportJson: String {
        selectedRows.map { cash in
            let obj: [String: Any] = [
                "owner": cash.owner,
                "birthTxId": cash.birthTxId,
                "birthIndex": cash.birthIndex,
                "value": cash.value,
                "birthTime": cash.birthTime ?? 0
            ]
            let data = (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]))
                ?? Data("{}".utf8)
            return String(decoding: data, as: UTF8.self)
        }
        .joined(separator: "\n")
    }

    private func copy(_ text: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
    }

    private func describe(_ error: Error) -> String {
        if let e = error as? WalletService.Failure { return e.description }
        if let e = error as? CashReorg.Failure { return e.description }
        if let e = error as? CoinSelector.Failure { return e.description }
        return String(describing: error)
    }

    // MARK: - format

    private func formatFch(_ sats: Int64) -> String {
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        let value = Double(sats) / Double(Cash.satoshisPerBch)
        return (f.string(from: NSNumber(value: value)) ?? "0") + " FCH"
    }

    /// The unabbreviated figure, for tooltips where the exact digit is
    /// the point.
    private func formatExactNumber(_ n: Int64) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? String(n)
    }

    /// Android's `formatLargeNumber` — CoinDays run to the billions
    /// and the exact digit is never what anyone is reading for.
    private func formatLargeNumber(_ n: Int64) -> String {
        switch n {
        case 1_000_000_000...: return String(format: "%.1fb", Double(n) / 1_000_000_000)
        case 1_000_000...:     return String(format: "%.1fm", Double(n) / 1_000_000)
        case 1_000...:         return String(format: "%.1fk", Double(n) / 1_000)
        default:               return String(n)
        }
    }
}

/// What a Cash action sheet reports back. `.broadcast` carries the
/// txid so the pane can offer it for copying; `.exported` means an
/// unsigned document was produced and nothing was sent.
enum CashActionOutcome {
    case cancelled
    case broadcast(txid: String, note: String)
    case exported
}
