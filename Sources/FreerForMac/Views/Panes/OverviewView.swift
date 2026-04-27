import SwiftUI
import FCDomain
import FCUI

/// Wallet overview. Balance card + a "pending" section that shows any
/// locally-marked cashes (post-broadcast, pre-confirmation): change
/// cashes the wallet just minted and inputs the wallet just spent. The
/// recover button on a `pendingSpend` row un-marks it so the cash is
/// selectable again — used when a Send tx never confirms.
struct OverviewView: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession

    @State private var balance: Balance?
    @State private var loading: Bool = false
    @State private var loadError: String?

    @State private var pendingCashes: [Cash] = []
    @State private var recoverError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            balanceCard
            if !pendingCashes.isEmpty {
                pendingCard
            }
            Spacer()
            comingSoon
        }
        .padding()
        .frame(minWidth: 480)
        .onAppear {
            reloadPending()
            // Kick a fresh balance + cash sync every time the user
            // navigates to Overview. Without this the pane shows
            // whatever the previous in-pane Refresh produced, which
            // goes stale after a Send. base.balanceByIds is cheap;
            // hitting it on every appear is fine.
            Task { await refresh() }
        }
    }

    private var balanceCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Balance")
                    .font(.headline)
                Spacer()
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
            }

            if let bal = balance {
                Text(formatBch(bal.satoshis))
                    .font(.system(size: 38, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                Text("\(bal.satoshis) sat")
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                if let h = bal.bestHeight {
                    Text("Block \(h)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text("Updated \(bal.fetchedAt.formatted(.relative(presentation: .named)))")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            } else if let err = loadError {
                Text("—")
                    .font(.system(size: 38, weight: .semibold, design: .rounded))
                    .foregroundStyle(.secondary)
                CopyableText(err, font: .callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("—")
                    .font(.system(size: 38, weight: .semibold, design: .rounded))
                    .foregroundStyle(.secondary)
                Text("Tap Refresh to load.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var pendingCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "clock.badge.exclamationmark")
                Text("Pending").font(.headline)
                Spacer()
                Text("\(pendingCashes.count)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Text("Cashes affected by a Send that hasn't been confirmed by the chain. The next Refresh after the tx confirms will reconcile them; if the tx never confirms, use Recover on a spent input to put it back in play.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(pendingCashes, id: \.compositeKey) { cash in
                pendingRow(cash)
                    .padding(.vertical, 4)
            }

            if let err = recoverError {
                CopyableText(err, font: .caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    @ViewBuilder
    private func pendingRow(_ cash: Cash) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if cash.pendingSpend {
                        Label("Spending", systemImage: "arrow.up.forward")
                            .font(.caption.bold())
                            .foregroundStyle(.orange)
                    } else {
                        Label("Awaiting confirmation", systemImage: "arrow.down.circle")
                            .font(.caption.bold())
                            .foregroundStyle(.blue)
                    }
                    Text(formatBch(cash.value))
                        .font(.callout.monospacedDigit())
                }
                CopyableText(
                    display: "\(cash.birthTxId.prefix(12))…:\(cash.birthIndex)",
                    copy: "\(cash.birthTxId):\(cash.birthIndex)",
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
            Spacer()
            if cash.pendingSpend, let id = cash.id {
                Button("Recover") {
                    recover(cashId: id)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .help("Un-mark this cash as spent. The cash becomes spendable again — use only if the broadcast tx is definitely not going to confirm.")
            }
        }
    }

    private var comingSoon: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Coming next").font(.caption.bold()).foregroundStyle(.secondary)
            Text("Tx history, recent activity, and per-cash detail land in Phase 7.5.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - actions

    @MainActor
    private func refresh() async {
        loading = true
        loadError = nil
        defer { loading = false }
        do {
            let bal = try await session.wallet.balance(forFid: session.liveFid)
            self.balance = bal
            // Cache might have moved — also kick a cash sync so the
            // pending section reflects what just confirmed.
            _ = try? await session.wallet.refreshCashes(forFid: session.liveFid)
            reloadPending()
        } catch {
            self.loadError = String(describing: error)
        }
    }

    private func reloadPending() {
        do {
            let snap = try session.cashes.snapshot(forAddress: session.liveFid)
            // Show anything in a non-confirmed local state. The
            // .unknown rows are change cashes the wallet just minted;
            // pendingSpend rows are inputs the wallet just spent.
            pendingCashes = (snap?.cashes ?? []).filter {
                $0.pendingSpend || $0.localState != .onchain
            }
        } catch {
            pendingCashes = []
        }
    }

    private func recover(cashId: String) {
        recoverError = nil
        do {
            _ = try session.wallet.recoverPendingSpend(
                cashId: cashId, forFid: session.liveFid
            )
            reloadPending()
        } catch {
            recoverError = String(describing: error)
        }
    }

    // MARK: - format

    private func formatBch(_ sats: Int64) -> String {
        let bch = Double(sats) / Double(Cash.satoshisPerBch)
        let formatter = NumberFormatter()
        formatter.minimumFractionDigits = 0
        formatter.maximumFractionDigits = 8
        formatter.usesGroupingSeparator = true
        return (formatter.string(from: NSNumber(value: bch)) ?? "0") + " FCH"
    }
}

private extension Cash {
    /// Stable key for SwiftUI list iteration. Prefers the cash id;
    /// falls back to (birthTxId, birthIndex) for any row whose id is
    /// missing (server omission for very old cashes).
    var compositeKey: String {
        if let id, !id.isEmpty { return id }
        return "\(birthTxId):\(birthIndex)"
    }
}
