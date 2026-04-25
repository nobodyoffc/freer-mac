import SwiftUI
import FCDomain

/// Wallet overview. Balance card + (Phase 7.2) recent activity. The
/// refresh button calls `wallet.balance(forFid:)` against the active
/// session's FAPI client; until that's wired to a real server it
/// surfaces the stub error inline.
struct OverviewView: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession

    @State private var balance: Balance?
    @State private var loading: Bool = false
    @State private var loadError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            balanceCard
            Spacer()
            comingSoon
        }
        .padding()
        .frame(minWidth: 480)
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
                Text(err)
                    .font(.callout)
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

    private var comingSoon: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Coming next").font(.caption.bold()).foregroundStyle(.secondary)
            Text("Recent activity, UTXO summary, and quick send/receive land in Phase 7.2 once the FAPI client is wired against a real server.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @MainActor
    private func refresh() async {
        loading = true
        loadError = nil
        defer { loading = false }
        do {
            let bal = try await session.wallet.balance(forFid: session.liveFid)
            self.balance = bal
        } catch {
            self.loadError = String(describing: error)
        }
    }

    private func formatBch(_ sats: Int64) -> String {
        let bch = Double(sats) / Double(Utxo.satoshisPerBch)
        let formatter = NumberFormatter()
        formatter.minimumFractionDigits = 0
        formatter.maximumFractionDigits = 8
        formatter.usesGroupingSeparator = true
        return (formatter.string(from: NSNumber(value: bch)) ?? "0") + " FCH"
    }
}
