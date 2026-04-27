import SwiftUI
import FCDomain
import FCUI

/// Recent on-chain activity for the live FID. The wallet doesn't
/// have a per-FID tx index server-side; instead we query the cash
/// index sorted by `lastHeight desc`, where each row is a cash
/// whose state most recently changed (create = income, spend =
/// outgoing). Spent cashes carry their `spend*` coordinates so
/// we can label them as outgoing.
///
/// First slice deliberately doesn't cache or paginate. We render
/// loading + error states so any wire-shape mismatch with
/// `base.search` is visible (and copyable).
struct TransactionsView: View {
    let session: ActiveSession

    @State private var rows: [Cash] = []
    @State private var loading: Bool = false
    @State private var loadError: String?
    @State private var lastFetchedAt: Date?
    @State private var loadedCacheForFid: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            header
            content
        }
        .padding()
        .frame(minWidth: 480)
        .onAppear {
            loadCacheIfNeeded()
            Task { await refresh() }
        }
    }

    /// Render the cached page (Pattern C) immediately on appear so the
    /// pane has content during the network round-trip. The fresh fetch
    /// kicked off in parallel by `onAppear` replaces these rows on
    /// success. Idempotent across re-renders for the same FID.
    private func loadCacheIfNeeded() {
        guard loadedCacheForFid != session.liveFid else { return }
        loadedCacheForFid = session.liveFid
        do {
            if let cached = try session.wallet.cachedRecentActivity(forFid: session.liveFid) {
                rows = cached.cashes
                lastFetchedAt = cached.fetchedAt
            }
        } catch {
            // Silent — the live refresh will surface its own error
            // via loadError if it fails too.
        }
    }

    private var header: some View {
        HStack {
            Text("Recent activity").font(.headline)
            Spacer()
            if let when = lastFetchedAt {
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
        }
    }

    @ViewBuilder
    private var content: some View {
        if let err = loadError {
            VStack(alignment: .leading, spacing: 8) {
                Label("Couldn't load activity", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
                CopyableText(err, font: .callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                Text("`base.search` on the cash index. Click the message above to copy it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        } else if rows.isEmpty && !loading {
            VStack(alignment: .leading, spacing: 8) {
                Label("No activity yet", systemImage: "tray")
                    .foregroundStyle(.secondary)
                Text("This FID has no on-chain cashes the server knows about. After your first received or sent tx confirms, it'll appear here.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(rows, id: \.compositeKey) { row in
                        activityRow(row)
                            .padding(.vertical, 8)
                            .padding(.horizontal, 16)
                        Divider()
                    }
                }
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    @ViewBuilder
    private func activityRow(_ cash: Cash) -> some View {
        // valid==false means spent; otherwise treat as incoming/held.
        // (We can't tell "still in wallet" vs "incoming brand-new"
        // from the cash index alone — both are valid==true; the
        // distinction is just how recently it landed.)
        let isSpent = (cash.valid ?? true) == false
        let isIncoming = !isSpent
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Image(systemName: isIncoming ? "arrow.down.left" : "arrow.up.right")
                        .foregroundStyle(isIncoming ? Color.green : Color.orange)
                    Text(isIncoming ? "Received" : "Sent")
                        .font(.callout.bold())
                        .foregroundStyle(isIncoming ? Color.green : Color.orange)
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
            VStack(alignment: .trailing, spacing: 2) {
                // For incoming, birthTime / birthHeight are when the
                // cash arrived. For outgoing (spent), lastTime /
                // lastHeight are when the cash's state last changed —
                // i.e. when it was spent.
                let when = isIncoming ? cash.birthTime : cash.lastTime
                let height = isIncoming ? cash.birthHeight : cash.lastHeight
                if let ts = when {
                    Text(Date(timeIntervalSince1970: TimeInterval(ts))
                        .formatted(date: .abbreviated, time: .shortened))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                if let h = height {
                    Text("Block \(h)")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    // MARK: - actions

    @MainActor
    private func refresh() async {
        loading = true
        loadError = nil
        defer { loading = false }
        do {
            let result = try await session.wallet.fetchRecentActivity(forFid: session.liveFid)
            self.rows = result
            self.lastFetchedAt = Date()
        } catch {
            self.loadError = String(describing: error)
        }
    }

    // MARK: - format

    private func formatBch(_ sats: Int64) -> String {
        let bch = Double(sats) / Double(Cash.satoshisPerBch)
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        return (f.string(from: NSNumber(value: bch)) ?? "0") + " FCH"
    }

}

private extension Cash {
    var compositeKey: String {
        if let id, !id.isEmpty { return id }
        return "\(birthTxId):\(birthIndex)"
    }
}
