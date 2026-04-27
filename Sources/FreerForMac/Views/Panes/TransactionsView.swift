import SwiftUI
import FCDomain
import FCUI

/// Recent on-chain activity for the live FID. The wallet doesn't have
/// a per-FID tx index server-side; we derive the feed from the cash
/// index and group cashes by their event tx so a single Send (one or
/// more spent inputs + a change output) collapses into a single row.
///
/// Cache-first render: the previous fetch's results show instantly on
/// appear, then a fresh `base.search` runs in the background and
/// replaces the rows on success.
struct TransactionsView: View {
    let session: ActiveSession

    @State private var rows: [Cash] = []
    @State private var loading: Bool = false
    @State private var loadingMore: Bool = false
    @State private var loadError: String?
    @State private var lastFetchedAt: Date?
    @State private var loadedCacheForFid: String?
    @State private var expanded: Set<String> = []
    @State private var nextCursor: [String]?

    private var groups: [TxGroup] { TxGroup.group(rows) }

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

    private func loadCacheIfNeeded() {
        guard loadedCacheForFid != session.liveFid else { return }
        loadedCacheForFid = session.liveFid
        do {
            if let cached = try session.wallet.cachedRecentActivity(forFid: session.liveFid) {
                rows = cached.cashes
                lastFetchedAt = cached.fetchedAt
            }
        } catch {
            // Silent — live refresh will surface its own error.
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
            errorCard(err)
        } else if groups.isEmpty && !loading {
            emptyCard
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(groups, id: \.txid) { group in
                        groupRow(group)
                            .padding(.vertical, 10)
                            .padding(.horizontal, 16)
                            .contentShape(Rectangle())
                            .onTapGesture { toggleExpanded(group.txid) }
                        if expanded.contains(group.txid) {
                            groupDetail(group)
                                .padding(.bottom, 10)
                                .padding(.horizontal, 16)
                        }
                        Divider()
                    }
                    if nextCursor != nil {
                        loadMoreFooter
                    }
                }
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    private var loadMoreFooter: some View {
        HStack {
            Spacer()
            Button {
                Task { await loadMore() }
            } label: {
                if loadingMore {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Loading…")
                    }
                } else {
                    Label("Load more", systemImage: "ellipsis.circle")
                }
            }
            .buttonStyle(.borderless)
            .disabled(loadingMore)
            Spacer()
        }
        .padding(.vertical, 14)
    }

    private func errorCard(_ err: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Couldn't load activity", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.red)
            CopyableText(err, font: .callout)
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var emptyCard: some View {
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
    }

    @ViewBuilder
    private func groupRow(_ group: TxGroup) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Image(systemName: glyph(group.role))
                        .foregroundStyle(color(group.role))
                    Text(label(group.role))
                        .font(.callout.bold())
                        .foregroundStyle(color(group.role))
                    Text(formatNet(group.netSats))
                        .font(.callout.monospacedDigit())
                }
                CopyableText(
                    display: "\(group.txid.prefix(12))…",
                    copy: group.txid,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                if let ts = group.time {
                    Text(Date(timeIntervalSince1970: TimeInterval(ts))
                        .formatted(date: .abbreviated, time: .shortened))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                if let h = group.height {
                    Text("Block \(h)")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.tertiary)
                } else {
                    Text("Pending")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
                Image(systemName: expanded.contains(group.txid) ? "chevron.up" : "chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    @ViewBuilder
    private func groupDetail(_ group: TxGroup) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            if !group.incoming.isEmpty {
                Text("Received \(group.incoming.count) cash(es)")
                    .font(.caption.bold())
                    .foregroundStyle(.green)
                ForEach(group.incoming, id: \.compositeKey) { cash in
                    detailLine("+", cash.value, txid: cash.birthTxId, index: cash.birthIndex)
                }
            }
            if !group.outgoing.isEmpty {
                Text("Spent \(group.outgoing.count) cash(es)")
                    .font(.caption.bold())
                    .foregroundStyle(.orange)
                ForEach(group.outgoing, id: \.compositeKey) { cash in
                    detailLine("−", cash.value, txid: cash.birthTxId, index: cash.birthIndex)
                }
            }
        }
        .padding(.leading, 4)
    }

    @ViewBuilder
    private func detailLine(_ sign: String, _ sats: Int64, txid: String, index: Int) -> some View {
        HStack(spacing: 8) {
            Text("\(sign)\(formatBch(sats))")
                .font(.caption.monospacedDigit())
            CopyableText(
                display: "\(txid.prefix(10))…:\(index)",
                copy: "\(txid):\(index)",
                font: .caption.monospaced()
            )
            .foregroundStyle(.tertiary)
        }
    }

    private func toggleExpanded(_ txid: String) {
        if expanded.contains(txid) { expanded.remove(txid) } else { expanded.insert(txid) }
    }

    // MARK: - actions

    @MainActor
    private func refresh() async {
        loading = true
        loadError = nil
        defer { loading = false }
        do {
            // First page: replace rows + reset cursor.
            let page = try await session.wallet.fetchRecentActivity(
                forFid: session.liveFid
            )
            self.rows = page.cashes
            self.nextCursor = page.next
            self.lastFetchedAt = Date()
        } catch {
            self.loadError = String(describing: error)
        }
    }

    @MainActor
    private func loadMore() async {
        guard let cursor = nextCursor, !loadingMore else { return }
        loadingMore = true
        defer { loadingMore = false }
        do {
            let page = try await session.wallet.fetchRecentActivity(
                forFid: session.liveFid, after: cursor
            )
            // Append, dedupe by composite key. Server may include
            // boundary rows from the previous page on rare timing
            // edges; stripping duplicates keeps the UI stable.
            var seen = Set(rows.map(\.compositeKey))
            for cash in page.cashes where seen.insert(cash.compositeKey).inserted {
                rows.append(cash)
            }
            nextCursor = page.next
        } catch {
            // Surface the error inline; rows already-loaded stay.
            loadError = String(describing: error)
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

    private func formatNet(_ sats: Int64) -> String {
        let sign = sats > 0 ? "+" : (sats < 0 ? "−" : "")
        let abs = sats.magnitude
        return "\(sign)\(formatBch(Int64(abs)))"
    }

    private func glyph(_ role: TxGroup.Role) -> String {
        switch role {
        case .received: return "arrow.down.left"
        case .sent:     return "arrow.up.right"
        case .mixed:    return "arrow.left.arrow.right"
        }
    }

    private func color(_ role: TxGroup.Role) -> Color {
        switch role {
        case .received: return .green
        case .sent:     return .orange
        case .mixed:    return .blue
        }
    }

    private func label(_ role: TxGroup.Role) -> String {
        switch role {
        case .received: return "Received"
        case .sent:     return "Sent"
        case .mixed:    return "Self / change"
        }
    }
}

private extension Cash {
    var compositeKey: String {
        if let id, !id.isEmpty { return id }
        return "\(birthTxId):\(birthIndex)"
    }
}
