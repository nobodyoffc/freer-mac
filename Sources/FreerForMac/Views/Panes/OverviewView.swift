import SwiftUI
import FCDomain
import FCUI

/// The landing pane: what happened while you were away, and what still
/// needs you.
///
/// **The balance used to live here.** It moved into ``PaneHeader``,
/// where it is visible from every pane instead of only this one, and it
/// arrives with the rest of the FID's on-chain stats in a single
/// `base.freerByIds` call. That left this pane free to answer the
/// question a landing screen should answer — *what is waiting for me* —
/// which is Android's home grid of badge counts, rearranged for a window
/// that has a sidebar doing the navigating.
///
/// Four sections, in the order you would want them:
///
///   - **Attention.** Unread counts per surface, each hiding at zero and
///     each a link into the pane that owns it. All read from local
///     stores, so this paints instantly and is correct offline.
///   - **Pending.** Cashes a broadcast Send has touched but the chain has
///     not confirmed. The recover button on a `pendingSpend` row un-marks
///     it so the cash is selectable again — used when a Send never
///     confirms.
///   - **Recent activity.** The last few transactions, grouped per txid
///     so one Send is one row rather than an input and a change output.
///   - **Latest news.** The head of the chain-wide feed.
///
/// Every section is cache-first: it paints from the per-identity store
/// and *then* refreshes. A landing pane that blocks on the network is a
/// landing pane that feels broken every time the server is slow.
struct OverviewView: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession

    @State private var loading: Bool = false
    @State private var loadError: String?

    @State private var pendingCashes: [Cash] = []
    @State private var recoverError: String?

    @State private var unreadMail = 0
    @State private var unreadChat: [ImType: Int] = [:]

    @State private var recentGroups: [TxGroup] = []
    @State private var latestNews: [News] = []

    /// How many rows each feed section shows. Enough to be a glance,
    /// few enough that the pane stays a summary rather than becoming a
    /// second copy of the pane it links to.
    private static let feedRows = 5

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    attentionCard
                    if appState.liveFidIsBroke { firstFchCard }
                    if !pendingCashes.isEmpty {
                        pendingCard
                    }
                    recentActivityCard
                    newsCard
                }
                .padding(.bottom, 8)
            }
        }
        .padding()
        .frame(minWidth: 480)
        .onAppear {
            reloadLocal()
            // Re-sync the cash index every time the user lands here, so
            // a Send that has since confirmed drops off the pending list
            // rather than sitting there looking stuck — and top up the
            // two feeds while we are at it.
            Task { await refresh() }
        }
        // A background collect that filed a message changes the unread
        // counts under us. They come from local stores, so re-reading is
        // cheap enough to do on every revision.
        .onChange(of: appState.inboxRevision) { _, _ in
            reloadUnread()
        }
    }

    private var firstFchCard: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "hand.raised")
                .font(.title3)
                .foregroundStyle(.teal)
            VStack(alignment: .leading, spacing: 4) {
                Text("This FID holds no coins").font(.headline)
                Text("""
                    Every carve, name and message costs a fee, so an empty FID cannot do much. \
                    Ask on the public First FCH board, or have somebody send coins straight to \
                    your address.
                    """)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    Button("Open the First FCH board") {
                        appState.selectedPane = .firstFch
                    }
                    CopyableText.elidingMiddle(session.liveFid, font: .callout.monospaced())
                }
                .padding(.top, 2)
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.teal.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var pendingCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "clock.badge.exclamationmark")
                Text("Pending").font(.headline)
                Text("\(pendingCashes.count)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
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
            Text("Cashes affected by a Send that hasn't been confirmed by the chain. The next Refresh after the tx confirms will reconcile them; if the tx never confirms, use Recover on a spent input to put it back in play.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(pendingCashes, id: \.compositeKey) { cash in
                pendingRow(cash)
                    .padding(.vertical, 4)
            }

            if let err = loadError {
                CopyableText(err, font: .caption, color: .red)
                    .fixedSize(horizontal: false, vertical: true)
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
                    display: "\(cash.birthTxId.elidingMiddle()):\(cash.birthIndex)",
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

    // MARK: - attention

    /// Android puts these as badges on the home grid's icons. A Mac
    /// window has a sidebar doing the navigating, so they become a row
    /// of tiles here — same counts, same click-through, one screen.
    private var attentionCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Needs attention").font(.headline)

            if attentionTiles.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle")
                        .foregroundStyle(.green)
                    Text("Nothing unread. You are all caught up.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } else {
                // Wraps instead of scrolling: five tiles at a narrow
                // window width would otherwise hide the last two behind
                // a scroll gesture nobody knows is there.
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 150), spacing: 10)],
                    alignment: .leading,
                    spacing: 10
                ) {
                    ForEach(attentionTiles) { tile in
                        attentionTile(tile)
                    }
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    /// One unread surface worth showing. Built rather than hard-coded so
    /// the zero-hiding rule lives in exactly one place.
    private struct AttentionTile: Identifiable {
        let id: String
        let title: String
        let count: Int
        let systemImage: String
        let tint: Color
        let open: () -> Void
    }

    private var attentionTiles: [AttentionTile] {
        var tiles: [AttentionTile] = []
        if unreadMail > 0 {
            tiles.append(AttentionTile(
                id: "mail", title: "Mail", count: unreadMail,
                systemImage: "envelope.fill", tint: .accentColor,
                open: { appState.selectedPane = .mail }
            ))
        }
        // Somebody is asking for their first FCH, and this identity
        // asked to be told. Off by default, so this tile only appears
        // for a helper who opted in — see ``FirstFchBoardView``.
        if appState.newcomersWaiting > 0 {
            tiles.append(AttentionTile(
                id: "firstFch", title: "First FCH", count: appState.newcomersWaiting,
                systemImage: "hand.raised.fill", tint: .teal,
                open: { appState.selectedPane = .firstFch }
            ))
        }
        // Chat flavours keep the colour, word and icon they have
        // everywhere else — ChatModeStyle is the single table those come
        // from, and a square being red here and red there is the whole
        // point of it.
        for style in ChatModeStyle.all {
            let count = unreadChat[style.mode] ?? 0
            guard count > 0 else { continue }
            tiles.append(AttentionTile(
                id: style.id, title: style.title, count: count,
                systemImage: style.systemImage, tint: style.tint,
                open: { appState.openChat(mode: style.mode) }
            ))
        }
        return tiles
    }

    private func attentionTile(_ tile: AttentionTile) -> some View {
        Button(action: tile.open) {
            HStack(spacing: 10) {
                Image(systemName: tile.systemImage)
                    .font(.title3)
                    .foregroundStyle(tile.tint)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 1) {
                    Text("\(tile.count)")
                        .font(.title3.bold())
                        .monospacedDigit()
                    Text(tile.title)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 8)
            .padding(.horizontal, 12)
            .background(tile.tint.opacity(0.10))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
        .contentShape(Rectangle())
        .help("Open \(tile.title) — \(tile.count) unread")
    }

    // MARK: - recent activity

    private var recentActivityCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader(
                "Recent activity",
                systemImage: "arrow.left.arrow.right",
                open: .transactions
            )

            if recentGroups.isEmpty {
                emptyNote("No transactions yet for this FID.")
            } else {
                ForEach(recentGroups.prefix(Self.feedRows), id: \.txid) { group in
                    activityRow(group)
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func activityRow(_ group: TxGroup) -> some View {
        HStack(spacing: 10) {
            Image(systemName: group.netSats >= 0 ? "arrow.down.circle.fill" : "arrow.up.forward.circle.fill")
                .foregroundStyle(group.netSats >= 0 ? Color.green : Color.orange)

            Text(signedBch(group.netSats))
                .font(.callout.monospacedDigit())

            CopyableText.elidingMiddle(
                group.txid, head: 6, tail: 6,
                font: .caption.monospaced(),
                color: .secondary
            )

            Spacer(minLength: 8)

            if let t = group.time {
                Text(Date(timeIntervalSince1970: TimeInterval(t))
                        .formatted(.relative(presentation: .named)))
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            } else {
                Text("unconfirmed")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    // MARK: - news

    private var newsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("Latest news", systemImage: "dot.radiowaves.left.and.right", open: .news)

            if latestNews.isEmpty {
                emptyNote("The chain-wide feed hasn't loaded yet.")
            } else {
                ForEach(Array(latestNews.prefix(Self.feedRows).enumerated()), id: \.offset) { _, item in
                    newsRow(item)
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func newsRow(_ item: News) -> some View {
        HStack(spacing: 10) {
            FidAvatarView(fid: item.doer ?? "", size: 24)

            if let act = item.act, !act.isEmpty {
                Text(act)
                    .font(.caption2.bold())
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(Color.orange.opacity(0.15))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
            }

            Text(item.objectName
                 ?? item.objectId?.elidingMiddle(head: 6, tail: 6)
                 ?? "—")
                .font(.callout)
                .lineLimit(1)
                .truncationMode(.middle)

            Spacer(minLength: 8)

            if let t = item.time {
                Text(Date(timeIntervalSince1970: TimeInterval(t))
                        .formatted(.relative(presentation: .named)))
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    // MARK: - section chrome

    private func sectionHeader(
        _ title: String,
        systemImage: String,
        open pane: WalletPane
    ) -> some View {
        HStack(spacing: 8) {
            Image(systemName: systemImage)
            Text(title).font(.headline)
            Spacer()
            Button("See all") { appState.selectedPane = pane }
                .buttonStyle(.link)
                .font(.caption)
        }
    }

    private func emptyNote(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    // MARK: - actions

    /// Everything that can be answered from disk. Runs before any
    /// network call so the pane is never blank while the server thinks.
    private func reloadLocal() {
        reloadPending()
        reloadUnread()
        reloadRecentActivity()
        reloadNews()
    }

    private func reloadUnread() {
        unreadMail = (try? session.mails.unreadCount()) ?? 0
        var byType: [ImType: Int] = [:]
        for style in ChatModeStyle.all {
            byType[style.mode] = (try? session.conversations.unread(type: style.mode)) ?? 0
        }
        unreadChat = byType
    }

    private func reloadRecentActivity() {
        let cashes = (try? session.wallet.cachedRecentActivity(forFid: session.liveFid))?.cashes ?? []
        recentGroups = TxGroup.group(cashes)
    }

    private func reloadNews() {
        latestNews = (try? session.newsCache.load())?.news ?? []
    }

    @MainActor
    private func refresh() async {
        loading = true
        loadError = nil
        defer { loading = false }

        // The cash sync is the one that can fail loudly: it is what the
        // pending list is built from, and a stale pending row is a user
        // wondering whether their money moved.
        do {
            _ = try await session.wallet.refreshCashes(forFid: session.liveFid)
            reloadPending()
        } catch {
            self.loadError = String(describing: error)
        }

        // The two feeds are a glance, not a source of truth. A server
        // that cannot answer them should leave the last known rows on
        // screen rather than replace this pane with an error.

        // Deliberately the *default* page size, matching Transactions:
        // this call writes the shared `.all` cold-start blob, and asking
        // for a shorter page here would quietly shrink what Transactions
        // paints on its next cold open.
        if let page = try? await session.wallet.fetchRecentActivity(
            forFid: session.liveFid
        ) {
            recentGroups = TxGroup.group(page.cashes)
        }

        // Rendered, not cached. `NewsStore.save` replaces the whole
        // window, so writing this five-row page would truncate the two
        // hundred rows the News pane keeps for its own cold start. That
        // pane owns the cache; this one is only ever borrowing a glance
        // at the top of it.
        if let page = try? await session.newsService.fetch(.newest, size: Self.feedRows) {
            latestNews = page.news
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

    /// Signed so the direction of a transaction is readable without
    /// decoding the arrow glyph beside it.
    private func signedBch(_ sats: Int64) -> String {
        (sats >= 0 ? "+" : "−") + formatBch(abs(sats))
    }

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
