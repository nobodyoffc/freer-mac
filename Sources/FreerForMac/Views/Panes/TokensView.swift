import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Tokens — the Mac port of Android's `TokensActivity`,
/// `MyTokenActivity`, `CreateTokenActivity`, `IssueTokenActivity`,
/// `SendTokenActivity`, `CloseTokenActivity`, `TokenHistoryActivity`,
/// `HiddenTokenActivity` and `HiddenTokenHolderActivity`, as one pane.
///
/// A token is a ledger the chain keeps on someone's behalf. Nothing
/// here is encrypted — like proofs and unlike secrets, the whole point
/// is that a third party can check the balances themselves.
///
/// **Three tabs over three indices, which is why they are tabs and not
/// filters.** Holdings is `token_holder` scoped to the live FID —
/// what you can actually spend. Tokens is the chain-wide `token` index
/// — every ledger that exists, including ones you have no stake in.
/// History is `token_history`, the op stream those two are derived
/// from. Android splits these across seven activities with three
/// separate copies of the paging, sorting and hide logic; the queries
/// differ, the machinery does not.
///
/// **Holdings needs two fetches, and the second one is not optional.**
/// A holder row carries a `tokenId` and a balance and nothing else — no
/// name, no decimal scale, no closed flag. A balance cannot even be
/// *formatted* until its token is resolved, let alone spent, so every
/// holdings refresh follows up with a by-ids batch over the tokens it
/// mentions.
struct TokensView: View {
    let session: ActiveSession

    private static let pageSize = 25

    private enum Tab: String, CaseIterable, Identifiable {
        case holdings = "Holdings"
        case tokens = "Tokens"
        case history = "History"
        var id: String { rawValue }
    }

    @State private var tab: Tab = .holdings

    // Holdings
    @State private var holders: [TokenHolder] = []
    /// Token id → token, for every row on screen. Populated by the
    /// by-ids follow-up; a holding whose token is missing from here is
    /// shown but cannot be sent.
    @State private var tokensById: [String: Token] = [:]

    // Tokens
    @State private var chainTokens: [Token] = []

    // History
    @State private var history: [TokenHistory] = []

    @State private var total: Int64?
    @State private var cursor: [String]?
    @State private var hasMore = false

    @State private var loading = false
    @State private var loadingMore = false
    @State private var loadError: String?
    @State private var note: String?
    @State private var didAutoLoad = false
    /// Set when the last refresh failed and the rows came from the
    /// cache instead.
    @State private var showingCache = false

    @State private var searchText = ""
    /// Non-nil while the rows on screen are a chain search's results.
    @State private var chainQuery: String?
    @State private var tokenField: TokenService.TokenField?
    @State private var sortField: TokenService.TokenField?
    @State private var ascending = false
    /// Show what has been hidden instead of what has not.
    @State private var showingHidden = false
    @State private var hiddenTokenIds: Set<String> = []
    @State private var hiddenHolderIds: Set<String> = []

    @State private var showDeploySheet = false
    @State private var issuing: Token?
    @State private var sending: SendTarget?
    @State private var detail: Token?
    @State private var pendingClose: [Token] = []
    @State private var pendingDestroy: TokenHolder?
    @State private var busyId: String?
    @State private var actionError: String?
    @State private var actionNote: String?

    /// A holding plus its resolved token — the pair the send sheet
    /// needs, and the reason it is a pair: a `TokenHolder` alone cannot
    /// say how many decimal places its amount may carry.
    private struct SendTarget: Identifiable {
        let holder: TokenHolder
        let token: Token
        var id: String { holder.id }
    }

    // MARK: - derived

    private var visibleHolders: [TokenHolder] {
        holders.filter { showingHidden == hiddenHolderIds.contains($0.id) }
    }

    private var visibleTokens: [Token] {
        chainTokens.filter { showingHidden == hiddenTokenIds.contains($0.id) }
    }

    private var filteredHolders: [TokenHolder] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return visibleHolders }
        return visibleHolders.filter { holder in
            if holder.matches(query: q) { return true }
            // A holdings list is read by token name, not by the 64 hex
            // characters of a token id — searching only the fields the
            // holder row happens to carry would make the obvious query
            // the one that does not work.
            guard let tid = holder.tokenId, let token = tokensById[tid] else { return false }
            return token.matches(query: q)
        }
    }

    private var filteredTokens: [Token] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return visibleTokens }
        return visibleTokens.filter { $0.matches(query: q) }
    }

    private var filteredHistory: [TokenHistory] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return history }
        return history.filter { $0.matches(query: q) }
    }

    private var rowCount: Int {
        switch tab {
        case .holdings: return visibleHolders.count
        case .tokens:   return visibleTokens.count
        case .history:  return history.count
        }
    }

    private var filteredCount: Int {
        switch tab {
        case .holdings: return filteredHolders.count
        case .tokens:   return filteredTokens.count
        case .history:  return filteredHistory.count
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            toolbar
            if chainQuery != nil { chainSearchChip }
            statusLine
            banner

            if let err = loadError, rowCount == 0 {
                card {
                    Label("Couldn't load tokens", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    CopyableText(err, font: .callout).foregroundStyle(.red)
                    Text("Nothing is shown rather than the last list that loaded — a failed query has no answer, and rows left over from a different one would be read as this one's.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else if loading && rowCount == 0 {
                card {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Loading \(tab.rawValue.lowercased())…")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            } else if rowCount == 0 {
                emptyCard
            } else if filteredCount == 0 {
                noMatchCard
            } else {
                list
            }

            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 700)
        .onAppear {
            guard !didAutoLoad else { return }
            didAutoLoad = true
            loadLocal()
            Task { await refresh() }
        }
        .onChange(of: tab) { _, _ in
            // Every tab starts empty and can only be filled by a fetch
            // made *for that tab*. Leaving the old rows up while the new
            // fetch is in flight shows one query's answer under another
            // query's heading — and if the fetch then fails, nothing
            // ever replaces them.
            clearRows()
            loadLocal()
            Task { await refresh() }
        }
        .sheet(isPresented: $showDeploySheet) {
            DeployTokenSheet(session: session) { token in
                showDeploySheet = false
                guard let token else { return }
                actionError = nil
                actionNote = "Deployed — tx \(token.id.elidingMiddle(head: 8, tail: 8)). The token's ID is that transaction; it appears in the chain list once a block confirms it."
                tokensById[token.id] = token
                tab = .tokens
                Task { await refresh() }
            }
        }
        .sheet(item: $issuing) { token in
            IssueTokenSheet(session: session, token: token) { txid in
                issuing = nil
                guard let txid else { return }
                actionError = nil
                actionNote = "Issue broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). Balances update when a block confirms it."
                Task { await refresh() }
            }
        }
        .sheet(item: $sending) { target in
            SendTokenSheet(session: session, token: target.token, holder: target.holder) { txid in
                sending = nil
                guard let txid else { return }
                actionError = nil
                actionNote = "Send broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The balance moves when a block confirms it."
                Task { await refresh() }
            }
        }
        .sheet(item: $detail) { token in
            TokenDetailSheet(session: session, token: token) { detail = nil }
        }
        .alert(
            closeAlertTitle,
            isPresented: Binding(
                get: { !pendingClose.isEmpty },
                set: { if !$0 { pendingClose = [] } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingClose = [] }
            Button("Close token", role: .destructive) {
                let targets = pendingClose
                pendingClose = []
                Task { await close(targets) }
            }
        } message: {
            Text("Closing retires the token for everybody, permanently: no further issue, no further transfer, every balance frozen where it sits. Nothing undoes it, and it is not the same as hiding it from your own list.")
        }
        .alert(
            "Burn your whole balance?",
            isPresented: Binding(
                get: { pendingDestroy != nil },
                set: { if !$0 { pendingDestroy = nil } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingDestroy = nil }
            Button("Burn it all", role: .destructive) {
                let target = pendingDestroy
                pendingDestroy = nil
                if let target { Task { await destroy(target) } }
            }
        } message: {
            Text(destroyAlertMessage)
        }
    }

    // MARK: - toolbar

    private var toolbar: some View {
        HStack(spacing: 12) {
            Picker("", selection: $tab) {
                ForEach(Tab.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 260)

            Spacer(minLength: 8)

            SearchField(searchPlaceholder, text: $searchText, minWidth: 150)
                .help("Filters the rows loaded here. Search chain looks through the whole index.")

            if tab == .tokens {
                Menu {
                    Picker("Search in", selection: $tokenField) {
                        Text("Any field").tag(TokenService.TokenField?.none)
                        ForEach(TokenService.TokenField.searchable) {
                            Text($0.label).tag(TokenService.TokenField?.some($0))
                        }
                    }
                    Picker("Sort by", selection: $sortField) {
                        Text("Height (default)").tag(TokenService.TokenField?.none)
                        ForEach(TokenService.TokenField.sortable) {
                            Text($0.label).tag(TokenService.TokenField?.some($0))
                        }
                    }
                    Toggle("Oldest first", isOn: $ascending)
                    Divider()
                    Button("Search chain") { Task { await searchChain() } }
                        .disabled(searchText.trimmingCharacters(in: .whitespaces).isEmpty)
                } label: {
                    Label("Chain", systemImage: "line.3.horizontal.decrease.circle")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .help("Take this text to the chain index, with a field and sort of your choosing")
            }

            if tab != .history {
                Button {
                    showingHidden.toggle()
                } label: {
                    Label(showingHidden ? "Hidden" : "Visible",
                          systemImage: showingHidden ? "eye.slash" : "eye")
                }
                .help(showingHidden
                      ? "Showing what you hid. Hiding is local to this Mac and changes nothing on the chain."
                      : "Show the rows you have hidden")
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

            Button {
                showDeploySheet = true
            } label: {
                Label("Deploy", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!session.canSign)
            .help(session.canSign
                  ? "Deploy a new token — its rules are permanent"
                  : "Watch-only identity — no key to sign a carve with")
        }
    }

    private var searchPlaceholder: String {
        switch tab {
        case .holdings: return "Search your holdings…"
        case .tokens:   return "Search name, description, deployer…"
        case .history:  return "Search ops, FIDs, token IDs…"
        }
    }

    private var chainSearchChip: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass.circle.fill").foregroundStyle(.blue)
            Text("Chain results for “\(chainQuery ?? "")”\(tokenField.map { " in \($0.label)" } ?? "")")
                .font(.caption)
            Button("Clear") {
                chainQuery = nil
                Task { await refresh() }
            }
            .buttonStyle(.link)
            .font(.caption)
        }
    }

    @ViewBuilder
    private var statusLine: some View {
        HStack(spacing: 10) {
            Text("\(rowCount) shown\(total.map { " of \($0)" } ?? "")")
                .font(.caption).foregroundStyle(.secondary)
            if showingHidden {
                countChip("hidden rows — local to this Mac", color: .orange)
            }
            if tab == .holdings, !holders.isEmpty {
                let unresolved = holders.filter { $0.tokenId.map { tokensById[$0] == nil } ?? true }.count
                if unresolved > 0 {
                    countChip("\(unresolved) token\(unresolved == 1 ? "" : "s") unresolved", color: .orange)
                }
            }
            if showingCache {
                countChip("offline — showing the cached copy", color: .orange)
            }
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder
    private var banner: some View {
        if let err = actionError {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.red)
                CopyableText(err, font: .caption).foregroundStyle(.red)
            }
        } else if let n = actionNote {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.seal").foregroundStyle(.green)
                CopyableText(n, font: .caption).foregroundStyle(.green)
            }
        } else if let n = note {
            CopyableText(n, font: .caption).foregroundStyle(.secondary)
        }
    }

    // MARK: - list

    private var list: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                switch tab {
                case .holdings:
                    ForEach(filteredHolders) { holder in
                        holdingRow(holder)
                            .padding(.vertical, 10)
                            .padding(.horizontal, 16)
                        Divider()
                    }
                case .tokens:
                    ForEach(filteredTokens) { token in
                        tokenRow(token)
                            .padding(.vertical, 10)
                            .padding(.horizontal, 16)
                        Divider()
                    }
                case .history:
                    ForEach(filteredHistory) { entry in
                        TokenHistoryRow(
                            entry: entry,
                            scale: scale(forTokenId: entry.affectedTokenIds.first),
                            liveFid: session.liveFid,
                            names: tokenNames
                        )
                        .padding(.vertical, 10)
                        .padding(.horizontal, 16)
                        Divider()
                    }
                }
                footer
                    .padding(.vertical, 12)
                    .frame(maxWidth: .infinity)
            }
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    @ViewBuilder
    private var footer: some View {
        if loadingMore {
            ProgressView().controlSize(.small)
        } else if hasMore {
            Button("Load more") { Task { await loadMore() } }
                .disabled(loading)
        } else {
            Text("That's all of them")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
    }

    // MARK: - rows

    @ViewBuilder
    private func holdingRow(_ holder: TokenHolder) -> some View {
        let token = holder.tokenId.flatMap { tokensById[$0] }
        let busy = busyId == holder.id
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "circlebadge.2")
                .font(.title2)
                .foregroundStyle(token?.isClosed == true ? Color.secondary : Color.blue)
                .frame(width: 34)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(token?.displayName
                         ?? holder.tokenId?.elidingMiddle(head: 8, tail: 8)
                         ?? "Unknown token")
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)

                    if let token {
                        ForEach(chips(for: token), id: \.0) { text, color in
                            chip(text, color: color)
                        }
                    } else {
                        // Not an error: the by-ids follow-up may still be
                        // in flight, or the token may have been pruned
                        // from the index. Either way the balance is real
                        // and the rules behind it are not known here.
                        chip("token not resolved", color: .orange)
                    }

                    Spacer(minLength: 8)

                    Text(TokenAmount.string(holder.balance, scale: token?.decimalPlaces ?? 0))
                        .font(.body.monospacedDigit().bold())
                }

                HStack(spacing: 10) {
                    if let tid = holder.tokenId {
                        HStack(spacing: 3) {
                            Text("Token").font(.caption2).foregroundStyle(.tertiary)
                            CopyableText.elidingMiddle(
                                tid, head: 6, tail: 6,
                                font: .system(.caption2, design: .monospaced)
                            )
                            .foregroundStyle(.secondary)
                        }
                    }
                    if let h = holder.lastHeight {
                        Text("height \(h)").font(.caption2).foregroundStyle(.tertiary)
                    }
                }

                HStack(spacing: 8) {
                    if let token {
                        Button {
                            sending = SendTarget(holder: holder, token: token)
                        } label: {
                            Label("Send", systemImage: "paperplane")
                        }
                        .controlSize(.small)
                        .disabled(busy || !session.canSign || !token.canTransfer || !holder.hasBalance)
                        .help(sendHelp(token: token, holder: holder))

                        Button {
                            detail = token
                        } label: {
                            Label("Details", systemImage: "info.circle")
                        }
                        .controlSize(.small)

                        if holder.hasBalance && session.canSign {
                            Button("Burn…", role: .destructive) { pendingDestroy = holder }
                                .controlSize(.small)
                                .disabled(busy)
                                .help("Destroy your whole balance of this token. There is no partial burn.")
                        }
                    }
                    hideButton(id: holder.id, isHidden: hiddenHolderIds.contains(holder.id)) {
                        toggleHiddenHolder(holder.id)
                    }
                    if busy { ProgressView().controlSize(.small) }
                }
                .padding(.top, 2)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { if let token { detail = token } }
        .contextMenu {
            if let token { Button("Show details") { detail = token } }
            if let tid = holder.tokenId {
                Button("Copy token ID") { copyToPasteboard(tid) }
            }
            Button("Copy holder record ID") { copyToPasteboard(holder.id) }
            Divider()
            Button(hiddenHolderIds.contains(holder.id) ? "Unhide" : "Hide from this list") {
                toggleHiddenHolder(holder.id)
            }
        }
    }

    @ViewBuilder
    private func tokenRow(_ token: Token) -> some View {
        let busy = busyId == token.id
        HStack(alignment: .top, spacing: 12) {
            FidAvatarView(fid: token.deployer ?? "", size: 36)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(token.displayName)
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)

                    ForEach(chips(for: token), id: \.0) { text, color in
                        chip(text, color: color)
                    }

                    Spacer(minLength: 8)

                    if let t = token.lastTime {
                        Text(TokenDetailSheet.dateString(t))
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                if let desc = token.desc, !desc.isEmpty {
                    Text(desc)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                HStack(spacing: 10) {
                    HStack(spacing: 3) {
                        Text("Deployer").font(.caption2).foregroundStyle(.tertiary)
                        CopyableText.elidingMiddle(
                            token.deployer ?? "—", head: 6, tail: 6,
                            font: .system(.caption2, design: .monospaced)
                        )
                        .foregroundStyle(.secondary)
                    }
                    Text("circulating \(TokenAmount.string(token.circulating, scale: token.decimalPlaces))")
                        .font(.caption2).foregroundStyle(.tertiary)
                    if let cap = token.capacity, !cap.isEmpty {
                        Text("cap \(cap)").font(.caption2).foregroundStyle(.tertiary)
                    }
                }

                HStack(spacing: 8) {
                    if token.canIssue(as: session.liveFid) {
                        Button {
                            issuing = token
                        } label: {
                            Label("Issue", systemImage: "plus.circle")
                        }
                        .controlSize(.small)
                        .disabled(busy || !session.canSign)
                    }
                    if token.canClose(as: session.liveFid) {
                        Button("Close…", role: .destructive) { pendingClose = [token] }
                            .controlSize(.small)
                            .disabled(busy || !session.canSign)
                            .help("Retire this token for everybody, permanently")
                    }
                    Button {
                        detail = token
                    } label: {
                        Label("Details", systemImage: "info.circle")
                    }
                    .controlSize(.small)

                    hideButton(id: token.id, isHidden: hiddenTokenIds.contains(token.id)) {
                        toggleHiddenToken(token.id)
                    }
                    if busy { ProgressView().controlSize(.small) }
                }
                .padding(.top, 2)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { detail = token }
        .contextMenu {
            Button("Show details") { detail = token }
            Button("Copy token ID") { copyToPasteboard(token.id) }
            if let dep = token.deployer { Button("Copy deployer FID") { copyToPasteboard(dep) } }
            Divider()
            Button(hiddenTokenIds.contains(token.id) ? "Unhide" : "Hide from this list") {
                toggleHiddenToken(token.id)
            }
        }
    }

    private func hideButton(id: String, isHidden: Bool, action: @escaping () -> Void) -> some View {
        Button {
            action()
        } label: {
            Label(isHidden ? "Unhide" : "Hide", systemImage: isHidden ? "eye" : "eye.slash")
        }
        .controlSize(.small)
        .help(isHidden
              ? "Put this back in the list"
              : "Stop showing this row on this Mac. Nothing is carved and the balance is untouched.")
    }

    private func sendHelp(token: Token, holder: TokenHolder) -> String {
        if !session.canSign { return "Watch-only identity — no key to sign a carve with" }
        if token.isClosed { return "This token is closed: balances are frozen where they sit" }
        if token.transferable != true { return "This token was deployed non-transferable" }
        if !holder.hasBalance { return "Nothing to send — this holding is empty" }
        return "Send some of this balance to another FID"
    }

    /// State chips, in the order that answers "can I do anything with
    /// this" before "what is it".
    private func chips(for token: Token) -> [(String, Color)] {
        var out: [(String, Color)] = []
        if token.deployer == session.liveFid { out.append(("Yours", .blue)) }
        if token.isClosed {
            out.append(("Closed", .red))
        } else if token.transferable != true {
            out.append(("Non-transferable", .orange))
        }
        if token.openIssue == true { out.append(("Open issue", .purple)) }
        return out
    }

    private var tokenNames: [String: String] {
        tokensById.compactMapValues { token in
            let n = token.displayName
            return n == token.id ? nil : n
        }
    }

    private func scale(forTokenId id: String?) -> Int {
        guard let id, let token = tokensById[id] else { return 8 }
        return token.decimalPlaces
    }

    // MARK: - loading

    /// Drop everything that described the previous query.
    private func clearRows() {
        holders = []
        chainTokens = []
        history = []
        total = nil
        cursor = nil
        hasMore = false
        chainQuery = nil
        note = nil
        loadError = nil
        showingCache = false
    }

    private func loadLocal() {
        do {
            hiddenTokenIds = try session.tokens.hiddenTokenIds()
            hiddenHolderIds = try session.tokens.hiddenHolderIds()
            switch tab {
            case .holdings where holders.isEmpty:
                holders = try session.tokens.allHolders()
                showingCache = !holders.isEmpty
                seedTokensFromCache()
            case .tokens where chainTokens.isEmpty:
                chainTokens = try session.tokens.tokenWindow()
                showingCache = !chainTokens.isEmpty
            case .history where history.isEmpty:
                history = try session.tokens.historyWindow()
                showingCache = !history.isEmpty
            default:
                break
            }
            loadError = nil
        } catch {
            loadError = String(describing: error)
        }
    }

    /// Seed ``tokensById`` from the cached token window so an offline
    /// holdings list can still name and scale its balances — otherwise
    /// every cached balance renders as a bare hex id with no decimal
    /// point in the right place.
    private func seedTokensFromCache() {
        guard let cached = try? session.tokens.tokenWindow() else { return }
        for token in cached where tokensById[token.id] == nil {
            tokensById[token.id] = token
        }
    }

    private func refresh() async {
        loading = true
        defer { loading = false }
        do {
            switch tab {
            case .holdings:
                let page = try await session.tokenService.fetchHolders(
                    for: session.liveFid, ascending: ascending, size: Self.pageSize
                )
                holders = page.rows
                total = page.total
                cursor = page.last
                hasMore = page.rows.count >= Self.pageSize
                // A page is a slice, so only a first page that got
                // everything may replace the cache wholesale.
                if hasMore {
                    _ = try? session.tokens.mergeHolders(page.rows)
                } else {
                    _ = try? session.tokens.replaceHolders(with: page.rows)
                }
                await resolveTokens(for: page.rows)
            case .tokens:
                let page = try await session.tokenService.fetchTokens(
                    ascending: ascending, size: Self.pageSize
                )
                chainTokens = page.rows
                total = page.total
                cursor = page.last
                hasMore = page.rows.count >= Self.pageSize
                for token in page.rows { tokensById[token.id] = token }
                try? session.tokens.saveTokenWindow(page.rows)
            case .history:
                let page = try await session.tokenService.fetchHistory(
                    fid: session.liveFid, ascending: ascending, size: Self.pageSize
                )
                history = page.rows
                total = page.total
                cursor = page.last
                hasMore = page.rows.count >= Self.pageSize
                try? session.tokens.saveHistoryWindow(page.rows)
                await resolveTokenNames(for: page.rows)
            }
            chainQuery = nil
            loadError = nil
            showingCache = false
            note = nil
        } catch {
            // A failed query has no rows, so the pane shows none. Any
            // rows still on screen would be the *previous* query's, and
            // an error banner over a stale list reads as a list.
            clearRows()
            loadError = String(describing: error)
            loadLocalFallback()
        }
    }

    /// A failed refresh falls back to the cached rows rather than
    /// blanking a pane that had content — and says which it is showing.
    private func loadLocalFallback() {
        switch tab {
        case .holdings:
            if let cached = try? session.tokens.allHolders(), !cached.isEmpty {
                holders = cached
                showingCache = true
                seedTokensFromCache()
            }
        case .tokens:
            if let cached = try? session.tokens.tokenWindow(), !cached.isEmpty {
                chainTokens = cached
                showingCache = true
            }
        case .history:
            if let cached = try? session.tokens.historyWindow(), !cached.isEmpty {
                history = cached
                showingCache = true
            }
        }
    }

    private func loadMore() async {
        guard let cursor, !loadingMore else { return }
        loadingMore = true
        defer { loadingMore = false }
        do {
            switch tab {
            case .holdings:
                let page = try await session.tokenService.fetchHolders(
                    for: session.liveFid, ascending: ascending,
                    after: cursor, size: Self.pageSize
                )
                holders += page.rows
                self.cursor = page.last
                hasMore = page.rows.count >= Self.pageSize
                _ = try? session.tokens.mergeHolders(page.rows)
                await resolveTokens(for: page.rows)
            case .tokens:
                let page: TokenService.Page<Token>
                if let q = chainQuery {
                    page = try await session.tokenService.searchTokens(
                        query: q, inField: tokenField, sortField: sortField,
                        ascending: ascending, after: cursor, size: Self.pageSize
                    )
                } else {
                    page = try await session.tokenService.fetchTokens(
                        ascending: ascending, after: cursor, size: Self.pageSize
                    )
                }
                chainTokens += page.rows
                self.cursor = page.last
                hasMore = page.rows.count >= Self.pageSize
                for token in page.rows { tokensById[token.id] = token }
                // The cache is "the window I was looking at", so it
                // grows with the window — saving only the first page
                // would show an offline user less than they had loaded.
                // A search result is not the browse window and is not
                // cached; see `searchChain`.
                if chainQuery == nil { try? session.tokens.saveTokenWindow(chainTokens) }
            case .history:
                let page = try await session.tokenService.fetchHistory(
                    fid: session.liveFid, ascending: ascending,
                    after: cursor, size: Self.pageSize
                )
                history += page.rows
                self.cursor = page.last
                hasMore = page.rows.count >= Self.pageSize
                try? session.tokens.saveHistoryWindow(history)
                await resolveTokenNames(for: page.rows)
            }
        } catch {
            note = "Couldn't load more: \(error)"
        }
    }

    private func searchChain() async {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty, tab == .tokens else { return }
        loading = true
        defer { loading = false }
        do {
            let page = try await session.tokenService.searchTokens(
                query: q, inField: tokenField, sortField: sortField,
                ascending: ascending, size: Self.pageSize
            )
            chainTokens = page.rows
            total = page.total
            cursor = page.last
            hasMore = page.rows.count >= Self.pageSize
            chainQuery = q
            loadError = nil
            showingCache = false
            for token in page.rows { tokensById[token.id] = token }
            // A search result is not the browse window, so it must not
            // overwrite the cache the offline list is drawn from.
        } catch {
            loadError = String(describing: error)
        }
    }

    /// Resolve the tokens a page of holdings refers to. Without this a
    /// balance has no name and no scale — see the type's note.
    private func resolveTokens(for rows: [TokenHolder]) async {
        let wanted = Set(rows.compactMap(\.tokenId)).filter { tokensById[$0] == nil }
        guard !wanted.isEmpty else { return }
        if let found = try? await session.tokenService.fetchTokensByIds(Array(wanted)) {
            for (id, token) in found { tokensById[id] = token }
        }
    }

    /// Same, for the token ids a page of history mentions — a history
    /// row carries the token's name only on the `deploy` op.
    private func resolveTokenNames(for rows: [TokenHistory]) async {
        let wanted = Set(rows.flatMap(\.affectedTokenIds)).filter { tokensById[$0] == nil }
        guard !wanted.isEmpty else { return }
        if let found = try? await session.tokenService.fetchTokensByIds(Array(wanted)) {
            for (id, token) in found { tokensById[id] = token }
        }
    }

    // MARK: - actions

    private func close(_ targets: [Token]) async {
        let ids = targets.map(\.id)
        guard !ids.isEmpty else { return }
        busyId = ids.first
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let txid = try await session.carveTokenCloseOnChain(tokenIds: ids)
            actionNote = "Close broadcast for \(ids.count) token\(ids.count == 1 ? "" : "s") — tx \(txid.elidingMiddle(head: 8, tail: 8))."
            await refresh()
        } catch {
            actionError = "Couldn't close: \(error)"
        }
    }

    private func destroy(_ holder: TokenHolder) async {
        guard let tokenId = holder.tokenId else { return }
        busyId = holder.id
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let txid = try await session.carveTokenDestroyOnChain(tokenId: tokenId)
            actionNote = "Burn broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The balance goes to zero when a block confirms it."
            await refresh()
        } catch {
            actionError = "Couldn't burn: \(error)"
        }
    }

    private func toggleHiddenToken(_ id: String) {
        if hiddenTokenIds.contains(id) {
            try? session.tokens.unhideTokens(ids: [id])
        } else {
            try? session.tokens.hideTokens(ids: [id])
        }
        hiddenTokenIds = (try? session.tokens.hiddenTokenIds()) ?? hiddenTokenIds
    }

    private func toggleHiddenHolder(_ id: String) {
        if hiddenHolderIds.contains(id) {
            try? session.tokens.unhideHolders(ids: [id])
        } else {
            try? session.tokens.hideHolders(ids: [id])
        }
        hiddenHolderIds = (try? session.tokens.hiddenHolderIds()) ?? hiddenHolderIds
    }

    private var closeAlertTitle: String {
        guard let first = pendingClose.first else { return "Close token?" }
        if pendingClose.count == 1 {
            return "Close “\(first.displayName.elidingMiddle(head: 20, tail: 8))” for everybody?"
        }
        return "Close \(pendingClose.count) tokens for everybody?"
    }

    private var destroyAlertMessage: String {
        guard let holder = pendingDestroy else { return "" }
        let token = holder.tokenId.flatMap { tokensById[$0] }
        let amount = TokenAmount.string(holder.balance, scale: token?.decimalPlaces ?? 0)
        return "The destroy op takes a token, not an amount — it burns your entire \(amount) of \(token?.displayName ?? "this token"). There is no partial burn: to keep some, send the rest away first. This cannot be undone."
    }

    // MARK: - small pieces

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    private func countChip(_ text: String, color: Color = .secondary) -> some View {
        Text(text)
            .font(.caption.monospacedDigit())
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
    }

    private func card(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8, content: content)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var emptyCard: some View {
        card {
            if showingHidden {
                Label("Nothing hidden", systemImage: "eye")
                    .font(.headline)
                Text("Hiding a row stops this Mac showing it. It carves nothing, changes no balance, and another device will still show it — which is why it is not the same as closing a token.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                switch tab {
                case .holdings:
                    Label("You hold no tokens", systemImage: "circlebadge.2")
                        .font(.headline)
                    Text("A token is a ledger the chain keeps: someone deploys it, issues supply into people's balances, and — if they deployed it transferable — those balances can move. When somebody issues one to you it appears here.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                case .tokens:
                    Label("No tokens found", systemImage: "circle.grid.2x2")
                        .font(.headline)
                    Text("This is the whole chain's token list, not just yours. Deploy fixes a token's rules permanently — name, supply cap, decimal places, and whether it can be transferred, closed or issued by anyone.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                case .history:
                    Label("No token activity", systemImage: "clock.arrow.circlepath")
                        .font(.headline)
                    Text("Every deploy, issue, transfer, burn and close you are party to shows here, oldest at the bottom. It is the op stream your holdings are derived from.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var noMatchCard: some View {
        card {
            Label("No loaded row matches “\(searchText)”", systemImage: "magnifyingglass")
                .font(.headline)
            Text(tab == .tokens
                 ? "This searched the \(rowCount) row\(rowCount == 1 ? "" : "s") loaded here. Chain ▸ Search chain looks through the whole index."
                 : "This searched the \(rowCount) row\(rowCount == 1 ? "" : "s") loaded here.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private func copyToPasteboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }
}
