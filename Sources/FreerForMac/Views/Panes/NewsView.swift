import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The chain-wide activity feed — the Mac port of Android's
/// `NewsActivity` + `NewsCardContainer`.
///
/// Every other list pane in this app shows *your* records: your mail,
/// your contacts, your files. This one shows everyone's. Each row is a
/// pointer — this FID did this to this object at this height — and the
/// whole feed is public chain data, so it loads without a key and works
/// for a watch-only identity.
///
/// **Two searches, one box.** Typing filters the rows already loaded,
/// instantly, the way every other pane's search field behaves. **Search
/// chain** takes the same text to the server, with the field / sort /
/// order controls Android puts in three spinners. The distinction
/// matters because the loaded window is a few hundred rows and the
/// index has millions.
///
/// **What Android's sliding window was for.** `NewsActivity` caps the
/// container at 40 rows and deletes from the far end whenever it adds
/// to the near one, because each row is an inflated `View` in a
/// `LinearLayout`. A `LazyVStack` draws only what is visible, so the
/// window here simply grows; only the *cached* copy is bounded (see
/// ``NewsStore/maxCachedNews``). That also removes the scroll-position
/// arithmetic that half of `NewsCardContainer` is.
struct NewsView: View {
    let session: ActiveSession

    /// One page. Android asks for 10 at a time on a phone; a Mac window
    /// shows more than that at rest, and an empty-looking feed after a
    /// refresh reads as broken.
    private static let pageSize = 25

    @State private var rows: [News] = []
    @State private var total: Int64?
    @State private var hasMoreOlder = true
    /// Server cursor for the next page of a chain search. Browse mode
    /// pages from the oldest row held instead — see ``News/cursor``.
    @State private var searchCursor: [String]?

    @State private var loading = false
    @State private var loadingOlder = false
    @State private var loadError: String?
    @State private var note: String?
    @State private var didAutoLoad = false
    /// Set when the last refresh failed and the rows on screen came out
    /// of the cache instead.
    @State private var showingCacheFrom: Int64?

    @State private var searchText = ""
    /// Non-nil while the rows on screen are a chain search's results.
    @State private var chainQuery: String?
    @State private var inField: News.Field?
    @State private var sortField: News.Field?
    @State private var ascending = false

    /// doer FID → CID, filled from contacts first and the directory
    /// after. Missing means "no CID on chain", so the FID is shown.
    @State private var names: [String: String] = [:]

    @State private var detail: News?
    @State private var addingContact: Contact?

    // MARK: - derived

    private var filtered: [News] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return rows }
        return rows.filter { $0.matches(query: q) }
    }

    private var newCount: Int { rows.filter { $0.isNew == true }.count }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            toolbar
            if chainQuery != nil { chainSearchChip }
            statusLine
            banner

            if let err = loadError, rows.isEmpty {
                card {
                    Label("Couldn't load the feed", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    CopyableText(err, font: .callout).foregroundStyle(.red)
                }
            } else if rows.isEmpty && !loading {
                emptyCard
            } else if filtered.isEmpty {
                noMatchCard
            } else {
                list
            }

            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 620)
        .onAppear {
            guard !didAutoLoad else { return }
            didAutoLoad = true
            loadCache()
            Task { await refresh() }
        }
        .sheet(item: $detail) { item in
            NewsDetailSheet(
                news: item,
                doerName: item.doer.flatMap { names[$0] },
                onAddContact: { fid in
                    detail = nil
                    addingContact = Contact(id: fid)
                },
                onClose: { detail = nil }
            )
        }
        .sheet(item: $addingContact) { contact in
            ContactEditorSheet(
                session: session,
                mode: .createFor(contact.id),
                onSaved: { _ in
                    note = "Added \(contact.id.elidingMiddle(head: 8, tail: 8)) to contacts."
                    addingContact = nil
                },
                onCancel: { addingContact = nil }
            )
        }
    }

    // MARK: - chrome

    private var toolbar: some View {
        HStack(spacing: 12) {
            Text("News").font(.headline)
            if !rows.isEmpty {
                countChip("\(rows.count)")
            }
            if newCount > 0 {
                countChip("\(newCount) new", color: .accentColor)
            }

            Spacer()

            SearchField("Filter loaded, or search the chain…", text: $searchText)

            Menu {
                Picker("Search in", selection: $inField) {
                    Text("All fields").tag(News.Field?.none)
                    ForEach(News.searchableFields) { field in
                        Text(field.label).tag(News.Field?.some(field))
                    }
                }
                Picker("Sort by", selection: $sortField) {
                    Text("Time").tag(News.Field?.none)
                    ForEach(News.sortableFields) { field in
                        Text(field.label).tag(News.Field?.some(field))
                    }
                }
                Picker("Order", selection: $ascending) {
                    Text("Newest / Z→A first").tag(false)
                    Text("Oldest / A→Z first").tag(true)
                }
            } label: {
                Image(systemName: "line.3.horizontal.decrease.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help("Which field a chain search matches, and how results are sorted")

            Button {
                Task { await runChainSearch() }
            } label: {
                Label("Search chain", systemImage: "magnifyingglass.circle")
            }
            .disabled(loading || searchText.trimmingCharacters(in: .whitespaces).isEmpty)
            .help("Search the whole index, not just the rows loaded here")

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
            .help("Pull the newest activity from the chain")
        }
    }

    private var chainSearchChip: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").font(.caption)
            Text("Chain search “\(chainQuery ?? "")” in \(inField?.label ?? "all fields"), by \(sortField?.label ?? "Time") \(ascending ? "ascending" : "descending")")
                .font(.caption)
            Button {
                Task { await refresh() }
            } label: {
                Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.borderless)
            .help("Back to the live feed")
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(Capsule().fill(Color.secondary.opacity(0.12)))
    }

    /// "Showing 25 · of 4,242 on-chain" — Android's `above` /
    /// `onChain` statistics line, which is the only thing telling a
    /// reader that the window is a window.
    private var statusText: String {
        var parts = ["Showing \(filtered.count)"]
        if let total { parts.append("of \(total) on-chain") }
        if let at = showingCacheFrom {
            let when = Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(at)))
            parts.append("cached \(when) — offline")
        }
        return parts.joined(separator: " · ")
    }

    private var statusLine: some View {
        Text(statusText)
            .font(.caption)
            .foregroundStyle(showingCacheFrom == nil ? Color.secondary : Color.orange)
    }

    @ViewBuilder
    private var banner: some View {
        if let err = loadError, !rows.isEmpty {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                CopyableText(err, font: .caption).foregroundStyle(.orange)
            }
        } else if let note {
            CopyableText(note, font: .caption).foregroundStyle(.secondary)
        }
    }

    // MARK: - list

    private var list: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(filtered) { item in
                    row(item)
                        .padding(.vertical, 10)
                        .padding(.horizontal, 16)
                    Divider()
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
        if loadingOlder {
            ProgressView().controlSize(.small)
        } else if hasMoreOlder {
            Button("Load more") {
                Task { await loadOlder() }
            }
            .disabled(loading)
        } else {
            Text("End of the feed")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
    }

    @ViewBuilder
    private func row(_ item: News) -> some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack(alignment: .topLeading) {
                FidAvatarView(fid: item.doer ?? "", size: 40)
                if item.isNew == true {
                    Circle()
                        .fill(Color.accentColor)
                        .frame(width: 9, height: 9)
                        .offset(x: -3, y: -1)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                // Doer first, title under it: a feed row's question is
                // "who did something" before it is "to what". The two
                // keep the type they had — the doer stays the small
                // monospaced id line, the title stays the bold one.
                HStack(spacing: 6) {
                    if let doer = item.doer, !doer.isEmpty {
                        CopyableText(
                            display: names[doer] ?? doer.elidingMiddle(head: 8, tail: 8),
                            copy: doer,
                            font: .system(.caption, design: .monospaced)
                        )
                        .foregroundStyle(.secondary)
                    }
                    if let act = item.act, !act.isEmpty {
                        chip(act, color: .orange)
                    }
                    if let type = FeipProtocol.displayName(forSn: item.objectType) {
                        chip(type, color: .blue)
                    }

                    Spacer(minLength: 8)

                    if let t = item.time {
                        Text(Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(t))))
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                Text(item.objectName ?? item.objectId?.elidingMiddle(head: 6, tail: 6) ?? "—")
                    .font(.body.bold())
                    .lineLimit(1)
                    .truncationMode(.middle)

                if let brief = item.objectBrief, !brief.isEmpty {
                    Text(brief)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .lineLimit(2)
                }
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { detail = item }
        .contextMenu {
            Button("Show details") { detail = item }
            if let doer = item.doer, !doer.isEmpty {
                Button("Add doer to contacts") { addingContact = Contact(id: doer) }
                Button("Copy doer FID") { copyToPasteboard(doer) }
            }
            if let objectId = item.objectId ?? item.id {
                Button("Copy object ID") { copyToPasteboard(objectId) }
            }
        }
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
            Label("Nothing in the feed yet", systemImage: "newspaper")
                .font(.headline)
            Text("News is what the whole chain is doing — registrations, carves, group changes. Refresh to pull the newest activity.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var noMatchCard: some View {
        card {
            Label("No loaded row matches “\(searchText)”", systemImage: "magnifyingglass")
                .font(.headline)
            Text("This searched the \(rows.count) row\(rows.count == 1 ? "" : "s") loaded here. Search chain looks through the whole index.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    private func copyToPasteboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    // MARK: - loading

    /// Show whatever the last session left behind, immediately, so the
    /// pane has content before the network answers — and keeps content
    /// if it never does.
    private func loadCache() {
        guard let cache = try? session.newsCache.load(), !cache.news.isEmpty else { return }
        rows = cache.news
        Task { await resolveNames(for: cache.news) }
    }

    /// Back to the top of the live feed. Also the way out of a chain
    /// search.
    private func refresh() async {
        guard !loading else { return }
        loading = true
        defer { loading = false }
        note = nil

        let watermark = (try? session.newsCache.lastSeenHeight()) ?? nil
        do {
            let page = try await session.newsService.fetch(.newest, size: Self.pageSize)
            rows = NewsService.markingNew(page.news, sinceHeight: watermark)
            total = page.total
            hasMoreOlder = page.news.count >= Self.pageSize
            searchCursor = nil
            chainQuery = nil
            loadError = nil
            showingCacheFrom = nil
            try? session.newsCache.save(news: rows, bestHeight: page.bestHeight)
            Task { await resolveNames(for: rows) }
        } catch {
            loadError = String(describing: error)
            // Offline, or the service is down: fall back to the cache
            // rather than blanking a pane that had content.
            if rows.isEmpty, let cache = try? session.newsCache.load(), !cache.news.isEmpty {
                rows = cache.news
                hasMoreOlder = false
            }
            showingCacheFrom = (try? session.newsCache.load())?.savedAt
        }
    }

    /// The next page further back in time — or the next page of the
    /// chain search, if that is what is on screen.
    private func loadOlder() async {
        guard !loadingOlder, !loading, hasMoreOlder else { return }
        loadingOlder = true
        defer { loadingOlder = false }

        do {
            let page: NewsService.Page
            if let chainQuery {
                page = try await session.newsService.search(
                    query: chainQuery,
                    inField: inField,
                    sortField: sortField,
                    ascending: ascending,
                    after: searchCursor,
                    size: Self.pageSize
                )
                searchCursor = page.last
            } else {
                page = try await session.newsService.fetch(
                    .older, reference: rows.last, size: Self.pageSize
                )
            }
            let added = append(page.news)
            total = page.total ?? total
            hasMoreOlder = page.news.count >= Self.pageSize
            loadError = nil
            if added == 0 && !page.news.isEmpty {
                // Every row was already held: the cursor is not moving,
                // so stop offering a button that does nothing.
                hasMoreOlder = false
            }
            if chainQuery == nil {
                try? session.newsCache.save(news: rows)
            }
            Task { await resolveNames(for: page.news) }
        } catch {
            loadError = String(describing: error)
        }
    }

    private func runChainSearch() async {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty, !loading else { return }
        loading = true
        defer { loading = false }
        note = nil

        do {
            let page = try await session.newsService.search(
                query: query,
                inField: inField,
                sortField: sortField,
                ascending: ascending,
                size: Self.pageSize
            )
            rows = page.news
            total = page.total
            searchCursor = page.last
            hasMoreOlder = page.news.count >= Self.pageSize
            chainQuery = query
            loadError = nil
            showingCacheFrom = nil
            // A search result is not the feed — caching it would make
            // the next launch open on someone's old query.
            if page.news.isEmpty { note = "No news matched “\(query)”." }
            Task { await resolveNames(for: page.news) }
        } catch {
            loadError = String(describing: error)
        }
    }

    /// Append, skipping ids already held. Returns how many were new.
    @discardableResult
    private func append(_ incoming: [News]) -> Int {
        let held = Set(rows.compactMap(\.id))
        let fresh = incoming.filter { item in
            guard let id = item.id else { return true }
            return !held.contains(id)
        }
        rows.append(contentsOf: fresh)
        return fresh.count
    }

    /// Fill in doer CIDs: local contacts first (free), then one
    /// directory call for whatever is left. A feed of bare FIDs is
    /// unreadable, and the doer is the only field in a row that has a
    /// name somewhere else.
    private func resolveNames(for items: [News]) async {
        let unknown = Set(items.compactMap(\.doer))
            .filter { !$0.isEmpty && names[$0] == nil }
        guard !unknown.isEmpty else { return }

        var stillUnknown: [String] = []
        for fid in unknown {
            if let contact = try? session.contacts.get(fid: fid),
               let name = contact.cid ?? contact.titles?.first {
                names[fid] = name
            } else {
                stillUnknown.append(fid)
            }
        }
        guard !stillUnknown.isEmpty else { return }

        // One page of doers is at most `pageSize` distinct FIDs, so this
        // is a single call in practice; the chunking is for the case
        // where several pages resolve at once.
        for chunk in stride(from: 0, to: stillUnknown.count, by: 50) {
            let batch = Array(stillUnknown[chunk..<min(chunk + 50, stillUnknown.count)])
            guard let found = try? await session.directory.freerByIds(batch) else { continue }
            for (fid, freer) in found {
                if let cid = freer.cid, !cid.isEmpty { names[fid] = cid }
            }
        }
    }
}

/// One news record, every field, with the ids copyable — the Mac
/// answer to Android's tap-through to `DetailActivity`.
private struct NewsDetailSheet: View {
    let news: News
    let doerName: String?
    let onAddContact: (String) -> Void
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("News record").font(.title3.bold())
                Spacer()
                Button("Close", action: onClose)
            }
            .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let doer = news.doer, !doer.isEmpty {
                        HStack(alignment: .center, spacing: 12) {
                            FidAvatarView(fid: doer, size: 44)
                            VStack(alignment: .leading, spacing: 3) {
                                if let doerName { Text(doerName).font(.body.bold()) }
                                CopyableText.elidingMiddle(
                                    doer, head: 10, tail: 10,
                                    font: .system(.caption, design: .monospaced)
                                )
                                .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Add to contacts") { onAddContact(doer) }
                        }
                    }

                    field("Action", news.act)
                    field("Type", FeipProtocol.displayName(forSn: news.objectType).map {
                        news.objectType == $0 ? $0 : "\($0) (sn \(news.objectType ?? ""))"
                    })
                    field("Name", news.objectName)
                    field("Brief", news.objectBrief)
                    field("Object ID", news.objectId, mono: true)
                    field("Height", news.height.map(String.init))
                    field("Time", news.time.map {
                        Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval($0)))
                    })
                    field("Record ID", news.id, mono: true)
                }
                .padding()
            }
        }
        .frame(width: 480, height: 470)
    }

    @ViewBuilder
    private func field(_ label: String, _ value: String?, mono: Bool = false) -> some View {
        if let value, !value.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Text(label)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .textCase(.uppercase)
                    .tracking(0.5)
                    .foregroundStyle(.secondary)
                CopyableText(
                    value,
                    font: mono ? .system(.callout, design: .monospaced) : .callout
                )
                .textSelection(.enabled)
            }
        }
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .medium
        return f
    }()
}
