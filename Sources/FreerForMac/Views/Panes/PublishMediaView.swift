import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Published images, sounds and videos — FEIP24, FEIP23 and FEIP25 —
/// with FEIP22 `Remark` riding along inside each.
///
/// **One pane, three sidebar entries.** The three protocols differ in a
/// serial number, a name, an index and one field spelling (see
/// ``MediaKind``) and in nothing a person would notice, so this is one
/// implementation configured three ways rather than three files that
/// would drift. What varies is presentation — a picture, a play button,
/// a video — and that is ``MediaPresenter``'s job, not this one's.
///
/// Everything structural is Text's, unchanged: the four tabs, the two
/// queries behind them, the server cursor, the tab-meaning guard, the
/// one-tab-owns-the-cache rule and the digest draft id.
///
/// **Four tabs, two queries.** Mine and Deleted are the same publisher-
/// scoped fetch with the `deleted` flag flipped; Discover drops the
/// publisher clause and shows the whole chain, which is what a
/// published work is *for*. Drafts never touch the chain.
struct PublishMediaView: View {
    let session: ActiveSession
    /// Which of the three protocols this pane is. Everything else here
    /// is identical between them.
    let kind: MediaKind

    private static let pageSize = 25

    private enum Tab: String, CaseIterable, Identifiable {
        case mine = "Mine"
        case discover = "Discover"
        case deleted = "Deleted"
        case drafts = "Drafts"
        var id: String { rawValue }

        /// What the chain query's `deleted` flag should be.
        var wantsDeleted: Bool? { self == .drafts ? nil : (self == .deleted) }
        /// Whether the query is scoped to the live FID.
        var isMine: Bool { self == .mine || self == .deleted }
    }

    @State private var tab: Tab = .mine
    @State private var rows: [MediaRecord] = []
    @State private var drafts: [MediaRecord] = []
    @State private var total: Int64?
    @State private var cursor: [String]?
    @State private var hasMore = false

    @State private var loading = false
    @State private var loadingMore = false
    @State private var loadError: String?
    @State private var note: String?
    @State private var didAutoLoad = false
    @State private var showingCache = false

    @State private var searchText = ""
    @State private var chainQuery: String?
    @State private var inField: PublishService.Field?
    @State private var sortField: PublishService.Field?
    @State private var ascending = false

    /// FID → CID for the publishers on screen.
    @State private var names: [String: String] = [:]

    @State private var showComposer = false
    /// The draft open in the editor, or the carved record being revised.
    @State private var editing: MediaRecord?
    @State private var reading: MediaRecord?
    @State private var pendingDelete: [MediaRecord] = []
    @State private var busyId: String?
    @State private var actionError: String?
    @State private var actionNote: String?

    @State private var selection: Set<String> = []
    @State private var selecting = false

    // MARK: - derived

    private var source: [MediaRecord] { tab == .drafts ? drafts : rows }

    private var filtered: [MediaRecord] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return source }
        return source.filter { $0.matches(query: q) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            toolbar
            if chainQuery != nil { chainSearchChip }
            statusLine
            banner

            if let err = loadError, source.isEmpty {
                card {
                    Label("Couldn't load", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    CopyableText(err, font: .callout).foregroundStyle(.red)
                    Text("Nothing is shown rather than the last list that loaded — a failed query has no answer, and rows left over from a different one would be read as this one's.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else if loading && source.isEmpty {
                card {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Loading \(tab.rawValue.lowercased())…")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            } else if source.isEmpty {
                emptyCard
            } else if filtered.isEmpty {
                noMatchCard
            } else {
                list
            }

            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 640)
        .onAppear {
            guard !didAutoLoad else { return }
            didAutoLoad = true
            loadLocal()
            Task { await refresh() }
        }
        .onChange(of: tab) { _, _ in
            selection = []
            selecting = false
            // Every tab starts empty and is filled by a fetch made *for
            // that tab*: leaving the old rows up while the new fetch is
            // in flight is how a Deleted tab comes to show live records.
            clearRows()
            if tab == .drafts {
                loadLocal()
            } else {
                Task { await refresh() }
            }
        }
        .sheet(isPresented: $showComposer) {
            PublishMediaComposer(session: session, kind: kind) { result in
                showComposer = false
                loadLocal()
                handle(result)
            }
        }
        .sheet(item: $editing) { record in
            PublishMediaComposer(session: session, kind: kind, editing: record) { result in
                editing = nil
                loadLocal()
                handle(result)
            }
        }
        .sheet(item: $reading) { record in
            MediaViewerSheet(
                session: session,
                kind: kind,
                record: record,
                name: { names[$0] },
                onClose: { reading = nil }
            )
        }
        .alert(
            pendingDelete.count == 1
                ? "Delete this \(kind.noun)?"
                : "Delete \(pendingDelete.count) \(kind.plural)?",
            isPresented: Binding(
                get: { !pendingDelete.isEmpty },
                set: { if !$0 { pendingDelete = [] } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingDelete = [] }
            Button("Delete", role: .destructive) {
                let targets = pendingDelete
                pendingDelete = []
                Task { await setDeleted(targets, to: true) }
            }
        } message: {
            Text("The record stays on the chain, flagged deleted — and Recover puts it back. What ends is its place in a listing. The file on DISK is not touched. One miner fee for the whole batch.")
        }
    }

    private func handle(_ result: PublishMediaComposer.Result) {
        switch result {
        case .carved(let record):
            actionError = nil
            actionNote = "Published — tx \(record.id.elidingMiddle(head: 8, tail: 8)). It shows as On-chain once a block confirms it."
            tab = .mine
            Task { await refresh() }
        case .updated(let txid):
            actionError = nil
            actionNote = "New edition broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8))."
            Task { await refresh() }
        case .draft:
            actionError = nil
            actionNote = "Saved as a draft. Nothing is on the chain, and nothing is on DISK, until you publish it."
            tab = .drafts
        case .cancelled:
            break
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
            .frame(width: 330)

            Spacer(minLength: 8)

            SearchField("Search title, summary, FID…", text: $searchText, minWidth: 150)
                .help("Filters the rows loaded here. Search chain looks through the whole index.")

            if tab != .drafts {
                Menu {
                    Picker("Search in", selection: $inField) {
                        Text("Any field").tag(PublishService.Field?.none)
                        ForEach(PublishService.Field.searchableForMedia) {
                            Text($0.label).tag(PublishService.Field?.some($0))
                        }
                    }
                    Picker("Sort by", selection: $sortField) {
                        Text("Height (default)").tag(PublishService.Field?.none)
                        ForEach(PublishService.Field.sortable) {
                            Text($0.label).tag(PublishService.Field?.some($0))
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

            if tab.isMine && session.canSign {
                Button(selecting ? "Done" : "Select") {
                    selecting.toggle()
                    if !selecting { selection = [] }
                }
                .help("Tick several and delete or recover them in one carve — one miner fee for the batch")
            }

            Button {
                showComposer = true
            } label: {
                Label("Add \(kind.noun)", systemImage: kind.symbol)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!session.canSign)
            .help(session.canSign
                  ? "Pick \(kind == .image ? "an" : "a") \(kind.noun) and publish it"
                  : "Watch-only identity — no key to sign a carve with")
        }
    }

    private var chainSearchChip: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass.circle.fill").foregroundStyle(.blue)
            Text("Chain results for “\(chainQuery ?? "")”\(inField.map { " in \($0.label)" } ?? "")")
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
            if tab == .drafts {
                Text("\(drafts.count) draft\(drafts.count == 1 ? "" : "s") — nothing here is on the chain")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("\(rows.count) shown\(total.map { " of \($0)" } ?? "")")
                    .font(.caption).foregroundStyle(.secondary)
                if !selection.isEmpty {
                    countChip("\(selection.count) selected", color: .blue)
                    if tab == .deleted {
                        Button("Recover selected") {
                            let targets = rows.filter { selection.contains($0.id) }
                            Task { await setDeleted(targets, to: false) }
                        }
                        .font(.caption)
                    } else {
                        Button("Delete selected", role: .destructive) {
                            pendingDelete = rows.filter { selection.contains($0.id) }
                        }
                        .font(.caption)
                    }
                }
                if showingCache {
                    countChip("offline — showing the cached copy", color: .orange)
                }
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
                ForEach(filtered) { record in
                    row(record)
                        .padding(.vertical, 10)
                        .padding(.horizontal, 16)
                    Divider()
                }
                if tab != .drafts {
                    footer
                        .padding(.vertical, 12)
                        .frame(maxWidth: .infinity)
                }
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

    @ViewBuilder
    private func row(_ record: MediaRecord) -> some View {
        HStack(alignment: .top, spacing: 12) {
            if selecting && tab.isMine {
                Toggle("", isOn: Binding(
                    get: { selection.contains(record.id) },
                    set: { on in
                        if on { selection.insert(record.id) } else { selection.remove(record.id) }
                    }
                ))
                .labelsHidden()
                .disabled(record.publisher != session.liveFid)
                .help("Only the publisher can delete or recover a record")
            }

            // The picture leads the row, not the publisher's avatar: a
            // gallery is browsed by what the thing looks like. Only
            // local bytes are drawn — see ``ImageThumbnail``.
            MediaThumbnail(session: session, kind: kind, did: record.did, side: 44)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(record.title?.isEmpty == false ? record.title! : "Untitled")
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)

                    ForEach(chips(for: record), id: \.0) { text, color in
                        chip(text, color: color)
                    }

                    Spacer(minLength: 8)

                    if let t = record.lastTime {
                        Text(Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(t))))
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                if let summary = record.summary, !summary.isEmpty {
                    Text(summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                HStack(spacing: 10) {
                    fidLine("By", record.publisher)
                    if let rate = record.tRate {
                        Text(String(format: "★ %.1f", rate))
                            .font(.caption2)
                            .foregroundStyle(.orange)
                            .help("CDD-weighted average of \(record.tCdd ?? 0) coin-days of ratings")
                    }
                    if record.did == nil {
                        Text("no \(kind.noun)")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .help("This record carries metadata only — its did is empty, so there are no bytes to fetch.")
                    }
                }

                actions(for: record)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            // A draft's tap opens the editor: everything on it is still
            // changeable, so "look at it" and "work on it" are the same
            // gesture. A carved record opens the reader.
            if record.onChain == false { editing = record } else { reading = record }
        }
        .contextMenu {
            if record.onChain == false {
                Button("Edit draft") { editing = record }
            } else {
                Button("View") { reading = record }
                if record.canUpdate(as: session.liveFid) && session.canSign {
                    Button("Publish a new edition…") { editing = record }
                }
            }
            Button("Copy record ID") { copyToPasteboard(record.id) }
            if let did = record.did { Button("Copy document ID") { copyToPasteboard(did) } }
            if let publisher = record.publisher {
                Button("Copy publisher FID") { copyToPasteboard(publisher) }
            }
            if session.canSign && record.publisher == session.liveFid && record.onChain != false {
                Divider()
                if record.isDeleted {
                    Button("Recover") { Task { await setDeleted([record], to: false) } }
                } else {
                    Button("Delete…", role: .destructive) { pendingDelete = [record] }
                }
            }
        }
    }

    @ViewBuilder
    private func actions(for record: MediaRecord) -> some View {
        let busy = busyId == record.id
        HStack(spacing: 8) {
            if record.onChain == false {
                Button {
                    editing = record
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .controlSize(.small)
                .disabled(busy)

                Button("Discard", role: .destructive) { discardDraft(record) }
                    .controlSize(.small)
            } else {
                Button {
                    reading = record
                } label: {
                    Label("View", systemImage: "eye")
                }
                .controlSize(.small)
                .disabled(busy)

                if record.canUpdate(as: session.liveFid) && session.canSign {
                    Button {
                        editing = record
                    } label: {
                        Label("New edition", systemImage: "pencil")
                    }
                    .controlSize(.small)
                    .disabled(busy)
                }
                if record.canRecover(as: session.liveFid) && session.canSign {
                    Button {
                        Task { await setDeleted([record], to: false) }
                    } label: {
                        Label("Recover", systemImage: "arrow.uturn.backward")
                    }
                    .controlSize(.small)
                    .disabled(busy)
                }
            }
            if busy { ProgressView().controlSize(.small) }
        }
        .padding(.top, 2)
    }

    /// Role and state chips, in the order that answers "what is this to
    /// me" before "what state is it in".
    private func chips(for record: MediaRecord) -> [(String, Color)] {
        var out: [(String, Color)] = []
        if record.publisher == session.liveFid { out.append(("Mine", .blue)) }

        if record.isDeleted {
            out.append(("Deleted", .red))
        } else if record.onChain == false {
            out.append(("Draft", .gray))
        } else if record.onChain == nil {
            out.append(("Broadcast", .orange))
        }

        // The edition is worth a chip only once it is not the first —
        // "v1" on every row is noise, "v3" is information.
        if record.edition > 1, record.ver != nil {
            out.append(("v\(record.edition)", .indigo))
        }
        if let lang = record.lang, !lang.isEmpty { out.append((lang, .secondary)) }
        return out
    }

    @ViewBuilder
    private func fidLine(_ label: String, _ fid: String?) -> some View {
        if let fid, !fid.isEmpty {
            HStack(spacing: 3) {
                Text(label).font(.caption2).foregroundStyle(.tertiary)
                CopyableText(
                    display: names[fid] ?? fid.elidingMiddle(head: 6, tail: 6),
                    copy: fid,
                    font: .system(.caption2, design: .monospaced)
                )
                .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - loading

    private func clearRows() {
        rows = []
        total = nil
        cursor = nil
        hasMore = false
        chainQuery = nil
        note = nil
        loadError = nil
        showingCache = false
    }

    /// Keep only the rows that belong on this tab, and say so when the
    /// server sent others.
    ///
    /// A filter the server silently dropped is indistinguishable from
    /// one it applied, and the symptom is the worst kind: Mine and
    /// Deleted showing the same list with nothing to say which is
    /// lying. So the tab's meaning is enforced here, where it is
    /// defined.
    private func belongingToTab(_ records: [MediaRecord]) -> (kept: [MediaRecord], dropped: Int) {
        guard let want = tab.wantsDeleted else { return (records, 0) }
        let kept = records.filter { $0.isDeleted == want }
        return (kept, records.count - kept.count)
    }

    private func noteServerFilterMismatch(_ dropped: Int, of total: Int) {
        guard dropped > 0 else { return }
        note = "The server returned \(dropped) of \(total) row\(total == 1 ? "" : "s") that don't belong on this tab — it ignored the deleted filter, so this list is filtered here instead and Load more may return fewer rows than it fetches."
    }

    private func loadLocal() {
        do {
            drafts = try session.media(kind).drafts()
            if rows.isEmpty, tab == .mine {
                rows = try session.media(kind).all().filter {
                    $0.onChain != false && !$0.isDeleted && $0.publisher == session.liveFid
                }
                showingCache = !rows.isEmpty
            }
            loadError = nil
        } catch {
            loadError = String(describing: error)
        }
    }

    private func refresh() async {
        guard tab != .drafts else { return }
        loading = true
        defer { loading = false }
        do {
            let page = try await session.publish.fetchMedia(
                kind: kind,
                publisher: tab.isMine ? session.liveFid : nil,
                deleted: tab.wantsDeleted,
                ascending: ascending,
                size: Self.pageSize
            )
            let (kept, dropped) = belongingToTab(page.rows)
            rows = kept
            total = dropped > 0 ? nil : page.total
            cursor = page.last
            hasMore = page.rows.count >= Self.pageSize
            chainQuery = nil
            loadError = nil
            showingCache = false
            note = nil
            noteServerFilterMismatch(dropped, of: page.rows.count)
            // Only Mine owns the cache: it is the list the cache is a
            // copy of. Caching Discover would fill this identity's store
            // with strangers' records, and caching Deleted would
            // overwrite the live rows with their complement.
            if tab == .mine {
                _ = try? session.media(kind).replaceChainRows(with: kept)
            }
            await resolveNames(for: kept)
        } catch {
            clearRows()
            loadError = String(describing: error)
            loadLocalFallback()
        }
    }

    /// A failed refresh falls back to the cached rows rather than
    /// blanking a pane that had content — and says which it is showing.
    private func loadLocalFallback() {
        guard rows.isEmpty, tab == .mine else { return }
        if let cached = try? session.media(kind).all().filter({
            $0.onChain != false && !$0.isDeleted && $0.publisher == session.liveFid
        }), !cached.isEmpty {
            rows = cached
            showingCache = true
        }
    }

    private func loadMore() async {
        guard !loadingMore, let cursor else { return }
        loadingMore = true
        defer { loadingMore = false }
        do {
            let page: PublishService.Page<MediaRecord>
            if let q = chainQuery {
                page = try await session.publish.searchMedia(
                    kind: kind,
                    query: q, inField: inField,
                    publisher: tab.isMine ? session.liveFid : nil,
                    sortField: sortField, ascending: ascending,
                    deleted: tab.wantsDeleted, after: cursor, size: Self.pageSize
                )
            } else {
                page = try await session.publish.fetchMedia(
                    kind: kind,
                    publisher: tab.isMine ? session.liveFid : nil,
                    deleted: tab.wantsDeleted, ascending: ascending,
                    after: cursor, size: Self.pageSize
                )
            }
            let (kept, _) = belongingToTab(page.rows)
            let known = Set(rows.map(\.id))
            rows.append(contentsOf: kept.filter { !known.contains($0.id) })
            self.cursor = page.last
            hasMore = page.rows.count >= Self.pageSize
            await resolveNames(for: kept)
        } catch {
            actionError = String(describing: error)
        }
    }

    /// Take the search box to the chain index rather than the loaded
    /// rows. Pages from the server's own cursor — see
    /// ``PublishService/Page``.
    private func searchChain() async {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return }
        loading = true
        defer { loading = false }
        do {
            let page = try await session.publish.searchMedia(
                    kind: kind,
                query: q, inField: inField,
                publisher: tab.isMine ? session.liveFid : nil,
                sortField: sortField, ascending: ascending,
                deleted: tab.wantsDeleted, size: Self.pageSize
            )
            let (kept, dropped) = belongingToTab(page.rows)
            rows = kept
            total = dropped > 0 ? nil : page.total
            cursor = page.last
            hasMore = page.rows.count >= Self.pageSize
            chainQuery = q
            loadError = nil
            showingCache = false
            searchText = ""
            noteServerFilterMismatch(dropped, of: page.rows.count)
            await resolveNames(for: kept)
        } catch {
            loadError = String(describing: error)
        }
    }

    private func resolveNames(for records: [MediaRecord]) async {
        var wanted = Set<String>()
        for r in records {
            if let p = r.publisher, !p.isEmpty, names[p] == nil { wanted.insert(p) }
        }
        guard !wanted.isEmpty else { return }
        for fid in wanted {
            if let contact = try? session.contacts.get(fid: fid),
               let label = contact.cid ?? contact.titles?.first, !label.isEmpty {
                names[fid] = label
                wanted.remove(fid)
            }
        }
        guard !wanted.isEmpty else { return }
        if let found = try? await session.directory.freerByIds(Array(wanted)) {
            for (fid, freer) in found {
                if let cid = freer.cid, !cid.isEmpty { names[fid] = cid }
            }
        }
    }

    // MARK: - actions

    /// Delete and recover are one carve with one boolean flipped, and
    /// they take a list because the protocol does — several records,
    /// one miner fee.
    private func setDeleted(_ records: [MediaRecord], to deleted: Bool) async {
        let ids = records.map(\.id)
        guard !ids.isEmpty else { return }
        busyId = ids.count == 1 ? ids[0] : nil
        defer { busyId = nil }
        do {
            let txid = deleted
                ? try await session.carveMediaDeleteOnChain(kind: kind, mediaIds: ids)
                : try await session.carveMediaRecoverOnChain(kind: kind, mediaIds: ids)
            actionError = nil
            actionNote = "\(deleted ? "Delete" : "Recover") broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The flag flips when a block confirms it."
            selection = []
            selecting = false
            await refresh()
        } catch {
            actionNote = nil
            actionError = String(describing: error)
        }
    }

    private func discardDraft(_ record: MediaRecord) {
        _ = try? session.media(kind).remove(id: record.id)
        loadLocal()
        actionError = nil
        actionNote = "Draft discarded."
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
            switch tab {
            case .mine:
                Label("You haven't published \(kind == .image ? "an" : "a") \(kind.noun)", systemImage: kind.symbol)
                    .font(.headline)
                Text("Publishing catalogues the work on the chain — a title, a summary, and a pointer to the file. The bytes are not carved: they go to DISK, and what the chain holds is their hash, so anyone who fetches the file can check they got the right one. The record's ID is the transaction that published it.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .discover:
                Label("Nothing published yet", systemImage: "globe")
                    .font(.headline)
                Text("This is the whole chain's shelf, not yours. If it is empty, nobody has published \(kind == .image ? "an" : "a") \(kind.noun) on this index yet.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .deleted:
                Label("Nothing deleted", systemImage: "archivebox")
                    .font(.headline)
                Text("Deleting retires the record: it stays on the chain, flagged deleted, and Recover puts it back. The file on DISK is not touched. None of yours are deleted.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .drafts:
                Label("No drafts", systemImage: "tray")
                    .font(.headline)
                Text("Pick a file and choose Save draft to keep it here without paying for anything. A draft exists only on this Mac — nothing has been uploaded and nothing has been carved — and it stays editable until you publish it.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var noMatchCard: some View {
        card {
            Label("No loaded row matches “\(searchText)”", systemImage: "magnifyingglass")
                .font(.headline)
            Text("This searched the \(source.count) row\(source.count == 1 ? "" : "s") loaded here. Chain ▸ Search chain looks through the whole index.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yy-MM-dd HH:mm"
        return f
    }()

    private func copyToPasteboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }
}
