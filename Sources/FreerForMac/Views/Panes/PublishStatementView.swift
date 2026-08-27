import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Formal statements — FEIP8, and the one Publish record that is
/// finished the moment it is made.
///
/// **Everything the other five panes do, this one does not.** There is
/// no edition, because there is no update. No Deleted tab, because
/// there is no delete. No rating, no remarks, no `did`: the text is in
/// the transaction, so there is nothing to fetch and nothing anyone can
/// take down. What is left is three tabs — yours, everyone's, and the
/// drafts that are the only mutable form a statement ever has.
///
/// The composer is where this record's weight is carried, not here:
/// see ``ComposeStatementSheet`` and FEIP8's `confirm` phrase.
struct PublishStatementView: View {
    let session: ActiveSession

    private static let pageSize = 25

    private enum Tab: String, CaseIterable, Identifiable {
        case mine = "Mine"
        case discover = "Discover"
        case drafts = "Drafts"
        var id: String { rawValue }

        var isMine: Bool { self == .mine }
    }

    @State private var tab: Tab = .mine
    @State private var rows: [Statement] = []
    @State private var drafts: [Statement] = []
    @State private var total: Int64?
    @State private var cursor: [String]?
    @State private var hasMore = false

    @State private var loading = false
    @State private var loadingMore = false
    @State private var loadError: String?
    @State private var didAutoLoad = false
    @State private var showingCache = false

    @State private var searchText = ""
    @State private var chainQuery: String?
    @State private var inField: PublishService.Field?
    @State private var sortField: PublishService.Field?
    @State private var ascending = false

    @State private var names: [String: String] = [:]

    @State private var showComposer = false
    @State private var editingDraft: Statement?
    @State private var reading: Statement?
    @State private var actionError: String?
    @State private var actionNote: String?

    // MARK: - derived

    private var source: [Statement] { tab == .drafts ? drafts : rows }

    private var filtered: [Statement] {
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
                }
            } else if loading && source.isEmpty {
                card {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Loading \(tab.rawValue.lowercased())…")
                            .font(.callout).foregroundStyle(.secondary)
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
            clearRows()
            if tab == .drafts {
                loadLocal()
            } else {
                Task { await refresh() }
            }
        }
        .sheet(isPresented: $showComposer) {
            ComposeStatementSheet(session: session) { result in
                showComposer = false
                loadLocal()
                handle(result)
            }
        }
        .sheet(item: $editingDraft) { draft in
            ComposeStatementSheet(session: session, editing: draft) { result in
                editingDraft = nil
                loadLocal()
                handle(result)
            }
        }
        .sheet(item: $reading) { statement in
            StatementReaderSheet(
                session: session,
                statement: statement,
                name: { names[$0] },
                onClose: { reading = nil }
            )
        }
    }

    private func handle(_ result: ComposeStatementSheet.Result) {
        switch result {
        case .carved(let statement):
            actionError = nil
            actionNote = "Carved — tx \(statement.id.elidingMiddle(head: 8, tail: 8)). It is on the chain for good; nothing can change or remove it."
            tab = .mine
            Task { await refresh() }
        case .draft:
            actionError = nil
            actionNote = "Saved as a draft. Nothing is on the chain yet, and a draft is the only form you can still change."
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
            .frame(width: 250)

            Spacer(minLength: 8)

            SearchField("Search title, content, FID…", text: $searchText, minWidth: 150)
                .help("Filters the rows loaded here. Search chain looks through the whole index.")

            if tab != .drafts {
                Menu {
                    Picker("Search in", selection: $inField) {
                        Text("Any field").tag(PublishService.Field?.none)
                        ForEach(PublishService.Field.searchableForStatement) {
                            Text($0.label).tag(PublishService.Field?.some($0))
                        }
                    }
                    Picker("Sort by", selection: $sortField) {
                        Text("Height (default)").tag(PublishService.Field?.none)
                        ForEach(PublishService.Field.sortableForStatement) {
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

            Button {
                showComposer = true
            } label: {
                Label("Declare", systemImage: "text.quote")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!session.canSign)
            .help(session.canSign
                  ? "Write a formal statement and carve it"
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
        }
    }

    // MARK: - list

    private var list: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(filtered) { statement in
                    row(statement)
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
    private func row(_ statement: Statement) -> some View {
        HStack(alignment: .top, spacing: 12) {
            FidAvatarView(fid: statement.publisher ?? "", size: 40)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(statement.name)
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)

                    if statement.publisher == session.liveFid { chip("Mine", color: .blue) }
                    if statement.onChain == false {
                        chip("Draft", color: .gray)
                    } else if statement.onChain == nil {
                        chip("Broadcast", color: .orange)
                    }

                    Spacer(minLength: 8)

                    if let t = statement.birthTime {
                        Text(Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(t))))
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                if let content = statement.content, !content.isEmpty {
                    Text(content)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                fidLine("By", statement.publisher)

                if statement.onChain == false {
                    HStack(spacing: 8) {
                        Button {
                            editingDraft = statement
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        .controlSize(.small)
                        Button("Discard", role: .destructive) { discardDraft(statement) }
                            .controlSize(.small)
                    }
                    .padding(.top, 2)
                }
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            if statement.onChain == false { editingDraft = statement } else { reading = statement }
        }
        .contextMenu {
            if statement.onChain == false {
                Button("Edit draft") { editingDraft = statement }
                Button("Discard draft", role: .destructive) { discardDraft(statement) }
            } else {
                Button("Read") { reading = statement }
            }
            Button("Copy statement ID") { copyToPasteboard(statement.id) }
            if let publisher = statement.publisher {
                Button("Copy publisher FID") { copyToPasteboard(publisher) }
            }
        }
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
        loadError = nil
        showingCache = false
    }

    private func loadLocal() {
        do {
            drafts = try session.statements.drafts()
            if rows.isEmpty, tab == .mine {
                rows = try session.statements.all().filter {
                    $0.onChain != false && $0.publisher == session.liveFid
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
            let page = try await session.publish.fetchStatements(
                publisher: tab.isMine ? session.liveFid : nil,
                ascending: ascending,
                size: Self.pageSize
            )
            rows = page.rows
            total = page.total
            cursor = page.last
            hasMore = page.rows.count >= Self.pageSize
            chainQuery = nil
            loadError = nil
            showingCache = false
            // Only Mine owns the cache — caching Discover would fill
            // this identity's store with strangers' declarations.
            if tab == .mine {
                _ = try? session.statements.replaceChainRows(with: page.rows)
            }
            await resolveNames(for: page.rows)
        } catch {
            clearRows()
            loadError = String(describing: error)
            loadLocalFallback()
        }
    }

    private func loadLocalFallback() {
        guard rows.isEmpty, tab == .mine else { return }
        if let cached = try? session.statements.all().filter({
            $0.onChain != false && $0.publisher == session.liveFid
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
            let page: PublishService.Page<Statement>
            if let q = chainQuery {
                page = try await session.publish.searchStatements(
                    query: q, inField: inField,
                    publisher: tab.isMine ? session.liveFid : nil,
                    sortField: sortField, ascending: ascending,
                    after: cursor, size: Self.pageSize
                )
            } else {
                page = try await session.publish.fetchStatements(
                    publisher: tab.isMine ? session.liveFid : nil,
                    ascending: ascending, after: cursor, size: Self.pageSize
                )
            }
            let known = Set(rows.map(\.id))
            rows.append(contentsOf: page.rows.filter { !known.contains($0.id) })
            self.cursor = page.last
            hasMore = page.rows.count >= Self.pageSize
            await resolveNames(for: page.rows)
        } catch {
            actionError = String(describing: error)
        }
    }

    private func searchChain() async {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return }
        loading = true
        defer { loading = false }
        do {
            let page = try await session.publish.searchStatements(
                query: q, inField: inField,
                publisher: tab.isMine ? session.liveFid : nil,
                sortField: sortField, ascending: ascending,
                size: Self.pageSize
            )
            rows = page.rows
            total = page.total
            cursor = page.last
            hasMore = page.rows.count >= Self.pageSize
            chainQuery = q
            loadError = nil
            showingCache = false
            searchText = ""
            await resolveNames(for: page.rows)
        } catch {
            loadError = String(describing: error)
        }
    }

    private func resolveNames(for statements: [Statement]) async {
        var wanted = Set<String>()
        for s in statements {
            if let p = s.publisher, !p.isEmpty, names[p] == nil { wanted.insert(p) }
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

    private func discardDraft(_ statement: Statement) {
        _ = try? session.statements.remove(id: statement.id)
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
                Label("You haven't made a statement", systemImage: "text.quote")
                    .font(.headline)
                Text("A statement is a formal declaration carved onto the chain under your FID — a notice, a commitment, a public position. Unlike everything else in Publish, the text itself goes into the transaction rather than to DISK, so nobody can take it down. And unlike everything else, it cannot be edited or deleted afterwards. That is what it is for.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .discover:
                Label("Nothing declared yet", systemImage: "globe")
                    .font(.headline)
                Text("This is every statement on the chain, not just yours. If it is empty, nobody has made one on this index yet.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .drafts:
                Label("No drafts", systemImage: "tray")
                    .font(.headline)
                Text("Write a statement and choose Save draft to keep it here without carving it. A draft is the only form of a statement you can still change your mind about — once carved, that is the end of it.")
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
