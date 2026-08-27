import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// The protocol registry — the Mac port of Android's eight protocol
/// activities (`Protocol`, `CreateProtocol`, `UpdateProtocol`,
/// `StopProtocol`, `StoppedProtocol`, `RecoverProtocol`,
/// `CloseProtocol`, `HiddenProtocol`) as one pane.
///
/// A protocol record registers a specification: what it is called, what
/// version, where the document lives, who published it and who serves
/// it. It is the first of the four **Construct** records — Protocol,
/// Service, Code and App — which is why the sidebar gives them their
/// own heading: they register what the network is made of, as opposed
/// to what passes through it.
///
/// **This registry is chain-wide, and that is the difference from
/// Proofs.** A proof list is yours by construction; a registry is worth
/// having precisely because it holds everybody's. So Registry browses
/// the whole index and Mine is the filter you opt into — Android's More
/// ▸ My protocols.
///
/// **Four tabs, two of them local.** Registry and Mine are chain
/// queries. Drafts are records composed here and never carved; Hidden
/// is a local decision to stop looking at rows that carry on existing.
/// Android gives Stopped and Hidden an activity each — 983 lines of
/// paging, sorting and statistics between them — and both are this pane
/// with one filter changed.
struct ProtocolsView: View {
    let session: ActiveSession

    private static let pageSize = 25

    private enum Tab: String, CaseIterable, Identifiable {
        case registry = "Registry"
        case mine = "Mine"
        case drafts = "Drafts"
        case hidden = "Hidden"
        var id: String { rawValue }

        var isChainQuery: Bool { self == .registry || self == .mine }
    }

    /// Which lifecycle state the chain query asks for. Its own control
    /// rather than a tab, because it is orthogonal to *whose* records
    /// are being listed — Android has no equivalent at all: its list is
    /// hardwired to `active = true` and its Stopped activity to the
    /// complement, so a closed protocol is reachable from neither.
    private enum StateFilter: String, CaseIterable, Identifiable {
        case live = "Live"
        case stopped = "Stopped"
        case closed = "Closed"
        case all = "All states"
        var id: String { rawValue }

        var active: Bool? {
            switch self {
            case .live:    return true
            case .stopped: return false
            case .closed:  return nil
            case .all:     return nil
            }
        }

        var closed: Bool? {
            switch self {
            case .live:    return false
            case .stopped: return false
            case .closed:  return true
            case .all:     return nil
            }
        }

        /// Whether a row belongs on this filter — the same question the
        /// query asks, asked again locally. See ``belongingToFilter``.
        func admits(_ spec: ProtocolSpec) -> Bool {
            switch self {
            case .all:     return true
            case .closed:  return spec.isClosed
            case .stopped: return spec.isStopped
            case .live:    return !spec.isClosed && spec.active != false
            }
        }
    }

    @State private var tab: Tab = .registry
    @State private var stateFilter: StateFilter = .live

    @State private var rows: [ProtocolSpec] = []
    @State private var drafts: [ProtocolSpec] = []
    @State private var hiddenRows: [ProtocolSpec] = []
    @State private var hiddenIds: Set<String> = []
    @State private var total: Int64?
    @State private var cursor: [String]?
    @State private var hasMore = false

    @State private var loading = false
    @State private var loadingMore = false
    @State private var loadError: String?
    @State private var note: String?
    @State private var didAutoLoad = false
    /// Set when the last refresh failed and the rows came from the
    /// cached window instead.
    @State private var showingCache = false

    @State private var searchText = ""
    /// Non-nil while the rows on screen are a chain search's results.
    @State private var chainQuery: String?
    @State private var inField: ProtocolService.Field?
    @State private var sortField: ProtocolService.Field?
    @State private var ascending = false

    /// FID → CID for the owners on screen.
    @State private var names: [String: String] = [:]

    @State private var composing: ProtocolComposeTarget?
    @State private var detail: ProtocolSpec?
    @State private var closing: [ProtocolSpec] = []
    @State private var pendingStop: [ProtocolSpec] = []
    @State private var pendingRecover: [ProtocolSpec] = []
    @State private var busyId: String?
    @State private var actionError: String?
    @State private var actionNote: String?

    /// Ids ticked for a bulk stop / recover / close. Empty means
    /// selection mode is off — the three ops take a list of ids, so
    /// ticking several and paying one miner fee is the difference the
    /// mode exists for.
    @State private var selection: Set<String> = []
    @State private var selecting = false

    // MARK: - derived

    private var source: [ProtocolSpec] {
        switch tab {
        case .drafts: return drafts
        case .hidden: return hiddenRows
        default:      return rows.filter { !hiddenIds.contains($0.id) }
        }
    }

    private var filtered: [ProtocolSpec] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return source }
        return source.filter { $0.matches(query: q) }
    }

    private var selected: [ProtocolSpec] {
        source.filter { selection.contains($0.id) }
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
                    Label("Couldn't load the registry", systemImage: "exclamationmark.triangle")
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
                        Text("Loading protocols…")
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
        .frame(minWidth: 680)
        .onAppear {
            guard !didAutoLoad else { return }
            didAutoLoad = true
            loadLocal()
            Task { await refresh() }
        }
        .onChange(of: tab) { _, _ in
            selection = []
            selecting = false
            // Every tab starts empty and can only be filled by a fetch
            // made *for that tab*. Leaving the old rows up while the new
            // fetch is in flight is how a pane comes to show one query's
            // answer under another query's heading.
            clearRows()
            loadLocal()
            if tab.isChainQuery { Task { await refresh() } }
        }
        .onChange(of: stateFilter) { _, _ in
            guard tab.isChainQuery else { return }
            clearRows()
            Task { await refresh() }
        }
        .sheet(item: $composing) { target in
            PublishProtocolSheet(session: session, target: target) { result in
                composing = nil
                loadLocal()
                switch result {
                case .published(let spec):
                    actionError = nil
                    actionNote = "Published — tx \(spec.id.elidingMiddle(head: 8, tail: 8)). It shows as On-chain once a block confirms it."
                    tab = .mine
                    Task { await refresh() }
                case .updated(let txid):
                    actionError = nil
                    actionNote = "Update broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The record changes when a block confirms it."
                    Task { await refresh() }
                case .draft:
                    actionError = nil
                    actionNote = "Saved as a draft. Nothing is on the chain until you publish it."
                    tab = .drafts
                case .cancelled:
                    break
                }
            }
        }
        .sheet(item: $detail) { spec in
            ProtocolDetailSheet(
                session: session,
                spec: spec,
                name: { names[$0] },
                onClose: { detail = nil }
            )
        }
        .sheet(isPresented: Binding(
            get: { !closing.isEmpty },
            set: { if !$0 { closing = [] } }
        )) {
            CloseProtocolSheet(session: session, specs: closing) { txid in
                let ids = closing.map(\.id)
                closing = []
                if let txid {
                    selection = []
                    selecting = false
                    actionError = nil
                    actionNote = "Close broadcast for \(ids.count) protocol\(ids.count == 1 ? "" : "s") — tx \(txid.elidingMiddle(head: 8, tail: 8)). Nothing reopens a closed protocol."
                    Task { await refresh() }
                }
            }
        }
        .alert(
            pendingStop.count == 1
                ? "Stop “\(pendingStop[0].displayName.elidingMiddle(head: 20, tail: 8))”?"
                : "Stop \(pendingStop.count) protocols?",
            isPresented: Binding(
                get: { !pendingStop.isEmpty },
                set: { if !$0 { pendingStop = [] } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingStop = [] }
            Button("Stop") {
                let targets = pendingStop
                pendingStop = []
                Task { await stop(targets) }
            }
        } message: {
            Text("Stopping takes a protocol out of force without retiring it: the record stays on the chain, and Recover puts it back. One miner fee for the whole batch.")
        }
        .alert(
            pendingRecover.count == 1
                ? "Recover “\(pendingRecover[0].displayName.elidingMiddle(head: 20, tail: 8))”?"
                : "Recover \(pendingRecover.count) protocols?",
            isPresented: Binding(
                get: { !pendingRecover.isEmpty },
                set: { if !$0 { pendingRecover = [] } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingRecover = [] }
            Button("Recover") {
                let targets = pendingRecover
                pendingRecover = []
                Task { await recover(targets) }
            }
        } message: {
            Text("Recovering puts a stopped protocol back in force. One miner fee for the whole batch.")
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
            .frame(width: 320)

            Spacer(minLength: 8)

            SearchField("Search name, description, FID…", text: $searchText, minWidth: 150)
                .help("Filters the rows loaded here. Search chain looks through the whole index.")

            if tab.isChainQuery {
                // The state picker rides in the toolbar rather than
                // inside the Chain menu, where it started. "Where are my
                // stopped records" had no answer you could see, and a
                // filter parked behind a button labelled Chain reads as
                // part of chain search rather than as the thing that
                // decides which rows are on screen. Stopped and Hidden
                // are each a whole activity in Android; here they are
                // this one control, so it has to be visible.
                Picker("", selection: $stateFilter) {
                    ForEach(StateFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                .help("Live, stopped, closed or all — pick Stopped to find records to recover")

                Menu {
                    Picker("Search in", selection: $inField) {
                        Text("Any field").tag(ProtocolService.Field?.none)
                        ForEach(ProtocolService.Field.searchable) {
                            Text($0.label).tag(ProtocolService.Field?.some($0))
                        }
                    }
                    Picker("Sort by", selection: $sortField) {
                        Text("Height (default)").tag(ProtocolService.Field?.none)
                        ForEach(ProtocolService.Field.sortable) {
                            Text($0.label).tag(ProtocolService.Field?.some($0))
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
                .help("Filter by state, and take this text to the chain index with a field and sort of your choosing")

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

            if tab == .mine && session.canSign {
                Button(selecting ? "Done" : "Select") {
                    selecting.toggle()
                    if !selecting { selection = [] }
                }
                .help("Tick several protocols and stop, recover or close them in one carve — one miner fee for the batch")
            }

            Button {
                composing = .new
            } label: {
                Label("Publish", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!session.canSign)
            .help(session.canSign
                  ? "Register a new protocol"
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
            switch tab {
            case .drafts:
                Text("\(drafts.count) draft\(drafts.count == 1 ? "" : "s") — nothing here is on the chain")
                    .font(.caption).foregroundStyle(.secondary)
            case .hidden:
                Text("\(hiddenRows.count) hidden — hiding is local, and none of these are stopped or closed by it")
                    .font(.caption).foregroundStyle(.secondary)
            default:
                Text("\(source.count) shown\(total.map { " of \($0)" } ?? "")")
                    .font(.caption).foregroundStyle(.secondary)
                countChip(stateFilter.rawValue, color: .secondary)
                if !selection.isEmpty {
                    countChip("\(selection.count) selected", color: .blue)
                    Button("Stop") { pendingStop = selected.filter { $0.canStop(as: session.liveFid) } }
                        .font(.caption)
                        .disabled(!selected.contains { $0.canStop(as: session.liveFid) })
                    Button("Recover") { pendingRecover = selected.filter { $0.canRecover(as: session.liveFid) } }
                        .font(.caption)
                        .disabled(!selected.contains { $0.canRecover(as: session.liveFid) })
                    Button("Close…", role: .destructive) {
                        closing = selected.filter { $0.canClose(as: session.liveFid) }
                    }
                    .font(.caption)
                    .disabled(!selected.contains { $0.canClose(as: session.liveFid) })
                }
                if showingCache {
                    countChip("offline — showing the cached window", color: .orange)
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
                ForEach(filtered) { spec in
                    row(spec)
                        .padding(.vertical, 10)
                        .padding(.horizontal, 16)
                    Divider()
                }
                if tab.isChainQuery {
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
    private func row(_ spec: ProtocolSpec) -> some View {
        HStack(alignment: .top, spacing: 12) {
            if selecting && tab == .mine {
                Toggle("", isOn: Binding(
                    get: { selection.contains(spec.id) },
                    set: { on in
                        if on { selection.insert(spec.id) } else { selection.remove(spec.id) }
                    }
                ))
                .labelsHidden()
                .disabled(!spec.canUpdate(as: session.liveFid))
                .help(spec.canUpdate(as: session.liveFid)
                      ? "Include in the batch"
                      : "Only the owner can carve against a protocol")
            }

            FidAvatarView(fid: spec.owner ?? "", size: 40)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(spec.displayName)
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)

                    ForEach(chips(for: spec), id: \.0) { text, color in
                        chip(text, color: color)
                    }

                    Spacer(minLength: 8)

                    if let t = spec.lastTime {
                        Text(Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(t))))
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                if let desc = spec.desc, !desc.isEmpty {
                    Text(desc)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                HStack(spacing: 10) {
                    fidLine("Owner", spec.owner)
                    if let waiters = spec.waiters, !waiters.isEmpty {
                        Text("\(waiters.count) waiter\(waiters.count == 1 ? "" : "s")")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if let cdd = spec.tCdd, cdd > 0 {
                        Text("\(cdd) cdd")
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    if let rate = spec.tRate, rate > 0 {
                        Text(String(format: "★ %.1f", rate))
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    }
                }

                actions(for: spec)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            // A draft's tap opens the editor rather than a read-only
            // detail sheet: everything on a draft is still changeable,
            // so "look at it" and "work on it" are the same gesture.
            if spec.onChain == false { composing = .draft(spec) } else { detail = spec }
        }
        .contextMenu {
            if spec.onChain == false {
                Button("Edit draft") { composing = .draft(spec) }
            }
            Button("Show details") { detail = spec }
            Button("Copy protocol ID") { copyToPasteboard(spec.id) }
            if let owner = spec.owner { Button("Copy owner FID") { copyToPasteboard(owner) } }
            if spec.onChain != false {
                Divider()
                if hiddenIds.contains(spec.id) {
                    Button("Unhide") { unhide(spec) }
                } else {
                    Button("Hide from my lists") { hide(spec) }
                }
            }
            if spec.canClose(as: session.liveFid) && session.canSign {
                Divider()
                Button("Close…", role: .destructive) { closing = [spec] }
            }
        }
    }

    @ViewBuilder
    private func actions(for spec: ProtocolSpec) -> some View {
        let busy = busyId == spec.id
        HStack(spacing: 8) {
            if spec.onChain == false {
                Button {
                    composing = .draft(spec)
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .controlSize(.small)
                .disabled(busy)

                Button {
                    Task { await publishDraft(spec) }
                } label: {
                    Label("Publish on chain", systemImage: "square.and.arrow.up")
                }
                .controlSize(.small)
                .disabled(busy || !session.canSign)

                Button("Discard", role: .destructive) { discardDraft(spec) }
                    .controlSize(.small)
            } else if tab == .hidden {
                Button {
                    unhide(spec)
                } label: {
                    Label("Unhide", systemImage: "eye")
                }
                .controlSize(.small)
            } else if spec.canUpdate(as: session.liveFid) && session.canSign {
                Button {
                    composing = .update(spec)
                } label: {
                    Label("Update", systemImage: "pencil")
                }
                .controlSize(.small)
                .disabled(busy)

                if spec.canStop(as: session.liveFid) {
                    Button("Stop") { pendingStop = [spec] }
                        .controlSize(.small)
                        .disabled(busy)
                        .help("Out of force, reversibly — Recover puts it back")
                }
                if spec.canRecover(as: session.liveFid) {
                    Button {
                        pendingRecover = [spec]
                    } label: {
                        Label("Recover", systemImage: "arrow.uturn.backward")
                    }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
                    .disabled(busy)
                }
                // Close is the third op an owner has, and until
                // now it lived only in the context menu — reachable
                // by right-click or by entering Select mode, which
                // is no way to find the one action that cannot be
                // undone. It sits last, and opens the sheet rather
                // than carving, so the click is still only a step
                // toward retiring the protocol.
                if spec.canClose(as: session.liveFid) {
                    Button("Close…", role: .destructive) { closing = [spec] }
                        .controlSize(.small)
                        .disabled(busy)
                        .help("Retire it for good — nothing reopens a closed protocol")
                }
            }
            if busy { ProgressView().controlSize(.small) }
        }
        .padding(.top, 2)
    }

    /// Role and state chips, in the order that answers "what is this to
    /// me" before "what state is it in".
    private func chips(for spec: ProtocolSpec) -> [(String, Color)] {
        var out: [(String, Color)] = []
        if spec.owner == session.liveFid { out.append(("Mine", .blue)) }
        if spec.waiters?.contains(session.liveFid) == true { out.append(("Waiter", .teal)) }

        switch spec.state {
        case .closed:    out.append(("Closed", .red))
        case .stopped:   out.append(("Stopped", .orange))
        case .draft:     out.append(("Draft", .gray))
        case .broadcast: out.append(("Broadcast", .orange))
        case .live:      break
        }

        if let ver = spec.ver, !ver.isEmpty { out.append(("v\(ver)", .indigo)) }
        if let sn = spec.sn, !sn.isEmpty { out.append(("sn \(sn)", .secondary)) }
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

    /// Drop everything that described the previous query.
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

    /// Keep only the rows that belong under the current state filter,
    /// and say so when the server sent others.
    ///
    /// The state clauses go to the index on every query, but a filter
    /// the server silently drops is indistinguishable from one it
    /// applied — and the symptom is the worst kind: Live and Stopped
    /// showing byte-for-byte the same list, with nothing to say which is
    /// lying. So the filter's meaning is enforced here, where it is
    /// defined, and a mismatch is reported rather than hidden: it also
    /// means the list is paging through a mixed result and its Load more
    /// will thin out.
    private func belongingToFilter(_ specs: [ProtocolSpec]) -> (kept: [ProtocolSpec], dropped: Int) {
        guard stateFilter != .all else { return (specs, 0) }
        let kept = specs.filter { stateFilter.admits($0) }
        return (kept, specs.count - kept.count)
    }

    private func noteServerFilterMismatch(_ dropped: Int, of total: Int) {
        guard dropped > 0 else { return }
        note = "The server returned \(dropped) of \(total) row\(total == 1 ? "" : "s") that don't match the \(stateFilter.rawValue.lowercased()) filter — it ignored the state clause, so this list is filtered here instead and Load more may return fewer rows than it fetches."
    }

    private func loadLocal() {
        do {
            drafts = try session.protocols.drafts()
            hiddenIds = try session.protocols.hiddenIds()
            hiddenRows = try session.protocols.hidden()
            // Seeding from the cache is a chain-tab affordance, and the
            // window is the registry list — offering it under Drafts or
            // Hidden would answer a question nobody asked.
            if rows.isEmpty, tab.isChainQuery {
                rows = belongingToFilter(try scopedWindow()).kept
                showingCache = !rows.isEmpty
            }
            loadError = nil
        } catch {
            loadError = String(describing: error)
        }
    }

    /// The cached window narrowed to the current tab. Mine is a filter
    /// on the same window, so going offline on it shows your records
    /// rather than everybody's.
    private func scopedWindow() throws -> [ProtocolSpec] {
        let window = try session.protocols.window()
        return tab == .mine ? window.filter { $0.owner == session.liveFid } : window
    }

    private var ownerScope: String? { tab == .mine ? session.liveFid : nil }

    private func refresh() async {
        guard tab.isChainQuery else { return }
        loading = true
        defer { loading = false }
        do {
            let page = try await session.protocolService.fetchProtocols(
                owner: ownerScope,
                active: stateFilter.active,
                closed: stateFilter.closed,
                ascending: ascending,
                size: Self.pageSize
            )
            let (kept, dropped) = belongingToFilter(page.protocols)
            rows = kept
            // A server-side total counts what the server matched, which
            // is not what is on screen once its filter has been
            // second-guessed here.
            total = dropped > 0 ? nil : page.total
            cursor = page.last
            hasMore = page.protocols.count >= Self.pageSize
            chainQuery = nil
            loadError = nil
            showingCache = false
            note = nil
            noteServerFilterMismatch(dropped, of: page.protocols.count)
            // Only the unscoped, unsearched registry owns the cache.
            // Caching a Mine page would have it overwrite the registry
            // window with the small subset you happen to own, and the
            // next offline open would show four rows where the chain has
            // four hundred.
            if tab == .registry, stateFilter == .live {
                try? session.protocols.saveWindow(kept)
            }
            await resolveNames(for: kept)
        } catch {
            // A failed query has no rows, so the pane shows none. Any
            // rows still on screen would be the *previous* query's, and
            // an error banner over a stale list reads as a list.
            clearRows()
            loadError = String(describing: error)
            loadLocalFallback()
        }
    }

    /// A failed refresh falls back to the cached window rather than
    /// blanking a pane that had content — and says which it is showing.
    private func loadLocalFallback() {
        guard rows.isEmpty, tab.isChainQuery else { return }
        if let cached = try? scopedWindow(), !cached.isEmpty {
            rows = belongingToFilter(cached).kept
            showingCache = !rows.isEmpty
        }
    }

    private func searchChain() async {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return }
        loading = true
        defer { loading = false }
        do {
            let page = try await session.protocolService.search(
                query: q,
                inField: inField,
                sortField: sortField,
                ascending: ascending,
                owner: ownerScope,
                active: stateFilter.active,
                closed: stateFilter.closed,
                size: Self.pageSize
            )
            let (kept, dropped) = belongingToFilter(page.protocols)
            rows = kept
            total = dropped > 0 ? nil : page.total
            cursor = page.last
            hasMore = page.protocols.count >= Self.pageSize
            chainQuery = q
            // The chip now describes what is on screen, so leaving the
            // text in the box would filter the results a second time.
            searchText = ""
            loadError = nil
            showingCache = false
            noteServerFilterMismatch(dropped, of: page.protocols.count)
            await resolveNames(for: kept)
        } catch {
            clearRows()
            loadError = String(describing: error)
        }
    }

    private func loadMore() async {
        guard !loadingMore, let after = cursor else { return }
        loadingMore = true
        defer { loadingMore = false }
        do {
            let page: ProtocolService.Page
            if let q = chainQuery {
                page = try await session.protocolService.search(
                    query: q, inField: inField, sortField: sortField,
                    ascending: ascending, owner: ownerScope,
                    active: stateFilter.active, closed: stateFilter.closed,
                    after: after, size: Self.pageSize
                )
            } else {
                page = try await session.protocolService.fetchProtocols(
                    owner: ownerScope,
                    active: stateFilter.active, closed: stateFilter.closed,
                    ascending: ascending, after: after, size: Self.pageSize
                )
            }
            let known = Set(rows.map(\.id))
            let fresh = belongingToFilter(page.protocols).kept.filter { !known.contains($0.id) }
            rows.append(contentsOf: fresh)
            // Keep the cache in step with what is on screen. A refresh
            // resets it to the first page; pages loaded after that are
            // appended, so going offline mid-scroll keeps everything
            // already fetched.
            if tab == .registry, stateFilter == .live, chainQuery == nil {
                try? session.protocols.saveWindow(rows)
            }
            cursor = page.last
            hasMore = page.protocols.count >= Self.pageSize
            await resolveNames(for: page.protocols)
        } catch {
            note = "Couldn't load more: \(error)"
        }
    }

    /// Contacts first (free), then one directory batch for the rest —
    /// the same two-step every other pane uses to put names on FIDs.
    private func resolveNames(for specs: [ProtocolSpec]) async {
        var wanted = Set<String>()
        for s in specs {
            if let o = s.owner, !o.isEmpty, names[o] == nil { wanted.insert(o) }
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

    private func stop(_ targets: [ProtocolSpec]) async {
        let ids = targets.map(\.id)
        guard !ids.isEmpty else { return }
        busyId = ids.first
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let txid = try await session.carveProtocolStopOnChain(pids: ids)
            selection = []
            selecting = false
            actionNote = "Stop broadcast for \(ids.count) protocol\(ids.count == 1 ? "" : "s") — tx \(txid.elidingMiddle(head: 8, tail: 8))."
            await refresh()
        } catch {
            actionError = "Couldn't stop: \(error)"
        }
    }

    private func recover(_ targets: [ProtocolSpec]) async {
        let ids = targets.map(\.id)
        guard !ids.isEmpty else { return }
        busyId = ids.first
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let txid = try await session.carveProtocolRecoverOnChain(pids: ids)
            selection = []
            selecting = false
            actionNote = "Recover broadcast for \(ids.count) protocol\(ids.count == 1 ? "" : "s") — tx \(txid.elidingMiddle(head: 8, tail: 8))."
            await refresh()
        } catch {
            actionError = "Couldn't recover: \(error)"
        }
    }

    private func publishDraft(_ draft: ProtocolSpec) async {
        busyId = draft.id
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let spec = try await session.carveProtocolPublishOnChain(
                name: draft.name ?? "",
                type: draft.type, sn: draft.sn, ver: draft.ver, did: draft.did,
                desc: draft.desc, lang: draft.lang, home: draft.home,
                preDid: draft.prePid, waiters: draft.waiters,
                draftId: draft.id
            )
            actionNote = "Published — tx \(spec.id.elidingMiddle(head: 8, tail: 8)). It shows as On-chain once a block confirms it."
            loadLocal()
            tab = .mine
            await refresh()
        } catch {
            actionError = "Couldn't publish: \(error)"
        }
    }

    private func discardDraft(_ draft: ProtocolSpec) {
        _ = try? session.protocols.removeDraft(id: draft.id)
        loadLocal()
    }

    private func hide(_ spec: ProtocolSpec) {
        try? session.protocols.hide(ids: [spec.id])
        loadLocal()
    }

    private func unhide(_ spec: ProtocolSpec) {
        try? session.protocols.unhide(ids: [spec.id])
        loadLocal()
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
            case .registry:
                Label("Nothing \(stateFilter.rawValue.lowercased()) in the registry", systemImage: "doc.text.magnifyingglass")
                    .font(.headline)
                Text("A protocol record registers a specification: its name, version, language, where the document lives, and who serves it. FEIP itself is registered this way. Publishing one costs a miner fee and nothing else — the chain holds the registration, not the document.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .mine:
                // With a state filter on, "you have published
                // none" is the wrong sentence: you may own a
                // dozen and have stopped none of them. Say
                // which of the two empties this is, and name
                // the way out of the narrower one.
                if stateFilter == .all {
                    Label("You haven't published a protocol", systemImage: "doc.badge.plus")
                        .font(.headline)
                    Text("Publish registers a specification under your FID. You stay its only owner: nobody else can update, stop or close it, and there is no op that transfers one.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    Label("None of your protocols are \(stateFilter.rawValue.lowercased())", systemImage: "line.3.horizontal.decrease.circle")
                        .font(.headline)
                    Text("That is the state filter talking, not your whole list. Set it to All states to see everything you own.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            case .drafts:
                Label("No drafts", systemImage: "doc.text")
                    .font(.headline)
                Text("Publish a protocol and choose Save draft to keep it here without paying for a carve. A draft exists only on this Mac and stays editable; once published, changing it means an update carve that everyone can see.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .hidden:
                Label("Nothing hidden", systemImage: "eye")
                    .font(.headline)
                Text("Hiding a protocol stops it appearing in your lists on this Mac. It is not stopping and it is not closing: nothing is carved, the record carries on existing, and another device still shows it.")
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
