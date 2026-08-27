import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// On-chain proofs — the Mac port of Android's `ProofActivity` +
/// `IssueProofActivity` + `DestroyProofActivity` +
/// `ProofDestroyedActivity`, as one pane.
///
/// A proof is a public statement carved onto the chain: a title, a
/// body, an issuer, an owner, and the people the issuer invited to
/// countersign. **Nothing on this path is encrypted**, which makes it
/// the opposite of the Secrets pane in every way that matters — the
/// point of a proof is that you can hand it to someone who does not
/// trust you and they can check it themselves.
///
/// **Three tabs, one query.** Live, Destroyed and Drafts are three views
/// of the same fetch (see ``ProofService/fetchProofs(for:destroyed:ascending:after:size:timeoutMs:)``
/// — the server matches your FID against `owner`, `issuer` *and*
/// `cosignersInvited` in one clause). Android splits Destroyed into its
/// own `ProofDestroyedActivity` with its own paging, sorting and
/// statistics code, all of which is this pane with one query flag
/// flipped.
struct ProofsView: View {
    let session: ActiveSession

    private static let pageSize = 25

    private enum Tab: String, CaseIterable, Identifiable {
        case live = "Live"
        /// The protocol's own word. It was "Retired" briefly, which
        /// meant nothing to anyone: the op is `destroy`, the button says
        /// Destroy and the row chip says Destroyed, so a third word for
        /// the same thing was one word too many.
        case destroyed = "Destroyed"
        case drafts = "Drafts"
        var id: String { rawValue }

        /// What the chain query's `destroyed` flag should be. Drafts
        /// never touch the chain.
        var wantsDestroyed: Bool? { self == .drafts ? nil : (self == .destroyed) }
    }

    @State private var tab: Tab = .live
    @State private var rows: [Proof] = []
    @State private var drafts: [Proof] = []
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
    @State private var inField: ProofService.Field?
    @State private var sortField: ProofService.Field?
    @State private var ascending = false

    /// FID → CID for the issuers and owners on screen.
    @State private var names: [String: String] = [:]

    @State private var showIssueSheet = false
    /// The draft open in the editor. Only drafts are editable — a
    /// carved proof is whatever the chain says it is.
    @State private var editingDraft: Proof?
    @State private var detail: Proof?
    @State private var transferring: Proof?
    @State private var pendingDestroy: [Proof] = []
    @State private var busyId: String?
    @State private var actionError: String?
    @State private var actionNote: String?

    /// Ids ticked for a bulk destroy. Empty means selection mode is off
    /// — the protocol takes a list of ids per `destroy`, so ticking
    /// several and paying one miner fee is the difference the mode
    /// exists for.
    @State private var selection: Set<String> = []
    @State private var selecting = false

    // MARK: - derived

    private var source: [Proof] { tab == .drafts ? drafts : rows }

    private var filtered: [Proof] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return source }
        return source.filter { $0.matches(query: q) }
    }

    private var awaitingMe: Int {
        rows.filter { $0.awaitsSignature(from: session.liveFid) }.count
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
                    Label("Couldn't load your proofs", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    CopyableText(err, font: .callout).foregroundStyle(.red)
                    Text("Nothing is shown rather than the last list that loaded — a failed query has no answer, and rows left over from a different one would be read as this one's.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else if loading && source.isEmpty {
                // The rows were cleared for this tab, so there is nothing
                // to keep on screen while the fetch runs. Say so, rather
                // than drawing an empty list frame that reads as "none".
                card {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Loading \(tab.rawValue.lowercased()) proofs…")
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
            // Every tab starts empty and can only be filled by a fetch
            // made *for that tab*. Leaving the old rows up while the new
            // fetch is in flight is how Destroyed came to show Live's
            // list: if the fetch then failed, nothing ever replaced them
            // and the pane sat there displaying the wrong query's answer
            // under the right query's heading.
            clearRows()
            if tab == .drafts {
                loadLocal()
            } else {
                Task { await refresh() }
            }
        }
        .sheet(isPresented: $showIssueSheet) {
            IssueProofSheet(
                session: session,
                onDone: { result in
                    showIssueSheet = false
                    loadLocal()
                    switch result {
                    case .carved(let proof):
                        actionError = nil
                        actionNote = "Issued — tx \(proof.id.elidingMiddle(head: 8, tail: 8)). It shows as On-chain once a block confirms it."
                        tab = .live
                        Task { await refresh() }
                    case .draft:
                        actionError = nil
                        actionNote = "Saved as a draft. Nothing is on the chain until you carve it."
                        tab = .drafts
                    case .cancelled:
                        break
                    }
                }
            )
        }
        .sheet(item: $editingDraft) { draft in
            IssueProofSheet(session: session, editing: draft) { result in
                editingDraft = nil
                loadLocal()
                switch result {
                case .carved(let proof):
                    actionError = nil
                    actionNote = "Issued — tx \(proof.id.elidingMiddle(head: 8, tail: 8)). It shows as On-chain once a block confirms it."
                    tab = .live
                    Task { await refresh() }
                case .draft:
                    actionError = nil
                    actionNote = "Draft saved."
                case .cancelled:
                    break
                }
            }
        }
        .sheet(item: $detail) { p in
            ProofDetailSheet(
                session: session,
                proof: p,
                name: { names[$0] },
                onClose: { detail = nil }
            )
        }
        .sheet(item: $transferring) { p in
            TransferProofSheet(
                session: session,
                proof: p,
                onDone: { txid in
                    transferring = nil
                    if let txid {
                        actionError = nil
                        actionNote = "Transfer broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). Ownership moves when a block confirms it."
                        Task { await refresh() }
                    }
                }
            )
        }
        .alert(
            destroyAlertTitle,
            isPresented: Binding(
                get: { !pendingDestroy.isEmpty },
                set: { if !$0 { pendingDestroy = [] } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingDestroy = [] }
            Button("Destroy", role: .destructive) {
                let targets = pendingDestroy
                pendingDestroy = []
                Task { await destroy(targets) }
            }
        } message: {
            Text("Destroying retires a proof: it stays on the chain and stays readable, flagged destroyed, but it is no longer in force. That cannot be undone, and it costs one miner fee for the whole batch.")
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
                        Text("Any field").tag(ProofService.Field?.none)
                        ForEach(ProofService.Field.searchable) {
                            Text($0.label).tag(ProofService.Field?.some($0))
                        }
                    }
                    Picker("Sort by", selection: $sortField) {
                        Text("Height (default)").tag(ProofService.Field?.none)
                        ForEach(ProofService.Field.sortable) {
                            Text($0.label).tag(ProofService.Field?.some($0))
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

            if tab == .live && session.canSign {
                Button(selecting ? "Done" : "Select") {
                    selecting.toggle()
                    if !selecting { selection = [] }
                }
                .help("Tick several proofs and destroy them in one carve — one miner fee for the batch")
            }

            Button {
                showIssueSheet = true
            } label: {
                Label("Issue", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!session.canSign)
            .help(session.canSign
                  ? "Write a new proof"
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
                if awaitingMe > 0 && tab == .live {
                    countChip("\(awaitingMe) awaiting your signature", color: .orange)
                }
                if !selection.isEmpty {
                    countChip("\(selection.count) selected", color: .blue)
                    Button("Destroy selected", role: .destructive) {
                        pendingDestroy = rows.filter { selection.contains($0.id) }
                    }
                    .font(.caption)
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
                ForEach(filtered) { proof in
                    row(proof)
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
    private func row(_ proof: Proof) -> some View {
        HStack(alignment: .top, spacing: 12) {
            if selecting && tab == .live {
                Toggle("", isOn: Binding(
                    get: { selection.contains(proof.id) },
                    set: { on in
                        if on { selection.insert(proof.id) } else { selection.remove(proof.id) }
                    }
                ))
                .labelsHidden()
                .disabled(!proof.canDestroy(as: session.liveFid))
                .help(proof.canDestroy(as: session.liveFid)
                      ? "Include in the batch destroy"
                      : "Only the current owner can destroy a proof")
            }

            FidAvatarView(fid: proof.issuer ?? "", size: 40)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(proof.title?.isEmpty == false ? proof.title! : "Untitled proof")
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)

                    ForEach(chips(for: proof), id: \.0) { text, color in
                        chip(text, color: color)
                    }

                    Spacer(minLength: 8)

                    if let t = proof.lastTime {
                        Text(Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(t))))
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                if let content = proof.content, !content.isEmpty {
                    Text(content)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                HStack(spacing: 10) {
                    fidLine("Issuer", proof.issuer)
                    if proof.owner != proof.issuer { fidLine("Owner", proof.owner) }
                    if let invited = proof.cosignersInvited, !invited.isEmpty {
                        Text("\(invited.count - proof.cosignersPending.count)/\(invited.count) signed")
                            .font(.caption2)
                            .foregroundStyle(proof.isFullySigned ? .green : .orange)
                    }
                }

                actions(for: proof)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            // A draft's tap opens the editor rather than a read-only
            // detail sheet: everything on a draft is still changeable,
            // so "look at it" and "work on it" are the same gesture.
            if proof.onChain == false { editingDraft = proof } else { detail = proof }
        }
        .contextMenu {
            if proof.onChain == false {
                Button("Edit draft") { editingDraft = proof }
            }
            Button("Show details") { detail = proof }
            Button("Copy proof ID") { copyToPasteboard(proof.id) }
            if let issuer = proof.issuer { Button("Copy issuer FID") { copyToPasteboard(issuer) } }
            if proof.canDestroy(as: session.liveFid) && session.canSign {
                Divider()
                Button("Destroy…", role: .destructive) { pendingDestroy = [proof] }
            }
        }
    }

    @ViewBuilder
    private func actions(for proof: Proof) -> some View {
        let busy = busyId == proof.id
        HStack(spacing: 8) {
            if proof.onChain == false {
                Button {
                    editingDraft = proof
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .controlSize(.small)
                .disabled(busy)

                Button {
                    Task { await carveDraft(proof) }
                } label: {
                    Label("Carve on chain", systemImage: "square.and.arrow.up")
                }
                .controlSize(.small)
                .disabled(busy || !session.canSign)

                Button("Discard", role: .destructive) {
                    discardDraft(proof)
                }
                .controlSize(.small)
            } else {
                if proof.awaitsSignature(from: session.liveFid) {
                    Button {
                        Task { await sign(proof) }
                    } label: {
                        Label("Countersign", systemImage: "signature")
                    }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
                    .disabled(busy || !session.canSign)
                    .help(session.canSign
                          ? "Sign this proof — the carve is signed by your key, which is the signature"
                          : "Watch-only identity — there is no key here to countersign with")
                }
                if proof.canTransfer(as: session.liveFid) {
                    Button {
                        transferring = proof
                    } label: {
                        Label("Transfer", systemImage: "arrow.right.circle")
                    }
                    .controlSize(.small)
                    .disabled(busy || !session.canSign)
                }
            }
            if busy { ProgressView().controlSize(.small) }
        }
        .padding(.top, 2)
    }

    /// Role and state chips, in the order that answers "what is this to
    /// me" before "what state is it in".
    private func chips(for proof: Proof) -> [(String, Color)] {
        var out: [(String, Color)] = []
        let me = session.liveFid
        if proof.issuer == me && proof.owner == me {
            out.append(("Mine", .blue))
        } else if proof.issuer == me {
            out.append(("Issued", .purple))
        } else if proof.owner == me {
            out.append(("Held", .blue))
        } else if proof.cosignersInvited?.contains(me) == true {
            out.append(("Cosigner", .teal))
        }

        if proof.destroyed == true {
            out.append(("Destroyed", .red))
        } else if proof.onChain == false {
            out.append(("Draft", .gray))
        } else if proof.onChain == nil {
            out.append(("Broadcast", .orange))
        }

        if proof.transferable == true { out.append(("Transferable", .indigo)) }
        if proof.awaitsSignature(from: me) { out.append(("Needs you", .orange)) }
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

    /// Keep only the rows that belong in the current tab, and say so
    /// when the server sent others.
    ///
    /// The `destroyed` clause goes to the index on every query, but a
    /// filter the server silently drops is indistinguishable from one it
    /// applied — and the symptom is the worst kind: Live and Destroyed
    /// showing byte-for-byte the same list, with nothing to say which of
    /// the two is lying. So the tab's meaning is enforced here, where it
    /// is defined, and a mismatch is reported rather than hidden: rows
    /// arriving on the wrong tab means the clause did not take, which is
    /// worth knowing because it also means the tab is paging through a
    /// mixed result and its "Load more" will thin out.
    private func belongingToTab(_ proofs: [Proof]) -> (kept: [Proof], dropped: Int) {
        guard let want = tab.wantsDestroyed else { return (proofs, 0) }
        let kept = proofs.filter { $0.isDestroyed == want }
        return (kept, proofs.count - kept.count)
    }

    private func noteServerFilterMismatch(_ dropped: Int, of total: Int) {
        guard dropped > 0 else { return }
        note = "The server returned \(dropped) of \(total) row\(total == 1 ? "" : "s") that don't belong on this tab — it ignored the destroyed filter, so this list is filtered here instead and Load more may return fewer rows than it fetches."
    }

    private func loadLocal() {
        do {
            drafts = try session.proofs.drafts()
            // Seeding from the cache is a Live-tab affordance: it is the
            // live list, and this runs whenever a sheet closes, so
            // without the guard it would quietly repopulate the
            // Destroyed tab with live proofs.
            if rows.isEmpty, tab == .live {
                rows = try session.proofs.all().filter { $0.onChain != false }
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
            let page = try await session.proofService.fetchProofs(
                for: session.liveFid,
                destroyed: tab.wantsDestroyed,
                ascending: ascending,
                size: Self.pageSize
            )
            let (kept, dropped) = belongingToTab(page.proofs)
            rows = kept
            // A server-side total counts what the server matched, which
            // is not what is on screen once its filter has been
            // second-guessed here.
            total = dropped > 0 ? nil : page.total
            cursor = page.last
            hasMore = page.proofs.count >= Self.pageSize
            chainQuery = nil
            loadError = nil
            showingCache = false
            note = nil
            noteServerFilterMismatch(dropped, of: page.proofs.count)
            // Only the live view owns the cache: caching the destroyed
            // list would have it overwrite the live rows with the
            // records they are the complement of.
            if tab == .live {
                _ = try? session.proofs.replaceChainRows(with: kept)
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

    /// A failed refresh falls back to the cached rows rather than
    /// blanking a pane that had content — and says which it is showing.
    ///
    /// **Live only.** The cache holds the live list; offering it on the
    /// Destroyed tab would answer a question nobody asked with the
    /// complement of the right records, which is precisely the confusion
    /// this pane already had once.
    private func loadLocalFallback() {
        guard rows.isEmpty, tab == .live else { return }
        if let cached = try? session.proofs.all().filter({ $0.onChain != false }), !cached.isEmpty {
            rows = cached
            showingCache = true
            // The cache is the live list, so it is trustworthy here only
            // to the extent the tab agrees with it.
            rows = belongingToTab(rows).kept
        }
    }

    private func searchChain() async {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return }
        loading = true
        defer { loading = false }
        do {
            let page = try await session.proofService.search(
                for: session.liveFid,
                query: q,
                inField: inField,
                sortField: sortField,
                ascending: ascending,
                destroyed: tab.wantsDestroyed,
                size: Self.pageSize
            )
            let (kept, dropped) = belongingToTab(page.proofs)
            rows = kept
            total = dropped > 0 ? nil : page.total
            cursor = page.last
            hasMore = page.proofs.count >= Self.pageSize
            chainQuery = q
            // The box now describes what is on screen, so leaving the
            // text in it would filter the results a second time.
            searchText = ""
            loadError = nil
            showingCache = false
            noteServerFilterMismatch(dropped, of: page.proofs.count)
            await resolveNames(for: kept)
        } catch {
            // As in `refresh`: a failed search has no results, and the
            // rows it would otherwise leave up are the browse list, which
            // would read as results.
            clearRows()
            loadError = String(describing: error)
        }
    }

    private func loadMore() async {
        guard !loadingMore, let after = cursor else { return }
        loadingMore = true
        defer { loadingMore = false }
        do {
            let page: ProofService.Page
            if let q = chainQuery {
                page = try await session.proofService.search(
                    for: session.liveFid, query: q,
                    inField: inField, sortField: sortField,
                    ascending: ascending, destroyed: tab.wantsDestroyed,
                    after: after, size: Self.pageSize
                )
            } else {
                page = try await session.proofService.fetchProofs(
                    for: session.liveFid, destroyed: tab.wantsDestroyed,
                    ascending: ascending, after: after, size: Self.pageSize
                )
            }
            let known = Set(rows.map(\.id))
            let fresh = belongingToTab(page.proofs).kept.filter { !known.contains($0.id) }
            rows.append(contentsOf: fresh)
            // Keep the cache in step with what is on screen. A refresh
            // resets it to the first page (`replaceChainRows`); pages
            // loaded after that are added, not swapped in, so going
            // offline mid-scroll keeps everything already fetched.
            if tab == .live {
                for proof in fresh { try? session.proofs.upsert(proof) }
            }
            cursor = page.last
            hasMore = page.proofs.count >= Self.pageSize
            await resolveNames(for: page.proofs)
        } catch {
            note = "Couldn't load more: \(error)"
        }
    }

    /// Contacts first (free), then one directory batch for the rest —
    /// the same two-step every other pane uses to put names on FIDs.
    private func resolveNames(for proofs: [Proof]) async {
        var wanted = Set<String>()
        for p in proofs {
            if let i = p.issuer, !i.isEmpty, names[i] == nil { wanted.insert(i) }
            if let o = p.owner, !o.isEmpty, names[o] == nil { wanted.insert(o) }
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

    private func sign(_ proof: Proof) async {
        busyId = proof.id
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let txid = try await session.carveProofSignOnChain(proofId: proof.id)
            actionNote = "Countersigned — tx \(txid.elidingMiddle(head: 8, tail: 8)). Your signature shows on the proof once a block confirms it."
            await refresh()
        } catch {
            actionError = "Couldn't countersign: \(error)"
        }
    }

    private func destroy(_ targets: [Proof]) async {
        let ids = targets.map(\.id)
        guard !ids.isEmpty else { return }
        busyId = ids.first
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let txid = try await session.carveProofDestroyOnChain(proofIds: ids)
            selection = []
            selecting = false
            actionNote = "Destroy broadcast for \(ids.count) proof\(ids.count == 1 ? "" : "s") — tx \(txid.elidingMiddle(head: 8, tail: 8))."
            await refresh()
        } catch {
            actionError = "Couldn't destroy: \(error)"
        }
    }

    private func carveDraft(_ draft: Proof) async {
        busyId = draft.id
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let proof = try await session.carveProofIssueOnChain(
                title: draft.title ?? "",
                content: draft.content ?? "",
                cosigners: draft.cosignersInvited ?? [],
                transferable: draft.transferable ?? false,
                allSignsRequired: draft.allSignsRequired ?? false,
                draftId: draft.id
            )
            actionNote = "Issued — tx \(proof.id.elidingMiddle(head: 8, tail: 8)). It shows as On-chain once a block confirms it."
            loadLocal()
            tab = .live
            await refresh()
        } catch {
            actionError = "Couldn't carve: \(error)"
        }
    }

    private func discardDraft(_ draft: Proof) {
        _ = try? session.proofs.remove(id: draft.id)
        loadLocal()
    }

    private var destroyAlertTitle: String {
        if pendingDestroy.count == 1 {
            return "Destroy “\(pendingDestroy[0].name.elidingMiddle(head: 20, tail: 8))”?"
        }
        return "Destroy \(pendingDestroy.count) proofs?"
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
            case .live:
                Label("No proofs yet", systemImage: "checkmark.seal")
                    .font(.headline)
                Text("A proof is a public statement carved onto the chain — a receipt, a certificate, an agreement. It has a title and a body, its ID is the transaction that issued it, and the issuer can invite other people to countersign. Nothing here is encrypted: that is what makes a proof something you can show to someone who does not trust you.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .destroyed:
                Label("Nothing destroyed", systemImage: "archivebox")
                    .font(.headline)
                Text("Destroying a proof retires it: the record stays on the chain and stays readable, flagged destroyed, but it is no longer in force. None of yours have been destroyed.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .drafts:
                Label("No drafts", systemImage: "doc.text")
                    .font(.headline)
                Text("Issue a proof and choose Save draft to keep it here without paying for a carve. A draft exists only on this Mac, and stays editable until you carve it — after that the chain's copy is the proof, and nothing can change it.")
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
