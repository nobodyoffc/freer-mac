import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// The service registry — the Mac port of Android's ten service
/// activities (`ServiceActivity`, `CreateServiceActivity`,
/// `UpdateServiceActivity`, `StopServiceActivity`,
/// `StoppedServiceActivity`, `RecoverServiceActivity`,
/// `CloseServiceActivity`, `HiddenServiceActivity`,
/// `ApiServicesActivity`, `ChangeApiServiceActivity`) plus
/// `ServiceManager`, as one pane.
///
/// A service record registers a **running instance** you can talk to:
/// what it is called, what it offers, where to reach it, who runs it and
/// what it charges. It is the third of the four **Construct** records —
/// Protocol, Service, Code and App — and the one furthest down the
/// chain of claims: a protocol is a specification, a code record is an
/// implementation of one, and a service is an implementation somebody
/// is actually running at an address.
///
/// **What makes this pane different from Protocols and Codes.** Two
/// things. A service is *reachable* — it has an endpoint under `home`,
/// so the rows carry a URL and a component list, and the component is a
/// filter of its own (finding "a DOCK" is the reason most people open
/// this). And a service has **prices**: thirteen fields the other two
/// records have no analogue of, which is also why the byte budget bites
/// soonest here.
///
/// **Four tabs, two of them local.** Registry and Mine are chain
/// queries. Drafts are records composed here and never carved; Hidden is
/// a local decision to stop looking at rows that carry on existing.
/// Android gives Stopped and Hidden an activity each — 982 lines
/// between them — and both are this pane with one filter changed.
struct ServicesView: View {
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
    /// are being listed — Android's list is hardwired to `active = true`
    /// and its `StoppedServiceActivity` to the complement, so a closed
    /// service is reachable from neither.
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
        func admits(_ service: Service) -> Bool {
            switch self {
            case .all:     return true
            case .closed:  return service.isClosed
            case .stopped: return service.isStopped
            case .live:    return !service.isClosed && service.active != false
            }
        }
    }

    /// The component narrowing — "show me the DOCKs".
    ///
    /// **This is the question the service index is usually asked**, and
    /// it is a filter on ``Service/components`` rather than a query on
    /// ``Service/type``: one server publishes one record listing
    /// everything it runs, so `type` matches every FC service on the
    /// chain and tells you nothing.
    private enum ComponentFilter: String, CaseIterable, Identifiable {
        case any = "Any component"
        case dock = "DOCK"
        case disk = "DISK"
        case road = "ROAD"
        case fapi = "FAPI"
        var id: String { rawValue }

        /// The well-known component name, as it appears in a `home` map
        /// and in a `components` list.
        var wire: String? {
            switch self {
            case .any:  return nil
            case .dock: return ServiceName.dock
            case .disk: return ServiceName.disk
            case .road: return ServiceName.road
            case .fapi: return ServiceName.fapi
            }
        }
    }

    @State private var tab: Tab = .registry
    @State private var stateFilter: StateFilter = .live
    @State private var componentFilter: ComponentFilter = .any

    @State private var rows: [Service] = []
    @State private var drafts: [Service] = []
    @State private var hiddenRows: [Service] = []
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
    @State private var inField: ServiceRegistry.Field?
    @State private var sortField: ServiceRegistry.Field?
    @State private var ascending = false

    /// FID → CID for the owners on screen.
    @State private var names: [String: String] = [:]

    @State private var composing: ServiceComposeTarget?
    @State private var detail: Service?
    @State private var closing: [Service] = []
    @State private var pendingStop: [Service] = []
    @State private var pendingRecover: [Service] = []
    @State private var busyId: String?
    @State private var actionError: String?
    @State private var actionNote: String?

    /// Ids ticked for a bulk stop / recover / close. The three ops take
    /// a list, so ticking several and paying one miner fee is the
    /// difference the mode exists for.
    @State private var selection: Set<String> = []
    @State private var selecting = false

    // MARK: - derived

    private var source: [Service] {
        switch tab {
        case .drafts: return drafts
        case .hidden: return hiddenRows
        default:      return rows.filter { !hiddenIds.contains($0.sid) }
        }
    }

    private var filtered: [Service] {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return source }
        return source.filter { $0.matches(query: q) }
    }

    private var selected: [Service] {
        source.filter { selection.contains($0.sid) }
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
                    Label("Couldn't load the service registry", systemImage: "exclamationmark.triangle")
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
                        Text("Loading services…")
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
        .onChange(of: componentFilter) { _, _ in
            guard tab.isChainQuery else { return }
            clearRows()
            Task { await refresh() }
        }
        .sheet(item: $composing) { target in
            PublishServiceSheet(session: session, target: target) { result in
                composing = nil
                loadLocal()
                switch result {
                case .published(let service):
                    actionError = nil
                    actionNote = "Published — tx \(service.sid.elidingMiddle(head: 8, tail: 8)). It shows as On-chain once a block confirms it."
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
        .sheet(item: $detail) { service in
            ServiceDetailSheet(
                session: session,
                service: service,
                name: { names[$0] },
                onClose: { detail = nil }
            )
        }
        .sheet(isPresented: Binding(
            get: { !closing.isEmpty },
            set: { if !$0 { closing = [] } }
        )) {
            CloseServiceSheet(session: session, services: closing) { txid in
                let ids = closing.map(\.sid)
                closing = []
                if let txid {
                    selection = []
                    selecting = false
                    actionError = nil
                    actionNote = "Close broadcast for \(ids.count) service\(ids.count == 1 ? "" : "s") — tx \(txid.elidingMiddle(head: 8, tail: 8)). Nothing reopens a closed record."
                    Task { await refresh() }
                }
            }
        }
        .alert(
            pendingStop.count == 1
                ? "Stop “\(pendingStop[0].displayName.elidingMiddle(head: 20, tail: 8))”?"
                : "Stop \(pendingStop.count) services?",
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
            Text("Stopping takes a service out of force without retiring it: the record stays on the chain, and Recover puts it back. It does not turn the server off — clients are told to stop routing here, and the daemon carries on answering until you stop it yourself. One miner fee for the whole batch.")
        }
        .alert(
            pendingRecover.count == 1
                ? "Recover “\(pendingRecover[0].displayName.elidingMiddle(head: 20, tail: 8))”?"
                : "Recover \(pendingRecover.count) services?",
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
            Text("Recovering puts a stopped service back in force. Check the endpoint under Home still answers before you pay for this — a recovered record sends clients to a URL that may have moved. One miner fee for the whole batch.")
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

            SearchField("Search name, description, component…", text: $searchText, minWidth: 150)
                .help("Filters the rows loaded here. Search chain looks through the whole index.")

            if tab.isChainQuery {
                // The component picker is the first control rather than a
                // menu item: "find me a DOCK" is what this index is
                // mostly asked, and it is the one narrowing that has no
                // equivalent on the other three Construct panes.
                Picker("", selection: $componentFilter) {
                    ForEach(ComponentFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                .help("Narrow to services that actually offer one component — matched against the component list, not the type")

                Picker("", selection: $stateFilter) {
                    ForEach(StateFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                .help("Live, stopped, closed or all — pick Stopped to find records to recover")

                Menu {
                    Picker("Search in", selection: $inField) {
                        Text("Any field").tag(ServiceRegistry.Field?.none)
                        ForEach(ServiceRegistry.Field.searchable) {
                            Text($0.label).tag(ServiceRegistry.Field?.some($0))
                        }
                    }
                    Picker("Sort by", selection: $sortField) {
                        Text("Height (default)").tag(ServiceRegistry.Field?.none)
                        ForEach(ServiceRegistry.Field.sortable) {
                            Text($0.label).tag(ServiceRegistry.Field?.some($0))
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
                .help("Take this text to the chain index with a field and sort of your choosing")

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
                .help("Tick several records and stop, recover or close them in one carve — one miner fee for the batch")
            }

            Button {
                composing = .new
            } label: {
                Label("Publish", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!session.canSign)
            .help(session.canSign
                  ? "Register a service you run"
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
                if componentFilter != .any {
                    countChip(componentFilter.rawValue, color: .teal)
                }
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
                ForEach(filtered) { service in
                    row(service)
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
    private func row(_ service: Service) -> some View {
        HStack(alignment: .top, spacing: 12) {
            if selecting && tab == .mine {
                Toggle("", isOn: Binding(
                    get: { selection.contains(service.sid) },
                    set: { on in
                        if on { selection.insert(service.sid) } else { selection.remove(service.sid) }
                    }
                ))
                .labelsHidden()
                .disabled(!service.canUpdate(as: session.liveFid))
                .help(service.canUpdate(as: session.liveFid)
                      ? "Include in the batch"
                      : "Only the owner can carve against a service")
            }

            FidAvatarView(fid: service.owner ?? "", size: 40)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(service.displayName)
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)

                    ForEach(chips(for: service), id: \.0) { text, color in
                        chip(text, color: color)
                    }

                    Spacer(minLength: 8)

                    if let t = service.lastTime {
                        Text(Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(t))))
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                if let desc = service.desc, !desc.isEmpty {
                    Text(desc)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }

                // The endpoint is what makes this record a service rather
                // than a claim about one, so it is on the row and it is
                // copyable — a URL you cannot copy is a URL you retype.
                if let url = service.apiUrl, !url.isEmpty {
                    HStack(spacing: 4) {
                        Image(systemName: "link").font(.caption2).foregroundStyle(.tertiary)
                        CopyableText(url, font: .system(.caption2, design: .monospaced))
                            .foregroundStyle(.blue)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }

                HStack(spacing: 10) {
                    fidLine("Owner", service.owner)
                    if let codes = service.codes, !codes.isEmpty {
                        Text("\(codes.count) code\(codes.count == 1 ? "" : "s")")
                            .font(.caption2)
                            .foregroundStyle(.indigo)
                    }
                    if let protocols = service.protocols, !protocols.isEmpty {
                        Text("\(protocols.count) protocol\(protocols.count == 1 ? "" : "s")")
                            .font(.caption2)
                            .foregroundStyle(.indigo)
                    }
                    if let waiters = service.waiters, !waiters.isEmpty {
                        Text("\(waiters.count) waiter\(waiters.count == 1 ? "" : "s")")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if let price = priceSummary(service) {
                        Text(price)
                            .font(.caption2)
                            .foregroundStyle(.green)
                    }
                    if let cdd = service.tCdd, cdd > 0 {
                        Text("\(cdd) cdd")
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    if let rate = service.tRate, rate > 0 {
                        Text(String(format: "★ %.1f", rate))
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    }
                }

                actions(for: service)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            // A draft's tap opens the editor rather than a read-only
            // detail sheet: everything on a draft is still changeable,
            // so "look at it" and "work on it" are the same gesture.
            if service.onChain == false { composing = .draft(service) } else { detail = service }
        }
        .contextMenu {
            if service.onChain == false {
                Button("Edit draft") { composing = .draft(service) }
            }
            Button("Show details") { detail = service }
            Button("Copy SID") { copyToPasteboard(service.sid) }
            if let url = service.apiUrl { Button("Copy API URL") { copyToPasteboard(url) } }
            if let owner = service.owner { Button("Copy owner FID") { copyToPasteboard(owner) } }
            if service.onChain != false {
                Divider()
                if hiddenIds.contains(service.sid) {
                    Button("Unhide") { unhide(service) }
                } else {
                    Button("Hide from my lists") { hide(service) }
                }
            }
            if service.canClose(as: session.liveFid) && session.canSign {
                Divider()
                Button("Close…", role: .destructive) { closing = [service] }
            }
        }
    }

    @ViewBuilder
    private func actions(for service: Service) -> some View {
        let busy = busyId == service.sid
        HStack(spacing: 8) {
            if service.onChain == false {
                Button {
                    composing = .draft(service)
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .controlSize(.small)
                .disabled(busy)

                Button {
                    Task { await publishDraft(service) }
                } label: {
                    Label("Publish on chain", systemImage: "square.and.arrow.up")
                }
                .controlSize(.small)
                .disabled(busy || !session.canSign)

                Button("Discard", role: .destructive) { discardDraft(service) }
                    .controlSize(.small)
            } else if tab == .hidden {
                Button {
                    unhide(service)
                } label: {
                    Label("Unhide", systemImage: "eye")
                }
                .controlSize(.small)
            } else if service.canUpdate(as: session.liveFid) && session.canSign {
                Button {
                    composing = .update(service)
                } label: {
                    Label("Update", systemImage: "pencil")
                }
                .controlSize(.small)
                .disabled(busy)

                if service.canStop(as: session.liveFid) {
                    Button("Stop") { pendingStop = [service] }
                        .controlSize(.small)
                        .disabled(busy)
                        .help("Out of force, reversibly — Recover puts it back")
                }
                if service.canRecover(as: session.liveFid) {
                    Button {
                        pendingRecover = [service]
                    } label: {
                        Label("Recover", systemImage: "arrow.uturn.backward")
                    }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
                    .disabled(busy)
                }
                // The third op an owner has. It sits last and opens the
                // sheet rather than carving, so the click is still only
                // a step toward retiring the service.
                if service.canClose(as: session.liveFid) {
                    Button("Close…", role: .destructive) { closing = [service] }
                        .controlSize(.small)
                        .disabled(busy)
                        .help("Retire it for good — nothing reopens a closed record")
                }
            }
            if busy { ProgressView().controlSize(.small) }
        }
        .padding(.top, 2)
    }

    /// Role, state and shape chips, in the order that answers "what is
    /// this to me" before "what state is it in".
    private func chips(for service: Service) -> [(String, Color)] {
        var out: [(String, Color)] = []
        if service.owner == session.liveFid { out.append(("Mine", .blue)) }
        if service.waiters?.contains(session.liveFid) == true { out.append(("Waiter", .teal)) }

        switch service.state {
        case .closed:    out.append(("Closed", .red))
        case .stopped:   out.append(("Stopped", .orange))
        case .draft:     out.append(("Draft", .gray))
        case .broadcast: out.append(("Broadcast", .orange))
        case .live:      break
        }

        if let ver = service.ver, !ver.isEmpty { out.append(("v\(ver)", .indigo)) }
        // Components are what it actually offers, which is the first
        // thing anyone reads a service row for.
        for component in (service.components ?? []).prefix(3) where !component.isEmpty {
            out.append((shortComponent(component), .teal))
        }
        return out
    }

    /// `DOCK@No1_NrC7` reads as `DOCK` on a chip. The owner half is the
    /// same on nearly every component name on the chain, so showing it
    /// costs three chips' width to say nothing.
    private func shortComponent(_ name: String) -> String {
        name.split(separator: "@").first.map(String.init) ?? name
    }

    /// The one price worth a row: whichever headline figure the operator
    /// set, with its currency. The rest are in the detail sheet — a row
    /// with thirteen numbers on it is a spreadsheet.
    private func priceSummary(_ service: Service) -> String? {
        let unit = service.currency?.trimmingCharacters(in: .whitespaces)
        let headline: (String, String)? =
            service.pricePerRequest.map { ($0, "per request") }
            ?? service.pricePerKB.map { ($0, "per KB") }
            ?? service.pricePerKBOut.map { ($0, "per KB out") }
            ?? service.minPayment.map { ($0, "minimum") }
        guard let (value, label) = headline, !value.isEmpty else { return nil }
        return unit.map { "\(value) \($0) \(label)" } ?? "\(value) \(label)"
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

    /// Keep only the rows that belong under the current filters, and say
    /// so when the server sent others.
    ///
    /// The clauses go to the index on every query, but a filter the
    /// server silently drops is indistinguishable from one it applied —
    /// and the symptom is the worst kind: Live and Stopped showing
    /// byte-for-byte the same list, with nothing to say which is lying.
    /// So the filters' meaning is enforced here, where it is defined, and
    /// a mismatch is reported rather than hidden: it also means the list
    /// is paging through a mixed result and its Load more will thin out.
    private func belongingToFilter(_ services: [Service]) -> (kept: [Service], dropped: Int) {
        let component = componentFilter.wire
        guard stateFilter != .all || component != nil else { return (services, 0) }
        let kept = services.filter { row in
            stateFilter.admits(row) && (component.map { row.offers($0) } ?? true)
        }
        return (kept, services.count - kept.count)
    }

    private func noteServerFilterMismatch(_ dropped: Int, of total: Int) {
        guard dropped > 0 else { return }
        note = "The server returned \(dropped) of \(total) row\(total == 1 ? "" : "s") that don't match the filters — it ignored a clause, so this list is filtered here instead and Load more may return fewer rows than it fetches."
    }

    private func loadLocal() {
        do {
            drafts = try session.services.drafts()
            hiddenIds = try session.services.hiddenIds()
            hiddenRows = try session.services.hidden()
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

    /// The cached window narrowed to the current tab. Mine is a filter on
    /// the same window, so going offline on it shows your records rather
    /// than everybody's.
    private func scopedWindow() throws -> [Service] {
        let window = try session.services.window()
        return tab == .mine ? window.filter { $0.owner == session.liveFid } : window
    }

    private var ownerScope: String? { tab == .mine ? session.liveFid : nil }

    private func refresh() async {
        guard tab.isChainQuery else { return }
        loading = true
        defer { loading = false }
        do {
            let page = try await session.serviceRegistry.fetchServices(
                owner: ownerScope,
                offering: componentFilter.wire,
                active: stateFilter.active,
                closed: stateFilter.closed,
                ascending: ascending,
                size: Self.pageSize
            )
            let (kept, dropped) = belongingToFilter(page.services)
            rows = kept
            // A server-side total counts what the server matched, which
            // is not what is on screen once its filter has been
            // second-guessed here.
            total = dropped > 0 ? nil : page.total
            cursor = page.last
            hasMore = page.services.count >= Self.pageSize
            chainQuery = nil
            loadError = nil
            showingCache = false
            note = nil
            noteServerFilterMismatch(dropped, of: page.services.count)
            // Only the unscoped, unnarrowed, unsearched registry owns the
            // cache. Caching a Mine page would overwrite the registry
            // window with the small subset you happen to own; caching a
            // DOCK-only page would leave the offline pane claiming the
            // chain has nothing but DOCKs.
            if tab == .registry, stateFilter == .live, componentFilter == .any {
                try? session.services.saveWindow(kept)
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
            let page = try await session.serviceRegistry.search(
                query: q,
                inField: inField,
                sortField: sortField,
                ascending: ascending,
                owner: ownerScope,
                offering: componentFilter.wire,
                active: stateFilter.active,
                closed: stateFilter.closed,
                size: Self.pageSize
            )
            let (kept, dropped) = belongingToFilter(page.services)
            rows = kept
            total = dropped > 0 ? nil : page.total
            cursor = page.last
            hasMore = page.services.count >= Self.pageSize
            chainQuery = q
            // The chip now describes what is on screen, so leaving the
            // text in the box would filter the results a second time.
            searchText = ""
            loadError = nil
            showingCache = false
            noteServerFilterMismatch(dropped, of: page.services.count)
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
            let page: ServiceRegistry.Page
            if let q = chainQuery {
                page = try await session.serviceRegistry.search(
                    query: q, inField: inField, sortField: sortField,
                    ascending: ascending, owner: ownerScope,
                    offering: componentFilter.wire,
                    active: stateFilter.active, closed: stateFilter.closed,
                    after: after, size: Self.pageSize
                )
            } else {
                page = try await session.serviceRegistry.fetchServices(
                    owner: ownerScope,
                    offering: componentFilter.wire,
                    active: stateFilter.active, closed: stateFilter.closed,
                    ascending: ascending, after: after, size: Self.pageSize
                )
            }
            let known = Set(rows.map(\.sid))
            let fresh = belongingToFilter(page.services).kept.filter { !known.contains($0.sid) }
            rows.append(contentsOf: fresh)
            // Keep the cache in step with what is on screen. A refresh
            // resets it to the first page; pages loaded after that are
            // appended, so going offline mid-scroll keeps everything
            // already fetched.
            if tab == .registry, stateFilter == .live, componentFilter == .any, chainQuery == nil {
                try? session.services.saveWindow(rows)
            }
            cursor = page.last
            hasMore = page.services.count >= Self.pageSize
            await resolveNames(for: page.services)
        } catch {
            note = "Couldn't load more: \(error)"
        }
    }

    /// Contacts first (free), then one directory batch for the rest —
    /// the same two-step every other pane uses to put names on FIDs.
    private func resolveNames(for services: [Service]) async {
        var wanted = Set<String>()
        for s in services {
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

    private func stop(_ targets: [Service]) async {
        let ids = targets.map(\.sid)
        guard !ids.isEmpty else { return }
        busyId = ids.first
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let txid = try await session.carveServiceStopOnChain(sids: ids)
            selection = []
            selecting = false
            actionNote = "Stop broadcast for \(ids.count) service\(ids.count == 1 ? "" : "s") — tx \(txid.elidingMiddle(head: 8, tail: 8))."
            await refresh()
        } catch {
            actionError = "Couldn't stop: \(error)"
        }
    }

    private func recover(_ targets: [Service]) async {
        let ids = targets.map(\.sid)
        guard !ids.isEmpty else { return }
        busyId = ids.first
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let txid = try await session.carveServiceRecoverOnChain(sids: ids)
            selection = []
            selecting = false
            actionNote = "Recover broadcast for \(ids.count) service\(ids.count == 1 ? "" : "s") — tx \(txid.elidingMiddle(head: 8, tail: 8))."
            await refresh()
        } catch {
            actionError = "Couldn't recover: \(error)"
        }
    }

    private func publishDraft(_ draft: Service) async {
        busyId = draft.sid
        defer { busyId = nil }
        actionError = nil
        actionNote = nil
        do {
            let service = try await session.carveServicePublishOnChain(
                stdName: draft.stdName ?? "",
                localNames: draft.localNames,
                desc: draft.desc,
                type: draft.type,
                components: draft.components,
                ver: draft.ver,
                home: draft.home,
                waiters: draft.waiters,
                protocols: draft.protocols,
                codes: draft.codes,
                services: draft.services,
                pricing: draft.pricing,
                draftId: draft.sid
            )
            actionNote = "Published — tx \(service.sid.elidingMiddle(head: 8, tail: 8)). It shows as On-chain once a block confirms it."
            loadLocal()
            tab = .mine
            await refresh()
        } catch {
            actionError = "Couldn't publish: \(error)"
        }
    }

    private func discardDraft(_ draft: Service) {
        _ = try? session.services.removeDraft(id: draft.sid)
        loadLocal()
    }

    private func hide(_ service: Service) {
        try? session.services.hide(ids: [service.sid])
        loadLocal()
    }

    private func unhide(_ service: Service) {
        try? session.services.unhide(ids: [service.sid])
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
                Label(
                    componentFilter == .any
                        ? "Nothing \(stateFilter.rawValue.lowercased()) in the service registry"
                        : "No \(stateFilter.rawValue.lowercased()) service offers \(componentFilter.rawValue)",
                    systemImage: "server.rack"
                )
                .font(.headline)
                Text("A service record registers a running instance: what it offers, where to reach it, who runs it and what it charges. It is the end of the chain the other Construct records start — a protocol is a specification, a code record is an implementation of one, and this is an implementation somebody is actually running at an address.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .mine:
                // With a filter on, "you have published none" is the
                // wrong sentence: you may run a dozen and have stopped
                // none of them. Say which of the two empties this is.
                if stateFilter == .all && componentFilter == .any {
                    Label("You haven't published a service", systemImage: "doc.badge.plus")
                        .font(.headline)
                    Text("Publish registers a service under your FID. You stay its only owner: nobody else can update, stop or close it, and there is no op that transfers one. Registering does not start anything — the record points at a server you are already running.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    Label("None of your services match these filters", systemImage: "line.3.horizontal.decrease.circle")
                        .font(.headline)
                    Text("That is the state and component filters talking, not your whole list. Set them to All states and Any component to see everything you own.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            case .drafts:
                Label("No drafts", systemImage: "doc.text")
                    .font(.headline)
                Text("Publish a service and choose Save draft to keep it here without paying for a carve. A draft exists only on this Mac and stays editable; once published, changing it means an update carve that everyone can see.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .hidden:
                Label("Nothing hidden", systemImage: "eye")
                    .font(.headline)
                Text("Hiding a service stops it appearing in your lists on this Mac. It is not stopping and it is not closing: nothing is carved, the record carries on existing, and another device still shows it.")
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
