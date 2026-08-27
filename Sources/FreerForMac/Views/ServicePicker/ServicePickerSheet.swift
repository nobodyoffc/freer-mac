import SwiftUI
import FCCore
import FCDomain
import FCUI

/// A service the user chose, reduced to what a caller actually needs.
///
/// The **SID** is what goes into a `home` map, not the URL: a server can
/// move, and the chain record is what everyone re-resolves through. The
/// URL is here only so the sheet's caller can show where it currently
/// points.
struct PickedService: Identifiable, Hashable, Sendable {
    let sid: String
    let stdName: String?
    let apiUrl: String?
    let owner: String?

    var id: String { sid }

    var name: String {
        if let stdName, !stdName.isEmpty { return stdName }
        return sid
    }

    init?(_ service: Service) {
        guard let sid = service.id, !sid.isEmpty else { return nil }
        self.sid = sid
        self.stdName = service.stdName
        self.apiUrl = service.apiUrl
        self.owner = service.owner ?? service.dealer
    }
}

/// Find and choose an on-chain service offering one component — the Mac
/// port of Android's `SetDiskActivity`, which is the same screen its
/// DOCK and DISK pickers both open.
///
/// **The component is the whole point.** One FAPI server usually runs
/// several services, so a picker that searched on the record's `type`
/// would offer every service on the chain and let the user pick one that
/// cannot do the job. The search filters on the component list, so
/// everything offered here can actually be what it is being picked for.
///
/// **A typed SID is a lookup, not a search.** Someone pasting a SID they
/// already have wants that record, and answering with a fuzzy match on
/// it would be a strange thing to do — ``DirectoryService/findServices(offering:matching:after:size:timeoutMs:)``
/// makes the split, the same way the FID picker does.
struct ServicePickerSheet: View {

    let session: ActiveSession
    /// Which component the picked service has to offer, e.g.
    /// ``ServiceName/dock``.
    var component: String = ServiceName.dock
    var title: String = "Choose a DOCK"
    var subtitle: String?
    /// Seeds the search box — normally whatever was already typed in the
    /// field that opened this.
    var initialQuery: String = ""
    let onPicked: (PickedService) -> Void
    let onCancel: () -> Void

    @State private var query = ""
    @State private var results: [PickedService] = []
    @State private var after: [String]?
    @State private var total: Int64?
    @State private var searching = false
    @State private var searched = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            searchBar
            Divider()
            list
            Divider()
            footer
        }
        .frame(minWidth: 560, minHeight: 480)
        .onAppear {
            query = initialQuery
            // Open on the list rather than on an empty box: "which
            // DOCKs are there" is the question almost everybody has,
            // and making them press Search to find out is a step for
            // nothing.
            search(reset: true)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                Image(systemName: "server.rack")
                    .font(.title2)
                    .foregroundStyle(.tint)
                Text(title).font(.title2).bold()
                Spacer()
            }
            Text(subtitle ?? "Search the chain for a server offering \(component). Its service id is what gets published, so the server can move without anyone losing it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
        .padding(.bottom, 10)
    }

    private var searchBar: some View {
        HStack(spacing: 8) {
            TextField("Name, service id, owner or description", text: $query)
                .textFieldStyle(.roundedBorder)
                .onSubmit { search(reset: true) }
            Button {
                search(reset: true)
            } label: {
                if searching {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Search", systemImage: "magnifyingglass")
                }
            }
            .disabled(searching)
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 10)
    }

    @ViewBuilder
    private var list: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(results) { service in
                    row(service)
                    Divider()
                }

                if let error {
                    CopyableText(error, font: .caption)
                        .foregroundStyle(.red)
                        .padding(12)
                } else if results.isEmpty, searched, !searching {
                    Text("No \(component) service matched.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(12)
                }

                if after != nil, !results.isEmpty {
                    Button {
                        search(reset: false)
                    } label: {
                        if let total, total > Int64(results.count) {
                            Text("Load more (\(total - Int64(results.count)) left)")
                        } else {
                            Text("Load more")
                        }
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    .disabled(searching)
                    .padding(12)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func row(_ service: PickedService) -> some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(service.name).font(.callout.bold()).lineLimit(1)
                CopyableText(
                    display: service.sid.elidingMiddle(head: 10, tail: 10),
                    copy: service.sid,
                    font: .caption
                )
                .foregroundStyle(.secondary)
                if let url = service.apiUrl {
                    Text(url).font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            Button("Choose") { onPicked(service) }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private var footer: some View {
        HStack {
            if !results.isEmpty {
                Text("\(results.count) shown").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Cancel", role: .cancel) { onCancel() }
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - searching

    /// `reset: false` is Load more, and it is the only path that keeps
    /// the cursor — a fresh search with a stale `after` would page into
    /// the middle of somebody else's result set.
    private func search(reset: Bool) {
        guard !searching else { return }
        searching = true
        error = nil
        if reset {
            after = nil
            total = nil
        }
        let cursor = reset ? nil : after
        let term = query
        Task {
            do {
                let page = try await session.directory.findServices(
                    offering: component, matching: term, after: cursor
                )
                let picked = page.services.compactMap(PickedService.init)
                await MainActor.run {
                    if reset { results = picked } else { results += picked }
                    // No cursor, or a short page, means the end. Keeping
                    // a Load-more button that returns nothing is worse
                    // than not offering one.
                    after = (page.last?.isEmpty == false && !picked.isEmpty) ? page.last : nil
                    total = page.total
                    searching = false
                    searched = true
                }
            } catch {
                await MainActor.run {
                    self.error = String(describing: error)
                    searching = false
                    searched = true
                }
            }
        }
    }
}
