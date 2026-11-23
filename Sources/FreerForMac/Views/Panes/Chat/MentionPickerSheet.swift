import SwiftUI
import FCDomain
import FCUI

/// Whom an `@` names: the group's members, searchable.
///
/// Opened by typing `@` in a group's composer. A group can have hundreds
/// of members and a square thousands, so nothing here is done for all of
/// them at once:
///
/// - **The list is paged.** It shows ``pageSize`` rows and grows by as
///   many when its last row comes on screen, and only the rows shown are
///   named — one directory call per page, not one for the square.
/// - **The order puts the likely first**: you (an `@` of yourself flags a
///   message for your other devices), then whoever spoke last, then the rest.
/// - **The search covers what is not yet named.** It matches at once on
///   FIDs, the names already known and the address book; in a group
///   larger than a page it also asks the directory, which searches every
///   CID a FID has had, and keeps the hits that are members.
///
/// The search box is at the top and has the focus as the sheet opens, so
/// typing after the `@` carries on into it; Return takes the only match,
/// Esc leaves. (The iPhone's is at the foot, by the thumb, and waits to
/// be tapped, since its keyboard would cover the list.) Picking a row
/// writes `@name ` in the draft; leaving keeps the `@` as typed.
struct MentionPickerSheet: View {

    let session: ActiveSession
    let names: ChatNameBook
    /// Every member, in the order to offer them.
    let fids: [String]
    /// What the address book calls each member, for the search.
    let contactKeys: [String: [String]]
    /// The FID and what to write after the `@` for it.
    let onPick: (_ fid: String, _ handle: String) -> Void
    let onClose: () -> Void

    static let pageSize = 50

    @State private var query = ""
    @State private var limit = MentionPickerSheet.pageSize
    @FocusState private var searching: Bool

    /// CIDs the directory search turned up, for members not yet named.
    @State private var foundCids: [String: String] = [:]
    /// Members the directory search matched for `searchedTerm`.
    @State private var directoryHits: Set<String> = []
    @State private var searchedTerm = ""
    @State private var searchingDirectory = false

    private var term: String { query.trimmingCharacters(in: .whitespacesAndNewlines) }

    /// The members the search leaves, in the list's order.
    private var shown: [String] {
        guard !term.isEmpty else { return fids }
        let hits = searchedTerm == term ? directoryHits : []
        return fids.filter { fid in
            hits.contains(fid)
                || fid.localizedStandardContains(term)
                || cid(of: fid)?.localizedStandardContains(term) == true
                || names.contactLabel(of: fid)?.localizedStandardContains(term) == true
                || (contactKeys[fid] ?? []).contains { $0.localizedStandardContains(term) }
        }
    }

    private func cid(of fid: String) -> String? { names.cid(of: fid) ?? foundCids[fid] }

    var body: some View {
        let matching = shown
        let page = Array(matching.prefix(limit))
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("Mention", systemImage: "at")
                    .font(.headline)
                Spacer()
                Button("Cancel", action: onClose)
                    .keyboardShortcut(.cancelAction)
            }

            searchRow

            HStack(spacing: 6) {
                Text(term.isEmpty
                     ? "\(fids.count) members"
                     : "\(matching.count) of \(fids.count) members")
                if searchingDirectory {
                    ProgressView().controlSize(.mini)
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(page, id: \.self) { fid in
                        Button { pick(fid) } label: { row(fid) }
                            .buttonStyle(.plain)
                            .onAppear {
                                // The last row coming on screen asks for the next page.
                                if fid == page.last, page.count < matching.count {
                                    limit += Self.pageSize
                                }
                            }
                        Divider()
                    }
                    if matching.isEmpty, !searchingDirectory {
                        Text("No member matches.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.vertical, 20)
                    }
                }
            }
        }
        .padding(20)
        .frame(width: 420, height: 520)
        .onAppear { searching = true }
        // Name the rows on screen, a page at a time; the book skips any
        // it has asked about already.
        .task(id: page) { names.resolve(page, session: session) }
        .onChange(of: term) { _, _ in limit = Self.pageSize }
        .task(id: term) { await searchDirectory(term) }
    }

    private var searchRow: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(searching ? Color.accentColor : .secondary)
            TextField("", text: $query, prompt: Text("Search name, FID…"))
                .textFieldStyle(.plain)
                .autocorrectionDisabled()
                .focused($searching)
                .onSubmit { if shown.count == 1, let only = shown.first { pick(only) } }
            if !query.isEmpty {
                Button { query = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Clear the search")
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(NSColor.controlBackgroundColor)))
    }

    private func row(_ fid: String) -> some View {
        let name = cid(of: fid) ?? fid.elidingMiddle(head: 6, tail: 6)
        let mine = fid == session.liveFid
        return HStack(spacing: 10) {
            FidAvatarView(fid: fid, size: 32)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(mine ? String(localized: "\(name) (you)") : name)
                        .lineLimit(1)
                    if !mine { ContactLabelText(fid: fid, names: names) }
                }
                if cid(of: fid) != nil {
                    Text(fid.elidingMiddle(head: 8, tail: 8))
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 8)
        .contentShape(Rectangle())
    }

    private func pick(_ fid: String) {
        onPick(fid, cid(of: fid) ?? fid)
    }

    /// Ask the directory for members whose CID — any they have had —
    /// contains `term`. Only where the list is longer than a page, so
    /// most of its names are not known here; and after a pause in the
    /// typing, so a name typed fast costs one search and not six.
    private func searchDirectory(_ term: String) async {
        guard term.count >= 2, fids.count > Self.pageSize else {
            searchedTerm = term
            directoryHits = []
            return
        }
        try? await Task.sleep(for: .milliseconds(400))
        guard !Task.isCancelled else { return }
        searchingDirectory = true
        defer { searchingDirectory = false }

        let members = Set(fids)
        var hits: Set<String> = []
        var found: [String: String] = [:]
        var after: [String]? = nil
        // A few pages of the directory's answer: a common word matches
        // many FIDs that are not in this group.
        for _ in 0..<5 {
            guard let result = try? await session.directory.searchFreers(matching: term, after: after, size: 100),
                  !Task.isCancelled
            else { break }
            for freer in result.freers {
                guard let fid = freer.id, members.contains(fid) else { continue }
                hits.insert(fid)
                if let cid = freer.cid, !cid.isEmpty { found[fid] = cid }
            }
            guard let next = result.last, !next.isEmpty, result.freers.count == 100 else { break }
            after = next
        }
        guard !Task.isCancelled else { return }
        foundCids.merge(found) { _, new in new }
        directoryHits = hits
        searchedTerm = term
    }
}
