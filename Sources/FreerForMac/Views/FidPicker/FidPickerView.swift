import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The reusable find-and-choose-people surface: one search box, the
/// device's own contacts and keys filtering live underneath it, and the
/// chain's answer when asked. Drives ``FidSearchModel``; carries no
/// state of its own so it can be embedded in a sheet, a pane, or a
/// form section without the host having to re-derive anything.
///
/// The sheet wrapper — the way nearly every caller wants it — is
/// ``FidPickerSheet``.
struct FidPickerView: View {

    @Bindable var model: FidSearchModel

    /// Placeholder for the search box. Callers with a narrower job
    /// ("who is this room for?") can say so here.
    var prompt: String = "FID, or part of a CID"

    @FocusState private var searchFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            searchBar
            statusLine
            if model.mode == .many, !model.selected.isEmpty {
                selectedTray
            }
            if model.mode == .many, hasVisibleRows {
                HStack {
                    Spacer()
                    Button("Select all shown") { model.selectAllVisible() }
                        .buttonStyle(.borderless)
                        .font(.caption)
                        .help("Add every row listed below to the selection.")
                }
            }
            results
        }
        .onAppear {
            model.loadLocalSources()
            searchFocused = true
            if !model.searchesChain {
                Task { await model.enrichPool() }
            } else if !model.query.isEmpty {
                // Seeded from the field that opened this — the user has
                // already said what they're looking for.
                Task { await model.search() }
            }
        }
    }

    // MARK: - search bar

    private var searchBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("", text: $model.query, prompt: Text(prompt))
                    .textFieldStyle(.plain)
                    .font(.system(.body, design: .monospaced))
                    .focused($searchFocused)
                    .onSubmit { Task { await model.search() } }
                if !model.query.isEmpty {
                    Button {
                        model.clearSearch()
                        searchFocused = true
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("Clear the search")
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color(nsColor: .textBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .strokeBorder(Color.secondary.opacity(0.3), lineWidth: 0.5)
            )

            if model.searchesChain {
                Button {
                    Task { await model.search() }
                } label: {
                    if model.searching {
                        HStack(spacing: 4) {
                            ProgressView().controlSize(.small)
                            Text("Searching…")
                        }
                    } else {
                        Label("Search chain", systemImage: "link")
                    }
                }
                .disabled(!model.canSearch)
                .help("Contacts filter as you type. This asks the chain: a full FID is fetched exactly, anything else matches CIDs — current and past.")
            }
        }
    }

    // MARK: - status

    @ViewBuilder
    private var statusLine: some View {
        if let err = model.error {
            HStack(alignment: .top, spacing: 4) {
                Image(systemName: "xmark.octagon.fill")
                CopyableText(err, font: .caption)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .foregroundStyle(.red)
            .font(.caption)
        } else if model.exactFidUnknown {
            HStack(spacing: 6) {
                Image(systemName: "questionmark.circle")
                Text("That FID is valid but has no on-chain record yet. You can still pick it — messages to it can't be encrypted until it publishes a key.")
                    .fixedSize(horizontal: false, vertical: true)
            }
            .foregroundStyle(.orange)
            .font(.caption)
        } else if model.noChainMatches {
            HStack(spacing: 6) {
                Image(systemName: "questionmark.circle")
                Text("No CID on chain contains “\(model.searchTerm ?? "")”.")
            }
            .foregroundStyle(.orange)
            .font(.caption)
        }
    }

    // MARK: - selected tray

    private var selectedTray: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text("Selected \(model.selected.count)")
                    .font(.caption.bold())
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Clear all") { model.clearSelection() }
                    .buttonStyle(.borderless)
                    .font(.caption)
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(model.selected) { picked in
                        chip(picked)
                    }
                }
                .padding(.vertical, 2)
            }
        }
    }

    private func chip(_ picked: PickedFid) -> some View {
        HStack(spacing: 5) {
            FidAvatarView(fid: picked.fid, size: 18)
            Text(picked.cid ?? picked.fid.elidingMiddle(head: 6, tail: 6))
                .font(.caption)
                .lineLimit(1)
            if picked.pubkey == nil {
                Image(systemName: "lock.open")
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .help("No published key — anything sent to them can't be encrypted.")
            }
            Button {
                model.deselect(picked.fid)
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Remove")
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 4)
        .background(
            Capsule().fill(Color.accentColor.opacity(0.14))
        )
    }

    // MARK: - results

    private var hasVisibleRows: Bool {
        !model.localMatches.isEmpty || !model.chainResults.isEmpty
    }

    private var results: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                if let typed = model.typedCandidate {
                    sectionHeader("Typed", count: nil)
                    row(typed)
                    Divider()
                }

                let local = model.localMatches
                if !local.isEmpty {
                    sectionHeader(
                        model.searchesChain ? "On this device" : "Members",
                        count: local.count
                    )
                    ForEach(local) { picked in
                        row(picked)
                        Divider()
                    }
                }

                if !model.chainResults.isEmpty {
                    sectionHeader("On chain", count: model.chainResults.count)
                    ForEach(model.chainResults) { picked in
                        row(picked)
                        Divider()
                    }
                    if model.hasMoreResults { moreRow }
                }

                if local.isEmpty && model.chainResults.isEmpty
                    && model.typedCandidate == nil {
                    emptyState
                }
            }
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .frame(minHeight: 220)
    }

    private func sectionHeader(_ title: String, count: Int?) -> some View {
        HStack(spacing: 6) {
            Text(title.uppercased())
                .font(.caption2.bold())
                .foregroundStyle(.secondary)
            if let count {
                Text("\(count)")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.tertiary)
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.top, 10)
        .padding(.bottom, 4)
    }

    private func row(_ picked: PickedFid) -> some View {
        let selected = model.isSelected(picked.fid)
        let selectable = model.isSelectable(picked.fid)
        return Button {
            model.toggle(picked)
        } label: {
            HStack(spacing: 10) {
                if model.mode == .many {
                    Image(systemName: selected
                          ? "checkmark.circle.fill"
                          : (selectable ? "circle" : "minus.circle"))
                        .foregroundStyle(selected ? Color.accentColor : .secondary)
                } else if selected {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(Color.accentColor)
                }

                FidAvatarView(fid: picked.fid, size: 32)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(picked.name)
                            .font(.body.weight(picked.cid == nil ? .regular : .semibold))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        badge(picked.source)
                        if picked.pubkey == nil {
                            Image(systemName: "lock.open")
                                .font(.caption2)
                                .foregroundStyle(.orange)
                                .help("No published key — anything sent to them can't be encrypted.")
                        }
                    }
                    if picked.cid != nil {
                        Text(picked.fid.elidingMiddle(head: 10, tail: 10))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    if let used = picked.usedCids, !used.isEmpty,
                       let term = model.searchTerm,
                       used.contains(where: { $0.localizedCaseInsensitiveContains(term) }) {
                        // The reason this row matched isn't visible
                        // otherwise: the hit was on a name they no
                        // longer use.
                        Text("was: \(used.joined(separator: ", "))")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
                }

                Spacer(minLength: 8)

                if let bal = picked.balance {
                    Text(formatFch(bal))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!selectable)
        .opacity(selectable ? 1 : 0.45)
        .background(selected ? Color.accentColor.opacity(0.08) : .clear)
        .help(selectable ? picked.fid : "\(picked.fid) — already in the list.")
    }

    private var moreRow: some View {
        HStack(spacing: 8) {
            Button {
                Task { await model.loadMore() }
            } label: {
                if model.loadingMore {
                    HStack(spacing: 4) {
                        ProgressView().controlSize(.small)
                        Text("Loading…")
                    }
                } else {
                    Label("More", systemImage: "chevron.down")
                }
            }
            .buttonStyle(.borderless)
            .disabled(model.loadingMore)

            if let left = model.remainingCount {
                Text("\(left) left")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(model.query.isEmpty
                 ? "No contacts on this device yet."
                 : "Nothing here matches “\(model.query)”.")
                .font(.callout)
                .foregroundStyle(.secondary)
            if model.searchesChain, !model.query.isEmpty, !model.noChainMatches {
                Text("Press Return, or Search chain, to look it up on chain.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
    }

    private func badge(_ source: PickedFid.Source) -> some View {
        HStack(spacing: 3) {
            Image(systemName: source.systemImage)
            Text(source.label)
        }
        .font(.caption2)
        .padding(.horizontal, 5)
        .padding(.vertical, 1)
        .background(
            Capsule().fill(Color.secondary.opacity(0.15))
        )
        .foregroundStyle(.secondary)
    }

    private func formatFch(_ sats: Int64) -> String {
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 4
        let value = Double(sats) / 100_000_000.0
        return (f.string(from: NSNumber(value: value)) ?? "0") + " FCH"
    }
}
