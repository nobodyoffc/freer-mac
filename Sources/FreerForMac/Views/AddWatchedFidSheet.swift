import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Add a watch-only FID to the current Setting — the Mac port of
/// Android's `AddWatchedFidActivity`: type (or QR-scan) a FID, or
/// search Freers by partial CID and pick a result; **Look up**
/// confirms the on-chain record (cid / pubkey / balance) before
/// saving. The entry is stored as `KeyInfo(kind: .watched)` — no
/// privkey, so living as it puts Send into the cold-sign path.
struct AddWatchedFidSheet: View {
    let session: ActiveSession
    let onAdded: (KeyInfo) -> Void
    let onCancel: () -> Void

    @State private var fid: String = ""
    @State private var label: String = ""

    @State private var lookedUpFreer: Freer?
    @State private var lookingUp = false
    @State private var lookupError: String?
    @State private var lookupKnownOffChain = false

    @State private var searchResults: [Freer] = []
    @State private var searchTerm: String?
    @State private var searchAfter: [String]?
    @State private var searchTotal: Int64?
    @State private var searchNoMatches = false
    @State private var loadingMore = false

    @State private var showScan = false
    @State private var saveError: String?

    private static let searchPageSize = 10

    private var fidLooksValid: Bool {
        (try? FchAddress(fid: fid)) != nil
    }

    /// Why this FID can't be added, or nil when it can. Mirrors
    /// Android's duplicate checks when confirming.
    private var blockReason: String? {
        let trimmed = fid.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, fidLooksValid else { return nil }
        if trimmed == session.mainFid {
            return "That's this Setting's main FID — it's already here."
        }
        if let existing = session.setting.keyInfoMap[trimmed] {
            return "Already registered as \(existing.kind.rawValue)\(existing.label.isEmpty ? "" : " “\(existing.label)”")."
        }
        return nil
    }

    private var canAdd: Bool {
        fidLooksValid && blockReason == nil
    }

    private var canLookup: Bool {
        !lookingUp && !fid.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            Form {
                Section("Watched FID") {
                    LabeledField(
                        "FID",
                        hint: (!fid.isEmpty && !fidLooksValid)
                            ? "Not a FID — Look up searches CIDs instead."
                            : blockReason,
                        hintIsError: blockReason != nil
                    ) {
                        HStack(spacing: 8) {
                            TextField("", text: $fid, prompt: Text("F… or CID"))
                                .font(.system(.body, design: .monospaced))
                                .fieldInputStyle()
                                .onSubmit { Task { await runLookup() } }
                                .onChange(of: fid) { _, newValue in
                                    guard lookedUpFreer?.id != newValue else { return }
                                    lookedUpFreer = nil
                                    lookupKnownOffChain = false
                                    lookupError = nil
                                    searchNoMatches = false
                                }

                            Button {
                                showScan = true
                            } label: {
                                Image(systemName: "qrcode.viewfinder")
                            }
                            .help("Scan a FID QR code")

                            Button {
                                Task { await runLookup() }
                            } label: {
                                if lookingUp {
                                    HStack(spacing: 4) {
                                        ProgressView().controlSize(.small)
                                        Text("Looking up…")
                                    }
                                } else {
                                    Label("Look up", systemImage: "magnifyingglass")
                                }
                            }
                            .disabled(!canLookup)
                            .help("A valid FID fetches its on-chain record; any other text searches Freers by CID.")
                        }
                    }

                    if let err = lookupError {
                        HStack(alignment: .top, spacing: 4) {
                            Image(systemName: "xmark.octagon.fill")
                            CopyableText(err, font: .caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .foregroundStyle(.red)
                        .font(.caption)
                    } else if lookupKnownOffChain {
                        HStack(spacing: 6) {
                            Image(systemName: "questionmark.circle")
                            Text("No on-chain record — this FID hasn't registered a Freer yet. You can still watch it.")
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .foregroundStyle(.orange)
                        .font(.caption)
                    } else if let f = lookedUpFreer {
                        onChainStatus(f)
                    }

                    if searchNoMatches {
                        HStack(spacing: 6) {
                            Image(systemName: "questionmark.circle")
                            Text("No matching CIDs found.")
                        }
                        .foregroundStyle(.orange)
                        .font(.caption)
                    } else if !searchResults.isEmpty {
                        searchResultsList
                    }

                    LabeledField(
                        "Label",
                        hint: "Optional. Shown in the person menu; defaults to the CID when looked up."
                    ) {
                        TextField("", text: $label, prompt: Text("Cold wallet"))
                            .fieldInputStyle()
                    }
                }

                if let err = saveError {
                    Section {
                        CopyableText(err, font: .callout)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack {
                Text("Watched FIDs are read-only: balances and history load normally, sending exports an unsigned tx for cold signing.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("Add") { add() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canAdd)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 540, minHeight: 420)
        .sheet(isPresented: $showScan) {
            QrScanSheet(title: "Scan FID") { scanned in
                fid = scanned
                showScan = false
                Task { await runLookup() }
            } onCancel: {
                showScan = false
            }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            if !fid.isEmpty, fidLooksValid {
                FidAvatarView(fid: fid, size: 40)
            } else {
                ZStack {
                    Circle()
                        .fill(Color.secondary.opacity(0.15))
                        .frame(width: 40, height: 40)
                    Image(systemName: "eye")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                }
            }
            Text("Add watched FID")
                .font(.title2).bold()
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var searchResultsList: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("\(searchResults.count) match\(searchResults.count == 1 ? "" : "es") — click one to select")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.bottom, 4)

            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(searchResults.enumerated()), id: \.offset) { idx, f in
                    if idx > 0 { Divider() }
                    searchResultRow(f)
                }
            }
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color.secondary.opacity(0.06))
            )

            if hasMoreResults {
                HStack(spacing: 8) {
                    Button {
                        Task { await loadMoreResults() }
                    } label: {
                        if loadingMore {
                            HStack(spacing: 4) {
                                ProgressView().controlSize(.small)
                                Text("Loading…")
                            }
                        } else {
                            Label("More", systemImage: "chevron.down")
                        }
                    }
                    .disabled(loadingMore)

                    if let total = searchTotal, total > Int64(searchResults.count) {
                        Text("\(total - Int64(searchResults.count)) left")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }
                .padding(.top, 6)
            }
        }
    }

    private func searchResultRow(_ f: Freer) -> some View {
        Button {
            select(f)
        } label: {
            HStack(spacing: 8) {
                if let id = f.id {
                    FidAvatarView(fid: id, size: 28)
                }
                VStack(alignment: .leading, spacing: 2) {
                    if let cid = f.cid, !cid.isEmpty {
                        Text(cid)
                            .font(.callout.weight(.semibold))
                            .lineLimit(1)
                    }
                    Text((f.id ?? "?").elidingMiddle(head: 12, tail: 12))
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(f.id == nil)
    }

    @ViewBuilder
    private func onChainStatus(_ f: Freer) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                Text("On-chain record").font(.caption.bold())
                    .foregroundStyle(.green)
                Spacer()
            }
            if let cid = f.cid, !cid.isEmpty {
                CopyableText(
                    display: "cid: \(cid)",
                    copy: cid,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
            if let pkHex = f.pubkey, !pkHex.isEmpty {
                CopyableText(
                    display: "pubkey: \(pkHex.elidingMiddle(head: 10, tail: 10))",
                    copy: pkHex,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Color.green.opacity(0.08))
        )
    }

    // MARK: - lookup / save

    /// Same split as ContactEditorSheet / Android's `performSearch`:
    /// a valid FID means an exact `freerByIds` fetch, anything else
    /// a partial CID search.
    @MainActor
    private func runLookup() async {
        let term = fid.trimmingCharacters(in: .whitespaces)
        guard !term.isEmpty, !lookingUp else { return }
        lookingUp = true
        lookupError = nil
        lookupKnownOffChain = false
        searchNoMatches = false
        defer { lookingUp = false }

        if fidLooksValid {
            clearSearchResults()
            do {
                let freer = try await session.directory.freer(byId: term)
                if let freer {
                    lookedUpFreer = freer
                    if label.isEmpty, let cid = freer.cid { label = cid }
                } else {
                    lookedUpFreer = nil
                    lookupKnownOffChain = true
                }
            } catch {
                lookedUpFreer = nil
                lookupError = String(describing: error)
            }
        } else {
            lookedUpFreer = nil
            do {
                let page = try await session.directory.searchFreers(
                    matching: term, size: Self.searchPageSize
                )
                searchResults = page.freers
                searchTerm = term
                searchAfter = page.last
                searchTotal = page.total
                searchNoMatches = page.freers.isEmpty
            } catch {
                clearSearchResults()
                lookupError = String(describing: error)
            }
        }
    }

    private var hasMoreResults: Bool {
        guard let after = searchAfter, !after.isEmpty else { return false }
        if let total = searchTotal { return Int64(searchResults.count) < total }
        return searchResults.count % Self.searchPageSize == 0
    }

    @MainActor
    private func loadMoreResults() async {
        guard let term = searchTerm,
              let after = searchAfter, !after.isEmpty,
              !loadingMore else { return }
        loadingMore = true
        defer { loadingMore = false }
        do {
            let page = try await session.directory.searchFreers(
                matching: term, after: after, size: Self.searchPageSize
            )
            let seen = Set(searchResults.compactMap(\.id))
            searchResults.append(contentsOf: page.freers.filter {
                guard let id = $0.id else { return false }
                return !seen.contains(id)
            })
            searchAfter = page.last
            if let t = page.total { searchTotal = t }
        } catch {
            lookupError = String(describing: error)
        }
    }

    @MainActor
    private func select(_ f: Freer) {
        guard let id = f.id else { return }
        fid = id
        lookedUpFreer = f
        if label.isEmpty, let cid = f.cid { label = cid }
        lookupError = nil
        lookupKnownOffChain = false
        clearSearchResults()
    }

    private func clearSearchResults() {
        searchResults = []
        searchTerm = nil
        searchAfter = nil
        searchTotal = nil
        searchNoMatches = false
    }

    private func add() {
        guard canAdd else { return }
        let trimmed = fid.trimmingCharacters(in: .whitespaces)
        // On-chain facts only when the looked-up record is for this
        // exact FID (a stale record from an earlier lookup must not
        // leak its pubkey onto a retyped address).
        let onChain: KeyInfo? = (lookedUpFreer?.id == trimmed)
            ? lookedUpFreer.flatMap { KeyInfo.from(freer: $0) }
            : nil
        do {
            let info = try session.addWatchedFid(
                trimmed,
                label: label.trimmingCharacters(in: .whitespaces),
                pubkey: onChain?.pubkey,
                master: onChain?.master
            )
            onAdded(info)
        } catch {
            saveError = String(describing: error)
        }
    }
}
