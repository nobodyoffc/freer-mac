import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The live FID's address book. Lists contacts with avatar, name
/// (cid → fid), and titles. Pin / edit / delete are inline; an
/// `Add` button opens the editor sheet for a fresh entry.
///
/// Cross-pane "Send to this contact" jump is deferred — would require
/// `AppState`-mediated tab switching, which is a separate refactor.
struct ContactsView: View {
    let session: ActiveSession

    @State private var rows: [Contact] = []
    @State private var loadError: String?
    @State private var search: String = ""

    @State private var syncing = false
    @State private var syncError: String?
    @State private var syncSummary: String?
    @State private var didAutoSync = false

    @State private var editorMode: EditorMode?
    @State private var pendingDelete: Contact?
    @State private var pendingCarve: Contact?
    @State private var carving = false
    @State private var carveTxid: String?

    enum EditorMode: Identifiable {
        case create
        /// A new contact for a FID the user arrived with — the News
        /// feed's "add doer to contacts". Same save path as ``create``;
        /// only the FID starts filled in.
        case createFor(String)
        case edit(Contact)

        var id: String {
            switch self {
            case .create: return "create"
            case .createFor(let fid): return "createFor:\(fid)"
            case .edit(let c): return "edit:\(c.id)"
            }
        }
    }

    private var filtered: [Contact] {
        let q = search.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return rows }
        let needle = q.lowercased()
        return rows.filter { c in
            c.id.lowercased().contains(needle) ||
            c.name.lowercased().contains(needle) ||
            (c.titles ?? []).contains { $0.lowercased().contains(needle) } ||
            (c.memo ?? "").lowercased().contains(needle)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            HStack(spacing: 12) {
                Text("Contacts").font(.headline)
                if !rows.isEmpty {
                    Text("\(rows.count)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.secondary.opacity(0.15)))
                }
                Spacer()
                SearchField("Search name, FID, title…", text: $search)
                Button {
                    Task { await syncFromChain() }
                } label: {
                    if syncing {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(syncing || !session.canSign)
                .help(session.canSign
                      ? "Pull your carved contacts from the chain"
                      : "Watch-only identity — cannot decrypt on-chain contacts")
                Button {
                    editorMode = .create
                } label: {
                    Label("Add", systemImage: "plus")
                }
                .buttonStyle(.borderedProminent)
            }

            if let err = syncError {
                syncErrorBanner(err)
            } else if let txid = carveTxid {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.seal")
                        .foregroundStyle(.green)
                    CopyableText(
                        display: "Carve broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). Shows as On-chain once a block confirms it.",
                        copy: txid,
                        font: .caption
                    )
                    .foregroundStyle(.green)
                }
            } else if let summary = syncSummary {
                CopyableText(summary, font: .caption)
                    .foregroundStyle(.secondary)
            }

            if let err = loadError {
                errorCard(err)
            } else if rows.isEmpty {
                emptyCard
            } else if filtered.isEmpty {
                noMatchCard
            } else {
                list
            }

            Spacer()
        }
        .padding()
        .frame(minWidth: 520)
        .onAppear {
            reload()
            // First visit per pane instance: pull carved contacts from
            // the chain, like Android's loadInitialData →
            // refreshContactsFromAPI. Local rows render immediately;
            // the sync merges on top when it lands.
            if !didAutoSync {
                didAutoSync = true
                Task { await syncFromChain() }
            }
        }
        .sheet(item: $editorMode) { mode in
            ContactEditorSheet(
                session: session,
                mode: mode,
                onSaved: { txid in
                    editorMode = nil
                    if let txid {
                        syncError = nil
                        carveTxid = txid
                    }
                    reload()
                },
                onCancel: { editorMode = nil }
            )
        }
        .alert(
            "Delete \(pendingDelete?.name ?? "contact")?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingDelete = nil }
            Button("Delete locally", role: .destructive) {
                if let c = pendingDelete { delete(c) }
                pendingDelete = nil
            }
            if let c = pendingDelete, canDeleteOnChain(c) {
                Button("Delete locally + on-chain", role: .destructive) {
                    let contact = c
                    pendingDelete = nil
                    Task { await deleteOnChain(contact) }
                }
            }
        } message: {
            if let c = pendingDelete {
                if canDeleteOnChain(c) {
                    Text("\(c.id.elidingMiddle(head: 8, tail: 8)) has an on-chain carve. Deleting only locally makes it come back on the next chain sync; deleting on-chain carves a removal record (small miner fee).")
                } else {
                    Text("Removes the local entry for \(c.id.elidingMiddle(head: 8, tail: 8)). On-chain records are not affected.")
                }
            }
        }
        .alert(
            "Carve \(pendingCarve?.name ?? "contact") on-chain?",
            isPresented: Binding(
                get: { pendingCarve != nil },
                set: { if !$0 { pendingCarve = nil } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingCarve = nil }
            Button(pendingCarve?.onChain == true ? "Carve update" : "Carve") {
                let contact = pendingCarve
                pendingCarve = nil
                if let contact { Task { await carve(contact) } }
            }
        } message: {
            if let c = pendingCarve {
                Text(c.onChain == true
                     ? "Writes the current titles/memo/permissions of \(c.name) as an on-chain update of the existing carve. Encrypted to your key; costs a small miner fee."
                     : "Writes \(c.name)'s titles/memo/permissions to the FCH chain, encrypted so only you can read them. Costs a small miner fee, and the contact then syncs to any device you unlock with this key.")
            }
        }
    }

    private var list: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(filtered) { c in
                    row(c)
                        .padding(.vertical, 10)
                        .padding(.horizontal, 16)
                    Divider()
                }
            }
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    @ViewBuilder
    private func row(_ c: Contact) -> some View {
        HStack(alignment: .top, spacing: 12) {
            FidAvatarView(fid: c.id, size: 40)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(c.name)
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if c.pinnedAt != nil {
                        Image(systemName: "pin.fill")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    }
                    if c.onChain == true {
                        chip("On-chain", color: .blue)
                    } else if c.onChain == nil && c.lastHeight == nil {
                        // never touched the chain
                    }
                }

                if c.cid != nil {
                    // Name shows the CID, so show the FID separately
                    // for verification.
                    CopyableText.elidingMiddle(
                        c.id, head: 8, tail: 8,
                        font: .system(.caption, design: .monospaced)
                    )
                    .foregroundStyle(.secondary)
                }

                if let titles = c.titles, !titles.isEmpty {
                    Text(titles.joined(separator: " · "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }

                if let memo = c.memo, !memo.isEmpty {
                    Text(memo)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .lineLimit(2)
                }
            }

            Spacer(minLength: 8)

            HStack(spacing: 4) {
                Button {
                    togglePin(c)
                } label: {
                    Image(systemName: c.pinnedAt == nil ? "pin" : "pin.slash")
                }
                .buttonStyle(.borderless)
                .help(c.pinnedAt == nil ? "Pin to top" : "Unpin")

                Button {
                    editorMode = .edit(c)
                } label: {
                    Image(systemName: "pencil")
                }
                .buttonStyle(.borderless)
                .help("Edit")

                if session.canSign {
                    Button {
                        pendingCarve = c
                    } label: {
                        Image(systemName: "link.badge.plus")
                    }
                    .buttonStyle(.borderless)
                    .disabled(carving)
                    .help(c.onChain == true
                          ? "Carve an update of this contact on-chain"
                          : "Carve this contact on-chain (encrypted to your key)")
                }

                Button(role: .destructive) {
                    pendingDelete = c
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .help("Delete")
            }
            .foregroundStyle(.secondary)
        }
        .contentShape(Rectangle())
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    private var emptyCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("No contacts yet", systemImage: "person.2")
                .foregroundStyle(.secondary)
            Text("Add an FID to remember friends, services, or your other identities. Each entry can carry titles and a private memo.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var noMatchCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("No matches", systemImage: "magnifyingglass")
                .foregroundStyle(.secondary)
            Text("No contact matches \"\(search)\". Try a different term, or clear the search to see everyone.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func errorCard(_ err: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Couldn't load contacts", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.red)
            CopyableText(err, font: .callout)
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func syncErrorBanner(_ err: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.orange)
            CopyableText("Chain sync failed: \(err)", font: .caption)
                .foregroundStyle(.orange)
        }
    }

    // MARK: - actions

    /// Pull the live FID's carved CONTACT records from the chain,
    /// decrypt, and merge into the local store. Non-fatal: local rows
    /// stay visible if the network or decryption stumbles.
    private func syncFromChain() async {
        guard session.canSign, !syncing else { return }
        syncing = true
        syncError = nil
        defer { syncing = false }
        do {
            let priv = try session.livePrikey()
            let result = try await session.directory.syncOnChainContacts(
                owner: session.liveFid,
                privkey: priv,
                into: session.contacts
            )
            carveTxid = nil
            if result.total == 0 && result.demoted == 0 {
                syncSummary = "No carved contacts on-chain."
            } else {
                var parts = ["\(result.merged) on-chain contact\(result.merged == 1 ? "" : "s") synced"]
                if result.removed > 0 {
                    parts.append("\(result.removed) removed (deleted on-chain)")
                }
                if result.demoted > 0 {
                    parts.append("\(result.demoted) unmarked (no carve found on-chain)")
                }
                if result.undecryptable > 0 {
                    parts.append("\(result.undecryptable) could not be decrypted")
                    parts.append(contentsOf: result.failureReasons)
                }
                syncSummary = parts.joined(separator: " · ")
            }
            reload()
        } catch {
            syncError = String(describing: error)
        }
    }

    private func reload() {
        do {
            rows = try session.contacts.all()
            loadError = nil
        } catch {
            loadError = String(describing: error)
        }
    }

    private func togglePin(_ c: Contact) {
        do {
            _ = try session.contacts.togglePin(fid: c.id)
            reload()
        } catch {
            loadError = String(describing: error)
        }
    }

    private func delete(_ c: Contact) {
        do {
            _ = try session.contacts.remove(fid: c.id)
            reload()
        } catch {
            loadError = String(describing: error)
        }
    }

    // MARK: - carving

    private func canDeleteOnChain(_ c: Contact) -> Bool {
        session.canSign && c.onChain == true && !(c.carveId ?? "").isEmpty
    }

    /// Carve `c` on-chain (add, or update when a carveId is known).
    /// The row is left untouched — the next sync flips it to On-chain
    /// once a block confirms the carve.
    private func carve(_ c: Contact) async {
        guard session.canSign, !carving else { return }
        carving = true
        syncError = nil
        carveTxid = nil
        defer { carving = false }
        do {
            carveTxid = try await session.carveContactOnChain(c)
        } catch {
            syncError = String(describing: error)
        }
    }

    /// Carve a delete op for `c`'s on-chain record, then remove the
    /// local row. If the carve broadcast fails the row stays.
    private func deleteOnChain(_ c: Contact) async {
        guard let carveId = c.carveId, !carveId.isEmpty, !carving else { return }
        carving = true
        syncError = nil
        carveTxid = nil
        defer { carving = false }
        do {
            carveTxid = try await session.carveContactDeleteOnChain(carveIds: [carveId])
            delete(c)
        } catch {
            syncError = String(describing: error)
        }
    }
}
