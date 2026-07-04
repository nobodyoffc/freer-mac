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

    enum EditorMode: Identifiable {
        case create
        case edit(Contact)

        var id: String {
            switch self {
            case .create: return "create"
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
                searchField
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
                onSaved: {
                    editorMode = nil
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
            Button("Delete", role: .destructive) {
                if let c = pendingDelete { delete(c) }
                pendingDelete = nil
            }
        } message: {
            if let c = pendingDelete {
                Text("Removes the local entry for \(c.id.elidingMiddle(head: 8, tail: 8)). On-chain records are not affected.")
            }
        }
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField("", text: $search, prompt: Text("Search name, FID, title…"))
                .textFieldStyle(.plain)
                .frame(minWidth: 180, maxWidth: 280)
            if !search.isEmpty {
                Button {
                    search = ""
                } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
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
            if result.total == 0 {
                syncSummary = "No carved contacts on-chain."
            } else {
                var parts = ["\(result.merged) on-chain contact\(result.merged == 1 ? "" : "s") synced"]
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
}
