import SwiftUI
import FCDomain
import FCUI

/// Lists all main FIDs in the unlocked Configure. Tapping one opens
/// an ActiveSession for it; the "+" button takes the user to the
/// AddMainView form; each row's "…" menu deletes the identity.
struct ChooseMainView: View {
    @Environment(AppState.self) private var appState

    @State private var working: String?     // FID currently being unlocked

    /// Held in state rather than read straight off the session: the
    /// ConfigureSession isn't observable, so a delete would otherwise
    /// leave the deleted row on screen until something else redrew.
    @State private var mains: [KeyInfo] = []

    @State private var pendingDelete: KeyInfo?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Choose identity").font(.title).bold()
                    if let cs = appState.configureSession {
                        Text("Vault \(cs.passwordName)\(cs.label.isEmpty ? "" : " · \(cs.label)")")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Button {
                    appState.route = .addMain
                } label: {
                    Label("Add", systemImage: "plus")
                }
                Button("Lock vault") {
                    appState.lockAll()
                }
            }
            .padding(.horizontal)

            if mains.isEmpty {
                emptyState
            } else {
                mainList
            }

            if let err = appState.lastError {
                Text(err)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }
        }
        .padding(.vertical)
        .frame(minWidth: 520, minHeight: 360)
        .onAppear(perform: reload)
        .alert(deleteTitle, isPresented: deleteBinding) {
            Button("Cancel", role: .cancel) { pendingDelete = nil }
            Button("Delete key", role: .destructive) { confirmDelete(deletingSetting: false) }
            Button("Delete key and data", role: .destructive) { confirmDelete(deletingSetting: true) }
        } message: {
            Text("""
            This vault holds the only copy of that private key. Unless you have the key written down elsewhere, deleting it means the FID — and anything it owns on chain — is gone for good. There is no undo and no export.

            “Delete key” leaves this identity's local data (contacts, chat, caches) on disk, so re-importing the same private key later picks it all back up. “Delete key and data” erases that folder too.
            """)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "person.crop.circle.badge.plus")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)
            Text("No identities yet")
                .font(.title2).bold()
            Text("Add a main FID — generate a fresh key, paste a hex/WIF privkey, or derive one from a passphrase.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 380)
            Button("Add identity") {
                appState.route = .addMain
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    private var mainList: some View {
        List(mains, id: \.fid) { info in
            HStack(spacing: 8) {
                Button {
                    Task {
                        working = info.fid
                        await appState.unlockMain(fid: info.fid)
                        working = nil
                    }
                } label: {
                    row(info)
                }
                .buttonStyle(.plain)
                .disabled(working != nil)

                Menu {
                    Button("Delete identity…", role: .destructive) {
                        pendingDelete = info
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .disabled(working != nil)
                .help("Delete this identity from the vault.")
            }
            .contextMenu {
                Button("Delete identity…", role: .destructive) {
                    pendingDelete = info
                }
            }
        }
        .listStyle(.inset(alternatesRowBackgrounds: true))
    }

    private func row(_ info: KeyInfo) -> some View {
        HStack(spacing: 12) {
            FidAvatarView(fid: info.fid, size: 44)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(info.activeCid
                         ?? (info.label.isEmpty ? "Main FID" : info.label))
                        .font(.headline)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    // With a CID heading the row, the local label
                    // still earns its place beside it: the CID is
                    // what the chain calls this identity, the
                    // label is what *you* call it, and a vault
                    // holding several identities is exactly where
                    // the two need telling apart.
                    if info.activeCid != nil, !info.label.isEmpty {
                        HStack(spacing: 3) {
                            Image(systemName: "tag.fill")
                            Text(info.label)
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    }
                }
                Text(info.fid)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            if working == info.fid {
                ProgressView().controlSize(.small)
            } else {
                Image(systemName: "chevron.right")
                    .foregroundStyle(.tertiary)
            }
        }
        .contentShape(Rectangle())
        .padding(.vertical, 4)
    }

    // MARK: - delete

    private var deleteBinding: Binding<Bool> {
        Binding(get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } })
    }

    /// The FID is spelled out in full, elided in the middle: two
    /// identities in one vault can share a label, and the tail is
    /// exactly where they differ.
    private var deleteTitle: String {
        guard let info = pendingDelete else { return "Delete identity?" }
        let name = info.activeCid ?? (info.label.isEmpty ? nil : info.label)
        let fid = info.fid.elidingMiddle(head: 8, tail: 8)
        return name.map { "Delete “\($0)” (\(fid))?" } ?? "Delete \(fid)?"
    }

    private func confirmDelete(deletingSetting: Bool) {
        guard let info = pendingDelete else { return }
        pendingDelete = nil
        Task {
            await appState.deleteMain(fid: info.fid, deletingSetting: deletingSetting)
            reload()
        }
    }

    private func reload() {
        mains = appState.configureSession?.listMains() ?? []
    }
}
