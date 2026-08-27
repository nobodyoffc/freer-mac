import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Register servants of this main FID — the Mac port of Android's
/// `AddServantFidActivity`.
///
/// **Nothing here publishes anything.** A servant relationship is
/// created by the *servant*, carving a Master record that names us; a
/// master cannot carve one to acquire a servant. So this sheet only
/// asks the chain "who has named me?" and lets the user tick which of
/// those answers to keep in the person menu. No key, no fee, no carve —
/// which is exactly the opposite of ``SetMasterSheet``, the other side
/// of the same relationship.
///
/// The list is the chain's answer, filtered to the ones not already
/// registered. Everything already in the Setting is shown as such
/// rather than hidden, so an empty list reads as "you have them all"
/// instead of "the lookup failed".
struct AddServantsSheet: View {
    let session: ActiveSession
    let onAdded: (Int) -> Void
    let onCancel: () -> Void

    @State private var found: [Freer] = []
    @State private var loading = false
    @State private var loadError: String?
    @State private var loaded = false
    @State private var selected: Set<String> = []
    @State private var saveError: String?

    /// FIDs the Setting already holds, in any role.
    private var alreadyRegistered: Set<String> {
        Set(session.setting.keyInfoMap.keys)
    }

    private var addable: [Freer] {
        found.filter { freer in
            guard let id = freer.id else { return false }
            return !alreadyRegistered.contains(id)
        }
    }

    private var already: [Freer] {
        found.filter { freer in
            guard let id = freer.id else { return false }
            return alreadyRegistered.contains(id)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            content
            Divider()
            footer
        }
        .frame(minWidth: 560, minHeight: 460)
        .task {
            guard !loaded else { return }
            await load()
        }
    }

    // MARK: - panels

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "person.2.badge.key")
                .font(.title2)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text("Add servants")
                    .font(.title2).bold()
                Text("FIDs that have named this one as their master, on chain.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await load() }
            } label: {
                if loading {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "arrow.clockwise")
                }
            }
            .disabled(loading)
            .help("Ask the chain again")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    @ViewBuilder
    private var content: some View {
        if loading && found.isEmpty {
            centered {
                ProgressView()
                Text("Looking for servants…").foregroundStyle(.secondary)
            }
        } else if let err = loadError {
            centered {
                Image(systemName: "xmark.octagon.fill")
                    .font(.title)
                    .foregroundStyle(.red)
                CopyableText(err, font: .callout)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else if found.isEmpty {
            centered {
                Image(systemName: "person.2.slash")
                    .font(.title)
                    .foregroundStyle(.secondary)
                Text("No servants found.")
                    .font(.headline)
                Text("A FID becomes your servant by carving a Master record naming this FID. Nothing you do here can create one — they have to do it from their own wallet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 380)
            }
        } else {
            List {
                if !addable.isEmpty {
                    Section {
                        ForEach(addable, id: \.id) { freer in
                            row(freer, registered: false)
                        }
                    } header: {
                        HStack {
                            Text("Found")
                            Spacer()
                            Button(selected.count == addable.count ? "Select none" : "Select all") {
                                if selected.count == addable.count {
                                    selected.removeAll()
                                } else {
                                    selected = Set(addable.compactMap(\.id))
                                }
                            }
                            .buttonStyle(.link)
                            .font(.caption)
                        }
                    }
                }
                if !already.isEmpty {
                    Section("Already registered") {
                        ForEach(already, id: \.id) { freer in
                            row(freer, registered: true)
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    private func row(_ freer: Freer, registered: Bool) -> some View {
        let fid = freer.id ?? ""
        return HStack(spacing: 10) {
            if registered {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.secondary)
                    .frame(width: 16)
            } else {
                Toggle("", isOn: Binding(
                    get: { selected.contains(fid) },
                    set: { on in
                        if on { selected.insert(fid) } else { selected.remove(fid) }
                    }
                ))
                .labelsHidden()
            }
            FidAvatarView(fid: fid, size: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(freer.cid?.isEmpty == false ? freer.cid! : "No CID")
                    .lineLimit(1)
                CopyableText(
                    display: fid.elidingMiddle(head: 10, tail: 10),
                    copy: fid,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
            Spacer()
            if registered {
                Text("registered")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            guard !registered else { return }
            if selected.contains(fid) { selected.remove(fid) } else { selected.insert(fid) }
        }
    }

    private var footer: some View {
        HStack {
            if let err = saveError {
                CopyableText(err, font: .caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Registering a servant is local — it publishes nothing and costs nothing.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button("Cancel", role: .cancel) { onCancel() }
                .keyboardShortcut(.cancelAction)
            Button(selected.count > 1 ? "Add \(selected.count)" : "Add") { add() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(selected.isEmpty)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private func centered<C: View>(@ViewBuilder _ content: () -> C) -> some View {
        VStack(spacing: 10) { content() }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(24)
    }

    // MARK: - actions

    @MainActor
    private func load() async {
        guard !loading else { return }
        loading = true
        loadError = nil
        defer {
            loading = false
            loaded = true
        }
        do {
            let page = try await session.directory.myServants(of: session.mainFid)
            found = page.freers
            // Drop selections for rows that are no longer offered.
            let offered = Set(page.freers.compactMap(\.id))
            selected.formIntersection(offered)
        } catch {
            loadError = String(describing: error)
        }
    }

    private func add() {
        var added = 0
        for freer in addable {
            guard let fid = freer.id, selected.contains(fid) else { continue }
            do {
                try session.addServantFid(
                    fid,
                    label: freer.cid ?? "",
                    pubkey: KeyInfo.from(freer: freer)?.pubkey
                )
                added += 1
            } catch {
                saveError = String(describing: error)
                // Keep whatever landed before the failure — the Setting
                // is already saved per entry, so pretending none were
                // added would be a lie the next reopen contradicts.
                break
            }
        }
        if added > 0 { onAdded(added) }
    }
}
