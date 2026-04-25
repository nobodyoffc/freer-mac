import SwiftUI
import FCDomain

/// Pick which registered identity to log in as. Lists all identities
/// from the vault; tapping a row routes to ``UnlockView``.
struct ChooseIdentityView: View {
    @Environment(AppState.self) private var appState

    @State private var pendingDelete: IdentityRecord?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Choose identity")
                        .font(.title).bold()
                    Text("\(appState.identities.count) on this Mac")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    appState.goToCreateIdentity()
                } label: {
                    Label("New", systemImage: "plus")
                }
            }
            .padding(.horizontal)

            List(appState.identities, id: \.fid) { record in
                Button {
                    appState.selectIdentity(record)
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "person.crop.circle.fill")
                            .font(.system(size: 32))
                            .foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(record.displayName)
                                .font(.headline)
                            Text(record.fid)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundStyle(.tertiary)
                    }
                    .contentShape(Rectangle())
                    .padding(.vertical, 4)
                }
                .buttonStyle(.plain)
                .contextMenu {
                    Button(role: .destructive) {
                        pendingDelete = record
                    } label: {
                        Label("Delete identity…", systemImage: "trash")
                    }
                }
            }
            .listStyle(.inset(alternatesRowBackgrounds: true))

            if let err = appState.lastError {
                Text(err)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }
        }
        .padding(.vertical)
        .frame(minWidth: 480, minHeight: 320)
        .alert("Delete identity?", isPresented: Binding(
            get: { pendingDelete != nil },
            set: { if !$0 { pendingDelete = nil } }
        ), presenting: pendingDelete) { record in
            Button("Delete", role: .destructive) {
                appState.deleteIdentity(record)
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) {
                pendingDelete = nil
            }
        } message: { record in
            Text("\"\(record.displayName)\" will be permanently removed from this Mac. " +
                 "Without the passphrase, the underlying data is unrecoverable — " +
                 "but the keypair is yours forever. You can recreate this identity by entering the same passphrase later.")
        }
    }
}
