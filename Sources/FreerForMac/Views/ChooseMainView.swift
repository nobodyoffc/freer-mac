import SwiftUI
import FCDomain
import FCUI

/// Lists all main FIDs in the unlocked Configure. Tapping one opens
/// an ActiveSession for it; the "+" button takes the user to the
/// AddMainView form.
struct ChooseMainView: View {
    @Environment(AppState.self) private var appState

    @State private var working: String?     // FID currently being unlocked

    private var mains: [KeyInfo] {
        appState.configureSession?.listMains() ?? []
    }

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
            Button {
                Task {
                    working = info.fid
                    await appState.unlockMain(fid: info.fid)
                    working = nil
                }
            } label: {
                HStack(spacing: 12) {
                    FidAvatarView(fid: info.fid, size: 44)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(info.label.isEmpty ? "Main FID" : info.label)
                            .font(.headline)
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
            .buttonStyle(.plain)
            .disabled(working != nil)
        }
        .listStyle(.inset(alternatesRowBackgrounds: true))
    }
}
