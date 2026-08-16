import SwiftUI
import FCDomain
import FCUI

/// Who may start a conversation with this identity — Android's
/// `P2pChatSettingsActivity` and `BlacklistActivity` in one place,
/// because they are one question and its exceptions.
///
/// **This applies to P2P only, and the sheet says so.** A square is open
/// by definition, and being in a team or a room already means the
/// conversation was accepted; a setting that silently also governed
/// group traffic would quarantine a group chat one member at a time.
struct StrangerPolicySheet: View {

    let session: ActiveSession
    let onClose: () -> Void

    @State private var policy = ContactPolicy()
    @State private var error: String?
    @State private var addFid = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Who can message me").font(.title3.bold())
                Spacer()
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }

            Text("An FID is public, so anyone who knows yours can send you a message. This decides what happens to the first one. It applies to direct chats only — rooms, teams and squares are governed by their own membership.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            strategyPicker

            Divider()

            listSection(
                title: "Blocked",
                caption: "Messages from these FIDs are discarded on arrival. Nothing is stored and nothing is shown.",
                fids: policy.blacklist.sorted(),
                actionTitle: "Unblock",
                action: { fid in change { $0.unblock(fid) } }
            )

            listSection(
                title: "Always allowed",
                caption: "Accepted senders. Their messages go straight into your chat list.",
                fids: policy.whitelist.sorted().filter { $0 != session.liveFid },
                actionTitle: "Forget",
                action: { fid in change { $0.whitelist.remove(fid) } }
            )

            blockByHand

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(width: 560, height: 560)
        .onAppear(perform: load)
    }

    private var strategyPicker: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(ContactPolicy.Strategy.allCases) { option in
                Button {
                    change { $0.strategy = option }
                } label: {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: policy.strategy == option
                              ? "largecircle.fill.circle" : "circle")
                            .foregroundStyle(policy.strategy == option ? Color.accentColor : .secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(option.title)
                            Text(option.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }

            // Said plainly, because "held" is the whole design and it is
            // not what people expect a blocklist app to do.
            Text("Whatever you choose, a held message is kept — it waits in Message requests rather than being deleted.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    private func listSection(
        title: String,
        caption: String,
        fids: [String],
        actionTitle: String,
        action: @escaping (String) -> Void
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("\(title) (\(fids.count))").font(.headline)
            Text(caption).font(.caption2).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)

            if fids.isEmpty {
                Text("None.").font(.caption).foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(fids, id: \.self) { fid in
                            HStack {
                                CopyableText(
                                    display: fid.elidingMiddle(head: 8, tail: 8),
                                    copy: fid,
                                    font: .caption
                                )
                                Spacer()
                                Button(actionTitle) { action(fid) }
                                    .buttonStyle(.borderless)
                                    .font(.caption)
                            }
                            .padding(.vertical, 4)
                            Divider()
                        }
                    }
                }
                .frame(maxHeight: 96)
            }
        }
    }

    private var blockByHand: some View {
        HStack(spacing: 8) {
            TextField("FID to block", text: $addFid)
                .textFieldStyle(.roundedBorder)
            Button("Block") {
                let fid = addFid.trimmingCharacters(in: .whitespaces)
                guard !fid.isEmpty else { return }
                change { $0.block(fid) }
                addFid = ""
            }
            .disabled(addFid.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }

    // MARK: - actions

    private func load() {
        do {
            policy = try session.contactPolicy.load(liveFid: session.liveFid)
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    private func change(_ edit: (inout ContactPolicy) -> Void) {
        do {
            policy = try session.contactPolicy.mutate(liveFid: session.liveFid, edit)
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }
}
