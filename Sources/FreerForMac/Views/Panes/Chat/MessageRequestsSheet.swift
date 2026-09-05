import SwiftUI
import FCDomain
import FCUI

/// Messages from people this identity has not agreed to hear from.
///
/// This is the queue that makes the stranger gate humane. Holding a
/// message would be no better than dropping it if there were nowhere to
/// look, so everything held is here, in full, with the three answers
/// that make sense: let them in, throw this batch away, or make sure
/// they cannot reach us again.
///
/// **Accept and Block are not opposites of the same strength.** Accept
/// starts a thread and remembers the sender, so nothing they send later
/// is asked about again. Reject throws away *this batch only* — most of
/// these are somebody writing to the wrong FID, and making that
/// permanent would be a worse mistake than reading it. Block is the
/// permanent one, and it says so.
struct MessageRequestsSheet: View {

    let session: ActiveSession
    /// Who these strangers are. The sheet needs it more than anywhere
    /// else in the pane does: a name is most of the answer to "should I
    /// let this person in", and a bare FID is none of it.
    let names: ChatNameBook
    let onClose: () -> Void
    /// Called after anything that changes the thread list.
    let onChanged: () -> Void

    @State private var requests: [MessageRequest] = []
    @State private var selected: String?
    @State private var held: [ImMessage] = []
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Message requests").font(.title3.bold())
                Spacer()
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }

            Text("Nobody here is in a conversation yet. Their messages are stored on this Mac and nothing about them appears in your chat list until you accept.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            if requests.isEmpty {
                Spacer()
                Text("No requests waiting.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                Spacer()
            } else {
                HStack(alignment: .top, spacing: 12) {
                    senderList.frame(width: 210)
                    Divider()
                    detail
                }
            }
        }
        .padding(20)
        .frame(width: 640, height: 440)
        .onAppear(perform: load)
    }

    // MARK: - list

    private var senderList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(requests) { request in
                    HStack(alignment: .top, spacing: 8) {
                        FidAvatarView(
                            fid: request.fid,
                            size: 28,
                            isNobody: names.isNobody(request.fid)
                        )
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 4) {
                                Text(names.label(for: request.fid))
                                    .font(.body.weight(.bold))
                                    .lineLimit(1)
                                Text("\(request.count)")
                                    .font(.caption2.bold())
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(Capsule().fill(Color.secondary.opacity(0.25)))
                            }
                            Text(request.lastPreview ?? "")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                    .padding(.vertical, 7)
                    .padding(.horizontal, 9)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(request.fid == selected ? Color.accentColor.opacity(0.14) : .clear)
                    .contentShape(Rectangle())
                    .onTapGesture { select(request.fid) }
                    Divider()
                }
            }
        }
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - detail

    @ViewBuilder
    private var detail: some View {
        if let selected {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 8) {
                    FidAvatarView(
                        fid: selected,
                        size: 32,
                        isNobody: names.isNobody(selected)
                    )
                    // The full identity, badged: this is the string the
                    // user checks against whatever made them expect the
                    // message, and it decides the answer.
                    ChatIdentityTag(
                        fid: selected,
                        cid: names.cid(of: selected),
                        tint: .accentColor,
                        size: .large
                    )
                    Spacer()
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(held) { message in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(Conversation.preview(for: message) ?? "")
                                    .textSelection(.enabled)
                                if let time = message.timestamp {
                                    Text(ChatFormat.shortTime.string(
                                        from: Date(timeIntervalSince1970: Double(time) / 1000)
                                    ))
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                                }
                            }
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color(NSColor.controlBackgroundColor))
                            )
                        }
                    }
                }

                Text("Held messages are not counted as unread and their sender cannot see that you have read them.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)

                HStack {
                    Button("Accept") { accept(selected) }
                        .buttonStyle(.borderedProminent)
                        .help("Start a conversation with everything they have said already in it, and stop asking about them.")
                    Button("Reject") { reject(selected) }
                        .help("Throw this batch away. They are not blocked — a later message will be held and asked about again.")
                    Spacer()
                    Button("Block", role: .destructive) { block(selected) }
                        .help("Throw this batch away and discard anything they send from now on, without holding it.")
                }
            }
        } else {
            Text("Pick a sender on the left.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: - actions

    private func load() {
        do {
            requests = try session.messageRequests.pending()
            if selected == nil || !requests.contains(where: { $0.fid == selected }) {
                select(requests.first?.fid)
            }
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    private func select(_ fid: String?) {
        selected = fid
        guard let fid else { return held = [] }
        held = (try? session.messageRequests.held(from: fid)) ?? []
    }

    private func accept(_ fid: String) {
        do {
            _ = try session.messageRequests.promote(fid, as: session.liveFid)
            // Whitelisting is the half that matters tomorrow: without
            // it the next message from this sender is held all over
            // again and the user is asked a question they answered.
            try session.contactPolicy.mutate(liveFid: session.liveFid) { $0.allow(fid) }
            finish()
        } catch {
            self.error = String(describing: error)
        }
    }

    private func reject(_ fid: String) {
        do {
            _ = try session.messageRequests.reject(fid)
            finish()
        } catch {
            self.error = String(describing: error)
        }
    }

    private func block(_ fid: String) {
        do {
            _ = try session.messageRequests.reject(fid)
            try session.contactPolicy.mutate(liveFid: session.liveFid) { $0.block(fid) }
            finish()
        } catch {
            self.error = String(describing: error)
        }
    }

    private func finish() {
        load()
        onChanged()
    }
}
