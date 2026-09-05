import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// The messages of one conversation.
///
/// The transcript itself is the one part of the pane that genuinely is
/// the same for all four flavours: a bubble, who said it, when, and what
/// happened to it. Everything that differs — who may be here, what
/// sealing applies, what the menu offers — was decided before this view
/// is reached, which is why it takes a ``ChatModeStyle`` only to tint
/// its own chrome and never to branch on.
struct TranscriptView: View {

    let session: ActiveSession
    let style: ChatModeStyle
    let conversation: Conversation
    let page: MessagesStore.Page
    let player: VoicePlayer
    /// Who the FIDs in this transcript are. Read-only here — the pane
    /// owns it and fills it as threads are opened.
    let names: ChatNameBook

    let onLoadOlder: () -> Void
    let onDownload: (ImMessage) -> Void

    /// The empty row pinned under the last bubble. Scrolling to a bubble
    /// would stop at the top of a tall one; scrolling here always lands
    /// on the true end of the transcript.
    private static let bottomAnchor = "transcript.bottom"

    /// False until the first scroll has happened, so a transcript that is
    /// merely being opened *starts* at the bottom instead of animating
    /// down to it in front of the user.
    @State private var settled = false

    /// The speaker's circle, and the gutter every bubble in their run
    /// is indented by. One constant so the two cannot drift apart and
    /// leave a run stepping sideways at its second message.
    private static let avatarSize: CGFloat = 30

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    if page.hasOlder {
                        Button("Load earlier messages", action: onLoadOlder)
                            .buttonStyle(.borderless)
                            .font(.caption)
                    }
                    ForEach(Array(page.messages.enumerated()), id: \.element.id) { index, message in
                        bubble(message, after: index > 0 ? page.messages[index - 1] : nil)
                    }
                    if page.messages.isEmpty {
                        Text("Nothing said here yet.")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                            .padding(.vertical, 20)
                    }
                    Color.clear
                        .frame(height: 1)
                        .id(Self.bottomAnchor)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
            }
            // The newest message, not the count: loading *earlier* pages
            // grows the list too, and yanking the view to the bottom
            // there would undo what the user just asked for.
            .onChange(of: newestId, initial: true) { _, _ in
                scrollToBottom(proxy)
            }
            .onChange(of: conversation.id) { _, _ in
                settled = false
                scrollToBottom(proxy)
            }
        }
        .background(Color(NSColor.textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    /// What the user thinks of as "the latest message" — a new one sent
    /// or received changes this; a status flipping to Sent does not.
    private var newestId: String? {
        page.messages.last?.id
    }

    private func scrollToBottom(_ proxy: ScrollViewProxy) {
        // The row that triggered this doesn't exist in the lazy stack yet
        // on the turn the page changes, so the scroll is asked for once
        // that layout pass is behind us.
        Task { @MainActor in
            if settled {
                withAnimation(.easeOut(duration: 0.2)) {
                    proxy.scrollTo(Self.bottomAnchor, anchor: .bottom)
                }
            } else {
                proxy.scrollTo(Self.bottomAnchor, anchor: .bottom)
                settled = true
            }
        }
    }

    // MARK: - bubbles

    /// The FID behind an incoming message.
    ///
    /// A P2P message that arrived without a `senderId` can only have
    /// come from the one party the thread is with, so the thread's own
    /// target stands in. A group message cannot be repaired that way:
    /// the target of a room, a team or a square is a room id or a txid,
    /// and handing one of those to ``AvatarMaker`` would composite a
    /// face out of a transaction. Nil, and the row draws the neutral
    /// stand-in instead.
    private func senderFid(of message: ImMessage) -> String? {
        if let sender = message.senderId, !sender.isEmpty { return sender }
        return conversation.type == .p2p ? conversation.targetId : nil
    }

    /// How long a silence ends a run. Past this, the next message is a
    /// fresh remark rather than the same breath, and it gets its own
    /// face and name.
    ///
    /// **Not only a tidiness rule.** Without it a run has no upper
    /// bound: five messages sent across two days from one person are
    /// one run, so the four after the first are anonymous, and a
    /// transcript scrolled back to them shows nobody at all. Fifteen
    /// minutes is the usual chat-app figure and it does the job here —
    /// consecutive typing stays grouped, and coming back later does not.
    private static let runGap: Int64 = 15 * 60 * 1000

    /// Whether this message starts a new speaker's run, and so earns a
    /// face and a name of its own.
    private func opens(
        _ message: ImMessage, mine: Bool, sender: String?, after previous: ImMessage?
    ) -> Bool {
        guard let previous else { return true }
        if previous.isOutgoing(from: session.liveFid) != mine { return true }
        if senderFid(of: previous) != sender { return true }
        // An unstamped message cannot be shown to be *close* to the one
        // before it, so it is not assumed to be: it opens a run. The
        // cost of being wrong is a repeated avatar; the cost the other
        // way is a bubble with no attribution at all.
        guard let then = previous.timestamp, let now = message.timestamp else { return true }
        return now - then > Self.runGap
    }

    private func bubble(_ message: ImMessage, after previous: ImMessage?) -> some View {
        let mine = message.isOutgoing(from: session.liveFid)
        let sender = senderFid(of: message)
        // One person saying three things in a row is one person. Only
        // the first of a run is badged and given a face; the rest are
        // indented to the same place, so a P2P transcript does not turn
        // into a column of the same avatar repeated forty times while a
        // room still names every change of speaker.
        let opensRun = opens(message, mine: mine, sender: sender, after: previous)
        return HStack(alignment: .top, spacing: 8) {
            if mine {
                Spacer(minLength: 40)
            } else if opensRun {
                // Every flavour, including P2P. The thread header names
                // the one person a P2P chat is with, but a transcript
                // read from the middle — scrolled back, or glanced at
                // after switching threads — has no header in view, and
                // the face is the fastest answer to "whose words are
                // these" that a screen can give.
                FidAvatarView(
                    fid: sender ?? "",
                    size: Self.avatarSize,
                    isNobody: sender.map(names.isNobody) ?? false
                )
            } else {
                Color.clear.frame(width: Self.avatarSize, height: 1)
            }
            VStack(alignment: mine ? .trailing : .leading, spacing: 3) {
                if !mine, opensRun, let sender {
                    ChatIdentityTag(
                        fid: sender,
                        cid: names.cid(of: sender) ?? message.senderName,
                        tint: style.tint
                    )
                }
                body(of: message)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(mine ? style.tint.opacity(0.18)
                                       : Color(NSColor.controlBackgroundColor))
                    )
                HStack(spacing: 4) {
                    if let time = message.timestamp {
                        Text(ChatFormat.shortTime.string(from: Date(timeIntervalSince1970: Double(time) / 1000)))
                    }
                    if mine { statusLabel(message) }
                }
                .font(.caption2)
                .foregroundStyle(.tertiary)
            }
            if !mine { Spacer(minLength: 40) }
        }
    }

    @ViewBuilder
    private func body(of message: ImMessage) -> some View {
        if message.isSealed {
            HStack(spacing: 4) {
                Image(systemName: "lock.slash")
                Text(message.symkeyVersion.map { "Sealed with key v\($0) — not held here" }
                     ?? "Sealed to a key this identity doesn't hold")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        } else if message.contentType == .voice {
            // Before the `content` branch, because a voice note's
            // content is its metadata JSON — showing that to the user is
            // showing them the plumbing.
            voiceBubble(message)
        } else if message.contentType == .hat, let offer = session.fileShare.offer(in: message) {
            fileBubble(offer, message: message)
        } else if let content = message.content {
            Text(content).textSelection(.enabled)
        } else {
            Text(Conversation.preview(for: message) ?? "")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    /// A voice note: play it, and see how long it is.
    ///
    /// The audio is *in* the message — a short note travels inline — so
    /// there is nothing to fetch and no offer to accept. A long note
    /// went to DISK instead and arrives as a file share, which is why
    /// there is no download button here.
    @ViewBuilder
    private func voiceBubble(_ message: ImMessage) -> some View {
        let meta = VoiceNote.meta(in: message)
        let id = message.id ?? ""
        let playing = player.playingId == id

        if let audio = message.data, !audio.isEmpty {
            HStack(spacing: 8) {
                Button {
                    player.toggle(id: id, data: audio)
                } label: {
                    Image(systemName: playing ? "pause.circle.fill" : "play.circle.fill")
                        .font(.title2)
                }
                .buttonStyle(.borderless)
                .help(playing ? "Stop" : "Play this voice note")

                ChatTrack(fraction: playing ? player.progress : 0, width: 90, color: style.tint)

                Text(VoiceNote.formatDuration(meta?.durationMs ?? 0))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        } else {
            // Metadata but no audio: a note whose payload was dropped
            // somewhere between the sender and the store. Say so rather
            // than drawing a play button that does nothing.
            Label("Voice note — the audio didn't arrive", systemImage: "mic.slash")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    /// A shared file: what it is, and the one action that applies.
    private func fileBubble(_ offer: FileShareService.Offer, message: ImMessage) -> some View {
        HStack(spacing: 8) {
            Image(systemName: offer.isDownloaded ? "doc.fill" : "doc")
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(offer.name).lineLimit(1)
                HStack(spacing: 6) {
                    if let size = offer.size {
                        Text(ByteCountFormatter.string(fromByteCount: size, countStyle: .file))
                    }
                    if !offer.hasKey {
                        Text("no key — only fetchable if public")
                    }
                }
                .font(.caption2)
                .foregroundStyle(.tertiary)
            }
            if offer.isDownloaded {
                Button("Reveal") {
                    if let url = offer.localURL {
                        NSWorkspace.shared.activateFileViewerSelecting([url])
                    }
                }
                .buttonStyle(.borderless)
                .font(.caption)
            } else {
                Button("Download") { onDownload(message) }
                    .buttonStyle(.borderless)
                    .font(.caption)
            }
        }
    }

    /// The delivery state, told straight. "Sent" means the DOCK took it
    /// and nothing more — a checkmark claiming the recipient has it would
    /// be a claim this route cannot make.
    @ViewBuilder
    private func statusLabel(_ message: ImMessage) -> some View {
        switch message.status {
        case .pending, .none:
            Label("Queued", systemImage: "clock")
                .help("Sealed and waiting in the outbox. It goes out on the next send.")
        case .sent:
            Label("Sent", systemImage: "checkmark")
                .help("Parked at their DOCK. They have it when they next collect.")
        case .delivered:
            Label("Delivered", systemImage: "checkmark.circle")
        case .read:
            Label("Read", systemImage: "checkmark.circle.fill")
        case .failed:
            Label("Failed", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
        case .quarantined:
            Label("Held", systemImage: "hand.raised")
                .help("Held as a message request — it is not in a conversation yet.")
        case .imported:
            Label("Imported", systemImage: "tray.and.arrow.down")
        }
    }
}

/// The one bar shape both playback progress and the recording level are
/// drawn with.
struct ChatTrack: View {
    let fraction: Double
    let width: CGFloat
    let color: Color

    var body: some View {
        ZStack(alignment: .leading) {
            Capsule().fill(Color.secondary.opacity(0.25))
            Capsule().fill(color)
                .frame(width: width * max(0, min(1, fraction)))
        }
        .frame(width: width, height: 5)
    }
}
