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

    let onLoadOlder: () -> Void
    let onDownload: (ImMessage) -> Void

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 10) {
                if page.hasOlder {
                    Button("Load earlier messages", action: onLoadOlder)
                        .buttonStyle(.borderless)
                        .font(.caption)
                }
                ForEach(page.messages) { message in
                    bubble(message)
                }
                if page.messages.isEmpty {
                    Text("Nothing said here yet.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .padding(.vertical, 20)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
        }
        .background(Color(NSColor.textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - bubbles

    private func bubble(_ message: ImMessage) -> some View {
        let mine = message.isOutgoing(from: session.liveFid)
        return HStack {
            if mine { Spacer(minLength: 40) }
            VStack(alignment: mine ? .trailing : .leading, spacing: 3) {
                if !mine, conversation.type != .p2p {
                    Text((message.senderName ?? message.senderId ?? "").elidingMiddle(head: 6, tail: 6))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
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
