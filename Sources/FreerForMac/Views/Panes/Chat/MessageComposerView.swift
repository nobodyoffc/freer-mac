import SwiftUI
import FCDomain
import FCUI

/// The composer, and the gate in front of it.
///
/// **What you may do here is decided by ``ChatGate``, not by this view.**
/// The pane used to check one thing — whether we had left the group —
/// and let everything else fail at send time, which meant it was
/// possible to write a message into a team this identity does not belong
/// to and learn about it from a sealing error. Now the verdict arrives
/// already made, and this view only renders it:
///
/// - `.open` — the composer.
/// - `.blocked` — the composer, disabled, with the reason under it. The
///   conversation is real and might work later.
/// - `.notMember` — no composer at all. There is nothing to write and no
///   state in which writing it would help; the transcript stays, because
///   the history is ours.
/// - `.ownerNeedsKey` — the composer disabled, plus the two ways out
///   only an owner has.
///
/// The sealing note is always drawn, whatever the verdict, and in the
/// flavour's own colour — the square's is the one that had to be
/// written, since a padlock the user assumed was there is worse than
/// none at all.
struct MessageComposerView: View {

    let style: ChatModeStyle
    let verdict: ChatGate.Verdict
    @Binding var draft: String

    let recorder: VoiceRecorder
    let attaching: Bool
    let sendingVoice: Bool
    let attachProgress: (sent: Int64, total: Int64)?
    let errorText: String?

    let onSend: () -> Void
    let onAttach: () -> Void
    let onStartRecording: () -> Void
    let onSendVoice: () -> Void
    let onCancelRecording: () -> Void
    let onGenerateKey: () -> Void

    @State private var showEmoji = false

    private var enabled: Bool { verdict.canSend }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let err = errorText ?? recorder.failure {
                CopyableComposerError(text: err)
            }

            if let reason = verdict.reason {
                reasonBar(reason)
            }

            if case .ownerNeedsKey = verdict {
                ownerKeyActions
            }

            if verdict.showsComposer {
                if let progress = attachProgress {
                    ProgressView(
                        value: Double(progress.sent),
                        total: Double(max(progress.total, 1))
                    ) {
                        Text("Uploading… the file goes to DISK before the message goes out")
                            .font(.caption2)
                    }
                    .progressViewStyle(.linear)
                }

                if recorder.isActive {
                    recordingBar
                } else {
                    textComposer
                }
            }

            sealingNote
        }
    }

    // MARK: - the gate's own chrome

    private func reasonBar(_ reason: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: verdict.showsComposer ? "exclamationmark.circle" : "person.crop.circle.badge.xmark")
            Text(reason)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    /// The owner's way out.
    ///
    /// Android offers two — make a key, or ask the members for the one
    /// they hold — and the second is deliberately **not** here yet:
    /// nothing on this client routes an inbound key share, so a button
    /// that sent a request no answer could ever satisfy would be worse
    /// than no button. It arrives with the rest of the key exchange.
    private var ownerKeyActions: some View {
        HStack(spacing: 8) {
            Button("Generate a key", action: onGenerateKey)
                .help("Make a new key for this \(style.noun) and share it with the members. Messages sealed under an older key stay readable to whoever holds that one.")
            Spacer(minLength: 0)
        }
        .font(.caption)
    }

    // MARK: - composer

    private var textComposer: some View {
        HStack(spacing: 8) {
            Button {
                showEmoji.toggle()
            } label: {
                Image(systemName: "face.smiling")
            }
            .buttonStyle(.borderless)
            .disabled(!enabled)
            .help("Insert an emoji")
            .popover(isPresented: $showEmoji, arrowEdge: .bottom) {
                EmojiPicker { emoji in
                    draft += emoji
                    showEmoji = false
                }
            }

            Button(action: onAttach) {
                if attaching {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "paperclip")
                }
            }
            .buttonStyle(.borderless)
            .disabled(!enabled || attaching)
            .help("Share a file — it is encrypted, uploaded to DISK, and the message carries the key")

            Button(action: onStartRecording) {
                Image(systemName: "mic")
            }
            .buttonStyle(.borderless)
            .disabled(!enabled || attaching)
            .help("Record a voice note. A short one rides inside the message; a long one goes to DISK like a shared file.")

            TextField(enabled ? "Message" : "Can't send here", text: $draft, axis: .vertical)
                .lineLimit(1...5)
                .textFieldStyle(.roundedBorder)
                .disabled(!enabled)
                .onSubmit(onSend)

            Button(action: onSend) {
                Label("Send", systemImage: "paperplane.fill")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!enabled || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }

    /// What the composer becomes while a note is being recorded.
    ///
    /// The text field goes away on purpose: there is one thing to decide
    /// here — send it or bin it — and leaving a half-typed message next
    /// to a running microphone invites sending the wrong one.
    private var recordingBar: some View {
        HStack(spacing: 10) {
            Button(action: onCancelRecording) {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .disabled(sendingVoice)
            .help("Discard this recording")

            Circle()
                .fill(recorder.isCapturing ? Color.red : Color.secondary)
                .frame(width: 8, height: 8)

            Text(VoiceNote.formatDuration(recorder.elapsedMs))
                .font(.callout.monospacedDigit())

            ChatTrack(fraction: recorder.level, width: 120, color: .red)
                .animation(.linear(duration: 0.1), value: recorder.level)

            if recorder.atLimit {
                Text("Five minutes is the cap — send it or start again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 0)

            Button(action: onSendVoice) {
                if sendingVoice {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Send", systemImage: "paperplane.fill")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(sendingVoice || !enabled)
        }
    }

    /// What sealing this conversation gets. Drawn in the flavour's
    /// colour, so the square's is red and impossible to read as the
    /// same reassurance the other three carry.
    private var sealingNote: some View {
        HStack(spacing: 4) {
            Image(systemName: style.sealingIcon)
            Text(style.sealingNote)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.caption2)
        .foregroundStyle(style.isPublic ? AnyShapeStyle(style.tint) : AnyShapeStyle(.tertiary))
    }
}

/// A composer error, copyable — the same rule the rest of the app
/// follows for anything a user might need to paste into a bug report.
private struct CopyableComposerError: View {
    let text: String

    var body: some View {
        CopyableText(text, font: .caption)
            .foregroundStyle(.orange)
    }
}
