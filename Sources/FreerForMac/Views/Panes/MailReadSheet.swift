import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Read one mail — the Mac port of Android's `ReadMailActivity`.
///
/// Shows the body it was handed (the pane decrypts before presenting)
/// and, under it, the envelope: both FIDs, the time, the fee that was
/// paid, and the carve txid. That block is not incidental detail — it is
/// the part of a mail that is *public*, and a reader deciding what to
/// write back should be able to see exactly what the chain already
/// says.
struct MailReadSheet: View {
    let session: ActiveSession
    let mail: Mail
    let onClose: () -> Void
    let onReply: (Mail) -> Void
    let onDelete: (Mail) -> Void

    private var me: String { session.liveFid }
    private var incoming: Bool { mail.isIncoming(for: me) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    bodySection
                    Divider()
                    envelopeSection
                }
                .padding(20)
            }

            Divider()
            footer
        }
        .frame(width: 620, height: 560)
    }

    // MARK: - sections

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            FidAvatarView(fid: mail.counterparty(for: me) ?? me, size: 44)
            VStack(alignment: .leading, spacing: 2) {
                Text(incoming ? "From" : "To")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                CopyableText(
                    display: displayName,
                    copy: mail.counterparty(for: me) ?? "",
                    font: .headline
                )
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                if let t = mail.birthTime {
                    Text(Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(t))))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if mail.isDeleted {
                    Text("Deleted")
                        .font(.caption2.bold())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.red.opacity(0.15)))
                        .foregroundStyle(.red)
                }
            }
        }
        .padding(20)
    }

    private var displayName: String {
        if let name = mail.counterpartyName(for: me),
           (try? FchAddress(fid: name)) == nil {
            return name
        }
        return (mail.counterparty(for: me) ?? "?").elidingMiddle(head: 10, tail: 10)
    }

    @ViewBuilder
    private var bodySection: some View {
        if let content = mail.content, !content.isEmpty {
            Text(content)
                .font(.body)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        } else if mail.decrypted == false {
            VStack(alignment: .leading, spacing: 6) {
                Label("Can't open this mail", systemImage: "lock.slash")
                    .foregroundStyle(.orange)
                Text(session.canSign
                     ? "It is sealed to a key this identity doesn't hold — most often it was addressed to another of your FIDs. Switch to that identity and it will open. The ciphertext is kept, so nothing is lost in the meantime."
                     : "This is a watch-only identity, so there is no private key here to decrypt with.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else {
            Text("Empty message.")
                .font(.body)
                .foregroundStyle(.secondary)
        }
    }

    private var envelopeSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "eye").foregroundStyle(.secondary)
                Text("Public on the chain")
                    .font(.caption.bold())
                    .foregroundStyle(.secondary)
            }
            Text("Only the message above is encrypted. Everything below was written to the chain in the clear when this mail was sent.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)

            field("From", mail.from)
            field("To", mail.to)
            if let fee = mail.noticeFee {
                LabeledContent("Notice fee") {
                    Text("\(NoticeFee.coinString(satoshis: fee)) F \(incoming ? "paid to you" : "paid by you")")
                        .font(.callout)
                }
            }
            if let height = mail.lastHeight {
                LabeledContent("Block") {
                    Text(height == MailsStore.unconfirmedHeight
                         ? "Pending — broadcast, not yet in a block"
                         : String(height))
                        .font(.callout)
                }
            }
            field("Transaction", mail.id)
        }
    }

    @ViewBuilder
    private func field(_ label: String, _ value: String?) -> some View {
        if let value, !value.isEmpty {
            LabeledContent(label) {
                CopyableText(
                    display: value.count > 24 ? value.elidingMiddle(head: 10, tail: 10) : value,
                    copy: value,
                    font: .system(.callout, design: .monospaced)
                )
            }
        }
    }

    private var footer: some View {
        HStack {
            Button(role: mail.isDeleted ? nil : .destructive) {
                onDelete(mail)
            } label: {
                Label(mail.isDeleted ? "Recover…" : "Delete…",
                      systemImage: mail.isDeleted ? "arrow.uturn.backward" : "trash")
            }

            Spacer()

            Button("Close") { onClose() }
                .keyboardShortcut(.cancelAction)

            if !mail.isDeleted {
                Button {
                    onReply(mail)
                } label: {
                    Label("Reply", systemImage: "arrowshape.turn.up.left")
                }
                .buttonStyle(.borderedProminent)
                .disabled(!session.canSign)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .full
        f.timeStyle = .short
        return f
    }()
}
