import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Write and send a mail — the Mac port of Android's
/// `CreateMailActivity`.
///
/// The screen is built around one fact: **sending costs money and can be
/// refused**, so the quote comes first. Before the user types anything
/// we look the recipient up and answer two questions they cannot guess —
/// whether the FID has ever published a public key (without one there is
/// nothing to encrypt to, and no mail is possible at all), and what they
/// charge to receive mail. Android asks both questions *after* the user
/// has written the message and pressed send.
struct MailComposeSheet: View {

    /// Pre-filled state, used by Reply.
    struct Preset {
        var recipient: String
        var body: String
        /// The mail being answered. Its notice fee is what the
        /// correspondent paid us, which the pay-back rule may match.
        var replyingTo: Mail?
    }

    let session: ActiveSession
    let preset: Preset?
    let onSent: (String) -> Void
    let onCancel: () -> Void

    @State private var recipient = ""
    /// Named `messageText`, not `body`: `body` is SwiftUI's own.
    @State private var messageText = ""
    @State private var quote: ActiveSession.MailQuote?
    @State private var quoting = false
    @State private var quoteError: String?
    @State private var sending = false
    @State private var sendError: String?
    @State private var showScan = false
    @State private var showConfirm = false

    private var replyingTo: Mail? { preset?.replyingTo }

    private var recipientLooksValid: Bool {
        (try? FchAddress(fid: recipient.trimmingCharacters(in: .whitespaces))) != nil
    }

    private var bodyBytes: Int { messageText.utf8.count }
    private var overLimit: Bool { bodyBytes > MailFeip.maxBodyBytes }

    private var canSend: Bool {
        session.canSign
            && !sending
            && recipientLooksValid
            && !messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !overLimit
            && quote?.canSend == true
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    recipientField
                    quotePanel
                    bodyField
                    if let err = sendError {
                        CopyableText(err, font: .caption).foregroundStyle(.red)
                    }
                }
                .padding(20)
            }

            Divider()
            footer
        }
        .frame(width: 620, height: 620)
        .onAppear {
            recipient = preset?.recipient ?? ""
            messageText = preset?.body ?? ""
            if recipientLooksValid { Task { await refreshQuote() } }
        }
        .onChange(of: recipient) { _, _ in
            quote = nil
            quoteError = nil
            if recipientLooksValid { Task { await refreshQuote() } }
        }
        .sheet(isPresented: $showScan) {
            QrScanSheet(title: "Scan recipient FID") { scanned in
                recipient = scanned
                showScan = false
            } onCancel: {
                showScan = false
            }
        }
        .alert("Send this mail?", isPresented: $showConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Send") { Task { await send() } }
        } message: {
            Text(confirmMessage)
        }
    }

    private var confirmMessage: String {
        let fee = quote?.fee.satoshis ?? 0
        return """
        Pays \(NoticeFee.coinString(satoshis: fee)) F to \(recipient.elidingMiddle(head: 10, tail: 10)), plus a small miner fee.

        The body is encrypted to you and the recipient. The two FIDs, the time and the amount are written to the chain in the clear and cannot be taken back.
        """
    }

    // MARK: - sections

    private var header: some View {
        HStack {
            Label(replyingTo == nil ? "New mail" : "Reply", systemImage: "square.and.pencil")
                .font(.headline)
            Spacer()
            Text("From \(session.liveFid.elidingMiddle(head: 8, tail: 8))")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(20)
    }

    private var recipientField: some View {
        LabeledField(
            "To",
            hint: (!recipient.isEmpty && !recipientLooksValid)
                ? "Not a valid FCH mainnet address."
                : nil,
            hintIsError: true
        ) {
            HStack(spacing: 8) {
                TextField("", text: $recipient, prompt: Text("F…"))
                    .font(.system(.body, design: .monospaced))
                    .fieldInputStyle()

                if !contacts.isEmpty {
                    Menu {
                        ForEach(contacts, id: \.id) { contact in
                            Button(contact.name) { recipient = contact.id }
                        }
                    } label: {
                        Image(systemName: "person.2")
                    }
                    .menuStyle(.borderlessButton)
                    .frame(width: 34)
                    .help("Pick from contacts")
                }

                Button {
                    showScan = true
                } label: {
                    Image(systemName: "qrcode.viewfinder")
                }
                .help("Scan the recipient FID from a QR code")
            }
        }
    }

    /// What this will cost, and whether it can happen at all. Both
    /// answers are the recipient's, not ours, so they arrive from the
    /// chain and are worth showing before a word is typed.
    @ViewBuilder
    private var quotePanel: some View {
        if quoting {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Looking up \(recipient.elidingMiddle(head: 8, tail: 8))…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } else if let err = quoteError {
            panel(color: .orange, icon: "exclamationmark.triangle") {
                Text("Couldn't reach the chain to price this mail.")
                    .font(.callout)
                CopyableText(err, font: .caption).foregroundStyle(.secondary)
            }
        } else if let quote {
            switch quote.fee {
            case .pay(let sats) where quote.recipientPubkey != nil:
                panel(color: .secondary, icon: "creditcard") {
                    Text("Notice fee: \(NoticeFee.coinString(satoshis: sats)) F")
                        .font(.callout)
                    Text(feeExplanation(sats: sats, published: quote.publishedNoticeFee))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            case .pay:
                panel(color: .red, icon: "key.slash") {
                    Text("This FID has never published a public key.")
                        .font(.callout)
                    Text("A mail is encrypted to the recipient's key, so there is nothing to encrypt to. A FID publishes its key the first time it spends — ask them to send any transaction, then try again.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            case let .refuse(requested, limit):
                panel(color: .red, icon: "hand.raised") {
                    Text("This FID charges \(NoticeFee.coinString(satoshis: requested)) F to receive mail.")
                        .font(.callout)
                    Text("That is over your limit of \(NoticeFee.coinString(satoshis: limit)) F. Raise the limit in Settings if you mean to pay it.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func feeExplanation(sats: Int64, published: String?) -> String {
        if let received = replyingTo?.noticeFee, received == sats, received > 0 {
            return "Matching what they paid you on the mail you're answering. Turn that off in Settings if you'd rather always pay their published rate."
        }
        if published == nil {
            return "They publish no rate, so this is the default. It is paid to the recipient, not to miners — it is what makes the mail reach them."
        }
        return "The rate this FID publishes for receiving mail. It is paid to them, not to miners."
    }

    private var bodyField: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Message").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text("\(bodyBytes) / \(MailFeip.maxBodyBytes) bytes")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(overLimit ? .red : .secondary)
            }
            TextEditor(text: $messageText)
                .font(.body)
                .frame(minHeight: 200)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .strokeBorder(
                            overLimit ? Color.red : Color.secondary.opacity(0.3),
                            lineWidth: overLimit ? 1.5 : 0.5
                        )
                )
            if overLimit {
                Text("Too long by \(bodyBytes - MailFeip.maxBodyBytes) bytes. A mail lives inside one transaction's data field; the limit is on the encrypted, encoded body, which is about a third larger than what you typed.")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var footer: some View {
        HStack {
            if !session.canSign {
                Label("Watch-only identity — no key to sign or encrypt with", systemImage: "eye")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            Spacer()
            Button("Cancel", role: .cancel) { onCancel() }
                .keyboardShortcut(.cancelAction)
            Button {
                showConfirm = true
            } label: {
                if sending {
                    ProgressView().controlSize(.small)
                } else {
                    Text("Send")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!canSend)
            .keyboardShortcut(.defaultAction)
        }
        .padding(20)
    }

    private func panel(
        color: Color,
        icon: String,
        @ViewBuilder content: () -> some View
    ) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 4, content: content)
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var contacts: [Contact] {
        (try? session.contacts.all()) ?? []
    }

    // MARK: - actions

    private func refreshQuote() async {
        let fid = recipient.trimmingCharacters(in: .whitespaces)
        guard (try? FchAddress(fid: fid)) != nil else { return }
        quoting = true
        quoteError = nil
        defer { quoting = false }
        do {
            let result = try await session.quoteMail(to: fid, replyingTo: replyingTo)
            // The field may have moved on while we were waiting.
            guard recipient.trimmingCharacters(in: .whitespaces) == fid else { return }
            quote = result
        } catch {
            quoteError = String(describing: error)
        }
    }

    private func send() async {
        guard let quote, canSend else { return }
        sending = true
        sendError = nil
        defer { sending = false }
        do {
            let sent = try await session.sendMailOnChain(quote: quote, content: messageText)
            onSent(sent.txid)
        } catch {
            sendError = String(describing: error)
        }
    }
}
