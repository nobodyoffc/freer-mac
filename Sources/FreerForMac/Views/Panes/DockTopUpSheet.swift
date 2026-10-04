import SwiftUI
import FCDomain
import FCUI

/// Top up our prepaid balance on a DOCK that has started answering 402.
///
/// A FAPI server charges per KB for what `dock.fetch` returns and what
/// `dock.put` stores. When the balance runs out it keeps the messages
/// but stops handing them over, and before this sheet the only trace
/// was a "Could not collect" line in the system log that read like a
/// network fault. The fix is a payment to the service's dealer, which
/// the server credits to the payer after one confirmation — see
/// ``DockTopUp``.
///
/// **Paid from the main FID, whoever is live.** The DOCK connection is
/// the main's, so the main is the account the server charges; the sheet
/// says so rather than letting a sub-identity pay into a balance nobody
/// draws on.
struct DockTopUpSheet: View {

    @Environment(AppState.self) private var appState
    let session: ActiveSession
    let unpaid: DockRegistry.Unpaid
    let onClose: () -> Void

    @State private var topUp: DockTopUp?
    @State private var loading = true
    @State private var loadError: String?

    @State private var amountText = ""
    @State private var paying = false
    @State private var payError: String?
    @State private var paidTxid: String?

    /// Where the payment for this DOCK stands, as of when the sheet opened.
    private var stage: DockRegistry.Unpaid.Stage { unpaid.stage() }

    /// Paid and waiting: the sheet reports, it does not offer to pay
    /// again — that is how a second payment for one shortfall happens.
    private var isConfirming: Bool {
        if case .confirming = stage { return paidTxid == nil }
        return false
    }

    private var amountSats: Int64? {
        NoticeFee.satoshis(coinString: amountText).flatMap { $0 > 0 ? $0 : nil }
    }

    /// Why Pay is disabled, always said out loud. A grey button with
    /// nothing beside it is what this sheet first shipped with, and it
    /// told the user nothing about a lookup that had failed above.
    private var blockReason: String? {
        if paidTxid != nil { return nil }
        if loading { return "Asking the server who to pay…" }
        guard let topUp else { return "No one to pay yet. See the problem above." }
        guard let amountSats else { return "Enter an amount in F, like 0.01." }
        if let min = topUp.minPaymentSats, amountSats < min {
            return "This service asks for at least \(NoticeFee.coinString(satoshis: min)) F per payment."
        }
        if !topUp.offeredCashes.isEmpty, amountSats >= topUp.offeredSats + topUp.localSats {
            return "Only \(NoticeFee.coinString(satoshis: topUp.offeredSats + topUp.localSats)) F is available to pay from, and the miner fee comes out of it too. Pay less."
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if isConfirming, case let .confirming(txid, sentAt) = stage {
                        confirmingPanel(txid: txid, sentAt: sentAt)
                    } else {
                        payBody
                    }
                }
                .padding(16)
            }
            Divider()
            footer
        }
        .frame(width: 520, height: 540)
        .fidDetailsHost(session: session)
        .task {
            if isConfirming { loading = false } else { await load() }
        }
    }

    @ViewBuilder
    private var payBody: some View {
                    if case let .lapsed(txid, sentAt) = stage, paidTxid == nil {
                        lapsedPanel(txid: txid, sentAt: sentAt)
                    }
                    whyPanel
                    if let loadError {
                        problem(loadError)
                    } else if let topUp {
                        payPanel(topUp)
                    }
                    if let payError { problem(payError) }
                    if let paidTxid { paidPanel(paidTxid) }
    }

    // MARK: - chrome

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "creditcard.trianglebadge.exclamationmark")
                .font(.title2)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("Top up server balance").font(.title3.bold())
                CopyableText(
                    unpaid.dockUrl,
                    font: .system(.caption, design: .monospaced),
                    color: .secondary
                )
            }
            Spacer()
            if loading { ProgressView().controlSize(.small) }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var footer: some View {
        HStack(spacing: 10) {
            if let blockReason, !paying {
                CopyableText(blockReason)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if isConfirming {
                Button("Close", action: onClose).keyboardShortcut(.cancelAction)
                Button("Check now") {
                    appState.retryUnpaidDock(unpaid.dockUrl)
                    onClose()
                }
                .keyboardShortcut(.defaultAction)
            } else if paidTxid != nil {
                Button("Done") {
                    appState.retryUnpaidDock(unpaid.dockUrl)
                    onClose()
                }
                .keyboardShortcut(.defaultAction)
            } else {
                Button("Cancel", action: onClose).keyboardShortcut(.cancelAction)
                Button {
                    Task { await pay() }
                } label: {
                    if paying {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Pay", systemImage: "arrow.up.right.circle.fill")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(topUp == nil || blockReason != nil || paying)
            }
        }
        .padding(12)
    }

    // MARK: - panels

    private var whyPanel: some View {
        panel("Why") {
            Text("This server is up, but your prepaid balance with it has run out, so it is holding your messages instead of handing them over. Nothing is lost: they are collected once the top-up confirms.")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            CopyableText(unpaid.message, font: .caption, color: .secondary)
            if !unpaid.recipientIds.isEmpty {
                caption("\(unpaid.recipientIds.count) mailbox\(unpaid.recipientIds.count == 1 ? "" : "es") waiting here.")
            }
        }
    }

    private func payPanel(_ topUp: DockTopUp) -> some View {
        panel("Payment") {
            row("Service") {
                Text(topUp.service.displayName).font(.callout)
            }
            row("Pay to") { FidValue(topUp.dealer) }
            row("Paid from") { FidValue(topUp.payer) }
            if topUp.payer != session.liveFid {
                caption("Your main FID pays, not the identity you are living as: the DOCK connection is the main's, so that is the balance the server draws on.")
            }
            row("Amount") {
                HStack(spacing: 6) {
                    TextField("", text: $amountText)
                        .fieldInputStyle()
                        .frame(width: 140)
                        .monospacedDigit()
                        .disabled(paidTxid != nil)
                    Text("F").foregroundStyle(.secondary)
                }
            }
            if let min = topUp.minPaymentSats {
                caption("Minimum payment: \(NoticeFee.coinString(satoshis: min)) F.")
            }
            if !topUp.offeredCashes.isEmpty {
                caption("Your balance here is spent, so this server refuses every call, including the ones a payment needs. It has offered \(topUp.offeredCashes.count) of your cashes (\(NoticeFee.coinString(satoshis: topUp.offeredSats)) F) and one free broadcast to pay with. Approve the payment within a minute of pressing Pay.")
                if topUp.localSats > 0 {
                    caption("To pay more, cashes from this Mac's cache (up to \(NoticeFee.coinString(satoshis: topUp.localSats)) F) are added after the offered ones. The server has not checked those; if one turns out to be spent, the payment is refused and you open this again.")
                }
                if let amountSats, amountSats >= topUp.offeredSats, topUp.localSats > 0,
                   amountSats < topUp.offeredSats + topUp.localSats {
                    // Not `caption(_:)`: its own `.secondary` would beat
                    // an outer orange.
                    CopyableText("This amount uses cashes from the local cache as well as the offered ones.", font: .caption, color: .orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if topUp.source == .chain {
                caption("The server did not describe itself, so this dealer comes from its record on the chain.")
            }
            if let out = topUp.service.pricePerKBOut ?? topUp.service.pricePerKB {
                caption("Price: \(out) F per KB delivered to you.")
            }
            caption("The server credits a payment once a block confirms it, usually within a minute or two.")
        }
    }

    private func confirmingPanel(txid: String, sentAt: Date) -> some View {
        panel("Top-up sent") {
            HStack(spacing: 6) {
                Image(systemName: "hourglass").foregroundStyle(.blue)
                Text("Paid \(sentAt.formatted(.relative(presentation: .named))). Messages resume once a block confirms it and the server credits it, usually within a few minutes.")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
            row("Txid") { txidText(txid) }
            caption("This tile clears itself the first time the server serves again. If it is still here half an hour after paying, it turns orange and lets you pay again.")
        }
    }

    private func lapsedPanel(txid: String, sentAt: Date) -> some View {
        panel("Earlier top-up not credited") {
            CopyableText("A top-up sent \(sentAt.formatted(.relative(presentation: .named))) has not been credited. Check the txid before paying again: if it confirmed, the server may just be slow to scan.")
                .font(.callout)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            row("Txid") { txidText(txid) }
        }
    }

    private func txidText(_ txid: String) -> some View {
        CopyableText(
            display: txid.elidingMiddle(head: 10, tail: 10),
            copy: txid,
            font: .system(.caption, design: .monospaced)
        )
    }

    private func paidPanel(_ txid: String) -> some View {
        panel("Paid") {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                Text("Sent. Messages arrive once the payment confirms.").font(.callout)
            }
            row("Txid") {
                CopyableText(
                    display: txid.elidingMiddle(head: 10, tail: 10),
                    copy: txid,
                    font: .system(.caption, design: .monospaced)
                )
            }
        }
    }

    // MARK: - actions

    private func load() async {
        loading = true
        defer { loading = false }
        do {
            let found = try await session.dockTopUp(for: unpaid.dockUrl)
            topUp = found
            if amountText.isEmpty {
                amountText = NoticeFee.coinString(satoshis: found.suggestedSats)
            }
        } catch {
            loadError = String(describing: error)
        }
    }

    private func pay() async {
        guard let topUp, let amountSats else { return }
        paying = true
        payError = nil
        defer { paying = false }
        do {
            let result = try await session.payDockTopUp(topUp, amount: amountSats)
            paidTxid = result.remoteTxid
            await appState.refreshLiveFidInfo()
        } catch {
            payError = String(describing: error)
        }
    }

    // MARK: - bits

    private func panel<Content: View>(
        _ title: String, @ViewBuilder _ content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func row<Content: View>(
        _ label: String, @ViewBuilder _ content: () -> Content
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 72, alignment: .leading)
            content()
            Spacer(minLength: 0)
        }
    }

    private func caption(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func problem(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            CopyableText(text, font: .callout)
        }
    }
}
