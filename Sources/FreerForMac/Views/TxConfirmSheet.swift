import SwiftUI
import AppKit
import FCDomain
import FCUI

/// "Here is what you are about to sign." The modal behind the
/// Settings switch — Android's `SendTxActivity` review step, made
/// global so it covers every signing path rather than only the ones
/// that happen to route through a send screen.
///
/// **It shows the built transaction, not the request that produced
/// it.** Inputs are the cashes being consumed, outputs are decoded
/// back out of their scripts, and change is labelled as change. A
/// carve additionally shows its payload, because "publish this
/// contact" and "write these 400 bytes on a public ledger forever"
/// are the same action described at two very different distances.
///
/// **Nothing here is a button that means "yes" by accident.** Approve
/// is not the default action, so a stray Return doesn't sign; Escape
/// declines, which is the safe direction.
struct TxConfirmSheet: View {
    let preview: TxPreview
    let waiting: Int
    /// Used only to put names on FIDs. Optional because the dialog has
    /// to work when there is no session to speak of — a signing
    /// request outliving its session is a bug, but one that should
    /// still be refusable rather than crash.
    let session: ActiveSession?
    let onAnswer: (Bool) -> Void

    @State private var showInputs = false
    /// FID → the name we can show for it. Seeded synchronously from
    /// local contacts on appear, then topped up from the chain.
    @State private var names: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    headline
                    outputsCard
                    costCard
                    if preview.opReturn != nil { payloadCard }
                    inputsCard
                    if preview.spendsUnconfirmed { unconfirmedNote }
                }
                .padding(16)
            }
            Divider()
            buttons
        }
        .frame(minWidth: 580, minHeight: 540)
        .onAppear {
            resolveLocalNames()
            Task { await resolveChainNames() }
        }
    }

    // MARK: - header

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: glyph).font(.title2).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("Approve this transaction?").font(.title3).bold()
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if waiting > 0 {
                Text("\(waiting) more waiting")
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Capsule().fill(Color.secondary.opacity(0.15)))
                    .help("Other transactions are queued behind this one.")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var glyph: String {
        if !preview.payloadRedeemScripts.isEmpty { return "lock" }
        switch preview.kind {
        case .payment: return "paperplane.fill"
        case .carve:   return "square.and.pencil"
        case .reorg:   return "arrow.triangle.merge"
        }
    }

    private var subtitle: String {
        switch preview.kind {
        case .payment:
            return "A payment from this identity"
        case .reorg:
            return "Paying yourself to change denominations"
        case .carve:
            // A carve is only "writing data" when that is all it does.
            // A time lock's payload is machinery rather than a message,
            // and a composed transaction can pay people *and* carry
            // one — describing either as a data write buries the fact
            // that money is moving.
            if !preview.payloadRedeemScripts.isEmpty {
                return "A time-locked payment from this identity"
            }
            let subject = preview.feipName.map { "\($0) data" } ?? "data"
            if preview.payments.isEmpty { return "Writing \(subject) on chain" }
            return "A payment from this identity, writing \(subject) on chain"
        }
    }

    /// The one number most people are actually deciding about.
    private var headline: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(formatFch(preview.leaving))
                .font(.system(.largeTitle, design: .rounded).monospacedDigit().bold())
            Text("leaves this identity")
                .font(.callout)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    // MARK: - cards

    /// **Who is being paid, at a glance.** A 34-point avatar is
    /// derived from the address itself, so it is recognisable before
    /// the address is readable — which matters most for the mistake
    /// this dialog exists to catch: an address that is *almost* the
    /// right one. Two FIDs differing in the middle elide to the same
    /// `F9kL…mBq2` string and produce completely different avatars.
    private var outputsCard: some View {
        card("Outputs", systemImage: "arrow.up.right") {
            ForEach(Array(preview.outputs.enumerated()), id: \.offset) { index, out in
                HStack(alignment: .center, spacing: 10) {
                    Text("#\(index)")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.tertiary)
                        .frame(width: 22, alignment: .leading)

                    outputAvatar(out)

                    VStack(alignment: .leading, spacing: 2) {
                        if out.isOpReturn {
                            Text("OP_RETURN — data, pays nobody")
                                .font(.callout)
                                .foregroundStyle(.purple)
                        } else if let fid = out.fid, isAddress(fid) {
                            HStack(spacing: 6) {
                                Text(nameFor(fid, isSelf: out.isSelf))
                                    .font(.callout.bold())
                                    .lineLimit(1)
                                    .truncationMode(.tail)
                                if out.isSelf {
                                    chip(preview.kind == .reorg ? "yours" : "change", color: .blue)
                                        .help("This output pays the sending identity back.")
                                }
                            }
                            CopyableText.elidingMiddle(
                                fid, head: 10, tail: 8,
                                font: .system(.caption, design: .monospaced)
                            )
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        } else {
                            Text("unrecognised script")
                                .font(.callout)
                                .foregroundStyle(.orange)
                            if let hex = out.fid {
                                CopyableText.elidingMiddle(
                                    hex, head: 12, tail: 10,
                                    font: .system(.caption, design: .monospaced)
                                )
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                            }
                        }
                    }

                    Spacer(minLength: 8)
                    Text(formatFch(out.amount))
                        .font(.callout.monospacedDigit().bold())
                        .foregroundStyle(out.isSelf || out.isOpReturn ? .secondary : .primary)
                }
            }
        }
    }

    /// Avatar, or a same-sized stand-in for the outputs that have no
    /// address to derive one from — so every row lines up and the
    /// column reads as one list rather than a ragged one.
    @ViewBuilder
    private func outputAvatar(_ out: TxPreview.Output) -> some View {
        if out.isOpReturn {
            placeholderAvatar(systemImage: "doc.text", color: .purple)
        } else if let fid = out.fid, isAddress(fid) {
            FidAvatarView(fid: fid, size: 34)
                .overlay(
                    Circle().strokeBorder(
                        out.isSelf ? Color.blue.opacity(0.6) : Color.clear,
                        lineWidth: 2
                    )
                )
                .help(out.isSelf ? "This is you" : fid)
        } else {
            placeholderAvatar(systemImage: "questionmark", color: .orange)
        }
    }

    private func placeholderAvatar(systemImage: String, color: Color) -> some View {
        ZStack {
            Circle().fill(color.opacity(0.15))
            Image(systemName: systemImage)
                .font(.system(size: 14))
                .foregroundStyle(color)
        }
        .frame(width: 34, height: 34)
    }

    /// A decoded output carries either an address or a raw script hex
    /// in the same field; only the first can be avatared. FCH mainnet
    /// addresses are Base58Check and start with `F`.
    private func isAddress(_ s: String) -> Bool {
        s.first == "F" && s.count >= 26 && s.count <= 40
    }

    /// The name shown above the address: the identity's own label for
    /// change, a contact CID or a chain CID when we know one, and
    /// otherwise a plain word — never a second copy of the address,
    /// which is already on the line below.
    private func nameFor(_ fid: String, isSelf: Bool) -> String {
        if let known = names[fid], !known.isEmpty { return known }
        if isSelf {
            let label = session?.liveKeyInfo.label ?? ""
            return label.isEmpty ? "This identity" : label
        }
        // Not an alarm — paying someone you have never saved is
        // ordinary. It says what is true: the app has no name for
        // this address, so the avatar and the digits are all there is
        // to check against.
        return "Not in your contacts"
    }

    private var costCard: some View {
        card("Cost", systemImage: "tag") {
            row("Miner fee", "\(preview.fee) sat")
            row("Size", "\(preview.estimatedSize) B at \(preview.feePerByte) sat/B")
            if preview.coinDaysDestroyed > 0 {
                row("CoinDays destroyed", "\(preview.coinDaysDestroyed)")
            }
            HStack(spacing: 8) {
                Text("From").font(.callout).foregroundStyle(.secondary)
                Spacer(minLength: 8)
                FidAvatarView(fid: preview.from, size: 20)
                CopyableText.elidingMiddle(preview.from, head: 10, tail: 8,
                                          font: .system(.callout, design: .monospaced))
            }
        }
    }

    /// What is about to be written on the chain, **shown, not
    /// offered**.
    ///
    /// This was a collapsed disclosure group whose label said only how
    /// many bytes there were. That put the one part of the transaction
    /// that is irreversible *and* public behind a click, while the
    /// amounts — recoverable by asking the recipient nicely — sat in
    /// the open. Everything else in this dialog is a number a person
    /// can sanity-check at a glance; the payload is the part they
    /// actually have to read, so it is the last thing that should have
    /// to be asked for.
    ///
    /// Inputs stay collapsed, and that is not the same call: an
    /// outpoint list is noise whose total is already on the label, and
    /// nothing in it can surprise you the way a sentence can.
    private var payloadCard: some View {
        card(payloadTitle, systemImage: "curlybraces") {
            VStack(alignment: .leading, spacing: 8) {
                if !preview.payloadRedeemScripts.isEmpty {
                    redeemScriptSummary
                    Divider()
                }

                ScrollView {
                    Text(prettyPayload)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .frame(maxHeight: 200)
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color(nsColor: .textBackgroundColor))
                )

                HStack(spacing: 6) {
                    Text("\(preview.opReturnByteCount) bytes, written to the chain permanently and in public")
                    if payloadIsReformatted {
                        chip("formatted for reading", color: .secondary)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
    }

    private var payloadTitle: String {
        if !preview.payloadRedeemScripts.isEmpty { return "Payload — time-lock redeem scripts" }
        return preview.feipName.map { "Payload — \($0)" } ?? "Payload"
    }

    /// The manifest in words. Without this a time-locked payment asks
    /// the user to approve a wall of hex whose only readable fact —
    /// when the money comes free — is buried inside it.
    private var redeemScriptSummary: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Your payees need these to spend what you are paying them.")
                .font(.caption)
                .foregroundStyle(.secondary)
            ForEach(Array(preview.payloadRedeemScripts.enumerated()), id: \.offset) { _, p2sh in
                HStack(spacing: 8) {
                    Image(systemName: "lock")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                    CopyableText.elidingMiddle(
                        p2sh.address, head: 8, tail: 6,
                        font: .system(.caption, design: .monospaced)
                    )
                    if let lockTime = p2sh.lockTime, lockTime > 0 {
                        Text("locked until block \(lockTime)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.orange)
                    }
                    if let m = p2sh.m, let n = p2sh.n {
                        chip("\(m)-of-\(n)", color: .secondary)
                    }
                    Spacer(minLength: 8)
                }
            }
        }
    }

    /// True when what is on screen is a tidied rendering of the bytes
    /// rather than the bytes themselves — said out loud, because a
    /// dialog that reformats what you are signing and does not mention
    /// it is quietly asking you to trust the formatter.
    private var payloadIsReformatted: Bool {
        guard let raw = preview.opReturn else { return false }
        return prettyPayload != raw
    }

    private var inputsCard: some View {
        card("Inputs", systemImage: "arrow.down.left") {
            DisclosureGroup(isExpanded: $showInputs) {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(preview.inputs.enumerated()), id: \.offset) { _, cash in
                        HStack(spacing: 8) {
                            CopyableText(
                                display: "\(cash.birthTxId.elidingMiddle(head: 8, tail: 6)):\(cash.birthIndex)",
                                copy: "\(cash.birthTxId):\(cash.birthIndex)",
                                font: .system(.caption, design: .monospaced)
                            )
                            .foregroundStyle(.secondary)
                            if cash.unconfirmedDepth > 0 {
                                chip("unconfirmed ×\(cash.unconfirmedDepth)", color: .orange)
                            }
                            Spacer(minLength: 8)
                            Text(formatFch(cash.value))
                                .font(.caption.monospacedDigit())
                        }
                    }
                }
                .padding(.top, 4)
            } label: {
                Text("\(preview.inputs.count) cash(es), \(formatFch(preview.totalIn)) in total")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var unconfirmedNote: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "clock.badge.exclamationmark")
            Text("This spends cash from \(preview.unconfirmedDepth) of your own transaction(s) that haven't confirmed yet. It is valid and will normally confirm right behind them — but if one of those is ever dropped, this goes with it. The network carries at most \(Cash.maxUnconfirmedChain) such links.")
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.caption)
        .foregroundStyle(.orange)
    }

    // MARK: - buttons

    private var buttons: some View {
        HStack(spacing: 8) {
            Button("Don't sign") { onAnswer(false) }
                .keyboardShortcut(.cancelAction)
            Spacer()
            Text("Nothing is signed or broadcast until you approve.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button {
                onAnswer(true)
            } label: {
                Text("Approve & sign").frame(width: 150)
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - bits

    @ViewBuilder
    private func card(
        _ title: String,
        systemImage: String,
        @ViewBuilder _ content: () -> some View
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: systemImage)
                .font(.caption.bold())
                .foregroundStyle(.secondary)
            content()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func row(_ label: String, _ value: String, mono: Bool = false) -> some View {
        HStack(spacing: 8) {
            Text(label).font(.callout).foregroundStyle(.secondary)
            Spacer(minLength: 8)
            if mono {
                CopyableText.elidingMiddle(value, head: 10, tail: 8,
                                           font: .system(.callout, design: .monospaced))
            } else {
                Text(value).font(.callout.monospacedDigit())
            }
        }
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    /// Pretty-print the payload when it is JSON — which every FEIP
    /// carve is — and show it verbatim otherwise. Re-encoding sorts
    /// keys, so this is a *display* of the bytes, never the bytes
    /// themselves; the byte count above comes from the original.
    private var prettyPayload: String {
        guard let raw = preview.opReturn else { return "" }
        guard let data = raw.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(
                withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]
              )
        else { return raw }
        return String(decoding: pretty, as: UTF8.self)
    }

    // MARK: - names

    /// Every FID this dialog shows, deduped: the outputs plus the
    /// sender.
    private var addressesOnScreen: [String] {
        var out = preview.outputs.compactMap { o -> String? in
            guard !o.isOpReturn, let fid = o.fid, isAddress(fid) else { return nil }
            return fid
        }
        out.append(preview.from)
        return Array(Set(out))
    }

    /// Local contacts only — a store read, no network. Runs on appear
    /// so the dialog is never *waiting* on a name: the decision here
    /// is about money and must not be blocked on a lookup.
    private func resolveLocalNames() {
        guard let session else { return }
        for fid in addressesOnScreen where names[fid] == nil {
            if let contact = try? session.contacts.get(fid: fid),
               let label = contact.cid ?? contact.titles?.first,
               !label.isEmpty {
                names[fid] = label
            }
        }
    }

    /// Chain CIDs for whatever contacts didn't cover — the second half
    /// of the two-step every other pane uses. Best-effort and late:
    /// names appear while the user reads, and their absence never
    /// stops them from approving or refusing.
    private func resolveChainNames() async {
        guard let session else { return }
        let wanted = addressesOnScreen.filter { names[$0] == nil }
        guard !wanted.isEmpty else { return }
        guard let found = try? await session.directory.freerByIds(wanted) else { return }
        for (fid, freer) in found {
            if let cid = freer.cid, !cid.isEmpty { names[fid] = cid }
        }
    }

    private func formatFch(_ sats: Int64) -> String {
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        let value = Double(sats) / Double(Cash.satoshisPerBch)
        return (f.string(from: NSNumber(value: value)) ?? "0") + " FCH"
    }
}
