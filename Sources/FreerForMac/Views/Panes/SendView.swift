import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Build, sign, and broadcast an FCH transaction from the live FID.
///
/// Flow: enter recipient + amount + fee → confirm → `session.sendFromLive`
/// (refresh UTXOs → greedy select → build → sign each P2PKH input →
/// `base.broadcastTx`). The signed tx never leaves the Mac unsigned.
///
/// Watch-only FIDs see a banner and the Send button stays disabled —
/// cold-sign export is a Phase 8 path.
struct SendView: View {
    let session: ActiveSession

    @State private var recipientFid: String = ""
    @State private var amountBch: String = ""
    @State private var feePerByte: String = "1"

    @State private var sending: Bool = false
    @State private var sendError: String?
    @State private var result: WalletService.SendResult?

    @State private var showConfirm: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            if !session.canSign {
                watchOnlyBanner
            }

            form
            Spacer()
        }
        .padding()
        .frame(minWidth: 480)
        .alert("Send \(formatBch(amountSatoshis ?? 0)) FCH?",
               isPresented: $showConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Send", role: .destructive) {
                Task { await runSend() }
            }
        } message: {
            Text("To: \(recipientFid)\nFee rate: \(feePerByte) sat/byte\n\nThis broadcasts immediately and cannot be undone.")
        }
    }

    private var watchOnlyBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "eye")
            Text("Watch-only — this FID has no privkey, sending is disabled. Switch to a signing FID or export an unsigned TxInfo (Phase 8).")
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
        .foregroundStyle(.orange)
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var form: some View {
        Form {
            Section {
                LabeledField(
                    "Recipient FID",
                    hint: (!recipientFid.isEmpty && !recipientLooksValid)
                        ? "Not a valid FCH mainnet address."
                        : nil,
                    hintIsError: true
                ) {
                    TextField("", text: $recipientFid, prompt: Text("F…"))
                        .font(.system(.body, design: .monospaced))
                        .fieldInputStyle()
                }
            } header: {
                Text("To")
            }

            Section {
                LabeledField(
                    "Amount",
                    hint: amountSatoshis.map { "= \($0) sat" }
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $amountBch, prompt: Text("0.001"))
                            .fieldInputStyle()
                            .frame(maxWidth: 200)
                        Text("FCH").foregroundStyle(.secondary)
                    }
                }

                LabeledField("Fee rate") {
                    HStack(spacing: 8) {
                        TextField("", text: $feePerByte, prompt: Text("1"))
                            .fieldInputStyle()
                            .frame(maxWidth: 80)
                        Text("sat/byte").foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Amount")
            }

            if let result {
                Section("Sent") { resultRows(result) }
            } else if let err = sendError {
                Section {
                    CopyableText(err, font: .callout)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Section {
                HStack {
                    Spacer()
                    Button {
                        sendError = nil
                        result = nil
                        showConfirm = true
                    } label: {
                        if sending {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("Sending…")
                            }
                            .frame(width: 120)
                        } else {
                            Text("Send").frame(width: 120)
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmit)
                }
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder
    private func resultRows(_ r: WalletService.SendResult) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                Text("Broadcast accepted").bold()
            }
            CopyableText(
                display: "txid: \(r.remoteTxid)",
                copy: r.remoteTxid,
                font: .system(.caption, design: .monospaced)
            )
            .lineLimit(1)
            .truncationMode(.middle)

            let summary = "\(r.plan.selected.count) input(s) · fee \(r.plan.fee) sat · \(r.plan.estimatedSize) B" +
                (r.plan.hasChange ? " · change \(r.plan.change) sat" : " · no change")
            CopyableText(summary, font: .caption.monospaced())
                .foregroundStyle(.secondary)

            if r.remoteTxid != r.transaction.txidDisplay {
                CopyableText(
                    "Local txid: \(r.transaction.txidDisplay) — server returned a different value.",
                    font: .caption
                )
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: - validation

    private var recipientLooksValid: Bool {
        (try? FchAddress(fid: recipientFid)) != nil
    }

    /// Parse `amountBch` as a decimal FCH amount and convert to
    /// satoshis. Returns nil if blank, malformed, ≤ 0, or > 21M FCH
    /// (which would overflow the Int64 cast in practice but mostly
    /// catches finger-trouble).
    private var amountSatoshis: Int64? {
        guard !amountBch.isEmpty,
              let bch = Double(amountBch),
              bch > 0,
              bch < 21_000_000
        else { return nil }
        return Int64((bch * Double(Cash.satoshisPerBch)).rounded())
    }

    private var feeRate: Int64? {
        guard let n = Int64(feePerByte), n > 0 else { return nil }
        return n
    }

    private var canSubmit: Bool {
        session.canSign &&
        !sending &&
        recipientLooksValid &&
        amountSatoshis != nil &&
        feeRate != nil
    }

    // MARK: - run

    @MainActor
    private func runSend() async {
        guard let amount = amountSatoshis, let fee = feeRate else { return }
        sending = true
        sendError = nil
        result = nil
        defer { sending = false }
        do {
            let r = try await session.sendFromLive(
                to: recipientFid,
                amount: amount,
                feePerByte: fee
            )
            result = r
        } catch {
            sendError = String(describing: error)
        }
    }

    private func formatBch(_ sats: Int64) -> String {
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        let bch = Double(sats) / Double(Cash.satoshisPerBch)
        return f.string(from: NSNumber(value: bch)) ?? "0"
    }
}
