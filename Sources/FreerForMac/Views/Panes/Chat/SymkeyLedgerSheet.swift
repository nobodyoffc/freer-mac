import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Every symkey this device gave away or took in, for one room or team.
///
/// **This exists because the exchange is silent.** A device answers a
/// symkey request automatically, on a membership check nobody watches,
/// and the key it hands over opens every message under that version —
/// including messages sent long before the requester joined. That is
/// intended: a joiner has to get the key from somewhere, and a human gate
/// would strand them. But it means this Mac gives away the group's
/// readable history without saying so, and FIMP §9.7 requires the record
/// that makes it inspectable afterwards.
///
/// Three questions have no other answer, and the sheet is laid out around
/// them: **who can read this** (the header), **what left unexpectedly**
/// (the refused and unsolicited rows), and **whose copy am I reading**
/// (the received rows' counterparties).
///
/// **It is local and never leaves.** It is a map of who can read what,
/// and unlike the membership it derives from — which is public on the
/// chain for a team — it exists nowhere else. Nothing here can be
/// exported, and the store it reads is excluded from history shares.
struct SymkeyLedgerSheet: View {

    @Environment(\.inspectFid) private var inspectFid

    let session: ActiveSession
    let style: ChatModeStyle
    let conversation: Conversation
    let names: ChatNameBook
    let onClose: () -> Void

    @State private var rows: [KeyLedgerEntry] = []
    @State private var holders: [String] = []
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Symkey exchange").font(.title3.bold())
                Spacer()
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }

            Text(explanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if !holders.isEmpty { holdersNote }

            if rows.isEmpty {
                Text("Nothing recorded for this \(style.noun) yet. This fills as keys are handed over, received, or asked for and refused.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                header
                Divider()
                list
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }
        }
        .padding(20)
        .frame(width: 620, height: 480)
        .onAppear(perform: load)
    }

    private var explanation: String {
        "Every symkey this Mac handed over or took in for this \(style.noun), and every request it could not answer. Kept on this Mac only — it is never sent anywhere, and never included in a history share."
    }

    /// The leak radius, said in one line.
    ///
    /// **Not the membership**, and the difference is the point: a member
    /// the owner never managed to push to can read nothing, and a FID
    /// removed from the group still holds every version it was given. Only
    /// this record knows which is which.
    private var holdersNote: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(holders.count) \(holders.count == 1 ? "identity" : "identities") can open this \(style.noun)'s messages")
                .font(.callout.bold())
            Text(holders.map(display).formatted(.list(type: .and)))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Everyone who was given a key, and everyone who gave us one. Not the same as the member list — a member who never received a key cannot read anything, and somebody who has left still holds what they were given.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(style.tint.opacity(0.08)))
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text("When").frame(width: 122, alignment: .leading)
            Text("").frame(width: 16)
            Text("Who").frame(width: 150, alignment: .leading)
            Text("Symkey").frame(width: 122, alignment: .leading)
            Text("What happened").frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(.caption2.bold())
        .foregroundStyle(.tertiary)
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(rows) { row in
                    HStack(spacing: 8) {
                        // Fixed-width and year-first, so two rows can be
                        // compared character by character.
                        Text(SymkeyVersionText.inTable(stampVersion(row.lastAt)))
                            .font(.caption.monospacedDigit())
                            .frame(width: 122, alignment: .leading)
                        Image(systemName: row.direction == .sent ? "arrow.up.right" : "arrow.down.left")
                            .font(.caption)
                            .foregroundStyle(row.direction == .sent ? .orange : style.tint)
                            .frame(width: 16)
                            .help(row.direction == .sent ? "Left this Mac" : "Arrived here")
                        Button {
                            inspectFid(row.counterparty)
                        } label: {
                            Text(display(row.counterparty))
                                .font(.caption)
                                .lineLimit(1)
                        }
                        .buttonStyle(.link)
                        .frame(width: 150, alignment: .leading)
                        CopyableText(
                            display: SymkeyVersionText.inTable(row.version),
                            copy: SymkeyVersionText.raw(row.version),
                            font: .caption.monospacedDigit(),
                            color: .secondary,
                            help: "Copy this symkey's version number"
                        )
                        .frame(width: 122, alignment: .leading)
                        HStack(spacing: 5) {
                            ChatChip(outcomeText(row), color: outcomeColor(row))
                            if !row.solicited, row.outcome == .shared || row.outcome == .stored {
                                ChatChip("unasked", color: .secondary)
                            }
                            if row.repeats > 1 {
                                Text("×\(row.repeats)")
                                    .font(.caption2.monospacedDigit())
                                    .foregroundStyle(.secondary)
                                    .help("Repeated \(row.repeats) times, most recently here")
                            }
                            Spacer(minLength: 0)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.vertical, 5)
                    Divider()
                }
            }
        }
        .task(id: rows.map(\.counterparty)) {
            names.resolve(rows.map(\.counterparty), session: session)
        }
    }

    /// What a row means, in the words a person would use. The refusals are
    /// said plainly rather than softened: a member asking again and again
    /// for a key nobody has is a stalled recovery somebody can fix.
    private func outcomeText(_ row: KeyLedgerEntry) -> String {
        switch row.outcome {
        case .shared:     return row.direction == .sent ? "sent" : "given to us"
        case .stored:     return "stored"
        case .duplicate:  return "already had it"
        case .refused:    return "refused — not asked for"
        case .unreadable: return "would not open"
        case .notHeld:    return "we don't hold it"
        case .notAMember: return "not a member"
        case .noPubkey:   return "no pubkey to seal to"
        }
    }

    private func outcomeColor(_ row: KeyLedgerEntry) -> Color {
        switch row.outcome {
        case .shared, .stored:          return style.tint
        case .duplicate:                return .secondary
        case .refused, .notAMember:     return .red
        case .unreadable, .noPubkey:    return .orange
        case .notHeld:                  return .orange
        }
    }

    private func display(_ fid: String) -> String {
        if fid == session.liveFid { return "your other devices" }
        return names.cid(of: fid) ?? fid.elidingMiddle(head: 6, tail: 6)
    }

    /// A ledger timestamp is milliseconds; ``SymkeyVersionText`` speaks
    /// seconds, which is what a version is.
    private func stampVersion(_ millis: Int64) -> Int64 { millis / 1000 }

    private func load() {
        do {
            rows = try session.keyLedger.entries(for: conversation.targetId)
            holders = try session.keyLedger.holders(of: conversation.targetId)
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }
}
