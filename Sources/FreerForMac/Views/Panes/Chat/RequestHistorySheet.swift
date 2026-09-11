import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Ask one person for this conversation's messages over a date range —
/// Android's Request History, which is a member picker followed by a
/// date-range dialog.
///
/// **One person per ask.** Whoever approves uploads the whole range to
/// their own DISK, so asking five people at once is five uploads of the
/// same transcript paid for by five people, and five copies of it filed
/// into the same thread here.
///
/// The answer is not immediate: a person on the other side has to agree,
/// and what they send is fetched and filed on a later receive.
struct RequestHistorySheet: View {

    let session: ActiveSession
    let style: ChatModeStyle
    let conversation: Conversation
    let names: ChatNameBook
    let onClose: () -> Void
    let onSent: (String) -> Void

    @State private var candidates: [String] = []
    @State private var owner: String?
    @State private var chosen: String?
    @State private var since = Calendar.current.date(byAdding: .month, value: -1, to: Date()) ?? Date()
    @State private var through = Date()
    @State private var waiting: [OutgoingHistoryRequest] = []
    @State private var sending = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Request history").font(.title3.bold())
                Spacer()
                Button("Cancel", role: .cancel, action: onClose)
            }

            Text("Whoever you ask sees the request and decides. If they agree, the messages they hold from this \(style.noun) in that range are uploaded encrypted to their DISK, then fetched and added here, marked as imported. Messages already here are left as they are.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if !waiting.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(waiting) { ask in
                        Label(
                            "Waiting on \(ask.askedFid.elidingMiddle(head: 6, tail: 6)) · \(rangeText(ask.since, ask.before))",
                            systemImage: "hourglass"
                        )
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Text("Ask").font(.headline)
            if candidates.isEmpty {
                Text("Nobody to ask: this \(style.noun) lists no members on this Mac. Refresh it first.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                list
            }

            Text("Range").font(.headline)
            HStack(spacing: 12) {
                DatePicker("From", selection: $since, in: ...through, displayedComponents: .date)
                DatePicker("Through", selection: $through, in: since..., displayedComponents: .date)
            }
            .fixedSize()

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            HStack {
                Spacer()
                if sending { ProgressView().controlSize(.small) }
                Button("Send request") { send() }
                    .buttonStyle(.borderedProminent)
                    .disabled(chosen == nil || sending || !session.canSign)
            }
        }
        .padding(20)
        .frame(width: 500, height: 520)
        .onAppear(perform: load)
        .task(id: candidates) { names.resolve(candidates, session: session) }
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(candidates, id: \.self) { fid in
                    Button {
                        chosen = fid
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 8) {
                                Image(systemName: chosen == fid ? "largecircle.fill.circle" : "circle")
                                    .foregroundStyle(chosen == fid ? style.tint : .secondary)
                                FidAvatarView(fid: fid, size: 22, isNobody: names.isNobody(fid))
                                if let cid = names.cid(of: fid) {
                                    Text(cid).font(.callout)
                                }
                                Text(fid.elidingMiddle(head: 8, tail: 8))
                                    .font(.callout)
                                    .foregroundStyle(names.cid(of: fid) == nil ? .primary : .secondary)
                                NobodyChip(fid: fid)
                                if fid == owner { ChatChip("owner", color: style.tint) }
                                if fid == session.liveFid { ChatChip("your other devices", color: style.tint) }
                                Spacer(minLength: 0)
                            }
                            if fid == session.liveFid {
                                Text("Every other device signed in as this identity sees the request, and any of them can answer with what it holds. This one ignores its own request.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .padding(.leading, 26)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .padding(.vertical, 5)
                    Divider()
                }
            }
        }
        .frame(maxHeight: 200)
    }

    // MARK: - actions

    /// Who can be asked. Our own FID is offered **first**, for the reason
    /// ``AskMembersSheet`` gives: a second Mac has the identity and none
    /// of the transcript, and the only holder is the first Mac.
    private func load() {
        let me = session.liveFid
        var others: [String] = []
        switch conversation.type {
        case .p2p:
            if conversation.targetId != me { others = [conversation.targetId] }
        case .room:
            let room = try? session.rooms.get(id: conversation.targetId)
            owner = room?.owner
            others = ([room?.owner].compactMap { $0 } + (room?.members ?? []))
        case .team:
            let team = try? session.teams.get(id: conversation.targetId)
            owner = team?.owner
            others = ([team?.owner].compactMap { $0 } + (team?.members ?? []))
        case .square:
            others = (try? session.squares.get(id: conversation.targetId))??.members ?? []
        }
        var seen: Set<String> = [me]
        candidates = [me] + others.filter { seen.insert($0).inserted }
        // The other party is the obvious answer in a P2P chat; in a group
        // there isn't one, so nothing is picked for the user.
        if conversation.type == .p2p, candidates.count > 1 { chosen = candidates[1] }

        waiting = ((try? session.historyShares.asks()) ?? []).filter { $0.conversationId == conversation.id }
    }

    private func send() {
        guard let fid = chosen else { return }
        let start = Calendar.current.startOfDay(for: since)
        let end = Calendar.current.date(byAdding: .day, value: 1, to: Calendar.current.startOfDay(for: through)) ?? through
        sending = true
        error = nil
        Task {
            do {
                let privkey = try session.livePrikey()
                guard let pubkey = await session.resolvePubkey(of: fid) else {
                    throw ChatService.Failure.noRecipientKey(fid)
                }
                let ask = try session.historyShare.ask(
                    about: conversation, of: fid,
                    since: Self.millis(start), before: Self.millis(end),
                    as: session.liveFid, privkey: privkey, recipientPubkey: pubkey
                )
                _ = try? await session.courier.drainOutbox(as: session.liveFid)
                await MainActor.run {
                    sending = false
                    let who = fid == session.liveFid ? "your other devices" : fid.elidingMiddle(head: 6, tail: 6)
                    onSent("Asked \(who) for history \(rangeText(ask.since, ask.before)). It is added here once they agree.")
                    onClose()
                }
            } catch {
                await MainActor.run {
                    sending = false
                    self.error = String(describing: error)
                }
            }
        }
    }

    private func rangeText(_ since: Int64, _ before: Int64) -> String {
        HistoryRangeText.format(since: since, before: before)
    }

    private static func millis(_ date: Date) -> Int64 {
        Int64(date.timeIntervalSince1970 * 1000)
    }
}

/// A history range as a person reads it: whole days, with the exclusive
/// end shown as the last day it includes.
enum HistoryRangeText {
    static func format(since: Int64, before: Int64) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        let start = Date(timeIntervalSince1970: TimeInterval(since) / 1000)
        let last = Date(timeIntervalSince1970: TimeInterval(before - 1) / 1000)
        let a = formatter.string(from: start)
        let b = formatter.string(from: last)
        return a == b ? "on \(a)" : "from \(a) through \(b)"
    }
}
