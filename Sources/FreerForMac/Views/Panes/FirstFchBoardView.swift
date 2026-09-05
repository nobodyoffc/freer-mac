import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The **First FCH board** — the Mac port of Android's `NobodyBoard` /
/// `NewcomerRequestsActivity` pair, and the one pane that serves two
/// opposite people.
///
/// **The problem it solves.** Every action in this app costs a fee, and a
/// brand-new FID has nothing to pay one with. It cannot carve, cannot
/// register a DOCK of its own, cannot even buy a name — so the ordinary
/// answer to "how do I get started" is "know somebody already", which is
/// no answer at all. The board is the way in: a public inbox, on a FID
/// whose private key is published, that a newcomer can post to for free
/// and every existing freer can read.
///
/// **So it is two panes in one frame.** If your balance is zero you are
/// here to ask, and the top half is a note and a button. If it is not,
/// you are here to answer, and the bottom half is the list of people
/// waiting, an amount, and one transaction that pays as many of them as
/// you tick. The same screen shows both because the whole point is that
/// today's newcomer is next month's helper.
///
/// **Nothing on the board is actionable.** Anyone can write as the board
/// FID, so a row is a FID and a sentence — never a link, a card, or a
/// payment request. The only thing a helper can do with one is send coins
/// to the FID it names, from their own identity, through the same
/// approval path as any other payment. See ``NobodyBoard``.
struct FirstFchBoardView: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession

    /// What a helper sends by default: enough for a DOCK registration
    /// plus a little slack, in three separate cashes so a fresh FID can
    /// take two or three on-chain actions in parallel instead of waiting
    /// for one UTXO to confirm between them. Android's numbers.
    private static let defaultAmountCoins = "1.01"
    private static let defaultCount = "3"

    /// Ceiling on `count × askers`. A single transaction with far more
    /// outputs than this becomes unwieldy, and refusing here is kinder
    /// than failing deep inside the builder.
    private static let maxTotalOutputs = 100

    /// How much of the board is shown at once. The rest stays in the
    /// session cache and appears as rows are cleared.
    private static let maxShownRequests = 30

    /// Matches the conversation list's avatar, so a FID looks the same
    /// size here as it does in Chat.
    private static let avatarSize: CGFloat = 32

    /// ``FirstFchBoardStore/dismissalWindow`` in days, for the sentence
    /// that explains it. Derived rather than typed twice.
    private static var dismissalDays: Int {
        Int(FirstFchBoardStore.dismissalWindow / 86_400)
    }

    @State private var requests: [NobodyBoard.Request] = []
    /// Askers held back by a decision this identity already took —
    /// funded or skipped — with the decision itself, so the pane can say
    /// which and offer them back.
    @State private var hidden: [(request: NobodyBoard.Request, dismissal: BoardDismissal)] = []
    @State private var showHidden = false
    @State private var selectedFids: Set<String> = []

    @State private var amountCoins = FirstFchBoardView.defaultAmountCoins
    @State private var countPerAsker = FirstFchBoardView.defaultCount

    @State private var snapshot: CashSnapshot?
    @State private var loading = false
    @State private var sending = false
    @State private var boardError: String?
    @State private var status: Status?
    @State private var showConfirm = false

    @State private var note = ""
    @State private var posting = false
    @State private var boardState = FirstFchBoardState()

    private enum Status: Identifiable {
        case ok(String)
        case bad(String)
        var id: String { text }
        var text: String {
            switch self { case .ok(let t), .bad(let t): return t }
        }
        var isError: Bool { if case .bad = self { return true }; return false }
    }

    // MARK: - derived

    private var amountSats: Int64? {
        guard let coins = Double(amountCoins.trimmingCharacters(in: .whitespaces)),
              coins >= TxFee.minAmountCoins, coins <= TxFee.maxAmountCoins
        else { return nil }
        return Int64((coins * Double(Cash.satoshisPerBch)).rounded())
    }

    private var count: Int? {
        guard let n = Int(countPerAsker.trimmingCharacters(in: .whitespaces)), n > 0 else { return nil }
        return n
    }

    private var totalOutputs: Int { (count ?? 0) * selectedFids.count }

    private var totalSats: Int64? {
        guard let amountSats, let count, !selectedFids.isEmpty else { return nil }
        return amountSats * Int64(count) * Int64(selectedFids.count)
    }

    /// Takes the snapshot rather than reading ``snapshot``: the send
    /// path fetches a fresh one and must select from *that*, not from
    /// whatever the last render happened to hold.
    private func spendableCashes(in snapshot: CashSnapshot?) -> [Cash] {
        guard let h160 = try? FchAddress(fid: session.liveFid).hash160 else { return [] }
        return (snapshot?.cashes ?? []).filter {
            !$0.pendingSpend && $0.withinUnconfirmedChainLimit && $0.locksToP2PKH(hash160: h160)
        }
    }

    private var allSelected: Bool {
        !requests.isEmpty && selectedFids.count == requests.count
    }

    // MARK: - body

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            PaneHeader(session: session)
            Divider()
            toolbar
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    noticeCard
                    if appState.liveFidIsBroke { askCard }
                    requestsCard
                    if let status { statusRow(status) }
                }
                .padding(.bottom, 12)
            }
        }
        .padding()
        .frame(minWidth: 560)
        .task { await load() }
        .onChange(of: session.liveFid) { _, _ in
            resetForIdentity()
            Task { await load() }
        }
        .alert("Send \(coins(totalSats ?? 0)) F to \(selectedFids.count) newcomer\(selectedFids.count == 1 ? "" : "s")?",
               isPresented: $showConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Send", role: .destructive) { Task { await sendToSelected() } }
        } message: {
            Text("""
                \(totalOutputs) output\(totalOutputs == 1 ? "" : "s") of \(coins(amountSats ?? 0)) F, \
                paid from \(session.liveFid) in one transaction.

                They are strangers, and the board says nothing about them beyond \
                what they typed. This broadcasts immediately and cannot be undone.
                """)
        }
    }

    private var toolbar: some View {
        HStack(spacing: 12) {
            Button {
                Task { await refreshBoard() }
            } label: {
                if loading {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
            .disabled(loading)

            Toggle("Check at login", isOn: Binding(
                get: { boardState.checkAtLogin },
                set: { setCheckAtLogin($0) }
            ))
            .toggleStyle(.switch)
            .controlSize(.small)
            .help("Off by default. When on, Freer looks once per login for newcomers asking for their first FCH, and tells you only if somebody is waiting.")

            Spacer()
        }
    }

    // MARK: - the notice

    private var noticeCard: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 6) {
                Text("This is a public board on a nobody identity.")
                    .font(.callout.bold())
                Text("""
                    Its private key is published, so everything here can be read — and \
                    written — by anyone. Use it only to ask for your first FCH. You never \
                    need to pay, click a link, or share anything to receive coins; the only \
                    proof that somebody helped is your own balance going up.
                    """)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    FidAvatarView(fid: NobodyBoard.defaultNobodyFid, size: 16, isNobody: true)
                    CopyableText.elidingMiddle(
                        NobodyBoard.defaultNobodyFid,
                        font: .caption.monospaced(), color: .secondary
                    )
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - asking

    private var askCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Ask for your first FCH", systemImage: "hand.raised")
                .font(.headline)

            if boardState.hasAsked {
                Text("""
                    Your request is on the board. Now wait for somebody to see it and send \
                    coins to your address — and you can ask people you know to send to the \
                    same one. A FID asks once: posting again says nothing new.
                    """)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    Text("Your address").font(.caption).foregroundStyle(.secondary)
                    CopyableText.elidingMiddle(session.liveFid, font: .callout.monospaced())
                }
            } else {
                Text("""
                    Posts your FID publicly, so an existing freer can send you the coins every \
                    other action needs. Anyone can see it.
                    """)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 8) {
                    TextField("", text: $note, prompt: Text("Add a note (optional)"))
                        .textFieldStyle(.roundedBorder)
                        .onChange(of: note) { _, new in
                            if new.count > NobodyBoard.noteMaxCharacters {
                                note = String(new.prefix(NobodyBoard.noteMaxCharacters))
                            }
                        }
                    Button {
                        Task { await post() }
                    } label: {
                        if posting {
                            ProgressView().controlSize(.small)
                        } else {
                            Text("Post request")
                        }
                    }
                    .disabled(posting || !session.canSign)
                    .help(session.canSign
                          ? "Post your FID on the public board"
                          : "Watch-only identity — there is no key here to seal a post with.")
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - answering

    private var requestsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Label("Waiting for their first FCH", systemImage: "person.2.wave.2")
                    .font(.headline)
                Text("\(requests.count)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                Spacer()
                if !requests.isEmpty {
                    Toggle("All", isOn: Binding(
                        get: { allSelected },
                        set: { on in
                            selectedFids = on ? Set(requests.map(\.requesterFid)) : []
                        }
                    ))
                    .toggleStyle(.checkbox)
                }
            }

            if requests.isEmpty {
                Text(boardError
                     ?? "Nobody is waiting. Requests from FIDs that have since been funded are not shown.")
                    .font(.callout)
                    .foregroundStyle(boardError == nil
                                     ? AnyShapeStyle(.secondary) : AnyShapeStyle(Color.red))
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                if let boardError {
                    CopyableText(boardError, font: .caption, color: .red)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(requests) { request in
                    requestRow(request)
                }
                Divider()
                sendControls
            }
            if !hidden.isEmpty { hiddenSection }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    /// The people this identity has already dealt with, folded away.
    ///
    /// Shown as a count rather than as rows, because the whole point of
    /// the decision was not to look at them again — but shown *at all*,
    /// because a persisted hide the user cannot see or undo is a trap,
    /// and one mis-click on Ignore would otherwise cost a week.
    private var hiddenSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            HStack(spacing: 8) {
                Image(systemName: "eye.slash")
                    .foregroundStyle(.secondary)
                Text(hiddenSummary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button(showHidden ? "Hide" : "Show") { showHidden.toggle() }
                    .buttonStyle(.link)
                    .font(.caption)
            }
            if showHidden {
                ForEach(hidden, id: \.request.requesterFid) { entry in
                    hiddenRow(entry.request, entry.dismissal)
                }
            }
        }
    }

    private var hiddenSummary: String {
        let funded = hidden.filter { $0.dismissal.reason == .funded }.count
        let skipped = hidden.count - funded
        var parts: [String] = []
        if funded > 0 { parts.append("\(funded) funded") }
        if skipped > 0 { parts.append("\(skipped) skipped") }
        return parts.joined(separator: ", ")
            + " — hidden until you have not acted on them for \(Self.dismissalDays) days"
    }

    private func hiddenRow(
        _ request: NobodyBoard.Request, _ dismissal: BoardDismissal
    ) -> some View {
        HStack(alignment: .center, spacing: 8) {
            FidAvatarView(fid: request.requesterFid, size: 20)
            CopyableText.elidingMiddle(
                request.requesterFid, head: 6, tail: 6,
                font: .caption.monospaced(), color: .secondary
            )
            Text(dismissal.reason == .funded ? "funded" : "skipped")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(Color.secondary.opacity(0.12))
                .clipShape(Capsule())
            Text("back \(relative(dismissal.until))")
                .font(.caption2)
                .foregroundStyle(.tertiary)
            Spacer(minLength: 8)
            Button("Restore") { restore(request.requesterFid) }
                .buttonStyle(.link)
                .font(.caption)
        }
        .opacity(0.75)
    }

    private func requestRow(_ request: NobodyBoard.Request) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Toggle("", isOn: Binding(
                get: { selectedFids.contains(request.requesterFid) },
                set: { on in
                    if on { selectedFids.insert(request.requesterFid) }
                    else { selectedFids.remove(request.requesterFid) }
                }
            ))
            .toggleStyle(.checkbox)
            .labelsHidden()
            // Centred against the avatar rather than pinned to the top
            // of a row whose height is set by a two-line note.
            .frame(height: Self.avatarSize)

            // The requester's own avatar, generated from the FID exactly
            // as it is everywhere else in the app — which is the point:
            // the face beside a request is the same face you will see on
            // the payment, on the contact, and in a chat later. It is
            // *not* marked as a nobody; the board is one, the people
            // asking on it are not.
            FidAvatarView(fid: request.requesterFid, size: Self.avatarSize)

            VStack(alignment: .leading, spacing: 2) {
                CopyableText.elidingMiddle(
                    request.requesterFid, font: .callout.monospaced()
                )
                if !request.note.isEmpty {
                    // Written by a stranger, rendered as plain text and
                    // nothing else — no links, no markup, no actions.
                    Text(request.note)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            Text(time(request.createTime))
                .font(.caption.monospacedDigit())
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 3)
    }

    private var sendControls: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                LabeledContent("Each cash") {
                    TextField("", text: $amountCoins)
                        .frame(width: 90)
                        .multilineTextAlignment(.trailing)
                        .monospacedDigit()
                }
                LabeledContent("Cashes each") {
                    TextField("", text: $countPerAsker)
                        .frame(width: 50)
                        .multilineTextAlignment(.trailing)
                        .monospacedDigit()
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 1) {
                    Text(totalSats.map { "\(coins($0)) F" } ?? "—")
                        .font(.callout.bold().monospacedDigit())
                    Text("\(selectedFids.count) selected · \(totalOutputs) outputs")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Text("""
                Several small cashes rather than one: a fresh FID can then take two or three \
                on-chain actions in parallel instead of waiting for a single coin to confirm \
                between them.
                """)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 10) {
                Button {
                    showConfirm = true
                } label: {
                    if sending {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Send", systemImage: "paperplane.fill")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canSend)

                Button("Ignore", systemImage: "eye.slash") {
                    ignoreSelected()
                }
                .disabled(selectedFids.isEmpty)
                .help("Hide these rows for this session. Nothing is blocked and nothing is carved.")

                Spacer()
                if !session.canSign {
                    Text("Watch-only identity — no key to sign a payment with.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    private var canSend: Bool {
        !sending && session.canSign && !selectedFids.isEmpty
            && amountSats != nil && count != nil
            && totalOutputs <= Self.maxTotalOutputs
    }

    private func statusRow(_ status: Status) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: status.isError ? "exclamationmark.triangle" : "checkmark.circle")
            CopyableText(status.text, font: .callout, color: status.isError ? .red : .green)
                .fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
    }

    // MARK: - actions

    @MainActor
    private func load() async {
        boardState = session.firstFchBoardState.get(fid: session.liveFid)
        if let cached = try? session.wallet.cachedSnapshot(forAddress: session.liveFid) {
            snapshot = cached
        }
        await refreshBoard()
    }

    private func resetForIdentity() {
        requests = []
        hidden = []
        showHidden = false
        selectedFids = []
        snapshot = nil
        status = nil
        boardError = nil
        note = ""
    }

    /// One pass over the board.
    ///
    /// **The viewer reads the whole current board, not the tail past its
    /// cursor.** The stored cursor answers a different question — "has
    /// anything appeared since this identity last looked", which is all
    /// the login nudge needs. Fetching from it here instead would mean
    /// that opening the pane, leaving it and coming back showed an empty
    /// board: the first visit moved the watermark past everything, and
    /// the rows only ever lived in this view's memory. Android has that
    /// bug; this does not.
    ///
    /// Advancing the watermark on display is still right, because
    /// display is exactly what it records. It moves past everything the
    /// server handed over, including posts that were filtered out, so a
    /// board full of answered asks does not keep re-notifying.
    @MainActor
    private func refreshBoard() async {
        guard !loading else { return }
        loading = true
        defer { loading = false }

        let result = await session.firstFchBoard.fetch()
        boardError = result.error

        // A read that failed leaves what is on screen alone: an error is
        // not evidence that the people who were waiting have been helped.
        //
        // The dismissal filter is applied inside ``FirstFchBoard/fetch``
        // rather than here, so the login nudge counts the same rows this
        // pane shows — a badge naming people you funded last week would
        // be worse than no badge.
        if result.error == nil {
            requests = Array(result.requests.prefix(Self.maxShownRequests))
            hidden = result.dismissed
            selectedFids.formIntersection(Set(requests.map(\.requesterFid)))
        }
        if result.maxCreateTime > boardState.cursor {
            boardState.cursor = result.maxCreateTime
            try? session.firstFchBoardState.put(boardState, fid: session.liveFid)
        }
        // Whatever the pane just showed, the nudge has been answered.
        appState.clearNewcomersWaiting()
    }

    /// Ignore is still not a block — nothing is carved and nobody is
    /// blacklisted — but it now outlives the pane. It has to: the board
    /// is one list everybody reads, so a decision that evaporated when
    /// the window closed meant working through the same faces every
    /// time, which is the failure that makes a shared list unusable.
    ///
    /// It also lapses, after ``FirstFchBoardStore/dismissalWindow``.
    /// Skipping somebody today is not a promise never to help them.
    private func ignoreSelected() {
        dismiss(Array(selectedFids), reason: .skipped)
    }

    /// Record a decision about these askers and take them off the list
    /// without waiting for a round trip.
    private func dismiss(_ fids: [String], reason: BoardDismissal.Reason) {
        guard !fids.isEmpty else { return }
        let now = Date()
        _ = try? session.firstFchBoardState.dismiss(
            fids, reason: reason, fid: session.liveFid, now: now
        )
        let dismissal = BoardDismissal(
            reason: reason,
            until: FirstFchBoardStore.millis(
                now.addingTimeInterval(FirstFchBoardStore.dismissalWindow)
            )
        )
        let moving = Set(fids)
        for request in requests where moving.contains(request.requesterFid) {
            hidden.append((request, dismissal))
        }
        requests.removeAll { moving.contains($0.requesterFid) }
        hidden.sort { $0.request.createTime > $1.request.createTime }
        selectedFids.subtract(moving)
    }

    /// Put one asker back on the list. The undo for a mis-click that
    /// would otherwise cost a week.
    private func restore(_ fid: String) {
        _ = try? session.firstFchBoardState.restore([fid], fid: session.liveFid)
        if let index = hidden.firstIndex(where: { $0.request.requesterFid == fid }) {
            let entry = hidden.remove(at: index)
            requests.append(entry.request)
            requests.sort { $0.createTime > $1.createTime }
            requests = Array(requests.prefix(Self.maxShownRequests))
        }
        if hidden.isEmpty { showHidden = false }
    }

    @MainActor
    private func setCheckAtLogin(_ on: Bool) {
        boardState.checkAtLogin = on
        try? session.firstFchBoardState.put(boardState, fid: session.liveFid)
        if !on { appState.clearNewcomersWaiting() }
    }

    @MainActor
    private func post() async {
        guard let privkey = try? session.livePrikey() else {
            status = .bad("This identity has no private key, so there is nothing to seal a post with.")
            return
        }
        posting = true
        defer { posting = false }
        do {
            try await session.firstFchBoard.post(
                note: note, as: session.liveFid, privkey: privkey
            )
            boardState.askedAt = Int64(Date().timeIntervalSince1970 * 1000)
            try? session.firstFchBoardState.put(boardState, fid: session.liveFid)
            note = ""
            status = .ok("Your request is on the board.")
        } catch {
            status = .bad("Couldn't post your request: \(error)")
        }
    }

    /// One transaction paying every ticked asker.
    ///
    /// The inputs are chosen here rather than by ``CoinSelector/select``
    /// because that one funds a *single* payment: it prices two outputs,
    /// and a plan built for two outputs does not cover thirty. Everything
    /// after the selection is the ordinary composed-transaction path, so
    /// this goes through the same approval, signing and cache-update
    /// steps as any other payment — and is sent from the helper's own
    /// FID, never from the board.
    @MainActor
    private func sendToSelected() async {
        guard let amountSats, let count, !selectedFids.isEmpty else { return }
        sending = true
        defer { sending = false }
        status = nil

        // Ticked rows in the order they are shown, so the transaction
        // reads the way the list does.
        let payees = requests.map(\.requesterFid).filter { selectedFids.contains($0) }
        let payout = amountSats * Int64(count) * Int64(payees.count)

        do {
            let fresh = try await session.wallet.refreshCashes(forFid: session.liveFid)
            snapshot = fresh
            let inputs = try selectInputs(
                from: spendableCashes(in: fresh),
                payout: payout,
                outputCount: payees.count * count
            )

            var outputs: [RawTxInfo.Slot] = []
            for fid in payees {
                for _ in 0..<count {
                    outputs.append(.output(to: fid, amount: amountSats))
                }
            }
            let info = RawTxInfo(
                sender: session.liveFid,
                feeRate: RawTxInfo.feeRate(satsPerByte: 1),
                inputs: inputs.map(RawTxInfo.Slot.input(from:)),
                outputs: outputs,
                changeTo: session.liveFid
            )
            let result = try await session.sendAdvancedFromLive(
                info: info, inputCashes: inputs, bestHeight: fresh.bestHeight ?? 0
            )
            status = .ok("Sent — \(result.remoteTxid). \(payees.count) newcomer\(payees.count == 1 ? "" : "s") funded.")

            // They are answered now, so they stop being rows — and the
            // decision is written down rather than held in this view.
            // The funded check would eventually hide them anyway, but
            // only once the chain confirms and only while they stay
            // funded; between broadcast and confirmation they would come
            // straight back, and a helper would pay them twice.
            dismiss(payees, reason: .funded)
            await appState.refreshLiveFidInfo()
        } catch {
            status = .bad(String(describing: error))
        }
    }

    /// Greedy largest-first, priced for the real output count.
    private func selectInputs(
        from cashes: [Cash], payout: Int64, outputCount: Int
    ) throws -> [Cash] {
        var picked: [Cash] = []
        var sum: Int64 = 0
        for cash in cashes.sorted(by: { $0.value > $1.value }) {
            picked.append(cash)
            sum += cash.value
            // One more output than the payees get: the change. If it
            // turns out to be dust the builder folds it into the fee,
            // which only ever leaves us over-funded.
            let size = CoinSelector.sizeFor(nIn: picked.count, nOut: outputCount + 1)
            if sum >= payout + Int64(size) { return picked }
        }
        throw BoardSendFailure.notEnoughFch(needed: payout, have: sum)
    }

    // MARK: - formatting

    private func coins(_ sats: Int64) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        f.usesGroupingSeparator = false
        return f.string(from: NSNumber(value: Double(sats) / Double(Cash.satoshisPerBch))) ?? "0"
    }

    /// "in 6 days" / "in 3 hours" — when a hidden asker comes back.
    private func relative(_ millis: Int64) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(
            for: Date(timeIntervalSince1970: Double(millis) / 1000), relativeTo: Date()
        )
    }

    private func time(_ millis: Int64) -> String {
        guard millis > 0 else { return "" }
        let f = DateFormatter()
        f.dateFormat = "MM/dd HH:mm"
        return f.string(from: Date(timeIntervalSince1970: Double(millis) / 1000))
    }
}

enum BoardSendFailure: Error, CustomStringConvertible {
    case notEnoughFch(needed: Int64, have: Int64)

    var description: String {
        switch self {
        case let .notEnoughFch(needed, have):
            return "Not enough spendable FCH: this needs \(needed) satoshi including the fee, "
                + "and the confirmed cashes on this FID come to \(have)."
        }
    }
}
