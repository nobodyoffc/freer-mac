import SwiftUI
import FCDomain
import FCUI

/// The getting-started checklist at the top of Overview.
///
/// It replaces two cards that each knew one thing — "back up your prikey"
/// and "this FID holds no coins" — and then left the newcomer on their own
/// the moment both were answered. The steps after those are the ones
/// nobody finds unaided: a CID, a DOCK and a DISK, the guide who funded
/// them, a square to talk in. The CID and the DOCK and DISK are carved from
/// Settings, which is where their steps send you.
///
/// **Order is dependency, not preference.** The backup is free and the
/// most urgent. Everything after the first FCH is a carve, and a carve at
/// or past ``FeipCdd/activationHeight`` that destroys less than one coin
/// day is confirmed, paid for, and ignored by every parser — so those steps
/// say how long the coins still have to age instead of offering a button
/// that would spend the fee for nothing.
///
/// Only the step being worked on is expanded; clicking any other row opens
/// that one instead. A step's tick always comes from state (the chain, the
/// contacts and the square store), so work done from another device
/// shows up here without being reported.
struct GettingStartedCard: View {
    @Environment(AppState.self) private var appState
    @Environment(\.inspectFid) private var inspectFid
    let session: ActiveSession

    @State private var guideIsContact = false
    @State private var joinedSquare = false
    /// This FID's request is already on the First FCH board, so there is
    /// nothing left to do there but wait.
    @State private var askedForFirstFch = false
    @State private var askingForFirstFch = false
    @State private var askError: String?
    /// Carves broadcast and not yet on the chain, from the two records
    /// that keep them: the identity carves and the group acts.
    @State private var pending: [OnboardingStep: OnboardingPending] = [:]
    /// A row the user opened by hand. Nil means "the current step".
    @State private var expanded: OnboardingStep?

    @State private var addingGuide = false

    private var onboarding: Onboarding {
        Onboarding(OnboardingFacts(
            prikeyBackedUp: appState.prikeyBackedUp,
            chain: appState.knownLiveFidInfo,
            guideIsContact: guideIsContact,
            joinedSquare: joinedSquare,
            skipped: appState.onboardingSkipped,
            pending: pending
        ))
    }

    var body: some View {
        let ob = onboarding
        Group {
            // Watch-only identities cannot carve, back up or write anything,
            // so every step would be a button that fails.
            if session.canSign && ob.shouldShow(started: appState.onboardingStarted) {
                card(ob)
                    .onAppear { noteStarted(ob) }
                    .task(id: ob.status(of: .firstFch) == .open) { await watchForFirstFch(ob) }
            }
        }
        .onAppear { reloadLocal(guide: ob.guide) }
        .onChange(of: ob.guide) { _, guide in reloadLocal(guide: guide) }
        .onChange(of: ob.hasRequiredStepOpen) { _, _ in noteStarted(ob) }
        // A refresh is also what clears a landed CID or home carve.
        .onChange(of: appState.knownLiveFidInfo) { _, _ in reloadLocal(guide: ob.guide) }
        .sheet(isPresented: $addingGuide) {
            ContactEditorSheet(
                session: session,
                mode: .createFor(ob.guide ?? ""),
                onSaved: { _ in
                    addingGuide = false
                    reloadLocal(guide: ob.guide)
                },
                onCancel: { addingGuide = false }
            )
        }
    }

    // MARK: - card

    private func card(_ ob: Onboarding) -> some View {
        let settled = ob.items.filter(\.status.isSettled).count
        let open = expanded.flatMap { step in ob.items.first { $0.step == step } } ?? ob.current
        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: "flag.checkered")
                    .foregroundStyle(.teal)
                Text("Getting started").font(.headline)
                Spacer()
                Text("\(settled) of \(ob.items.count) done")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            ProgressView(value: Double(settled), total: Double(max(ob.items.count, 1)))
                .tint(.teal)

            VStack(alignment: .leading, spacing: 2) {
                ForEach(ob.items) { item in
                    row(item, isOpen: item.step == open?.step, ob: ob)
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.teal.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func row(_ item: Onboarding.Item, isOpen: Bool, ob: Onboarding) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Button {
                expanded = isOpen ? nil : item.step
            } label: {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    statusIcon(item.status)
                        .frame(width: 18)
                    Text(Self.title(item.step))
                        .font(.callout.weight(isOpen ? .semibold : .regular))
                        .foregroundStyle(item.status.isSettled ? .secondary : .primary)
                        .strikethrough(item.status == .skipped)
                    Spacer(minLength: 8)
                    if !isOpen, let line = statusLine(item.status) {
                        Text(line)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isOpen {
                VStack(alignment: .leading, spacing: 8) {
                    Text(Self.explanation(item.step))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    switch item.status {
                    case .waiting:
                        if let line = statusLine(item.status) {
                            Label(line, systemImage: "hourglass")
                                .font(.callout)
                                .foregroundStyle(.orange)
                        }
                    case .pending(let txid):
                        carveNote(
                            "Carved. Waiting for the chain to confirm it; this ticks itself once it does.",
                            txid: txid, color: .secondary
                        )
                    case .stalled(let txid):
                        carveNote(
                            "Still not on the chain a day after it was carved. The transaction may have failed. Check it, then try again.",
                            txid: txid, color: .orange
                        )
                    default:
                        EmptyView()
                    }
                    if item.status.isActionable {
                        actions(item, ob: ob)
                    }
                }
                .padding(.leading, 28)
                .padding(.bottom, 8)
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private func statusIcon(_ status: OnboardingStatus) -> some View {
        switch status {
        case .done:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .skipped:
            Image(systemName: "minus.circle").foregroundStyle(.secondary)
        case .open:
            Image(systemName: "circle").foregroundStyle(.teal)
        case .waiting:
            Image(systemName: "hourglass.circle").foregroundStyle(.orange)
        case .pending:
            ProgressView().controlSize(.mini)
        case .stalled:
            Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
        case .unknown:
            ProgressView().controlSize(.mini)
        }
    }

    private func carveNote(_ text: String, txid: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(text)
                .font(.callout)
                .foregroundStyle(color)
                .fixedSize(horizontal: false, vertical: true)
            CopyableText(
                display: "tx " + txid.elidingMiddle(head: 8, tail: 8),
                copy: txid,
                font: .caption.monospaced()
            )
            .foregroundStyle(.secondary)
        }
    }

    private func statusLine(_ status: OnboardingStatus) -> String? {
        switch status {
        case .done, .open: return nil
        case .skipped: return "Skipped"
        case .unknown: return "Checking the chain…"
        case .pending: return "Waiting for the chain"
        case .stalled: return "Not on the chain after a day"
        case .waiting(.step(let step)):
            return "After “\(Self.title(step))”"
        case .waiting(.coinDays(let have, let need, let days)):
            let base = "Your coins are still aging: \(have) of \(need) CD"
            guard let days else { return base }
            return base + ", about \(days) day\(days == 1 ? "" : "s") to go"
        }
    }

    // MARK: - actions

    @ViewBuilder
    private func actions(_ item: Onboarding.Item, ob: Onboarding) -> some View {
        HStack(spacing: 10) {
            switch item.step {
            case .backupPrikey:
                Button("Back up now") { appState.openBackupPrikey() }

            case .firstFch:
                // Posts straight from here: a note is optional, and making
                // a newcomer find the board to press one button there was a
                // detour. The board is still where the note can be added.
                Button {
                    Task { await askForFirstFch() }
                } label: {
                    if askingForFirstFch {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Ask help")
                    }
                }
                .disabled(askedForFirstFch || askingForFirstFch)
                .help(askedForFirstFch
                      ? "Your request is already on the board. Now wait for somebody to send coins to your address."
                      : "Post your FID on the public First FCH board, where anyone can read it")
                CopyableText.elidingMiddle(session.liveFid, font: .callout.monospaced())

            case .registerCid, .setHome:
                // While the coins are still aging the hourglass line says
                // why; a button into a form that cannot carve would not.
                if item.status.isActionable, !isWaiting(item.status) {
                    Button("Open Settings") { appState.selectedPane = .settings }
                }

            case .addGuide:
                if let guide = ob.guide {
                    Button { inspectFid(guide) } label: {
                        FidAvatarView(fid: guide, size: 20)
                    }
                    .buttonStyle(.plain)
                    .help("Show your guide's details")
                    CopyableText.elidingMiddle(guide, head: 6, tail: 6, font: .callout.monospaced())

                    Button {
                        addingGuide = true
                    } label: {
                        Label("Add to contacts", systemImage: "person.badge.plus")
                    }
                }

            case .joinSquare:
                // Browsing is free; only the join itself is a carve, and
                // the join form says so where it happens.
                Button("Browse squares") { appState.openJoinSquare() }
            }

            if item.step.isSkippable {
                Spacer(minLength: 0)
                Button("Skip") { appState.skipOnboardingStep(item.step) }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.top, 2)

        if item.step == .firstFch, let askError {
            CopyableText(askError, font: .callout, color: .red)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @MainActor
    private func askForFirstFch() async {
        guard !askingForFirstFch else { return }
        guard let privkey = try? session.livePrikey() else {
            askError = "This identity has no prikey, so there is nothing to seal a request with."
            return
        }
        askError = nil
        askingForFirstFch = true
        defer { askingForFirstFch = false }
        let fid = session.liveFid
        do {
            _ = try await session.firstFchBoard.post(note: nil, as: fid, privkey: privkey)
            var state = session.firstFchBoardState.get(fid: fid)
            state.askedAt = Int64(Date().timeIntervalSince1970 * 1000)
            try? session.firstFchBoardState.put(state, fid: fid)
            askedForFirstFch = true
        } catch {
            askError = "Couldn't post your request: \(error)"
        }
    }

    // MARK: - state

    private func reloadLocal(guide: String?) {
        let fid = session.liveFid
        let now = Date()
        joinedSquare = !((try? session.squares.joined(by: fid)) ?? []).isEmpty
        askedForFirstFch = session.firstFchBoardState.get(fid: fid).hasAsked
        guideIsContact = guide.map { (try? session.contacts.get(fid: $0)) != nil } ?? false

        var found: [OnboardingStep: OnboardingPending] = [:]
        for (step, kind) in [(OnboardingStep.registerCid, PendingIdentityCarve.Kind.cid), (.setHome, .home)] {
            if let carve = try? session.pendingIdentityCarves.get(fid: fid, kind: kind) {
                found[step] = OnboardingPending(txid: carve.txid, overdue: carve.isOverdue(now: now))
            }
        }
        // Creating a square makes you its first member, so a create counts
        // as much as a join. A fresh one outranks a stalled one: that is
        // the attempt still in flight.
        let squareActs = ((try? session.pendingGroups.all(fid: fid, type: .square)) ?? [])
            .filter { $0.act == .join || $0.act == .create }
        if let act = squareActs.first(where: { !$0.isOverdue(now: now) }) ?? squareActs.first {
            found[.joinSquare] = OnboardingPending(txid: act.txid, overdue: act.isOverdue(now: now))
        }
        pending = found
    }

    /// A newcomer who asked for coins sits on this card waiting for them,
    /// and nothing else re-reads the FID record when they arrive. So while
    /// the step is open and the card is on screen, ask again now and then.
    /// The task ends as soon as the step ticks, or the card goes away, so a
    /// funded identity never polls.
    private func watchForFirstFch(_ ob: Onboarding) async {
        guard ob.status(of: .firstFch) == .open else { return }
        while !Task.isCancelled {
            try? await Task.sleep(for: Self.firstFchPollInterval)
            guard !Task.isCancelled else { return }
            await appState.refreshLiveFidInfo()
        }
    }

    /// About one block.
    private static let firstFchPollInterval: Duration = .seconds(60)

    private func isWaiting(_ status: OnboardingStatus) -> Bool {
        if case .waiting = status { return true }
        return false
    }

    private func noteStarted(_ ob: Onboarding) {
        if ob.hasRequiredStepOpen { appState.markOnboardingStarted() }
    }

    // MARK: - words

    static func title(_ step: OnboardingStep) -> String {
        switch step {
        case .backupPrikey: return "Back up your prikey"
        case .firstFch: return "Get your first FCH"
        case .registerCid: return "Register a CID"
        case .setHome: return "Set your DOCK and DISK"
        case .addGuide: return "Add your guide to contacts"
        case .joinSquare: return "Join a square"
        }
    }

    static func explanation(_ step: OnboardingStep) -> String {
        switch step {
        case .backupPrikey:
            return """
                Your prikey is the only proof this identity is yours, and it exists on this Mac \
                alone. If the machine dies, so does the identity. Nobody can reissue it. Keep a \
                copy on paper, or as an encrypted file you can store anywhere.
                """
        case .firstFch:
            return """
                Every carve, name and message costs a fee, so an empty FID can't do much yet. Ask \
                on the public First FCH board, or have somebody send coins straight to your \
                address. Whoever sends your first coins becomes your guide.
                """
        case .registerCid:
            return """
                A CID is a name people can find you by, like Alice_VkUV. The last characters of \
                your FID keep it unique. Registering one also puts your pubkey on the chain, and \
                nobody can write to you until it's there. You register it in Settings.
                """
        case .setHome:
            return """
                A DOCK holds messages for you while you're offline, and a DISK keeps your files. \
                Until both are registered on the chain, other freers have nowhere to reach you. \
                You choose them in Settings.
                """
        case .addGuide:
            return """
                Your guide sent you your first coins. They're the one person here you already \
                know, so keep them in your contacts.
                """
        case .joinSquare:
            return """
                Squares are open group chats that anyone can join. Find one about something you \
                care about and say hello.
                """
        }
    }
}
