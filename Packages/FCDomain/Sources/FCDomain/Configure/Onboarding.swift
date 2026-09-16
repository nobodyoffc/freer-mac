import Foundation

/// FEIP0 §9: the coin-days a carve has to destroy before any parser will
/// read it.
///
/// Below the activation height nothing is required. From it on, every FEIP
/// operation must destroy at least ``minimum`` CDD or it is **silently
/// ignored** — the transaction confirms, the fee is gone, and nothing
/// changes. That is why a newcomer's first carve has to wait for their
/// first coins to age, and why the checklist says so rather than letting
/// them pay for nothing.
public enum FeipCdd {

    /// The wallet's carve path enforces the same rule from these, so they
    /// are one number, not two that agree.
    public static let activationHeight = ContactFeip.cddCheckHeight
    public static let minimum = ContactFeip.cdRequired

    /// Whether a carve at `height` needs coin days. An unknown height
    /// counts as needing them: waiting a day costs less than a carve no
    /// parser reads.
    public static func isRequired(atHeight height: Int64?) -> Bool {
        guard let height else { return true }
        return height >= activationHeight
    }
}

/// One step of the getting-started checklist, in the order it is shown.
/// The raw values are persisted (``Setting/onboardingSkipped``), so they
/// must not be renamed.
public enum OnboardingStep: String, CaseIterable, Codable, Sendable {
    case backupPrikey
    case firstFch
    case registerCid
    case setHome
    case addGuide
    case joinSquare

    /// The first four are what make an identity work at all. The last two
    /// are being part of the place, which nobody should be made to do.
    ///
    /// A master is deliberately not a step: it names another FID of your
    /// own, which a beginner does not have. It lives in Settings › Identity.
    public var isSkippable: Bool {
        switch self {
        case .addGuide, .joinSquare: return true
        default: return false
        }
    }
}

public enum OnboardingStatus: Equatable, Sendable {
    case done
    case skipped
    /// Can be done now.
    case open
    /// Cannot be done yet, and this is what it is waiting for.
    case waiting(OnboardingWait)
    /// Carved and broadcast; the chain has not shown it yet. Nothing to do
    /// but wait, and offering the carve again would charge for it twice.
    case pending(txid: String)
    /// Carved over a day ago and still not on the chain: the transaction
    /// most likely failed. Open again, with the txid to check.
    case stalled(txid: String)
    /// Depends on the chain, which has not answered yet.
    case unknown

    /// Done or skipped — nothing more will be asked for this step.
    public var isSettled: Bool {
        self == .done || self == .skipped
    }

    /// Whether the step's actions are offered: not while it is settled,
    /// unknown, or pending on a carve already paid for.
    public var isActionable: Bool {
        switch self {
        case .done, .skipped, .unknown, .pending: return false
        case .open, .waiting, .stalled: return true
        }
    }
}

/// A broadcast carve for a step, as the caller found it recorded.
public struct OnboardingPending: Equatable, Sendable {
    public var txid: String
    /// Past ``PendingGroupsStore/overdueMs`` without landing.
    public var overdue: Bool

    public init(txid: String, overdue: Bool) {
        self.txid = txid
        self.overdue = overdue
    }
}

public enum OnboardingWait: Equatable, Sendable {
    /// An earlier step has to happen first.
    case step(OnboardingStep)
    /// The FID's coins have not aged enough to pay FEIP0's CDD. `days` is a
    /// rough forecast at the current balance, nil when there is no balance
    /// to age.
    case coinDays(have: Int64, need: Int64, days: Int?)
}

/// Everything the checklist is decided from. Gathered by the caller so the
/// decision itself is a pure function the tests can drive.
public struct OnboardingFacts: Sendable {
    public var prikeyBackedUp: Bool
    /// The live FID's on-chain record, or nil when it is not known yet.
    public var chain: LiveFidInfo?
    public var guideIsContact: Bool
    public var joinedSquare: Bool
    public var skipped: Set<OnboardingStep>
    /// Carves broadcast for ``OnboardingStep/registerCid``, ``OnboardingStep/setHome``
    /// and ``OnboardingStep/joinSquare`` that the chain does not show yet.
    public var pending: [OnboardingStep: OnboardingPending]

    public init(
        prikeyBackedUp: Bool,
        chain: LiveFidInfo?,
        guideIsContact: Bool = false,
        joinedSquare: Bool = false,
        skipped: Set<OnboardingStep> = [],
        pending: [OnboardingStep: OnboardingPending] = [:]
    ) {
        self.prikeyBackedUp = prikeyBackedUp
        self.chain = chain
        self.guideIsContact = guideIsContact
        self.joinedSquare = joinedSquare
        self.skipped = skipped
        self.pending = pending
    }
}

/// The getting-started checklist, decided.
///
/// **Every tick comes from state, never from the user ticking it.** A
/// backup is the user's word because nothing else can know; everything
/// else is on the chain or on this Mac, so a step done from another device,
/// or before this checklist existed, shows as done without being told.
public struct Onboarding: Equatable, Sendable {

    public struct Item: Equatable, Sendable, Identifiable {
        public let step: OnboardingStep
        public let status: OnboardingStatus
        public var id: OnboardingStep { step }
    }

    /// The steps that apply, in order. `addGuide` is left out for a FID
    /// that has coins but no guide on record — there is nobody to add.
    public let items: [Item]

    /// The FID that funded this one, when the chain knows it.
    public let guide: String?

    /// Whether a carve from this FID would be read now.
    public let canCarve: Bool

    public init(_ facts: OnboardingFacts) {
        let chain = facts.chain
        guide = chain?.guide.flatMap { $0.isEmpty ? nil : $0 }

        let funded = chain.map { ($0.balance ?? 0) > 0 || $0.guide?.isEmpty == false }
        let cdWait = chain.flatMap(Self.coinDayWait)
        canCarve = funded == true && cdWait == nil

        /// A carve-backed step: done by the chain, else pending on a carve
        /// already broadcast, else blocked by the first FCH, else by coin age.
        /// **Done only when the chain says so**, never on broadcast: a carve
        /// can still be dropped, or confirmed and ignored, and a step ticked
        /// early could complete the checklist and hide it before that shows.
        func carveStep(_ step: OnboardingStep, done: Bool) -> OnboardingStatus {
            guard let funded else { return .unknown }
            if done { return .done }
            if let pending = facts.pending[step] {
                return pending.overdue ? .stalled(txid: pending.txid) : .pending(txid: pending.txid)
            }
            if !funded { return .waiting(.step(.firstFch)) }
            if let cdWait { return .waiting(cdWait) }
            return .open
        }

        var items: [Item] = []
        items.append(Item(step: .backupPrikey, status: facts.prikeyBackedUp ? .done : .open))
        items.append(Item(step: .firstFch, status: funded.map { $0 ? .done : .open } ?? .unknown))

        let cid = chain?.cid?.trimmingCharacters(in: .whitespaces) ?? ""
        items.append(Item(step: .registerCid, status: carveStep(.registerCid, done: !cid.isEmpty)))

        let homeSet = HomeFeip.declares("DOCK", in: chain?.home) && HomeFeip.declares("DISK", in: chain?.home)
        items.append(Item(step: .setHome, status: carveStep(.setHome, done: homeSet)))

        if facts.skipped.contains(.addGuide) {
            items.append(Item(step: .addGuide, status: .skipped))
        } else if facts.guideIsContact {
            items.append(Item(step: .addGuide, status: .done))
        } else if funded == false {
            items.append(Item(step: .addGuide, status: .waiting(.step(.firstFch))))
        } else if funded == nil {
            items.append(Item(step: .addGuide, status: .unknown))
        } else if guide != nil {
            // A contact is local, so this never waits on coin age.
            items.append(Item(step: .addGuide, status: .open))
        }

        if facts.skipped.contains(.joinSquare) {
            items.append(Item(step: .joinSquare, status: .skipped))
        } else {
            items.append(Item(step: .joinSquare, status: carveStep(.joinSquare, done: facts.joinedSquare)))
        }

        self.items = items
    }

    public func status(of step: OnboardingStep) -> OnboardingStatus? {
        items.first { $0.step == step }?.status
    }

    /// The first step there is something to do about — the one the card
    /// expands. A pending carve is skipped: it only needs waiting for.
    public var current: Item? {
        items.first {
            guard !$0.status.isSettled, $0.status != .unknown else { return false }
            if case .pending = $0.status { return false }
            return true
        }
    }

    public var isComplete: Bool {
        items.allSatisfy(\.status.isSettled)
    }

    /// Whether a required step is still to do, as far as anyone knows.
    public var hasRequiredStepOpen: Bool {
        items.contains { !$0.step.isSkippable && !$0.status.isSettled && $0.status != .unknown }
    }

    /// Whether to draw the checklist.
    ///
    /// A required step still open always shows it. The two optional steps
    /// only keep it up for an identity that went through the checklist
    /// (`started`): somebody who registered a CID and set their home long
    /// before this existed has plainly finished getting started, and a card
    /// appearing to ask them to join a square would be a nag, not help.
    public func shouldShow(started: Bool) -> Bool {
        if hasRequiredStepOpen { return true }
        return started && !isComplete
    }

    /// FEIP0's CDD rule against this FID's record, or nil when it is met or
    /// does not apply at this height.
    public static func coinDayWait(_ info: LiveFidInfo) -> OnboardingWait? {
        guard FeipCdd.isRequired(atHeight: info.bestHeight) else { return nil }
        let have = info.cd ?? 0
        let need = FeipCdd.minimum
        guard have < need else { return nil }
        // A CD is one coin held one day, so the balance in coins is the rate
        // coin days accrue at.
        let coins = Double(info.balance ?? 0) / 100_000_000
        let days = coins > 0 ? max(1, Int((Double(need - have) / coins).rounded(.up))) : nil
        return .coinDays(have: have, need: need, days: days)
    }
}
