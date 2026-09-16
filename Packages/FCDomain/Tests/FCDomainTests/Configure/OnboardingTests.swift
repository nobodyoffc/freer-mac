import XCTest
@testable import FCDomain

/// The getting-started checklist: which steps show, what each waits on,
/// and when the card appears at all.
final class OnboardingTests: XCTestCase {

    private let guide = "FGuideFid1111111111111111111111111"

    /// A funded FID past the CDD activation height with coins old enough
    /// to carve.
    private func funded(cd: Int64 = 5, balance: Int64 = 100_000_000) -> LiveFidInfo {
        var info = LiveFidInfo(fid: "FNewcomer")
        info.balance = balance
        info.cd = cd
        info.guide = guide
        info.bestHeight = 4_100_000
        return info
    }

    private func status(_ facts: OnboardingFacts, _ step: OnboardingStep) -> OnboardingStatus? {
        Onboarding(facts).status(of: step)
    }

    // MARK: - the CDD rule

    func testCddIsRequiredFromTheActivationHeightOn() {
        XCTAssertFalse(FeipCdd.isRequired(atHeight: 3_999_999))
        XCTAssertTrue(FeipCdd.isRequired(atHeight: 4_000_000))
        XCTAssertTrue(FeipCdd.isRequired(atHeight: nil), "an unknown height must not let a carve through for nothing")
    }

    // MARK: - steps

    func testABrandNewFidWaitsOnItsFirstFch() {
        var info = LiveFidInfo(fid: "FNewcomer")
        info.balance = 0
        let facts = OnboardingFacts(prikeyBackedUp: false, chain: info)
        let ob = Onboarding(facts)

        XCTAssertEqual(ob.status(of: .backupPrikey), .open)
        XCTAssertEqual(ob.status(of: .firstFch), .open)
        XCTAssertEqual(ob.status(of: .registerCid), .waiting(.step(.firstFch)))
        XCTAssertEqual(ob.status(of: .setHome), .waiting(.step(.firstFch)))
        XCTAssertEqual(ob.status(of: .addGuide), .waiting(.step(.firstFch)))
        XCTAssertEqual(ob.status(of: .joinSquare), .waiting(.step(.firstFch)))
        XCTAssertEqual(ob.current?.step, .backupPrikey)
        XCTAssertFalse(ob.canCarve)
    }

    func testUnknownChainStateIsNeitherDoneNorOpen() {
        let ob = Onboarding(OnboardingFacts(prikeyBackedUp: true, chain: nil))
        XCTAssertEqual(ob.status(of: .firstFch), .unknown)
        XCTAssertEqual(ob.status(of: .registerCid), .unknown)
        XCTAssertNil(ob.current, "nothing to expand until the chain answers")
        XCTAssertFalse(ob.hasRequiredStepOpen, "a slow index must not flash the card for a finished identity")
    }

    func testYoungCoinsWaitWithAForecast() {
        // 0.25 FCH with no coin days yet: four days to one CD.
        let facts = OnboardingFacts(prikeyBackedUp: true, chain: funded(cd: 0, balance: 25_000_000))
        XCTAssertEqual(status(facts, .firstFch), .done)
        XCTAssertEqual(status(facts, .registerCid), .waiting(.coinDays(have: 0, need: 1, days: 4)))
        XCTAssertEqual(status(facts, .addGuide), .open, "adding the guide as a contact costs nothing")
        XCTAssertFalse(Onboarding(facts).canCarve)
    }

    func testBeforeActivationYoungCoinsCanCarve() {
        var info = funded(cd: 0)
        info.bestHeight = 3_900_000
        let facts = OnboardingFacts(prikeyBackedUp: true, chain: info)
        XCTAssertEqual(status(facts, .registerCid), .open)
        XCTAssertTrue(Onboarding(facts).canCarve)
    }

    func testAFidThatSpentEverythingStillCountsAsFunded() {
        var info = funded(cd: 0, balance: 0)
        info.guide = guide
        let facts = OnboardingFacts(prikeyBackedUp: true, chain: info)
        XCTAssertEqual(status(facts, .firstFch), .done)
        XCTAssertEqual(status(facts, .registerCid), .waiting(.coinDays(have: 0, need: 1, days: nil)))
    }

    func testCidAndHomeComeFromTheChain() {
        var info = funded()
        info.cid = "alice_VkUV"
        info.home = [ServiceName.dock: "(sid)abc", ServiceName.disk: ""]
        let facts = OnboardingFacts(prikeyBackedUp: true, chain: info)
        XCTAssertEqual(status(facts, .registerCid), .done)
        XCTAssertEqual(status(facts, .setHome), .open, "a blank DISK is not a DISK")

        // Another client may have written a bare key; that FID is still
        // reachable, so it still counts.
        info.home?[ServiceName.disk] = nil
        info.home?["DISK"] = "https://disk.example"
        XCTAssertEqual(status(OnboardingFacts(prikeyBackedUp: true, chain: info), .setHome), .done)
    }

    func testAddingTheGuideIsDoneByTheContact() {
        var facts = OnboardingFacts(prikeyBackedUp: true, chain: funded())
        XCTAssertEqual(status(facts, .addGuide), .open)
        facts.guideIsContact = true
        XCTAssertEqual(status(facts, .addGuide), .done)
    }

    func testNoGuideOnRecordDropsTheStep() {
        var info = funded()
        info.guide = nil
        let ob = Onboarding(OnboardingFacts(prikeyBackedUp: true, chain: info))
        XCTAssertNil(ob.status(of: .addGuide))
        XCTAssertNil(ob.guide)
    }

    func testABroadcastCarveIsPendingNotDone() {
        var facts = OnboardingFacts(
            prikeyBackedUp: true, chain: funded(),
            pending: [.registerCid: OnboardingPending(txid: "tx1", overdue: false),
                      .joinSquare: OnboardingPending(txid: "tx2", overdue: false)]
        )
        let ob = Onboarding(facts)
        XCTAssertEqual(ob.status(of: .registerCid), .pending(txid: "tx1"))
        XCTAssertEqual(ob.status(of: .joinSquare), .pending(txid: "tx2"))
        XCTAssertEqual(ob.current?.step, .setHome, "nothing to do on a pending step but wait")
        XCTAssertFalse(ob.isComplete)
        XCTAssertTrue(ob.hasRequiredStepOpen, "the card must outlive a carve that has not landed")

        facts.joinedSquare = true
        XCTAssertEqual(Onboarding(facts).status(of: .joinSquare), .done, "the chain wins over the record")
    }

    func testAPendingCarveOverADayOldStallsAndReopens() {
        let facts = OnboardingFacts(
            prikeyBackedUp: true, chain: funded(),
            pending: [.setHome: OnboardingPending(txid: "tx3", overdue: true)]
        )
        let ob = Onboarding(facts)
        XCTAssertEqual(ob.status(of: .setHome), .stalled(txid: "tx3"))
    }

    func testSkippedStepsSettle() {
        let facts = OnboardingFacts(
            prikeyBackedUp: true, chain: funded(), skipped: [.addGuide, .joinSquare]
        )
        XCTAssertEqual(status(facts, .addGuide), .skipped)
        XCTAssertEqual(status(facts, .joinSquare), .skipped)
    }

    // MARK: - showing the card

    func testMasterIsNotAStep() {
        // A beginner has no other FID to name; the master is in Settings.
        let ob = Onboarding(OnboardingFacts(prikeyBackedUp: true, chain: funded()))
        XCTAssertFalse(ob.items.map(\.step.rawValue).contains("setMaster"))
    }

    func testAnIdentitySetUpBeforeTheChecklistNeverSeesIt() {
        var info = funded()
        info.cid = "alice_VkUV"
        info.home = ["DOCK": "sid1", "DISK": "sid2"]
        let ob = Onboarding(OnboardingFacts(prikeyBackedUp: true, chain: info))
        XCTAssertFalse(ob.isComplete, "the optional steps are still open")
        XCTAssertFalse(ob.shouldShow(started: false))
        XCTAssertTrue(ob.shouldShow(started: true))
    }

    func testARequiredStepAlwaysShowsIt() {
        let ob = Onboarding(OnboardingFacts(prikeyBackedUp: false, chain: nil))
        XCTAssertTrue(ob.shouldShow(started: false))
    }

    func testCompleteHidesIt() {
        var info = funded()
        info.cid = "alice_VkUV"
        info.home = ["DOCK": "sid1", "DISK": "sid2"]
        let ob = Onboarding(OnboardingFacts(
            prikeyBackedUp: true, chain: info,
            guideIsContact: true, joinedSquare: true
        ))
        XCTAssertTrue(ob.isComplete)
        XCTAssertFalse(ob.shouldShow(started: true))
    }

    // MARK: - persistence

    func testSkippedRoundTripsThroughTheSettingAndDropsUnknownNames() {
        var setting = Setting(mainFid: "FMain")
        XCTAssertEqual(setting.onboardingSkipped, [])
        setting.onboardingSkipped = [.joinSquare, .addGuide]
        XCTAssertEqual(setting.settingMap[Setting.onboardingSkippedKey], .string("addGuide,joinSquare"))
        XCTAssertEqual(setting.onboardingSkipped, [.joinSquare, .addGuide])

        setting.settingMap[Setting.onboardingSkippedKey] = .string("joinSquare,somethingNew")
        XCTAssertEqual(setting.onboardingSkipped, [.joinSquare])
    }
}
