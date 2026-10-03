import XCTest
import FCCore
@testable import FCDomain

/// The home BASE: finding it in a home map, checking the key a server
/// answers HELLO with against its record, and the order a launch tries
/// servers in.
final class HomeBaseTests: XCTestCase {

    private let sid = String(repeating: "a", count: 64)

    private func pubkey(_ fill: UInt8) throws -> Data {
        try Secp256k1.publicKey(fromPrivateKey: Data(repeating: fill, count: 32))
    }

    // MARK: - finding it

    func testValueReadsTheKeyThisAppWrites() {
        XCTAssertEqual(HomeFeip.value(of: "BASE", in: [ServiceName.base: "(sid)" + sid, ServiceName.dock: "(sid)d"]), "(sid)" + sid)
    }

    func testValueReadsAKeyAnotherClientWrote() {
        XCTAssertEqual(HomeFeip.value(of: "BASE", in: ["base": " fudp://b.example:8500 "]), "fudp://b.example:8500")
    }

    func testNoBaseIsNil() {
        XCTAssertNil(HomeFeip.value(of: "BASE", in: nil))
        XCTAssertNil(HomeFeip.value(of: "BASE", in: [ServiceName.dock: "(sid)d"]))
        XCTAssertNil(HomeFeip.value(of: "BASE", in: [ServiceName.base: "  "]), "a blank entry names nothing")
        XCTAssertNil(HomeFeip.value(of: "BASE", in: ["BASEMENT": "x"]), "a key merely starting BASE is another kind")
    }

    func testEntrySaysWhatKindOfBaseTheHomeNames() throws {
        let prikey = Data(repeating: 7, count: 32)
        let sealed = try HomePrivacy.seal(sid, toPubkey: try Secp256k1.publicKey(fromPrivateKey: prikey))
        XCTAssertEqual(HomeBase.entry(in: [:], prikey: prikey), .none)
        XCTAssertEqual(HomeBase.entry(in: [ServiceName.base: "(sid)" + sid], prikey: nil), .serviceId(sid))
        XCTAssertEqual(HomeBase.entry(in: [ServiceName.base: sealed], prikey: prikey), .serviceId(sid))
        XCTAssertEqual(HomeBase.entry(in: [ServiceName.base: sealed], prikey: Data(repeating: 8, count: 32)), .unreadable)
        XCTAssertEqual(HomeBase.entry(in: [ServiceName.base: "fudp://b.example:8500"], prikey: nil), .address("fudp://b.example:8500"))
    }

    // MARK: - the key check

    func testDealerPubkeyMustMatchTheHelloKey() throws {
        let key = try pubkey(1)
        let record = Service(dealerPubkey: Hex.encode(key).uppercased())
        XCTAssertEqual(HomeBase.verify(helloPubkey: key, against: record), .matches, "hex case is not a different key")
        let other = Service(dealerPubkey: Hex.encode(try pubkey(2)))
        guard case .mismatch = HomeBase.verify(helloPubkey: key, against: other) else {
            return XCTFail("a server holding another key must not pass")
        }
    }

    func testDealerFidIsCheckedWhenTheRecordHasNoPubkey() throws {
        let key = try pubkey(3)
        let fid = try FchAddress(publicKey: key).fid
        XCTAssertEqual(HomeBase.verify(helloPubkey: key, against: Service(dealer: fid)), .matches)
        let stranger = try FchAddress(publicKey: try pubkey(4)).fid
        XCTAssertEqual(HomeBase.verify(helloPubkey: key, against: Service(dealer: stranger)), .mismatch(expected: stranger))
    }

    func testNothingToCheckAgainstIsUnverifiable() throws {
        let key = try pubkey(5)
        XCTAssertEqual(HomeBase.verify(helloPubkey: key, against: nil), .unverifiable)
        XCTAssertEqual(HomeBase.verify(helloPubkey: key, against: Service()), .unverifiable)
    }

    // MARK: - where a launch starts

    func testAKnownHomeBaseLeadsAndTheSettingsServerIsTheWayBack() {
        let prefs = Preferences(
            preferredFapiService: "start.example:8500", preferredFapiServicePubkeyHex: "02aa",
            homeBaseService: "home.example:8500", homeBaseServicePubkeyHex: "03bb"
        )
        XCTAssertEqual(prefs.baseCandidates, [
            BaseEndpoint(service: "home.example:8500", pubkeyHex: "03bb", source: .home),
            BaseEndpoint(service: "start.example:8500", pubkeyHex: "02aa", source: .starting),
        ])
    }

    func testPinnedIgnoresTheHomeBase() {
        let prefs = Preferences(
            preferredFapiService: "start.example:8500", preferredFapiServicePubkeyHex: "02aa",
            followHomeBase: false,
            homeBaseService: "home.example:8500", homeBaseServicePubkeyHex: "03bb"
        )
        XCTAssertEqual(prefs.baseCandidates, [
            BaseEndpoint(service: "start.example:8500", pubkeyHex: "02aa", source: .thisMac),
        ])
    }

    func testTheSameServerTwiceIsTriedOnce() {
        let prefs = Preferences(
            preferredFapiService: "one.example:8500", preferredFapiServicePubkeyHex: "02aa",
            homeBaseService: "one.example:8500", homeBaseServicePubkeyHex: "02aa"
        )
        XCTAssertEqual(prefs.baseCandidates.map(\.source), [.home])
    }

    func testANewIdentityStartsOnTheProjectServer() {
        XCTAssertEqual(Preferences.defaults.baseCandidates, [
            BaseEndpoint(
                service: Preferences.defaultFapiService,
                pubkeyHex: Preferences.defaultFapiServicePubkeyHex,
                source: .starting
            ),
        ])
    }

    // MARK: - carving it

    func testMergeSetsBaseBesideTheRest() {
        let merged = HomeFeip.merged(over: [ServiceName.dock: "(sid)d"], base: sid, dock: nil, disk: nil)
        XCTAssertEqual(merged, [ServiceName.dock: "(sid)d", ServiceName.base: "(sid)" + sid])
        XCTAssertNil(HomeFeip.merged(over: merged, base: sid, dock: nil, disk: nil), "the same BASE again carves nothing")
    }
}
