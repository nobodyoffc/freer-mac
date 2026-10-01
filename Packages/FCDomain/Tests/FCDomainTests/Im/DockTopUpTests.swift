import XCTest
@testable import FCDomain

/// The free half of a top-up: reading who to pay from a server's PONG.
final class DockTopUpTests: XCTestCase {

    /// Verbatim from fapi.cid.cash:8500, 2026-10-01.
    private let advert = #"{"services":[{"ver":"1","components":["BASE@No1_NrC7","DISK@No1_NrC7","MAP@No1_NrC7","ROAD@No1_NrC7","DOCK@No1_NrC7"],"name":"Fast FAPI","minPayment":"0.01","dealerPubkey":"03f55c464d74dc97f3636bfb713a86cb1af9ec9321255b58f107533579d2b4f89c","type":"FAPI@No1_NrC7","minCredit":"0.0001","sid":"65c475ac49f3e69587da1bac4ba196c0aa7be99a8684a790505b92169beec9b3"}]}"#

    func testAPongAdvertNamesTheDealerAndTheMinimum() throws {
        let services = DockTopUp.services(fromPongInfo: Data(advert.utf8))
        XCTAssertEqual(services.count, 1)
        let service = try XCTUnwrap(services.first)
        XCTAssertEqual(service.sid, "65c475ac49f3e69587da1bac4ba196c0aa7be99a8684a790505b92169beec9b3")
        XCTAssertEqual(service.stdName, "Fast FAPI")
        XCTAssertTrue(service.offers(ServiceName.dock))
        XCTAssertEqual(DockTopUp.dealer(of: service), "FPYoNSZLRfoVEEamoTeMJNMJk82hDjfapi")
        XCTAssertEqual(NoticeFee.satoshis(coinString: service.minPayment), 1_000_000)
    }

    /// A Java writer may emit prices as numbers rather than strings.
    func testNumericPricesAreTakenToo() {
        let json = #"{"services":[{"sid":"ab","minPayment":0.5,"dealerPubkey":"03f55c464d74dc97f3636bfb713a86cb1af9ec9321255b58f107533579d2b4f89c"}]}"#
        let service = DockTopUp.services(fromPongInfo: Data(json.utf8)).first
        XCTAssertEqual(service?.minPayment, "0.5")
    }

    func testAnEmptyOrForeignPongNamesNobody() {
        XCTAssertTrue(DockTopUp.services(fromPongInfo: Data()).isEmpty)
        XCTAssertTrue(DockTopUp.services(fromPongInfo: Data("not json".utf8)).isEmpty)
        XCTAssertTrue(DockTopUp.services(fromPongInfo: Data(#"{"peers":[]}"#.utf8)).isEmpty)
    }
}
