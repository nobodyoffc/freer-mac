import XCTest
@testable import FCTransport

/// The canonical form, and the equality that depends on it.
///
/// These are not string-hygiene tests. The DOCK layer asks "is this
/// server the one I am already connected to?" and answers it by
/// comparing URLs that arrive from three sources with three spellings —
/// so every case here is a way the send path could ask its own server
/// to forward a message to itself.
final class FudpUrlTests: XCTestCase {

    func testEverySpellingOfOneServerNormalisesTheSameWay() {
        let expected = "fudp://dock.example:8500"
        for spelling in [
            "dock.example:8500",
            "fudp://dock.example:8500",
            "https://dock.example:8500",
            "http://dock.example:8500/",
            "fudp://dock.example:8500/some/path",
            "dock.example:8500?x=1",
            "  dock.example:8500  ",
        ] {
            XCTAssertEqual(FudpUrl.normalize(spelling), expected, "spelling: \(spelling)")
        }
    }

    /// A bare host means the default port, so a `home` that omits it and
    /// a Settings field that spells it out are the same machine.
    func testABareHostTakesTheDefaultPort() {
        XCTAssertEqual(FudpUrl.normalize("dock.example"), "fudp://dock.example:8500")
        XCTAssertTrue(FudpUrl.sameEndpoint("dock.example", "fudp://dock.example:8500"))
    }

    func testHostAndPortAreParsedForTheSocket() {
        let endpoint = FudpUrl.hostPort("fudp://10.0.0.4:9000")
        XCTAssertEqual(endpoint?.host, "10.0.0.4")
        XCTAssertEqual(endpoint?.port, 9000)
        XCTAssertEqual(FudpUrl.hostPort("dock.example")?.port, FudpUrl.defaultPort)
    }

    /// Nothing that cannot name a host normalises — including, and this
    /// is the point, when compared against itself. An address we cannot
    /// parse is not evidence that two things are the same place.
    func testUnusableAddressesNormaliseToNothingAndMatchNothing() {
        for junk in ["", "   ", "fudp://", "dock.example:not-a-port", "..", ".leading", "trailing."] {
            XCTAssertNil(FudpUrl.normalize(junk), "junk: \(junk)")
        }
        XCTAssertNil(FudpUrl.normalize(nil))
        XCTAssertFalse(FudpUrl.sameEndpoint("", ""))
        XCTAssertFalse(FudpUrl.sameEndpoint(nil, nil))
    }

    func testDifferentPortsAreDifferentServers() {
        XCTAssertFalse(FudpUrl.sameEndpoint("dock.example:8500", "dock.example:8501"))
        XCTAssertFalse(FudpUrl.sameEndpoint("dock.example", "other.example"))
    }
}
