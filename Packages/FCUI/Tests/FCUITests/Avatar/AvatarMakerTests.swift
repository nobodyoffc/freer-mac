import XCTest
import AppKit
@testable import FCUI

final class AvatarMakerTests: XCTestCase {

    /// Project test fixture: privkey hex
    /// `a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575`
    /// produces this FID. The avatar should be deterministic from
    /// these bytes alone — no time, randomness, or process state.
    private let fixtureFid = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"

    // MARK: - layerKeys

    func testLayerKeysForFixtureFid() throws {
        // FID  = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK" (34 chars)
        // chars[33-4-i] for i in 0..<10 sample indices 29..20:
        //   i=0 idx=29 → 'm' → 44
        //   i=1 idx=28 → 'm' → 44
        //   i=2 idx=27 → '7' → 6
        //   i=3 idx=26 → 'i' → 41
        //   i=4 idx=25 → 'k' → 43
        //   i=5 idx=24 → 'd' → 36
        //   i=6 idx=23 → 'k' → 43
        //   i=7 idx=22 → 'U' → 27
        //   i=8 idx=21 → 'T' → 26
        //   i=9 idx=20 → 'D' → 12
        let keys = try AvatarMaker.layerKeys(for: fixtureFid)
        XCTAssertEqual(keys, [44, 44, 6, 41, 43, 36, 43, 27, 26, 12])
    }

    func testLayerKeysAreDeterministic() throws {
        let a = try AvatarMaker.layerKeys(for: fixtureFid)
        let b = try AvatarMaker.layerKeys(for: fixtureFid)
        XCTAssertEqual(a, b)
    }

    func testDifferentFidsProduceDifferentKeys() throws {
        // Construct another well-formed FID-shaped string. The
        // alphabet is constrained, so we just swap one character in
        // the sampled range.
        var swapped = fixtureFid
        let target = swapped.index(swapped.startIndex, offsetBy: 25)  // a sampled position
        swapped.replaceSubrange(target...target, with: "X")
        let a = try AvatarMaker.layerKeys(for: fixtureFid)
        let b = try AvatarMaker.layerKeys(for: swapped)
        XCTAssertNotEqual(a, b)
    }

    // MARK: - error cases

    func testRejectsTooShortFid() {
        XCTAssertThrowsError(try AvatarMaker.layerKeys(for: "F1234")) { error in
            guard case AvatarMaker.Failure.fidTooShort = error else {
                XCTFail("expected fidTooShort, got \(error)"); return
            }
        }
    }

    func testRejectsNonBase58Character() {
        // Insert an `O` (illegal in Base58) into a sampled position.
        var fid = fixtureFid
        let target = fid.index(fid.startIndex, offsetBy: 25)
        fid.replaceSubrange(target...target, with: "O")
        XCTAssertThrowsError(try AvatarMaker.layerKeys(for: fid)) { error in
            guard case AvatarMaker.Failure.unknownCharacter("O") = error else {
                XCTFail("expected unknownCharacter('O'), got \(error)"); return
            }
        }
    }

    // MARK: - rendering

    func testAvatarRendersAtNativeSize() throws {
        let img = try AvatarMaker.avatar(for: fixtureFid)
        XCTAssertEqual(img.size, NSSize(width: 150, height: 150))
        // Has at least one bitmap-shaped representation.
        XCTAssertFalse(img.representations.isEmpty)
    }

    func testCacheReturnsSameInstance() throws {
        // Second call should hit the NSCache and return the same
        // NSImage by identity. (NSCache is allowed to evict, so this
        // is a "usually true" assertion under healthy memory; with
        // a fresh test bundle and no memory pressure it's reliable.)
        let first = try AvatarMaker.avatar(for: fixtureFid)
        let second = try AvatarMaker.avatar(for: fixtureFid)
        XCTAssertTrue(first === second, "expected NSCache to return the same NSImage instance")
    }

    // MARK: - resource bundle sanity

    func testEveryLayerHasAllElements() throws {
        // 10 layers × 58 elements = 580 PNGs. If somebody dropped
        // assets from the bundle by mistake this test catches it
        // before the user's avatar fails to render mid-flow.
        for layer in 0..<AvatarMaker.layerCount {
            for element in 0..<AvatarMaker.alphabet.count {
                let url = AvatarMaker.elementURL(layer: layer, element: element)
                XCTAssertNotNil(url, "missing avatar-elements/\(layer)/\(element).png")
            }
        }
    }
}
