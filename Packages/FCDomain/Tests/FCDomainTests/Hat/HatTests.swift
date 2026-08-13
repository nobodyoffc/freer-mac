import XCTest
import FCCore
@testable import FCDomain

/// Wire-format parity for ``Hat``.
///
/// The vectors come from the REAL FC-AJDK `Hat` class (see
/// `tools/vector-gen/HatRef.java`), so these assertions check the Swift
/// model against the producer Android ships — not against a second
/// reading of the Java source.
final class HatTests: XCTestCase {

    // MARK: - the acceptance test

    /// Decode Android's `Hat.toJson()` and re-encode it byte-identically.
    /// This is what makes an IM file message or a HAT export survive a
    /// round trip through the Mac app unchanged.
    func testAndroidJsonRoundTripsLosslessly() throws {
        let vectors = try DomainVectors.load()
        XCTAssertFalse(vectors.hat.isEmpty)

        for v in vectors.hat {
            let hat = try Hat.fromJson(v.json)
            XCTAssertEqual(hat.wireJson(), v.json, "re-encoded JSON for '\(v.label)'")
        }
    }

    /// `toBytes()` escaping: identical to `toJson()` except that
    /// `< > & = '` become `\uXXXX`. The DID is hashed over THIS form.
    func testIdSourceJsonMatchesJavaToBytes() throws {
        let vectors = try DomainVectors.load()
        for v in vectors.hat {
            let hat = try Hat.fromJson(v.json)
            XCTAssertEqual(hat.idSourceJson(), v.idBytesJson,
                           "toBytes()-equivalent JSON for '\(v.label)'")
        }
    }

    /// At least one vector must actually exercise the escaping split,
    /// otherwise the test above proves nothing.
    func testEscapingSplitIsRepresented() throws {
        let vectors = try DomainVectors.load()
        let diverging = vectors.hat.filter { $0.json != $0.idBytesJson }
        XCTAssertFalse(diverging.isEmpty,
                       "expected a vector whose toJson/toBytes differ (HTML-escapable characters)")
        for v in diverging {
            XCTAssertTrue(v.idBytesJson.contains("\\u0026") || v.idBytesJson.contains("\\u003c")
                            || v.idBytesJson.contains("\\u003d") || v.idBytesJson.contains("\\u0027"),
                          "'\(v.label)' should carry \\uXXXX escapes")
        }
    }

    /// `checkIdWithCreate()` must derive the same DID Android would, for
    /// an imported HAT that arrives without an id.
    func testCheckIdWithCreateMatchesAndroid() throws {
        let vectors = try DomainVectors.load()
        for v in vectors.hat {
            var hat = try Hat.fromJson(v.json)
            hat.id = nil
            // The bytes hashed must match Java's first…
            XCTAssertEqual(hat.idSourceJson(), v.derivedIdSourceJson,
                           "id-source bytes for '\(v.label)'")
            // …and therefore so must the DID.
            hat.checkIdWithCreate()
            XCTAssertEqual(hat.id, v.derivedIdWithoutIdField,
                           "derived DID for '\(v.label)'")
        }
    }

    func testCheckIdWithCreateLeavesExistingIdAlone() throws {
        var hat = Hat(name: "x.txt", id: "already-set")
        hat.checkIdWithCreate()
        XCTAssertEqual(hat.id, "already-set")
    }

    // MARK: - field mapping

    func testCapitalLeakedAndOtherJavaSpellings() throws {
        let json = #"{"hAlg":"sha256x2","tDid":"t1","tSize":9,"kCipher":"kc","Leaked":true,"id":"i"}"#
        let hat = try Hat.fromJson(json)
        XCTAssertEqual(hat.hAlg, "sha256x2")
        XCTAssertEqual(hat.tDid, "t1")
        XCTAssertEqual(hat.tSize, 9)
        XCTAssertEqual(hat.kCipher, "kc")
        XCTAssertEqual(hat.leaked, true)
        // And back out under the same spellings.
        XCTAssertEqual(hat.wireJson(), json)
    }

    func testStatesRoundTripByName() throws {
        for state in Hat.DataState.allCases {
            let hat = Hat(state: state, id: "x")
            let json = hat.wireJson()
            XCTAssertTrue(json.contains("\"state\":\"\(state.rawValue)\""))
            XCTAssertEqual(try Hat.fromJson(json).state, state)
        }
        // Byte values match the Java enum's `number`.
        XCTAssertEqual(Hat.DataState.deleted.number, 0)
        XCTAssertEqual(Hat.DataState.active.number, 1)
        XCTAssertEqual(Hat.DataState.outdated.number, 2)
        XCTAssertEqual(Hat.DataState.archived.number, 3)
    }

    func testEmptyListsSurviveAsEmptyNotNull() throws {
        let hat = Hat(types: [], locas: [], id: "e")
        let json = hat.wireJson()
        XCTAssertTrue(json.contains("\"types\":[]"))
        let back = try Hat.fromJson(json)
        XCTAssertEqual(back.types, [])
        XCTAssertNotNil(back.types)
    }

    func testNilFieldsAreOmitted() {
        let hat = Hat(name: "only-name", id: "i")
        XCTAssertEqual(hat.wireJson(), #"{"name":"only-name","id":"i"}"#)
    }

    // MARK: - escaping table

    func testEscapingMatchesGsonTables() {
        // Control characters, quotes and backslashes are escaped in both
        // modes; the HTML set only in htmlSafe mode.
        let raw = "a\"b\\c\nd\te\u{01}f<g>h&i=j'k"
        let plain = GsonCompatibleWriter.escape(raw, htmlSafe: false)
        let safe = GsonCompatibleWriter.escape(raw, htmlSafe: true)

        for escaped in [plain, safe] {
            XCTAssertTrue(escaped.contains("\\\""))
            XCTAssertTrue(escaped.contains("\\\\"))
            XCTAssertTrue(escaped.contains("\\n"))
            XCTAssertTrue(escaped.contains("\\t"))
            XCTAssertTrue(escaped.contains("\\u0001"))
        }
        XCTAssertTrue(plain.contains("<"))
        XCTAssertFalse(safe.contains("<"))
        XCTAssertTrue(safe.contains("\\u003c"))
        XCTAssertTrue(safe.contains("\\u003e"))
        XCTAssertTrue(safe.contains("\\u0026"))
        XCTAssertTrue(safe.contains("\\u003d"))
        XCTAssertTrue(safe.contains("\\u0027"))
    }

    func testLineSeparatorsAreEscapedLikeGson() {
        // Gson escapes U+2028/U+2029 in both modes — they terminate
        // lines in JavaScript.
        let raw = "a\u{2028}b\u{2029}c"
        XCTAssertEqual(GsonCompatibleWriter.escape(raw, htmlSafe: false), "a\\u2028b\\u2029c")
        XCTAssertEqual(GsonCompatibleWriter.escape(raw, htmlSafe: true), "a\\u2028b\\u2029c")
    }

    func testMultibyteTextIsNotEscaped() throws {
        let hat = Hat(name: "自由现金 🚀.pdf", id: "u")
        XCTAssertEqual(hat.wireJson(), #"{"name":"自由现金 🚀.pdf","id":"u"}"#)
        XCTAssertEqual(try Hat.fromJson(hat.wireJson()).name, "自由现金 🚀.pdf")
    }

    // MARK: - derived properties

    func testCipherHatDetection() {
        XCTAssertFalse(Hat(id: "raw").isCipherHat)
        XCTAssertTrue(Hat(rawDid: "raw", id: "cipher").isCipherHat)
    }

    func testLocationHelpers() {
        let hat = Hat(locas: [
            "local:///Users/me/a.txt",
            "fudp://1.2.3.4:9000",
            "(sid)svc-1",
        ], id: "x")
        XCTAssertEqual(hat.localPaths, ["/Users/me/a.txt"])
        XCTAssertEqual(hat.remoteLocas, ["fudp://1.2.3.4:9000", "(sid)svc-1"])
        XCTAssertTrue(hat.hasDiskSource)

        let localOnly = Hat(locas: ["local:///tmp/x"], id: "y")
        XCTAssertFalse(localOnly.hasDiskSource)
        // A HAT with no locations but a cipher HAT is still fetchable.
        XCTAssertTrue(Hat(cipherIds: ["c"], id: "z").hasDiskSource)
    }

    func testDisplayNameFallsBackToId() {
        XCTAssertEqual(Hat(name: "a.txt", id: "did").displayName, "a.txt")
        XCTAssertEqual(Hat(name: "   ", id: "did").displayName, "did")
        XCTAssertEqual(Hat(id: "did").displayName, "did")
    }

    func testMutationHelpersAreIdempotent() {
        var hat = Hat(id: "x")
        hat.addLoca("local:///tmp/a", nowMs: 100)
        hat.addLoca("local:///tmp/a", nowMs: 200)
        XCTAssertEqual(hat.locas, ["local:///tmp/a"])
        XCTAssertEqual(hat.last, 100, "a no-op add must not bump `last`")

        hat.addCipherId("c1", nowMs: 300)
        hat.addCipherId("c1", nowMs: 400)
        XCTAssertEqual(hat.cipherIds, ["c1"])
        XCTAssertEqual(hat.last, 300)

        hat.addLoca("(sid)svc", nowMs: 500)
        hat.removeLocalLocas(nowMs: 600)
        XCTAssertEqual(hat.locas, ["(sid)svc"])
        XCTAssertEqual(hat.last, 600)
    }

    // MARK: - store row separation

    /// The Mac-only sidecar must never reach the wire JSON — that is
    /// what keeps `local://` stamps and app-copy flags out of IM
    /// messages and exports.
    func testHatRecordKeepsLocalStateOutOfWireJson() throws {
        var local = HatLocal(appManagedCopy: true)
        local.setStamp(HatLocal.FileStamp(path: "/Users/me/a.txt", size: 10, modifiedAtMs: 123))
        let record = HatRecord(wire: Hat(name: "a.txt", id: "did"), local: local)

        let wire = record.wire.wireJson()
        XCTAssertEqual(wire, #"{"name":"a.txt","id":"did"}"#)
        XCTAssertFalse(wire.contains("stamps"))
        XCTAssertFalse(wire.contains("appManagedCopy"))
        XCTAssertFalse(wire.contains("/Users/me"))

        // The record as a whole still persists both halves.
        let encoded = try JSONEncoder().encode(record)
        let back = try JSONDecoder().decode(HatRecord.self, from: encoded)
        XCTAssertEqual(back.local.stamps["/Users/me/a.txt"]?.size, 10)
        XCTAssertTrue(back.local.appManagedCopy)
        XCTAssertEqual(back.wire, record.wire)
    }
}
