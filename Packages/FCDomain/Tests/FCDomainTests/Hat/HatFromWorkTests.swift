import XCTest
@testable import FCDomain

/// ``Hat/fromWork(kind:did:title:format:summary:locas:nowMs:)``.
///
/// The vector cases are shared, verbatim, with FC-JDK and FC-AJDK
/// `HatFromWorkTest.java`: a work HAT built on any device must serialize
/// identically.
final class HatFromWorkTests: XCTestCase {

    static let did = "5DF6E0E2761359D30A8275058E299FCC0381534545F55CF43E41983F5D4C9456"
    static let id = did.lowercased()
    static let now: Int64 = 1762300800000

    static let vectorVideoJson = "{\"hAlg\":\"sha256x2\",\"born\":1762300800000,\"last\":1762300800000,"
        + "\"name\":\"Lesson 1_ Keys.mp4\",\"desc\":\"Intro to keys\",\"types\":[\"video/mp4\"],"
        + "\"pids\":[\"89c23e636e93e6feb6776720688f02a138a036db338ed72df5510d5129b9ac00\"],"
        + "\"state\":\"ACTIVE\",\"locas\":[\"(sid)abc\",\"https://example.com/v.mp4\"],"
        + "\"id\":\"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456\"}"

    func testVectorVideo() throws {
        let hat = try Hat.fromWork(kind: .video, did: Self.did, title: " Lesson 1: Keys ", format: "video/mp4",
                                   summary: " Intro to keys ",
                                   locas: ["(sid)abc", " ", "https://example.com/v.mp4", "(sid)abc"],
                                   nowMs: Self.now)
        XCTAssertEqual(hat.wireJson(), Self.vectorVideoJson)
    }

    func testVectorMinimalText() throws {
        let hat = try Hat.fromWork(kind: .text, did: Self.did, title: nil, format: nil, summary: nil,
                                   locas: nil, nowMs: Self.now)
        XCTAssertEqual(hat.name, "5df6e0e2.txt")
        XCTAssertEqual(hat.types, ["text/plain"])
        XCTAssertNil(hat.desc)
        XCTAssertNil(hat.locas)
        XCTAssertNil(hat.size)
    }

    func testFormatResolution() {
        XCTAssertEqual(Hat.workMime(kind: .sound, format: "MP3"), "audio/mpeg")
        XCTAssertEqual(Hat.workMime(kind: .image, format: ".jpeg"), "image/jpeg")
        XCTAssertEqual(Hat.workMime(kind: .text, format: "text/markdown; charset=utf-8"), "text/markdown")
        XCTAssertEqual(Hat.workMime(kind: .video, format: "mp4/h.264"), "video/*")
        XCTAssertEqual(Hat.workMime(kind: .video, format: "H.265"), "video/*")

        XCTAssertEqual(Hat.workFileName(did: Self.id, title: "song", mime: "audio/mpeg", format: nil), "song.mp3")
        XCTAssertEqual(Hat.workFileName(did: Self.id, title: "Song.MP3", mime: "audio/mpeg", format: nil), "Song.MP3")
        XCTAssertEqual(Hat.workFileName(did: Self.id, title: "pic.jpeg", mime: "image/jpeg", format: nil), "pic.jpeg")
        XCTAssertEqual(Hat.workFileName(did: Self.id, title: "clip", mime: "video/*", format: "avi"), "clip.avi")
        XCTAssertEqual(Hat.workFileName(did: Self.id, title: "clip", mime: "video/*", format: "H.265"), "clip")
        XCTAssertEqual(Hat.workFileName(did: Self.id, title: "a/b\\c", mime: "text/plain", format: nil), "a_b_c.txt")
    }

    func testRejectsBadDid() {
        for bad in [nil, "", "abc", Self.id + "0", Self.id.replacingOccurrences(of: "5", with: "g")] as [String?] {
            XCTAssertThrowsError(try Hat.fromWork(kind: .image, did: bad, title: "x", format: nil,
                                                  summary: nil, locas: nil, nowMs: Self.now), "accepted \(bad ?? "nil")")
        }
    }

    func testMergeKeepsUserFields() throws {
        let mine = Hat(size: 42, born: 1, last: 2, name: "my copy.mp4", types: ["video/mp4"],
                       key: "k", locas: ["local:///tmp/x"], id: Self.id)
        let work = try Hat.fromWork(kind: .video, did: Self.did, title: "Talk", format: "video/webm",
                                    summary: "about", locas: ["(sid)abc"], nowMs: Self.now)
        let merged = try Hat.mergeWork(mine, work)

        XCTAssertEqual(merged.name, "my copy.mp4")
        XCTAssertEqual(merged.types, ["video/mp4"])
        XCTAssertEqual(merged.desc, "about")
        XCTAssertEqual(merged.size, 42)
        XCTAssertEqual(merged.born, 1)
        XCTAssertEqual(merged.last, Self.now)
        XCTAssertEqual(merged.key, "k")
        XCTAssertEqual(merged.locas, ["local:///tmp/x", "(sid)abc"])
        XCTAssertEqual(merged.pids, [Hat.WorkKind.video.pid])
    }

    func testMergeReplacesPlaceholderName() throws {
        let placeholder = Hat(name: String(Self.id.prefix(8)), id: Self.id)
        let work = try Hat.fromWork(kind: .text, did: Self.did, title: "Notes", format: "text/markdown",
                                    summary: nil, locas: nil, nowMs: Self.now)
        XCTAssertEqual(try Hat.mergeWork(placeholder, work).name, "Notes.md")
    }

    func testMergeRejectsOtherDid() throws {
        let other = Hat(id: String(repeating: "00", count: 32))
        let work = try Hat.fromWork(kind: .text, did: Self.did, title: nil, format: nil, summary: nil,
                                    locas: nil, nowMs: Self.now)
        XCTAssertThrowsError(try Hat.mergeWork(other, work))
    }

    func testMediaKindMapsToPid() throws {
        let rec = MediaRecord(id: "V1", kind: .video, title: "Talk", did: Self.did, format: "webm")
        let hat = try Hat.fromMedia(rec, nowMs: Self.now)
        XCTAssertEqual(hat.name, "Talk.webm")
        XCTAssertEqual(hat.types, ["video/webm"])
        XCTAssertEqual(hat.pids, [Hat.WorkKind.video.pid])
    }

    // MARK: - toWorkDraft (same cases as HatFromWorkTest.java)

    func testDraftFromAFileHat() throws {
        let hat = Hat(name: "Lesson 1.mp4", desc: " Intro ", types: ["video/mp4"],
                      locas: ["local:///x", "(sid)abc", "fudp://unknown", "https://e.com/v",
                              "fudp://1.2.3.4:8500", "(sid)def"],
                      id: Self.did)
        let d = try hat.toWorkDraft()
        XCTAssertEqual(d, Hat.WorkDraft(kind: .video, did: Self.id, title: "Lesson 1", format: "video/mp4",
                                        summary: "Intro", locas: ["(sid)abc", "https://e.com/v", "fudp://1.2.3.4:8500"]))
    }

    func testDraftFormatAndKindFallbacks() throws {
        func draft(_ name: String?, _ types: [String]?) throws -> Hat.WorkDraft {
            try Hat(name: name, types: types, id: Self.id).toWorkDraft()
        }
        var d = try draft("notes.md", ["application/octet-stream"])
        XCTAssertEqual([d.title, d.format], ["notes", "text/markdown"]); XCTAssertEqual(d.kind, .text)
        d = try draft("pic", ["image/*"])
        XCTAssertNil(d.format); XCTAssertEqual(d.kind, .image)
        d = try draft("book.pdf", nil)
        XCTAssertEqual(d.format, "application/pdf"); XCTAssertEqual(d.kind, .text)
        d = try draft("data.bin", ["application/zip"])
        XCTAssertEqual(d.format, "application/zip"); XCTAssertNil(d.kind)
        d = try draft(".bashrc", nil)
        XCTAssertEqual(d.title, ".bashrc"); XCTAssertNil(d.format)
        d = try draft("archive.tar.gz", nil)
        XCTAssertEqual(d.title, "archive.tar"); XCTAssertNil(d.format)
        d = try draft(nil, nil)
        XCTAssertNil(d.title); XCTAssertNil(d.locas)
    }

    func testDraftDropsLocasOfAHatHoldingAPlainKey() throws {
        let hat = Hat(name: "x.txt", key: "00ff", locas: ["(sid)abc"], id: Self.id)
        XCTAssertNil(try hat.toWorkDraft().locas)
    }

    func testDraftRefusesCipherAndBadDid() {
        XCTAssertThrowsError(try Hat(rawDid: Self.id, id: Self.id).toWorkDraft()) {
            XCTAssertEqual($0 as? Hat.WorkError, .cipherHat)
        }
        XCTAssertThrowsError(try Hat(name: "x", id: "abc").toWorkDraft())
        XCTAssertThrowsError(try Hat(name: "x").toWorkDraft())
    }

    func testDraftRoundTripsAWorkHat() throws {
        let hat = try Hat.fromWork(kind: .video, did: Self.did, title: "Talk", format: "video/webm",
                                   summary: "about", locas: ["(sid)abc"], nowMs: Self.now)
        XCTAssertEqual(try hat.toWorkDraft(), Hat.WorkDraft(kind: .video, did: Self.id, title: "Talk",
                                                            format: "video/webm", summary: "about", locas: ["(sid)abc"]))
    }
}

