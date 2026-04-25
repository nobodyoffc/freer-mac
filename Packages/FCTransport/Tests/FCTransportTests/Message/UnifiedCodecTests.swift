import XCTest
@testable import FCTransport

/// UnifiedCodec is wire-compatible with `FC-AJDK/.../UnifiedCodec.java`.
/// Byte-exact JSON parity isn't a goal (key order, whitespace, number
/// formatting differ across JSON libs). What we DO test:
///   - round-trip preserves every field
///   - the 4-byte BE headerLen prefix is correct
///   - opaque `params` / `fcdsl` / `data` JSON survives unchanged
///   - binary trailers survive end-to-end
///   - malformed inputs throw the right typed error
final class UnifiedCodecTests: XCTestCase {

    // MARK: - request

    func testRequestRoundTripWithAllScalarFields() throws {
        let req = FapiRequest(
            id: "req-1700000000000-deadbeef",
            api: "base.search",
            sid: "service-7",
            via: "FViaChannel123",
            fcdsl: nil,
            params: Data("{\"q\":\"foo\"}".utf8),
            dataSize: 1024,
            dataHash: "abcdef",
            maxCost: 50_000
        )
        let bytes = try UnifiedCodec.encodeRequest(req)
        let (decoded, binary) = try UnifiedCodec.decodeRequest(bytes)

        XCTAssertEqual(decoded.id, req.id)
        XCTAssertEqual(decoded.api, req.api)
        XCTAssertEqual(decoded.sid, req.sid)
        XCTAssertEqual(decoded.via, req.via)
        XCTAssertEqual(decoded.dataSize, req.dataSize)
        XCTAssertEqual(decoded.dataHash, req.dataHash)
        XCTAssertEqual(decoded.maxCost, req.maxCost)
        XCTAssertNil(binary)

        // params is opaque JSON — re-decode to inspect, since key order
        // may differ even after round-trip.
        let p = try JSONSerialization.jsonObject(with: try XCTUnwrap(decoded.params)) as? [String: Any]
        XCTAssertEqual(p?["q"] as? String, "foo")
    }

    func testRequestBinaryTrailerSurvivesAndDataSizeAutoFills() throws {
        let req = FapiRequest(api: "disk.put")
        let blob = Data((0..<256).map { UInt8($0) })
        let bytes = try UnifiedCodec.encodeRequest(req, binary: blob)
        let (decoded, gotBinary) = try UnifiedCodec.decodeRequest(bytes)
        XCTAssertEqual(gotBinary, blob)
        // dataSize was nil on input but UnifiedCodec auto-fills it from
        // binary length, matching the Java helper.
        XCTAssertEqual(decoded.dataSize, Int64(blob.count))
    }

    func testRequestHeaderPrefixIsBigEndian() throws {
        let req = FapiRequest(id: "x", api: "y")
        let bytes = try UnifiedCodec.encodeRequest(req)
        let arr = [UInt8](bytes)
        let headerLen = (UInt32(arr[0]) << 24)
                      | (UInt32(arr[1]) << 16)
                      | (UInt32(arr[2]) <<  8)
                      |  UInt32(arr[3])
        XCTAssertEqual(Int(headerLen), arr.count - 4)
    }

    // MARK: - response

    func testResponseRoundTripWithAllScalarFields() throws {
        let resp = FapiResponse(
            id: "resp-1700000000001-cafebabe",
            requestId: "req-1700000000000-deadbeef",
            code: 0,
            message: "Success",
            data: Data("{\"items\":[1,2,3]}".utf8),
            got: 3,
            total: 999,
            last: ["cursor1", "cursor2"],
            bestHeight: 1_000_000,
            bestBlockId: "0000abc",
            balance: 12345,
            balanceSeq: 7,
            dataSize: 0,
            charged: 100
        )
        let bytes = try UnifiedCodec.encodeResponse(resp)
        let (decoded, binary) = try UnifiedCodec.decodeResponse(bytes)

        XCTAssertEqual(decoded.id, resp.id)
        XCTAssertEqual(decoded.requestId, resp.requestId)
        XCTAssertEqual(decoded.code, resp.code)
        XCTAssertEqual(decoded.message, resp.message)
        XCTAssertEqual(decoded.got, resp.got)
        XCTAssertEqual(decoded.total, resp.total)
        XCTAssertEqual(decoded.last, resp.last)
        XCTAssertEqual(decoded.bestHeight, resp.bestHeight)
        XCTAssertEqual(decoded.bestBlockId, resp.bestBlockId)
        XCTAssertEqual(decoded.balance, resp.balance)
        XCTAssertEqual(decoded.balanceSeq, resp.balanceSeq)
        XCTAssertEqual(decoded.dataSize, resp.dataSize)
        XCTAssertEqual(decoded.charged, resp.charged)
        XCTAssertNil(binary)

        let d = try JSONSerialization.jsonObject(with: try XCTUnwrap(decoded.data)) as? [String: Any]
        XCTAssertEqual(d?["items"] as? [Int], [1, 2, 3])
    }

    func testResponseBinaryTrailer() throws {
        let resp = FapiResponse(code: 0, message: "ok")
        let blob = Data(repeating: 0xAB, count: 64)
        let bytes = try UnifiedCodec.encodeResponse(resp, binary: blob)
        let (_, gotBinary) = try UnifiedCodec.decodeResponse(bytes)
        XCTAssertEqual(gotBinary, blob)
    }

    func testResponseSuccessFlag() {
        XCTAssertTrue(FapiResponse(code: 0).isSuccess)
        XCTAssertFalse(FapiResponse(code: 1).isSuccess)
        XCTAssertFalse(FapiResponse(code: nil).isSuccess)
    }

    // MARK: - omitted optionals

    func testOmittedOptionalFieldsAreNotEncoded() throws {
        // Build a minimal request — only api set. The encoded JSON
        // header should not contain "id", "sid", etc. or even keys with
        // null values (matching Java's Gson default).
        let req = FapiRequest(api: "ping.ping")
        let bytes = try UnifiedCodec.encodeRequest(req)
        let arr = [UInt8](bytes)
        let headerLen = Int((UInt32(arr[0]) << 24) | (UInt32(arr[1]) << 16)
                          | (UInt32(arr[2]) <<  8) |  UInt32(arr[3]))
        let json = String(data: Data(arr[4..<(4 + headerLen)]), encoding: .utf8) ?? ""
        XCTAssertEqual(json, #"{"api":"ping.ping"}"#)
    }

    // MARK: - error cases

    func testDecodeRejectsTruncatedHeader() {
        XCTAssertThrowsError(try UnifiedCodec.decodeRequest(Data([0x01, 0x02]))) { e in
            guard case UnifiedCodec.Failure.truncated = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }

    func testDecodeRejectsHeaderLenOutOfRange() {
        // header says 1000 bytes but data has only 4.
        let bytes = Data([0x00, 0x00, 0x03, 0xE8])
        XCTAssertThrowsError(try UnifiedCodec.decodeRequest(bytes)) { e in
            guard case UnifiedCodec.Failure.invalidHeaderLength = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }

    func testDecodeRejectsNonObjectHeader() {
        // Build a payload whose JSON header is a top-level array, not
        // an object — the protocol mandates object.
        let json = Data("[1,2,3]".utf8)
        var bytes = Data()
        var lenBE = UInt32(json.count).bigEndian
        bytes.append(Data(bytes: &lenBE, count: 4))
        bytes.append(json)
        XCTAssertThrowsError(try UnifiedCodec.decodeRequest(bytes)) { e in
            guard case UnifiedCodec.Failure.headerNotObject = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }

    // MARK: - generateId

    func testGenerateIdShape() {
        let id = FapiRequest.generateId()
        XCTAssertTrue(id.hasPrefix("req-"))
        let parts = id.split(separator: "-")
        XCTAssertEqual(parts.count, 3)
        // millis is digits, hex segment is 0-9a-f.
        XCTAssertNotNil(Int64(String(parts[1])))
        XCTAssertTrue(parts[2].allSatisfy { $0.isHexDigit })
    }
}
