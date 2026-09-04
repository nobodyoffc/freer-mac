import XCTest
import CryptoKit
import FCCore
@testable import FCDomain

/// ``SshAgentProtocol``: the byte shapes `ssh` expects, and the much
/// longer list of things this agent refuses to do.
final class SshAgentProtocolTests: XCTestCase {

    private let comment = "freer:FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private var key: SshEd25519Key!

    override func setUpWithError() throws {
        key = try SshEd25519Key(
            mainPrikey: Data(repeating: 0x42, count: 32),
            mainFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        )
    }

    // MARK: - Parsing

    func testParsesRequestIdentities() {
        XCTAssertEqual(SshAgentProtocol.parse(body: Data([11])), .requestIdentities)
    }

    func testParsesSignRequest() {
        let body = Data([13])
            + SshWire.string(key.publicKeyBlob)
            + SshWire.string(Data("payload".utf8))
            + SshWire.uint32(0)
        guard case let .sign(blob, data, flags) = SshAgentProtocol.parse(body: body) else {
            return XCTFail("expected .sign")
        }
        XCTAssertEqual(blob, key.publicKeyBlob)
        XCTAssertEqual(data, Data("payload".utf8))
        XCTAssertEqual(flags, 0)
    }

    func testTruncatedSignRequestIsMalformedNotACrash() {
        let body = Data([13]) + SshWire.string(key.publicKeyBlob)   // no data, no flags
        XCTAssertEqual(SshAgentProtocol.parse(body: body), .malformed(13))
    }

    func testEmptyBodyIsMalformed() {
        XCTAssertEqual(SshAgentProtocol.parse(body: Data()), .malformed(0))
    }

    // MARK: - Identities answer

    /// Byte-exact. `ssh` compares the blob it gets here against the one
    /// it read from the `.pub`, so a single wrong length prefix means
    /// silent fallback to password auth.
    func testIdentitiesAnswerIsByteExact() {
        let framed = SshAgentProtocol.identitiesAnswer(keyBlob: key.publicKeyBlob, comment: comment)

        var expectedBody = Data([12])
        expectedBody += SshWire.uint32(1)
        expectedBody += SshWire.string(key.publicKeyBlob)
        expectedBody += SshWire.string(comment)
        XCTAssertEqual(framed, SshWire.uint32(UInt32(expectedBody.count)) + expectedBody)

        // And the frame length must describe the rest exactly.
        var reader = SshWire.Reader(framed)
        let declared = try? reader.readUInt32()
        XCTAssertEqual(Int(declared ?? 0), framed.count - 4)
    }

    func testRespondToRequestIdentitiesAdvertisesExactlyOneKey() throws {
        let (response, _) = SshAgentProtocol.respond(to: Data([11]), key: key, comment: comment)
        var reader = SshWire.Reader(response)
        _ = try reader.readUInt32()
        XCTAssertEqual(try reader.readByte(), 12)
        XCTAssertEqual(try reader.readUInt32(), 1)
        XCTAssertEqual(try reader.readString(), key.publicKeyBlob)
        XCTAssertEqual(String(data: try reader.readString(), encoding: .utf8), comment)
        XCTAssertTrue(reader.isAtEnd)
    }

    // MARK: - Signing

    func testSignRequestProducesAVerifiableSignature() throws {
        let payload = Data("SSH_MSG_USERAUTH_REQUEST".utf8)
        let body = Data([13])
            + SshWire.string(key.publicKeyBlob)
            + SshWire.string(payload)
            + SshWire.uint32(0)

        let (response, _) = SshAgentProtocol.respond(to: body, key: key, comment: comment)
        var reader = SshWire.Reader(response)
        _ = try reader.readUInt32()
        XCTAssertEqual(try reader.readByte(), 14)

        let sigBlob = try reader.readString()
        XCTAssertEqual(sigBlob.count, 83)
        var inner = SshWire.Reader(sigBlob)
        XCTAssertEqual(String(data: try inner.readString(), encoding: .utf8), "ssh-ed25519")
        let signature = try inner.readString()
        XCTAssertEqual(signature.count, 64)

        // Verified, not compared byte-for-byte: CryptoKit's ed25519
        // signing is randomized, so two signatures over one message
        // differ while both verify. That is fine for SSH — the server
        // only ever verifies — but it means a golden-signature test
        // would fail at random, which is worth stating once here.
        let pub = try Curve25519.Signing.PublicKey(rawRepresentation: key.publicKeyBytes)
        XCTAssertTrue(pub.isValidSignature(signature, for: payload))
        XCTAssertFalse(pub.isValidSignature(signature, for: Data("tampered".utf8)))
    }

    // MARK: - Refusals
    //
    // Each of these is the agent declining to be useful to someone who
    // reached the socket, so each gets its own test rather than a loop.

    private func assertFailure(_ body: Data, _ message: String, file: StaticString = #filePath, line: UInt = #line) {
        let (response, _) = SshAgentProtocol.respond(to: body, key: key, comment: comment)
        XCTAssertEqual(response, SshAgentProtocol.failure(), message, file: file, line: line)
        XCTAssertEqual(response, Data([0, 0, 0, 1, 5]), "a failure is 5 bytes", file: file, line: line)
    }

    func testSignRequestForSomeoneElsesKeyFails() throws {
        let other = try SshEd25519Key(
            mainPrikey: Data(repeating: 0x43, count: 32),
            mainFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        )
        let body = Data([13])
            + SshWire.string(other.publicKeyBlob)
            + SshWire.string(Data("x".utf8))
            + SshWire.uint32(0)
        assertFailure(body, "a blob that is not ours must not be signed")
    }

    /// The only defined flags select an RSA hash. RFC 9987 says an
    /// agent that does not support the requested flags MUST fail rather
    /// than sign something the client did not ask for.
    func testNonZeroFlagsFail() {
        for flags: UInt32 in [1, 2, 4, 0xffff_ffff] {
            let body = Data([13])
                + SshWire.string(key.publicKeyBlob)
                + SshWire.string(Data("x".utf8))
                + SshWire.uint32(flags)
            assertFailure(body, "flags \(flags) must be refused for ed25519")
        }
    }

    /// The mutating half of the protocol. This agent derived its one
    /// key and will not take another, drop it, or lock itself.
    func testMutatingAndExtensionMessagesAllFail() {
        let types: [(UInt8, String)] = [
            (17, "ADD_IDENTITY"),
            (18, "REMOVE_IDENTITY"),
            (19, "REMOVE_ALL_IDENTITIES"),
            (20, "ADD_ID_CONSTRAINED"),
            (22, "LOCK"),
            (23, "UNLOCK"),
            (25, "ADD_SMARTCARD_KEY"),
            (27, "EXTENSION")
        ]
        for (type, name) in types {
            assertFailure(Data([type]) + Data(repeating: 0xaa, count: 16), "\(name) (\(type)) must fail")
            XCTAssertEqual(
                SshAgentProtocol.parse(body: Data([type])), .unsupported(type),
                "\(name) should parse as unsupported, not malformed"
            )
        }
    }

    /// `ssh` sends `session-bind@openssh.com` as an EXTENSION before it
    /// uses an agent key, and logs our refusal at debug level. It is
    /// covered above; this test exists to record that the refusal is
    /// expected traffic, not a fault to surface in the UI.
    func testSessionBindExtensionIsRoutineRefusal() {
        let body = Data([27]) + SshWire.string("session-bind@openssh.com")
        let (response, request) = SshAgentProtocol.respond(to: body, key: key, comment: comment)
        XCTAssertEqual(response, SshAgentProtocol.failure())
        XCTAssertEqual(request, .unsupported(27))
    }
}
