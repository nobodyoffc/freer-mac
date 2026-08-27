import XCTest
@testable import FCCore

/// Tests for the Converter primitives ported from Android's `convert/`
/// activities: hex, multi-encoding strings, public-key forms, the
/// seven-chain address table, script ASM, and FcDate.
///
/// Address expectations are pinned to *published* vectors rather than to
/// this port's own output: the secp256k1 generator point (privkey = 1),
/// whose hash160 `751e76…` is the BIP-173 P2WPKH example and whose
/// Ethereum address is the well-known `0x7E5F…Bdf`; and the two CashAddr
/// vectors from the Bitcoin Cash spec. A wrong version byte or a wrong
/// checksum polynomial still produces a plausible-looking address, so
/// self-consistent round-trip tests alone would not catch it.
final class ConverterPrimitivesTests: XCTestCase {

    /// secp256k1 G — the public key for private key 1.
    static let pubkey33 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    static let pubkey65 = """
        0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
        483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        """
    static let hash160Hex = "751e76e8199196d454941c45d1b3a323f1433bd6"

    // MARK: - Hex

    func testHexRoundTrips() throws {
        XCTAssertEqual(Hex.encode(Data([0x00, 0x0f, 0xff])), "000fff")
        XCTAssertEqual(try Hex.decode("000FFF"), Data([0x00, 0x0f, 0xff]))
        XCTAssertEqual(try Hex.decode("0x00ff"), Data([0x00, 0xff]))
    }

    func testHexRejectsOddLengthAndGarbage() {
        XCTAssertThrowsError(try Hex.decode("abc"))
        XCTAssertThrowsError(try Hex.decode("zz"))
        XCTAssertFalse(Hex.isHex(""))
        XCTAssertFalse(Hex.isHex("abc"))
        XCTAssertTrue(Hex.isHex("0xabcd"))
    }

    // MARK: - String encodings

    func testStringCodecRendersEveryEncoding() {
        let rendered = Dictionary(
            uniqueKeysWithValues: StringCodec.renderAll(Data("foobar".utf8))
                .map { ($0.0, $0.1) }
        )
        XCTAssertEqual(rendered[.hex], "666f6f626172")
        XCTAssertEqual(rendered[.base64], "Zm9vYmFy")
        XCTAssertEqual(rendered[.base32], "MZXW6YTBOI")
        XCTAssertEqual(rendered[.utf8], "foobar")
    }

    /// Binary that is not valid UTF-8 must not produce a UTF-8 line.
    /// Android's `new String(bytes)` emits one full of U+FFFD, which
    /// does not decode back to the bytes it is displayed beside.
    func testStringCodecOmitsUtf8ForNonTextBytes() {
        let binary = Data([0xff, 0xfe, 0x00, 0x80])
        let encodings = StringCodec.renderAll(binary).map(\.0)
        XCTAssertFalse(encodings.contains(.utf8))
        XCTAssertEqual(encodings, [.hex, .base58, .base64, .base32])
    }

    func testStringCodecDetectsHexBeforeOtherAlphabets() throws {
        let (data, encoding) = try StringCodec.decodeDetecting("666f6f")
        XCTAssertEqual(encoding, .hex)
        XCTAssertEqual(data, Data("foo".utf8))
    }

    func testStringCodecFallsBackToUtf8() throws {
        // '!' is in no base alphabet, so nothing above UTF-8 can claim it.
        let (data, encoding) = try StringCodec.decodeDetecting("hello!")
        XCTAssertEqual(encoding, .utf8)
        XCTAssertEqual(data, Data("hello!".utf8))
    }

    func testStringCodecExplicitDecodeCanFail() {
        XCTAssertThrowsError(try StringCodec.decode("not hex!", as: .hex))
    }

    // MARK: - Public key forms

    func testDecompressMatchesGeneratorPoint() throws {
        XCTAssertEqual(
            try PubkeyFormats.decompress(pubkey33: Self.pubkey33),
            Self.pubkey65
        )
    }

    func testCompressIsTheInverseOfDecompress() throws {
        XCTAssertEqual(try PubkeyFormats.compress(pubkey65: Self.pubkey65), Self.pubkey33)
    }

    /// A y coordinate with leading zero bytes must still occupy 32
    /// bytes. BigInt drops them, which would yield a short key that
    /// looks fine until something tries to use it.
    func testDecompressLeftPadsShortCoordinates() throws {
        // Any valid key works as a shape check; the invariant is length.
        for suffix in ["02", "03"] {
            let key = suffix + String(Self.pubkey33.dropFirst(2))
            let full = try PubkeyFormats.decompress(pubkey33: key)
            XCTAssertEqual(full.count, 130)
            XCTAssertTrue(full.hasPrefix("04"))
        }
    }

    func testPubkey33NormalizesEveryAcceptedForm() throws {
        XCTAssertEqual(try PubkeyFormats.pubkey33(from: Self.pubkey33), Self.pubkey33)
        XCTAssertEqual(try PubkeyFormats.pubkey33(from: Self.pubkey65), Self.pubkey33)

        let wif = try PubkeyFormats.wifForms(ofPubkey33: Self.pubkey33)
        XCTAssertEqual(wif.compressedWithoutVersion.count, 50)
        XCTAssertEqual(wif.compressedWithVersion0.count, 51)
        XCTAssertEqual(
            try PubkeyFormats.pubkey33(from: wif.compressedWithoutVersion), Self.pubkey33
        )
        XCTAssertEqual(
            try PubkeyFormats.pubkey33(from: wif.compressedWithVersion0), Self.pubkey33
        )
    }

    func testIsPubkeyRejectsAddressesAndBadPrefixes() {
        XCTAssertTrue(PubkeyFormats.isPubkey(Self.pubkey33))
        XCTAssertTrue(PubkeyFormats.isPubkey(Self.pubkey65))
        XCTAssertFalse(PubkeyFormats.isPubkey("FGWP1xKhDP5RmV525TmUoEwX9mTZwp3sJn"))
        // Right length, wrong prefix byte.
        XCTAssertFalse(PubkeyFormats.isPubkey("05" + String(Self.pubkey33.dropFirst(2))))
    }

    // MARK: - Private key input forms

    func testPrivkey32AcceptsHexAndBothWifForms() throws {
        let privkey = try Hex.decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        let compressed = WifPrivkey.encode(privkey: privkey, compressed: true)
        let uncompressed = WifPrivkey.encode(privkey: privkey, compressed: false)
        XCTAssertEqual(compressed.first, "K")
        XCTAssertEqual(uncompressed.first, "5")

        for form in [Hex.encode(privkey), "0x" + Hex.encode(privkey), compressed, uncompressed] {
            XCTAssertEqual(try WifPrivkey.privkey32(from: form), privkey, "form \(form)")
        }
    }

    func testPrivkey32RejectsWrongLengthHexAndBadWif() {
        XCTAssertThrowsError(try WifPrivkey.privkey32(from: "abcd"))
        XCTAssertThrowsError(try WifPrivkey.privkey32(from: "not a key"))
    }

    // MARK: - Bech32 / CashAddr

    func testBech32MatchesBip173P2wpkhVector() throws {
        XCTAssertEqual(
            try Bech32.segwitAddress(hash160: try Hex.decode(Self.hash160Hex)),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        )
    }

    func testCashAddrMatchesSpecVectors() throws {
        let vectors = [
            ("76a04053bda0a88bda5177b86a15c3b29f559873",
             "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
            ("cb481232299cd5743151ac4b2d63ae198e7bb0a9",
             "qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"),
        ]
        for (hash, expected) in vectors {
            XCTAssertEqual(try CashAddr.encode(hash: try Hex.decode(hash)), expected)
            XCTAssertEqual(
                try CashAddr.encodeWithPrefix(hash: try Hex.decode(hash)),
                "bitcoincash:" + expected
            )
        }
    }

    func testCashAddrRejectsUnsupportedHashLength() {
        XCTAssertThrowsError(try CashAddr.encode(hash: Data(repeating: 0, count: 21)))
    }

    // MARK: - Chain addresses

    func testAddressesFromPubkeyMatchPublishedVectors() throws {
        let table = Dictionary(
            uniqueKeysWithValues: try ChainAddresses.fromPubkey(Self.pubkey33)
                .map { ($0.0, $0.1) }
        )
        XCTAssertEqual(table[.fch], "FGWP1xKhDP5RmV525TmUoEwX9mTZwp3sJn")
        XCTAssertEqual(table[.btc], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        XCTAssertEqual(table[.ltc], "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ")
        XCTAssertEqual(table[.doge], "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE")
        XCTAssertEqual(table[.eth], "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
        XCTAssertEqual(table[.bch], "qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h")
        // TRON: same keccak digest as ETH, Base58Check under version 0x41.
        XCTAssertEqual(table[.trx]?.first, "T")
    }

    /// The uncompressed key must give the same seven addresses as the
    /// compressed one, since it is the same point.
    func testUncompressedPubkeyGivesTheSameAddresses() throws {
        let fromCompressed = try ChainAddresses.fromPubkey(Self.pubkey33).map(\.1)
        let fromUncompressed = try ChainAddresses.fromPubkey(Self.pubkey65).map(\.1)
        XCTAssertEqual(fromCompressed, fromUncompressed)
    }

    /// The hash160 path must *not* invent ETH and TRX addresses. Their
    /// hash is over different bytes, so any value shown there would be
    /// an address nobody can spend from.
    func testAddressesFromHash160OmitEthAndTrx() throws {
        let table = try ChainAddresses.fromHash160(try Hex.decode(Self.hash160Hex))
        let chains = table.map(\.0)
        XCTAssertFalse(chains.contains(.eth))
        XCTAssertFalse(chains.contains(.trx))
        XCTAssertEqual(chains, [.fch, .btc, .bch, .ltc, .doge])

        let byChain = Dictionary(uniqueKeysWithValues: table.map { ($0.0, $0.1) })
        // Bitcoin is the segwit form on this path, not the legacy one.
        XCTAssertEqual(byChain[.btc], "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        XCTAssertEqual(byChain[.fch], "FGWP1xKhDP5RmV525TmUoEwX9mTZwp3sJn")
    }

    func testHash160FromAddressRoundTripsAcrossChains() throws {
        let expected = try Hex.decode(Self.hash160Hex)
        for address in [
            "FGWP1xKhDP5RmV525TmUoEwX9mTZwp3sJn",
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ",
            "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE",
        ] {
            XCTAssertEqual(try ChainAddresses.hash160(fromAddress: address), expected,
                           "hash160 of \(address)")
        }
    }

    /// Android slices bytes 1…21 off a raw Base58 decode, so a typo'd
    /// address converts happily into a set of addresses for a key that
    /// does not exist. Going through Base58Check rejects it instead.
    func testHash160FromAddressRejectsBadChecksum() {
        var typo = Array("FGWP1xKhDP5RmV525TmUoEwX9mTZwp3sJn")
        typo[5] = typo[5] == "x" ? "y" : "x"
        XCTAssertThrowsError(try ChainAddresses.hash160(fromAddress: String(typo)))
    }

    // MARK: - Script ASM

    func testDisassembleP2pkh() throws {
        let script = try Hex.decode(
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
        )
        XCTAssertEqual(
            try ScriptAsm.disassemble(script),
            "OP_DUP OP_HASH160 751e76e8199196d454941c45d1b3a323f1433bd6 "
                + "OP_EQUALVERIFY OP_CHECKSIG"
        )
    }

    func testAssembleIsTheInverseOfDisassemble() throws {
        let hex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
        let asm = try ScriptAsm.disassemble(try Hex.decode(hex))
        XCTAssertEqual(Hex.encode(try ScriptAsm.assemble(asm)), hex)
    }

    /// ASM copied out of the Android app uses bitcoinj's dialect —
    /// `PUSHDATA(n)[hex]` and opcodes stripped of their `OP_` prefix.
    func testAssembleAcceptsBitcoinjDialect() throws {
        let bitcoinj = "DUP HASH160 PUSHDATA(20)[751e76e8199196d454941c45d1b3a323f1433bd6] "
            + "EQUALVERIFY CHECKSIG"
        XCTAssertEqual(
            Hex.encode(try ScriptAsm.assemble(bitcoinj)),
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
        )
    }

    func testDisassembleOpReturnAndPushdata1() throws {
        // OP_RETURN OP_PUSHDATA1 <76 bytes>
        let payload = Data(repeating: 0xAB, count: 76)
        let script = ScriptBuilder.opReturnOutput(data: payload).bytes
        let asm = try ScriptAsm.disassemble(script)
        XCTAssertEqual(asm, "OP_RETURN " + Hex.encode(payload))
        XCTAssertEqual(try ScriptAsm.assemble(asm), script)
    }

    func testDisassembleMultisigUsesSmallNumberOpcodes() throws {
        let pubkey = try Hex.decode(Self.pubkey33)
        let script = try ScriptBuilder.multisigOutput(required: 1, pubkeys: [pubkey, pubkey])
        let asm = try ScriptAsm.disassemble(script.bytes)
        XCTAssertTrue(asm.hasPrefix("OP_1 "), asm)
        XCTAssertTrue(asm.hasSuffix("OP_2 OP_CHECKMULTISIG"), asm)
        XCTAssertEqual(try ScriptAsm.assemble(asm), script.bytes)
    }

    /// A push that claims more bytes than the script holds is a broken
    /// script, and saying so beats printing a plausible truncation.
    func testDisassembleRejectsTruncatedPush() {
        XCTAssertThrowsError(try ScriptAsm.disassemble(Data([0x14, 0x01, 0x02])))
    }

    func testAssembleRejectsUnknownToken() {
        XCTAssertThrowsError(try ScriptAsm.assemble("OP_DUP OP_NOTANOPCODE"))
    }

    func testAssembleEncodesNumbersOutsideSmallRange() throws {
        XCTAssertEqual(Hex.encode(try ScriptAsm.assemble("16")), "60")      // OP_16
        XCTAssertEqual(Hex.encode(try ScriptAsm.assemble("17")), "0111")    // push 0x11
        XCTAssertEqual(Hex.encode(try ScriptAsm.assemble("128")), "028000") // sign byte
        XCTAssertEqual(Hex.encode(try ScriptAsm.assemble("-1000")), "02e883")
    }

    // MARK: - JSON

    func testJsonPrettyPrintAndMinifyRoundTrip() throws {
        let compact = #"{"a":1,"b":[1,2,{"c":null}],"d":"x"}"#
        let pretty = try JsonFormatter.prettyPrint(compact)
        XCTAssertEqual(pretty, """
            {
              "a": 1,
              "b": [
                1,
                2,
                {
                  "c": null
                }
              ],
              "d": "x"
            }
            """)
        XCTAssertEqual(try JsonFormatter.minify(pretty), compact)
    }

    /// Key order is load-bearing: a signed FEIP payload reformatted
    /// with its keys reordered no longer hashes to what was signed.
    /// A dictionary round-trip loses this.
    func testJsonPreservesKeyOrder() throws {
        let compact = #"{"z":1,"a":2,"m":3}"#
        XCTAssertEqual(try JsonFormatter.minify(try JsonFormatter.prettyPrint(compact)), compact)
    }

    /// Numbers are copied as text. Parsing them into `Double` — what
    /// `JSONSerialization` does — changes the literal that comes back
    /// out, silently altering amounts and IDs.
    func testJsonPreservesNumberLiteralsExactly() throws {
        let compact = #"{"sats":123456789012345678,"fee":0.00000001,"e":1.0E+2,"neg":-0}"#
        XCTAssertEqual(try JsonFormatter.minify(try JsonFormatter.prettyPrint(compact)), compact)
    }

    func testJsonPreservesStringEscapesAndStructuralCharsInStrings() throws {
        let compact = #"{"s":"a\"b,{}[]:","t":"\\"}"#
        XCTAssertEqual(try JsonFormatter.minify(try JsonFormatter.prettyPrint(compact)), compact)
    }

    func testJsonHandlesEmptyContainers() throws {
        XCTAssertEqual(try JsonFormatter.prettyPrint(#"{"a":{},"b":[]}"#), """
            {
              "a": {},
              "b": []
            }
            """)
    }

    func testJsonRejectsMalformedInput() {
        XCTAssertThrowsError(try JsonFormatter.minify(#"{"a":1,}"#))
        XCTAssertThrowsError(try JsonFormatter.minify(#"{"a" 1}"#))
        XCTAssertThrowsError(try JsonFormatter.minify(#"{a:1}"#))
        XCTAssertThrowsError(try JsonFormatter.minify(#"{"a":01}"#))
        XCTAssertThrowsError(try JsonFormatter.minify(#"{"a":1} trailing"#))
        XCTAssertThrowsError(try JsonFormatter.minify(#"{"a":"unterminated}"#))
        XCTAssertThrowsError(try JsonFormatter.minify(#"{"a":tru}"#))
    }

    func testJsonLooksPrettyHeuristic() {
        XCTAssertTrue(JsonFormatter.looksPretty("{\n  \"a\": 1\n}"))
        XCTAssertFalse(JsonFormatter.looksPretty(#"{"a":1}"#))
    }

    // MARK: - FcDate

    func testFcDateDecomposesHeight() throws {
        // 1 year + 2 days + 3 hours + 4 minutes.
        let height = Int64(FcDate.blocksPerYear + 2 * FcDate.blocksPerDay + 3 * 60 + 4)
        let date = try FcDate(height: height)
        XCTAssertEqual(date.text, "1.2.3.4")
        XCTAssertEqual(date.height, height)
    }

    func testFcDateGenesisIsZero() throws {
        XCTAssertEqual(try FcDate(height: 0).text, "0.0.0.0")
        XCTAssertEqual(FcDate.height(fromUnixSeconds: FcDate.genesisUnixSeconds), 0)
        XCTAssertEqual(try FcDate(height: 0).approximateUnixSeconds, FcDate.genesisUnixSeconds)
    }

    func testFcDateRoundTripsThroughUnixSeconds() throws {
        let height: Int64 = 1_234_567
        let seconds = try FcDate(height: height).approximateUnixSeconds
        XCTAssertEqual(FcDate.height(fromUnixSeconds: seconds), height)
    }

    func testFcDateParsesAndRejectsPartialText() throws {
        XCTAssertEqual(try FcDate(text: "3.120.7.45").height,
                       3 * Int64(FcDate.blocksPerYear) + 120 * Int64(FcDate.blocksPerDay)
                           + 7 * 60 + 45)
        XCTAssertThrowsError(try FcDate(text: "3.120"))
        XCTAssertThrowsError(try FcDate(text: "3.120.7.x"))
    }

    func testFcDateRejectsPreGenesisHeight() {
        XCTAssertThrowsError(try FcDate(height: -1))
        // A time one minute before genesis rounds down, not toward zero.
        XCTAssertEqual(FcDate.height(fromUnixSeconds: FcDate.genesisUnixSeconds - 1), -1)
    }
}
