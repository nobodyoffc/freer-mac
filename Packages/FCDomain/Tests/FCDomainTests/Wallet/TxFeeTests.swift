import XCTest
import FCCore
@testable import FCDomain

/// ``TxFee`` against `txFeeVectors.json`, produced by running the real
/// FC-AJDK `TxHandler.calcFee`.
///
/// The fee is not a cosmetic number: it decides whether a change
/// output exists, and therefore what the transaction *is*. Two clients
/// that price the same document differently build two different
/// transactions from it, and only one of them is the one the user
/// approved.
final class TxFeeTests: XCTestCase {

    // MARK: - vectors

    struct Vectors: Decodable {
        let calcFee: [Case]

        enum CodingKeys: String, CodingKey { case calcFee = "calc_fee" }

        struct Case: Decodable {
            let label: String
            let sender: String?
            let changeTo: String?
            let feeRate: Double?
            let opReturnIn: String?
            let inputs: [Slot]
            let outputs: [Slot]
            let fee: Int64?
            let finalOpReturn: String?
            let p2shOutputCount: Int

            struct Slot: Decodable {
                let value: Int64?
                let owner: String?
                let birthTxId: String?
                let birthIndex: Int?
                let lockTime: Int64?
                let redeemScript: String?

                enum CodingKeys: String, CodingKey {
                    case value, owner
                    case birthTxId = "birth_tx_id"
                    case birthIndex = "birth_index"
                    case lockTime = "lock_time"
                    case redeemScript = "redeem_script"
                }

                var asSlot: RawTxInfo.Slot {
                    RawTxInfo.Slot(
                        owner: owner,
                        value: value,
                        birthTxId: birthTxId,
                        birthIndex: birthIndex,
                        redeemScript: redeemScript,
                        lockTime: lockTime
                    )
                }
            }

            enum CodingKeys: String, CodingKey {
                case label, sender, inputs, outputs, fee
                case changeTo = "change_to"
                case feeRate = "fee_rate"
                case opReturnIn = "op_return_in"
                case finalOpReturn = "final_op_return"
                case p2shOutputCount = "p2sh_output_count"
            }
        }
    }

    private func vectors() throws -> Vectors {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "txFeeVectors", withExtension: "json"),
            "txFeeVectors.json missing — run tools/vector-gen/gradlew run"
        )
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }

    /// The vector's multisig case names its group by address only; the
    /// group itself is rebuilt from the input's redeem script, which is
    /// what a real caller would have on file too.
    private func info(from c: Vectors.Case) throws -> RawTxInfo {
        var info = RawTxInfo(
            sender: c.sender,
            feeRate: c.feeRate,
            inputs: c.inputs.map(\.asSlot),
            outputs: c.outputs.map(\.asSlot),
            opReturn: c.opReturnIn,
            changeTo: c.changeTo
        )
        if let sender = c.sender, FchAddress.isP2sh(fid: sender),
           let hex = c.inputs.first?.redeemScript,
           let p2sh = try? P2sh(redeemScriptHex: hex),
           let m = p2sh.m, let n = p2sh.n {
            var group = Multisig()
            group.m = m
            group.n = n
            group.pubkeys = p2sh.pubkeys
            group.redeemScript = hex
            info.senderMultisig = group
        }
        return info
    }

    // MARK: - tests

    func testFeeMatchesAndroidForEveryShape() throws {
        for c in try vectors().calcFee {
            let result = TxFee.calc(try info(from: c))
            XCTAssertEqual(result.fee, c.fee, "fee for '\(c.label)'")
        }
    }

    /// A time-locked output publishes its redeem script in the
    /// OP_RETURN, displacing whatever text the user typed. Getting this
    /// wrong is silent: the transaction still sends, but the recipient
    /// can never reconstruct the script to spend it.
    func testFinalOpReturnMatchesAndroid() throws {
        for c in try vectors().calcFee {
            let result = TxFee.calc(try info(from: c))
            let text = result.opReturn.isEmpty
                ? nil : String(decoding: result.opReturn, as: UTF8.self)
            XCTAssertEqual(text, c.finalOpReturn.flatMap { $0.isEmpty ? nil : $0 },
                           "OP_RETURN for '\(c.label)'")
            XCTAssertEqual(result.p2shOutputs.count, c.p2shOutputCount,
                           "P2SH output count for '\(c.label)'")
        }
    }

    /// The lock-mode case: a user's message and a redeem-script
    /// manifest cannot both occupy the one OP_RETURN output, and the
    /// manifest is the one that has to survive.
    func testManifestDisplacesTheUsersMessage() throws {
        let c = try XCTUnwrap(try vectors().calcFee.first { $0.label == "cltv-output" })
        XCTAssertNotNil(c.opReturnIn, "the vector must actually set a message")
        let result = TxFee.calc(try info(from: c))
        let text = String(decoding: result.opReturn, as: UTF8.self)
        XCTAssertTrue(text.hasPrefix("["), "the manifest is a JSON array of scripts")
        XCTAssertNotEqual(text, c.opReturnIn)
    }

    /// The two sides of the change decision, pinned by vectors that sit
    /// either side of the line. Between them lies the only place the
    /// change-or-not question is actually hard: enough is left to clear
    /// dust, but not once the change output has paid for itself.
    func testChangeExistsOnlyWhenItPaysForItself() throws {
        let all = try vectors().calcFee
        let withChange = try XCTUnwrap(all.first { $0.label == "one-in-one-out-with-change" })
        let boundary = try XCTUnwrap(all.first { $0.label == "change-boundary" })

        XCTAssertTrue(TxFee.calc(try info(from: withChange)).willHaveChange)
        XCTAssertFalse(TxFee.calc(try info(from: boundary)).willHaveChange)

        // The boundary case is the interesting one only if the plain
        // remainder really does clear dust before the change is priced.
        let remainder = boundary.inputs.reduce(0) { $0 + ($1.value ?? 0) }
            - boundary.outputs.reduce(0) { $0 + ($1.value ?? 0) }
        XCTAssertGreaterThan(remainder - (boundary.fee ?? 0), TxFee.dustSatoshi)
    }

    // MARK: - size arithmetic

    /// The plain shape, worked out by hand: 10 bytes of overhead, a
    /// 141-byte Schnorr P2PKH input, a 34-byte output, and 34 more for
    /// the change.
    func testPlainSizeIsOverheadPlusInputsPlusOutputs() throws {
        let c = try XCTUnwrap(
            try vectors().calcFee.first { $0.label == "one-in-one-out-with-change" }
        )
        let result = TxFee.calc(try info(from: c))
        XCTAssertEqual(result.estimatedSize, 10 + 141 + 34 + 34)
        XCTAssertEqual(result.fee, result.estimatedSize)   // 1 sat/byte
    }

    func testChangeOutputSizeDependsOnTheAddressKind() {
        XCTAssertEqual(TxFee.changeOutputBytes(payingTo: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"), 34)
        XCTAssertEqual(TxFee.changeOutputBytes(payingTo: "3Co4peuZUuKkdRZpuzuCyJLcUoXVz8Enqi"), 32)
        XCTAssertEqual(TxFee.changeOutputBytes(payingTo: nil), 34)
    }

    func testLockTimeIsAHeightBelowTheThresholdAndATimeAbove() {
        // Block heights.
        XCTAssertTrue(TxFee.isLockTimeUnlocked(900_000, bestHeight: 900_000))
        XCTAssertTrue(TxFee.isLockTimeUnlocked(900_000, bestHeight: 900_001))
        XCTAssertFalse(TxFee.isLockTimeUnlocked(900_000, bestHeight: 899_999))
        // Zero means no lock at all.
        XCTAssertTrue(TxFee.isLockTimeUnlocked(0, bestHeight: 0))
        // Unix seconds — the block height is irrelevant on this side.
        let past = Date(timeIntervalSince1970: 1_600_000_000)
        XCTAssertTrue(TxFee.isLockTimeUnlocked(
            1_500_000_000, bestHeight: 0, now: past
        ))
        XCTAssertFalse(TxFee.isLockTimeUnlocked(
            1_700_000_000, bestHeight: 99_999_999, now: past
        ))
    }

    /// A document whose inputs cannot be priced must report *no* fee
    /// rather than a plausible one — a wrong fee is spent, an unknown
    /// fee is refused.
    func testUnpriceableInputsYieldNoFee() {
        let info = RawTxInfo(
            sender: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
            inputs: [RawTxInfo.Slot(
                owner: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
                value: 100_000,
                birthTxId: String(repeating: "a", count: 64),
                birthIndex: 0,
                redeemScript: "76a914",        // not a redeem script
                lockTime: 900_000
            )],
            outputs: [.output(to: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", amount: 1_000)]
        )
        XCTAssertNil(TxFee.calc(info).fee)
        XCTAssertNil(TxFee.calc(RawTxInfo()).fee, "no inputs is also unpriceable")
    }
}
