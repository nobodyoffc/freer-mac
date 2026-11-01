import XCTest
@testable import FCDomain

/// One approval for a cover image and the work that names it.
final class PairedApprovalGateTests: XCTestCase {

    func carve(_ feip: String, payTo: String? = nil) -> TxPreview {
        var outputs = [TxPreview.Output(fid: nil, amount: 0, isSelf: false, isOpReturn: true)]
        if let payTo { outputs.append(.init(fid: payTo, amount: 1000, isSelf: false)) }
        return TxPreview(kind: .carve, from: "FMe", inputs: [], outputs: outputs, fee: 100, estimatedSize: 300,
                         feePerByte: 1, opReturn: "{\"type\":\"FEIP\",\"sn\":\"\(feip)\",\"ver\":\"1\",\"data\":{}}")
    }

    final class Asked: @unchecked Sendable {
        var previews: [TxPreview] = []
        var answer: TxDecision = .approve
    }

    func approver(_ asked: Asked) -> TxApprover {
        { preview in asked.previews.append(preview); return asked.answer }
    }

    func testTheWorkFollowsTheApprovedImageWithoutASecondDialog() async {
        let gate = PairedApprovalGate(), asked = Asked()
        let grant = gate.open(follower: "Video", note: "also the video")
        let first = await gate.decide(carve("24"), approver(asked))
        let second = await gate.decide(carve("25"), approver(asked))
        XCTAssertEqual([first, second], [.approve, .approve])
        XCTAssertEqual(asked.previews.count, 1)
        XCTAssertEqual(asked.previews[0].note, "also the video")
        // Only one follower: a third carve is asked as usual.
        _ = await gate.decide(carve("25"), approver(asked))
        XCTAssertEqual(asked.previews.count, 2)
        XCTAssertNil(asked.previews[1].note)
        gate.close(grant)
    }

    func testOnlyTheNamedProtocolPayingNoOneFollows() async {
        let gate = PairedApprovalGate(), asked = Asked()
        _ = gate.open(follower: "Video", note: "n")
        _ = await gate.decide(carve("24"), approver(asked))
        _ = await gate.decide(carve("7"), approver(asked))
        _ = await gate.decide(carve("25", payTo: "FOther"), approver(asked))
        XCTAssertEqual(asked.previews.count, 3, "a mail and a paying carve are still shown")
    }

    func testADeclinedImageGrantsNothing() async {
        let gate = PairedApprovalGate(), asked = Asked()
        _ = gate.open(follower: "Video", note: "n")
        asked.answer = .decline
        let first = await gate.decide(carve("24"), approver(asked))
        asked.answer = .approve
        _ = await gate.decide(carve("25"), approver(asked))
        XCTAssertEqual(first, .decline)
        XCTAssertEqual(asked.previews.count, 2)
    }

    func testAClosedGrantGrantsNothing() async {
        let gate = PairedApprovalGate(), asked = Asked()
        let grant = gate.open(follower: "Video", note: "n")
        _ = await gate.decide(carve("24"), approver(asked))
        gate.close(grant)
        _ = await gate.decide(carve("25"), approver(asked))
        XCTAssertEqual(asked.previews.count, 2)
    }
}
