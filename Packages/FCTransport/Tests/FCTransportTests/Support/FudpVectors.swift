import Foundation
import XCTest

/// Loader for `fudpVectors.json` — produced by `tools/vector-gen/`
/// using `FudpRef.java`, which mirrors the FC-JDK FUDP wire format.
enum FudpVectors {

    struct Root: Decodable {
        let generatedAt: String
        let schemaVersion: Int
        let generator: String
        let quicVarint: [VarintCase]
        let packetHeader: [PacketHeaderCase]
        let streamFrame: [StreamFrameCase]
        let ackFrame: [AckFrameCase]
        let paddingFrame: [PaddingFrameCase]
        let plaintextPayload: [PlaintextPayloadCase]
        let asyTwoWay: [AsyTwoWayCase]
        let challengePacket: [ChallengePacketCase]
        let challengeResponsePacket: [ChallengeResponsePacketCase]
        let proofOfWork: [ProofOfWorkCase]

        enum CodingKeys: String, CodingKey {
            case generatedAt = "generated_at"
            case schemaVersion = "schema_version"
            case generator
            case quicVarint = "quic_varint"
            case packetHeader = "packet_header"
            case streamFrame = "stream_frame"
            case ackFrame = "ack_frame"
            case paddingFrame = "padding_frame"
            case plaintextPayload = "plaintext_payload"
            case asyTwoWay = "asy_two_way"
            case challengePacket = "challenge_packet"
            case challengeResponsePacket = "challenge_response_packet"
            case proofOfWork = "proof_of_work"
        }
    }

    struct ChallengePacketCase: Decodable {
        let label: String
        let nonceHex: String
        let difficulty: Int
        let timestamp: Int64
        let encodedHex: String

        enum CodingKeys: String, CodingKey {
            case label, difficulty, timestamp
            case nonceHex = "nonce_hex"
            case encodedHex = "encoded_hex"
        }
    }

    struct ChallengeResponsePacketCase: Decodable {
        let label: String
        let nonceHex: String
        let solutionHex: String
        let encodedHex: String

        enum CodingKeys: String, CodingKey {
            case label
            case nonceHex = "nonce_hex"
            case solutionHex = "solution_hex"
            case encodedHex = "encoded_hex"
        }
    }

    struct ProofOfWorkCase: Decodable {
        let nonceHex: String
        let difficulty: Int
        let solutionHex: String
        let expectedHashHex: String

        enum CodingKeys: String, CodingKey {
            case difficulty
            case nonceHex = "nonce_hex"
            case solutionHex = "solution_hex"
            case expectedHashHex = "expected_hash_hex"
        }
    }

    struct AsyTwoWayCase: Decodable {
        let label: String
        let localPrivkeyHex: String
        let localPubkeyHex: String
        let peerPubkeyHex: String
        let ivHex: String
        let plaintextHex: String
        let aadHex: String
        let sharedSecretHex: String
        let symKeyHex: String
        let bundleHex: String

        enum CodingKeys: String, CodingKey {
            case label
            case localPrivkeyHex = "local_privkey_hex"
            case localPubkeyHex = "local_pubkey_hex"
            case peerPubkeyHex = "peer_pubkey_hex"
            case ivHex = "iv_hex"
            case plaintextHex = "plaintext_hex"
            case aadHex = "aad_hex"
            case sharedSecretHex = "shared_secret_hex"
            case symKeyHex = "sym_key_hex"
            case bundleHex = "bundle_hex"
        }
    }

    struct VarintCase: Decodable {
        let value: UInt64
        let encodedHex: String

        enum CodingKeys: String, CodingKey {
            case value
            case encodedHex = "encoded_hex"
        }
    }

    struct PacketHeaderCase: Decodable {
        let label: String
        let flags: UInt8
        let version: UInt32
        let connectionId: Int64
        let packetNumber: Int64
        let encodedHex: String

        enum CodingKeys: String, CodingKey {
            case label, flags, version
            case connectionId = "connection_id"
            case packetNumber = "packet_number"
            case encodedHex = "encoded_hex"
        }
    }

    struct StreamFrameCase: Decodable {
        let label: String
        let streamId: UInt64
        let offset: UInt64
        let fin: Bool
        let dataHex: String
        let encodedHex: String

        enum CodingKeys: String, CodingKey {
            case label
            case streamId = "stream_id"
            case offset, fin
            case dataHex = "data_hex"
            case encodedHex = "encoded_hex"
        }
    }

    struct AckFrameCase: Decodable {
        struct Range: Decodable {
            let gap: UInt64
            let length: UInt64
        }
        let label: String
        let largestAcknowledged: UInt64
        let ackDelay: UInt64
        let ranges: [Range]
        let encodedHex: String

        enum CodingKeys: String, CodingKey {
            case label
            case largestAcknowledged = "largest_acknowledged"
            case ackDelay = "ack_delay"
            case ranges
            case encodedHex = "encoded_hex"
        }
    }

    struct PaddingFrameCase: Decodable {
        let label: String
        let encodedHex: String

        enum CodingKeys: String, CodingKey {
            case label
            case encodedHex = "encoded_hex"
        }
    }

    struct PlaintextPayloadCase: Decodable {
        let label: String
        let includeTimestamp: Bool
        let timestamp: Int64?
        let includeEpoch: Bool
        let sessionEpoch: Int64?
        let framesHex: [String]
        let encodedHex: String

        enum CodingKeys: String, CodingKey {
            case label
            case includeTimestamp = "include_timestamp"
            case timestamp
            case includeEpoch = "include_epoch"
            case sessionEpoch = "session_epoch"
            case framesHex = "frames_hex"
            case encodedHex = "encoded_hex"
        }
    }

    static func load(file: StaticString = #file, line: UInt = #line) throws -> Root {
        guard let url = Bundle.module.url(forResource: "fudpVectors", withExtension: "json") else {
            XCTFail("fudpVectors.json missing — run tools/vector-gen", file: file, line: line)
            throw CocoaError(.fileReadNoSuchFile)
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Root.self, from: data)
    }
}

// MARK: - hex helpers (kept local to FCTransport tests, mirroring FCCore's pattern)

extension Data {
    init(fromHex hex: String) {
        precondition(hex.count % 2 == 0, "hex string has odd length: \(hex)")
        var data = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<next], radix: 16) else {
                preconditionFailure("invalid hex byte: \(hex[idx..<next])")
            }
            data.append(byte)
            idx = next
        }
        self = data
    }

    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
