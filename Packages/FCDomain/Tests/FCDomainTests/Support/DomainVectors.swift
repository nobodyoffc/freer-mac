import Foundation
import XCTest

/// Loader for the domain-layer golden vectors at
/// `Tests/FCDomainTests/Resources/domainVectors.json`, produced by
/// `tools/vector-gen` running the REAL FC-AJDK classes (see
/// `HatRef.java`). Regenerate with:
///
/// ```
/// cd tools/vector-gen && ./gradlew run --args="<crypto> <fudp> <domain>"
/// ```
enum DomainVectors {

    struct Root: Decodable {
        let generatedAt: String
        let schemaVersion: Int
        let generator: String
        let hat: [HatCase]
        let mail: [MailCase]
        let imMessage: ImMessageRoot
        let asyTwoWayEnvelope: AsyTwoWayRoot

        enum CodingKeys: String, CodingKey {
            case generatedAt = "generated_at"
            case schemaVersion = "schema_version"
            case generator
            case hat
            case mail
            case imMessage = "im_message"
            case asyTwoWayEnvelope = "asy_two_way_envelope"
        }
    }

    /// `ImMessage` vectors from the real FC-AJDK class (see
    /// `ImMessageRef.java`), plus the enum ordinal tables the binary wire
    /// format depends on.
    struct ImMessageRoot: Decodable {
        /// Java constant names in declaration order — so index *is* the
        /// ordinal — keyed by enum name.
        let enumOrdinals: [String: [String]]
        let vectors: [ImMessageCase]

        enum CodingKeys: String, CodingKey {
            case enumOrdinals = "enum_ordinals"
            case vectors
        }
    }

    struct ImMessageCase: Decodable {
        let label: String
        /// `JsonUtils.toJson(message)` — the local-storage form, which
        /// carries the local-only delivery fields too.
        let json: String
        /// `toWireBytes()`, hex.
        let wireHex: String
        /// `toJson(fromWireBytes(toWireBytes(m)))` — what survives the
        /// trip. The local-only fields are gone from this one.
        let wireDecodedJson: String

        enum CodingKeys: String, CodingKey {
            case label
            case json
            case wireHex = "wire_hex"
            case wireDecodedJson = "wire_decoded_json"
        }
    }

    /// One `Mail` vector as the Android class produced it. Unlike `Hat`,
    /// Mail has a single encoder — `JsonUtils.toJson` with HTML escaping
    /// disabled — so its stored JSON and its id-source bytes differ only
    /// by the presence of the `id` field.
    struct MailCase: Decodable {
        let label: String
        /// `JsonUtils.toJson(mail)`.
        let json: String
        /// The exact bytes `checkIdWithCreate()` hashes (the object minus
        /// its id).
        let idSourceJson: String
        /// The id that derivation assigns.
        let derivedIdWithoutIdField: String

        enum CodingKeys: String, CodingKey {
            case label
            case json
            case idSourceJson = "id_source_json"
            case derivedIdWithoutIdField = "derived_id_without_id_field"
        }
    }

    /// AsyTwoWay / AsyOneWay CryptoDataStr envelopes sealed by the real
    /// FC-AJDK `Encryptor` and reopened by its `Decryptor` before being
    /// written out (see `AsyTwoWayRef.java`). `A` is the sender, `B` the
    /// recipient, `C` an unrelated third party.
    struct AsyTwoWayRoot: Decodable {
        let prikeyA: String
        let pubkeyA: String
        let prikeyB: String
        let pubkeyB: String
        let strangerPrikey: String
        /// Generated as `false`; kept in the file so the claim that the
        /// stranger is locked out is the generator's, not the reader's.
        let strangerCanDecrypt: Bool
        let vectors: [AsyCase]

        enum CodingKeys: String, CodingKey {
            case prikeyA, pubkeyA, prikeyB, pubkeyB, vectors
            case strangerPrikey = "prikeyC_stranger"
            case strangerCanDecrypt = "stranger_can_decrypt"
        }
    }

    struct AsyCase: Decodable {
        let name: String
        /// `AsyTwoWay` or `AsyOneWay`.
        let mode: String
        /// The Java `AlgorithmId` enum constant name.
        let alg: String
        let plaintext: String
        let plaintextHex: String
        /// `cryptoDataByte.toJson()` — what lands in the FEIP `cipher`.
        let envelope: String

        var isTwoWay: Bool { mode == "AsyTwoWay" }

        enum CodingKeys: String, CodingKey {
            case name, mode, alg, plaintext, envelope
            case plaintextHex = "plaintext_hex"
        }
    }

    /// One `Hat` vector as the Android class produced it.
    struct HatCase: Decodable {
        let label: String
        /// `hat.toJson()` — HTML escaping disabled.
        let json: String
        /// `new String(hat.toBytes())` — HTML escaping ON. Differs from
        /// `json` only when a value contains `< > & = '`.
        let idBytesJson: String
        /// The DID `checkIdWithCreate()` assigns when the `id` field is
        /// stripped first.
        let derivedIdWithoutIdField: String
        /// The exact bytes that derivation hashes over.
        let derivedIdSourceJson: String

        enum CodingKeys: String, CodingKey {
            case label
            case json
            case idBytesJson = "id_bytes_json"
            case derivedIdWithoutIdField = "derived_id_without_id_field"
            case derivedIdSourceJson = "derived_id_source_json"
        }
    }

    static func load(file: StaticString = #filePath, line: UInt = #line) throws -> Root {
        guard let url = Bundle.module.url(forResource: "domainVectors", withExtension: "json") else {
            XCTFail("domainVectors.json missing from the test bundle", file: file, line: line)
            throw CocoaError(.fileNoSuchFile)
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Root.self, from: data)
    }
}
