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

        enum CodingKeys: String, CodingKey {
            case generatedAt = "generated_at"
            case schemaVersion = "schema_version"
            case generator
            case hat
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
