import Foundation
import FCCore

/// On-disk metadata about one registered identity. **Contains no
/// secrets** — privkeys are never persisted; this record only describes
/// *which* identity exists and *how* to derive its key from a passphrase.
///
/// Stored in the plaintext index file `identities.json` next to the
/// per-identity DB directories. Including KDF parameters here means a
/// future change to the Argon2 parameters can coexist with old records
/// without forcing a migration.
public struct IdentityRecord: Codable, Equatable, Hashable, Sendable {

    /// Schema revision of this record. Bumped if the field set changes
    /// in a non-additive way.
    public static let currentVersion: Int = 1

    public var version: Int
    public var fid: String
    public var displayName: String
    public var phraseScheme: PhraseKey.Scheme
    public var createdAt: Date

    public init(
        version: Int = IdentityRecord.currentVersion,
        fid: String,
        displayName: String,
        phraseScheme: PhraseKey.Scheme,
        createdAt: Date = Date()
    ) {
        self.version = version
        self.fid = fid
        self.displayName = displayName
        self.phraseScheme = phraseScheme
        self.createdAt = createdAt
    }
}

/// Plaintext on-disk index of every identity registered on this Mac.
/// Loaded once at app start; mutated by ``IdentityVault`` and rewritten
/// atomically (write-temp-then-rename) so a crash mid-write can't leave
/// a half-written file.
public struct IdentityIndex: Codable, Equatable, Sendable {
    public var version: Int
    public var identities: [IdentityRecord]

    public init(version: Int = IdentityRecord.currentVersion, identities: [IdentityRecord] = []) {
        self.version = version
        self.identities = identities
    }

    public func find(fid: String) -> IdentityRecord? {
        identities.first { $0.fid == fid }
    }

    public mutating func upsert(_ record: IdentityRecord) {
        if let i = identities.firstIndex(where: { $0.fid == record.fid }) {
            identities[i] = record
        } else {
            identities.append(record)
        }
    }

    public mutating func remove(fid: String) -> Bool {
        guard let i = identities.firstIndex(where: { $0.fid == fid }) else { return false }
        identities.remove(at: i)
        return true
    }
}

/// Reads and writes ``IdentityIndex`` to disk atomically. Pulled out of
/// ``IdentityVault`` so tests can stub the storage path without
/// touching the real Application Support directory.
public struct IdentityIndexStore {

    public enum Failure: Error, CustomStringConvertible {
        case ioFailed(URL, Error)
        case decodingFailed(Error)

        public var description: String {
            switch self {
            case .ioFailed(let url, let err):
                return "IdentityIndexStore: I/O failed at \(url.path) — \(err)"
            case .decodingFailed(let err):
                return "IdentityIndexStore: decoding failed — \(err)"
            }
        }
    }

    public let url: URL

    public init(url: URL) { self.url = url }

    /// Returns an empty index if the file doesn't exist yet — first run.
    public func load() throws -> IdentityIndex {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return IdentityIndex()
        } catch {
            throw Failure.ioFailed(url, error)
        }
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(IdentityIndex.self, from: data)
        } catch {
            throw Failure.decodingFailed(error)
        }
    }

    public func save(_ index: IdentityIndex) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data
        do {
            data = try encoder.encode(index)
        } catch {
            throw Failure.decodingFailed(error)
        }
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            // .atomic := write to temp file, fsync, rename — survives crashes.
            try data.write(to: url, options: [.atomic])
        } catch {
            throw Failure.ioFailed(url, error)
        }
    }
}
