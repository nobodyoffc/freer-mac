import Foundation
import FCCore
import FCStorage

/// Top-level vault management. Owns the list of password-protected
/// Configures on this Mac and the boot-time lookup
/// (`password → ConfigureRecord`).
///
/// Filesystem layout under `baseDirectory`:
///
/// ```
/// baseDirectory/
/// ├── configures.json                       # plaintext index
/// └── configures/<passwordName>/
///     ├── configure.encrypted.dat           # AES-GCM(symkey, Configure)
///     └── settings/<mainFid>/
///         ├── setting.encrypted.dat         # AES-GCM(symkey, Setting)
///         └── store.sqlite                  # per-main EncryptedKVStore
/// ```
///
/// `passwordName` is `dSHA256(password)[0..6]` hex — deterministic,
/// so the boot flow can ask "which Configure am I about to unlock?"
/// before doing any KDF work.
public final class ConfigureManager {

    public enum Failure: Error, CustomStringConvertible {
        case alreadyExists(passwordName: String)
        case notFound(passwordName: String)
        case wrongPassword
        case io(URL, Error)
        case underlying(Error)

        public var description: String {
            switch self {
            case .alreadyExists(let pn): return "ConfigureManager: a Configure with passwordName=\(pn) already exists"
            case .notFound(let pn):      return "ConfigureManager: no Configure with passwordName=\(pn)"
            case .wrongPassword:         return "ConfigureManager: wrong password"
            case let .io(url, err):      return "ConfigureManager: I/O at \(url.path) — \(err)"
            case .underlying(let err):   return "ConfigureManager: \(err)"
            }
        }
    }

    public let baseDirectory: URL
    private let indexUrl: URL

    public convenience init() throws {
        try self.init(baseDirectory: ConfigureManager.defaultBaseDirectory())
    }

    public init(baseDirectory: URL) throws {
        self.baseDirectory = baseDirectory
        self.indexUrl = baseDirectory.appendingPathComponent("configures.json")
        do {
            try FileManager.default.createDirectory(
                at: baseDirectory.appendingPathComponent("configures"),
                withIntermediateDirectories: true
            )
        } catch {
            throw Failure.io(baseDirectory, error)
        }
    }

    public static func defaultBaseDirectory() -> URL {
        let appSupport = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        return appSupport.appendingPathComponent("fc.freer.mac", isDirectory: true)
    }

    // MARK: - index

    public func listConfigures() throws -> [ConfigureRecord] {
        try readIndex().configures
    }

    public func find(passwordName: String) throws -> ConfigureRecord? {
        try readIndex().find(passwordName: passwordName)
    }

    public func find(forPassword password: Data) throws -> ConfigureRecord? {
        try find(passwordName: ConfigureCrypto.passwordName(from: password))
    }

    // MARK: - create / open / delete

    /// Mint a new Configure. The password's bytes are not retained;
    /// the resulting ``ConfigureSession`` holds the derived symkey
    /// for the duration of the session.
    @discardableResult
    public func createConfigure(
        password: Data,
        label: String = "",
        kdfKind: KdfKind = .argon2id
    ) throws -> ConfigureSession {
        let passwordName = ConfigureCrypto.passwordName(from: password)
        var index = try readIndex()
        if index.find(passwordName: passwordName) != nil {
            throw Failure.alreadyExists(passwordName: passwordName)
        }

        let nonce = try Self.randomBytes(count: 16)
        let symkey: Data
        do {
            symkey = try kdfKind.deriveSymkey(password: password, salt: nonce)
        } catch {
            throw Failure.underlying(error)
        }
        let passwordHash = ConfigureCrypto.verificationToken(symkey: symkey)

        let record = ConfigureRecord(
            passwordName: passwordName,
            nonce: nonce,
            kdfKind: kdfKind,
            passwordHash: passwordHash,
            label: label
        )
        let configure = Configure()

        // Persist body first so a crash mid-creation can't leave an
        // index entry pointing at no body.
        try writeConfigureBody(configure, for: record, symkey: symkey)
        index.upsert(record)
        try writeIndex(index)

        return ConfigureSession(record: record, configure: configure, symkey: symkey, manager: self)
    }

    /// Verify a password against the named Configure and return an
    /// unlocked ``ConfigureSession``. Throws ``Failure/wrongPassword``
    /// when the password doesn't produce the recorded verification token.
    public func openConfigure(passwordName: String, password: Data) throws -> ConfigureSession {
        guard let record = try find(passwordName: passwordName) else {
            throw Failure.notFound(passwordName: passwordName)
        }
        guard let symkey = ConfigureCrypto.verify(password: password, against: record) else {
            throw Failure.wrongPassword
        }
        let configure = try readConfigureBody(for: record, symkey: symkey)
        return ConfigureSession(record: record, configure: configure, symkey: symkey, manager: self)
    }

    /// Delete a Configure: remove from the index, then unlink its
    /// directory. Returns `true` if something was removed.
    @discardableResult
    public func deleteConfigure(passwordName: String) throws -> Bool {
        var index = try readIndex()
        guard index.remove(passwordName: passwordName) else { return false }
        try writeIndex(index)

        let dir = configureDirectory(for: passwordName)
        if FileManager.default.fileExists(atPath: dir.path) {
            do { try FileManager.default.removeItem(at: dir) }
            catch { throw Failure.io(dir, error) }
        }
        return true
    }

    // MARK: - paths (also used by ConfigureSession)

    func configureDirectory(for passwordName: String) -> URL {
        baseDirectory
            .appendingPathComponent("configures", isDirectory: true)
            .appendingPathComponent(passwordName, isDirectory: true)
    }

    func configureBodyUrl(for passwordName: String) -> URL {
        configureDirectory(for: passwordName)
            .appendingPathComponent("configure.encrypted.dat")
    }

    func settingsRoot(for passwordName: String) -> URL {
        configureDirectory(for: passwordName)
            .appendingPathComponent("settings", isDirectory: true)
    }

    func settingDirectory(passwordName: String, mainFid: String) -> URL {
        settingsRoot(for: passwordName).appendingPathComponent(mainFid, isDirectory: true)
    }

    // MARK: - body I/O (called from ConfigureSession)

    func writeConfigureBody(_ configure: Configure, for record: ConfigureRecord, symkey: Data) throws {
        let url = configureBodyUrl(for: record.passwordName)
        do {
            try EncryptedFile.write(configure, to: url, key: symkey)
        } catch {
            throw Failure.underlying(error)
        }
    }

    func readConfigureBody(for record: ConfigureRecord, symkey: Data) throws -> Configure {
        let url = configureBodyUrl(for: record.passwordName)
        do {
            return try EncryptedFile.read(Configure.self, from: url, key: symkey) ?? Configure()
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - index I/O

    private func readIndex() throws -> ConfigureIndex {
        do {
            let data = try Data(contentsOf: indexUrl)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(ConfigureIndex.self, from: data)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return ConfigureIndex()
        } catch {
            throw Failure.io(indexUrl, error)
        }
    }

    private func writeIndex(_ index: ConfigureIndex) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        do {
            let data = try encoder.encode(index)
            try FileManager.default.createDirectory(
                at: indexUrl.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: indexUrl, options: Data.WritingOptions.atomic)
        } catch {
            throw Failure.io(indexUrl, error)
        }
    }

    // MARK: - random

    static func randomBytes(count: Int) throws -> Data {
        var out = Data(count: count)
        let status = out.withUnsafeMutableBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else {
            throw Failure.underlying(NSError(domain: "SecRandom", code: Int(status)))
        }
        return out
    }
}
