import Foundation
import Security

/// Thin wrapper around macOS's generic-password Keychain API.
///
/// The primary use inside Freer is storing the *vault key* — the 32-byte
/// AES-GCM key that encrypts rows in the local SQLite DB. The vault key
/// itself never leaves Keychain storage (it's generated once, per
/// identity, by `EncryptedKVStore`), so there is one read at startup and
/// none afterwards in the hot path.
///
/// Items are scoped by `service` + `account`. All inserts use
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:
/// - *WhenUnlocked*: inaccessible while the device is locked.
/// - *ThisDeviceOnly*: not synced to iCloud Keychain, not restored to a
///   different machine from a backup.
public enum Keychain {

    public enum Failure: Error, CustomStringConvertible {
        case unexpectedStatus(OSStatus)
        case itemNotFound
        case invalidDataType

        public var description: String {
            switch self {
            case .unexpectedStatus(let code):
                let msg = SecCopyErrorMessageString(code, nil) as String? ?? "unknown"
                return "Keychain: unexpected status \(code) (\(msg))"
            case .itemNotFound:
                return "Keychain: item not found"
            case .invalidDataType:
                return "Keychain: returned item was not Data"
            }
        }
    }

    /// Upsert a secret under `(service, account)`. If an item already
    /// exists at that key it is overwritten; otherwise a new item is
    /// inserted with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
    public static func set(_ value: Data, service: String, account: String) throws {
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        // Try update first; fall back to insert on `errSecItemNotFound`.
        let updateStatus = SecItemUpdate(
            baseQuery as CFDictionary,
            [kSecValueData as String: value] as CFDictionary
        )
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw Failure.unexpectedStatus(updateStatus)
        }

        var insertQuery = baseQuery
        insertQuery[kSecValueData as String] = value
        insertQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(insertQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw Failure.unexpectedStatus(addStatus)
        }
    }

    /// Fetch the secret bytes for `(service, account)`.
    /// Throws `Failure.itemNotFound` if the item does not exist.
    public static func get(service: String, account: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { throw Failure.itemNotFound }
        guard status == errSecSuccess else { throw Failure.unexpectedStatus(status) }
        guard let data = out as? Data else { throw Failure.invalidDataType }
        return data
    }

    /// Delete the secret at `(service, account)`. Idempotent:
    /// returns `true` if an item was actually deleted, `false` if none
    /// existed.
    @discardableResult
    public static func delete(service: String, account: String) throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess { return true }
        if status == errSecItemNotFound { return false }
        throw Failure.unexpectedStatus(status)
    }

    public static func exists(service: String, account: String) throws -> Bool {
        do {
            _ = try get(service: service, account: account)
            return true
        } catch Failure.itemNotFound {
            return false
        }
    }
}
