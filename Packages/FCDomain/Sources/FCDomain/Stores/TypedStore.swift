import Foundation
import FCStorage

/// A typed, namespaced view over an ``EncryptedKVStore``. Domain stores
/// (`SettingsStore`, `ContactsStore`, `KeysStore`, …) are thin wrappers
/// around one of these — they pin the namespace and `Value` type and add
/// domain-flavored method names.
///
/// Why namespaces: each identity gets one SQLite file shared across all
/// concerns, and ``EncryptedKVStore``'s `(namespace, key)` primary key
/// keeps them from colliding. Splitting one DB per concern would
/// multiply the Keychain entries and the AAD-binding work without
/// buying anything.
public struct TypedStore<Value: Codable> {

    public let kv: EncryptedKVStore
    public let namespace: String

    public init(kv: EncryptedKVStore, namespace: String) {
        self.kv = kv
        self.namespace = namespace
    }

    public func put(_ value: Value, key: String) throws {
        try kv.put(value, namespace: namespace, key: key)
    }

    public func get(_ key: String) throws -> Value? {
        try kv.get(Value.self, namespace: namespace, key: key)
    }

    public func delete(_ key: String) throws {
        try kv.delete(namespace: namespace, key: key)
    }

    public func exists(_ key: String) throws -> Bool {
        try kv.exists(namespace: namespace, key: key)
    }

    /// Sorted ascending by key (the underlying store enforces it).
    public func keys() throws -> [String] {
        try kv.listKeys(namespace: namespace)
    }

    /// Read-modify-write one row inside a single transaction — see
    /// ``EncryptedKVStore/mutate(_:namespace:key:_:)``, whose warning
    /// about not touching the store from inside `change` applies here
    /// too.
    @discardableResult
    public func mutate(_ key: String, _ change: (Value?) throws -> Value?) throws -> Value? {
        try kv.mutate(Value.self, namespace: namespace, key: key, change)
    }

    /// This store's ``put(_:key:)``, as a change to be committed with
    /// others — see ``EncryptedKVStore/write(_:)``.
    public func change(putting value: Value, key: String) -> EncryptedKVStore.Change {
        .put(namespace: namespace, key: key, value: value)
    }

    /// This store's ``delete(_:)``, as a change to be committed with
    /// others.
    public func change(deleting key: String) -> EncryptedKVStore.Change {
        .delete(namespace: namespace, key: key)
    }

    /// Eagerly load every row in the namespace. Fine for small,
    /// human-scale collections (contacts, pinned services). Don't use
    /// for unbounded sets like message history — page those manually.
    public func all() throws -> [(key: String, value: Value)] {
        try keys().compactMap { k in
            guard let v = try get(k) else { return nil }
            return (k, v)
        }
    }
}
