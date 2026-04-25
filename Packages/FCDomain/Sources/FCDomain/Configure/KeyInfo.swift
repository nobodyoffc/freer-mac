import Foundation
import FCCore

/// What kind of FID this key represents inside a Setting. Mirrors
/// the Android `FidType` enum, but unified into a single field on
/// ``KeyInfo`` instead of three parallel arrays
/// (`watchedFidList` / `multisigFidList` / `servantFidList`).
public enum KeyKind: String, Codable, Sendable, CaseIterable {
    /// A main FID — has a privkey and operates on its own behalf.
    /// Stored both inside its own Setting's `keyInfoMap` and in the
    /// parent Configure's `mainCidInfoMap`.
    case main

    /// Watch-only FID. No privkey. Can read FAPI data and prepare
    /// unsigned tx for cold signing; cannot sign or decrypt.
    case watched

    /// Multisig group this main FID is a member of. (Phase 5.7 stores
    /// the FID + label only; signing flow lands later.)
    case multisig

    /// Delegated FID acting on behalf of the main. (Same — schema
    /// only in Phase 5.7.)
    case servant

    /// Whether operations needing a private key (sign tx, decrypt
    /// IM, FAPI sender auth) can run for this kind.
    public var canSign: Bool {
        switch self {
        case .main, .servant: return true
        case .watched, .multisig: return false
        }
    }
}

/// Encrypted private key. Same wire shape as one row of
/// ``EncryptedKVStore`` — `nonce(12) ‖ ciphertext(32) ‖ tag(16)` —
/// stored as three separate base64-friendly `Data` fields so JSON
/// inspection is bearable. The ciphertext encrypts the raw 32-byte
/// privkey under the parent Configure's symkey.
public struct PrikeyCipher: Codable, Equatable, Hashable, Sendable {
    public var iv: Data           // 12 B
    public var ciphertext: Data   // 32 B
    public var tag: Data          // 16 B

    public init(iv: Data, ciphertext: Data, tag: Data) {
        self.iv = iv
        self.ciphertext = ciphertext
        self.tag = tag
    }
}

/// A single key in the Freer model. Either a main FID (with
/// privkey, encrypted under the Configure symkey) or a sub-identity
/// of one (no privkey).
///
/// Merges the Android `KeyInfo` shape with the Mac improvements:
///   - `kind` replaces the parallel `watchedFidList`/`multisigFidList`/
///     `servantFidList` arrays in `Setting`
///   - `pubkey` is `Data` (33 B compressed), not hex string
///   - `master`, `label` kept as in Android
public struct KeyInfo: Codable, Equatable, Hashable, Sendable {
    public var fid: String
    public var pubkey: Data?            // 33 B SEC1 compressed; nil for some watch-only entries
    public var prikeyCipher: PrikeyCipher?
    public var label: String
    public var kind: KeyKind
    public var master: String?
    public var savedAt: Date

    public init(
        fid: String,
        pubkey: Data? = nil,
        prikeyCipher: PrikeyCipher? = nil,
        label: String = "",
        kind: KeyKind = .main,
        master: String? = nil,
        savedAt: Date = Date()
    ) {
        self.fid = fid
        self.pubkey = pubkey
        self.prikeyCipher = prikeyCipher
        self.label = label
        self.kind = kind
        self.master = master
        self.savedAt = savedAt
    }

    /// Whether this key has a privkey we can decrypt. Watch-only keys
    /// always return false.
    public var hasPrivkey: Bool { prikeyCipher != nil }

    /// Build a KeyInfo from a fresh raw privkey: derives pubkey + FID,
    /// encrypts the privkey under `symkey`. Caller decides `kind`/`label`.
    public static func make(
        fromPrivkey privkey: Data,
        symkey: Data,
        label: String = "",
        kind: KeyKind = .main,
        master: String? = nil
    ) throws -> KeyInfo {
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        let fid = try FchAddress(publicKey: pubkey).fid
        let cipher = try Self.encryptPrikey(privkey, symkey: symkey)
        return KeyInfo(
            fid: fid, pubkey: pubkey, prikeyCipher: cipher,
            label: label, kind: kind, master: master
        )
    }

    /// Decrypt the stored privkey under `symkey`. Throws if this is
    /// a watch-only key (no cipher) or the symkey is wrong.
    public func decryptPrikey(symkey: Data) throws -> Data {
        guard let c = prikeyCipher else {
            throw Failure.watchOnly(fid: fid)
        }
        do {
            return try AesGcm256.open(
                key: symkey, nonce: c.iv,
                ciphertext: c.ciphertext, tag: c.tag,
                aad: Data(fid.utf8)
            )
        } catch {
            throw Failure.decryptionFailed
        }
    }

    public enum Failure: Error, CustomStringConvertible {
        case watchOnly(fid: String)
        case decryptionFailed

        public var description: String {
            switch self {
            case .watchOnly(let fid): return "KeyInfo: \(fid) is watch-only — no privkey to decrypt"
            case .decryptionFailed:   return "KeyInfo: privkey decryption failed (wrong symkey?)"
            }
        }
    }

    private static func encryptPrikey(_ privkey: Data, symkey: Data) throws -> PrikeyCipher {
        precondition(privkey.count == 32, "privkey must be 32 bytes")
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        let fid = try FchAddress(publicKey: pubkey).fid
        var iv = Data(count: 12)
        let status = iv.withUnsafeMutableBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, 12, base)
        }
        guard status == errSecSuccess else {
            throw Failure.decryptionFailed   // best-effort error reuse; entropy unavailable is rare
        }
        let sealed = try AesGcm256.seal(
            key: symkey, nonce: iv,
            plaintext: privkey, aad: Data(fid.utf8)
        )
        return PrikeyCipher(iv: iv, ciphertext: sealed.ciphertext, tag: sealed.tag)
    }
}
