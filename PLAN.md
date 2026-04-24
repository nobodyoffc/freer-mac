---
title: FreerForMac — Migration Plan
status: Phases 1 & 2 complete; Phase 3 (FCStorage) next
last_updated: 2026-04-24
---

# FreerForMac — Migration Plan

A fresh-start Swift/SwiftUI rewrite of the Android Freer cryptographic wallet + IM/mail suite. Target is a clean, idiomatic macOS-native app — not a line-by-line port.

## Decisions locked (2026-04-24)

| # | Decision |
|---|---|
| 1 | **Transport:** FUDP + FAPI only. **APIP is retired** and will not be ported. |
| 2 | **Blockchain parity target:** `freecashj`, which is a fork of bitcoinj (BitcoinCash branch, ~2019-11-15). Tx/Script serialization must be byte-identical to that fork. |
| 3 | **KDF:** Argon2id, `iterations = 3`, `memory = 65536 KiB (64 MiB)`, `parallelism = 1`, `derivedKeyLen = 32`. |
| 4 | **Mnemonic dropped.** No BIP39 on Mac (or Android going forward). Passphrase → Argon2id → 32-byte private key. |
| 5 | **Target:** macOS 14 Sonoma (`@Observable`, Swift 5.9+). |
| 6 | **Bundle ID:** `fc.freer.mac`. |
| 7 | **Signing:** Developer ID available; sign + notarize for distribution. |
| 8 | **Scope:** full feature parity with Android (wallet, keys, secret, multisig, tx, tools, qr, contact, im, mail). |
| 9 | **Phase ordering:** wallet first, IM second. |
| 10 | Android bugs are tracked in `<android-repo>/docs/android-issues-to-fix.md`; append as we find more. |

## Design principles

- **SwiftUI-first**, AppKit only for windowing/menus SwiftUI cannot express cleanly.
- **Swift Concurrency** (`async`/`await`, actors). No callbacks or `DispatchQueue.main.async` scattered in view models.
- **`@Observable` MVVM.** No app-wide singletons. The Android "Manager" pattern becomes per-identity scoped dependency containers, passed explicitly.
- **Per-identity isolation at the type level.** An `Identity` value owns its own storage handle, FUDP session, and services — the compiler prevents mixing identities' data.
- **`Codable` everywhere.** One JSON path. No Gson/Jackson dualism.
- **Zeroize secrets.** Passwords live in `Data` (or `UnsafeMutableBufferPointer<UInt8>`) and are explicitly zeroed after use. Never `String`.
- **No premature abstraction.** One concrete implementation per service until a second call site appears.

## Repository layout

```
FreerForMac/
├── FreerForMac.xcodeproj
├── FreerForMac/                     # app target (SwiftUI entry + views)
├── Packages/
│   ├── FCCore/                      # pure-Swift, testable
│   │   ├── Crypto/                  # AES, ChaCha20, ECDH, Argon2, HKDF, hashes
│   │   ├── Keys/                    # PrivateKey, PublicKey, Address, passphrase→key
│   │   ├── Encoding/                # Base58, Bech32, CashAddr, VarInt
│   │   ├── Script/                  # Script, ScriptBuilder, opcodes
│   │   └── Tx/                      # Transaction, TxHandler, UTXO select, signing
│   ├── FCTransport/                 # FUDP packet stack + FAPI message layer
│   ├── FCStorage/                   # Keychain + GRDB per-identity, encrypted blobs
│   ├── FCDomain/                    # Wallet, Keys, Secret, Contact, Multisig, IM, Mail
│   └── FCUI/                        # shared SwiftUI components (toolbar, QR, icons, dialogs)
├── Tests/
└── PLAN.md
```

Rationale: every `Packages/*` is a Swift package — the app target just composes them. Layers stay honest; unit tests run without launching the app.

## Dependencies (SwiftPM)

| Need | Package |
|---|---|
| AES-GCM, ChaCha20-Poly1305, SHA256, HMAC, HKDF | **`CryptoKit`** (stdlib) |
| AES-CBC, RIPEMD160 | **`CryptoSwift`** |
| secp256k1 ECDSA + Schnorr (BIP340) | **`swift-secp256k1`** (GigaBitcoin) |
| Argon2id | **`CatCrypto`** (or a thin wrapper around the reference C impl) |
| SQLite (type-safe) | **`GRDB.swift`** |
| Logging | **`swift-log`** |

No `WalletCore`, no Electron, no KMP. Small, explicit, auditable.

## Phases

Each phase ends with a runnable / testable artifact. Day estimates are working days for one engineer.

### Phase 0 — Scaffolding · 0.5d
- Create Xcode project at `/Users/liuchangyong/MacApp/FreerForMac`. Bundle ID `fc.freer.mac`. macOS 14 deployment target.
- Create the five local SwiftPM packages empty.
- Add SwiftLint config, `swift test` target, `.gitignore`.
- First commit.

### Phase 1 — `FCCore` crypto foundation · ✅ complete

All primitives are live in Swift and cross-verified byte-for-byte against Java-generated vectors produced by `tools/vector-gen/` (freecashj v0.16 + BouncyCastle). Commits 7738391 → 260843f.

| Primitive | Scheme | Parity |
|---|---|---|
| Hashes | SHA-256, double-SHA-256, RIPEMD-160, Hash-160 | byte-exact |
| KDF (password) | Argon2id (iter=3, mem=64 MiB, par=1, 32 B) | byte-exact |
| KDF (key) | HKDF-SHA256, HKDF-SHA512 | byte-exact |
| AEAD | AES-256-GCM, ChaCha20-Poly1305 | byte-exact |
| secp256k1 | pubkey derivation, ECDSA sign / verify, ECDH | byte-exact for ECDH + verify; ECDSA sign round-trips (libsecp256k1 and BouncyCastle disagree on RFC 6979 internals — either side verifies the other) |
| Schnorr (BCH-2019, pre-BIP-340) | sign / verify | byte-exact |
| Encoding | Base58, Base58Check | byte-exact |
| Passphrase → privkey | `.legacySha256` (for Android import) and `.argon2id` (recommended, fixed protocol salt `fc.freer.phrase.v1`) | byte-exact both |

**Not implemented — intentionally out of scope:**
- **CashAddr** — FCH does not use CashAddr. FCH addresses are Base58Check only.
- **Bech32 / SegWit** — not used by FCH at all.
- **AES-256-CBC + HMAC-SHA256 "Bundle" format** — Android's legacy wire format with known weaknesses (S6–S8 in the Android bug log). If peer-to-peer IM with Android users ever needs this format, it can be built on top of the existing AES-GCM + HKDF primitives.

**Golden tests are non-negotiable.** We feed the same inputs as Android and byte-compare outputs. No parity → no build.

### Phase 2 — `FCCore` tx layer · ✅ complete

Shipped as sub-phases 2.1 → 2.4, commits `1b0dc8c` → `9e41b4d`. The wallet can now build and sign FCH transactions entirely in Swift.

| Sub-phase | Deliverable | Parity status |
|---|---|---|
| 2.1 | `VarInt`, `FchAddress` (mainnet version byte `0x23`, Base58Check) | byte-exact vs bitcoinj's `VarInt` |
| 2.2 | `Script`, `ScriptBuilder` (P2PKH/P2SH/multisig outputs, P2PKH input) | byte-exact vs `org.bitcoinj.script.ScriptBuilder` |
| 2.3a | `Transaction`, classic pre-SegWit serialization, txid (natural + display) | byte-exact vs `tx.bitcoinSerialize()` |
| 2.3b | BCH sighash — BIP-143 preimage with `SIGHASH_FORKID` (`0x41`) | byte-exact vs freecashj's `hashForSignatureWitness` |
| 2.4 | `TxHandler.signP2pkhInput` — compose scriptCode / sighash / sign / scriptSig / replace | scriptSig-composition byte-exact given the same DER sig; Swift-signed txs verify under both libraries |

**Not implemented — pushed out of Phase 2, added when a caller needs them:**
- Coin selection + fee estimation (depend on a live UTXO set; belong in the domain layer).
- Multisig / P2SH *input* signing (structurally similar to P2PKH signing; uses the same sighash primitives).
- `SIGHASH_NONE` / `SIGHASH_SINGLE` / `SIGHASH_ANYONECANPAY` sighash variants (zero out different preimage fields; we reject them with a typed error until a real caller appears).
- Tx deserialization (parse tx hex → `Transaction`). We only build/serialize today; parsing lands when we need to inspect received txs.

### Phase 3 — `FCStorage` · 2d
- Keychain wrapper for: password-derived master key, per-identity private keys.
- `GRDB` database per identity at `~/Library/Application Support/FreerForMac/<fid>/db.sqlite` (sandboxed).
- Row-level encryption with AES-GCM using a Keychain-held key — cleaner than bundling SQLCipher.
- `KVStore` (single `kv` table via GRDB) replaces the dual Hawk + MMKV system from Android.
- Schema: `settings`, `keys`, `utxos`, `txs`, `contacts`, `secrets`, `mail`, `im_rooms`, `im_messages`.
- Fresh start — no migration from Android data.

### Phase 4 — `FCTransport` (FUDP + FAPI) · 8d · **highest risk**
Biggest single chunk of work. FUDP is a custom UDP protocol; byte-level parity with the Android reference is required for interop with existing servers.

- **Socket:** `Network.framework` `NWConnection` (UDP), not BSD sockets — gives us sane async semantics.
- **Packet crypto:** AES-GCM via CryptoKit; replay-protection window (port Android's logic exactly).
- **ECDH session setup:** handshake, session key derivation via HKDF.
- **Congestion control:** port Android's algorithm verbatim; document parameters in code.
- **Peer cache:** bounded LRU (fixes Android bug C1).
- **FAPI message layer** on top of FUDP — `RequestBody` equivalent as Codable structs.
- `ClientGroup` strategies: `first`, `anyValid`, `all`, `oneRandom`, `oneRoundRobin` via a `ClientStrategy` protocol.
- **Interop test:** point the Swift client at a live Android-spun FAPI server and round-trip a request.

Subphase budgets: handshake 2d, datagram + crypto 2d, congestion/retry 2d, FAPI layer 1d, interop harness 1d.

### Phase 5 — `FCDomain` services · 4d
- `IdentityService` — password verify → identity selection → session
- `WalletService`, `KeysService`, `SecretService`, `ContactService`, `MultisigService`, `ToolsService`
- Each initialised with `StorageHandle` + `FapiClient` — no global state
- Use cases = `async` functions returning typed results (`Result<T, DomainError>` or `throws`)

### Phase 6 — App shell + auth flow · 2d
- `@main App` with single window, sidebar + detail (`NavigationSplitView`)
- `PasswordView` (create/verify) → `ChooseIdentityView` → `HomeView`
- Auto-lock via `ScenePhase` (replaces Android `BackgroundTimeoutManager`)
- Menu bar, Dock badge, about panel

### Phase 7 — Wallet features · 6d
- `AccountView` — send / receive / expense / income / import / reorg (cash UTXOs)
- `TxView` — create / send / carve / show-JSON
- `MyKeysView` — random-new / create-by-phrase (**no mnemonic**) / find-nice (vanity)
- `MultisigView` — create-id / sign-tx / detail
- `QRView` — scan via `AVCaptureMetadataOutput`, display via `CIFilter.qrCodeGenerator`

### Phase 8 — Smaller features · 3d
- `ToolsView` — encrypt / decrypt / sign-msg / verify / totp / hash / random-bytes
- `SecretView` — create / view / delete / TOTP import
- `ContactView` — CRUD, ties into IM/mail
- `HomeView` extras — application / token / proof / protocol lifecycle (create / issue / destroy / close)

### Phase 9 — IM + Mail · 10d · **largest feature chunk**
- Rooms / Squares / Teams (matches Android `im/` structure)
- Message types: text, emoji, voice (via `AVAudioRecorder`/`AVAudioPlayer`), file share
- Message handlers, adapters, dock-style quick access
- Local encrypted storage via `FCStorage`
- `MailView` — list / read / send / delete
- End-to-end encryption via `FCCore` (AES-GCM + ECDH)

### Phase 10 — Packaging & polish · 2d
- App icon, menu bar, Dock behaviour
- Code signing (Developer ID) + notarisation (`xcrun notarytool`)
- `.dmg` via `create-dmg`
- Optional: `MetricKit` for crash reporting

## Total estimated effort

**~44 working days** for a single engineer (Phase 0 through 10).

Rough breakdown: Crypto 7d · FUDP 8d · Wallet UI 6d · IM/Mail 10d · Everything else 13d.

## Key risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | **FUDP parity.** Custom protocol; any byte-level drift breaks interop with existing servers. | Interop harness against a live Android-spun server as early acceptance test (end of Phase 4). |
| R2 | **Tx serialization parity** with freecashj (BCH 2019-11-15 fork). Sighash quirks, BIP143-style preimage details. | Parity harness with captured tx hex fixtures (end of Phase 2). Do not advance to Phase 3 until it is green. |
| R3 | **Schnorr compatibility.** freecashj's Schnorr may predate BIP340 finalization and use non-standard R/tags. | Inspect freecashj source, mirror exactly. Add vectors from a freecashj-signed fixture set. |
| R4 | **macOS sandbox entitlements** — Keychain, camera (QR), microphone (voice msg), network-client, file-access for downloads. | List entitlements up front in Phase 0; add `.entitlements` file; test each in its feature's phase. |
| R5 | **Argon2 Swift library maturity.** Pure-Swift Argon2 implementations are rare. | Use `CatCrypto` (wraps reference C impl) or bundle `argon2` as a SwiftPM system target. Bench on target hardware. |
| R6 | **Single-engineer scope.** ~44 days is long; priorities may shift mid-flight. | Each phase produces a runnable artifact; pause-points are natural if scope trimming is needed. |

## Not doing (explicit non-goals)

- No APIP client (retired).
- No BIP39 mnemonic (retired).
- No SQLCipher (row-level AES-GCM instead).
- No CocoaPods (SwiftPM only).
- No cross-platform UI framework (no Catalyst, no Electron, no Flutter).
- No analytics, no telemetry, no auto-update (yet).

## How we'll work

- **Android bug log** lives in `<android-repo>/docs/android-issues-to-fix.md`. Every time we find something during the port, we append an entry. You fix the Android side at your own pace.
- **One phase at a time.** No phase starts until the previous phase's acceptance test (golden/parity/interop harness where applicable) is green.
- **Plan changes are logged here.** Any deviation from this document is updated in-place with a note in `last_updated`.
