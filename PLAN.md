---
title: FreerForMac — Migration Plan
status: Phases 1–7 complete; Phase 8 at 8.4.2 — FUDP large-payload streaming (8.4.1) and the DISK `FileCipher` with byte-parity against the real FC-AJDK encryptor (8.4.2) shipped; next is 8.4.3 (`Hat` + `HatsStore`); 8.3 (application/token/proof/protocol lifecycle) still pending.
last_updated: 2026-08-13
---

> **▶ Phase 8.4.2 (2026-08-13).** `FileCipher` — the FAPI DISK cipher-file format, byte-identical to FC-AJDK. **Format** (verified by running the real `Encryptor.encryptFileBySymkey`, not inferred): UTF-8 JSON header `{"type":"Symkey","alg":"AesGcm256@No1_NrC7","iv":"<24 hex>"}` (Gson field order = `CryptoDataStr` declaration order, nulls omitted, 76 B) immediately followed by AES-256-GCM `ciphertext ‖ 16 B tag` — **one GCM pass over the whole file**, 12 B iv, 128-bit tag. No `cipher` field, no `sum` (skipped for AEAD), no `keyName` (the file path never calls `makeKeyName`). **The header has no length prefix**: the Java reader (`JsonUtils.readOneJsonFromInputStream`) finds its end by *counting braces* and is not JSON-string-aware, so `FileCipher.headerLength` reproduces that algorithm exactly rather than parsing properly — agreeing with the producer on where ciphertext starts beats being correct in the abstract. Its backslash branch is a no-op (`\` is never a brace), and all four edge cases (normal, `}`-in-string → truncated 7 B header, `{`-in-string → no header found, nested objects) were checked against the real Java reader and match. **FCCore:** `FileCipher.{encrypt,decrypt,parseHeader,headerLength,headerJson,randomIv,randomSymkey}` + `Hash.doubleSha256(fileAt:)` (added in 8.4.1). GCM is one-shot on both sides, so the body is held once in memory; input is mmap'd to keep peak at ~one file. **Vector generation is no longer a re-implementation:** `tools/vector-gen` now compiles the REAL FC-AJDK `Encryptor`/`Decryptor` on a plain JVM (only 20 of its 324 files touch Android, none on the cipher path) — a `compileFcAjdk` task feeds javac the 3 entry points and lets `-sourcepath` pull the ~77-class closure, with `src/androidstubs/java` first on that path so its `TimberLogger` shadows FC-AJDK's (which drags in `android.util.Log`). 5 vectors (empty / ascii / multibyte UTF-8 / block-aligned / 5 000 B), each round-tripped through FC-AJDK's own decryptor before being emitted. Regeneration left every pre-existing vector byte-identical. Tests: 17, incl. Swift-encrypt == Java bytes, Swift decrypts Java files, header/Gson parity, tamper + wrong-key + truncation + non-cipher-file rejection. Reverse direction verified once by hand: Java decrypted a Swift-encrypted 20 023 B file (random key, multibyte tail) exactly.
>
> **▶ Phase 8.4.1 (2026-08-13).** FUDP large-payload streaming — the transport prerequisite for HAT/DISK file transfer. **FCTransport/Connection:** `RttEstimator` (EWMA, Java integer-math parity incl. rounding terms), `CongestionControl` (CUBIC in MSS units per RFC 8312, slow-start/avoidance/recovery, Reno floor, per-ACK growth cap), `SentPacketTracker` (loss detection: SACK-style gap threshold — adaptive 6→64 on spurious loss, RACK-style — + timeout backstop `clamp(2·sRTT+4·rttvar, 2 s, 4 s)` with per-retransmit exponential backoff; gap loss is the only congestion signal per RFC 9002), `AckGenerator` (every frame re-advertises all packet numbers retained 4 s so a lost ACK is survivable; incrementally-sorted storage — per-ACK re-sorting had capped throughput at ~475 KB/s), `TransferMachinery` (bundles the four + QUIC-style pacing at 1.25·cwnd/sRTT, 10 KB/s floor), `InboundMailbox` (replaces the AsyncStream hand-off: cancelling a consumer suspended on an AsyncStream iterator *terminates the stream*, which the timeout-sliced idle-refresh waits would do on their first slice), `QuietClock` (non-throwing sleeps so background-loop cancellation can't pollute error-trace hooks). **FudpClient:** receive pump task (decrypt → ACK processing → immediate ACK generation ACK_THRESHOLD=1 → stream reassembly; `InboundStreamBuffer` spills streams > 8 MB to a temp file and assembles them file-mapped), outbound fragmentation for any message > 1 chunk (cwnd-gated, paced, fin-on-last), `sendMessageStreaming` (envelope prefix + `FileHandle` reads — a file is never resident), retransmit loop (50 ms cadence, 50 pkt + pacer-budget caps, abandon after 60 attempts), retired-stream set against duplicate delivery. **F2 ECDH LRU cache** in `AsyTwoWay` (0.8 ms → 0.03 ms per seal+open pair). **Copy-free decode**: `AppMessageCodec`/`ResponseMessage`/`UnifiedCodec` now slice (`Data` CoW) instead of materialising `[UInt8]` — a mapped 100 MB download stays file-backed through every layer. **FapiClient:** `callUploadingFile` (streaming sha256x2 dataHash via new `Hash.doubleSha256(fileAt:)`, 2-pass, idle-refreshed timeout base+1 s/100 KB), `callDownloadingToFile` (binary slice → chunked write to output URL, cumulative progress). Tests: 23 unit (EWMA/CUBIC/ACK-ranges/loss-detection/spill) + 4 loopback integration over an injected `DatagramTransport` fake (in-process FUDP server: 100 KB round-trip, ~9 % simulated loss recovered via gap detection, 300 KB FAPI file upload hash-verified, 9 MB download through spill→mmap→slice→file in ~1 s).
>
> **▶ Phase 8.2 (2026-08-12).** Secrets — the Mac port of Android's `secret/` + `TotpActivity`. **FCDomain:** `Secret` model (Pattern B: plaintext `content` never persisted; at rest only `contentCipher` = AsyOneWay envelope to the owner's own pubkey; local id = `sha256x2(detailJson)` per `checkIdWithCreate`, carved id = the carve txid), `SecretsStore` (`secrets.v1`, keyed by id), `SecretFeip` (FEIP sn 17 ver 3 "Secret"; add `{op,cipher}` / update `{op,secretId,cipher}` / delete + recover `{op,secretIds}`; detail plaintext `{type,title,content,memo}` nil-omitted), `SecretService.syncOnChainSecrets` (pages `base.search` entity `secret`, `query.terms owner==fid`, active+inactive, sort `lastHeight desc, id desc`; decrypts each `cipher`, **re-encrypts content to own pubkey** as `contentCipher`, merges newest-first by record id; newest-carve-inactive → chain-sourced local row removed, local-only rows survive), `ActiveSession.{secrets, secretService, carveSecretOnChain (add vs update by carveId), carveSecretDeleteOnChain}`. **UI:** `SecretsView` pane, two tabs — Secrets (create / reveal-with-eye via on-demand privkey decrypt / carve / delete with the local-vs-on-chain alert, auto-sync on appear + Refresh) and **TOTP** (authenticator cards: decrypt Base32 seed once, 6-digit codes on a 1 s tick with 30 s countdown, eye toggle, click-to-copy); `SecretEditorSheet` (type picker, TOTP Base32 validation + random-seed generator, Save-locally / Save-&-carve; carve re-keys the row to the txid like Android's `secret.setId(txId)`). Watch-only identities: everything gated (no decrypt, no carve, hints throughout).
>
> **▶ Phase 8.1 (2026-08-12).** Tools pane — the Mac port of Android's `tools/` activities (`Encrypt/Decrypt/SignMsg/Verify/Hash/RandomBytesGenerator`). **FCCore:** `Base32` (RFC 4648 unpadded, Java-parity), `Totp` (RFC 6238 HMAC-SHA1/30 s, RFC vectors), `Hash.{md5,sha1,hmacSha256,hmacSha1,keccak256}` (`Keccak256` is a pure-Swift Keccak-f[1600] sponge — the Java "sha3" is BouncyCastle Keccak-256, *not* NIST SHA3), `SignedMessage` (bitcoinj `signMessage`/`signedMessageToKey`: varint-framed `"Bitcoin Signed Message:\n"` magic → sha256x2 → recoverable compact sig via P256K Recovery, header 27+recId+4; **byte-identical to freecashj v0.16** — vectors generated via jshell against the cached jar). **FCDomain:** `MsgSignature` (Java `Signature` ShortSign JSON: fid/keyName/msg/sign/alg-displayName; ECDSA + Schnorr(`base64(pub33‖sig64)` over sha256x2) + HMAC-SHA256 symkey with legacy `sha256x2(msg‖key)` verify fallback; accepts the long-form `address/message/signature/algorithm` aliases; missing alg defaults ECDSA), `TextCipher` (Password/Symkey CryptoDataStr envelopes: AES-256-GCM, password kdf = Argon2id salt=iv stamped `Argon2id@No1_NrC7`, decrypt honors the stamp and falls back Argon2id→legacy `sha256(sha256(pwd)‖iv)` when unstamped, CBC decrypt via the AsyOneWay `cbcOpen`; pubkey mode delegates to `AsyOneWayCipher`). **UI:** `ToolsView` pane (sidebar → Tools) with six segmented sub-tools; Decrypt defaults to the live privkey for Asy ciphers (watch-only aware); Sign gates ECDSA/Schnorr on `canSign`; Hash offers file hashing and treat-as-hex; Random emits hex/Base58/Base32/decimal-integer. Android bug C6 logged: its SHA3 branch hashes the hex *string* of the input, not the bytes. TOTP UI deferred to 8.2 where the Secret store lives.
>
> **▶ Phase 7.6.3 (2026-07-05).** On-chain contact **carve** — the write path mirroring Android's `sendContactOnChain → makeAddContactFeip → TxSender.carveSimpleFeip`. New pieces: `ScriptBuilder.opReturnOutput` (OP_RETURN + canonical pushdata, bitcoinj parity); `AsyOneWayCipher.encrypt` (ephemeral secp256k1 key per call, random 12 B iv, ECDH→HKDF-SHA512(salt=iv, info "hkdf")→AES-256-GCM, emits the CryptoDataStr JSON envelope `{type,alg,cipher,pubkeyA,iv}` — no `sum` for GCM, like the Java encryptor); `ContactFeip` builders (envelope `{"type":"FEIP","sn":"12","ver":"3","name":"Contact","data":…}`, add/update/delete/recover ops, detail plaintext); `CoinSelector.selectForCarve` (no recipient output, opReturn size via Java `calcOpReturnLen`, CoinDays accumulation — carves need 1 CD past height 4 000 000, waived below like Android); `TxBuilder.buildUnsignedCarve` (change first, zero-value OP_RETURN last); `WalletService.carve` (send-pipeline reuse: refresh→filter→select→build→Schnorr-sign→broadcast→optimistic cache update). `ActiveSession.carveContactOnChain` picks `add` vs `update` by the stored `carveId`; `carveContactDeleteOnChain` carves `delete` by carve ids. **Sync deletion cleanup** (the 7.6.2b gap): fetch now includes inactive records (Android's refresh `active=null`); a FID whose newest carve is `active==false` gets its chain-sourced local row removed (local-only rows survive); `carveId` captured on merge. UI: per-row Carve button (confirmation alert, copyable txid banner), delete alert gains "Delete locally + on-chain" when a carveId is known — a purely local delete of an on-chain contact would otherwise resurrect on the next sync.

> **▶ Phase 7.6.2b (2026-06-12).** On-chain contact **sync** — the missing read path that left the Contacts pane empty for accounts whose contacts live on-chain (Android's `ContactActivity.loadInitialData → ContactManager.refreshContactsFromAPI`). New `DirectoryService.syncOnChainContacts(owner:privkey:into:)`: pages `base.search` on `entity:"contact"` (`query.terms active=="true"` + `query.equals owner==fid`, sort `lastHeight desc, id desc`, cursor `after`), decrypts each record's `cipher` — a CryptoDataStr JSON envelope, `type:AsyOneWay`, `alg:"EccK1AesGcm256@No1_NrC7"`: sharedSecret = ECDH(privkey, pubkeyA).x → symkey = HKDF-SHA512(ikm=secret, salt=iv, info="hkdf", 32 B) → AES-256-GCM (12 B iv, tag appended to base64 `cipher`) — then enriches all decrypted FIDs in one `freerByIds` round-trip and upserts into `ContactsStore` (on-chain detail wins; `pinnedAt`/`addedAt` preserved; duplicate carves of one FID resolved newest-`lastHeight`-first; undecryptable records counted + skipped, since without plaintext the FID is unknown). ContactsView auto-syncs on first appear and gained a Refresh button (disabled for watch-only); sync errors render as a non-fatal copyable banner over the local rows. Legacy CBC cipher algs are explicitly unsupported.
>
> **▶ Phase 7.6.2 (2026-05-05).** New `DirectoryService` with `freerByIds(_:)` wired to `base.freerByIds` (FCDSL `{"ids":[fid…]}`, response `data` decoded as `[String: Freer]`), exposed via `ActiveSession.directory`. `Freer` is the wire-level Codable mirror of the Java `Freer extends FcSubject extends FcEntity`; `Contact.merging(_ freer:)` overwrites the on-chain block and bumps `onChain = true` while preserving local detail (titles/memo/seeStatement/seeWritings/pinnedAt/addedAt). The editor sheet has a **Look up** button next to FID that fetches the on-chain record, auto-fills CID, and shows a status panel (pubkey · balance · last block · cdd). Off-chain (server returns 404 / empty) and connectivity errors render distinct hints — the contact still saves locally regardless.
>
> **▶ Phase 7.6.1 (2026-05-05).** Contacts pane live with the Android-aligned `Contact` schema (`id` = FID, optional `cid` / `pubkey` / on-chain stats / cross-chain addresses / `multisig`, plus the editable detail block: `titles` / `memo` / `seeStatement` / `seeWritings`). `name = cid ?? id` mirrors the Java rule. The pane lists rows with 40 px `FidAvatarView` + name + middle-elided FID + comma-joined titles + truncated memo, supports search across all four, plus pin/edit/delete. Editor sheet exposes only the locally-editable fields — `cid`/`pubkey` will be auto-filled by FAPI `freer.byIds` (7.6.2, deferred). Store namespace bumped to `contacts.v2` so the alpha-era schema doesn't trip decode errors.
>
> **▶ Phase 7.5 closed (2026-05-01).** Transactions pane is live with All / Incomes / Expenses tabs, per-tx grouping in `.all`, flat per-cash rendering in Incomes/Expenses (rows lead with a 40 px FidAvatarView for the counterparty), pagination, auto-refresh on appear, and middle-elided IDs throughout (head + … + tail, never `prefix(N)`). Send works end-to-end on mainnet with BCH-Schnorr signatures (~10 ms/sig via libsecp256k1). Cash cache uses Pattern A incremental sync with a `lastHeight` watermark; Transactions pane uses Pattern C cursor-paginated cache split per-kind (all/incomes/expenses).
>
> **▶ Phase 4 resumed (2026-04-25).** FUDP v2 repairs (F1 header AAD, F2 LRU ECDH cache, F3 60 s replay tolerance, F5 explicit frame lengths) shipped on the Linux side at `FC-JDK/src/main/java/fudp/`. Wire-format version stayed at `1` (no third-party ecosystem to negotiate with). New DDoS layer (`security/{ProofOfWork,IpVerifier,ChallengeHandler,TokenBucket,DecryptRateLimiter,DDoSConfig}`) added beyond the v2 plan; Mac client implements the *initiator* side of it from day 1 so it works against DDoS-enabled servers out of the box.


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

### Phase 3 — `FCStorage` · ✅ complete

Shipped as 3.1 + 3.2, commits `3879ecb` → `4fdf5ef`.

| Sub-phase | Deliverable |
|---|---|
| 3.1 | `Keychain` — typed wrapper around `Security.framework` generic-password items, `whenUnlockedThisDeviceOnly`, service+account scoped. |
| 3.2 | `EncryptedKVStore` — GRDB-backed SQLite with row-level AES-256-GCM. Vault key generated on first open, held in Keychain. AAD-bound to `(namespace, key)`. |

**Deferred:** typed domain stores (Settings/Keys/UTXOs/Contacts/Secrets/Mail/IM). The `EncryptedKVStore` is already generic enough that each typed wrapper is ~20 lines — they land in Phase 5 (FCDomain) alongside the services that use them, when we have the use-case surface to design the models against.

### Phase 4 — `FCTransport` (FUDP + FAPI) · ~7d · in progress

Reference implementation lives at `FC-JDK/src/main/java/fudp/` (post-repair). Sub-phases:

| # | Scope | Estimate |
|---|---|---|
| 4.1 | Wire primitives — PacketHeader (21 B), Frame base + Stream/Ack/Padding etc., Packet ser/deser, byte-parity vectors. | 1.5d |
| 4.2 | Packet crypto — AsyTwoWay bundle (`algId+type+33B pubkey+12B IV+ct+tag`), **F1 header-as-AAD**, session epoch, LRU ECDH cache (cap 512). | 1d |
| 4.3 | Replay protection — 65 536-packet sliding window, 4 096-connection LRU, 60 s tolerance, session-epoch restart detection. | 0.5d |
| 4.4 | UDP socket + ConnectionManager — `NWConnection` UDP, peer state machine, receive loop, port the per-source `DecryptRateLimiter`. | 1.5d |
| 4.5 | DDoS client (initiator side) — `ProofOfWork` solver (SHA-256 grind), `ChallengeHandler` with timeout/difficulty caps, plaintext CHALLENGE / CHALLENGE_RESPONSE control packets. | 1d |
| 4.6 | FAPI message layer — Request / Response / Ping / Pong / Notify / Error codecs, ID-based correlation, timeout + retry. | 1d |
| 4.7 | Swift self-interop — toy echo server in `tools/`, full client↔server round-trip exercising the state machine. | 0.5d |
| 4.8 | Live FC-JDK interop — final validator against a running Linux server. Deferred until 4.7 is green. | TBD |

**The original Phase 4 outline below is preserved for reference but is superseded by the table above.**

- **Socket:** `Network.framework` `NWConnection` (UDP), not BSD sockets — gives us sane async semantics.
- **Packet crypto:** AES-GCM via CryptoKit; replay-protection window (port Android's logic exactly).
- **ECDH session setup:** handshake, session key derivation via HKDF.
- **Congestion control:** port Android's algorithm verbatim; document parameters in code.
- **Peer cache:** bounded LRU (fixes Android bug C1).
- **FAPI message layer** on top of FUDP — `RequestBody` equivalent as Codable structs.
- `ClientGroup` strategies: `first`, `anyValid`, `all`, `oneRandom`, `oneRoundRobin` via a `ClientStrategy` protocol.
- **Interop test:** point the Swift client at a live Android-spun FAPI server and round-trip a request.

Subphase budgets: handshake 2d, datagram + crypto 2d, congestion/retry 2d, FAPI layer 1d, interop harness 1d.

### Phase 5 — `FCDomain` services · 4d · in progress

| # | Scope | Status |
|---|---|---|
| 5.1 | Identity lifecycle — `IdentityRecord`/`IdentityIndex`, `Identity` (active session, lockable), `IdentityVault` (register/login/logout/delete). Vault key derived from privkey via HKDF — never persisted, so a stolen disk reveals nothing without the passphrase. Added a `vaultKey:`-direct `EncryptedKVStore` initializer. | ✅ |
| 5.2 | Typed stores — `TypedStore<Value>` generic + `SettingsStore` (single-row prefs), `ContactsStore` (FID address book), `KeysStore` (cached pubkey-for-FID with on-insert FID/pubkey validation). | ✅ |
| 5.3 | FAPI message layer + `FapiClient` — `UnifiedCodec` (4B BE headerLen + JSON + optional binary), `FapiRequest`/`FapiResponse` mirroring the Java fields, `FudpClient.receive(matching:)` helper, `FapiClient.call()` with two-level (transport `messageId` + app `id`/`requestId`) correlation. Retired the obsolete `RequestMessage`/`ResponseMessage` `sid+data` stub. | ✅ |
| 5.4 | `WalletService` (read path) — `FapiCalling` protocol (so domain services can be unit-tested with a stub), `Utxo`/`Balance`/`UtxoSnapshot` Codable models, `UtxosStore` per-identity cache, `WalletService.{health, balance(forFid:), balances(forFids:), refreshUtxos(forAddress:)}`. Send/coin-selection split out to 5.5. | ✅ |
| 5.5 | `WalletService` (send path) — `CoinSelector` (greedy largest-first, iterative fee re-estimation, dust handling), `TxBuilder` (display-txid → natural-order prevTxHash, P2PKH output script construction), `WalletService.send(from:to:amount:)` orchestrator that refreshes UTXOs, selects, builds, signs every input via `FCCore.TxHandler`, and broadcasts via `base.broadcastTx`. | ✅ |
| 5.6 | Composition + polish — `IdentitySession` (per-identity service container; lazy-instantiates Settings/Contacts/Keys/Utxos/WalletService over a single `Identity` + `FapiCalling`, locks chain through). FID validation in `ContactsStore.upsert` so malformed strings can't reach the tx builder. `SecretsStore`/`SecretService` deferred to Phase 8 where the UI lives. | ✅ (superseded by 5.7) |
| 5.7 | **Identity model rework.** Replaces the broken passphrase-derives-privkey assumption with the Android-Freer model: many `Configures` (one per password) → many main FIDs per Configure → many sub-identities per main. Added `WifPrivkey`/`EncryptedFile` primitives, `Configure`/`Setting`/`KeyInfo`/`KeyKind`/`PrikeyCipher` data types, `ConfigureManager` (list/create/open/delete) + `ConfigureSession` (listMains/addMain/lock/unlockMain), and `ActiveSession` (per-main runtime: liveFid, switching, watch-only refusal, lazy stores, `sendFromLive`). Per-main HKDF-derived sqlite vault keys give cross-main row isolation under the same symkey. Old `Identity*`/`IdentityVault`/`IdentitySession` deleted; the SwiftUI app shell is currently a placeholder pending 5.7d. | ✅ |
| 5.7d | Auth flow UI — `WelcomeView` (no Configures) → `PasswordView` (single field, derives `passwordName` live, branches between unlock-existing and create-new), `ChooseMainView`, `AddMainView` (random / hex / WIF / passphrase, schemes for each), `HomeView` with live-FID switcher menu and "switch identity" / "lock vault" buttons. ⌘L locks via the App menu. **State-leakage cleanup**: PasswordView later reworked to show the same UI regardless of whether vaults exist — single field, two explicit buttons, generic errors, no live `passwordName` hint. SwiftPM-binary activation policy fixed so SecureField gets first responder. | ✅ |
| 5.8 | Avatar module — `AvatarMaker` (deterministic 150×150 composite of 10 layers chosen from positions 20–29 of the FID via the Base58 alphabet, mirroring `FC-AJDK/feature/avatar/AvatarMaker.java`), 580 PNG assets bundled into `FCUI.Resources/avatar-elements/<layer>/<element>.png`, `FidAvatarView` SwiftUI wrapper with circular clip + SF-symbol fallback, `NSCache` of last 64 renders. Wired into `ChooseMainView` (44 px) and `HomeView` (56 px with a can-sign / watch-only corner badge). | ✅ |

**Design notes:**
- Per-identity isolation enforced at the type level: every domain service takes an `Identity` and pulls its `EncryptedKVStore` from there. No global "current identity" singleton.
- Use cases = `async` functions returning typed results (`throws` rather than `Result<T,E>` — Swift's typed-throws still requires opt-in and Result fights `try`).
- Each store namespaces its keys (`settings:*`, `keys:*`, `contacts:*`) inside the shared per-identity `EncryptedKVStore` — one DB per identity, not one per concern.

**Cache architecture (Three Patterns).** FCH's `lastHeight` is on every chain entity — every cache becomes incremental.

| Pattern | Shape | Sync | Used for |
|---|---|---|---|
| **A** | Watermark-synced collection by `lastHeight` | Bootstrap once, then `lastHeight > localMax − 30` (reorg window) | `CashesStore` (the wallet's spendable cash set) |
| **B** | Cipher-always-stored + plaintext decryption overlay | Cipher rows persist; plaintext lives only in memory under the symkey | Reserved for future per-main encrypted artifacts |
| **C** | Cursor-paginated stream blob | Append on next-cursor, replace on filter change | `RecentActivityStore` (Transactions pane, key per-kind: all / incomes / expenses) |

**Wire / consensus gotchas worth not relearning:**
- **P2PKH spends require BCH-Schnorr.** ECDSA-DER is rejected by mainnet with the misleading error `Signature cannot be 65 bytes in CHECKMULTISIG`.
- **FCDSL `query` vs `filter`.** Both are separate fields on the POJO. `base.search` consumes `query` via `queryExecutor.executeQuery`; `base.cashValid` mode-1 reaches for `filter`. Mixing them up causes silent timeouts.
- **FUDP STREAM frames must be reassembled.** Responses ≥ ~1 KB span multiple STREAM frames sharing a `streamId`, with `offset` and `fin` only on the last. Decoding each as a complete AppMessage corrupts the receiver's state and breaks every call after the big one.
- **Bootstrap fallback:** `base.cashValid` mode-2 (`params: {fid}`) is the known-working bootstrap. Incremental `base.search` is fail-soft — on any error it falls back to mode-2.

**UX rules locked in (saved as feedback memory):**
- Every FID and every toast/error is click-to-copy with a green-checkmark flash (`CopyableText` in FCUI).
- Every truncated ID renders middle-elided: `head + "…" + tail`, never `prefix(N)`. Use `String.elidingMiddle` or `CopyableText.elidingMiddle`.

### Phase 6 — App shell + auth flow · 2d · ✅ complete

| # | Scope | Status |
|---|---|---|
| 6.1 | Auth flow scaffold — `AppState` (@Observable, owns vault + session + route), `AppRouter`, `WelcomeView` / `CreateIdentityView` / `ChooseIdentityView` / `UnlockView` / `HomeView` placeholder. Argon2id runs on a background `Task.detached` so the UI stays responsive during ~300 ms KDF. ⌘L lock + menu-bar entry. | ✅ |
| 6.2 | Real `FapiClient` factory in `AppState` (replacing `StubFapiClient`). WIF / hex / passphrase import paths in `AddMainView` (5.7d). | ✅ |
| 6.3 | Auto-lock via `ScenePhase`, About panel polish, Dock badge. | deferred to Phase 10 |

### Phase 7 — Wallet features · 6d · in progress

| # | Scope | Status |
|---|---|---|
| 7.1 | Sidebar-driven nav scaffold — `WalletPane` enum, selectable sidebar in `HomeView`, six pane shells (Overview, Send, Receive, Transactions, Contacts, Settings). `OverviewView` has a balance card with a Refresh action that surfaces the stub error inline. `ReceiveView` shows the live FID big with Copy. `SettingsView` form for FAPI host/port/pubkey/theme/auto-lock, persists to per-main `PreferencesStore`. Send/Transactions/Contacts are labeled empty-state panes. Renamed FCDomain `Settings`→`Preferences` and `SettingsStore`→`PreferencesStore` to dodge the SwiftUI `Settings` Scene collision. | ✅ |
| 7.2 | Live `FapiClient` plumbing — `ActiveSession.fapi` is now mutable via `setFapi(_:)`; `wallet` is a computed property so swaps propagate. `AppState.applyFapiSettings(for:)` reads host/port/pubkey from `Preferences`, opens a real `FudpClient` (using main privkey for AsyTwoWay), wraps it in `FapiClient`, swaps into the session. SettingsView gained **Test connection** (one-shot `base.health` against form values), **Discover** (plaintext HELLO → auto-fill pubkey), and **Save**-and-apply. Live transport torn down on `lockAll` / `returnToChooseMain`. | ✅ |
| 7.3 | Real Send flow with **BCH-Schnorr** signatures (FCH rejects ECDSA-DER on P2PKH with a misleading "Signature cannot be 65 bytes in CHECKMULTISIG"). Sub-phases: 7.3.1 migrated cash fetching from `base.getUtxo` → `base.cashValid`, replacing `Utxo`/`UtxosStore` with `Cash`/`CashesStore`. 7.3.4 wired `BchSchnorr.sign` (BCH 2019 pre-BIP340: nonce = SHA-256(d ∥ m); challenge = SHA-256(R.x ∥ P_compressed_33 ∥ m); R selected so jacobi(R.y)==1) into `TxHandler.signP2pkhInput`; CoinSelector input-byte estimate dropped 148→141. 7.3.5 rewrote BchSchnorr over libsecp256k1 primitives, ~700× speedup (~30s → ~10ms per sig). | ✅ |
| 7.4 | Cash incremental sync (Pattern A: watermark by `lastHeight`, sync = items with `lastHeight > localMax − reorgWindow(30)`). Post-send optimistic update marks spent inputs `pendingSpend=true` (kept for recovery) and synthesizes change cashes with the pre-computed `id` so server delta merges by id. 7.4.1 added Recover (un-mark a stuck `pendingSpend`) and Purge (drop the cash cache; next refresh re-bootstraps via `base.cashValid` mode-2). 7.4.2 made bootstrap mode-2 (`params: {fid}`) the fallback when incremental search fails. | ✅ |
| 7.5 | Transactions pane via `base.search` on the cash index. Sub-phases: 7.5.1 fixed FCDSL — conditions go under `query`, not `filter` (matched Android `Freer/CashManager.java`). 7.5.2 fixed FUDP STREAM frame reassembly (large responses span multiple frames sharing a streamId; receiver was decoding each as a complete AppMessage — large `base.search` responses then broke subsequent calls). 7.5.3 added Pattern C cache (cursor-paginated stream blob, key per-kind via `RecentActivityStore.key(fid:kind:)`). 7.5.4 added per-tx grouping (TxGroup folds inputs+outputs of the same tx; valid==true→birthTxId is event, valid==false→spendTxId is event; mixed groups for self-sends). 7.5.5 added "Load more" pagination + Overview auto-refresh on appear. 7.5.6 added All / Incomes / Expenses tabs. 7.5.7 corrected Incomes/Expenses semantics (cashes with value > 0; income = owner==fid && issuer != fid; expense = issuer==fid && owner != fid; render flat per-cash, not per-tx). 7.5.8 made every UI ID render middle-elided (`head + "…" + tail`, never `prefix(N)`); Incomes/Expenses rows now lead with a 40 px FidAvatarView for the counterparty. | ✅ |
| 7.6 | Contacts pane. 7.6.1 reshaped the local `Contact` to mirror the Android `feip.Contact` (id=FID, optional cid/pubkey/on-chain stats/cross-chain addrs/multisig, editable detail = titles/memo/seeStatement/seeWritings; `name = cid ?? id`), bumped the store namespace to `contacts.v2`, and shipped a list+search+pin+edit+delete UI with an editor sheet covering the locally-editable fields. 7.6.2 added `DirectoryService.freerByIds` (`base.freerByIds` over `{"ids":[…]}`) + a `Freer` wire struct + `Contact.merging(_:)` that overwrites the on-chain block while keeping local edits, and a **Look up** button in the editor that auto-fills CID and surfaces pubkey / balance / last-block / cdd. 7.6.2b added on-chain contact sync: `DirectoryService.syncOnChainContacts` pages `base.search` over `entity:"contact"` (active==true, owner==fid), decrypts each `cipher` (AsyOneWay CryptoDataStr envelope — ECDH(privkey, pubkeyA) → HKDF-SHA512(salt=iv, info="hkdf") → AES-256-GCM), enriches via `freerByIds`, merges into `ContactsStore`; ContactsView auto-syncs on appear + Refresh button. 7.6.3 carved contacts on-chain via the FEIP `CONTACT` op (add/update/delete; OP_RETURN tx with CD-aware coin selection) and closed the deletion gap: sync now fetches inactive carves too and removes chain-sourced local rows whose newest carve is deleted. | 7.6.1 ✅, 7.6.2 ✅, 7.6.2b ✅, 7.6.3 ✅ |
| 7.7 | QR — ported the Android `QrCodeActivity`/`QRCodeGenerator` pair into FCUI. `QrCoder`: 300-byte UTF-8-safe chunking (same `DEFAULT_CAPACITY` as Android so multi-part codes interop both ways), `CIFilter.qrCodeGenerator` (correction M, 461 px, integer upscale), Vision (`VNDetectBarcodesRequest`) decode from image files. `QrCameraController` + `QrCameraPreview`: live scan via `AVCaptureVideoDataOutput` frames run through Vision — **`AVCaptureMetadataOutput` has no `.qr` type on macOS** (iOS-only; it fails at config time with an unsupported-type error) — pausing after each read (Android's append-and-stop rhythm). `QrDisplaySheet`: k/N pager over the chunked codes with Save-PNG(s) + Copy. `QrWorkbenchView`/`QrScanSheet`: editable content + camera scan / multi-image decode (NSOpenPanel multi-select + drag-drop) where every code **appends**, so long payloads split across images merge back together. Wired: ReceiveView shows the FID QR inline with Save; SendView recipient field gained a scan button; the full workbench opens as a sheet from a **toolbar `qrcode` button (⌘K)** — top-right on every pane, since it's a high-frequency tool. Round-trip tests (generate → Vision decode, incl. multibyte splitting) in `QrCoderTests`. | ✅ |
| 7.8 | Person menu + watch-only Send fallback (Android `personView` / `PersonPopupMenuHelper`). 7.8.1 replaced the toolbar switch-FID menu (and the separate switch-identity button) with the live FID's avatar opening a popover: header (avatar + "Living: \<role\>" + copyable elided FID), rows Main FID / My Master / My Watched FIDs / My Multisig FIDs / My Servants / Quit Main FID; Android's gating preserved (only-main-can-branch-out); master switch fetches its KeyInfo via `freerByIds` and caches it as a sub-identity when missing (`KeyInfo.from(freer:)`, `ActiveSession.addSubIdentity`); *setting* a master (on-chain carve, `SetMasterActivity`) deferred; `AppState.liveFid` observable mirror + `.id()` on the detail pane makes every switch refresh the pane for the new identity. 7.8.2 `AddWatchedFidSheet` — FID/CID lookup (exact `freerByIds` / partial `searchFreers`), QR scan, duplicate guard, saves `KeyInfo(kind:.watched)` with pubkey when known. 7.8.3 watch-only Send fallback: `RawTxInfo` (Android's ver-"2" cold-sign JSON — trimmed input `Cash`es per `makeCashListForPay`, feeRate in F/kB) + `WalletService.buildUnsignedSend` (same snapshot/spendability/coin-selection as `send`, no signing, no optimistic spend-marking) + `UnsignedTxSheet` export via Copy / Save / multi-part QR (`QrDisplaySheet`); Android `CreateTxActivity` imports it by paste or QR-merge. Tests: `SubIdentityTests`, `RawTxInfoTests` (incl. Android-shaped JSON decode + deterministic export). | 7.8.1 ✅, 7.8.2 ✅, 7.8.3 ✅ |

### Phase 8 — Smaller features · 3d · in progress

| # | Scope | Status |
|---|---|---|
| 8.1 | `ToolsView` — Encrypt / Decrypt / Sign / Verify / Hash / Random over new FCCore primitives (`Base32`, `Totp`, `Keccak256`, `Hash.{md5,sha1,hmacSha256,hmacSha1}`, `SignedMessage` with freecashj byte-parity) and FCDomain `MsgSignature` + `TextCipher`. TOTP UI deferred to 8.2 (needs the Secret store). | ✅ |
| 8.2 | Secrets — `Secret` (Pattern B cipher-only), `SecretsStore`, `SecretFeip` (sn 17), `SecretService` sync (decrypt → re-encrypt-to-self → merge by carve id, deletion-aware), `ActiveSession` carve add/update/delete, `SecretsView` (list + reveal + carve + delete, TOTP authenticator tab with live 30 s codes), `SecretEditorSheet` (create/import, Base32 validation, save-local or save-&-carve). | ✅ |
| 8.3 | `HomeView` extras — application / token / proof / protocol lifecycle (create / issue / destroy / close). | |
| 8.4 | HAT + file management (see detailed spec below) — **Phase 9 prerequisite**: IM file transfer sends the raw HAT JSON as the message body. | specced |

- `ContactView` CRUD shipped in 7.6; its IM/mail ties land with Phase 9.

### Phase 8.4 — HAT + file management · ~5d · **Phase 9 prerequisite**

Port of Android's `HatManager` + `DataSyncManager` + `DataActivity`/`HatFileOpener`. A `Hat` is a **local-only** (no blockchain sync, no FEIP) file-metadata record: `id` = DID = hex `sha256x2(content)`, `locas` = list of locations (`local://<path>`, `fudp://host:port`, `(sid)<serviceId>`), plus the two-HAT cipher fields. IM file messages (Android `FileShareHelper`) serialize the **raw HAT JSON as the message content** with the plaintext `key` and DISK locas copied in — the receiver adds that HAT to its own store and downloads via the plain-key path. So this layer, wire-compatible with Android's `Hat.toJson()`, must exist before Phase 9.

**Two-HAT cipher model (`DataSyncManager` parity).** Upload: random 32 B symkey → encrypt file → cipher DID = sha256x2(cipher file) → `kCipher` = AsyOneWay-encrypt the symkey to the owner's own pubkey (same envelope as 7.6.3's `AsyOneWayCipher`) → `disk.put` (temp, `dataLifeDays`) or `disk.carve` (permanent) → create cipher HAT (`id=cipherDid, rawDid=rawHat.id, kCipher, size, locas=[(sid)… preferred, fudp://… fallback]`) → append cipherDid to raw HAT's `cipherIds`. Download: (1) raw HAT's remote locas direct — **hash-verify against the DID, servers are untrusted**; (2) per cipherId: plain-key path first (`rawHat.key`, works without the cipher HAT in the local DB — the IM receive path), then kCipher path (decrypt with live privkey); stream-decrypt; plaintext must hash back to the raw DID; write into the app data dir and add a `local://` loca. Accumulate per-attempt failure diagnostics into the surfaced error (Android's `diag` string — keep it, it's what makes DISK failures debuggable).

**The Mac difference — reference, don't copy (decision 2026-08-13).** Android copies every imported file into `filesDir/data/<did>` because SAF content URIs aren't stable. On macOS (unsandboxed SwiftPM build) we register the **original file's path** as the `local://` loca — no copy, no doubled disk usage, instant import even for GB files. Reference-mode guard: a `HatLocal` sidecar (persisted next to the wire `Hat` in the store row, **never** serialized into IM/export JSON) records size+mtime per referenced path at registration; every access `stat`s the file — missing → drop the loca (self-heal); size/mtime changed → re-hash; hash ≠ DID (edited in place) → detach the loca and offer re-register-as-new-version (`preDid`/`srcDid` links). Cost: one `stat` per access; re-hash only on actual change. Downloads and explicit "materialize a copy" land in `Application Support/FreerForMac/<mainFid>/data/<did>` (checked as an implicit loca, like Android's `filesDir/data/<did>` fallback). A received HAT's foreign `local://` paths simply fail the `stat` and are ignored. If the app is ever sandboxed for distribution, `HatLocal` grows security-scoped bookmark data — field reserved now.

| # | Scope | Est |
|---|---|---|
| 8.4.1 | **Transport: large-payload streaming.** ✅ shipped 2026-08-13 — see the header blockquote. Port of the Java send path (`Protocol.sendAndCloseFromInputStream`): chunked outbound STREAM frames, receive-side ACK generation, `CongestionControl`/`RttEstimator`/loss-detection ports, retransmit loop, `FapiClient.callUploadingFile`/`callDownloadingToFile`, F2 ECDH cache, spill-to-disk reassembly, copy-free decode layers. | ✅ |
| 8.4.2 | **FCCore: `FileCipher` (Java parity).** ✅ shipped 2026-08-13 — see the header blockquote. Format pinned by running the real FC-AJDK encryptor; brace-counting header scanner reproduced exactly (all edge cases cross-checked); `tools/vector-gen` now compiles the actual FC-AJDK `Encryptor`/`Decryptor` on a plain JVM so vectors come from the true producer rather than a re-implementation. 17 tests, both directions verified. | ✅ |
| 8.4.3 | **FCDomain: `Hat` + `HatsStore`.** `Hat` Codable mirroring the Java class field-for-field (incl. the `Leaked` capital-L quirk; `DataState` byte raw values; nil-omitted) — acceptance test is decoding a real Android `Hat.toJson()` and re-encoding losslessly. `HatsStore` (namespace `hats.v1`) rows hold `{wire: Hat, local: HatLocal}`; in-memory index loaded per session gives byId / sorted-by-`last`-desc pagination / search (id·name·desc·types·DID fields·locas) / cipher-HAT filtering (`rawDid != nil` hidden from lists) / byLocation-prefix / modifiedSince. `checkIdWithCreate` parity for imported id-less HATs. | 0.5d |
| 8.4.4 | **FCDomain: `FileVault`** — the reference-mode file layer described above: `registerFile(url:)` (stream-hash → DID → raw Hat, locas=[local://original], HatLocal sidecar), `resolveLocalURL(hat:)` with the stat/re-hash/detach rule, `materialize(hat:)` (copy into the app data dir), `defaultLocalURL(did:)`, delete semantics (deleting a HAT removes app-managed copies only — referenced originals are never touched). | 0.5d |
| 8.4.5 | **FCDomain: `DiskService` + `HatSyncService`** (the `DataSyncManager` port): `DiskItem` Codable; `disk.put`/`disk.carve`/`disk.get` (params `{id}`)/`disk.check` (single + ≤200-id batches); two-HAT upload + download flows above; `lastSymkey` surfaced for the IM share path (raw HAT gets `key` hex + cipher locas before serializing into a message); `uploadRawData` (unencrypted, for public content-addressed docs — team consensus later); loca repair to `(sid)` when a download recovers via a fallback client. Loca→client resolution: default session client + literal `fudp://` URLs first; `(sid)`-bootstrap via serviceById + LRU cache (16) deferred to the IM phase that first needs a foreign DISK. | 1d |
| 8.4.6 | **UI: Files pane** (`DataActivity` port): sidebar pane listing raw HATs by `last` desc (cipher HATs hidden), search, per-row status (local / on-DISK / both / stale-reference), size + type icon, register via drag-drop + open panel (reference mode), open via `NSWorkspace`/Quick Look (auto-download first when remote-only, in-row progress + cancel — `HatFileOpener` parity), reveal in Finder, upload selected (put vs carve choice), download selected, remove-local-copy vs delete-HAT, copy DID (CopyableText), HAT JSON import/export (`ImportHat`/`ExportHat` parity — the cross-device escape hatch), detail sheet with locas management. | 1d |

**Acceptance:** cross-platform round-trip — a file uploaded from Android (its exported HAT JSON imported on Mac via QR/paste) downloads and decrypts on the Mac through both the plain-key and kCipher paths, and vice versa; a 100 MB upload from the Mac completes against a live DISK server without the file ever fully resident in memory.

### Phase 9 — IM + Mail · 10d · **largest feature chunk**
- Rooms / Squares / Teams (matches Android `im/` structure)
- Message types: text, emoji, voice (via `AVAudioRecorder`/`AVAudioPlayer`), file share — file share rides on Phase 8.4: the sender uploads via the two-HAT flow and serializes the raw HAT (plaintext `key` + DISK locas) as the message content; the receiver merges it into `HatsStore` and downloads via the plain-key path (Android `FileShareHelper`/`ChatActivity.startHatTransfer` parity)
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
