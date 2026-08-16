# IM wire format v2 — plan and findings

Working notes as of 2026-08-15. Spans three repos:

- `~/MacApp/FreerForMac` (Mac app)
- `~/AndroidStudioProjects/Freer` (Android app + FC-AJDK)
- `~/Desktop/Freeverse` (server: `FC-JDK/src/main/java/fapi`, `fudp`; specs: `Protocols/IM`)
  — readable as of 2026-08-15; the earlier TCC block is gone.

---

## Shipped already (done, tested, building)

### Mac
- **Per-DOCK routing.** `DockRegistry` + `DockFetchScheduler`; sends go direct to the
  recipient's DOCK, collects poll every group's DOCK. Cursors per DOCK; group items are
  never deleted (one copy serves every member).
- **`FudpUrl`** canonical `fudp://host:port` form, so "is this my own DOCK" compares
  endpoints rather than strings.
- **Concurrency fix in `FudpClient`.** The inbound mailbox is single-consumer and
  *discards* non-matching envelopes; nothing serialised calls, so overlapping requests ate
  each other's replies (symptom: `FudpClient: timeout` on the launch balance load once the
  poller existed). Added `exchanging { }`, a FIFO gate, around every send→receive.
- **`base.serviceByIds` → `base.getByIds` with `entity: "service"`.** The old endpoint does
  not exist; the server 404s, and 404 is treated as "no such record", so every SID silently
  failed to resolve while direct-URL homes kept working. Android does this via
  `entityByIds(IndicesNames.SERVICE, …)`.
- **`HomeServiceResolver` follows `setFapi`.** It is a `lazy var` that captured whatever
  client existed at first touch (the stub, since `unlockMain` sets `route = .home` before
  awaiting `applyFapiSettings`). Swap is synchronous — a `Task` hop made two swaps racy.
- **System pane + `SystemLog`.** The quiet failure paths (DOCK connect, collect, delivery,
  SID lookup, FAPI connect) now record somewhere visible.
- **Chat party detail sheet**, with routing as the headline section.

### Android
- **P2P bodies are sealed on the DOCK/ROAD paths** (`AsyTwoWay`: our prikey + their pubkey),
  opened in `handleIncoming` *before* the RECEIPT branch. FUDP direct stays plaintext —
  that session really is end-to-end.
- No plaintext fallback: a body that cannot be sealed fails the send.
- Self-chat uses `AsyOneWay` (AsyTwoWay would put the same key in both slots and
  `Decryptor`'s side-selection cannot resolve that).
- `BaseHandler`'s encryption-scheme doc corrected — **case 3, P2P via DOCK, was missing**,
  and that omission was the bug.

---

## The remaining problem

Three faults, one root cause: the wire format was designed for short text and then asked to
carry binary.

1. **`writeLenPfx16` is a 2-byte length** (`putShort`) → 65,535 byte ceiling, while
   `MAX_INLINE_DATA_SIZE` is 900 KB — 14× beyond what the format can express.
   Android **silently wraps** the length (corrupting every field after it); the Mac throws
   `WireFailure.fieldTooLong`. So inline binary is already broken above ~48 KB of audio.
2. **`dataBase64` is a String** — base64 exists only to fit bytes into a text field. +33%.
3. **Two body fields** (`content` and `dataBase64`), so encryption has to remember both.
   The Android fix above seals `content` only, which leaves voice **metadata encrypted and
   the audio in the clear** — the worst shape a half-fix can take.

Also found: `FileShareHelper` puts the file's symkey in the HAT (`rawHat.setKey(...)`) and
that HAT goes in `content`. Sealing `content` closed that hole — the key was previously
travelling in cleartext next to the DISK locations of the ciphertext.

---

## Decided design (v2)

One deliberate break. No backward compatibility — a version byte rejects old peers rather
than half-supporting both formats.

```
magic(1) = 0xF1   version(1) = 0x02      <- 2 bytes, see "Spec — done" #1
type(1) contentType(1)
senderId(len8) targetId(len8) timestamp(8) flags(2)
[ body(len32) ]                      <- the ONLY private field
[symkeyVersion(4)] [requestType(1)]
[requestId(len16)] [replyToId(len16)] [threadId(len16)] [messageId(len16)]

flags: bit0 body, bit1 bodySealed, bit2 symkeyVersion, bit3 requestType,
       bit4 requestId, bit5 replyToId, bit6 threadId, bit7 messageId
```

Inside `body`, before sealing:

```
contentLen(4) + content(utf8) + dataLen(4) + data(raw bytes)
```

- **Safe** — one private field, so "seal the body" is the whole rule. A private field added
  later rides inside automatically; the half-encrypted state becomes unrepresentable.
- **Efficient** — seal with `encryptByAsyTwoWayToBundle` (binary: alg + type + pubkeyA + iv
  + cipher, ~52 B overhead) instead of the JSON/base64 envelope, and carry raw `data`
  instead of `dataBase64`. Kills both base64 layers. The bundle embeds `pubkeyA`, so the
  receiver still does side-selection with no extra lookup.
- **Clean** — routing metadata outside, one sealed blob inside. Groups: same shape, symkey
  bundle. Squares: body unsealed (anyone may join; no secret).

Crypto is unchanged — only the container. The AsyTwoWay interop verified between the two
apps still holds (`CryptoDataStr` fields and `EccK1AesGcm256@No1_NrC7` match; side-selection
resolves in both roles).

## Server findings (read 2026-08-15, `FC-JDK/src/main/java/fapi`)

Both open questions are answered, and one answer overturns the sizing plan above.

**1. The DOCK per-item limit is 64 KB, not 1 MB.**
`DockComponent.DEFAULT_MAX_DATA_SIZE = 64 * 1024`, checked in `handlePut` against the raw
`binaryData` *before* base64. Each operator MAY override it from the on-chain service
record (`Service.maxDataSize`, a decimal byte string; `DockComponent:155`). So the "1 MB"
in the app comment was never real — today's 900 KB is **14×** the default ceiling, and the
proposed 256 KB is still 4× over. Fees are charged per KB on ingress *and* per KB per day
of retention, so size costs money as well as reliability.

**2. The server never parses the body.** Zero references to `ImMessage` or `FIMP` anywhere
in `fapi` or `fudp`. `handlePut` length-checks, base64s into ES, and stores;
`handleGet` decodes back to bytes. The payload is fully opaque. **v2 is client-only — no
server change.**

## Decided sizing (revised)

No fixed constant. The budget is **resolved per destination**:

```
budget = targetDock.maxDataSize (on-chain service record)  ?? 65_536
```

enforced against the **fully encoded wire envelope** (that is exactly what `dock.put`
receives), not the body alone. Over budget → DISK + HAT, as today.

This drops the "voice is always inline" invariant, and the `buildVoiceMessage → null →
FileShareHelper` fallback **stays**. It cannot survive a per-destination ceiling: at any
bitrate worth shipping, a 60 s note exceeds 64 KB, and a DOCK may advertise less than the
default anyway. Voice bitrate/duration become a tuning question (keep ordinary notes under
budget so they stay inline) rather than a correctness invariant.

Hard-coding 64 KB was rejected for the same reason 900 KB failed: an app-side constant
asserting a server limit it never read.

---

## Spec — done

`Protocols/IM` now carries a complete v2 set, written before any implementation so the two
clients agree via the document rather than by reading each other:

- `FIMP0V2_FIMP.md` — envelope, body framing, encryption model, new **Payload Sizing**
  section, `Changes from Version 1` table.
- `FIMP1V2_P2P.md`, `FIMP2V2_Room.md`, `FIMP3V2_Square.md`, `FIMP4V2_Team.md`.

v1 files are left in place; nothing was deleted.

Three deviations from the sketch above, each recorded in the spec with its rationale:

1. **Two-byte prefix `0xF1 0x02`**, not a bare version byte. v1's first byte is the
   `ImType` ordinal (0–3), so a bare `version = 2` is indistinguishable from a v1 **TEAM**
   message — a v2 decoder would silently misparse legacy TEAM traffic instead of rejecting
   it. `0xF1` cannot occur as a v1 first byte, so rejection is deterministic both ways.
2. **`FLAG_BODY_SEALED` flag bit.** Otherwise a receiver has to infer sealing from the
   channel a message arrived on. The bundle stays self-describing for *which* scheme; the
   flag only answers sealed-or-not.
3. **General Rule 9 inverted.** v1 made the Android implementation authoritative over the
   spec; that precedence is what let the two clients drift (`base.serviceByIds`). The
   document is now the contract.

Also corrected in the spec: **FIMP1V1 §7 said P2P adds no IM-layer encryption at all** —
which the already-shipped Android sealing directly contradicts. v2 states the real rule
(sealed on DOCK/ROAD, plaintext on direct FUDP, `asy1way` for self-chat).

## Next steps, in order

1. ~~Confirm the DOCK's real per-item limit.~~ **Done — 64 KB, per-DOCK configurable.**
2. ~~Does the server parse `ImMessage` bodies?~~ **Done — opaque; v2 is client-only.**
3. ~~Update `Protocols/IM` first.~~ **Done — FIMP0–4 V2.**
4. ~~Implement v2 on the Mac.~~ **Done — builds, 567 tests pass, none skipped.**
5. ~~Implement v2 on Android.~~ **Done — `:app:assembleDebug` succeeds, 10 new tests pass.**
6. ~~Regenerate the golden vectors and re-enable the parity tests.~~ **Done — the two
   clients are now checked against each other byte for byte.**

**The wire work is complete on both sides.** What is left is downstream of it, not part
of it: resolving the per-DOCK budget on Android (it currently passes
`ASSUMED_DOCK_ITEM_LIMIT` at the voice call site rather than reading the destination's
service record), and revisiting voice bitrate/duration now that 64 KB is the real
default.

**Both are now done on the Mac (2026-08-16).** `MessageCourier.itemBudget(forTarget:type:)`
resolves the destination's real ceiling before a voice note is composed — the same
question `overBudget` asks at send time, asked early enough to choose a route — and
`VoiceNote.fitsInline` decides inline-or-HAT from it. Recording is 16 kHz mono AAC at
**24 kbit/s**: Android's 64 kbit/s was picked against the imaginary 900 KB ceiling and
buys about eight seconds inline against the real one, where 24 buys twenty. Nothing about
the format changed, so a note recorded either side plays on the other.

## Mac implementation — done

- **`CryptoBundle`** (new) — the binary `CryptoDataByte.toBundle`/`fromBundle` form, read
  off FC-AJDK so the bytes match: `alg(6) type(1) [pubkeyA(33)] [keyName(6)] iv(12)
  cipher`. GCM only; the CBC/ChaCha shapes exist for legacy on-chain data and are rejected
  rather than half-supported. 52 B overhead for AsyTwoWay, 25 B for symkey.
- **`ImMessage`** — v2 envelope with the `0xF1 0x02` prefix, `body(len32)`, the new flag
  word, and `bodyFraming()`/`applyBodyFraming()`. `dataBase64: String` → `data: Data`
  (raw), `cipher: String` → `body: Data`.
- **`ImMessageBody`** — seals the *framing*, so `content` and `data` are inside or outside
  the seal together.
- **Budget** — `Service.maxDataSize`/`itemSizeLimit`, `HomeServiceResolver.dockItemLimit(url:)`,
  enforced in `MessageCourier` per DOCK route (forwarding checks both hops and takes the
  smaller). Over budget is a **permanent** failure, not a retry: it will not fit later.

### Three things worth knowing

1. **An AsyTwoWay bundle records only `pubkeyA`**, unlike the JSON envelope, so a sender
   cannot reopen what they sealed. Java has the same property, so Android will too. Nothing
   depends on it — `MessagesStore` keeps our own messages as plaintext — but two tests
   asserted the old behaviour and now assert the new one.
2. **Local-storage JSON renamed** `dataBase64`→`data`, `cipher`→`body`, both Base64
   strings. The *encoding* behind both changed, so keeping the old names would let a v1
   record parse and then fail deep inside the crypto instead of at the field. Written into
   FIMP0V2 §7 (including a warning against Gson's default `byte[]` handling) so Android
   implements it from the spec rather than from the Mac.
3. **Empty payload == no payload** at encode time. The framing records a length, not a
   presence, so an empty section decodes to nil; encoding it as an all-zero framing would
   make encode→decode→encode unstable.

`ImWireV2Tests` (14 new) covers the magic, the framing, oversized payloads, and
all-or-nothing sealing.

## Android implementation — done

- **`ImMessage`** — same v2 envelope. `dataBase64: String` → `data: byte[]` (raw),
  `cipher: String` → `body: byte[]`, plus `bodyFraming()`/`applyBodyFraming()`.
  **An over-long field now throws** instead of `putShort()` wrapping it, which is the
  original corruption bug.
- **`ImMessageBody`** (new, in FC-AJDK) — seals the framing with binary bundles via
  `Encryptor`/`Decryptor`. Algorithms are pinned to GCM explicitly: `new Encryptor()`
  defaults to **AES-CBC**, whose bundle carries a trailing sum the Mac does not read for an
  IM body.
- **`Base64BytesAdapter`** (new) — `@JsonAdapter` on the two binary fields. Gson's default
  for `byte[]` is a JSON array of signed numbers, which would have silently broken the
  history file. Applied per field, not globally, because Gson instances are built ad hoc
  across the codebase.
- **`P2pHandler`/`TeamHandler`/`RoomHandler`** — all three now seal on a copy, so the
  caller's object keeps its plaintext for the local transcript. P2P previously skipped
  sealing for "a STREAM whose payload rides in dataBase64", i.e. **every inline binary went
  out in the clear**; with one body that test cannot miss one.
- **`VoiceMessageHelper`** — takes the budget as a parameter instead of consulting a
  constant. The `→ null → FileShareHelper` fallback stays.

## Interop — verified

`tools/vector-gen` compiles the real FC-AJDK sources, so regenerating it ran the v2 Java
encoder. All 14 vectors now begin `f102`, and Java's local JSON writes `data`/`body` as
Base64 strings exactly as FIMP0V2 §7 specifies. The three parity tests are re-enabled and
green, which means **Swift's `toWireBytes()` produces the same bytes as Java's**, and both
agree on the stored form. That is the check the whole exercise was for.

## Receipts — fixed after live Mac↔Android testing

Messages moved in both directions but stayed at **Sent**. Two separate faults, one per
direction, neither of them a v2 regression:

1. **The Mac read a receipt before opening it.** `ChatService.receive` checked
   `contentType == .receipt` and asked `Receipt.kind(of:)` — which reads `content` — while
   the body was still sealed. A receipt is an ordinary P2P message, so the DOCK path seals
   it like any other; `content` was nil, every receipt was discarded as "matched nothing",
   and the sender's message never advanced. Android has always opened before its own
   RECEIPT branch (`P2pHandler` line 530 vs 532); the Mac was the outlier. Opening now
   happens first, which also fixes sealed SYMKEY and other signal types that were being
   routed onward still sealed.

   The existing test passed throughout because it fed an **unsealed** receipt — the one
   shape that never occurs in practice. There are now tests for the sealed case and for a
   sealed receipt we cannot open.

2. **The Mac never sent receipts at all.** `ImMessage.receipt(...)` existed and only tests
   called it. Added `ChatService.acknowledge(...)` — builds, seals and enqueues, and
   deliberately does **not** file the receipt in the transcript (it has no content of its
   own, so filing one would blank the thread preview). Wired to:
   - **delivered** — `MessageCourier` acknowledges each inbound P2P message as it is filed,
     resolving the sender's pubkey from their on-chain record. A failure here logs and
     moves on: the message is already filed, and a lost receipt costs a status, not a
     message.
   - **read** — `ChatView` on opening a thread. `markRead` now returns the messages it
     flipped rather than a count, so only genuinely-new reads are acknowledged.

Also corrected the P2P sealing note in the UI, which promised "both of you can reopen it" —
true of the v1 JSON envelope, not of the v2 bundle.

## Known gaps not yet addressed

- `LiveInteropTests` (FCTransport) fails without a real FUDP server on `localhost:9000` —
  environmental, pre-existing.
- Mac `refreshDockRegistry()` runs on group sync / manual exchange / startup, not on a
  timer, so an on-chain DOCK move is picked up at the next sync.
