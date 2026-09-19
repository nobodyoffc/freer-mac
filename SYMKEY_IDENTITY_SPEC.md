# Symkey identity — cross-client spec

How a Room or Team symkey is **named**, stored, asked for, handed over and
recorded. Both clients implement this document. The same file is kept in
both repositories — `FreerForMac/SYMKEY_IDENTITY_SPEC.md` and
`Freer/docs/SYMKEY_IDENTITY_SPEC.md` — so change both together.

**Nothing on the wire changes.** No envelope field, no flag bit, no request
string, no `contentType`. FIMP stays at V3 and that is not a concession:
§10's "wire-incompatible changes require a new version number" is never
triggered, because every change here is either a rule about what value goes
into an existing field or a local store that is never transmitted. The
server changes nothing — `symkeyVersion` appears nowhere in FC-JDK/FAPI, and
a DOCK forwards sealed bytes it cannot read.

Reference implementations:

| Part | Android (`Freer`) | Mac (`FreerForMac`) |
|---|---|---|
| Store | `app/.../im/SymkeyStore.java` | `Packages/FCDomain/.../Im/SymkeyStore.swift` |
| Minting | `app/.../im/handler/TeamHandler.java`, `RoomHandler.java` | `Packages/FCDomain/.../Im/TeamKeyService.swift`, `RoomService.swift` |
| Request / answer | `app/.../im/handler/TeamHandler.java`, `RoomHandler.java` | `Packages/FCDomain/.../Im/SignalRouter.swift`, `KeyExchange.swift` |
| Reopening a backlog | `app/.../im/ImManager.java` (`redecryptPendingMessages`) | `Packages/FCDomain/.../Im/MessageCourier.swift` |
| Asks (new) | `app/.../im/KeyAskStore.java` — shape it on `HistoryAskStore.java` | `Packages/FCDomain/.../Im/KeyAsks.swift` — shape it on `HistoryShare.swift` |
| Ledger (new) | `app/.../im/KeyLedger.java` | `Packages/FCDomain/.../Im/KeyLedger.swift` |
| Asking UI | `app/.../im/AskSymkeyActivity.java` | `Sources/FreerForMac/Views/Panes/Chat/AskMembersSheet.swift` |
| Sealed row | `app/.../im/adapter/` | `Sources/FreerForMac/Views/Panes/Chat/TranscriptView.swift` |
| Envelope (unchanged) | `FC-AJDK/.../fcData/ImMessage.java` | `Packages/FCDomain/.../Im/ImMessage.swift` |

## What is wrong today

`symkeyVersion` is a per-entity counter, and both clients mint the next one
from **their own** store: `currentVersion + 1`, which is `0 + 1` on a device
that holds nothing. So a device that has lost or never had an entity's keys
mints version 1 for a key that is not the version 1 everyone else holds.
Two distinct keys then answer to one name.

That is not a display problem. It has two silent, unrecoverable outcomes:

1. **History is destroyed.** `SymkeyStore.store(allowOverwrite:)` is called
   with `allowOverwrite: true` when the sender owns the entity, and it does a
   plain put. The owner's new v1 lands on a member's device, the member's real
   v1 is gone, and every message sealed under it is unreadable forever. There
   is no other copy.
2. **Recovery dead-ends.** A member missing the real v1 asks for "v1", is
   handed it, and cannot store it because a v1 is already present. The
   transcript keeps saying the key is held and does not open the row, and
   asking again can never change that.

A monotonic counter cannot be fixed by discipline, because **minting is not
single-device**. One FID is signed in on several devices by design
(`AskMembersSheet.ownRowHint`), so the owner's Mac and phone can both be
partitioned and both mint "the next version" for the same entity. No counter
assigned independently by two devices can avoid it.

## Decisions

1. **A symkey is named by when it was minted.** `symkeyVersion` carries
   seconds since the epoch, not a sequence number. Two devices have to mint
   in the same second to collide, and the field, the format and the sort
   order are the ones already in use.
2. **A mint never sorts below a key we know.** The value is
   `max(nowSeconds, highestKnown + 1)`, which makes a same-device collision
   impossible rather than unlikely, and makes a backwards clock unable to
   mint a key that supersedes nothing.
3. **A collision is survivable, not prevented.** Nothing is ever
   overwritten. Two keys may share a version; both are kept, and opening
   tries each. The residual risk of (1) costs one extra AES-GCM attempt.
4. **Identity is the key's own bytes.** `SHA256(symkey)` distinguishes two
   keys at one version. It is computed locally from the key, so it is never
   transmitted and costs no wire byte.
5. **One request type.** `SYMKEY` names zero, one or many versions.
   `SYMKEY_HISTORY` becomes an accepted alias and stops being sent.
6. **An unsolicited key is the owner's alone.** Anyone else's `SYMKEY` must
   answer an ask this device actually made. This is FIMP §4.2, unenforced
   until now, and it is also what bounds the store's growth once nothing is
   overwritten.
7. **An ask is state, not a toast.** It is persisted, it names who was
   asked, it paces retries, and it is what makes (6) checkable.
8. **Every key in and out is recorded.** FIMP §9.7, durable, local, never
   transmitted.

## 1. Naming: the mint rule

| Rule | Value |
|---|---|
| Field | `symkeyVersion`, unchanged: int32 on the wire, flag `0x0004` |
| Value | Seconds since the Unix epoch at mint |
| Floor | `version = max(nowSeconds, highestKnownVersion(entityId) + 1)` |
| Read as | **Unsigned.** See below |
| Legacy threshold | A value `< 1_000_000_000` is a pre-spec counter, not a time |
| Granularity | One second. Never milliseconds — 41 bits do not fit, and a truncated millisecond wraps every 49.7 days, which destroys the ordering that is the point |
| Who mints | The entity's owner, as before. Nothing else here changes who may |

**Why a floor and not just the clock.** Two cases stop being probabilistic
and become impossible. A double-tapped "Reset the key" or a test loop cannot
mint twice in one second, because the second mint is forced to
`highestKnown + 1`. And a clock that steps backwards — NTP correction, a
restored VM snapshot, a fresh install with a wrong clock — cannot mint a key
that sorts *below* an existing one. That case is worse than a tie: "current"
would select the retired key, so an owner who rotates after removing a
member keeps sealing under the key that member still holds, and FIMP §9.6
fails without a symptom. With the floor the field is a hybrid logical clock:
a timestamp where the clock is sane, a counter where it is not.

**Unsigned — done, in both clients.** Both sign-extended: `Int64(Int32(
bitPattern:))` on Mac, `(long) buf.getInt()` in FC-AJDK, deliberate
parity. Past January 2038 a timestamp read that way is negative, and a
negative value is not a version — so from that date on *every* key would
have been rejected on arrival. Both now read and write the field unsigned,
and a value that does not fit is **refused rather than truncated**
(`WireFailure.badSymkeyVersion` / `IllegalStateException`): a version is a
lookup key, and wrapping one produces a message naming a key that cannot
be found, with nothing to tell the sender. No byte on the wire changes, no
message that exists today is affected, and the cliff moves to 2106.

The shared vectors were regenerated for this by the Java class, so it is
Android's reading that the Mac test checks, not the Mac's own:
`symkey-version-truncated` — which pinned the sign-extended answer — is
replaced by `symkey-version-timestamp` and
`symkey-version-past-int-max`. Only `im_message.vectors` was spliced into
`domainVectors.json`; the file's other sections carry random IVs and
regenerate differently every run.

**Coexistence is free.** Existing keys are versioned 1, 2, 3; a timestamp is
about 1.79 × 10⁹. They cannot collide, `max()` still selects the newest
because a timestamp always exceeds a counter, and a device holding both
needs no rule to tell them apart beyond the legacy threshold above. No
re-keying, no version renumbering, no coordinated cutover.

**Do not automate rotation on a chain event without a leader rule.** The
same-second collision is improbable only while minting is a human action. If
"member removed on chain → rotate" is ever made automatic, both of the
owner's devices act on the same event in the same second, systematically
rather than by chance. FIMP §3.3 invites that automation; anyone adding it
owes this spec a per-device jitter or a single-writer rule.

## 2. The store

Identity is `(entityId, version, contentHash)`, where
`contentHash = SHA256(symkey)`.

| Rule | Value |
|---|---|
| Row key | `<entityId>_<19-digit version>_<first 16 hex of contentHash>` |
| Parsing a row key | Slice from the **end**: 16 hex, `_`, 19 digits, `_`, the rest is the entity id. Fixed widths, so an entity id containing `_` still parses |
| Ordering | Unchanged: the zero-padded version dominates the key text, so "which version is current" is still answered from row names without decrypting anything |
| Overwrite | **Never.** `allowOverwrite` is deleted from `store` and `receiveShared`, and `isOwner` is deleted from the receive path |
| Same key arrives twice | No-op. Two members answering one ask is normal, not a race |
| Different key, same version | Both kept. `key(for:version:)` returns *candidates* |
| Opening | Try each candidate for the version the message names; the body's AES-GCM tag decides. One attempt in every real case |
| Retiring a key | Still nothing. A rotation supersedes, it does not revoke |
| Cap | 256 keys per entity. Reaching it means something is wrong, and §4 is what stops it being reachable by a peer |

Deleting `allowOverwrite` is the substance of this section. The rule it
implemented — "only the owner may replace a version" — existed to stop a
member poisoning a version everyone uses. Content identity makes poisoning
impossible without it: a bogus key is an extra candidate that fails its tag
and is never selected, and the real key is still there. The rule that
protected history was also the only thing that could destroy it.

Migration is a local one-pass rewrite: read every row, compute
`SHA256(key)`, write it under the new row key. No network, nothing lost,
and messages whose key was never held stay exactly as unreadable as they
are now.

## 3. Requests: one shape

The content format is already a superset of what is needed, so the merge
costs no new string:

| Content | Means |
|---|---|
| `<entityId>` | Whatever you hold as current |
| `<entityId>:<v>` | That one version |
| `<entityId>:<v1>,<v2>,…` | Those versions |

One parser, one `requestType`, one cooldown, one cap. `SYMKEY_HISTORY` is
**accepted** as an alias for the third form and is **never sent**; its
ordinal stays reserved. On the Mac this collapses `SymkeyShare.requested`
and `requestedHistory`, the two answer paths in `SignalRouter`, and the
three-way branch in `AskMembersSheet.send()`; on Android, the equivalents in
`TeamHandler` and `RoomHandler`.

| Rule | Value |
|---|---|
| Cap per request | 64 versions, unchanged (FIMP §5.2) |
| Counted on | Versions **answered**, not named, so a request padded with versions the responder lacks cannot buy a larger answer (FIMP §9.8) |
| Versions we lack | Omitted from the answer. Never substituted, never a refusal of the whole batch |
| A named version | Answered with that version or not at all |

## 4. Who may give us a key, and how often we ask

**Accepting.** A `SYMKEY` is stored only when one of these holds:

1. the verified sender **owns** the entity; or
2. the verified sender is our **own FID**; or
3. its `requestId` matches an ask this device has outstanding, **and** the
   version it carries is one that ask named.

Otherwise it is dropped. (1) and (3) are FIMP §4.2 as written, and nothing
implemented it — any member could push arbitrary keys at any other. (2) is
an addition: one FID is signed in on several devices by design, and the
envelope signature proves the sender holds this identity's prikey, so the
key came from this identity whatever device sent it. It is also the only
route a reinstalled owner has, since their other device may hold the only
copy of the key in existence.

The rule is also what bounds §2's cap: once nothing is overwritten, "only
the owner, ourselves, or what we asked for" is what stops someone else
filling this store. Solicitation is **never** inferred from the mere
presence of a `requestId` — it has to match a request we still have a
record of.

**Asking.** `KeyAsksStore`, shaped on `HistorySharesStore`'s outgoing side:

| Field | Meaning |
|---|---|
| `entityId`, `version` | What is wanted. Version `0` means "whatever you hold now" |
| `kind` | `SYMKEY` or `ROOM_INFO` — a room's details answer carries a key too |
| `askedFids` | Who was asked, in the order they were asked |
| `askedAt` | FID → when we last put this question to them. The cooldown is per person, so this is per person |
| `requestIds` | Every request id sent for this ask; an answer must carry one of them |
| `firstAskedAt`, `attempts` | How long recovery has been stalled, and what it has cost |

| Rule | Value |
|---|---|
| Cooldown | One request per `(entityId, version, responder)` per **120 s** |
| Auto-ask | On filing a sealed message whose version we lack, ask **its sender** — who provably holds that key — subject to the cooldown |
| Resolution | The ask is cleared when a key for that version is **stored**, not when one arrives: a cipher that would not open left us no better off |
| Expiry | Dropped after 30 days, or when the user gives up |

**The cooldown is per person, not per question** — a refinement on the
first draft of this spec, and on FIMP §7.4 as first amended. What the limit
bounds is cost borne by whoever answers (FIMP §9.8), so what must be capped
is how often *one member* is made to answer the same thing. Counting per
question would mean a user who asked one member and got nothing could not
ask a second for two minutes, which throttles recovery rather than traffic:
asking somebody else is not a repeat, and it costs the first member
nothing.

**Every ask is recorded before it is sent, on both paths.** The automatic
one in the courier and the manual one in `AskMembersSheet` write the same
record, because the acceptance rule above reads it: an ask that sent
messages without recording them would have every answer dropped on arrival
— the request would go out, the member would answer, and nothing would
happen, permanently. This is the failure Android has in the field for
member-to-member answers, and it is invisible precisely because the
*owner's* answers still get through.

## 5. The distribution ledger

FIMP §9.7 requires this and neither client had it. A device answers a
`SYMKEY` request automatically, on a membership check it makes silently,
and the key it hands over opens every message under that version —
including messages sent long before the requester joined. The ledger is
the only trace.

`KeyLedger` (namespace `im.keyledger.v1`), one row per event:

| Field | Meaning |
|---|---|
| `entityId`, `version` | Which key. Version `0` when the event was about no particular one |
| `counterparty` | The FID it went to, or came from |
| `direction` | `sent` \| `received` |
| `outcome` | `shared`, `stored`, `duplicate`, `refused`, `unreadable`, `notHeld`, `notAMember`, `noPubkey` |
| `solicited` | Whether it answered a request, or was a proactive push |
| `requestId` | When solicited |
| `at`, `lastAt`, `repeats` | First and last occurrence, and how many times |

Row key is `<19-digit ms>_<12 hex of the event's identity>`, so the row
order is the time order with no sort, two different events in one
millisecond stay distinct, and the *same* event in the same millisecond is
the same row — a replayed delivery cannot write twice.

**Recorded where the keys actually move**, which is more places than the
request/answer path:

| Event | Where |
|---|---|
| Answering a request (`shared`), and every refusal (`notHeld`, `notAMember`, `noPubkey`) | `SignalRouter.answerSymkeyRequest` / `answerSymkeyHistoryRequest` |
| A key arriving (`stored`, `duplicate`, `unreadable`, `refused`) | `SignalRouter.routeSymkeyShare` |
| A team owner's fan-out after a mint or rotation (`shared`, unsolicited) | `TeamKeyService.shares` |
| Every room key that leaves, whatever carried it | `RoomService.invitation` — the single funnel for invitations, membership updates, rotations and "share the room's details" |
| A room key arriving in a `ROOM_INFO` | `RoomService.acceptInvite` / `handleInfo` |

The owner's fan-out is how most keys in a group ever travel, so a ledger
recording only the answers to requests would miss the majority of its own
subject.

| Rule | Value |
|---|---|
| Retention | Durable. **Not** a ring buffer, no expiry, no cap — FIMP §9.7 is explicit, because the row that matters after a suspected leak is characteristically the oldest, which is what a bounded log has already dropped |
| Growth | Bounded by `coalesceWindow` (1 h) rather than by a limit. See below |
| Transmission | Never. An export is built from `MessagesStore` rows and nothing else, and nothing in the codebase walks namespaces |
| Deletion | Only with the group: `RoomService.forget` clears the rows, because keeping a map of who could read an erased conversation is its own disclosure |
| Consent | None. Answering stays automatic — §9.7 says so, and a human gate would strand every joiner |
| Writing never fails the exchange | A lost row must not cost somebody their key |

**Why coalescing, and not a cap.** An *admitted* key costs its sender
ownership of the entity or a request we made (§4), so those rows are
bounded by honest activity. A **refusal** costs an attacker only the
sending, so a member pushing junk keys in a loop would otherwise write a
row per attempt — the one growth vector §9.7's reasoning does not cover,
because it assumed rows come from keys that were accepted. Identical
events inside the window fold into the row already there and bump
`repeats`, which preserves exactly the signal a person needs — "Carol
keeps pushing keys at me", with a first and last time — at one row an hour
instead of thousands. A refusal and a share are never folded together.

**The query that justifies the store**: `holders(of:version:)` — everyone
we gave a key to, and everyone who gave us one. That is §9.7's leak
radius, and it is deliberately *not* the membership: a member the owner
never managed to push to can read nothing, and a FID removed from the
group still holds every version it was given. `versionsGiven(to:of:)`
answers the same question about one person.

## 6. Showing a version in the UI

A version is a time, so **prose shows the time and never the number**. The
number appears only where two ids are compared, and only there is it worth
the width.

Implemented as `SymkeyVersionText` in FCDomain, with tests.

| Where | Form | Example |
|---|---|---|
| Sealed row, banners, toasts | The mint time in prose. Add `HH:mm` only when the entity has more than one key from that day | `Sealed with the symkey from 19 Sep — not held here` |
| Key list, ledger rows, ask rows | Fixed-width, year-first, monospaced digits so a column diffs by eye. Current year's `2026-` is dropped | `09-19 18:01:59` |
| Not the current year | Year kept | `2025-12-04 09:12:40` |
| On click | Copies the raw integer — what goes into a log or a message to another member | `1789813689` |
| Legacy value (`< 1e9`) | The counter, marked | `v3` + a `legacy` chip |
| Age | A secondary line, never the only rendering | `3 days ago` |
| Never | `v1789813689`, a truncated hash tail, or a bare epoch | |

Year-first rather than `26-09-19`, because `26` reads as a day in half the
world and this app has users in both halves. Seconds, because two keys of
one entity are minted seconds apart in exactly the case where telling them
apart matters. And a date beats a hash tag here for the reason the whole
design rests on: the id genuinely *is* a time, and a time tells a person
which era of the conversation they are missing, and therefore who to ask.

The contentHash is never shown. It exists so the store and the ledger can be
exact; a user comparing two keys compares times.

## 7. UI changes

Implemented in `SymkeyVersionText` (FCDomain, so the legacy threshold has
one home and the formatter has tests) plus four views:

| Change | Where |
|---|---|
| The sealed row says **when**, not `v1789813689`, and carries an inline `Ask for this symkey…` scoped to *that* version | `TranscriptView.sealedBubble` |
| The button shows the cooldown instead of failing silently — `Asked just now — again in 43s` | `TranscriptView.waiting(for:)` |
| `AskMembersSheet.Ask.symkey(version:)`: nil asks for everything this transcript is missing, one version named is a single row asking for the key it needs | `AskMembersSheet` |
| An outstanding-ask banner naming **who** was asked and how long ago, with *Ask more members…* and *Give up* | `ChatView.keyAsksBanner` |
| A `Symkey exchange…` sheet: the leak-radius line, then the ledger newest-first | `SymkeyLedgerSheet` |
| Counterparties as CID when known, else the FID elided in the middle; the version copies its raw number on click | all of the above |

Two departures from the plan above, both deliberate:

- **The ledger is its own sheet off the thread menu, not a section inside
  `MemberListSheet`.** That sheet cannot present another (its own comment
  says so), and folding a scrolling table into its fixed frame would have
  meant rebuilding its layout. A menu entry is also more discoverable than
  something buried behind *Members…*.
- **The sealed row's button is not gated on the cooldown being clear** — it
  shows the countdown and disables itself. The courier asks the sender
  automatically the moment the row is filed, so by the time a person reads
  it the question has usually already gone out; a button that silently did
  nothing would read as broken.

`SymkeyVersionText` has one more job worth naming: `needsTime(_:among:)`.
A date alone names two keys when both were minted on one day, so the clock
appears only when it has to, and the caller passes the versions it is
showing beside this one.

## 8. Tests

| What | Where |
|---|---|
| Mint floors above the highest known version, including when the clock goes backwards | `SymkeyStoreTests` |
| Two mints in one second get different versions | `SymkeyStoreTests` |
| Two different keys at one version: both stored, both candidates, the right one opens | `SymkeyStoreTests` |
| A legacy counter and a timestamp coexist; `max()` picks the timestamp | `SymkeyStoreTests` |
| A version past 2³¹ survives a wire round trip | `ImWireV2Tests` |
| An unsolicited non-owner `SYMKEY` is dropped; the same message with a matching `requestId` is stored | `SignalRouterTests` |
| One request inside the cooldown is not re-sent | new `KeyAsksTests` |
| A request naming 0, 1 and many versions all take one path; `SYMKEY_HISTORY` still parses | `SignalRouterTests` |
| Every store and answer writes a ledger row; a refusal writes one too | new `KeyLedgerTests` |
| The ledger is absent from a `HISTORY` response and from an export | `HistoryShareTests` |

The shared vectors are regenerated — see §1. `tools/vector-gen` compiles
against the real FC-AJDK sources, so a vector that disagrees with Android
cannot be produced by accident: the generator would have to be run against
an FC-AJDK that reads the field the old way, and its output would then fail
the Mac test.

## 9. Protocol documents

Amended in place, keeping V3 — **done**, in `Freeverse/Protocols/IM/`.

| Document | Section | Change |
|---|---|---|
| `FIMP0V2_FIMP.md` | §Symkey id (under Identifiers) | A version is seconds-since-epoch at mint, floored above every known version; unsigned, with the 2038 reasoning; legacy counters below 1e9 coexist; same-second collisions are tolerated, not assumed away |
| `FIMP0V2_FIMP.md` | §field table, `symkeyVersion` | `int32` → `uint32`, pointing at the above |
| `FIMP4V3_Team.md` | §4.2 | The store-only-if rule: owner, or a `requestId` matching a request this device still holds a record of, naming the version delivered. SHOULD → MUST |
| | §5.1 / §5.2 | One request taking zero, one or many versions, parsed by one parser; `SYMKEY_HISTORY` deprecated to an accepted alias with its ordinal reserved |
| | §7.1 | Never overwrite; two keys may share a version; try each; `SHA-256(symkey)` as local identity; the 256-key cap and what bounds it |
| | §7.2 | The mint rule; minting is not single-device; no automatic rotation on a chain event without a single-writer rule |
| | §7.4 | Ask the message's sender automatically; the two-minute limit becomes a MUST with persisted state; show the outstanding ask and who was asked |
| | §8.2, §9.8 | Point at §4.2's terms; the amplification section now speaks of a batch request rather than the deprecated type |
| | §9.7 | Refusals join the record; a version is its own mint time; growth is bounded by §4.2 and §7.4 rather than by retention, with identical repeats folded into one row |
| | §10 | Development amendments listed, **no version bump**, with why the wire is untouched |
| | §4.2, §7.4 | A key from our own FID is admitted unasked; the retry limit is counted per responder |
| `FIMP2V3_Room.md` | §4.4, §5.2, §5.3, §7.1, §7.2, §7.4, §8.6, §8.7, §8.8, §9 | The same, with three room-specific differences: a `ROOM_INFO` response also carries a key, so the solicitation rule accepts a `ROOM_INFO` request as the thing being answered; the rate limit rises from one minute to two to match FIMP4, so one implementation serves both modes; and the no-overwrite rule matters more, because a room's keys and membership exist nowhere but on its members' devices |

`FIMP1V3_P2P.md` and `FIMP3V3_Square.md` are untouched: P2P seals to a pubkey and Square does not seal.
