# Voice calls — cross-client spec

Live voice between Freer users: a **call** between two FIDs, and a
**meeting** of up to a few dozen members of a Room or Team. Both clients
implement this document. The same file is kept in both repositories —
`FreerForMac/VOICE_SPEC.md` and `Freer/docs/VOICE_SPEC.md` — so change both
together.

Status: **decided; Phase 1 done** — the DATAGRAM transport is implemented in FC-JDK, FC-AJDK and the Mac, checked against shared vectors, frozen in FUDP7, and its gate passed on 2026-09-23 (§14). **Phase 2 done** 2026-09-23: the audio spike passed its gate as restated in §14 (the original 300 ms mouth-to-ear limit cannot be met on the test phones by any Android voice stack). Phase 3 is next. The answers to the design questions are recorded in §15.

This is the implementation contract. The protocol documents it adds or
amends (§13) are written from it once the wire format is frozen at the end
of Phase 1 (§14).

Reference implementations (all new):

| Part | Android (`Freer`) | Mac (`FreerForMac`) | Server (`FC-JDK`) |
|---|---|---|---|
| DATAGRAM frame | `FC-AJDK/.../fudp/packet/frames/DatagramFrame.java` | `Packages/FCTransport/.../Wire/DatagramFrame.swift` | `src/main/java/fudp/packet/frames/DatagramFrame.java` |
| Keys, media frame, delegation | `FC-AJDK/.../call/` (`CallKeys`, `MediaFrame`, `Delegation`) | `Packages/FCDomain/.../Call/` | `fapi/components/call/` (verify only) |
| Signalling (`CALL` content) | `app/.../call/CallSignaller.java` | `Packages/FCDomain/.../Call/CallSignaller.swift` | — |
| Media engine | `app/.../call/engine/` (Opus via NDK, jitter buffer, `AudioRecord`/`AudioTrack`) | `Packages/FCDomain/.../Call/Engine/` (Opus, `AVAudioEngine`) | — |
| Relay | — | — | `fapi/components/CallComponent.java` |
| UI | `app/.../call/CallActivity.java`, `CallService.java` (foreground service) | `Sources/FreerForMac/Views/Call/` | — |
| Vectors | `FreerForMac/tools/vector-gen` (`CallRef.java`) | `FCDomainTests/Call/CallVectorTests.swift` | — |

## What this adds, and what it does not

**In scope:**

- 1:1 calls between two FIDs.
- Meetings inside a Room or Team, with up to 64 participants.
- Audio only.
- End-to-end encryption in every case: no server can hear anything.

**Not in scope:**

- Video.
- Square meetings: a Square has no secret, so it cannot have an E2EE meeting.
- Recording.
- Calls to phone numbers.
- More than one relay per meeting.
- Calls from sub-FIDs. As with IM (FIMP1 §4.5), a call needs `liveFid == mainFid`, because every signal and delegation is signed with the FID's key.

## Decisions

1. **Audio travels in a new FUDP DATAGRAM frame.** FUDP delivers
   everything reliably, but a late audio packet is worthless and
   retransmitting it only adds to the delay. A DATAGRAM frame is encrypted
   hop by hop like every other frame, but it is never retransmitted,
   never queued behind stream data, and not counted by congestion control
   (§2). Everything that is not audio stays on the reliable paths that
   already exist: FUDP request/response and FIMP messages.
2. **Signalling is FIMP.** Invites, answers and hang-ups are IM messages
   of a new content type, `CALL` (§3). They are signed, sealed,
   deduplicated and delivered by the channels IM already has. Ringing
   rides ROAD, because DOCK is polled — every 10 s at best and every 3
   minutes in the background — and a call cannot wait for a poll.
3. **The relay is a new FAPI component, `CALL@No1_NrC7` (§7).** ROAD
   cannot carry audio:
   - It charges per request, rounded up to a whole KB, so a 200-byte packet sent 25 times a second would be billed as 25 KB/s.
   - It checks the sender's balance on every request.
   - It is built for one delivery, not a session.

   CALL holds a session open, forwards frames it cannot read, and charges
   per minute. A relayed 1:1 call is just a CALL session with two people
   in it.
4. **The relay forwards; it does not mix.** It cannot mix audio it cannot
   decrypt. Each client sends one stream up, and the relay forwards the
   3 loudest speakers to everyone else (§7.4). To rank speakers, it reads
   a 1-byte audio level that the sender leaves in the clear (§5).
5. **Calls run under a throwaway transport identity (§4.1).** For each
   call, a client makes a fresh secp256k1 keypair and runs the call's
   FUDP connections under it. The FID key signs a short *delegation*
   saying "this key speaks for me in this call". The FID private key is
   therefore never needed by the media code, which is what lets it move to
   a separate `:voice` process later (§11.3) with no wire change.
6. **Key material by mode:**
   - **A 1:1 call** takes its key from an ECDH of the two throwaway keys, so it has forward secrecy: once both sides delete those keys, the call cannot be decrypted, even by someone who later steals a FID key.
   - **A meeting** takes its key from the entity's symkey, so anyone holding the symkey can join without the host being online to hand out keys. It has no more forward secrecy than the room itself (FIMP2 §8.2, FIMP4 §9.3). This trade is deliberate.
7. **Each sender has its own key per join.** The sender key is derived
   from the call key plus the sender's FID and a random 32-bit `ssrc`
   chosen fresh on every join. One FID can be in a meeting from a phone
   and a Mac at once. A key derived from the FID alone would give both
   devices the same key and the same packet counter, and so the same
   nonces. That is the "minting is not single-device" failure from
   SYMKEY_IDENTITY_SPEC, and the `ssrc` is what prevents it.
8. **Direct first, relay always ready.** A 1:1 call starts on the relay
   and tries a direct FUDP path at the same time. It moves to the direct
   path if one is found (§6). Direct calls are tried only with contacts,
   and never when the user has chosen *Always relay*, because a direct
   path shows each side the other's IP address.
9. **Only the host can moderate, and the relay enforces it.** Mute,
   remove and rekey are relay operations that the relay accepts only from
   the host's FID. The relay knows that FID because FUDP authenticated it
   when the meeting was created.
10. **Every sender signs its own audio, from v1.** Once a second, each
    sender signs a list of digests of the frames it has just sent (§5.1).
    The signature uses the sender's throwaway transport key, which the FID
    delegated (§4.1). A receiver checks every frame it played against those
    signatures, using delegations it verifies itself. So neither the relay
    nor another member can pass off audio as coming from someone else. The
    relay's roster is a convenience, not a source of trust.

## 1. Architecture

```
            signalling (reliable, FIMP CALL messages)
   ┌────────────────────────────────────────────────────────────┐
   │   caller ──ROAD (ring)──► callee's home ROAD ──MAP──► callee│
   │   caller ──DOCK (record)─► callee's DOCK                     │
   └────────────────────────────────────────────────────────────┘

            media (FUDP DATAGRAM, E2EE Opus frames)
   1:1  :  A ◄──────────── direct FUDP (if reachable) ─────────► B
           A ◄────► CALL relay ◄────► B          (always set up)

   meeting: P1 ─┐                ┌─► P2  (top-N speakers only)
            P2 ─┼──► CALL relay ─┼─► P3
            P3 ─┘  (reads header,└─► P1
                    never payload)
```

Each hop is FUDP-encrypted between its two ends. On top of that, each media
frame is sealed end to end (§5), so a relay that decrypts its hop still sees
only the frame header.

## 2. FUDP: the DATAGRAM frame

### 2.1. Encoding

```
DATAGRAM Frame {
  Type (varint) = 0x10,
  Length (varint),
  Data (Length bytes)
}
```

`0x10` is the first value after the STREAM range (`0x08`–`0x0F`). The
values `0x06`/`0x07` belonged to the removed symkey frames and are
not reused.

### 2.2. Rules

- A DATAGRAM frame MUST fit in one packet. It is never fragmented and
  never reassembled. The sender drops it if it would not fit. The largest
  payload is `maxPacketSize − 21 (header) − 68 (crypto) − 16 (timestamp and
  epoch) − 3 (frame type and length)`: 1242 bytes at the default 1350,
  1292 at 1400. Senders budget for the epoch even once it is confirmed, so
  the limit does not change during a connection.
- A packet MAY carry several DATAGRAM frames, and a packet MAY mix
  DATAGRAM and other frames. The relay SHOULD pack all frames for one
  receiver that fall due within 5 ms into a single packet. For three
  speakers, that saves two packet overheads (about 100 bytes each) every
  40 ms. `sendDatagrams(connectionId, list)` packs the frames it is given.
- DATAGRAM frames are **not retransmitted** (`shouldRetransmit() == false`).
- **Not ACK-eliciting:** a packet with only DATAGRAM, ACK and PADDING
  frames elicits no ACK. It still carries a timestamp, like any packet with
  application data, so it gets full replay protection.
- **Not in bytes in flight:** such a packet is not recorded in
  `sentPackets` and does not count toward bytes in flight.
  - A receiver MAY list these packet numbers in an ACK it sends anyway.
    FC-JDK lists every non-eliciting packet (ACK-only too), so ACK ranges
    have holes only where packets were lost (FUDP3 §2.1).
  - A sender MUST ignore ACK ranges covering packet numbers it does not
    track.
  - Gap-based loss detection counts the gap in tracked packets, not packet
    numbers, and RTT is sampled from the largest newly acknowledged tracked
    packet (FUDP3 §3.2, §4.1.1). Both were wrong before Phase 1.
- **Never waits behind stream data at the sender:** a datagram is sent
  the moment it is handed over. It skips the congestion window and the
  pacer, and when frames share a packet, DATAGRAM frames go first.
  - This is a **sender-side** guarantee only. A bulk upload still fills
    any queue further along the path — the receiver's socket buffer, or a
    bottleneck router — because loss-based congestion control backs off
    only when that queue overflows, and audio then waits in it. On loopback
    a 32 MB upload on the same connection put audio at p99 ≈ 0.5 s.
  - The remedy is the call layer's: cap or pause bulk transfers during a
    call (§9.5). With the same upload capped at 8 Mbit/s, audio delay
    stayed at its idle level. A delay-based limit inside FUDP is future
    work (§15, item 10).
- **Send or drop:** if the socket send buffer is full, the datagram is
  dropped immediately. It never waits (`bufferWaitMs = 0`, see
  `Protocol.writeDatagram`).
- **Rate cap:** instead of congestion control, each connection has a
  datagram budget, counted in datagram payload bytes with 100 ms of burst.
  The default is 256 kbps (`NodeConfig.datagramRateBps`). The relay may set
  1 Mbps for its own sending side. Datagrams over budget are dropped at the
  sender. Adapting to congestion is the application's job (§9.4).
- **Every send reports its outcome:** `SENT`, or why it was dropped
  (`NOT_ENABLED`, `TOO_LARGE`, `OVER_BUDGET`, `BUFFER_FULL`,
  `NO_CONNECTION`). Nothing is queued or retried.
- **Delivery to the app:** received datagrams are handed up as
  `onDatagram(peerId, connectionId, bytes)` in arrival order, with no
  ordering and no deduplication beyond the normal packet replay window.
  The callback runs on the node's single receive thread, so it must return
  quickly; the relay forwards inline there (§7.3).
- **Keeps the connection alive:** datagram traffic counts as activity
  for the idle timeout.

### 2.3. Capability

An older FUDP peer treats frame type `0x10` as unknown, and
`FrameType.fromValue` throws, so the whole packet is lost. Worse, deployed
nodes count that as a decrypt failure: after five such packets in a row —
a fifth of a second of audio — they drop *every* packet from the sender's
address for a second, reliable traffic included. (Phase 1 fixed this, FUDP1
§Versioning, but older nodes stay in the field.) An endpoint MUST NOT send
DATAGRAM frames on a connection until the peer has shown it supports them.
FUDP enforces it: datagrams are refused (`NOT_ENABLED`) until the
application calls `enableDatagrams(connectionId)`, and are disabled again
if the peer restarts.

- **With the relay:** the `call.join` response carries `"datagram": true`.
- **Direct:** both ends are call-capable clients by construction, having exchanged `CALL` INVITE and ACCEPT (§3). Nothing more is needed.

The PONG `info` payload is not used for this. It reports what a node is,
not what a particular connection has agreed to.

## 3. Signalling: the `CALL` content type

### 3.1. The envelope

`ContentType.CALL` is **appended after `ROOM_REMOVED`**. The wire carries
the ordinal (`ImMessage.toWireBytes`), so its position is fixed and both
clients MUST use the same ordinal.

**Check before shipping:** an older client decodes the new ordinal as a
`null` content type. It must drop such a message quietly, not show an empty
bubble. If it does show one, gate the feature behind a minimum-version rule.

**Checked 2026-09-23:**

- **Released Android (3.2.2) fails the check.** It stores a `null`-typed
  message and shows its content as a text bubble, so an INVITE appears as
  its JSON. That JSON holds only public keys and the call id. **Decided
  2026-09-23: no version gate.** Calls ship when they work, and a 3.2.2 user
  sees one such bubble per call attempt until they update.
- **This version drops any content type it does not know**, quietly, before
  anything else.
- **The Mac reserves `CALL`** at the same ordinal and treats it as a signal
  that nothing routes. So until Phase 6, a Mac drops calls quietly.

A `CALL` message is an ordinary FIMP message:

- signed with the FIMP0V3 trailer
- deduplicated on `(senderId, id)`
- sealed per mode: `asy2way` for 1:1 over ROAD or DOCK; the entity symkey for a meeting

`content` is JSON with an `op` field. Fields shown `<…>` are required.

- `delegation` is the §4.1 object itself, not a string.
- `expires` is milliseconds since the epoch.
- The reference is `CallSignal` in FC-AJDK. It refuses a signal that lacks
  what its op needs, or whose `callId` is not 16 bytes of hex.

The state machine is `CallSignaller` in the app:

- **Accepting:** it rings only for an INVITE whose delegation is from the
  sender, for this call, for the `transportPub` the INVITE names. It accepts
  an ACCEPT only from the callee it rang, under the same check.
- **Other devices:** on a verified ACCEPT, the caller sends `CANCEL
  answered_elsewhere` to the callee's FID, so the callee's other devices
  stop. The device that answered ignores it.
- **Keys:** each call's transport key is erased when the call ends.

Local call records ("Call, 4:12", "Missed call", "Declined"):

- They are `CALL` messages whose content is `{record, outgoing, duration,
  callId}`. They are written into the chat and never sent.
- A stranger's INVITE is held as a message request and shown as a missed
  call. If the user accepts the stranger, it enters the chat the same way.
- Signals go out through `P2pHandler.sendCallSignal`, on every channel
  at once, and never through the message queue.

### 3.2. 1:1 calls (`type = P2P`, `targetId` = callee)

| `op` | From | Fields | Meaning |
|---|---|---|---|
| `INVITE` | caller | `callId`, `transportPub`, `delegation`, `relay` {`url`} (the relay session id is `callId`), `candidates` (optional), `expires` (ms, now + 45 s), `codecs` = `["opus"]` | Ring the callee. |
| `ACCEPT` | callee | `callId`, `transportPub`, `delegation`, `candidates` (optional) | Answered. The call key can now be derived. |
| `REJECT` | callee | `callId`, `reason` ∈ {`declined`, `busy`, `unsupported`} | Not answered. |
| `CANCEL` | caller | `callId`, `reason` ∈ {`cancelled`, `timeout`, `answered_elsewhere`} | Stop ringing. `answered_elsewhere` goes to the callee's FID once one of its devices accepts, so its other devices stop. |
| `HANGUP` | either | `callId`, `duration` (ms) | Ended. |

Rules:

- `callId` is 16 random bytes, hex-encoded. Two different calls never share one.
- A callee MUST NOT ring for an INVITE whose `expires` has passed. The DOCK copy of an INVITE usually arrives late and shows as a **missed call**.
- The caller MUST send its first ACCEPT-dependent traffic only after verifying:
  - the ACCEPT's FIMP signature, and
  - that the ACCEPT's `delegation` is valid for its `transportPub` (§4.1).
- A device already in a call answers a new INVITE with `REJECT busy`. Call waiting is not in v1.
- `candidates` are the sender's addresses for a direct path (§6.1).
  - They are omitted when the sender has *Always relay* on, or when the peer is not a contact (Decision 8).
  - An INVITE to a stranger therefore never carries the caller's IP. The callee's ACCEPT decides the callee's side on the same terms.
- **Strangers:** an INVITE from a FID the user has not accepted does not
  ring.
  - It goes into Message Requests as a call request, shown as a missed
    call, through the same quarantine as stranger messages (FIMP1 §8).
  - Once the user accepts that FID, the same acceptance that lets their
    messages through, later INVITEs from it ring normally.
  - Accepting a FID does not make it a contact: calls with it are still
    relay-only unless it is also a contact (Decision 8).

### 3.3. Meetings (`type = ROOM` or `TEAM`, `targetId` = entity id)

| `op` | From | Fields | Meaning |
|---|---|---|---|
| `MEETING_START` | host | `meetingId`, `relay` {`url`}, `nonce` (32 bytes, hex), `symkeyVersion`, `authPub`, `title` (optional), `started` | A meeting is open. It appears in the chat as a card with a **Join** button. |
| `MEETING_END` | host | `meetingId`, `duration` | Closed. The card changes to "ended". |

`MEETING_START` is posted to the entity's DOCK like any chat message, so the
meeting shows up in the conversation for everyone, including members who
open the app later.

If the host picks *Notify members*, the same message is also sent through
ROAD (`road.relay` with `targetFids` = members, up to 100). That rings the
members who are online now.

Anyone holding the named symkey can use the `nonce` and `authPub`.
Receivers apply FIMP's membership checks:

- A `MEETING_START` whose verified sender is not a member is discarded (FIMP2 §8.4, FIMP4 §8.2).
- A `MEETING_END` from the host who started the meeting closes the card.
- A `MEETING_END` from any other member is only a hint: the client asks `call.info` (§7.2) and closes the card only if the relay reports the meeting gone.

## 4. Keys

All derivations use HKDF-SHA256 (FTSP13). `‖` is concatenation. Integers are
big-endian and unsigned (`ssrc` is a u32 even where a language stores it
signed).

- A quoted literal, such as `"FreerCall v1 p2p"`, is its UTF-8 bytes with no
  prefix. `str(x)` is a 2-byte big-endian length, then the UTF-8 bytes.
- An empty salt (`∅`) is RFC 5869's all-zero salt.
- `Schnorr(key, m)` is the BCH Schnorr signature that FIMP0V3 uses, over
  SHA-256d of `m`: 64 bytes, deterministic. Each preimage starts with its
  own literal tag, so a signature made for one purpose never verifies for
  another.
- `ECDH(a, B)` is the x-coordinate of `a·B`, 32 bytes.
- `callId` as a salt is its 16 raw bytes, not its hex. A meeting `nonce` is
  its 32 raw bytes.
- Timestamps in signed data (`ts` in `admitSig`) are milliseconds;
  `expiresSec` is seconds.

The reference implementation is `com.fc.fc_ajdk.call` in FC-AJDK. Its
vectors, `callVectors.json`, come from FreerForMac's vector-gen (`CallRef`).
FC-AJDK checks them in `CallVectorTest`; the Mac and FC-JDK copies must
reproduce every value.

### 4.1. Transport identity and delegation

For each call or meeting join, a client makes a fresh secp256k1 keypair
`(tPriv, tPub)`. Its FUDP node for that call runs under `tPriv`. The FID
key signs:

```
delegation = Schnorr_sign(fidPriv,
    "FreerCall-delegate-v1" ‖ str(callOrMeetingId) ‖ tPub(33) ‖ expiresSec(8))
```

and publishes `{fid, fidPub, tPub, expiresSec, sig}`.

A verifier (peer or relay) MUST check that:

- `fidPub` hashes to `fid`
- the signature verifies
- `expiresSec` has not passed (the maximum lifetime is 24 h)
- the id matches the call or meeting in hand

After that, the FUDP peer id `tPub` is treated as `fid` for this call only.
`tPriv` MUST be deleted at hang-up or leave.

### 4.2. The call secret

**1:1** (forward secret):

```
callSecret = HKDF(ikm  = ECDH(tPriv_self, tPub_peer),
                  salt = callId,
                  info = "FreerCall v1 p2p" ‖ str(min(fidA,fidB)) ‖ str(max(fidA,fidB)))
```

**Meeting** (no stronger than the symkey):

```
callSecret = HKDF(ikm  = symkey(entityId, symkeyVersion),
                  salt = nonce,
                  info = "FreerCall v1 meeting" ‖ str(entityId) ‖ u64(symkeyVersion) ‖ str(meetingId))
```

A member may hold two keys at one version (FIMP2 §7.1). It picks the one
whose derived `authPub` (§4.4) equals the `authPub` in `MEETING_START`.
This is decided without sending the key or its hash.

### 4.3. Sender keys and nonces

```
senderKey = HKDF(ikm = callSecret, salt = ∅,
                 info = "FreerCall v1 sender" ‖ str(fid) ‖ u32(ssrc) ‖ u8(keyEpoch))
nonce(12) = u32(ssrc) ‖ u64(seq)
```

- `ssrc` is random for every join. A client MUST pick a new one on
  rejoin, and the relay rejects an `ssrc` already in use in the
  meeting.
- `seq` starts at 0 and increases by 1 for each frame. A sender MUST
  rejoin before `seq` would wrap. At 25 frames/s, a 64-bit counter
  never gets there in practice.
- A receiver works out `senderKey` from the roster entry `(fid, ssrc)`,
  and nothing else. It never trusts a key the sender offers.

### 4.4. Admission key (meetings, and relayed 1:1 calls)

```
authSeed = HKDF(ikm = callSecret, salt = ∅, info = "FreerCall v1 admit", L = 32)
authPriv = authSeed mod n   (retry with info ‖ 0x01 if zero)
authPub  = authPriv · G
```

The host gives the relay only `authPub` (§7.2). A joiner proves it holds
the call key by signing with `authPriv`. The relay learns neither the key nor
anything that would let it derive the key.

For a relayed 1:1 call, the caller registers `authPub` when the callee
accepts. Until then the relay admits only the caller. The callee's join
arrives with an `authPriv` signature that only a peer who completed the ECDH
can produce.

### 4.5. Rekeying a live meeting

A meeting's key follows the entity's symkey. The owner might mint a new
version during the meeting, usually because a member was removed (FIMP2
§3.5, FIMP4 §3.3). When the host stores a symkey newer than the meeting's:

1. The host derives the new `callSecret` and `authPub` from the new version and a new `nonce`.
2. The host sends `call.rekey` with them (§7.2).
3. The relay pushes the rekey notice (`version`, `nonce`, `authPub`, new `keyEpoch`) to every participant.
4. Each participant has **30 s** to prove itself with a signature under the new `authPriv`. The relay drops anyone who does not.
5. A participant that lacks the new symkey version asks for it the FIMP way (FIMP2 §7.4, FIMP4 §7.4) and stays connected until the 30 s runs out.

Senders switch to the new `keyEpoch` as soon as they have it. Receivers keep
the previous epoch's keys for **5 s**, to cover frames already in flight.

The host does not rotate the symkey itself. FIMP forbids automatic rotation
(FIMP2 §7.2), and a meeting is no reason to break that rule. The host only
follows a rotation made by the owner.

A host can also remove a participant directly with `call.control kick` (§7.2). Kicking removes
them from the relay, but they still hold the key. To stop a removed member
decrypting what follows, the owner must rotate the symkey.

## 5. The media frame

This is the `Data` of a DATAGRAM frame. It is the same format on a direct
path and through the relay, and the relay forwards it byte for byte.

```
MediaFrame {
  kind      (1)  = 0x01 (media frame, v1)
  flags     (1)  bit0 VAD (voice active), bit1 DTX (comfort-noise frame),
                 bit7 CONTROL (payload is a probe or report, not Opus), bits 2-6 = 0
  routeId   (4)  assigned by the relay at join; 0 on a direct path
  ssrc      (4)
  seq       (8)
  timestamp (4)  48 kHz sample clock, random start per ssrc
  level     (1)  audio level, 0..127 = -dBov (RFC 6464), 127 = silence
  keyEpoch  (1)
  ciphertext     AES-256-GCM(senderKey, nonce, opus, aad = the 24 header bytes)  — includes 16-byte tag
}
```

The header is 24 bytes, plus a 16-byte tag. A 40 ms Opus frame at 24 kbps is
about 120 bytes, so each media frame is about 160 bytes.

**What the relay can see:** who is sending, how loud, how often, and for how
long. It cannot see or change the audio. Changing `level` or anything else
in the header breaks the GCM tag. That is also why the relay forwards the
frame without rewriting it.

A receiver MUST drop a frame if any of these holds:

- its `(ssrc)` is not in the roster
- its `keyEpoch` is not current or in its 5-second grace period
- it fails authentication
- its `seq` has already been seen in a 1024-frame sliding window for that `ssrc`

A receiver that sees a `kind` it does not know MUST ignore that datagram.

### 5.1. Signed attestations

Frame encryption proves only that the sender holds the call key, and every
member holds it. Attestations prove *which* participant sent a frame.

```
Attestation {
  kind      (1)  = 0x02
  routeId   (4)
  ssrc      (4)
  firstSeq  (8)
  count     (1)  1..64
  digests   (8 × count)  for seq = firstSeq .. firstSeq+count-1:
                         first 8 bytes of SHA-256(the complete MediaFrame bytes)
  sig       (64) Schnorr(tPriv, "FreerCall-attest-v1" ‖ str(callOrMeetingId) ‖ every byte above)
}
```

**Sender:**

- Emits one attestation each second, covering every frame sent since the
  previous one, including DTX and CONTROL frames.
- Emits one early if `count` would exceed 64.
- Emits a final one before `call.leave` or hang-up.
- `seq` is consecutive, so the ranges tile with no gaps.

**Delivery:** attestations travel reliably, as a FUDP NOTIFY
(`dataType = 0`), not as datagrams. A lost attestation would otherwise look
exactly like a forgery. This costs about 2.3 kbps per sender at 25
frames/s.

**Relay:**

- MUST forward each attestation unchanged to every participant that received at least one frame of that `ssrc` in its range.
- MAY verify attestations itself. It MAY remove a participant whose attestations do not match the frames it relayed.

**Receiver:**

1. **Checking the signer:** it verifies each roster entry's delegation
   itself (§4.1), which gives it the `tPub` bound to that FID. It accepts
   an attestation only if the signature verifies under the `tPub` of the
   participant the roster names for that `ssrc`. If the relay has mapped
   an `ssrc` to the wrong participant, the signatures fail.
2. **Keeping digests:** it plays frames as they arrive, since waiting
   would add a second of delay, and keeps each played frame's digest for
   5 s.
3. **Unverified audio:** if a played frame's digest does not match its
   attestation, or no attestation covering it arrives within 3 s, that
   `ssrc` is **unverified**:
   - The receiver stops playing it at once.
   - The UI shows that audio claimed to be from *that FID* could not be
     verified.
   - The receiver does not resume it for the rest of that join.
4. **What can slip through:** at most about 3 s of unattributed audio
   can play before it is caught. The UI never says who spoke unless
   the attestations bear it out.

The same rules apply on a direct 1:1 path. There the FUDP connection
already authenticates the peer, so attestations should never fail. A
failure means a bug, and the user is warned.

## 6. Paths for a 1:1 call

### 6.1. Candidates

A candidate is `{"t": "map"|"lan"|"home", "a": "ip:port"}`:

- **`map`:** the address a MAP server sees for the call's FUDP socket. The call node sends one `map.register` to the user's own MAP server when the call starts, and keeps registering every 25 s during the call.
- **`lan`:** the device's own interface addresses, only if they are private (RFC 1918 or a ULA). These let two devices on the same Wi-Fi connect without going through NAT.
- **`home`:** the sender's `freer.home.FUDP`, if one is set.

### 6.2. Setting up the call

1. **Caller:** `call.create` on its CALL relay (§7.2). Then it sends INVITE with `relay` and its candidates, and joins the relay.
2. **Callee:** when the user answers, sends ACCEPT with its own candidates. It can derive `callSecret` at once, because the INVITE carried the caller's `transportPub`.
3. **Caller:** on a verified ACCEPT, derives `callSecret` and calls `call.register` with `authPub`.
4. **Callee:** joins the relay. The join fails with 409 until the caller has registered, so the callee retries every 250 ms for up to 10 s.
5. **Audio starts on the relay** as soon as both ends are in the roster.
6. **In parallel, NAT punching:** each side sends FUDP HELLO to every peer candidate, every 100 ms for up to 3 s. HELLOs are harmless and open the sender's own NAT mapping. Only the side with the **lexicographically lower FID** goes on to send the first encrypted DATA packet, so the two do not build two connections to each other.
7. **Checking the direct path:** the connection is accepted once its FUDP peer id equals the `transportPub` from the other side's verified delegation. Then each side sends a `probe` datagram (a MediaFrame with `routeId = 0` and an empty payload) and waits for the other side's.
8. **Switching over:** once probes have passed in both directions, both sides send audio only on the direct path. They keep receiving on the relay for 5 s, then `call.leave` the relay.
9. **Falling back:** if the direct path goes quiet for 2 s, both sides switch back to the relay, rejoining if they had left. Punching is not retried during that call.

If the caller has no CALL relay configured, it uses the callee's
`home.CALL@No1_NrC7`. If neither side has one, the call needs direct
candidates on both sides, and fails with "no route" when punching fails.

### 6.3. Ringing and reaching the callee

The caller sends each INVITE, CANCEL, REJECT and HANGUP on every channel it
can, all at once:

- **FUDP direct:** when the peer is reachable.
- **ROAD:** to the peer's `home.ROAD`. It reaches a device registered in that server's MAP. The app already keeps MAP registered every 25 s (`ClientGroup.startMapKeepalive`).
- **DOCK:** as the lasting record.

Unlike chat, these signals ignore the opt-in *Use ROAD relay* and *Use
direct FUDP* settings. The fee a ring costs is part of placing a call. The
caller is told if its ROAD balance is too low to ring.

Receiving three copies of one message is expected; the `(senderId, id)`
check drops the extras.

Only a device that is actually registered and running can ring. That depends on the platform:

- **Mac:** a running app can ring.
- **Android, app open or recently used:** it rings.
- **Android, in the background:** it rings only with **Available for calls** turned on (off by default). This keeps a small foreground service running the MAP keepalive, and asks for an exemption from battery optimisation. Without it, Doze stops the keepalive and an incoming call shows as a missed call on the next DOCK fetch.

Freer uses no Google or Apple push service. Putting its call records on a
third party's servers is exactly what this app exists to avoid.

## 7. The CALL component (`CALL@No1_NrC7`)

This is a new FAPI component, to become FAPI16 (§13). It is registered on
chain like any other service. Like ROAD, it depends on a co-hosted MAP, and
here that is only for its clients' own `map.register` calls.

### 7.1. State

A **meeting** on the relay holds:

- `meetingId`
- `hostFid`
- `authPub` and `keyEpoch`
- `routeId` — the relay's random 32-bit handle for each participant's frames
- a roster of `{fid, tPub, ssrc, connectionId, joinedAt, mutedByHost}`
- the pinned ssrcs
- the forwarding state

The relay stores no audio, and it keeps nothing once the meeting closes.

### 7.2. Methods

All methods use FUDP request/response over a connection that authenticates
as `tPub`. Every request other than `call.info` and `call.stats` carries the
caller's delegation, and the relay verifies it (§4.1). For `kind = p2p`, the
`meetingId` is the `callId`.

| Method | Who | Params | Result |
|---|---|---|---|
| `call.create` | host | `meetingId`, `kind` ∈ {`p2p`, `meeting`}, `authPub` (a meeting sends it now; `p2p` sends it later, §4.4), `maxParticipants` (≤ 64; `p2p` defaults to 2), `maxCostPerMinute` | `price` {`perKBIn`, `perKBOut`}, `maxParticipants`. The host's `routeId` comes from its `call.join`. |
| `call.join` | anyone | `meetingId`, `ssrc`, `maxCostPerMinute` (optional), `ts` (ms), `admitSig` = Schnorr(`authPriv`, `"FreerCall-admit-v1" ‖ str(meetingId) ‖ tPub ‖ u32(ssrc) ‖ u64(ts)`) | `routeId`, `datagram: true`, `roster`, `keyEpoch`, `speakers` (N) |
| `call.leave` | participant | `meetingId` | — |
| `call.register` | host (`p2p` only) | `meetingId`, `authPub` | — |
| `call.rekey` | host | `meetingId`, `symkeyVersion`, `nonce`, `authPub` | new `keyEpoch` |
| `call.prove` | participant | `meetingId`, `keyEpoch`, `ts`, `admitSig` under the new `authPriv` | — |
| `call.control` | host | `meetingId`, `action` ∈ {`mute`, `unmute`, `lockMute`, `kick`, `pin`, `unpin`, `handoverHost`, `end`}, `target` (fid or ssrc) | — |
| `call.hand` | participant | `meetingId`, `raised` (bool) | — |
| `call.report` | participant | `meetingId`, per-ssrc `{loss, lateLoss, jitterMs}` over the last 2 s | — |
| `call.info` | anyone | `meetingId` | `open` (bool), `participants` (count), `started`. Used for the meeting card and to confirm a meeting has ended. |
| `call.stats` | anyone | — | Operator counters, like `road.stats` |

Rules for every request that carries a delegation:

- **The delegation must be for this connection:** its `tPub` must be the key
  the FUDP connection authenticated with. Otherwise a stolen delegation
  could be replayed from another connection. The relay admits, names and
  bills the delegated FID.

Rules for `call.join`:

- **Admission:** once `authPub` is known, every join needs `admitSig`, the
  host's included. Before a `p2p` host registers it, only the host may join,
  and anyone else gets 409 and retries (§6.2 step 4).
- **Clock:** `ts` MUST be within ±60 s of the relay's clock.
- **Replay:** the relay caches each `(meetingId, tPub, ts)` and rejects a repeat.
- **Two devices, one FID:** two sessions for the same FID but different `tPub` are separate participants. The UI groups them.

Pushed by the relay (FUDP NOTIFY with `dataType = 1`, JSON with a `type` and the `meetingId`):

- `roster` — someone joined or left, or a mute or host changed: `{type, meetingId, host, roster: [{fid, ssrc, routeId, delegation}]}`. The delegation is the JSON the participant sent, so receivers can verify it themselves (§5.1). `ssrc` and `routeId` are unsigned numbers.
- `rekey` — as in §4.5.
- `muted` — to the participant concerned.
- `kicked` — `{type, meetingId, reason}`; `reason = balance` after an unpaid grace period (§7.5).
- `ended`
- `uplink` — every 2 s. The relay's own loss and jitter counts for each sender's stream, which only the relay can see.

Other rules:

- **Admission and control are separate:** `call.join` checks only the `admitSig`. The host alone may call `call.control`, `call.rekey` and `call.register`, which the relay checks against the delegated FID.
- **If the host leaves:** the host role passes to the participant who has been present longest. The relay announces this in the roster.
- **Team membership (optional):** a relay with a BASE component MAY also check a Team meeting's joiners against the on-chain member list. It cannot do this for a Room, which has no chain record.
- **Attestations** reach the relay as FUDP NOTIFY with `dataType = 0` and the raw attestation bytes (§5.1), and leave it the same way. The relay passes on only those naming the sender's own `routeId` and `ssrc`.
- **Errors:** 400 malformed, 401 delegation or `admitSig` does not verify, 402 balance below one minute, 403 not the host, or the call is full, 404 no such call, 409 not open yet, `ssrc` in use, or a replayed join, 429 over a limit (§7.6).

### 7.3. Forwarding

On each DATAGRAM, the relay:

1. Looks up the sender by connection.
2. Checks that the frame's `routeId` and `ssrc` belong to that connection, and drops it if not. **This is what stops one participant sending as another.** The key alone cannot: every member holds it.
3. Drops the frame if the host has muted that `ssrc`.
4. Updates that `ssrc`'s level and loss counters.
5. Forwards the frame unchanged to every other participant for whom that `ssrc` is currently selected (§7.4).
6. Remembers, for each receiver and `ssrc`, the range of `seq` it forwarded, so it can pass on the matching attestations (§5.1).

A participant never receives its own frames.

### 7.4. Speaker selection

Every 100 ms the relay ranks the `ssrc`s. The score is the smoothed `level`
over the last 300 ms, counting only frames with VAD set.

- **Who is forwarded:** the top **N** speakers (default 3, maximum 5), plus any pinned `ssrc`s.
- **Replacing a speaker:** a new speaker displaces a selected one only when it has been at least 6 dB louder for 300 ms. This stops rapid switching between speakers.
- **When N drops:** a receiver whose `call.report` shows downlink loss above 10 % gets N reduced by 1, down to a minimum of 1. N goes back up after 10 s without such loss.
- **Receive side:** each client decodes up to N+pinned streams and mixes them itself.

### 7.5. Charging

This follows FAPI4, measured per **minute** rather than per request. Each
participant pays for their own traffic:

```
minuteCost = ceil(bytesIn_minute / 1024) · pricePerKBIn + ceil(bytesOut_minute / 1024) · pricePerKBOut
```

- **When it is taken:** charged at the end of each minute of a participant's presence, and for the part-minute when it leaves. The charge key is `call:<meetingId>:<fid>:<ssrc>:<minute>`, where `minute` counts from that join, so it is idempotent (FAPI4 §5.2). The `ssrc` is in it because two devices of one FID are separate participants.
- **Joining:** `call.join` needs enough balance for one minute at the full speaker count.
- **Running low:** if a minute cannot be paid, the relay sends a `balance` notice (`{type, meetingId, graceSeconds}`). After 60 s more without payment it sends `kicked` and removes the participant.
- **Cost cap:** a `maxCostPerMinute` in `call.join` caps the charge. The relay reduces that participant's N before it would go over the cap.
- **Price zero:** an operator may set it to offer a free relay.

For scale, at 24 kbps Opus and 40 ms frames:

| Traffic | Per participant per minute | Rate |
|---|---|---|
| In | about 0.4 MB | about 50 kbps once FUDP overhead is included |
| Out (N = 3, frames packed) | about 0.8 MB | |

### 7.6. Limits

| Limit | Default |
|---|---|
| Participants per meeting | 64 |
| Meetings per host FID at once | 4 |
| `call.join` attempts per `tPub` | 10 per minute |
| Datagram rate in, per participant | 64 kbps; excess is dropped |

A meeting with no participants closes after 60 s.

The relay SHOULD keep its UDP receive buffer small, not raise it to absorb bursts. A relay that falls behind should drop frames. A deep buffer instead turns overload into a standing queue: in the Phase 1 bench, a raised `rmem_max` turned a CPU-starved relay's backlog into seconds of delay on every frame. Audio that late is worthless (Decision 1).

## 8. Meetings in a Room or Team

**Choosing the relay:**

1. The entity's `home["CALL@No1_NrC7"]`. For a Team that is the on-chain `home`; for a Room it is `RoomInfo.home`.
2. Otherwise, the host's own configured CALL service.

A Team or Room owner who wants every meeting on one relay sets the entity's
`home`.

**Starting:**

1. The host picks the entity's newest symkey version, makes a `meetingId` (`"mtg_" + 24 hex`) and a `nonce`, and derives the keys.
2. It calls `call.create`, then posts `MEETING_START`.
3. It joins.

**Joining:** the member taps the card, derives the keys from the named
symkey version, and joins. A member without that key version is offered the
normal key request (SYMKEY_IDENTITY_SPEC §3). There is no separate request
path for meetings.

**Ending:** the host sends `call.control end` and posts `MEETING_END`. A
meeting whose host just disappears ends when the relay closes it (§7.6).
Any member may then post `MEETING_END` for it, and clients accept that only
once the relay confirms the meeting is gone.

**Where the host's powers come from:** being the host is a relay role, not
a FIMP role. The Room or Team owner has no special power in a meeting they
did not start, unless the host hands it over.

## 9. The media engine

### 9.1. Codec

Opus (RFC 6716), built from libopus:

- **Android:** through the NDK, about 300 KB per ABI. MediaCodec cannot be used: its Opus encoder needs API 29 and minSdk is 28.
- **Mac:** as a Swift package.

Settings:

| Setting | Value |
|---|---|
| Sample rate | 48 kHz |
| Channels | mono |
| `OPUS_APPLICATION_VOIP` | yes |
| Bitrate | VBR, 24 kbps target, adapting between 12 and 32 kbps |
| In-band FEC | on |
| DTX | on |
| Frame length | 40 ms by default; 20 ms when the RTT is below 50 ms (direct LAN) |

DTX matters in a meeting: a silent participant sends about 2.5 frames a
second instead of 25.

### 9.2. Capture and playout

**Android:**

- Capture and play out through AAudio, with the `VOICE_COMMUNICATION` input preset and usage and `AudioManager.MODE_IN_COMMUNICATION` set. That gives the platform's echo cancellation, noise suppression and gain control, with the smallest buffering the device offers. `AudioRecord`/`AudioTrack` with the same settings remain as a fallback; on devices without a low-latency voice path (the Samsungs in §14) the two perform the same.
- Keep only two bursts (or two frames) in the output buffer and grow it on underrun.
- Route with `setCommunicationDevice` (API 31+) for Bluetooth, speaker and earpiece.
- Handle audio focus, and put the call on hold when a phone call arrives.

**Mac:**

- `AVAudioEngine` with `setVoiceProcessingEnabled(true)` on its input node.

### 9.3. Jitter buffer and loss

Each `ssrc` gets its own adaptive buffer:

- **Target delay:** the 95th percentile of arrival jitter over the last 2 s, kept between 40 and 300 ms.
- **Shrinking:** by dropping frames only during DTX or silence.
- **Growing:** by stretching with packet-loss concealment.
- **Lost frame:**
  - If the next frame is already buffered, decode the lost one from its FEC data (`opus_decode(…, decode_fec=1)`).
  - Otherwise, use packet-loss concealment (`opus_decode(NULL)`).
- **Late frame:** discarded once its play time has passed.
- **Mixing:** decoded streams are summed and soft-clipped before playout.

### 9.4. Adapting to the network

Senders adapt on the relay's `uplink` report, or the peer's report on a direct path, which arrives as a 1 s `report` datagram with `routeId = 0` and `flags = 0x80`:

| Loss | Bitrate | Opus `PACKET_LOSS_PERC` |
|---|---|---|
| Below 2 % | Step back up | — |
| 2–10 % | Keep | Loss × 1.5 |
| Above 10 % | 16 kbps | 20 |
| Above 25 % | 12 kbps, 60 ms frames | — |

**Delay targets:** our stack (frame, jitter buffer and our part of the
output buffer) adds ≤ 100 ms beyond the devices' own audio paths and the
network's one-way delay. The first target, mouth to ear ≤ 300 ms relayed and
≤ 200 ms direct on a 50 ms RTT path, turned out to be unreachable on common
phones: on two Samsungs the voice-call capture and playout paths alone take
~235–265 ms, whatever API or stack is used (§14, Phase 2).

### 9.5. Bulk transfers during a call

A file upload or download on the same path fills the queues audio passes
through (§2.2) and can add hundreds of milliseconds, far past the delay
targets above. While a call is live:

- **Clients** SHOULD cap stream traffic on every FUDP connection with
  `setStreamRateCap(connectionId, bitsPerSecond)`, or pause bulk
  transfers. The cap applies to all connections, not only the call's,
  because every connection shares the device's uplink. It does not affect
  datagrams. Provisional default: 1 Mbit/s, to be tuned in Phase 3.
- **The relay** SHOULD cap stream traffic it sends to a participant (for
  example a DISK download on the same server) for as long as the
  participant is in a call, since that traffic shares the participant's
  downlink with the forwarded audio.
- The cap is removed when the call ends.

## 10. What each client shows

- **1:1 call:** a call button in P2P chat; incoming, outgoing and in-call
  screens; mute, speaker and route controls. The call is recorded in the
  chat as "Call, 4:12", "Missed call" or "Declined". The record is a local
  entry made from the signalling. It is not another message on the wire.
- **Meeting:** a Room or Team chat button that starts a meeting; the
  meeting card with a live participant count; an in-meeting screen with
  the participant list, who is speaking, raised hands and host controls.
- **Always shown:**
  - A lock with "End-to-end encrypted".
  - The path in use: "Direct" or "Relayed via &lt;relay&gt;".
  - An estimate of the relay fee while a relayed call is running.
- **Nobodies:** a participant whose FID is a nobody gets the skull mark
  (NOBODY_SPEC §2). Anyone holds a nobody's key, so a call with one is
  as private as a public square. Calling a nobody asks for confirmation
  first (NOBODY_SPEC §3).
- **Settings:** *Available for calls* (Android), *Always relay*, the
  default relay, and a per-minute cost cap.

## 11. Platform notes

### 11.1. Android

- **Permissions:** `RECORD_AUDIO` is already declared. Add `FOREGROUND_SERVICE_MICROPHONE`, `FOREGROUND_SERVICE_PHONE_CALL` and `BLUETOOTH_CONNECT`.
- **`CallService`:** a foreground service with `foregroundServiceType="microphone|phoneCall"` (both are required from API 34).
- **Incoming call:** shown as a full-screen intent notification, which needs `USE_FULL_SCREEN_INTENT` on API 34+.
- **Telecom:** v1 uses a self-managed `ConnectionService` only if it proves necessary for Bluetooth headset buttons. Otherwise it stays out of Telecom.

### 11.2. Mac

- **Entitlement:** a microphone usage string, and `com.apple.security.device.audio-input` in the sandbox.
- **Ringing:** only while the app runs. A menu-bar mode keeps it running with the window closed.

### 11.3. Process isolation (Android, after v1)

Decision 5 keeps the FID private key out of the media code. After v1, the
media engine and the call's FUDP node move into a `:voice` process. The main
process then hands that process only:

- the delegation
- `tPriv` (made fresh for the call)
- `callSecret` (or the symkey-derived secret, for a meeting)

A memory-corruption bug in libopus or the audio stack can then reach, at
most, the current call. It cannot reach the wallet.

## 12. Security considerations

1. **What a relay learns:** who joined which meeting and when, each
   speaker's loudness and speaking pattern, and traffic volume. It
   cannot hear audio, cannot insert audio, and cannot send as a member.
   It could *drop* frames or refuse service, as any relay can. The
   audio level is left readable deliberately (§15, item 1).
2. **What a DOCK or ROAD learns:** that a call happened between two
   FIDs, or that a meeting started in an entity. The same metadata IM
   already exposes (FIMP1 §7.4).
3. **Members sending as each other:** stopped twice over.
   - The relay binds each `ssrc` to the sender's authenticated connection (§7.3).
   - Receivers independently check every played frame against that sender's signed attestations (§5.1). An honest relay stops the attempt immediately; a colluding relay is caught by receivers within about 3 s.
   - *In a 1:1 call:* ECDH plus both signed delegations already authenticate both ends outright. Attestations are a second check.
4. **A malicious relay** cannot hear audio, and cannot make frames that
   authenticate, because it has no `callSecret`. It could lie in the
   roster, mapping an `ssrc` to the wrong FID, or replay one member's
   frames under another's `ssrc`. Attestations catch both: the
   signature is by the delegated `tPub` and covers the `ssrc` (§5.1).
   What remains is what any relay can do: drop frames, withhold
   attestations (which makes that speaker unverified and silent, never
   mislabelled), or refuse service.
5. **Replay:**
   - *Media frames:* the per-`ssrc` sequence window (§5) rejects a replayed frame, and the relay's hop is FUDP-protected on top of that.
   - *`call.join`:* the timestamp window and the replay cache (§7.2).
   - *Signalling:* the FIMP `(senderId, id)` check.
6. **Forward secrecy:** 1:1 calls have it (§4.2). Meetings do not
   (Decision 6). A later leak of the symkey exposes any meeting audio
   that someone recorded off the wire.
7. **Leaking IP addresses:** direct candidates are sent only to
   contacts, and never with *Always relay* on (Decision 8). A relayed
   call reveals each side's IP only to the relay.
8. **Denial of service:**
   - The relay caps datagram rates, `call.join` attempts and meetings per host (§7.6).
   - A stranger can make you ring only by paying ROAD to reach you.
   - Stranger calls go through the existing quarantine (FIMP1 §8). They do not ring until the user accepts the FID (§3.2).
9. **No plaintext fallback:** a client that cannot derive a key or
   verify a delegation MUST fail the call. It MUST NOT send unencrypted
   audio (compare FIMP1 §7.3).

## 13. Protocol documents

New documents are written once the wire format they describe is frozen. The
DATAGRAM frame froze at the end of Phase 1 and is specified in FUDP7; the
rest waits for Phases 3 and 4. The FUDP1, FUDP3 and FUDP4 amendments were
made early because they describe behaviour that FC-JDK already has, some of
which changed for every frame type.

| Document | Change |
|---|---|
| `FUDP/FUDP7V1_Datagram.md` | New: §2 of this spec. **Drafted** 2026-09-23; FUDP0 lists it and FUDP1's frame table points to it. |
| `FUDP/FUDP1V1_CoreTransport.md` | Add `0x10` to the Frame Type Summary, pointing to FUDP7. **Done** 2026-09-22, with the unknown-frame rules and the packet size budget. |
| `FUDP/FUDP3V1_LossAndCongestion.md` | **Done** 2026-09-22: DATAGRAM not ack-eliciting, ACKs listing untracked numbers, loss gap in tracked packets, RTT sampling, stream rate cap, recording every non-eliciting packet, ACK frames limited to one packet. |
| `FUDP/FUDP4V1_Security.md` | **Done** 2026-09-22: an unparseable authentic packet is not a decrypt failure. |
| `FAPI/FAPI16V1_CALL.md` | New: §7. |
| `FAPI/FAPI3V1_Components.md` | Add CALL to the component list. |
| `IM/FIMP5V1_Call.md` | New: §3, §4 and §8. |
| `IM/FIMP0` | Add `CALL` to the ContentType ordinal table. |

## 14. Implementation plan

Each phase ends at a **gate**. A phase does not start until the gate before
it has passed.

### Phase 0 — Decide

Done 2026-09-22 (§15).

### Phase 1 — Transport

**Work starts in the server repo, `~/Desktop/Freeverse/FC-JDK`.** Its FUDP
is where the reference implementation lives. `packet/`, `Frame`,
`FrameType`, `AckManager` and `CongestionControl` are identical to FC-AJDK's
copy, apart from package names. It also already has the lossy-network tests
the change needs (`LossyRequestResponseTest`, `WanSimulationThroughputTest`,
`AckRetentionTest`), and the relay benchmark has to run there anyway.

1. **FC-JDK `fudp/`:**
   - `DatagramFrame` — done
   - the send path: datagrams ahead of streams, send-or-drop, per-connection budget — done
   - the `onDatagram` callback on the node listener — done
   - ACK handling for untracked packet numbers — done
   - the stream rate cap (§9.5) — done
   - fixed on the way: loss detection counted untracked packet numbers;
     an unknown frame black-holed the sender's address; the receive loop
     slept 1–10 ms when the socket was empty
2. **FC-JDK tests:**
   - `DatagramFrameTest`: encoding round trip, a packet with several frames, the too-large case
   - `DatagramLossTest`: 10 % loss on loopback. Datagrams are never retransmitted, and a stream transfer on the same connection finishes unchanged
   - `DatagramPriorityTest`: during a bulk upload on the same connection, the sender never makes a datagram wait or drops it (the downstream delay is measured and printed); with the upload capped (§9.5), audio delay stays within 5 ms of idle
   - `UnknownFrameTest`: a peer without `0x10` loses only that packet, and the connection survives
   - `DatagramRelayBench`: 1 sender, 60 receivers, 25 to 500 pps. Run explicitly (`-Dtest=DatagramRelayBench`); the delay gate only with `-Dbench.latencyGate=true`
3. **FC-AJDK:** port the same diff. Most of it applies unchanged. `Protocol.java` and `FudpNode.java` differ between the two copies, so those parts are merged by hand. **Done** 2026-09-22 (Freer branch `fudp-datagram`), with the tests, which run on the JUnit Platform. An FC-AJDK node has no file-backed REQUEST path, so a request over 16 MB sent *to* it is dropped: the Android copy of `DatagramPriorityTest` uploads 12 MB.
4. **Mac FCTransport:** the same changes. **Done** 2026-09-22 (FreerForMac branch `fudp-datagram`), with ports of the tests.
5. **vector-gen:** DATAGRAM frame encoding vectors, checked by all three. **Done** 2026-09-23: `datagram_frame`, `datagram_payload` and `datagram_max_size` in `fudpVectors.json`, checked by `DatagramVectorTest` in FC-JDK and FC-AJDK and by `DatagramFrameTests` in FCTransport. Each repository keeps a copy of the file; regenerate it in vector-gen and copy it to all three.

**Gate:**

- One server core forwards at least 20 000 datagrams/s, with p99 added delay below 5 ms.
  - "Per core" is forwards per CPU-second of the relay's receive thread. "Added delay" is the wait before the relay's listener runs plus its fan-out to the last receiver.
  - Throughput: **passed** — about 50 000 forwards per CPU-second at 21 000 forwards/s (on a Mac).
  - Delay: **passed** 2026-09-23, three runs in a row. The relay and the sender ran on an OVH VPS in Singapore, and the 60 receivers ran on a VPS in Europe (`-Dbench.role=relay`, `clients -Dbench.part=sender|receivers`). The relay's 60 copies of each datagram went out over its real network interface, while inbound stayed on one clock. In the first run, inbound p99 + hold p99 was 1.0 + 2.9 ms at 25 pps and 1.2 + 2.7 ms at 350 pps (21 000 fwd/s), with nothing lost or dropped. Hold, the relay's own fan-out, is about 25 µs per copy.
  - Throughput on that host: 32 000 forwards per CPU-second at 350 pps. At 500 pps (30 000 fwd/s) the relay thread used 82% of a core and inbound p99 rose to 18 ms, so one core tops out at about 25–30k fwd/s, roughly five 64-person meetings with three speakers each. That is the ceiling for Phase 4's load test.
  - Where not to measure: every host on one machine. On a 4-vCPU VPS the 61 client nodes starved the relay thread of CPU, and Linux charged their loopback receive work to it. On a Mac the scheduling tail varied from 2 to 10 ms p99 between runs. With the sender on another continent, internet jitter (about 6 ms one way at p99, Europe to Singapore) swamped the relay's own delay.
- The wire format is frozen, and the protocol docs in §13 are drafted. **Passed** 2026-09-23 for the DATAGRAM frame: vectors agree across all three implementations and FUDP7 is drafted. The call-layer documents in §13 (FAPI16, FIMP5) describe Phases 3 and 4, and are written when those formats freeze.

### Phase 2 — Audio spike (Android only)

- libopus through the NDK, `AudioRecord`/`AudioTrack`, the jitter buffer, a mixer.
- Two phones on direct FUDP datagrams, then through a throwaway "forward everything" relay.
- Network faults injected with `tc netem` on the relay host: 5 % loss, 60 ms jitter.

**Gate:**

- ~~Delay is measured by recording a click through a loopback cable: ≤ 300 ms relayed.~~
  **Restated 2026-09-23:** our stack adds ≤ 100 ms beyond the devices' own
  audio paths and the network's one-way delay (§9.4).
- Speech stays intelligible at 5 % loss.
- There is no audible echo on speakerphone on at least three phone models.

**If this gate fails, stop and reconsider WebRTC's audio stack** (keeping
FUDP as the transport) before building any further.

**Built** 2026-09-23, Freer and FC-JDK branch `voice-spike`; the gate runs are
described in `Freer/docs/VOICE_SPIKE_GUIDE.md`.

- **Codec:** libopus 1.5.2, vendored without its DNN models, through JNI.
  The packaged library is 394 KB for arm64-v8a and 298 KB for armeabi-v7a.
- **Engine** (`app/.../call/engine/`): capture, playout with a mixer, and
  the §9.3 jitter buffer, which has JVM tests. Phase 3 keeps all of it.
- **Test screen:** *Tools → Voice test*, in debug builds only. Two phones
  can connect directly, or any number can join the relay.
- **Relay:** `VoiceSpikeRelay` in FC-JDK forwards every frame to everyone
  else.
- **Frames:** the §5 header with `kind = 0x7E` and the Opus data in the
  clear, so FUDP's hop encryption is the only protection. For the spike,
  `flags` bit 1 marks the first frame after a DTX run, so the gap before it
  is not counted as loss.
- **Checked on two emulators,** relayed and direct: no loss on a clean
  path. At a simulated 5% loss, FEC recovered 47 of the 48 dropped frames.

**Gate results** 2026-09-23, on a Galaxy S22+ and a Galaxy A05s:

- **Delay: passed as restated.** Our stack adds ~40–80 ms: a 20 ms frame
  and a 20–60 ms jitter buffer. The rest is not ours:
  - Measured by recording a flick, with the far phone muted. Two phones in
    one room feed back, and the loop period equals the one-way delay.
  - Each phone's own voice paths took ~235–265 ms: microphone ~85–100 ms,
    speaker 145–165 ms. Loopback mode on the A05s (no network) measured
    ~270 ms mic to speaker.
  - AAudio was granted only the normal 20 ms-burst path on both phones,
    even when exclusive mode was asked for, and gained nothing. WebRTC would
    use the same voice paths.
  - Mouth to ear: ~360 ms on Wi-Fi direct, ~510–540 ms through the
    Singapore relay. The phones were in Shanghai on a roaming Singapore
    SIM, with an RTT of 130–190 ms. On that route the first run lost 65% of
    the relay's traffic to the phones, a property of the route.
- **5% loss: passed.** Speech could be followed without repeats; FEC
  recovered ~93% of lost frames. A three-phone relay call also worked.
- **Echo: passed on two models;** a third is still to be tested.
- **Changes the gate runs caused:** the jitter buffer now also skips quiet
  frames, and after a second over target any frame, so continuous speech
  does not keep extra delay. Capture drops a standing backlog (none was
  seen). The output buffer holds two frames instead of the voice path's
  80–100 ms minimum. There is an AAudio backend, and a loopback mode for
  measuring a device.

### Phase 3 — 1:1 calls (Android)

Progress, in milestones:

1. **Call cryptography: done** 2026-09-23 (Freer and FreerForMac branch
   `voice-calls-p3`). `com.fc.fc_ajdk.call` in FC-AJDK holds `Delegation`,
   `CallKeys` (the p2p and meeting secrets, sender keys, admission, frame
   nonce), `MediaFrame`, `Attestation` and `ReplayWindow`. `CallCryptoTest`
   covers each property the spec relies on, and `callVectors.json` pins the
   bytes.
2. **`CallComponent`, `kind = p2p`: done** 2026-09-23 (Freeverse branch
   `voice-calls-p3`). The rules are in `fapi/components/call/CallRelay`,
   testable without FAPI or sockets. `CallComponent` wires them to requests,
   billing, and the new `FudpEventAware` hook, through which `FapiServer`
   now passes datagrams, notifies and disconnects to components. The call
   cryptography is ported there, and reproduces `callVectors.json`.
   `CallRelayTest` covers admission, forwarding, spoofing, attestations,
   billing and limits; `CallRelayFudpTest` runs a whole call over real FUDP.
3. **Signalling: done** 2026-09-23 (Freer and FreerForMac branch
   `voice-calls-p3`). `ContentType.CALL`, `CallSignal`, `CallSignaller`
   (`CallSignallerTest`, 14 cases), the ImManager wiring, the
   all-channel send, and call records in the chat. Placing and answering a
   call from the UI, and using the relay, come in milestone 4.
4. `CallService`, `CallActivity` and calls over the relay.
5. Direct paths, *Always relay* and *Available for calls*.

- **FC-AJDK:**
  - `CallKeys`, `MediaFrame`, `Attestation` and `Delegation`
  - vector-gen vectors for the delegation, `callSecret`, `senderKey`, `authPub`, one sealed frame and one attestation
- **FC-JDK:** `CallComponent` with `kind = p2p`: create, join, register, leave, forwarding, charging.
- **App:**
  - `ContentType.CALL` and `CallSignaller`
  - ringing over FUDP, ROAD and DOCK, with expiry and the missed-call record
  - `CallService`, `CallActivity`, the full-screen intent
  - the relay path, then candidates, punching and the direct upgrade and fallback
  - *Always relay* and *Available for calls*

**Gate:**

- A call works phone to phone on Wi-Fi to Wi-Fi, Wi-Fi to mobile data, and mobile data to mobile data.
- It survives a network change mid-call (FUDP path migration).
- A second device of the callee stops ringing when the first answers.
- An old client ignores `CALL` messages without errors.
- A relay patched to relabel an `ssrc` silences that speaker on every receiver within 3 s and shows the "could not be verified" warning.
- A call from a stranger does not ring until the stranger is accepted.

### Phase 4 — Meetings on the relay

**FC-JDK:** `kind = meeting`, the `admitSig` check, speaker selection,
forwarding attestations per receiver, `call.control`, rekey and
`call.prove`, reports, limits, and handing over the host role.

**Test:** a load test with 40 synthetic participants, 3 of them speaking.

**Gate:**

- The relay's CPU and bandwidth match §7.5 within 20 %.
- Rekey drops only participants who could not prove the new key.

### Phase 5 — Meetings (Android)

- `MEETING_START` and `MEETING_END` cards in Room and Team chat.
- Join, the participant list, the active-speaker indicator, raised hands, host controls.
- Rekey handling tied to `SymkeyStore`.
- Relay choice from the entity's `home`.

**Gate:** a 10-person meeting on real devices, including a member removal
with the owner rotating the key mid-meeting.

### Phase 6 — Mac

- Port Phases 3 and 5 against the frozen spec and vectors.
- `AVAudioEngine` with voice processing.
- Menu-bar availability.

**Gate:**

- Mac↔Android 1:1 calls work, directly and relayed.
- A mixed meeting works.
- All vectors pass on both clients.

### Phase 7 — Hardening

- Move the media code into the `:voice` process (§11.3).
- Publish the protocol docs in §13.

Phases 3 and 4 can overlap once Phase 2 passes. Phase 6 can start as soon
as Phase 3's vectors are frozen.

## 15. Decisions record

Answered 2026-09-22:

1. **The audio level stays readable by the relay.** Accepted.
2. **Charging is by data used,** per minute (§7.5).
3. ***Always relay* is off by default.** Direct paths are tried only with contacts (Decision 8).
4. **Background ringing on Android** uses the opt-in *Available for calls* foreground service (§6.3). There is no Google push.
5. **Meetings are limited to 64 participants** in v1 (§7.6).
6. **Per-sender signatures are in v1** (Decision 10, §5.1). They were not deferred to Phase 7.
7. **The component is named `CALL@No1_NrC7`.**
8. **Stranger calls ring once the stranger is accepted**, through the same step as stranger messages (§3.2).
9. **FUDP work starts in FC-JDK** and is ported to FC-AJDK and the Mac from there (§14, Phase 1).

Answered 2026-09-22, during Phase 1:

10. **Priority over stream data is guaranteed at the sender only.** A bulk transfer can still delay audio in queues further along the path. The call layer caps or pauses bulk transfers during a call (§9.5). A delay-based limit on streams inside FUDP is deferred.
