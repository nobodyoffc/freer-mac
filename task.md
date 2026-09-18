Task
[x] master
[x] list default Square
[x] onboarding task list.
[x] contacts detail
[x] Dock/DISK setup
[x] introduction for newcomer
[x] Newcomer has to expose the pubkey. register CID.
[x] first FCH(default words) - CID - DOCK/DISK - say thanks to guide - add guide to contacts - join a square  

[x] prikey backup
[x] input box hard to put cursor
[x] send page out of the screen
[x] first FCH to tool


## 9/14

Freer for Mac

Security, Logic and Data-Consistency Audit Report

Audit status: Ongoing
Audited source: freer-mac-main (1).zip
Current source size: 502 Swift files / approximately 140,719 Swift LOC

Current Audit Boundary

The latest completed source file is:

Packages/FCDomain/Sources/FCDomain/Im/GroupService.swift — lines 1–334, entire file reviewed.

The immediately preceding completed messaging file is:

Packages/FCDomain/Sources/FCDomain/Im/MessageCourier.swift — lines 1–694, entire file reviewed.

Additional current-stage inspection includes:

Packages/FCDomain/Sources/FCDomain/Im/ChatService.swift — inbound/receipt path through approximately line 390.

Sources/FreerForMac/AppState.swift — storage fallback path around lines 205–232.

Previously completed portions of FCTransport, FCStorage, FCDomain, Wallet, Construct, Publish, Secret, Proof, Rating, Mail, Directory/Contact, and application UI.

Approximate overall project coverage: 21–22%
Approximate FCDomain coverage: ~51%
Production-impact findings: 58
Test-only finding: 1
Potential findings under verification: 6

1. Executive Summary

The audit has identified a significant number of issues concentrated around:

Local state consistency versus blockchain state.

FUDP authentication, replay and connection-state handling.

Wallet reservation and transaction construction.

Incremental synchronization and incomplete pagination.

Concurrency between local stores and asynchronous operations.

Message delivery and deletion semantics.

Group membership synchronization.

Error handling that converts failures into apparently successful states.

Integer conversion and arithmetic safety.

Storage and cache recovery.

The most important architectural observation so far is that several components correctly treat the blockchain as the ultimate authority, but local optimistic state, cached state, and asynchronous synchronization are not always designed around that principle.

The most serious findings are therefore not limited to conventional cryptographic flaws. Several of the strongest findings are state-machine and consistency bugs, where a locally successful operation temporarily creates a state that can be overwritten, lost, or incorrectly interpreted before blockchain confirmation.

2. Confirmed Findings

BUG-001 — Setting file is not cryptographically bound to its main FID

Severity: Medium
Area: FCStorage / Configure

EncryptedFile.swift uses the filename as default authenticated data for encrypted files. ConfigureSession.unlockMain uses the same setting filename without binding the ciphertext to the expected FID.

A local file belonging to one main identity can therefore potentially be moved/swapped into another main's settings directory while remaining cryptographically valid.

Affected code:

Packages/FCStorage/Sources/FCStorage/EncryptedFile.swift, approximately lines 65–70 and 116–124.

Packages/FCDomain/Sources/FCDomain/Configure/ConfigureSession.swift, approximately lines 228–245.

Recommendation: Bind AAD to the identity, e.g. setting:v1:<fid>, and verify setting.mainFid == fid.

BUG-002 — Replay protection is implemented but not integrated into FUDP receive processing

Severity: High
Area: FCTransport

ReplayProtection.checkAndRecord() exists, but the production FUDP receive path does not consistently invoke it before accepting authenticated packets.

A valid packet can therefore potentially be replayed.

Recommendation: Integrate replay checking into the authenticated receive pipeline before state-changing processing.

BUG-003 — Incoming FUDP connection ID is not validated against the active connection

Severity: High

The receiver validates relevant cryptographic identity information but does not consistently require:

header.connectionId == currentConnection.connectionId.

A valid packet associated with another connection can therefore potentially enter the wrong connection state.

BUG-004 — Final stream size is not enforced consistently

Severity: Medium

InboundStreamBuffer permits inconsistent FIN/final-size handling.

Multiple final-size declarations or data beyond an already-established final size are not consistently rejected.

BUG-005 — Decrypt rate limiting is not integrated into the production receive path

Severity: Medium/High

DecryptRateLimiter exists, but expensive asymmetric processing can occur before effective rate limiting.

This creates an asymmetric CPU-cost opportunity for an attacker.

BUG-006 — FUDP discovery public key is unauthenticated

Severity: High

FudpDiscovery receives a public key through a plaintext discovery packet without cryptographic authentication or pinning.

A malicious network participant can potentially advertise a forged public key and redirect subsequent encrypted communication.

BUG-007 — Inbound NWConnections are retained indefinitely

Severity: Medium

FudpSocket appends inbound connections but does not consistently remove terminated connections from the retained collection.

Repeated inbound connections can therefore cause resource accumulation.

BUG-008 — ACK values can crash during UInt64 → Int64 conversion

Severity: Medium

Authenticated ACK values outside the signed 64-bit range can reach trapping conversions.

Affected areas include FrameParser, AckFrame, and FUDP ACK processing.

BUG-009 — Stream offset arithmetic can overflow

Severity: Medium

Offset plus payload length can overflow UInt64.

Malformed input can therefore cause a runtime trap rather than a clean protocol rejection.

BUG-010 — ACK range count is insufficiently bounded

Severity: Medium

The wire-level rangeCount controls parsing work without a sufficiently early protocol-level maximum.

A peer can cause excessive processing/allocation.

BUG-011 — ACK ranges beyond the generator's retained range can be lost

Severity: Medium

AckGenerator retains a limited set of ranges. Older ranges can disappear without a reliable mechanism guaranteeing that they will be retransmitted as ACK information.

This can delay loss recovery.

BUG-012 — Peer session epoch can move backwards

Severity: High

PeerConnection blindly updates _peerSessionEpoch.

An older delayed packet can therefore potentially replace a newer session epoch.

BUG-013 — ReconnectingFapiClient generation race

Severity: Medium

A generation value is captured before an asynchronous factory operation.

If markStale() occurs while the factory is executing, the newly created transport can still be installed despite having been invalidated.

BUG-014 — ACK delay conversion can trap

Severity: Medium

TransferMachinery performs unchecked numeric conversion/arithmetic involving ACK delay values.

Extreme authenticated input can cause a runtime trap.

BUG-015 — ECDH is performed before AEAD authentication

Severity: High

AsyTwoWay.open() performs expensive ECDH processing before the final authentication result is known.

This creates an asymmetric CPU-cost surface.

This is the underlying cryptographic mechanism associated with BUG-005.

BUG-016 — DecryptRateLimiter stale entries are not actually evicted by TTL

Severity: Low/Medium

The limiter declares a TTL but does not consistently perform TTL eviction.

The fixed capacity limits the worst-case memory growth, but the implementation does not match its stated expiration semantics.

BUG-017 — Client challenge solving is not adequately rate limited

Severity: Medium

Incoming challenge processing can invoke proof-of-work solving without sufficient production-level source/rate controls.

An attacker can therefore potentially consume client CPU.

BUG-018 — File hashing/upload has a TOCTOU window

Severity: Low/Medium

FapiClient hashes the file and subsequently uploads it through separate operations.

The file can change between those operations.

BUG-019 — Inbound streams lack sufficient global size/resource limits

Severity: High for DoS

Large offsets, many chunks, and many intervals can consume disk, memory, or CPU.

A protocol-level maximum for total stream size, offsets, intervals, and global receive budget is required.

BUG-020 — Conflicting overlapping stream data is accepted

Severity: Medium

Overlapping chunks are detected structurally but their overlapping bytes are not consistently compared.

Two authenticated chunks can therefore describe different bytes for the same stream range.

BUG-021 — Retired stream IDs are remembered only within a finite 512-ID window

Severity: Medium

After enough completed streams, older IDs leave the retirement set.

Very late packets can potentially recreate state for an old stream identifier.

BUG-022 — Inbound mailbox is unbounded

Severity: Medium

InboundMailbox can grow without an effective message/byte limit.

An attacker or malfunctioning peer can therefore create memory pressure.

BUG-023 — Large inbound messages are assembled before semantic validation

Severity: Medium

The system can fully materialize an inbound message before higher-level message validation occurs.

Resource limits should be enforced before complete materialization.

BUG-024 — Send failure leaves packet-tracking/congestion state dirty

Severity: Medium

A packet is recorded as sent before the underlying transport operation is known to have succeeded.

If sending fails, tracking state can remain inconsistent until connection teardown.

BUG-025 — Duplicate connection IDs can overwrite ConnectionManager state

Severity: Medium

Insertion by connection ID can replace an existing connection while peer-indexed state can retain stale information.

BUG-026 — FapiClient permits both params and fcdsl

Severity: Medium

The API contract describes the two forms as mutually exclusive, but the client does not enforce the exclusivity.

Ambiguous requests can therefore be constructed.

BUG-027 — Download directly truncates an existing destination

Severity: Medium

The destination file can be replaced/truncated before the complete download succeeds.

A failed download can therefore destroy an otherwise valid local file.

BUG-028 — Download lacks an application-level maximum before materialization

Severity: Medium

A remote response can cause excessive local materialization unless a sufficiently strict application-level download limit is applied.

BUG-029 — Replay timestamp subtraction can overflow

Severity: Medium

ReplayProtection uses direct timestamp subtraction before applying abs().

Extreme values can overflow.

BUG-030 — Epoch zero is used as an unset sentinel

Severity: Low/Medium

A valid epoch value of zero can be confused with the absence of an epoch.

Optional state should be represented explicitly.

BUG-031 — Discovery parser does not fully validate the discovery header

Severity: Medium

The parser checks the packet type but does not fully enforce all expected discovery-header invariants.

BUG-032 — Duplicate packet reception refreshes ACK timestamps

Severity: Medium

Refreshing the timestamp of an already-known packet can interfere with timestamp-based pruning/order assumptions.

BUG-033 — SentPacketTracker has no independent expiration for suspected-loss records

Severity: Low/Medium

Entries can remain until ACK/removal rather than having an independent abandonment/expiration policy.

BUG-034 — SentPacketTracker restart does not restore the initial reorder threshold

Severity: Medium

Restart/reset state retains an adapted reorder threshold instead of restoring the initial baseline.

BUG-035 — TransferMachinery initial timestamp behavior affects a test-only scenario

Severity: Low / Test-only

This finding is not counted as a production vulnerability.

It affects a near-zero test-clock condition and does not currently justify a production security finding.

BUG-036 — Wall-clock rollback can break packet-age calculations

Severity: Low/Medium

SentPacketTracker uses wall-clock differences for age calculations.

A system clock rollback can produce invalid/negative age behavior.

BUG-037 — Negative streaming file length can trap

Severity: Medium

A public signed Int64 file length is converted to UInt64 without rejecting negative values.

BUG-038 — Chunked stream can send more data than declared

Severity: Medium

The final-chunk logic relies on sent >= totalLength.

If the source supplies more bytes than declared, the extra data can be included in the terminating chunk.

BUG-039 — Zero-length streams are not correctly represented

Severity: Low/Medium

A zero-length stream can enter the stalled/no-data path instead of generating the correct empty stream completion.

BUG-040 — FileVault resolution has a TOCTOU window

Severity: Medium

A file is validated using metadata and then returned to another operation.

The file can change after validation but before consumption.

BUG-041 — KeyInfo uses precondition for private-key length

Severity: Medium

KeyInfo.make uses:

precondition(privkey.count == 32)

Invalid input therefore terminates the process rather than returning a normal validation error.

BUG-042 — Wallet claim silently ignores a missing selected Cash

Severity: High

WalletService.claim() skips an input when its selected Cash row no longer exists.

The transaction flow can continue despite the missing reservation.

The correct behavior is to abort and report that the selected input is no longer available.

BUG-043 — Transaction builder performs trapping signed-to-unsigned conversions

Severity: Medium

Negative transaction values or indexes can reach UInt64/UInt32 conversion.

This can terminate the process instead of rejecting invalid transaction input.

BUG-044 — Wallet transaction arithmetic can overflow

Severity: Medium

Input/output totals and fee arithmetic use unchecked signed integer accumulation.

Malformed or extreme values can trap.

This includes related arithmetic in TxFee and Cash/Reorg calculations.

BUG-045 — Advanced transaction locktime is silently truncated

Severity: Medium

UInt32(truncatingIfNeeded: maxInputLockTime) can silently change a value larger than the supported 32-bit range.

This is a transaction-integrity problem.

BUG-046 — Any non-zero cashValid response becomes an empty wallet

Severity: High — Data Integrity

WalletService.bootstrapCashes() treats any non-zero response code as if the wallet contains zero Cashes.

Therefore errors such as authentication failure, rate limiting, server errors, or temporary network problems can overwrite a valid cached wallet snapshot with an empty snapshot.

Only a genuine NOT_FOUND/404 response should mean "zero Cashes."

BUG-047 — sendAdvanced can reserve different Cashes from the transaction inputs

Severity: High — State Integrity

The transaction inputs and inputCashes used for local reservation are not cryptographically/structurally cross-checked.

A mismatch can result in:

transaction spending Cash A;

local wallet reserving Cash B;

optimistic state marking B as spent/pending.

This can permanently diverge local wallet state from the chain until reconciliation.

BUG-048 — Invalid or huge fee rates can trap during Double → Int64 conversion

Severity: Medium

TxFee converts externally supplied fee rates into Int64 without sufficient finite/range validation.

Huge or non-finite values can cause a runtime trap.

BUG-049 — Pending-spend recovery is not protected by CashLedgerLock

Severity: Medium/High

recoverPendingSpend() performs read/check/modify/save without the same lock used by competing Cash mutations.

Concurrent operations can therefore overwrite each other's state.

BUG-050 — Optimistic post-send state update is not protected by CashLedgerLock

Severity: High — State Integrity

applyOptimisticPostSend() reads and writes the wallet snapshot without the required synchronization.

A concurrent reservation can therefore be lost by a stale snapshot write.

BUG-051 — Cash bootstrap can replace a complete snapshot with an incomplete response

Severity: High if the backend response is capped

The mode-2 Cash query does not prove that all Cashes were returned.

If the backend imposes a response cap, the client can save an incomplete wallet snapshot as though it were complete.

This is partly dependent on backend/API semantics, but the client currently lacks a completeness guarantee.

BUG-052 — TxApprovalCenter mutates observable state outside MainActor

Severity: Medium

TxApprovalCenter is observable but is not consistently isolated to MainActor.

cancelAll() can mutate current and queue concurrently with UI/approval operations.

BUG-053 — Refreshing page 1 can delete older cached records

Severity: Medium — Data Integrity

Several views fetch only the first page and then call replaceChainRows.

Existing cached rows outside the returned page are removed.

Confirmed locations include:

ProofsView.swift

PublishTextView.swift

PublishMediaView.swift

PublishStatementView.swift

A cache containing hundreds of records can therefore shrink to the latest 25 records after a refresh.

BUG-054 — Unconfirmed broadcast state can be overwritten by stale chain refresh

Severity: High — State Integrity / Duplicate-operation Risk

Construct operations optimistically update local state immediately after broadcast.

The UI then performs an immediate refresh.

If the indexer has not yet included the transaction, the refresh can return the previous chain state and overwrite the optimistic local state.

Potential consequence:

Broadcast successful ↓ local state = stopped ↓ indexer still says active ↓ refresh ↓ local state = active again 

This can expose operations that should temporarily remain pending and can create duplicate-operation opportunities.

BUG-055 — Mail synchronization has a hard 40,000-record ceiling

Severity: Medium / Data Completeness

MailService uses:

page size: 200

maximum pages: 200

Therefore a full synchronization stops after approximately 40,000 records without an explicit incomplete-state indicator.

This is primarily a completeness/offline-availability problem rather than a direct security exploit.

BUG-056 — Contact is removed locally before delete confirmation

Severity: Medium — Data Integrity

ContactsView.deleteOnChain performs the chain broadcast and then immediately removes the local contact.

If the transaction is never confirmed or is dropped, local state temporarily says the contact no longer exists even though chain state still contains it.

A later exhaustive sync can restore the contact, so this is not permanent chain-data loss.

BUG-057 — AppState's last-resort storage fallback can still crash

Severity: Medium — Availability

Sources/FreerForMac/AppState.swift:222 contains:

try! ConfigureManager( baseDirectory: FileManager.default.temporaryDirectory ) 

The surrounding code explicitly describes this path as a last-resort fallback intended to avoid crashing on startup.

If both the primary storage and the first temporary fallback fail, try! terminates the process.

The recovery path therefore contradicts its own stated purpose.

BUG-058 — DOCK message can be deleted after local receive failure

Severity: High — Message Loss

MessageCourier.swift:625–643 performs:

(try? chat.receive(...)) ?? .ignored(reason: "receive failed") 

and subsequently can execute:

try? await dock.delete(...) 

The deletion decision is not conditioned on successful local processing.

If chat.receive() throws because local persistence fails, the item can still be deleted from the DOCK.

Result:

remote message ↓ local storage failure ↓ receive throws ↓ error converted to "ignored" ↓ DOCK item deleted ↓ message no longer recoverable 

This is a genuine message-loss condition.

BUG-059 — Group membership synchronization cannot reliably detect that the current user was removed

Severity: High — Authorization / State Integrity

GroupService.fetch() constructs a query requiring:

"terms": [ "fields": ["members"], "values": [fid] ] 

Therefore the server search only returns groups where the current FID is currently a member.

However, syncTeams() and syncSquares() are also responsible for detecting the transition:

member → removed 

The removed group no longer satisfies the membership query.

Consequently the client may never receive the updated group record needed to execute:

existing.leftGroup = !belongs 

for that group.

This creates the following state:

Chain: User removed from Team A ↓ Group query: Team A no longer matches "members contains myFID" ↓ Client: Team A update never arrives ↓ Local store: User still appears to be a member ↓ ChatGate: isMember may remain true 

This is especially important because the local membership is subsequently consumed by chat authorization logic.

The unit-test scenario is also insufficiently representative if the mock continues returning the removed team even though the production query excludes it.

Recommended fix: retain previously known group IDs and explicitly reconcile their current membership, or provide a server-side query/API capable of returning membership changes/removals.

3. Potential Findings Still Under Verification

These are intentionally NOT counted as confirmed vulnerabilities.

Potential-01 — Directory response key may not match returned object ID

DirectoryService.freerByIds does not currently prove that every returned map key corresponds to the object's internal ID.

Requires a trusted-but-malformed FAPI response or server/indexer inconsistency to become exploitable.

Potential-02 — Multisig firstDifference() does not compare every transaction field

Several fields are omitted from human-readable difference reporting.

However, the final cryptographic assembly verifies the complete transaction, so this currently appears to be a diagnostic/UX weakness rather than a signature-bypass vulnerability.

Potential-03 — Subidentity insertion can overwrite an existing local subidentity

addSubIdentity can replace an existing local record.

The security impact and intended replacement semantics still need confirmation.

Potential-04 — Mail delete/recover lacks complete local preflight authorization

The chain ultimately enforces ownership, so the currently demonstrated impact is mainly unnecessary fee/failed-operation behavior.

Potential-05 — MessageRequest promotion is not transactionally atomic

Messages can be promoted one by one before the request record is removed.

A failure in the middle can produce partial promotion and require recovery.

The exact retry semantics still need to be established before calling this a confirmed data-integrity bug.

Potential-06 — Team key sharing can leave a generated local key after share failure

If local key generation succeeds but the subsequent sharing operation fails, the local key may appear current and suppress another automatic share attempt.

Recovery mechanisms exist, so exploitability is still under investigation.

4. Findings Deliberately Not Counted

During the audit, several initially suspicious areas were examined and deliberately excluded because the current implementation contains a valid invariant or because the behavior is intentional.

Examples include:

Int(dataLenBig) in FUDP frame parsing.

PoW UInt64/Int64 handling.

AsyTwoWay ECDH cache key construction.

UnifiedCodec integer conversion on 64-bit macOS.

FUDP outgoing connection race.

ConnectionManager same-address reuse.

Discovery trailing bytes.

PoW wrap handling.

.waiting FUDP connections during wake/NAT recovery.

TransferMachinery reset behavior without production callers.

ActiveSession force unwraps covered by the Setting invariant.

FileShare plaintext HAT capability design.

HatSync DID verification.

MessagesStore pagination.

Room owner authorization paths.

SymkeyStore version/key validation.

KeyExchange self-FID handling.

Multisig cryptographic verification.

Token amount validation.

Token issuance/close authorization.

Rating duplicate behavior.

Secret full synchronization.

Mail send encryption path.

Several UInt64/Int64 findings that are already covered by BUG-043/BUG-044.

These exclusions are important because the audit is intended to distinguish actual defects from superficial static-analysis warnings.

5. Cross-Cutting Risk Areas

A. Local state is sometimes treated as authoritative before chain confirmation

This pattern appears in:

Construct operations

Contact deletion

Secret deletion

Wallet optimistic state

Group membership

Cached chain rows

The application needs a consistent state model:

local intent ↓ broadcast submitted ↓ pending confirmation ↓ confirmed chain state 

rather than:

broadcast succeeded ↓ pretend chain state already changed 

B. Error handling sometimes converts failure into an apparently valid state

Important examples:

BUG-046: API error → empty wallet.

BUG-057: fallback failure → try! crash.

BUG-058: receive failure → ignored → remote deletion.

This class deserves special attention because it is more dangerous than a normal thrown error: the application can continue operating with a false state.

C. Synchronization must distinguish "not returned" from "does not exist"

This is central to:

BUG-051

BUG-053

BUG-055

BUG-059

A missing record from a paginated/filtered query does not necessarily mean the record was deleted.

The client must know whether:

record absent because deleted 

or:

record absent because query/page/filter did not return it 

6. Priority Fix Order

Critical/Immediate

BUG-058 — DOCK deletion after receive failure

BUG-046 — API errors converted into empty wallet

BUG-047 — Reserved Cash mismatch

BUG-050 — Optimistic wallet race

BUG-002 — Missing FUDP replay integration

BUG-003 — Missing connection-ID validation

BUG-006 — Unauthenticated discovery key

BUG-015 — ECDH before authentication

BUG-019 — Inbound stream resource limits

BUG-059 — Group membership removal synchronization

Next priority

BUG-054 — stale chain refresh overwriting pending local state

BUG-042 — silent missing Cash during claim

BUG-049 — pending-spend recovery race

BUG-053 — cache truncation during refresh

BUG-051 — incomplete Cash synchronization

BUG-012 — session epoch rollback

BUG-020 — conflicting stream overlap

BUG-021 — retired stream reuse

BUG-022 — unbounded mailbox

BUG-027/028 — unsafe downloads

7. Overall Assessment

The codebase has several strong design elements:

extensive explicit protocol types;

authenticated cryptographic primitives;

careful transaction assembly;

meaningful ownership checks;

explicit chain-authoritative comments;

good separation between FCDomain services and UI;

several existing protections against malformed wire data;

extensive test coverage in several core components.

However, the dominant weakness is cross-component state consistency.

The most important remaining work is therefore not simply finding more isolated arithmetic bugs. The next audit stages should continue tracing complete state transitions:

Chain ↓ FAPI ↓ Service ↓ Store ↓ AppState ↓ UI ↓ User action ↓ Broadcast ↓ Pending state ↓ Refresh ↓ Reconciliation 

This is where the highest-value remaining defects are likely to exist.

Current Audit Progress

Project: ~21–22%
FCDomain: ~51%
IM/Chat: ~60%
Team/Group: ~72%
Confirmed production-impact findings: 58
Test-only finding: 1
Potential findings: 6

Latest completed file:
Packages/FCDomain/Sources/FCDomain/Im/GroupService.swift, lines 1–334.


## 9/16
Freer for Mac

Security, Logic and Data-Consistency Audit Report

Audit Report — Continuation / Final Deep Pass

Audit status: Final Deep Pass ongoing
Audited source: freer-mac-main
Audit scope: Swift application, FCDomain, FCTransport, messaging, session lifecycle, persistence, scheduler and security-sensitive state transitions.

Latest Review Boundary

The latest deep-pass review has reached the following areas:

Sources/FreerForMac/AppState.swift

Sources/FreerForMac/Views/SettingsView.swift

Packages/FCDomain/Sources/FCDomain/Stores/SettingsStore.swift

Packages/FCDomain/Sources/FCDomain/Im/DockFetchScheduler.swift

Packages/FCTransport/Sources/FCTransport/ReconnectingFapiClient.swift

Session locking/unlocking and vault lifecycle

FAPI lifecycle and reconnect handling

Dock fetch scheduling

Background/foreground and stale-transport handling

Terminal and SSH lifecycle

Message Courier / Outbox / MessageRequests / MessagesStore

Receipt processing and message state transitions

Previously identified duplicate/retracted findings remain excluded from the independent bug count.

BUG-094 — Auto-Lock Setting Has No Runtime Enforcement

Severity: High — Security

Files:

Sources/FreerForMac/Views/SettingsView.swift

Packages/FCDomain/Sources/FCDomain/Stores/SettingsStore.swift

Locations:

SettingsView.swift approximately lines 403–449

SettingsStore.swift approximately lines 43–70

Description

The application exposes an Auto-Lock configuration and persists the configured timeout through the settings layer.

The value is stored and can subsequently be read, but no production runtime mechanism was identified that consumes the configured timeout and automatically invokes the vault-lock operation after the required period of inactivity.

The expected security chain would be:

Auto-Lock setting ↓ inactivity tracking ↓ timeout reached ↓ lockAll() ↓ active session destroyed ↓ password screen 

The current production code contains the configuration/persistence path, but no corresponding runtime enforcement path was identified.

Impact

A user can configure Auto-Lock while the vault remains unlocked beyond the configured interval.

This creates a security gap between the documented/configured security control and its actual runtime behavior.

Confidence: High

BUG-095 — Existing Dock Fetch Scheduler Uses the Current Active Session Instead of Its Bound Session

Severity: High

File: Sources/FreerForMac/AppState.swift

Location: approximately lines 342–367

Description

A Dock fetch scheduler is created for a specific session, but its asynchronous closures subsequently obtain the session through self?.activeSession.

Conceptually:

startFetchScheduler(session A) ↓ scheduler starts asynchronous work ↓ active session changes ↓ activeSession = session B ↓ old scheduler resumes ↓ old scheduler accesses activeSession ↓ work may execute against session B 

The scheduler therefore does not consistently bind its asynchronous work to the session for which it was created.

Impact

During rapid session switching, an operation belonging to Session A may continue after Session B becomes active and obtain Session B through the mutable activeSession property.

This creates a cross-session lifecycle race and can cause synchronization/fetch activity to be associated with the wrong vault/session.

Confidence: High

BUG-096 — Fetch Scheduler Shutdown Is Asynchronous and Not Awaited

Severity: Medium/High

File: Sources/FreerForMac/AppState.swift

Location: approximately lines 370–374

Description

The scheduler reference is removed from AppState immediately, while the actual scheduler shutdown is launched in a separate task.

The relevant lifecycle is effectively:

stopFetchScheduler() ↓ fetchScheduler = nil ↓ Task { await fetchScheduler.stop() } ↓ new scheduler may be created ↓ old scheduler may still be shutting down 

There is therefore no synchronous lifecycle boundary between stopping the old scheduler and starting a new scheduler.

Impact

A session switch, lock/unlock operation, or FAPI reconfiguration can temporarily have both the old scheduler and a newly created scheduler alive.

When combined with BUG-095, this increases the possibility of stale asynchronous work executing against the current session.

Confidence: High

Previously Identified Related Lifecycle Findings

The following findings remain separate because they occur at different lifecycle boundaries.

BUG-090 — Reconnect Generation Race

File: Packages/FCTransport/Sources/FCTransport/ReconnectingFapiClient.swift

Location: approximately lines 255–274

A transport construction operation can overlap with markStale()/generation changes. The generation captured before the asynchronous factory operation can become stale before the newly constructed transport is returned.

Status: Confirmed; retained.

BUG-091 — Unlock Can Complete After Lock

File: Sources/FreerForMac/AppState.swift

Location: approximately lines 503–527

unlockMain() performs asynchronous work before assigning the resulting session to activeSession. A concurrent lockAll() can invalidate the session while the unlock operation is still running, after which the older unlock operation can complete and restore the active session.

Status: Confirmed; retained.

BUG-092 — Stale FAPI Configuration Can Recreate Transport After Session Teardown

File: Sources/FreerForMac/AppState.swift

Location: approximately lines 744–855

applyFapiSettings(for:) performs asynchronous operations without a final validation that the original session remains the active/current session after those awaits.

A session can therefore be locked or replaced while the operation is in progress, followed by the old operation continuing its FAPI setup.

Status: Confirmed; retained.

Messaging Findings Retained From Previous Pass

The following findings remain part of the audit and were not re-counted during this pass:

BUG-082 — Message Request quota can be consumed repeatedly by duplicate message IDs.

BUG-083 — Receipt processing does not sufficiently bind receipt sender identity to the original message recipient.

BUG-084 — Successful DOCK delivery can remain in Outbox after success persistence failure, allowing retry/duplicate delivery.

BUG-085 — Concurrent Outbox drains can process the same message before one drain removes/claims it.

BUG-086 — Failed message reception can be skipped when the DOCK pagination cursor advances.

BUG-087 — Message quarantine persistence and MessageRequest persistence are not atomic.

BUG-088 — MessagesStore can delete the old record before successfully storing the replacement.

BUG-089 — Successful DOCK delivery can remove the Outbox entry even when local message-state persistence fails.

Duplicate / Retracted Findings

The following are intentionally excluded from the independent bug count:

BUG-081 — Retracted as Duplicate

The finding concerning deletion of a DOCK item after chat.receive() failure overlaps the previously identified DOCK deletion/receive-failure finding and should not be counted as an independent vulnerability.

BUG-074 — Retracted

Previously determined not to represent an independent confirmed defect.

Current Audit Status

Independent confirmed findings retained: 93

Potential findings: 6

Retracted/duplicate findings: excluded from the confirmed count.

The latest deep-pass work has concentrated on validating whether previously reported findings survive caller-to-callee and lifecycle-level verification rather than generating additional findings merely to increase the bug count.

The most security-sensitive remaining area is the interaction between:

Vault/session lifecycle ↓ FAPI lifecycle ↓ DockFetchScheduler ↓ MessageCourier ↓ MessagesStore / MessageRequests ↓ background/reconnect operations 

Further review should therefore focus on proving or disproving cross-session data flow and stale asynchronous operations across these boundaries.

