# Nobody — cross-client spec

How Freer treats a **nobody**: an identity whose private key has been
published on chain. Both clients implement this document. The same file is
kept in both repositories — `FreerForMac/NOBODY_SPEC.md` and
`Freer/docs/NOBODY_SPEC.md` — so change both together.

Reference implementations:

| Part | Android (`Freer`) | Mac (`FreerForMac`) |
|---|---|---|
| Registry | `app/.../nobody/NobodyRegistry.java`, `MmkvNobodyStore.java` | `Packages/FCCore/.../Identity/NobodyRegistry.swift` |
| Lookup feed | `FC-AJDK/.../fapi/client/FapiClient.java` (`NobodyObserver`) | `Packages/FCDomain/.../Directory/DirectoryService.swift` |
| Marks | `app/.../nobody/NobodyUi.java`, `res/drawable/ic_skull.xml`, `res/layout/view_nobody_banner.xml` | `Packages/FCUI/.../Nobody/NobodyMark.swift`, `FidAvatarView.swift` |
| Confirmation | `app/.../nobody/NobodyGuard.java` | `Sources/FreerForMac/Views/Nobody/NobodyGate.swift` |
| Tests | `app/src/test/.../nobody/NobodyRegistryTest.java` | `FCCoreTests/Identity/NobodyRegistryTests.swift`, `FCDomainTests/Directory/NobodyLookupTests.swift`, `FCUITests/Nobody/NobodyMarkTests.swift` |

## What a nobody is, and why it matters

A FEIP4 carve publishes a FID's private key. The chain's **nobody index**
records it (`id` = FID, `priKey`, `deathTime`, `deathHeight`, `deathTxId`),
and the freer record gains `isNobody: true` (and `prikey`). Publishing
cannot be undone.

From then on **anyone** holds that key. Anyone can:

- spend its cash, including cash still unconfirmed, so spends from it may never confirm;
- sign as it: messages, carves, invitations, signatures, team consent;
- decrypt anything sealed to its pubkey: P2P messages, mail, room and team keys, a master's copy of a servant's key;
- rewrite its on-chain record, CID included. A nobody named "alice" is not Alice.

A nobody is not malicious. The default request board
(`FHG8DW2eHQ5wNAJQnLNKzYUSo2YKt7ffff`) is a nobody on purpose, and a user may
publish their own key deliberately. The clients neither hide nor block
nobodies. They make sure the user **knows**, every time it matters.

## Decisions

1. **Know it once.** Each client has one registry that every screen reads.
   No screen keeps its own list.
2. **Show it everywhere a FID appears.** The avatar is grey with a skull
   badge, and a "Nobody" chip goes before the name. The CID is still shown,
   and the chip says it cannot be trusted.
3. **Confirm, never block.** Every action that sends value or secrets to a
   nobody, acts on a nobody's word, or acts as a nobody first asks
   *Proceed anyway / Cancel* and names the consequence.
4. **Team consensus is labelled, not recounted.** A nobody member's consent
   is marked as forgeable. How consent is counted is protocol, and no client
   changes it on its own.

## 1. Knowing: the registry

| Rule | Value |
|---|---|
| A positive ("is a nobody") | Persisted. Never expires. |
| A negative ("not a nobody") | Memory only. Expires after **10 minutes**. |
| A failed check | Neither answer. Lists retry after **60 seconds**; confirmations retry immediately. |
| Always a nobody | `FHG8DW2eHQ5wNAJQnLNKzYUSo2YKt7ffff`, the default board |
| Reading | A synchronous set lookup. Never touches the network, so it is safe while drawing. |
| Scope | Global rather than per identity, because it is a fact of the chain. It stores only nobodies, which are public by definition. |

**Where the answers come from.** No screen records anything itself:

- **Every freer lookup** (`base.freerByIds`, `base.search` on `freer`,
  `myServants`) records as a nobody each freer with `isNobody == true` or a
  non-empty `prikey`. It **never records a negative**, because a freer
  fetched for a subset of fields (e.g. `getPubkey`) omits the flag.
- **The nobody index** (`base.getByIds`, `entity: "nobody"`) records both
  answers: the FIDs it returns are nobodies, and the ones it leaves out are
  not. A `404` is an answer ("none"). Any other failure records nothing.
- **Local flags.** A stored key or contact with `isNobody == true` counts.
  It may predate the registry.

**Resolving an unknown FID.** Check it against the nobody index, in batches,
with duplicates dropped while a check is in flight. List rows resolve
quietly and redraw when an answer lands. A confirmation resolves first,
retries a recent failure, and if the network is down decides from what is
already known.

**Persistence.** Android uses MMKV `nobody_registry` (keys `n:<fid>` and
`a:<fid>`). Mac uses `~/Library/Application Support/fc.freer.mac/nobodies.json`
(`{"nobodies": [...], "alerted": [...]}`).

## 2. Showing: one visual language

### Avatar

- **Greyscale.** The whole avatar is desaturated.
- **Skull badge.** A white-ringed disc sits bottom-right, inside the circle
  inscribed in the avatar, so an avatar clipped to a circle keeps it. For an
  avatar of side `s`:
  - badge radius `r = 0.2·s`
  - centre `(s/2 + d, s/2 + d)`, where `d = (s/2 − r)·0.7071`
  - white ring radius `1.12·r`
  - skull box side `1.44·r`, centred, white
- **Colour.** Mark colour `#E65100`, on-mark `#FFFFFF`. Orange means
  warning. Red is avoided because it is the colour of the unread dots, and a
  red disc on an avatar reads as "something new".
- **Skull geometry.** On a 24×24 grid, filled even-odd:
  ```
  M12,2 C6.48,2 2,6.03 2,11 c0,3.05 1.64,5.64 4,7.19 V21 c0,.55 .45,1 1,1 h10
  c.55,0 1,-.45 1,-1 v-2.81 c2.36,-1.55 4,-4.14 4,-7.19 C22,6.03 17.52,2 12,2 Z
  eyes: circles r=2.2 at (8.5,11.3) and (15.5,11.3)
  nose: M12,14.2 L10.7,16.6 H13.3 Z
  teeth gaps: rects 0.9×2.1 at (9.9,19.2) and (13.2,19.2)
  ```
- **Where the mark is applied.** It goes on at one choke point, so a status
  learned later marks the avatar on its next draw. On Android that is
  `AvatarManager.getAvatarBitmap` (applied at decode, never to cached bytes).
  On Mac it is `FidAvatarView`, which reads the registry.
- **Exports stay plain.** The full-size avatar sheet shows a written note
  instead of a badge, and a saved avatar file is the plain artwork.

### Name chip

A rounded "**Nobody**" (zh **明人**) chip in the mark colour, placed
**before** the CID or FID. The CID stays. The chip is display only: a
chip-decorated text is never read back as a CID or FID, and a field that is
editable or copied as an id gets no chip (the avatar carries the mark).
Group ids (rooms, teams, squares) are never marked.

### Banners

A line with the skull, in mark colour on a pale wash (Android `#FFF3E0`
light / `#3E2723` dark; Mac 10 % of the mark colour), shown only while the FID
is a nobody:

| Where | Text |
|---|---|
| Details of any FID | Nobody: this identity's private key is public. Anyone can act as it. |
| The live identity (Android Home/Pay; Mac pane header) | This identity's private key is public. Anyone can spend its funds, read its messages and act as it. |
| Receive (Android) | This address's private key is public. Anything paid here can be taken by anyone. |
| Mail from, pending issue, message request | The sender is a nobody: its private key is public, so anyone could have sent this. |
| Team / room invitation | The inviter is a nobody: its private key is public, so anyone could have sent this invitation. |
| P2P chat with a nobody (not the board) | This identity is a nobody: its private key is public, so messages from it can be written by anyone and cannot be trusted. |
| Valid signature by a nobody | Valid, but the signer is a nobody: its private key is public, so anyone could have signed this. It proves nothing. |
| Team member list with a nobody member | Nobody members' private keys are public: anyone can give their consent. |

## 3. Confirming

**The dialog.**
- Title: *Nobody identity*.
- Body: *Private key published on chain:* followed by one line per nobody
  (the CID when known, then the FID), a blank line, and the consequence.
- Buttons: **Cancel** and **Proceed Anyway**. Cancel is the default, so
  Return is never the risky answer.
- It appears only when a nobody is actually involved. Otherwise the action
  proceeds with no dialog.
- Android uses an `AlertDialog`. Mac uses an app-modal `NSAlert`, which sits
  above open sheets for the same reason the transaction approval uses a
  window.

### Sending to a nobody (value or secrets become public)

| Action | Consequence | Android | Mac |
|---|---|---|---|
| Send FCH | Anything sent to it can be taken by anyone. | `SendTxActivity` (every tx) | `TxConfirmSheet` banners (every tx) |
| Send / issue tokens | same | `SendTokenActivity.handleSend` | `TokenSheets` `send` / `issue` |
| Transfer a proof | same | `ProofActivity` (the recipient is an output, so `SendTxActivity` asks) | `ProofSheets.transfer` |
| Encrypt to a pubkey | Anyone can decrypt what you encrypt to it. | `EncryptActivity` | Tools › Encrypt |
| Mail | Anyone can read this mail and reply as the recipient. | `CreateMailActivity` | `MailComposeSheet.send` |
| Multisig member | Anyone can sign as this member, so the multisig needs fewer real signatures than it appears. | `CreateMultisigIdActivity` | `CreateMultisigSheet` |
| Set master | Setting a master publishes your private key encrypted to the master. Anyone can decrypt it and take this identity for good. | `SetMasterActivity` | `SetMasterSheet.carve` |
| Team invite / appoint / share team key | Anyone can read the team's messages and act as these members, including giving their consent. | `InviteTeamMemberActivity`, `ChatActivity`, `ManageTeamActivity` | `MemberListSheet` add / send key |
| Room members / room info / room key | Anyone can read the room's messages and speak as these members. | `CreateRoomActivity`, `ChatActivity` | `NewChatSheet` room, `MemberListSheet` add |
| Team ownership transfer; joining a nobody-owned team | Anyone could run the team as its owner. | `ChatActivity`, `ManageTeamActivity`, `JoinTeamActivity` | `NewChatSheet` join |
| Rate | Anyone can act as it, so its reputation means nothing. The coin days you destroy to rate it are wasted. | `RateFreerActivity` | `RateFreerSheet.send` |
| Add contact | Anyone can speak as it, change its CID, and read what you send it. | `CreateContactActivity` | `ContactEditorSheet` (new contacts) |
| Start a P2P chat (not the board) | Anyone can read this conversation and write as it. | `NewTalkActivity` | `NewChatSheet` P2P |

### Acting as a nobody (your own identity)

| Action | Behaviour |
|---|---|
| Import a key whose prikey is published | Confirm: *Anyone can spend this key's funds, read its messages and act as it. Use it only as a public identity.* Proceeding claims the one-time alert below. Android: `BaseCryptoActivity.saveAndFinishWithKeyInfo` (covers import and phrase). Mac: `AddMainView` (before a session, it decides from the registry alone). |
| Spend from a nobody | *The sender's private key is public. Anyone can spend the same cash first, so this transaction may never confirm.* Android confirms in `SendTxActivity`; Mac shows it in `TxConfirmSheet`. |
| A refresh finds the live key is a nobody | Show **once per FID, ever**: *Your private key is public — The private key of <FID> has been published on chain. Anyone can spend its funds, read its messages and act as it. Move your funds to a key only you hold.* Then keep the live-identity banner up. |

### Transactions

Every transaction a user signs passes one review screen, and the nobody check
lives there:

- **Android `SendTxActivity`.** Before broadcasting, it checks the nobody
  index for all output owners plus the sender. It then confirms twice: first
  nobody recipients (change excluded), then a nobody sender.
- **Mac `TxConfirmSheet`.** The sheet already *is* the confirmation, so the
  warnings are banners above the outputs, plus a chip on each nobody output.
  Approve means "proceed anyway".
  - **Confirmation turned off in Settings** (per identity) still resolves the
    recipients and sender, and **shows the sheet whenever a nobody is
    involved**. Turning the dialog off is a choice about routine spends, not
    about handing coins to a key anyone holds (`ActiveSession.effectiveApprover`).
  - **Actions whose target lives in the payload** (token transfer, master,
    rating, invites) are not visible as outputs, so they get their own
    confirmation *before* the transaction is built (table above).

### Acting on a nobody's word

- **Chat.** A nobody's text stays readable, but its interactive content is
  never drawn as something to click. It is replaced with
  *[Content from an unverifiable (nobody) identity is not shown]*:
  - Android: team invite and transfer notifications, file (HAT) and stream
    cards, voice notes.
  - Mac: file offers and voice notes.
- **Speakers.** Every speaker in a transcript is resolved, so the replacement
  happens as soon as a speaker is learned to be a nobody.
- **Invitations, mail, message requests, pending issues.** The sender or
  inviter gets the chip and the banner above.
- **Signatures.** A signature that verifies but was made by a nobody FID
  keeps its valid verdict and gets the "proves nothing" note.
- **Ratings, proofs, services, apps, protocols, codes, tokens.** The owner's
  avatar and name carry the mark wherever they are drawn.

## Strings

English is canonical. Chinese uses the product glossary, where Nobody is
**明人**. Android keys are in `values/strings.xml` and `values-zh/strings.xml`.
Mac strings live in `NobodyConsequence` / `NobodyText` until Phase 11
localisation, and must stay word-for-word with the English below.

| Android key | English | 中文 |
|---|---|---|
| `nobody` | Nobody | 明人 |
| `nobody_warning_title` | Nobody identity | 明人身份 |
| `nobody_list_intro` | Private key published on chain: | 私钥已在链上公开： |
| `proceed_anyway` | Proceed Anyway | 仍然继续 |
| `nobody_consequence_send` | Anything sent to it can be taken by anyone. | 发送给它的任何资产都可能被任何人取走。 |
| `nobody_consequence_send_from` | The sender's private key is public. Anyone can spend the same cash first, so this transaction may never confirm. | 发送方的私钥是公开的。任何人都可以抢先花掉同样的钞票，这笔交易可能永远无法确认。 |
| `nobody_consequence_encrypt` | Anyone can decrypt what you encrypt to it. | 任何人都能解密你加密给它的内容。 |
| `nobody_consequence_mail` | Anyone can read this mail and reply as the recipient. | 任何人都能读取这封邮件，并以收件人的身份回复。 |
| `nobody_consequence_multisig` | Anyone can sign as this member, so the multisig needs fewer real signatures than it appears. | 任何人都能以该成员身份签名，这个多签实际需要的真实签名比看上去少。 |
| `nobody_consequence_master` | Setting a master publishes your private key encrypted to the master. Anyone can decrypt it and take this identity for good. | 设置主人会把你的私钥加密给主人后公开上链。任何人都能解密它，从而永久接管这个身份。 |
| `nobody_consequence_team` | Anyone can read the team's messages and act as these members, including giving their consent. | 任何人都能读取团队消息，并以这些成员的身份行事，包括代其表示同意。 |
| `nobody_consequence_room` | Anyone can read the room's messages and speak as these members. | 任何人都能读取群组消息，并以这些成员的身份发言。 |
| `nobody_consequence_team_owner` | Anyone could run the team as its owner. | 任何人都可以作为团队所有者管理团队。 |
| `nobody_consequence_rate` | Anyone can act as it, so its reputation means nothing. The coin days you destroy to rate it are wasted. | 任何人都能冒充它，它的声誉没有意义。为评价它而销毁的币天将被浪费。 |
| `nobody_consequence_contact` | Anyone can speak as it, change its CID, and read what you send it. | 任何人都能冒充它发言、修改它的 CID，并读取你发给它的内容。 |
| `nobody_consequence_chat` | Anyone can read this conversation and write as it. | 任何人都能读取这段对话，并以它的身份发消息。 |
| `nobody_consequence_import` | Anyone can spend this key's funds, read its messages and act as it. Use it only as a public identity. | 任何人都能花掉这个密钥的资金、读取它的消息并冒充它。只把它当作公开身份使用。 |

The banner texts in §2 and the own-key alert in §3 are
`nobody_identity_banner`, `nobody_self_banner`, `nobody_receive_warning`,
`nobody_sender_warning`, `nobody_inviter_warning`, `nobody_partner_warning`,
`nobody_signature_note`, `nobody_member_consensus_note`,
`nobody_own_key_alert_title` / `_message` and `nobody_content_hidden`.

## Known differences between the clients

These are intentional, or follow from what each client has:

- The Mac has no team ownership-transfer or appoint UI, so nothing there to
  guard.
- Android confirms transactions in dialogs. Mac warns inside its existing
  approval sheet.
- The Mac pane header carries the live-identity banner above every pane.
  Android shows it on Home, Pay and Receive.
- **Adding a servant** gets the mark but no confirmation on either client: it
  only registers a fact already on chain.

## Not in scope

- **Counting consent.** No client excludes nobody members from team
  consensus. That would need a matching protocol rule.
- **Hard blocks.** By decision, nothing is refused.
- **Publishing your own key.** Neither client offers a FEIP4 carve.

## Verification

Use the default board `FHG8DW2eHQ5wNAJQnLNKzYUSo2YKt7ffff` as the test nobody.

1. Its avatar is grey with a skull badge, with a chip, in the picker, contacts, chat list, member lists and details.
2. Quit, go offline and relaunch: it is still marked.
3. Each of these asks first; Cancel aborts and Proceed continues:
   - sending FCH or a token to it;
   - encrypting to its pubkey or mailing it;
   - adding it to a multisig, setting it as master, inviting it, rating it.
4. On Mac, turn "confirm before signing" off: a payment to it still shows the approval sheet with the warning.
5. Import its prikey: it asks first, then the live-identity banner appears and the one-time alert does not.
6. Sign a message with its key and verify it: the result is valid, with the "proves nothing" note.
7. A FID that is not a nobody shows no chip, no banner and no dialog.
