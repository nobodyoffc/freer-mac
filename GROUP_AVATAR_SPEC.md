# Group avatar — cross-client spec

The avatar for a **room, team, or square**. Sits alongside `AvatarMaker`,
which stays exactly as it is and keeps serving FIDs.

Reference implementation: `Packages/FCUI/Sources/FCUI/Avatar/GroupAvatarMaker.swift`
(derivation) and `GroupAvatarView.swift` (drawing). Contract tests:
`Packages/FCUI/Tests/FCUITests/Avatar/GroupAvatarMakerTests.swift`.

## Why not the owner's face

Android currently sets `conversation.avatarDid` to the room/team owner, or
to a square's last namer, and renders that FID through `AvatarMaker`
(`ConversationAdapter.java:222`). Three problems:

1. **A group looks like a person.** In a list, a room owned by Alice and a
   DM with Alice are the same circle with the same face.
2. **It moves for the wrong reasons.** A team transfer or a square renaming
   repaints the group for every member. The thing users recognise a group
   by should not be the thing that changes most.
3. **On Mac it was worse than wrong.** `FidAvatarView(fid: targetId)` was
   being handed group ids: a room id is 29 characters and `AvatarMaker`
   needs 30, so every room fell back to a placeholder; a txid is long
   enough but hex contains `0`, which Base58 does not, so ~48% threw — and
   the other ~52% composited **a human face out of a transaction id**.

The fix is to draw the group's own permanent identity — **its id** — and
demote the owner to a badge. An owner can be transferred, a square can be
renamed by whoever last paid, membership is rewritten constantly. The id
is issued once and outlives all of it.

## The composition

```
┌─────────────────┐   rounded square  → it is a group (circle = person)
│  ▓ ░ ▓ ░ ▓      │   5×5 mirrored mark from sha256(groupId) → which group
│  ░ ▓ ▓ ▓ ░      │
│  ▓ ▓ ░ ▓ ▓      │   circular face badge, 38% of the side, bottom-right,
│  ░ ▓ ▓ (◕ ◕)    │   with a ring in the tile colour  → whose group
│  ▓ ░ ▓ ( ⌣ )    │
└─────────────────┘
```

The badge is omitted entirely when the owner is unknown. The ring is drawn
*inside* the tile bounds — the view must never paint past the size it was
given, or it shoulders its neighbours in a list row.

## Derivation

Let `H = sha256(utf8(groupId))`, 32 bytes, `H[0]` first. `groupId` is the
room id (`room_` + 24 hex) or the team/square txid — used verbatim, no
normalisation, no case folding.

**Pattern.** A 5×5 grid mirrored left-to-right, so only the 3 left columns
are free: 15 cells. For `i` in `0..<15`, free cell `i` is lit when `H[i]`
is odd. `i = column * 5 + row`, column-major, `row` counting downward.
Columns 3 and 4 mirror columns 1 and 0. If every free cell comes up dark
(1 group in 32768), invert all 15 — a blank tile is the one mark that
cannot be told from another blank.

**Hue.** `((H[15] << 8) | H[16]) % 12 * 30` degrees. Quantised to twelve
30° steps on purpose: a continuous hue makes 100° and 103° two groups
nobody can tell apart, spending entropy without buying distinctness.

**Palette.** Tile and mark are the same hue at different saturation and
brightness, defined outright per theme rather than by opacity, so a
selected row does not change the tile:

| | tile S/B | mark S/B |
|---|---|---|
| light | 0.16 / 0.97 | 0.64 / 0.70 |
| dark | 0.28 / 0.30 | 0.52 / 0.86 |

**Geometry**, as fractions of the side: corner radius 0.22, mark inset
0.12, badge diameter 0.50, badge ring `max(1, 0.055)`.

The badge is half the side: below that the owner is a coloured smudge
rather than a face at 32pt, and much above it the mark stops being the
thing the tile is mostly made of. It covers the tile from 44.5% to 94.5%
on both axes — roughly the bottom-right quadrant. Mirroring pays for most
of that, since the right two columns are only reflections and hide
nothing. The centre column is the one with no copy, and at this size the
badge clips the right edge of its lowest cells rather than swallowing
them.

## Java port

```java
public static boolean[] cells(String groupId) {          // row-major, 25
    byte[] h = Hash.sha256(groupId.getBytes(StandardCharsets.UTF_8));
    boolean[] free = new boolean[15];
    boolean any = false;
    for (int i = 0; i < 15; i++) { free[i] = (h[i] & 1) == 1; any |= free[i]; }
    if (!any) for (int i = 0; i < 15; i++) free[i] = true;

    boolean[] grid = new boolean[25];
    for (int col = 0; col < 5; col++) {
        int src = col < 3 ? col : 4 - col;
        for (int row = 0; row < 5; row++) grid[row * 5 + col] = free[src * 5 + row];
    }
    return grid;
}

public static int hueDegrees(String groupId) {
    byte[] h = Hash.sha256(groupId.getBytes(StandardCharsets.UTF_8));
    int raw = ((h[15] & 0xFF) << 8) | (h[16] & 0xFF);
    return (raw % 12) * 30;
}
```

Note `& 0xFF` — Java bytes are signed and Swift's `UInt8` is not; this is
the one place a port silently diverges.

## What it does not promise

The space is 2^15 patterns × 12 hues = **393,216 tiles**. Unique within
any one person's group list; *not* globally unique — a few thousand groups
and the birthday bound produces matching pairs. The extra bits would have
to be spent on finer hues or a denser grid, both invisible at the 32pt
where telling two rows apart actually matters.

## Android

Ported and shipped. `FC-AJDK/.../feature/avatar/GroupAvatarMaker.java`
holds the derivation and the drawing; `AvatarManager.getGroupAvatarBitmap`
is the app-level entry point (it resolves the night palette from
`Configuration.UI_MODE_NIGHT_MASK` and supplies the owner's face from the
existing avatar cache). Call sites converted: `ConversationAdapter`,
`ChatActivity`'s group toolbar, `JoinTeamActivity`, `JoinSquareActivity`,
`TeamInvitationAdapter`.

`conversation.avatarDid` keeps being written exactly as before (owner, or
a square's last namer) — it stays correct, it just means *who to badge*
rather than *what to draw*. No storage migration, no re-sync.

Two things a future port should not have to rediscover:

- **Do not clip a group avatar to the view's outline.** The avatar
  `ImageView` sets `clipToOutline="true"` with an oval background, which
  would clip the tile straight back into a person's circle. Swapping in a
  rounded-rect background works, but `clipToOutline` is honoured only
  under hardware rendering — a test that draws the view to a software
  canvas silently skips it and will "pass" either way. So group rows set
  `setBackground(null)` and `setClipToOutline(false)` instead, and the
  bitmap's own baked corners are the silhouette. Holders are recycled, so
  both branches must be set on every bind.
- **Cache on the owner's FID, not the bitmap.**
  `AvatarManager.getAvatarBitmap` decodes a fresh `Bitmap` per call, so a
  cache keyed on object identity misses every time and grows without
  bound.

The `ic_group` / `ic_team` fallbacks survive only for a missing group id:
the tile is a hash and is otherwise always renderable.

### Keeping the two in step

`FC-AJDK/src/test/java/.../GroupAvatarMakerTest.java` pins four ids'
patterns and hues against values produced by the Swift implementation. It
is not really a test of Java — it is the tripwire for drift. If it fails,
the two apps are drawing different pictures of the same group, and the fix
is never to update the constant.
