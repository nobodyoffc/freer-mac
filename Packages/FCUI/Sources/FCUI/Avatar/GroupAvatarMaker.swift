import Foundation
import FCCore

/// Deterministic mark for a **group** — a room, a team, or a square.
///
/// ``AvatarMaker`` cannot serve here, and not merely as a matter of
/// taste. It requires a Base58 string of at least 30 characters and
/// reads positions 20–29 of it, which is a description of a FID and of
/// nothing else. A room id is `room_` + 24 hex characters — 29 long, so
/// it throws — and a team or square id is a 64-character txid whose hex
/// alphabet contains `0`, which Base58 does not, so roughly half of them
/// throw too. The half that *didn't* throw were the real problem: they
/// rendered a human face composited from a transaction id, a face
/// belonging to no one, stable enough that a user would learn it as the
/// group's own.
///
/// So a group gets its own generator, built on the one fact about a
/// group that never changes: **its id**. An owner can be transferred, a
/// square can be renamed by whoever last paid to rename it, a room's
/// membership is rewritten every time somebody joins. The id is issued
/// once and outlives all of it, which is why it is the mark and the
/// owner is only a badge on top of it (see ``GroupAvatarView``).
///
/// ## The spec, so Android can render the same pixels
///
/// Let `H = sha256(utf8(groupId))`, 32 bytes, `H[0]` first.
///
/// **Pattern** — a 5×5 grid, mirrored left-to-right, so only the three
/// left columns are free: 15 cells. For `i` in `0..<15`, cell `i` is lit
/// when `H[i]` is odd; `i` is `column * 5 + row`, column-major from the
/// top-left, `row` counting downward. Columns 3 and 4 mirror columns 1
/// and 0. If the whole grid comes up dark — 1 group in 32768 — every
/// cell is inverted, because a blank tile is the one pattern that cannot
/// be told from another blank tile.
///
/// **Hue** — `((H[15] << 8) | H[16]) % 12 * 30` degrees. Quantising to
/// twelve 30° steps is deliberate: a continuous hue makes 100° and 103°
/// two different groups that no one can tell apart, which spends the
/// entropy without buying any distinctness. Twelve steps are separable
/// at 32pt, and the pattern carries the rest.
///
/// That is the whole format: `sha256`, fifteen parity bits, two bytes of
/// hue. No assets, no fonts, no platform drawing calls in the
/// derivation — a Java port is `MessageDigest` and a loop.
///
/// ## What it does not promise
///
/// The space is 2^15 patterns × 12 hues = **393,216 tiles**, so tiles
/// are unique within any one person's group list and are *not* unique
/// globally — a few thousand groups and the birthday bound produces
/// matching pairs. That is the right trade to have made: the extra bits
/// would have to be spent on finer hues or a denser grid, and both are
/// invisible at the 32pt where telling two rows apart actually matters.
public enum GroupAvatarMaker {

    /// Grid side. Odd on purpose: an even grid mirrors into two halves
    /// with a seam down the middle, an odd one has a spine.
    public static let gridSide = 5
    /// Columns that carry information; the rest are reflections.
    public static let freeColumns = 3
    public static let freeCells = gridSide * freeColumns   // 15
    /// Distinct hues. 360 / 12 = 30° apart.
    public static let hueSteps = 12

    /// The 25 cells of the grid, row-major (`row * 5 + column`), which
    /// is the order a renderer wants — unlike the column-major order the
    /// hash is read in, which is the order the *spec* is written in.
    /// Keeping the two orders explicitly separate is what stops a port
    /// from quietly transposing every mark.
    public static func cells(for groupId: String) -> [Bool] {
        let hash = Hash.sha256(Data(groupId.utf8))

        // Free columns first, in the hash's own column-major order.
        var free = [Bool](repeating: false, count: freeCells)
        for i in 0..<freeCells {
            free[i] = hash[i] % 2 == 1
        }
        // A blank mark is the only unusable one: invert rather than ship it.
        if !free.contains(true) {
            free = free.map { !$0 }
        }

        var grid = [Bool](repeating: false, count: gridSide * gridSide)
        for column in 0..<gridSide {
            // Columns 3, 4 reflect columns 1, 0.
            let source = column < freeColumns ? column : gridSide - 1 - column
            for row in 0..<gridSide {
                grid[row * gridSide + column] = free[source * gridSide + row]
            }
        }
        return grid
    }

    /// The mark's hue in degrees, snapped to one of ``hueSteps``.
    public static func hueDegrees(for groupId: String) -> Int {
        let hash = Hash.sha256(Data(groupId.utf8))
        let raw = (Int(hash[15]) << 8) | Int(hash[16])
        return (raw % hueSteps) * (360 / hueSteps)
    }

    /// Hue as SwiftUI wants it, `0..<1`.
    public static func hueFraction(for groupId: String) -> Double {
        Double(hueDegrees(for: groupId)) / 360.0
    }
}
