import SwiftUI

/// The avatar for a room, a team, or a square.
///
/// Three facts are drawn, in descending order of how much they can be
/// trusted to stay put:
///
/// 1. **It is a group** — the tile is a rounded square. ``FidAvatarView``
///    is a circle and always will be, so the two shapes never collide.
///    This is the part that works at 32pt in a list with no reading
///    involved: a group can no longer be mistaken for a DM with its
///    owner, which is exactly what an owner-face avatar was.
/// 2. **Which group** — the ``GroupAvatarMaker`` mark from the group id,
///    filling the tile. The id is the group's only permanent name, so it
///    gets the space.
/// 3. **Whose group** — the owner (a square's last namer) as a circular
///    face badge in the bottom-right, 38% of the side. A circle for a
///    person, inside a square for a group, is the composition saying
///    *this person owns this group* rather than *this group is this
///    person*. At 32pt the badge is ~12pt and reads as a presence; by
///    56pt the face is legible. That degradation is the right way round
///    — the size where you need to tell groups apart is the size where
///    the mark, not the face, is doing the work.
///
/// `ownerFid` is optional and drawing simply omits the badge when it is
/// nil. A group whose owner we have not learned yet still gets its
/// permanent mark; nothing about the tile shifts when the owner arrives
/// except the badge appearing.
public struct GroupAvatarView: View {

    public let groupId: String
    /// Owner for a room or team; last namer for a square. Nil draws no
    /// badge.
    public let ownerFid: String?
    public let size: CGFloat

    @Environment(\.colorScheme) private var colorScheme

    public init(groupId: String, ownerFid: String? = nil, size: CGFloat = 32) {
        self.groupId = groupId
        self.ownerFid = ownerFid
        self.size = size
    }

    // MARK: - geometry

    /// Fraction of the side taken by the owner badge.
    ///
    /// One half: large enough that the owner's face is recognisable in a
    /// 32pt list row, small enough that the mark is still the thing the
    /// tile is mostly made of.
    ///
    /// The badge covers the tile from 44.5% to 94.5% on both axes,
    /// roughly the bottom-right quadrant. Most of that is free, because
    /// the mark is mirrored — the right two columns are only reflections
    /// of the left two, so hiding them hides nothing. The centre column
    /// is the one that cannot be recovered, being its own reflection, and
    /// at this size the badge only clips the right edge of its lowest
    /// cells rather than swallowing them.
    private var badgeFraction: CGFloat { 0.50 }
    /// The gap punched around the badge so the face never sits directly
    /// on a lit cell.
    private var badgeRing: CGFloat { max(1, size * 0.055) }
    private var cornerRadius: CGFloat { size * 0.22 }
    /// Keeps the mark clear of the rounded corners.
    private var padding: CGFloat { size * 0.12 }

    // MARK: - colour

    private var hue: Double { GroupAvatarMaker.hueFraction(for: groupId) }

    /// Both palettes are defined outright rather than one being derived
    /// from the other by opacity: a tile that borrows its background
    /// from whatever is behind it stops being the same tile in a
    /// selected row.
    private var tileColor: Color {
        colorScheme == .dark
            ? Color(hue: hue, saturation: 0.28, brightness: 0.30)
            : Color(hue: hue, saturation: 0.16, brightness: 0.97)
    }

    private var markColor: Color {
        colorScheme == .dark
            ? Color(hue: hue, saturation: 0.52, brightness: 0.86)
            : Color(hue: hue, saturation: 0.64, brightness: 0.70)
    }

    public var body: some View {
        ZStack(alignment: .bottomTrailing) {
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(tileColor)
                .overlay(mark)
                .overlay(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .strokeBorder(markColor.opacity(0.25), lineWidth: 0.5)
                )
                .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))

            if let ownerFid, !ownerFid.isEmpty {
                FidAvatarView(fid: ownerFid, size: size * badgeFraction)
                    .background(
                        Circle()
                            .fill(tileColor)
                            .frame(
                                width: size * badgeFraction + badgeRing * 2,
                                height: size * badgeFraction + badgeRing * 2
                            )
                    )
                    // The separating ring is drawn *outside* the badge,
                    // so without this the view paints past the frame it
                    // was given and shoulders its neighbours in a row.
                    .padding([.trailing, .bottom], badgeRing)
            }
        }
        .frame(width: size, height: size)
    }

    /// The 5×5 mark. Drawn as one `Path` rather than 25 shape views so a
    /// list of these costs one draw call each.
    private var mark: some View {
        let cells = GroupAvatarMaker.cells(for: groupId)
        let side = GroupAvatarMaker.gridSide
        let inner = size - padding * 2
        let cell = inner / CGFloat(side)

        return Path { path in
            for row in 0..<side {
                for column in 0..<side where cells[row * side + column] {
                    path.addRect(
                        CGRect(
                            x: padding + CGFloat(column) * cell,
                            y: padding + CGFloat(row) * cell,
                            width: cell,
                            height: cell
                        )
                    )
                }
            }
        }
        .fill(markColor)
    }
}

#Preview {
    VStack(alignment: .leading, spacing: 20) {
        // A room id, a team/square txid, and an unknown-owner group.
        HStack(spacing: 16) {
            GroupAvatarView(
                groupId: "room_9f2c1ab4de77035c81ba64f2",
                ownerFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
                size: 32
            )
            GroupAvatarView(
                groupId: "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
                ownerFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
                size: 32
            )
            GroupAvatarView(groupId: "room_00000000000000000000ffff", size: 32)
            FidAvatarView(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", size: 32)
        }
        HStack(spacing: 16) {
            GroupAvatarView(
                groupId: "room_9f2c1ab4de77035c81ba64f2",
                ownerFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
                size: 56
            )
            GroupAvatarView(
                groupId: "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
                ownerFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
                size: 56
            )
            GroupAvatarView(groupId: "room_00000000000000000000ffff", size: 56)
            FidAvatarView(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", size: 56)
        }
    }
    .padding()
}
