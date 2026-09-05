import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Who said this, drawn to be found rather than to be read.
///
/// **Why an identity gets a badge and not a caption.** In every other
/// pane an id is a detail you go looking for, so `.tertiary` grey is
/// right. In a chat it is the opposite: the one question a transcript
/// has to answer at a glance is *who is talking*, and a grey 10-point
/// line above a bubble answers it only if you already know where to
/// look. So the identity is a tinted capsule — the one high-contrast
/// thing in a column of neutral bubbles.
///
/// **CID replaces FID; it never joins it.** When the chain publishes a
/// name for this identity, that name *is* the label, because it is the
/// only form a person recognises. With no CID the elided FID stands in
/// its place, middle-elided so the trailing characters — the ones
/// anybody actually verifies against — survive.
///
/// **Which of the two it is needs no marker.** A CID is a word and a
/// FID is `F9kL…mBq2`; nobody has ever had to look twice. The tag
/// carried an `@`/`#` glyph to say which, and it was answering a
/// question the strings answer themselves — so the colour and the
/// monospacing carry the distinction and the glyph is gone.
///
/// **The click copies the id either way, never the name.** A CID is a
/// name and names are not addresses: what you paste into a picker, a
/// send box or a member list is always the FID, so that is what lands
/// on the clipboard, and the tooltip says so when the two differ.
struct ChatIdentityTag: View {

    let fid: String
    /// The chain's name for `fid`, when it has published one.
    var cid: String?
    /// The flavour's colour — the tag belongs to the conversation it is
    /// drawn in, so a name in a square is red and the same name in a
    /// room is purple.
    var tint: Color
    /// Bigger for the header of a thread, smaller above a bubble.
    var size: Size = .small
    /// What this id is called, for the hover tip. A person's is a FID;
    /// a room's, a team's or a square's is a group id, and calling that
    /// a FID would send somebody looking for it in a FID picker.
    var noun: String = "FID"

    enum Size {
        case small, large

        var font: Font {
            switch self {
            case .small: return .caption.weight(.bold)
            case .large: return .callout.weight(.bold)
            }
        }

        var hPadding: CGFloat { self == .small ? 7 : 9 }
        var vPadding: CGFloat { self == .small ? 2 : 3 }
    }

    /// A named identity gets the flavour's colour; an unnamed one is
    /// deliberately quieter, because "we have no name for this person"
    /// is itself worth seeing — a stranger should not look like a
    /// contact.
    private var named: Bool { !(cid ?? "").isEmpty }

    private var color: Color { named ? tint : .secondary }

    var body: some View {
        CopyableText(
            display: named ? cid! : fid.elidingMiddle(head: 6, tail: 6),
            copy: fid,
            // An unnamed identity is digits, and digits are read
            // character by character — monospaced so they line up
            // between one bubble and the next.
            font: named ? size.font : size.font.monospaced(),
            color: color,
            help: named
                ? "\(cid!) — click to copy the \(noun) behind this name"
                : "Click to copy this \(noun)"
        )
        .padding(.horizontal, size.hPadding)
        .padding(.vertical, size.vPadding)
        .background(
            Capsule()
                .fill(color.opacity(0.14))
                .overlay(Capsule().strokeBorder(color.opacity(0.35), lineWidth: 0.5))
        )
        .fixedSize()
    }
}

#Preview {
    VStack(alignment: .leading, spacing: 10) {
        ChatIdentityTag(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", cid: "no1nrc7", tint: .accentColor)
        ChatIdentityTag(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", tint: .purple)
        ChatIdentityTag(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", cid: "freecash", tint: .red, size: .large)
    }
    .padding()
}
