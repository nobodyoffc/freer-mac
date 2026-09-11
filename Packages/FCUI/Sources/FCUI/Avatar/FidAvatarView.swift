import SwiftUI
import FCCore

/// SwiftUI view that renders an ``AvatarMaker`` avatar for a given
/// FID. Falls back to a neutral SF symbol if the FID is malformed
/// (so a half-typed or copy-paste-shortened address can't break a
/// list row).
///
/// `size` is the rendered side length in points; the underlying
/// `NSImage` is always native 150×150 and the view scales it.
///
/// **Nobody FIDs.** A FID whose private key is public knowledge renders
/// desaturated with a skull badge, matching Android's `NobodyUi`. The view
/// asks ``NobodyRegistry`` itself, so every avatar in the app is marked
/// the moment any lookup learns the key was published — no call site has
/// to remember. `isNobody` is still accepted for a caller that already
/// knows. Colour is the whole point of a generated avatar, so draining it
/// reads as "this identity is not yours alone" at a glance; the badge says
/// it where grey alone would pass for a dull palette. See `NOBODY_SPEC.md`.
public struct FidAvatarView: View {

    public let fid: String
    public let size: CGFloat
    public let isNobody: Bool

    public init(fid: String, size: CGFloat = 56, isNobody: Bool = false) {
        self.fid = fid
        self.size = size
        self.isNobody = isNobody
    }

    private var nobody: Bool {
        isNobody || NobodyRegistry.shared.isNobody(fid)
    }

    public var body: some View {
        let nobody = self.nobody
        return Group {
            if let nsImage = try? AvatarMaker.avatar(for: fid) {
                Image(nsImage: nsImage)
                    .resizable()
                    .interpolation(.high)
            } else {
                ZStack {
                    Circle().fill(Color.secondary.opacity(0.15))
                    Image(systemName: "person.fill")
                        .resizable()
                        .scaledToFit()
                        .padding(size * 0.18)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .frame(width: size, height: size)
        .grayscale(nobody ? 1 : 0)
        .clipShape(Circle())
        .overlay(alignment: .topLeading) {
            if nobody {
                // Drawn after the clip, inside the inscribed circle.
                let center = NobodyMark.badgeCenter(size: size)
                NobodyBadge(diameter: size * NobodyMark.badgeRadiusRatio * 2)
                    .position(center)
                    .frame(width: size, height: size)
            }
        }
        .help(nobody
              ? "Nobody FID — its private key is public, so anyone can act as it and spend from it."
              : "")
    }
}

#Preview {
    HStack(spacing: 16) {
        FidAvatarView(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", size: 56)
        FidAvatarView(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", size: 56, isNobody: true)
        FidAvatarView(fid: "FAlsoAFidThatNeverActuallyExisted1", size: 56)
        FidAvatarView(fid: "tooShort", size: 56)
    }
    .padding()
}
