import SwiftUI

/// SwiftUI view that renders an ``AvatarMaker`` avatar for a given
/// FID. Falls back to a neutral SF symbol if the FID is malformed
/// (so a half-typed or copy-paste-shortened address can't break a
/// list row).
///
/// `size` is the rendered side length in points; the underlying
/// `NSImage` is always native 150×150 and the view scales it.
///
/// **Nobody FIDs.** Set `isNobody` for a FID whose private key is public
/// knowledge — a vanity key from a published list, a demo key, anything
/// anyone can spend from. The avatar renders desaturated, matching
/// Android's `NobodyBoard.applyNobodyMark` (a colour matrix at zero
/// saturation). Colour is the whole point of a generated avatar, so
/// draining it reads as "this identity is not yours alone" at a glance,
/// across every list the avatar appears in.
public struct FidAvatarView: View {

    public let fid: String
    public let size: CGFloat
    public let isNobody: Bool

    public init(fid: String, size: CGFloat = 56, isNobody: Bool = false) {
        self.fid = fid
        self.size = size
        self.isNobody = isNobody
    }

    public var body: some View {
        Group {
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
        .saturation(isNobody ? 0 : 1)
        .clipShape(Circle())
        .help(isNobody
              ? "Nobody FID — its private key is public, so anyone can spend from it."
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
