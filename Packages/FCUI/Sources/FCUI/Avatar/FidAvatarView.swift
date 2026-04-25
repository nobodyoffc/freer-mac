import SwiftUI

/// SwiftUI view that renders an ``AvatarMaker`` avatar for a given
/// FID. Falls back to a neutral SF symbol if the FID is malformed
/// (so a half-typed or copy-paste-shortened address can't break a
/// list row).
///
/// `size` is the rendered side length in points; the underlying
/// `NSImage` is always native 150×150 and the view scales it.
public struct FidAvatarView: View {

    public let fid: String
    public let size: CGFloat

    public init(fid: String, size: CGFloat = 56) {
        self.fid = fid
        self.size = size
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
        .clipShape(Circle())
    }
}

#Preview {
    HStack(spacing: 16) {
        FidAvatarView(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", size: 56)
        FidAvatarView(fid: "FAlsoAFidThatNeverActuallyExisted1", size: 56)
        FidAvatarView(fid: "tooShort", size: 56)
    }
    .padding()
}
