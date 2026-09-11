import SwiftUI
import FCCore

/// The nobody mark, drawn the same way everywhere a FID appears: a
/// greyscale avatar with a skull badge, a "Nobody" chip before the name,
/// and a banner where the consequence needs saying. The colour and the
/// geometry match Android (`NobodyUi`, `ic_skull.xml`); see `NOBODY_SPEC.md`.
public enum NobodyMark {
    /// Deep orange — a warning, not an error. Red is taken: it is the
    /// colour of the unread dots, and a red disc on an avatar reads as
    /// "something new" before it reads as "danger".
    public static let color = Color(red: 0xE6 / 255, green: 0x51 / 255, blue: 0x00 / 255)
    public static let bannerBackground = color.opacity(0.10)

    /// The badge radius as a fraction of the avatar's side.
    public static let badgeRadiusRatio: CGFloat = 0.2

    /// Where the badge's centre sits in an avatar of side `size`: on the
    /// diagonal, far enough in that an avatar clipped to a circle keeps
    /// the whole badge.
    public static func badgeCenter(size: CGFloat) -> CGPoint {
        let radius = size * badgeRadiusRatio
        let offset = (size / 2 - radius) * 0.7071
        return CGPoint(x: size / 2 + offset, y: size / 2 + offset)
    }
}

/// A skull, filled with its eyes, nose and teeth cut out (even-odd). The
/// path is Android's `ic_skull.xml` on the same 24×24 grid.
public struct NobodySkullShape: Shape {

    public init() {}

    public var style: FillStyle { FillStyle(eoFill: true, antialiased: true) }

    public func path(in rect: CGRect) -> Path {
        let scale = min(rect.width, rect.height) / 24
        let dx = rect.minX + (rect.width - 24 * scale) / 2
        let dy = rect.minY + (rect.height - 24 * scale) / 2
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: dx + x * scale, y: dy + y * scale)
        }

        var path = Path()
        // Cranium and jaw.
        path.move(to: p(12, 2))
        path.addCurve(to: p(2, 11), control1: p(6.48, 2), control2: p(2, 6.03))
        path.addCurve(to: p(6, 18.19), control1: p(2, 14.05), control2: p(3.64, 16.64))
        path.addLine(to: p(6, 21))
        path.addCurve(to: p(7, 22), control1: p(6, 21.55), control2: p(6.45, 22))
        path.addLine(to: p(17, 22))
        path.addCurve(to: p(18, 21), control1: p(17.55, 22), control2: p(18, 21.55))
        path.addLine(to: p(18, 18.19))
        path.addCurve(to: p(22, 11), control1: p(20.36, 16.64), control2: p(22, 14.05))
        path.addCurve(to: p(12, 2), control1: p(22, 6.03), control2: p(17.52, 2))
        path.closeSubpath()
        // Eyes.
        for cx in [8.5, 15.5] as [CGFloat] {
            path.addEllipse(in: CGRect(origin: p(cx - 2.2, 11.3 - 2.2),
                                       size: CGSize(width: 4.4 * scale, height: 4.4 * scale)))
        }
        // Nose.
        path.move(to: p(12, 14.2))
        path.addLine(to: p(10.7, 16.6))
        path.addLine(to: p(13.3, 16.6))
        path.closeSubpath()
        // Gaps between the teeth.
        for x in [9.9, 13.2] as [CGFloat] {
            path.addRect(CGRect(origin: p(x, 19.2), size: CGSize(width: 0.9 * scale, height: 2.1 * scale)))
        }
        return path
    }
}

/// The badge on a nobody's avatar: a white-ringed orange disc with a skull.
public struct NobodyBadge: View {
    public let diameter: CGFloat

    public init(diameter: CGFloat) {
        self.diameter = diameter
    }

    public var body: some View {
        ZStack {
            Circle().fill(Color.white).frame(width: diameter * 1.12, height: diameter * 1.12)
            Circle().fill(NobodyMark.color).frame(width: diameter, height: diameter)
            NobodySkullShape()
                .fill(Color.white, style: FillStyle(eoFill: true))
                .frame(width: diameter * 0.72, height: diameter * 0.72)
        }
        .accessibilityHidden(true)
    }
}

/// "Nobody" before a name, or nothing at all. Reads ``NobodyRegistry``, so
/// it appears on its own the moment a lookup learns the key was published.
/// The CID beside it stays: the chip is what says it cannot be trusted.
public struct NobodyChip: View {
    private let fid: String?
    private let force: Bool
    private let compact: Bool

    /// - Parameters:
    ///   - fid: whose chip; drawn only when the registry knows it is a nobody.
    ///   - force: draw regardless — for a caller that already knows.
    ///   - compact: the smaller type used above chat bubbles and in list rows.
    public init(fid: String?, force: Bool = false, compact: Bool = true) {
        self.fid = fid
        self.force = force
        self.compact = compact
    }

    public var body: some View {
        if force || NobodyRegistry.shared.isNobody(fid) {
            Text("Nobody")
                .font(compact ? .caption2.weight(.bold) : .caption.weight(.bold))
                .foregroundStyle(.white)
                .padding(.horizontal, compact ? 5 : 6)
                .padding(.vertical, 1)
                .background(Capsule().fill(NobodyMark.color))
                .fixedSize()
                .help("Nobody — this identity's private key is public, so anyone can act as it.")
        }
    }
}

/// A warning line where a nobody is involved, or nothing when it is not.
public struct NobodyBanner: View {
    private let fid: String?
    private let force: Bool
    private let message: String

    public init(fid: String?, message: String) {
        self.fid = fid
        self.force = false
        self.message = message
    }

    /// For a caller that decides visibility itself — e.g. "some members".
    public init(shown: Bool, message: String) {
        self.fid = nil
        self.force = shown
        self.message = message
    }

    public var body: some View {
        if force || NobodyRegistry.shared.isNobody(fid) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                NobodySkullShape()
                    .fill(NobodyMark.color, style: FillStyle(eoFill: true))
                    .frame(width: 14, height: 14)
                    .alignmentGuide(.firstTextBaseline) { $0[.bottom] - 2 }
                Text(message)
                    .font(.callout)
                    .foregroundStyle(NobodyMark.color)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 8).fill(NobodyMark.bannerBackground)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8).strokeBorder(NobodyMark.color.opacity(0.6))
            )
        }
    }
}

#Preview {
    VStack(alignment: .leading, spacing: 16) {
        HStack(spacing: 16) {
            FidAvatarView(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", size: 56)
            FidAvatarView(fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", size: 56, isNobody: true)
            FidAvatarView(fid: NobodyRegistry.defaultNobodyFid, size: 32)
            NobodyBadge(diameter: 40)
        }
        HStack { NobodyChip(fid: nil, force: true); Text("alice") }
        NobodyBanner(shown: true, message: "This identity's private key is public. Anyone can act as it.")
    }
    .padding()
    .frame(width: 420)
}
