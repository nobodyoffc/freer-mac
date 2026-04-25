import SwiftUI
import FCDomain

/// Reusable empty-state pane for Phase-7-x features that aren't built
/// out yet. Names what's coming so navigating to the pane feels
/// intentional rather than broken.
struct PlaceholderPaneView: View {
    let session: ActiveSession
    let title: String
    let systemImage: String
    let summary: String
    let bullets: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 12) {
                    Image(systemName: systemImage)
                        .font(.system(size: 32))
                        .foregroundStyle(.secondary)
                    Text(title).font(.title).bold()
                }

                Text(summary)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if !bullets.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(bullets, id: \.self) { b in
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: "circle.fill")
                                    .font(.system(size: 5))
                                    .padding(.top, 7)
                                    .foregroundStyle(.secondary)
                                Text(b).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .font(.callout)
                    .foregroundStyle(.secondary)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            Spacer()
        }
        .padding()
        .frame(minWidth: 480)
    }
}
