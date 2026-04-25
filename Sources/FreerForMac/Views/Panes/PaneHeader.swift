import SwiftUI
import FCDomain
import FCUI

/// Shared header strip used at the top of every detail pane —
/// avatar + label + truncated FID + can-sign caption. Centralized so
/// each pane's header stays consistent and we only edit it once when
/// the avatar size or status badge style changes.
struct PaneHeader: View {
    let session: ActiveSession

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            FidAvatarView(fid: session.liveFid, size: 56)

            VStack(alignment: .leading, spacing: 4) {
                Text(session.liveKeyInfo.label.isEmpty
                     ? "Live: \(session.liveKeyInfo.kind.rawValue)"
                     : session.liveKeyInfo.label)
                    .font(.title2).bold()
                    .lineLimit(1)
                    .truncationMode(.tail)

                Text(session.liveFid)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack(spacing: 6) {
                    Image(systemName: session.canSign ? "key.fill" : "eye")
                    Text(session.canSign
                         ? "\(session.liveKeyInfo.kind.rawValue) — can sign"
                         : "\(session.liveKeyInfo.kind.rawValue) — watch only")
                }
                .font(.caption)
                .foregroundStyle(session.canSign ? Color.blue : Color.orange)
            }

            Spacer(minLength: 0)
        }
    }
}
