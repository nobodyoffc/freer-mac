import AppKit
import SwiftUI
import FCDomain
import FCUI

/// The context menu's copy, for parity with the click. Every pane has
/// its own private copy of this two-liner; this one is the file's.
private func copyToPasteboard(_ value: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
}

/// A labelled FID on a list row — "Owner F1a2b…9xyz", "Publisher …" —
/// and the way into that FID's details page from anywhere in the app.
///
/// **Why this is one type.** Eight panes had a byte-identical private
/// `fidLine(_:_:)`: services, codes, protocols, apps, proofs, and the
/// three publish panes. That was fine while the line only rendered
/// text, and stopped being fine the moment it needed to *do* something
/// — eight copies is eight places to add the affordance and eight
/// chances to add it slightly differently.
///
/// **Click still copies.** That is the app's rule for every id it
/// draws, and a line that opened a sheet instead would break the one
/// gesture people already have muscle memory for. The details page gets
/// its own target: an info button that fades in on hover, plus a
/// context menu for the same thing without the hover. Both go through
/// `@Environment(\.inspectFid)`, so the sheet belongs to whichever
/// context installed a ``View/fidDetailsHost(session:)`` — the window
/// for a pane's rows, the sheet itself for a sheet's.
///
/// `name` is the pane's resolved CID for this FID when it has one — the
/// panes keep a `names` map they fill in batches. Passing it keeps the
/// display name and the copied value distinct: what you see is the
/// name, what you get is the FID.
struct FidLine: View {

    @Environment(\.inspectFid) private var inspectFid

    let label: String
    let fid: String?
    let name: String?

    @State private var hovering = false

    init(_ label: String, _ fid: String?, name: String? = nil) {
        self.label = label
        self.fid = fid
        self.name = name
    }

    var body: some View {
        if let fid, !fid.isEmpty {
            HStack(spacing: 3) {
                Text(label).font(.caption2).foregroundStyle(.tertiary)
                NobodyChip(fid: fid)
                CopyableText(
                    display: name ?? fid.elidingMiddle(head: 6, tail: 6),
                    copy: fid,
                    font: .system(.caption2, design: .monospaced),
                    help: name == nil ? nil : "Copy the FID behind this name"
                )
                .foregroundStyle(.secondary)

                Button {
                    inspectFid(fid)
                } label: {
                    Image(systemName: "info.circle")
                        .font(.caption2)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.tertiary)
                // Hidden rather than absent so the line does not
                // reflow under the pointer — a row whose text shifts
                // sideways on hover is unreadable to click.
                .opacity(hovering ? 1 : 0)
                .help("Show this FID's details, standing and ratings")
            }
            .onHover { hovering = $0 }
            .contextMenu {
                Button("Show FID details") { inspectFid(fid) }
                Button("Copy FID") { copyToPasteboard(fid) }
            }
        }
    }
}

/// A FID as a detail sheet's field value — avatar, name, id. The
/// heavier sibling of ``FidLine``, used where a record's owner gets a
/// row of its own rather than a corner of one.
///
/// Same five panes had this one too, character for character: services,
/// codes, protocols, apps, proofs. The avatar is the target here — it
/// is already the largest thing in the row and it is already about
/// nothing but who this is — with the hover button kept for the case
/// where the avatar reads as decoration.
struct FidValue: View {

    @Environment(\.inspectFid) private var inspectFid

    let fid: String?
    let name: String?

    @State private var hovering = false

    init(_ fid: String?, name: String? = nil) {
        self.fid = fid
        self.name = name
    }

    var body: some View {
        if let fid, !fid.isEmpty {
            HStack(spacing: 6) {
                Button { inspectFid(fid) } label: {
                    FidAvatarView(fid: fid, size: 22)
                }
                .buttonStyle(.plain)
                .help("Show this FID's details, standing and ratings")

                CopyableText(
                    display: name ?? fid.elidingMiddle(head: 10, tail: 10),
                    copy: fid,
                    font: .system(.caption, design: .monospaced),
                    help: name == nil ? nil : "Copy the FID behind this name"
                )

                Button { inspectFid(fid) } label: {
                    Image(systemName: "info.circle").font(.caption2)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.tertiary)
                .opacity(hovering ? 1 : 0)
                .help("Show this FID's details, standing and ratings")
            }
            .onHover { hovering = $0 }
            .contextMenu {
                Button("Show FID details") { inspectFid(fid) }
                Button("Copy FID") { copyToPasteboard(fid) }
            }
        } else {
            Text("—").font(.caption).foregroundStyle(.tertiary)
        }
    }
}

/// A FID rendered on its own, with no label — the avatar-adjacent id on
/// a card header, a rater in a list. Same rules as ``FidLine``: click
/// copies, hover reveals the way in.
struct FidBadge: View {

    @Environment(\.inspectFid) private var inspectFid

    let fid: String
    let name: String?
    let font: Font
    let head: Int
    let tail: Int

    @State private var hovering = false

    init(
        _ fid: String,
        name: String? = nil,
        font: Font = .system(.caption, design: .monospaced),
        head: Int = 8,
        tail: Int = 8
    ) {
        self.fid = fid
        self.name = name
        self.font = font
        self.head = head
        self.tail = tail
    }

    var body: some View {
        HStack(spacing: 3) {
            NobodyChip(fid: fid)
            CopyableText(
                display: name ?? fid.elidingMiddle(head: head, tail: tail),
                copy: fid,
                font: font,
                help: name == nil ? nil : "Copy the FID behind this name"
            )
            .foregroundStyle(.secondary)

            Button {
                inspectFid(fid)
            } label: {
                Image(systemName: "info.circle").font(.caption2)
            }
            .buttonStyle(.plain)
            .foregroundStyle(.tertiary)
            .opacity(hovering ? 1 : 0)
            .help("Show this FID's details, standing and ratings")
        }
        .onHover { hovering = $0 }
        .contextMenu {
            Button("Show FID details") { inspectFid(fid) }
            Button("Copy FID") { copyToPasteboard(fid) }
        }
    }
}
