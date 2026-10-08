import SwiftUI
import FCDomain
import FCUI

/// A Publish/Update sheet opened by Release Sync to review one carve.
///
/// In review the sheet does not carve: it hands the fields back, and the
/// run carves them through the wallet's usual approval. Fields that come
/// from the repo (a document's DID and Summary, an archive's DID, a release
/// asset) are locked; changing them means changing the repo and scanning
/// again. Code and app edits are written back to `freeverse-release.json`.
struct ReleaseReview<Fields> {
    enum Decision {
        case carve(Fields)
        case skip
        case stop
    }

    /// The carve as Release Sync built it.
    let original: Fields
    /// Where the run is, and how the previous record went.
    var status: ReleaseRunStatus? = nil
    let decide: (Decision) -> Void
}

/// Shown at the top of each review page and while a carve is in progress,
/// so the user always knows which record this is and what just happened.
struct ReleaseRunStatus {
    enum Outcome {
        case carved(title: String, txid: String)
        case skipped(title: String)
        case failed(title: String, reason: String)
    }

    /// "Record 4 of 12".
    var position: String
    var previous: Outcome?
}

struct ReleaseRunStatusBanner: View {
    let status: ReleaseRunStatus

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let previous = status.previous {
                switch previous {
                case .carved(let title, let txid):
                    HStack(spacing: 6) {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                        Text("\(title) carved").bold()
                        CopyableText(display: String(txid.prefix(12)) + "…", copy: txid,
                                     font: .system(.caption, design: .monospaced))
                    }
                case .skipped(let title):
                    Label("\(title) skipped", systemImage: "forward.circle").foregroundStyle(.secondary)
                case .failed(let title, let reason):
                    Label("\(title) failed: \(reason)", systemImage: "xmark.octagon.fill").foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Text(status.position).font(.caption).foregroundStyle(.secondary)
        }
        .font(.callout)
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

/// The review sheet between pages: the carve the user just approved is
/// being stored, uploaded, signed or broadcast.
struct ReleaseRunWorkingView: View {
    let title: String
    let step: String
    let status: ReleaseRunStatus?
    let stop: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let status { ReleaseRunStatusBanner(status: status) }
            Spacer()
            HStack(spacing: 12) {
                ProgressView()
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.headline)
                    Text(step).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity)
            Spacer()
            HStack {
                Button("Stop Run", role: .cancel, action: stop)
                    .help("Stop after this carve. What went out already stays.")
                Spacer()
            }
        }
        .padding(20)
        .frame(width: 620, height: 300)
    }
}

/// Stop / Skip / Carve, in place of a sheet's Cancel / Save draft / Publish.
struct ReleaseReviewButtons: View {
    let canCarve: Bool
    let stop: () -> Void
    let skip: () -> Void
    let carve: () -> Void

    var body: some View {
        HStack {
            Button("Stop Run", role: .cancel, action: stop)
                .help("Stop here. Nothing more is carved; what went out already stays.")
            Spacer()
            Button("Skip", action: skip)
                .help("Leave this record out of the run. Records that link to it fail if it has no id yet.")
            Button("Carve", action: carve)
                .keyboardShortcut(.defaultAction)
                .disabled(!canCarve)
        }
    }
}

struct ReleaseReviewNote: View {
    let status: ReleaseRunStatus?
    let text: String

    var body: some View {
        if let status { ReleaseRunStatusBanner(status: status) }
        CopyableLabel(text, systemImage: "shippingbox")
            .font(.caption)
            .foregroundStyle(.blue)
            .fixedSize(horizontal: false, vertical: true)
    }
}
