import SwiftUI
import FCDomain
import FCUI

/// Where a published work says its bytes can be fetched — the record's
/// `locas` (FEIP21–25).
///
/// **DISK entries are shown, web entries are offered.** The app already
/// asks the `(sid)` and `fudp://` entries by itself while fetching (see
/// ``PublishBody/fetchURL(did:publisher:locas:progress:)``), and checks
/// whatever arrives against the DID, so listing them is information.
/// An `https://` entry is never fetched unasked: it is a server nobody
/// vouched for, and asking it tells it who is reading. So it is a link
/// the reader chooses to open, and what they download there is theirs
/// to check against the Document id shown beside it.
struct PublishLocasLine: View {
    let locas: [String]?

    var body: some View {
        let disks = PublishBody.diskLocas(locas)
        let webs = PublishBody.webLocas(locas)
        if !disks.isEmpty || !webs.isEmpty {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text("Stored at").font(.caption2).foregroundStyle(.tertiary)
                ForEach(disks, id: \.self) { loca in
                    CopyableText(
                        display: Self.display(loca),
                        copy: loca,
                        font: .system(.caption2, design: .monospaced)
                    )
                    .foregroundStyle(.secondary)
                    .help("A DISK service the publisher listed. This app tries it when fetching the work.")
                }
                ForEach(webs, id: \.self) { url in
                    Link(url.host ?? url.absoluteString, destination: url)
                        .font(.caption2)
                        .help("\(url.absoluteString)\n\nOpens in your browser. Not checked by this app: compare what you download with the Document id.")
                }
            }
        }
    }

    /// A DISK entry as a reader wants to see it: the SID, elided, or
    /// the FUDP host and port as written.
    private static func display(_ loca: String) -> String {
        if let sid = HomeServiceResolver.extractSid(loca) {
            return "DISK " + sid.elidingMiddle(head: 6, tail: 6)
        }
        return loca
    }
}
