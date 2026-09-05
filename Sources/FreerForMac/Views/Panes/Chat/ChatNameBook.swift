import SwiftUI
import Observation
import FCCore
import FCDomain
import FCUI

/// Who a FID is, for the chat pane.
///
/// **Why a book and not a lookup at each call site.** A transcript is a
/// list of the same handful of people saying things over and over: a
/// hundred bubbles from a five-person room are five identities. Asking
/// the chain per bubble would be a hundred round trips for five answers,
/// and asking it inside a view body would do it again on every redraw.
/// So every FID the pane draws is resolved **once**, cached here, and
/// read synchronously from then on.
///
/// **What a CID is worth.** It is the name the chain publishes for a
/// FID, and it is the only string in a chat that a human recognises —
/// `F9kL…mBq2` names nobody. So wherever we know one, the CID *replaces*
/// the FID on screen rather than sitting next to it. What we don't know
/// stays an elided FID; a made-up name would be worse than digits.
///
/// **The chain is asked, but never waited for.** A row draws with
/// whatever is known now — the local address book, which costs nothing —
/// and the chain's answer arrives later and redraws it. Nothing in the
/// pane blocks on this, and a failed lookup costs a name, not a message.
@MainActor
@Observable
final class ChatNameBook {

    /// FID → CID, for the FIDs that have one. A FID *known* to have no
    /// CID is absent, exactly like a FID we haven't asked about — the
    /// distinction would change nothing on screen.
    private(set) var cids: [String: String] = [:]

    /// FIDs whose private key is public knowledge. Their avatars are
    /// drained of colour, the same as everywhere else in the app.
    private(set) var nobodies: Set<String> = []

    /// Everyone already asked about, answered or not, so a FID with no
    /// record is not re-fetched on every redraw.
    private var asked: Set<String> = []

    /// The CID for `fid`, or nil when the chain has published none.
    func cid(of fid: String) -> String? { cids[fid] }

    func isNobody(_ fid: String) -> Bool { nobodies.contains(fid) }

    /// What to *show* for a FID: its CID when there is one, else the
    /// FID with its middle elided.
    func label(for fid: String, head: Int = 6, tail: Int = 6) -> String {
        cids[fid] ?? fid.elidingMiddle(head: head, tail: tail)
    }

    /// Learn everybody in `fids` — the address book first, because it
    /// is free and already on this Mac, then the chain for whatever is
    /// left. Safe to call on every reload: FIDs already asked about are
    /// dropped before anything is fetched.
    func resolve(_ fids: [String], session: ActiveSession) {
        let wanted = Set(fids.filter { !$0.isEmpty && !asked.contains($0) })
        guard !wanted.isEmpty else { return }
        asked.formUnion(wanted)

        var unresolved: [String] = []
        for fid in wanted {
            if let contact = (try? session.contacts.get(fid: fid)) ?? nil {
                if let cid = contact.cid, !cid.isEmpty { cids[fid] = cid }
                if contact.isNobody == true { nobodies.insert(fid) }
                // A contact row can predate the CID it was later given,
                // so one without a name is still worth asking about.
                if contact.cid?.isEmpty != false { unresolved.append(fid) }
            } else {
                unresolved.append(fid)
            }
        }
        guard !unresolved.isEmpty else { return }

        let directory = session.directory
        Task { @MainActor [weak self] in
            // One call for the lot. `freerByIds` simply omits the FIDs
            // that have no record, so an unnamed identity is an absence
            // rather than an error to handle.
            guard let found = try? await directory.freerByIds(unresolved),
                  let self
            else { return }
            for (fid, freer) in found {
                if let cid = freer.cid, !cid.isEmpty { cids[fid] = cid }
                if freer.isNobody == true { nobodies.insert(fid) }
            }
        }
    }
}
