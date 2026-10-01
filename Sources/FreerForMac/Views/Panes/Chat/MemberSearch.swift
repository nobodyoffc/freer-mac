import Foundation
import FCDomain

/// Narrowing a group's member list by what the user types.
///
/// **A member is matched on every name we hold for them**, not only the
/// one on screen: the FID itself, the CID the chain publishes, and what
/// the address book holds — the CIDs they used before and the titles the
/// user gave them. Somebody looking for a friend types whichever of those
/// they remember, and the row they want must not hide because the sheet
/// happened to draw a different one.
enum MemberSearch {

    /// Below this many members the whole list fits at a glance, and a
    /// search field would be furniture.
    static let threshold = 8

    /// The members whose FID or any of `names(fid)` contains `query`,
    /// case- and diacritic-insensitively, in their original order. An
    /// empty query keeps everyone.
    static func filter(
        _ fids: [String],
        by query: String,
        names: (String) -> [String]
    ) -> [String] {
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !term.isEmpty else { return fids }
        return fids.filter { fid in
            fid.localizedStandardContains(term)
                || names(fid).contains { $0.localizedStandardContains(term) }
        }
    }

    /// What the address book knows of each of `fids` that is worth
    /// matching on, keyed by FID. Read once when a sheet loads, so typing
    /// costs no store reads.
    static func contactKeys(_ fids: [String], session: ActiveSession) -> [String: [String]] {
        var keys: [String: [String]] = [:]
        for fid in fids {
            guard let contact = (try? session.contacts.get(fid: fid)) ?? nil else { continue }
            let all = [contact.cid].compactMap { $0 } + (contact.usedCids ?? []) + (contact.titles ?? [])
            if !all.isEmpty { keys[fid] = all }
        }
        return keys
    }
}
