import Foundation
import Observation

/// The label the user gave a FID in Contacts — its first title — shown
/// beside the FID's CID or elided FID, wherever another person appears.
///
/// **Beside, never instead.** A CID is chosen by its owner, so an impostor
/// can pick one that reads like a friend's. Showing both says who the FID
/// claims to be and who the user knows it as. Android does the same
/// (`ContactLabel` / `ContactManager.getLabel`).
///
/// One per ``ContactsStore``: the store clears it on every write, and the
/// table is rebuilt on the next read. Reading ``label(for:)`` on the main
/// thread registers with Observation, so a view redraws when a contact is
/// added, edited or removed.
@Observable
public final class ContactLabels: @unchecked Sendable {

    /// The live identity's labels, for views that draw a FID without a
    /// session at hand (a shared FID line). Set by the app with the session.
    nonisolated(unsafe) public static var current: ContactLabels?

    /// Bumped on every change; read by ``label(for:)`` so views observe it.
    public private(set) var revision = 0

    @ObservationIgnored private let load: () -> [Contact]
    @ObservationIgnored private let lock = NSLock()
    @ObservationIgnored private var cache: [String: String]?

    init(load: @escaping () -> [Contact]) {
        self.load = load
    }

    /// The label for `fid`, or nil when it is no live contact or has no title.
    public func label(for fid: String) -> String? {
        if Thread.isMainThread { _ = revision }
        guard !fid.isEmpty else { return nil }
        return table()[fid]
    }

    /// `name` followed by " (label)", or `name` alone without one — for
    /// sentences, menus and notifications, where there is no second line.
    public func paren(_ name: String, for fid: String) -> String {
        guard let label = label(for: fid) else { return name }
        return "\(name) (\(label))"
    }

    /// Drop the table; the next read rebuilds it.
    func invalidate() {
        lock.lock()
        cache = nil
        lock.unlock()
        if Thread.isMainThread {
            revision &+= 1
        } else {
            DispatchQueue.main.async { self.revision &+= 1 }
        }
    }

    private func table() -> [String: String] {
        lock.lock()
        if let cache { lock.unlock(); return cache }
        lock.unlock()
        var built: [String: String] = [:]
        for contact in load() {
            if let label = Self.label(of: contact) { built[contact.id] = label }
        }
        lock.lock()
        cache = built
        lock.unlock()
        return built
    }

    /// A contact's label: its first non-empty title. A contact on its
    /// way out (delete broadcast) or inactive has none.
    static func label(of contact: Contact) -> String? {
        if contact.active == false || contact.deletePendingTxid != nil { return nil }
        for title in contact.titles ?? [] {
            let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty, trimmed != contact.cid, trimmed != contact.id { return trimmed }
        }
        return nil
    }
}
