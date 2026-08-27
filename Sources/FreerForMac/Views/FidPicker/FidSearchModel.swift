import Foundation
import Observation
import FCCore
import FCDomain

/// How many FIDs a picker hands back.
enum FidPickMode: Sendable {
    /// Click a row and the picker closes with that one FID. Android's
    /// `ChooseMode.CHOOSE_ONE_RETURN`.
    case one
    /// Tick rows, then confirm. Selection order is preserved.
    /// Android's `ChooseMode.CHOOSE_MULTI`.
    case many
}

/// One identity the picker offers or returns.
///
/// Everything the callers of a FID picker have ever wanted about a
/// chosen person, in the one shape: the FID itself, the CID to show a
/// human, and the pubkey — which is the field that decides whether a
/// message to them can be encrypted at all, so it travels with the FID
/// rather than being re-fetched by each caller (Android returns two
/// index-aligned string arrays for exactly this reason; a struct can't
/// fall out of alignment).
struct PickedFid: Identifiable, Hashable, Sendable {

    /// Where this row came from — shown as a badge so the user can tell
    /// a chain record from a local address book entry.
    enum Source: String, Sendable {
        case onChain
        case contact
        case myKey
        case list
        /// Typed (or scanned) by hand, with no record behind it.
        case typed

        var label: String {
            switch self {
            case .onChain: return "on chain"
            case .contact: return "contact"
            case .myKey:   return "mine"
            case .list:    return "listed"
            case .typed:   return "typed"
            }
        }

        var systemImage: String {
            switch self {
            case .onChain: return "link"
            case .contact: return "person.crop.circle"
            case .myKey:   return "key"
            case .list:    return "list.bullet"
            case .typed:   return "keyboard"
            }
        }
    }

    let fid: String
    var cid: String?
    /// CIDs this identity has used before. Matched against alongside
    /// the current one, mirroring the chain's `usedCids` field.
    var usedCids: [String]?
    /// 33-byte SEC1-compressed key when known. Nil means "we cannot
    /// encrypt to this person yet" — the callers that care check it.
    var pubkey: Data?
    var balance: Int64?
    var source: Source
    /// The on-chain record, when this row came from one. Callers that
    /// want the rest of it (home, master, cross-chain addresses) get it
    /// without a second round-trip.
    var freer: Freer?

    var id: String { fid }

    /// CID when the chain knows one, else the FID itself.
    var name: String {
        if let cid, !cid.isEmpty { return cid }
        return fid
    }

    init(
        fid: String,
        cid: String? = nil,
        usedCids: [String]? = nil,
        pubkey: Data? = nil,
        balance: Int64? = nil,
        source: Source = .typed,
        freer: Freer? = nil
    ) {
        self.fid = fid
        self.cid = cid
        self.usedCids = usedCids
        self.pubkey = pubkey
        self.balance = balance
        self.source = source
        self.freer = freer
    }

    /// Nil when the record carries no `id` — there is nothing to pick.
    init?(freer: Freer, source: Source = .onChain) {
        guard let fid = freer.id, !fid.isEmpty else { return nil }
        self.init(
            fid: fid,
            cid: freer.cid,
            usedCids: freer.usedCids,
            // KeyInfo.from(freer:) is the public path to a decoded
            // 33-byte pubkey; Contact.decodePubkeyHex is internal to
            // FCDomain.
            pubkey: KeyInfo.from(freer: freer)?.pubkey,
            balance: freer.balance,
            source: source,
            freer: freer
        )
    }

    init(contact: Contact) {
        self.init(
            fid: contact.id,
            cid: contact.cid,
            usedCids: contact.usedCids,
            pubkey: contact.pubkey,
            balance: contact.balance,
            source: .contact
        )
    }

    init(keyInfo: KeyInfo) {
        self.init(
            fid: keyInfo.fid,
            cid: keyInfo.label.isEmpty ? nil : keyInfo.label,
            pubkey: keyInfo.pubkey,
            source: .myKey
        )
    }

    /// Fill in whatever this row is missing from a freshly fetched
    /// on-chain record, without losing where the row came from.
    func enriched(with freer: Freer) -> PickedFid {
        var out = self
        if let cid = freer.cid, !cid.isEmpty { out.cid = cid }
        if let used = freer.usedCids, !used.isEmpty { out.usedCids = used }
        if out.pubkey == nil { out.pubkey = KeyInfo.from(freer: freer)?.pubkey }
        if let b = freer.balance { out.balance = b }
        out.freer = freer
        return out
    }
}

/// The search-and-select engine behind every FID picker in the app —
/// the Mac port of Android's `SearchFidsOnChainActivity`, minus the
/// screen.
///
/// **One box, two queries.** What the user types is either a FID or it
/// isn't, and the two cases are answered by different endpoints: an
/// exact `base.freerByIds` fetch, or a partial match on `id` +
/// `usedCids` through `base.search`. ``DirectoryService/findFreers(matching:after:size:timeoutMs:)``
/// makes that decision once for the whole app, so no picker gets to
/// disagree about what counts as a FID.
///
/// **Local first, chain on demand.** Contacts and this Setting's own
/// keys are already on the device, so they filter as the user types
/// with no round-trip. The chain is only asked when the user presses
/// Search (or hits Return) — a keystroke-triggered chain search would
/// spend a request per character on a term that isn't finished.
///
/// **A FID with no record is still a FID.** When the term parses as an
/// address but the chain has never heard of it, the picker offers it
/// anyway (``typedCandidate``): plenty of valid FIDs have never carved
/// anything. Android does the same via `addFidToSelectedData(fid, null)`.
@MainActor
@Observable
final class FidSearchModel {

    // MARK: - configuration

    private let session: ActiveSession
    let mode: FidPickMode
    /// When non-nil the picker is confined to these FIDs — the caller
    /// already knows the universe (a room's members, a multisig's
    /// signers) and the chain has nothing to add to it. Android's
    /// `EXTRA_FID_LIST`.
    private let pool: [String]?
    /// FIDs the caller will not accept back (usually because they are
    /// already in whatever list is being added to). Shown, but not
    /// selectable.
    let excluded: Set<String>

    static let pageSize = 10

    // MARK: - state

    var query: String = "" {
        didSet {
            guard query != oldValue else { return }
            // Typing invalidates the last chain answer; local matches
            // re-filter for free because `localMatches` is computed.
            if query.trimmingCharacters(in: .whitespacesAndNewlines) != searchTerm {
                clearChainResults()
            }
        }
    }

    private(set) var contacts: [PickedFid] = []
    private(set) var myKeys: [PickedFid] = []
    private(set) var poolRows: [PickedFid] = []

    private(set) var chainResults: [PickedFid] = []
    private(set) var searchTerm: String?
    private(set) var searchAfter: [String]?
    private(set) var searchTotal: Int64?
    /// The chain was asked and answered with nothing.
    private(set) var noChainMatches = false
    /// The term is a well-formed FID that the chain has no record for.
    private(set) var exactFidUnknown = false

    private(set) var searching = false
    private(set) var loadingMore = false
    private(set) var enriching = false
    var error: String?

    /// Chosen rows, in the order they were chosen.
    private(set) var selected: [PickedFid] = []
    private var selectedIndex: [String: Int] = [:]

    // MARK: - init

    init(
        session: ActiveSession,
        mode: FidPickMode = .many,
        query: String = "",
        preselected: [PickedFid] = [],
        pool: [String]? = nil,
        excluded: Set<String> = []
    ) {
        self.session = session
        self.mode = mode
        self.pool = pool
        self.excluded = excluded
        self.query = query
        for p in preselected where !excluded.contains(p.fid) {
            appendSelected(p)
        }
    }

    /// Whether the chain can be searched at all. A pooled picker is a
    /// closed list, so it hides the chain entirely.
    var searchesChain: Bool { pool == nil }

    // MARK: - local sources

    /// Read the device-local sources. Cheap and synchronous; call it
    /// from `onAppear`.
    func loadLocalSources() {
        do {
            contacts = (try session.contacts.all())
                .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
                .map(PickedFid.init(contact:))
        } catch let loadFailure {
            contacts = []
            error = String(describing: loadFailure)
        }
        myKeys = session.setting.keyInfoMap.values
            .sorted { $0.fid < $1.fid }
            .map(PickedFid.init(keyInfo:))
        if let pool {
            // Prefer what we already know locally for each pooled FID,
            // so the list is legible before (and without) any fetch.
            let byFid = Dictionary(
                (contacts + myKeys).map { ($0.fid, $0) },
                uniquingKeysWith: { first, _ in first }
            )
            poolRows = pool.map { fid in
                var row = byFid[fid] ?? PickedFid(fid: fid, source: .list)
                row.source = .list
                return row
            }
        }
    }

    /// Fill in CIDs and pubkeys for a pooled list in one round-trip, so
    /// a members list doesn't render as a column of raw addresses.
    func enrichPool() async {
        guard let pool, !pool.isEmpty, !enriching else { return }
        enriching = true
        defer { enriching = false }
        let missing = poolRows.filter { $0.cid == nil || $0.pubkey == nil }.map(\.fid)
        guard !missing.isEmpty else { return }
        guard let freers = try? await session.directory.freerByIds(missing) else { return }
        poolRows = poolRows.map { row in
            guard let f = freers[row.fid] else { return row }
            return row.enriched(with: f)
        }
    }

    /// Contacts / own keys / pooled FIDs matching the current query.
    /// An empty query lists them all — that makes the picker double as
    /// the contact picker Android reaches through a second screen.
    var localMatches: [PickedFid] {
        let rows = pool == nil ? contacts + myKeys : poolRows
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !term.isEmpty else { return dedupe(rows) }
        return dedupe(rows.filter { $0.matches(term) })
    }

    // MARK: - chain search

    /// The term parses as a FID but nothing on chain answers to it —
    /// offer it as-is rather than pretending it isn't an address.
    var typedCandidate: PickedFid? {
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (try? FchAddress(fid: term)) != nil else { return nil }
        guard !chainResults.contains(where: { $0.fid == term }),
              !localMatches.contains(where: { $0.fid == term })
        else { return nil }
        return PickedFid(fid: term, source: .typed)
    }

    var canSearch: Bool {
        searchesChain && !searching
            && !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Ask the chain about the current term. A valid FID is fetched
    /// exactly; anything else is a partial CID/FID match.
    func search() async {
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard searchesChain, !term.isEmpty, !searching else { return }
        searching = true
        error = nil
        noChainMatches = false
        exactFidUnknown = false
        defer { searching = false }

        do {
            let page = try await session.directory.findFreers(
                matching: term, size: Self.pageSize
            )
            chainResults = page.freers.compactMap { PickedFid(freer: $0) }
            searchTerm = term
            searchAfter = page.isExactFid ? nil : page.last
            searchTotal = page.total
            noChainMatches = page.freers.isEmpty && !page.isExactFid
            exactFidUnknown = page.freers.isEmpty && page.isExactFid
            // An exact hit is deliberately *not* auto-selected: a
            // one-shot picker closes on selection, and a picker seeded
            // from the field that opened it searches on appear — so
            // auto-selecting would flash the sheet open and shut before
            // the user saw whose record it found.
        } catch {
            clearChainResults()
            self.error = String(describing: error)
        }
    }

    /// Full page plus a server cursor means there is more — Android's
    /// `updateMoreButtonVisibility`.
    var hasMoreResults: Bool {
        guard let after = searchAfter, !after.isEmpty else { return false }
        if let total = searchTotal { return Int64(chainResults.count) < total }
        return chainResults.count % Self.pageSize == 0
    }

    /// How many matches the server still holds back, when it says.
    var remainingCount: Int64? {
        guard let total = searchTotal else { return nil }
        let left = total - Int64(chainResults.count)
        return left > 0 ? left : nil
    }

    func loadMore() async {
        guard let term = searchTerm,
              let after = searchAfter, !after.isEmpty,
              !loadingMore else { return }
        loadingMore = true
        defer { loadingMore = false }
        do {
            let page = try await session.directory.searchFreers(
                matching: term, after: after, size: Self.pageSize
            )
            // Cursor pages can overlap; never show the same FID twice.
            let seen = Set(chainResults.map(\.fid))
            chainResults.append(contentsOf:
                page.freers
                    .compactMap { PickedFid(freer: $0) }
                    .filter { !seen.contains($0.fid) }
            )
            searchAfter = page.last
            if let t = page.total { searchTotal = t }
        } catch {
            self.error = String(describing: error)
        }
    }

    func clearSearch() {
        query = ""
        clearChainResults()
    }

    private func clearChainResults() {
        chainResults = []
        searchTerm = nil
        searchAfter = nil
        searchTotal = nil
        noChainMatches = false
        exactFidUnknown = false
    }

    // MARK: - selection

    func isSelected(_ fid: String) -> Bool { selectedIndex[fid] != nil }

    func isSelectable(_ fid: String) -> Bool { !excluded.contains(fid) }

    /// Click behaviour for a result row. In one-shot mode the newest
    /// click replaces the previous pick, so there is never a stale
    /// second answer waiting behind the confirm.
    func toggle(_ picked: PickedFid) {
        guard isSelectable(picked.fid) else { return }
        if isSelected(picked.fid) {
            deselect(picked.fid)
            return
        }
        if mode == .one { clearSelection() }
        appendSelected(picked)
    }

    func select(_ picked: PickedFid) {
        guard isSelectable(picked.fid), !isSelected(picked.fid) else { return }
        if mode == .one { clearSelection() }
        appendSelected(picked)
    }

    /// Add every row currently listed — Android's "add the whole FID
    /// list" button, generalised to whatever the list is showing.
    func selectAllVisible() {
        guard mode == .many else { return }
        for row in localMatches + chainResults where isSelectable(row.fid) {
            if !isSelected(row.fid) { appendSelected(row) }
        }
    }

    func deselect(_ fid: String) {
        guard let idx = selectedIndex[fid] else { return }
        selected.remove(at: idx)
        reindexSelection()
    }

    func clearSelection() {
        selected = []
        selectedIndex = [:]
    }

    var canConfirm: Bool { !selected.isEmpty && !enriching }

    /// The final answer. Anything picked that we have no on-chain record
    /// for gets one last batch lookup first.
    ///
    /// Two callers depend on that record, and both fail *silently*
    /// without it. A contact saved before its owner published a key
    /// comes back unencryptable, and the caller cannot tell that from a
    /// genuine absence. And a room invitation is only queued for
    /// somebody who publishes a DOCK — a row with no record reads as
    /// "no DOCK", so the person is quietly not written to. So the
    /// lookup covers a missing `freer` as well as a missing pubkey:
    /// a row that *has* been looked up and has neither is a real answer
    /// and is not asked again.
    func confirm() async -> [PickedFid] {
        let missing = selected.filter { $0.pubkey == nil || $0.freer == nil }.map(\.fid)
        guard !missing.isEmpty else { return selected }
        enriching = true
        defer { enriching = false }
        // Fail-soft: a directory hiccup must not lose the selection.
        guard let freers = try? await session.directory.freerByIds(missing),
              !freers.isEmpty else { return selected }
        selected = selected.map { row in
            guard let f = freers[row.fid] else { return row }
            return row.enriched(with: f)
        }
        return selected
    }

    // MARK: - internals

    private func appendSelected(_ picked: PickedFid) {
        guard selectedIndex[picked.fid] == nil else { return }
        selectedIndex[picked.fid] = selected.count
        selected.append(picked)
    }

    private func reindexSelection() {
        selectedIndex = [:]
        for (i, p) in selected.enumerated() { selectedIndex[p.fid] = i }
    }

    /// Keep the first occurrence of each FID — a contact and an own key
    /// can name the same address.
    private func dedupe(_ rows: [PickedFid]) -> [PickedFid] {
        var seen = Set<String>()
        return rows.filter { seen.insert($0.fid).inserted }
    }
}

extension PickedFid {
    /// Substring match on the FID, the current CID, and any CID this
    /// identity used before — the local mirror of the chain's
    /// `part` query on `id` + `usedCids`.
    func matches(_ term: String) -> Bool {
        if fid.localizedCaseInsensitiveContains(term) { return true }
        if let cid, cid.localizedCaseInsensitiveContains(term) { return true }
        if let usedCids,
           usedCids.contains(where: { $0.localizedCaseInsensitiveContains(term) }) {
            return true
        }
        return false
    }
}
