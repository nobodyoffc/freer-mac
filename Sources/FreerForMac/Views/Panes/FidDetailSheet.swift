import SwiftUI
import FCDomain
import FCUI

/// Everything known about a FID — the page every id in this app links
/// to when a glance is not enough.
///
/// **Why this exists.** ``PaneHeader`` has to fit above twenty-odd
/// panes, so it shows an elided FID, three metrics as icons, and
/// balances rounded to a rail width. That is the right trade for a bar
/// you see constantly and the wrong one for the moments where the exact
/// value is the whole point: reading a pubkey out to someone, checking
/// whether a master is named, confirming a balance to the satoshi, or
/// finding out why a FID that "exists" has no on-chain record.
///
/// **It is not only about you.** The sheet started as the live
/// identity's page, and every fact it shows about your own FID — the
/// CID, the standing, the home map, whether the chain has ever heard of
/// it — is the same fact somebody wants about a service's owner, a
/// mail's sender, a code's publisher, a stranger in a square. So the
/// FID is a parameter. Pass none and it is your own; pass any other and
/// the local sections quietly change shape rather than lying: *This
/// vault* only appears for an identity this Mac actually holds keys
/// for, *In your contacts* only for one you have saved.
///
/// **Two sources, kept apart on purpose.** The local sections come from
/// ``KeyInfo`` and ``Contact`` and are true offline. Everything below
/// them comes from one `base.freerByIds` call and is the chain's
/// answer, which may be absent entirely: a FID that has never
/// transacted has no ``Freer``, and saying so plainly beats a page of
/// dashes.
///
/// The bar's cache is deliberately not reused. ``LiveFidInfo`` keeps
/// the eight fields the bar draws and drops the rest of the record —
/// master, guide, notice fee, income, expend, the home map, the
/// cross-chain addresses — which are exactly the fields somebody
/// opening a details page came to read. So this fetches the whole
/// `Freer` itself.
///
/// Read-only apart from one act: the rating button. A rating is not a
/// note about somebody, it is an on-chain statement weighted by the
/// coin-days it destroys, so it goes through its own sheet and its own
/// approval — see ``RateFreerSheet``.
struct FidDetailSheet: View {

    let session: ActiveSession
    /// Whose page this is. Defaults to the live identity, which is what
    /// the FID bar wants.
    let fid: String
    let onClose: () -> Void

    init(session: ActiveSession, fid: String? = nil, onClose: @escaping () -> Void) {
        self.session = session
        self.fid = fid ?? session.liveFid
        self.onClose = onClose
    }

    @State private var freer: Freer?
    @State private var contact: Contact?
    @State private var loading = true
    @State private var loadError: String?
    @State private var fetchedAt: Date?

    @State private var ratings: [RepuHist] = []
    @State private var ratingsTotal: Int64?
    @State private var ratingsCursor: [String]?
    @State private var ratingsLoading = false
    @State private var ratingsError: String?

    @State private var rating = false
    @State private var rateNote: String?

    /// The vault's own entry for this FID, when it has one. Nil for a
    /// stranger — which is the common case on this page now.
    private var keyInfo: KeyInfo? { session.setting.keyInfoMap[fid] }

    /// Whether this is the identity the user is currently living as.
    /// The one FID that may not be rated, and the one whose vault
    /// section can speak in the present tense.
    private var isLive: Bool { fid == session.liveFid }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if let loadError {
                        Text(loadError)
                            .font(.callout)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let rateNote {
                        noteBanner(rateNote)
                    }
                    identitySection
                    if keyInfo != nil { vaultSection }
                    if contact != nil { contactSection }
                    if freer != nil {
                        balanceSection
                        standingSection
                        recordSection
                        homeSection
                        otherChainsSection
                    } else if !loading {
                        noRecordSection
                    }
                    ratingsSection
                    groupSection
                }
                .padding(20)
            }

            Divider()
            footer
        }
        .frame(width: 580, height: 680)
        .task { await load() }
        .sheet(isPresented: $rating) {
            RateFreerSheet(session: session, ratee: fid, freer: freer) { txid in
                rating = false
                rateNote = "Rating broadcast — \(txid.elidingMiddle(head: 8, tail: 8)). "
                    + "It moves this FID's score when the block confirms."
                Task { await load() }
            } onCancel: {
                rating = false
            }
        }
    }

    // MARK: - chrome

    private var header: some View {
        HStack(spacing: 12) {
            FidAvatarView(
                fid: fid,
                size: 44,
                isNobody: freer?.isNobody == true
            )
            VStack(alignment: .leading, spacing: 3) {
                Text(displayName)
                    .font(.title3.bold())
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(role)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if loading {
                ProgressView().controlSize(.small)
            }
            rateButton
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    /// The best name we have, in the order a reader would want it: the
    /// chain's CID, then whatever the vault or the contact book calls
    /// it, then nothing — never the FID, which is already on the page
    /// in full one line down.
    private var displayName: String {
        if let cid = freer?.cid ?? keyInfo?.activeCid ?? contact?.cid, !cid.isEmpty {
            return cid
        }
        if let label = keyInfo?.label, !label.isEmpty { return label }
        return fid.elidingMiddle(head: 10, tail: 10)
    }

    /// **The one act on a read-only page.** Disabled rather than hidden
    /// when it cannot be used, with the reason in the tooltip — the
    /// same refusal style as the rest of this app. A FID cannot rate
    /// itself, and a watch-only identity cannot sign anything.
    @ViewBuilder
    private var rateButton: some View {
        let blocked = rateBlockedReason
        Button {
            rating = true
        } label: {
            Label("Rate", systemImage: "hand.thumbsup")
        }
        .disabled(blocked != nil)
        .help(blocked ?? "Rate this FID good or bad — an on-chain statement weighted by the coin-days it destroys")
    }

    private var rateBlockedReason: String? {
        if isLive {
            return "You are living as this FID — a FID cannot rate itself."
        }
        if !session.canSign {
            return "This identity has no private key on this Mac, so it cannot sign a rating."
        }
        if freer == nil && !loading {
            return "This FID has no on-chain record, and a rating only applies to a FID that has one."
        }
        return nil
    }

    private var footer: some View {
        HStack(spacing: 10) {
            Text(fetchedNote)
                .font(.caption2)
                .foregroundStyle(.secondary)
            Spacer()
            Button {
                Task { await load() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(loading)
            Button("Done", action: onClose).keyboardShortcut(.defaultAction)
        }
        .padding(12)
    }

    private var fetchedNote: String {
        guard let fetchedAt else { return "Chain record not loaded" }
        return "Chain record read \(fetchedAt.formatted(.relative(presentation: .named)))"
    }

    /// What this FID is *to the person reading*. For an identity in the
    /// vault that is its role; for anyone else it is the relationship,
    /// which is the honest answer — "Servant FID" would be a lie about
    /// a stranger who merely happens to have one.
    private var role: String {
        if let keyInfo {
            if fid == session.mainFid { return isLive ? "Main FID — live" : "Main FID" }
            if let master = session.mainKeyInfo.master, master == fid { return "Master" }
            let name: String
            switch keyInfo.kind {
            case .main:     name = "Main FID"
            case .watched:  name = "Watched FID"
            case .multisig: name = "Multisig group"
            case .servant:  name = "Servant FID"
            }
            return isLive ? "\(name) — live" : name
        }
        if contact != nil { return "In your contacts" }
        return "Another FID"
    }

    // MARK: - local sections

    private var identitySection: some View {
        section("Identity") {
            row("FID") {
                // Whole, not elided. Somebody opening this page wants
                // the string itself — the bar already has the short form.
                CopyableText(fid, font: .system(.body, design: .monospaced))
                    .fixedSize(horizontal: false, vertical: true)
            }
            row("CID") {
                if let cid = freer?.cid ?? keyInfo?.activeCid ?? contact?.cid, !cid.isEmpty {
                    CopyableText(cid, font: .body)
                } else {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("None registered").foregroundStyle(.secondary)
                        caption("A CID is a name bought on chain. Without one this FID is known by its address.")
                    }
                }
            }
            if let used = freer?.usedCids, !used.isEmpty {
                row("Previously") {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(used, id: \.self) { CopyableText($0, font: .caption) }
                    }
                }
            }
            if let hex = pubkeyHex {
                row("Pubkey") {
                    CopyableText(hex, font: .system(.caption, design: .monospaced))
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if freer?.isNobody == true {
                row("Nobody") {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("The private key behind this FID is public").foregroundStyle(.orange)
                        caption("Anyone can spend from it. Never send value here.", warning: true)
                    }
                }
            }
            if keyInfo != nil, fid != session.mainFid {
                row("Main FID") {
                    CopyableText.elidingMiddle(
                        session.mainFid, head: 10, tail: 10,
                        font: .system(.caption, design: .monospaced)
                    )
                }
            }
        }
    }

    /// What this Mac holds, as opposed to what the chain says. Only
    /// drawn for an identity the vault actually knows — for a stranger
    /// there is nothing here but three dashes.
    @ViewBuilder
    private var vaultSection: some View {
        if let keyInfo {
            section("This vault") {
                row("Label") {
                    if keyInfo.label.isEmpty {
                        Text(isLive ? "None — set one in the FID bar" : "None")
                            .foregroundStyle(.secondary)
                    } else {
                        Text(keyInfo.label)
                    }
                }
                row("Keys") {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(keyState(keyInfo).headline)
                        caption(keyState(keyInfo).detail)
                    }
                }
                row("Added") {
                    Text(Self.stamp.string(from: keyInfo.savedAt)).foregroundStyle(.secondary)
                }
            }
        }
    }

    /// The contact book's own words about this FID — the titles and
    /// memo somebody wrote to remember who this is. Absent for the
    /// vault's own identities and for anyone never saved.
    @ViewBuilder
    private var contactSection: some View {
        if let contact {
            section("In your contacts") {
                if let titles = contact.titles, !titles.isEmpty {
                    row("Titles") { Text(titles.joined(separator: " · ")) }
                }
                if let memo = contact.memo, !memo.isEmpty {
                    row("Memo") {
                        Text(memo).fixedSize(horizontal: false, vertical: true)
                    }
                }
                row("Saved") {
                    Text(Self.stamp.string(from: contact.addedAt)).foregroundStyle(.secondary)
                }
                if contact.onChain == true {
                    row("Carved") {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Yes")
                            caption("Your note about this FID is on chain, encrypted so only you can read it.")
                        }
                    }
                }
            }
        }
    }

    /// The key situation, phrased for whichever identity this is —
    /// `session.canSign` answers only for the live one, so a
    /// non-live entry reads its own ``KeyInfo`` instead.
    private func keyState(_ info: KeyInfo) -> (headline: String, detail: String) {
        let signable = info.hasPrivkey && info.kind.canSign
        if signable {
            return ("Private key held",
                    isLive
                        ? "This vault can sign transactions and decrypt messages for this FID."
                        : "This vault holds the key. Switch to this identity to sign as it.")
        }
        switch info.kind {
        case .multisig:
            return ("Group address",
                    "Spending needs signatures from the other members too — collect them in the co-sign sheet.")
        case .watched:
            return ("Watch-only",
                    "No private key here. Transactions can be built but must be signed elsewhere.")
        default:
            return ("No private key",
                    "This identity can be read but not spent from on this Mac.")
        }
    }

    // MARK: - chain sections

    private var noRecordSection: some View {
        section("On chain") {
            Text("No record yet").foregroundStyle(.secondary)
            caption(
                "The index has never seen this FID. That is normal for an identity that has "
                    + "not received or sent anything — the record appears with its first transaction."
            )
        }
    }

    private var balanceSection: some View {
        section("Balance") {
            row("Spendable") {
                VStack(alignment: .leading, spacing: 2) {
                    Text(Self.coins(freer?.balance) + " F")
                        .font(.body.monospacedDigit())
                    if let sats = freer?.balance {
                        caption("\(Self.grouped(sats)) satoshis, exactly")
                    }
                }
            }
            row("Cash", freer?.cash.map { "\(Self.grouped($0)) UTXOs" })
            row("Received", freer?.income.map { Self.coins($0) + " F" })
            row("Spent", freer?.expend.map { Self.coins($0) + " F" })
        }
    }

    /// The numbers the bar compacts to "1.2k". Here they are whole.
    private var standingSection: some View {
        section("Standing") {
            row("CD", freer?.cd.map(Self.grouped), note:
                "Coin-days accumulated — the fuel most on-chain operations are priced in.")
            row("CDD", freer?.cdd.map(Self.grouped), note:
                "Coin-days destroyed — how much of that fuel this FID has spent over its life.")
            row("Weight", freer?.weight.map(Self.grouped), note:
                "This FID's share of the chain's total coin-days — \(WeightMethod.cdPercent)% CD, "
                    + "\(WeightMethod.cddPercent)% CDD, \(WeightMethod.reputationPercent)% reputation.")
            row("Reputation", freer?.reputation.map(Self.grouped), note:
                "The CDD-weighted score others have carved about this FID. Good ratings add their "
                    + "coin-days, bad ones subtract them, so this can be negative.")
            row("Hot", freer?.hot.map(Self.grouped), note:
                "Coin-days spent rating this FID at all, whichever way. Attention, not approval.")
        }
    }

    private var recordSection: some View {
        section("Record") {
            row("Born at height", freer?.birthHeight.map(Self.grouped))
            row("Last active at height", freer?.lastHeight.map(Self.grouped))
            row("Named", freer?.nameTime.map(Self.chainTime))
            if let master = freer?.master ?? keyInfo?.master, !master.isEmpty {
                row("Master") {
                    VStack(alignment: .leading, spacing: 2) {
                        CopyableText.elidingMiddle(
                            master, head: 10, tail: 10,
                            font: .system(.caption, design: .monospaced)
                        )
                        caption("The FID this one has published its private key to.")
                    }
                }
            }
            if let guide = freer?.guide, !guide.isEmpty {
                row("Guide") {
                    CopyableText.elidingMiddle(guide, head: 10, tail: 10, font: .caption)
                }
            }
            if let fee = freer?.noticeFee, !fee.isEmpty {
                row("Notice fee") {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(fee) F").monospacedDigit()
                        caption(isLive
                                ? "What this FID charges to accept mail. Change it in Settings."
                                : "What this FID charges to accept mail — a mail to them pays it.")
                    }
                }
            }
        }
    }

    /// Where this FID tells the world it can be reached. The section
    /// that explains a whole class of silence — a DOCK nobody publishes
    /// is a DOCK nobody can deliver to.
    @ViewBuilder
    private var homeSection: some View {
        section("Home services") {
            if let home = freer?.home, !home.isEmpty {
                ForEach(home.keys.sorted(), id: \.self) { key in
                    row(key) {
                        CopyableText(home[key] ?? "", font: .system(.caption, design: .monospaced))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            } else {
                Text("None published").foregroundStyle(.secondary)
                caption(
                    isLive
                        ? "This FID carries no home map on chain, so nobody can look up where to reach it. "
                            + "Publish one from the Services pane if you want mail or chat to find you."
                        : "This FID carries no home map on chain, so there is nowhere to look up for "
                            + "chat delivery. Mail still reaches it — mail rests on the chain itself."
                )
            }
        }
    }

    @ViewBuilder
    private var otherChainsSection: some View {
        let addrs = otherChainAddresses
        if !addrs.isEmpty {
            section("Other chains") {
                ForEach(addrs, id: \.0) { name, value in
                    row(name) {
                        CopyableText(value, font: .system(.caption, design: .monospaced))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }

    private var otherChainAddresses: [(String, String)] {
        guard let f = freer else { return [] }
        return [
            ("Bitcoin", f.btcAddr), ("Bitcoin Cash", f.bchAddr),
            ("Ethereum", f.ethAddr), ("Litecoin", f.ltcAddr),
            ("Dogecoin", f.dogeAddr), ("Tron", f.trxAddr)
        ].compactMap { name, value in
            guard let value, !value.isEmpty else { return nil }
            return (name, value)
        }
    }

    // MARK: - ratings

    /// Who has said what about this FID, and how loudly.
    ///
    /// **Why the list and not just the score.** ``Freer/reputation`` is
    /// a running total, and a total cannot distinguish one whale's
    /// opinion from a hundred small agreeing ones. Each row here shows
    /// the coin-days behind it, which is the only honest measure of how
    /// much a given rating counted for.
    @ViewBuilder
    private var ratingsSection: some View {
        section("Ratings\(ratingsTotal.map { " (\($0))" } ?? "")") {
            if ratingsLoading && ratings.isEmpty {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Reading the history…").foregroundStyle(.secondary)
                }
            } else if let ratingsError {
                Text(ratingsError)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            } else if ratings.isEmpty {
                Text("Nobody has rated this FID").foregroundStyle(.secondary)
                caption(
                    "A rating is an on-chain act weighted by the coin-days it destroys, so it costs "
                        + "the rater something to make. Most FIDs have none."
                )
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(ratings) { item in
                        ratingRow(item)
                        if item.id != ratings.last?.id { Divider() }
                    }
                }
                if ratingsCursor != nil {
                    Button {
                        Task { await loadRatings(more: true) }
                    } label: {
                        if ratingsLoading {
                            ProgressView().controlSize(.small)
                        } else {
                            Text("Load older")
                        }
                    }
                    .buttonStyle(.link)
                    .disabled(ratingsLoading)
                }
            }
        }
    }

    @ViewBuilder
    private func ratingRow(_ item: RepuHist) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: item.kind == .good ? "hand.thumbsup.fill"
                            : item.kind == .bad ? "hand.thumbsdown.fill"
                            : "questionmark.circle")
                .foregroundStyle(item.kind == .good ? Color.green
                                 : item.kind == .bad ? Color.red : Color.secondary)
                .font(.caption)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if let rater = item.rater, !rater.isEmpty {
                        CopyableText.elidingMiddle(
                            rater, head: 8, tail: 8,
                            font: .system(.caption, design: .monospaced)
                        )
                        if rater == session.liveFid {
                            Text("you")
                                .font(.caption2)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Capsule().fill(Color.accentColor.opacity(0.18)))
                        }
                    }
                    Spacer(minLength: 6)
                    if let time = item.time {
                        Text(Self.chainTime(time))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
                // The weight is the rating. Shown signed, because that
                // is exactly what it did to the score above.
                if let hot = item.hot {
                    Text(signedWeight(item, hot: hot))
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(item.kind == .bad ? Color.red : Color.secondary)
                }
                if let cause = item.cause, !cause.isEmpty {
                    Text(cause)
                        .font(.caption)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func signedWeight(_ item: RepuHist, hot: Int64) -> String {
        guard let kind = item.kind else {
            // A rate string outside the protocol's two: it burned the
            // coin-days but moved no score, and pretending otherwise
            // would misread the row.
            return "\(Self.grouped(hot)) CDD — no score change"
        }
        let signed = kind == .good ? "+\(Self.grouped(hot))" : "−\(Self.grouped(hot))"
        return "\(signed) reputation · \(Self.grouped(hot)) CDD"
    }

    @ViewBuilder
    private var groupSection: some View {
        if let ms = keyInfo?.multisig ?? freer?.multisig {
            section("Group") {
                row("Signatures needed") {
                    if let m = ms.m, let n = ms.n {
                        Text("\(m) of \(n)").monospacedDigit()
                    } else {
                        Text("Unknown").foregroundStyle(.secondary)
                    }
                }
                if let fids = ms.fids, !fids.isEmpty {
                    row("Members") {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(fids, id: \.self) { member in
                                HStack(spacing: 6) {
                                    CopyableText.elidingMiddle(
                                        member, head: 10, tail: 8,
                                        font: .system(.caption, design: .monospaced)
                                    )
                                    if member == session.mainFid {
                                        Text("you")
                                            .font(.caption2)
                                            .padding(.horizontal, 5).padding(.vertical, 1)
                                            .background(Capsule().fill(Color.accentColor.opacity(0.18)))
                                    }
                                }
                            }
                        }
                    }
                }
                if let script = ms.redeemScript, !script.isEmpty {
                    row("Redeem script") {
                        VStack(alignment: .leading, spacing: 2) {
                            CopyableText.elidingMiddle(
                                script, head: 16, tail: 16,
                                font: .system(.caption2, design: .monospaced)
                            )
                            caption("Click to copy the whole script — a spend from this group is signed against it.")
                        }
                    }
                }
            }
        }
    }

    // MARK: - building blocks

    private func noteBanner(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            CopyableText(text, font: .callout)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button { rateNote = nil } label: {
                Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.green.opacity(0.10)))
    }

    private func section<Content: View>(
        _ title: String, @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption)
                .fontWeight(.semibold)
                .textCase(.uppercase)
                .tracking(0.5)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 10) {
                content()
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color(NSColor.controlBackgroundColor))
            )
        }
    }

    private func row<Content: View>(
        _ label: String, @ViewBuilder content: () -> Content
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 150, alignment: .leading)
            content()
            Spacer(minLength: 0)
        }
    }

    /// A plain value row. Absent means the server said nothing about
    /// this field, which is not the same as zero — so the row is drawn
    /// with an em dash rather than dropped, and the page keeps its shape
    /// between one FID and the next.
    @ViewBuilder
    private func row(_ label: String, _ value: String?, note: String? = nil) -> some View {
        row(label) {
            VStack(alignment: .leading, spacing: 2) {
                Text(value ?? "—")
                    .monospacedDigit()
                    .foregroundStyle(value == nil ? .secondary : .primary)
                if let note {
                    caption(note)
                }
            }
        }
    }

    private func caption(_ text: String, warning: Bool = false) -> some View {
        Text(text)
            .font(.caption2)
            .foregroundStyle(warning ? Color.orange : Color.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: - format

    private var pubkeyHex: String? {
        if let data = keyInfo?.pubkey ?? contact?.pubkey {
            return data.map { String(format: "%02x", $0) }.joined()
        }
        // A watch-only entry may hold no pubkey locally; the chain
        // publishes one as soon as the FID has spent anything.
        guard let hex = freer?.pubkey, !hex.isEmpty else { return nil }
        return hex
    }

    private static func grouped(_ n: Int64) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? String(n)
    }

    /// Satoshis → coins at full precision. The bar bands and rounds
    /// these; a details page must not.
    private static func coins(_ satoshis: Int64?) -> String {
        guard let satoshis else { return "—" }
        let f = NumberFormatter()
        f.numberStyle = .decimal
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        let value = Double(satoshis) / Double(Cash.satoshisPerBch)
        return f.string(from: NSNumber(value: value)) ?? "0"
    }

    /// Chain timestamps arrive as seconds in some records and
    /// milliseconds in others, and the wire does not say which. Anything
    /// past the year 2286 in seconds is milliseconds — no on-chain
    /// record predates the chain, so the ambiguity only runs one way.
    private static func chainTime(_ raw: Int64) -> String {
        let seconds = raw > 10_000_000_000 ? Double(raw) / 1000 : Double(raw)
        return stamp.string(from: Date(timeIntervalSince1970: seconds))
    }

    /// How many rating rows a page holds. Also the test for whether
    /// there are more — see ``loadRatings(more:)``.
    private static let ratingsPageSize = 25

    private static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    // MARK: - loading

    private func load() async {
        loading = true
        loadError = nil
        contact = (try? session.contacts.get(fid: fid)) ?? nil
        defer { loading = false }
        do {
            freer = try await session.directory.freer(byId: fid)
            fetchedAt = Date()
        } catch {
            loadError = "Couldn't read the chain record — \(error)"
        }
        await loadRatings(more: false)
    }

    /// The rating history, paged. Its own failure line rather than the
    /// page's: an FAPI that answers `freerByIds` but not `base.search`
    /// should cost this section, not the whole sheet.
    private func loadRatings(more: Bool) async {
        if ratingsLoading { return }
        ratingsLoading = true
        ratingsError = nil
        defer { ratingsLoading = false }
        do {
            let page = try await session.reputationService.received(
                by: fid,
                after: more ? ratingsCursor : nil,
                size: Self.ratingsPageSize
            )
            if more {
                ratings += page.ratings
            } else {
                ratings = page.ratings
            }
            ratingsTotal = page.total
            // A short page is the end of the walk, whatever cursor the
            // server hands back — offering "Load older" there would
            // fetch the same nothing again. Otherwise prefer the
            // server's own cursor: it matches the sort it actually used.
            ratingsCursor = page.ratings.count < Self.ratingsPageSize
                ? nil
                : (page.last ?? page.ratings.last?.cursor)
        } catch {
            ratingsError = "Couldn't read the rating history — \(error)"
        }
    }
}
