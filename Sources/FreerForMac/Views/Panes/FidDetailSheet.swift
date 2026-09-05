import SwiftUI
import FCDomain
import FCUI

/// Everything known about the identity you are living as — the page the
/// FID bar links to when a glance is not enough.
///
/// **Why this exists.** ``PaneHeader`` has to fit above twenty-odd panes,
/// so it shows an elided FID, three metrics as icons, and balances
/// rounded to a rail width. That is the right trade for a bar you see
/// constantly and the wrong one for the moments where the exact value is
/// the whole point: reading a pubkey out to someone, checking whether a
/// master is named, confirming a balance to the satoshi, or finding out
/// why a FID that "exists" has no on-chain record.
///
/// **Two sources, kept apart on purpose.** The *This vault* section comes
/// from the local ``KeyInfo`` — the label, the key situation, when the
/// identity was added — and is true offline. Everything below it comes
/// from one `base.freerByIds` call and is the chain's answer, which may
/// be absent entirely: a FID that has never transacted has no ``Freer``,
/// and saying so plainly beats a page of dashes.
///
/// The bar's cache is deliberately not reused. ``LiveFidInfo`` keeps the
/// eight fields the bar draws and drops the rest of the record — master,
/// guide, notice fee, income, expend, the home map, the cross-chain
/// addresses — which are exactly the fields somebody opening a details
/// page came to read. So this fetches the whole `Freer` itself.
///
/// Read-only throughout. The label is editable in the bar, the notice
/// fee in Settings; both are acts, and this is a place to look.
struct FidDetailSheet: View {

    let session: ActiveSession
    let onClose: () -> Void

    @State private var freer: Freer?
    @State private var loading = true
    @State private var loadError: String?
    @State private var fetchedAt: Date?

    private var fid: String { session.liveFid }
    private var keyInfo: KeyInfo { session.liveKeyInfo }

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
                    identitySection
                    vaultSection
                    if freer != nil {
                        balanceSection
                        standingSection
                        recordSection
                        homeSection
                        otherChainsSection
                    } else if !loading {
                        noRecordSection
                    }
                    groupSection
                }
                .padding(20)
            }

            Divider()
            footer
        }
        .frame(width: 580, height: 660)
        .task { await load() }
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
                Text(freer?.cid ?? keyInfo.activeCid ?? "This identity")
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
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
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

    /// Which identity this is, in the same words the person menu uses.
    private var role: String {
        if fid == session.mainFid { return "Main FID" }
        if let master = session.mainKeyInfo.master, master == fid { return "Master" }
        switch keyInfo.kind {
        case .main:     return "Main FID"
        case .watched:  return "Watched FID"
        case .multisig: return "Multisig group"
        case .servant:  return "Servant FID"
        }
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
                if let cid = freer?.cid ?? keyInfo.activeCid, !cid.isEmpty {
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
            if fid != session.mainFid {
                row("Main FID") {
                    CopyableText.elidingMiddle(
                        session.mainFid, head: 10, tail: 10,
                        font: .system(.caption, design: .monospaced)
                    )
                }
            }
        }
    }

    /// What this Mac holds, as opposed to what the chain says.
    private var vaultSection: some View {
        section("This vault") {
            row("Label") {
                if keyInfo.label.isEmpty {
                    Text("None — set one in the FID bar").foregroundStyle(.secondary)
                } else {
                    Text(keyInfo.label)
                }
            }
            row("Keys") {
                VStack(alignment: .leading, spacing: 2) {
                    Text(keyState.headline)
                    caption(keyState.detail)
                }
            }
            row("Added") {
                Text(Self.stamp.string(from: keyInfo.savedAt)).foregroundStyle(.secondary)
            }
        }
    }

    private var keyState: (headline: String, detail: String) {
        if session.canSign {
            return ("Private key held",
                    "This vault can sign transactions and decrypt messages for this FID.")
        }
        switch keyInfo.kind {
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
                "This FID's share of the chain's total coin-days.")
            row("Reputation", freer?.reputation.map(Self.grouped), note:
                "The CDD-weighted score others have carved about this FID.")
            row("Hot", freer?.hot.map(Self.grouped), note:
                "How much recent activity surrounds this FID.")
        }
    }

    private var recordSection: some View {
        section("Record") {
            row("Born at height", freer?.birthHeight.map(Self.grouped))
            row("Last active at height", freer?.lastHeight.map(Self.grouped))
            row("Named", freer?.nameTime.map(Self.chainTime))
            if let master = freer?.master ?? keyInfo.master, !master.isEmpty {
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
                        caption("What this FID charges to accept mail. Change it in Settings.")
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
                    "This FID carries no home map on chain, so nobody can look up where to reach it. "
                        + "Publish one from the Services pane if you want mail or chat to find you."
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

    @ViewBuilder
    private var groupSection: some View {
        if let ms = keyInfo.multisig ?? freer?.multisig {
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
        if let data = keyInfo.pubkey {
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
        defer { loading = false }
        do {
            freer = try await session.directory.freer(byId: fid)
            fetchedAt = Date()
        } catch {
            loadError = "Couldn't read the chain record — \(error)"
        }
    }
}
