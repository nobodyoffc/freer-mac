import SwiftUI
import FCCore
import FCDomain
import FCTransport
import FCUI

/// Who — or what — is on the other end of a conversation.
///
/// **Why routing is the headline section.** The obvious contents of a
/// details page are a name, an id and a member list, and those are here.
/// But the questions that actually go wrong in this app are about
/// *where a party lives*: a `home` map publishes a DOCK as a URL or as a
/// `(sid)` that has to be looked up on chain, and when that resolution
/// fails the symptom is silence — messages that neither send nor arrive,
/// with nothing on screen to say why. So this page shows the raw `home`
/// value, what it resolved to, and whether the poller is actually
/// watching that server. A party whose DOCK will not resolve says so
/// here instead of just being quiet.
///
/// Everything is read-only. It is a place to look, not a place to edit —
/// membership and naming are on-chain acts that belong to their own
/// flows.
struct ChatPartyDetailSheet: View {

    let session: ActiveSession
    let conversation: Conversation
    let onClose: () -> Void

    @State private var party: Party?
    @State private var loadError: String?
    @State private var loading = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if loading {
                        HStack(spacing: 8) {
                            ProgressView().controlSize(.small)
                            Text("Looking up…").foregroundStyle(.secondary)
                        }
                        .padding(.top, 8)
                    }
                    if let loadError {
                        Text(loadError)
                            .font(.callout)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    identitySection
                    if conversation.type == .square {
                        namingSection
                    }
                    routingSection
                    if conversation.type == .p2p {
                        peerSection
                    } else {
                        membersSection
                    }
                    chainSection
                }
                .padding(20)
            }

            Divider()
            HStack {
                Spacer()
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }
            .padding(12)
        }
        .frame(width: 560, height: 620)
        .task { await load() }
    }

    // MARK: - chrome

    private var header: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(party?.name ?? conversation.displayName ?? "Chat party")
                    .font(.title3.bold())
                    .lineLimit(1)
                Text(flavourName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var flavourName: String {
        switch conversation.type {
        case .p2p: return "Person"
        case .team: return "Team"
        case .square: return "Square"
        case .room: return "Room"
        }
    }

    // MARK: - sections

    private var identitySection: some View {
        section("Identity") {
            row(conversation.type == .p2p ? "FID" : "Group id") {
                CopyableText.elidingMiddle(conversation.targetId, head: 10, tail: 10, font: .body)
            }
            if let desc = party?.desc, !desc.isEmpty {
                row("Description") {
                    Text(desc).fixedSize(horizontal: false, vertical: true)
                }
            }
            if let owner = party?.owner, !owner.isEmpty {
                row("Owner") {
                    CopyableText.elidingMiddle(owner, head: 8, tail: 8)
                }
            }
            if let pubkey = party?.pubkey, !pubkey.isEmpty {
                row("Pubkey") {
                    CopyableText.elidingMiddle(pubkey, head: 10, tail: 10, font: .caption.monospaced())
                }
            }
        }
    }

    /// Where this party's messages rest, and whether we can get there.
    private var routingSection: some View {
        section("Routing") {
            row("DOCK") {
                if let dock = party?.resolvedDock {
                    VStack(alignment: .leading, spacing: 3) {
                        CopyableText(dock, font: .body)
                        if party?.dockIsOurs == true {
                            caption("This is your own DOCK — messages here are stored locally, not forwarded.")
                        }
                        if party?.dockIsPolled == true {
                            caption("Polled for incoming messages.")
                        } else if conversation.type != .p2p {
                            caption(
                                "Not currently polled. Refresh the group list so this DOCK is registered.",
                                warning: true
                            )
                        }
                    }
                } else if party?.rawDock != nil {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Could not be resolved").foregroundStyle(.red)
                        caption(
                            "The party publishes a DOCK, but it could not be turned into an address. "
                                + "Messages to them cannot be sent or received until it resolves.",
                            warning: true
                        )
                    }
                } else {
                    Text("None published").foregroundStyle(.secondary)
                }
            }

            if let raw = party?.rawDock, raw != party?.resolvedDock {
                row("Published as") {
                    VStack(alignment: .leading, spacing: 3) {
                        CopyableText.elidingMiddle(raw, head: 12, tail: 10, font: .caption.monospaced())
                        // The distinction that explains a whole class of
                        // failure: a SID needs a chain lookup, a URL
                        // does not.
                        caption(
                            HomeServiceResolver.extractSid(raw) != nil
                                ? "A service id — resolved to an address by looking it up on chain."
                                : "A direct address."
                        )
                    }
                }
            }

            if let home = party?.home, !home.isEmpty {
                row("Home") {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(home.keys.sorted(), id: \.self) { key in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(key)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                                    .frame(width: 130, alignment: .leading)
                                VStack(alignment: .leading, spacing: 1) {
                                    CopyableText.elidingMiddle(
                                        home[key] ?? "", head: 10, tail: 8, font: .caption.monospaced()
                                    )
                                    if let resolved = party?.resolvedHome[key],
                                       resolved != home[key] {
                                        Text("→ \(resolved)")
                                            .font(.caption2)
                                            .foregroundStyle(.tertiary)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Square only: the auction that stands in place of an owner.
    ///
    /// **This is the section a square's details were missing.** Every
    /// other flavour answers "who is in charge here" with a FID — a
    /// room's owner, a team's owner — and a square answers it with a
    /// number: whoever destroys more coin-days than the last change did
    /// may rename it. Showing the members and the routing while leaving
    /// that number off the page left the one fact that actually governs
    /// a square invisible, and `namers` unexplained wherever it did
    /// appear.
    private var namingSection: some View {
        section("Naming") {
            row("Anyone may rename") {
                Text("This square has no owner")
                    .foregroundStyle(.secondary)
            }
            row("Price of the next") {
                if let cdd = party?.cddToUpdate, cdd > 0 {
                    Text("More than \(cdd) CD").monospacedDigit()
                } else {
                    Text("1 CD — never renamed").foregroundStyle(.secondary)
                }
            }
            if let last = party?.namers.last, !last.isEmpty {
                row("Named last by") {
                    HStack(spacing: 6) {
                        CopyableText.elidingMiddle(last, head: 8, tail: 8)
                        if last == session.liveFid {
                            Text("you")
                                .font(.caption2)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Capsule().fill(Color.accentColor.opacity(0.18)))
                        }
                    }
                }
            }
            if let namers = party?.namers, namers.count > 1 {
                row("Renamed") {
                    Text("\(namers.count) times").monospacedDigit()
                }
            }
            caption(
                party?.cddToUpdate ?? 0 > 0
                ? "Coin-days are value that has sat still, and destroying them is what a rename costs. Each one raises the price of the next, so a name gets harder to take the more it has been fought over."
                : "Coin-days are value that has sat still, and destroying them is what a rename costs. Nobody has renamed this square yet, so the first change is as cheap as any carve — and sets the price of the one after it."
            )
        }
    }

    /// P2P only: what we last observed about the person.
    private var peerSection: some View {
        section("Presence") {
            row("Last seen") {
                Text(party?.lastSeen.map(Self.stamp.string(from:)) ?? "Never")
                    .foregroundStyle(party?.lastSeen == nil ? .secondary : .primary)
            }
            row("Last delivered by") {
                Text(party?.lastDeliveryMethod ?? "—").foregroundStyle(.secondary)
            }
            row("Direct FUDP") {
                Text(party?.fudpReachable == true ? "Registered" : "Not registered")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var membersSection: some View {
        section("Members\(party.map { " (\($0.members.count))" } ?? "")") {
            if let members = party?.members, !members.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(members, id: \.self) { fid in
                        HStack(spacing: 6) {
                            CopyableText.elidingMiddle(fid, head: 10, tail: 8, font: .caption.monospaced())
                            if fid == session.liveFid {
                                Text("you")
                                    .font(.caption2)
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(Capsule().fill(Color.accentColor.opacity(0.18)))
                            }
                        }
                    }
                }
            } else {
                Text("No member list synced yet.").foregroundStyle(.secondary)
            }
        }
    }

    private var chainSection: some View {
        section("Record") {
            if conversation.type != .p2p {
                row("You are") {
                    Text(party?.weAreMember == true ? "A member" : "Not a member")
                        .foregroundStyle(party?.weAreMember == true ? .primary : .secondary)
                }
            }
            if let height = party?.lastHeight {
                row("Last change at height") { Text("\(height)").monospacedDigit() }
            }
            if let txid = party?.lastTxId, !txid.isEmpty {
                row("Last transaction") {
                    CopyableText.elidingMiddle(txid, head: 10, tail: 10, font: .caption.monospaced())
                }
            }
            row("Messages here") {
                Text("\(party?.messageCount ?? 0)").monospacedDigit()
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
                .frame(width: 130, alignment: .leading)
            content()
            Spacer(minLength: 0)
        }
    }

    private func caption(_ text: String, warning: Bool = false) -> some View {
        Text(text)
            .font(.caption2)
            .foregroundStyle(warning ? Color.orange : Color.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    // MARK: - loading

    private func load() async {
        let loaded = await Party.load(session: session, conversation: conversation)
        await MainActor.run {
            loading = false
            switch loaded {
            case .success(let party): self.party = party
            case .failure(let error): self.loadError = String(describing: error)
            }
        }
    }
}

// MARK: - the model

/// Everything the sheet shows, gathered once.
///
/// Assembled off the view so the lookups — a chain read for a P2P
/// party's `home`, a SID resolution, a registry query — happen in one
/// place and the view stays a rendering of a value.
struct Party {

    var name: String?
    var desc: String?
    var owner: String?
    var pubkey: String?

    var home: [String: String]?
    /// Every home entry we could turn into an address, keyed the same.
    var resolvedHome: [String: String] = [:]
    /// The raw `home` value under the DOCK key, before resolution.
    var rawDock: String?
    var resolvedDock: String?
    var dockIsOurs = false
    /// Whether the poller currently has this DOCK registered.
    var dockIsPolled = false

    var members: [String] = []
    var weAreMember = false

    // Square only
    /// Who has named this square, oldest first. A history, not a role.
    var namers: [String] = []
    /// What the last change to this square destroyed, in coin-days —
    /// and therefore what the next one has to beat.
    var cddToUpdate: Int64?

    var lastHeight: Int64?
    var lastTxId: String?
    var messageCount = 0

    // P2P only
    var lastSeen: Date?
    var lastDeliveryMethod: String?
    var fudpReachable = false

    static func load(
        session: ActiveSession, conversation: Conversation
    ) async -> Result<Party, Error> {
        var party = Party()
        let id = conversation.targetId

        do {
            switch conversation.type {
            case .p2p:
                // A person's home is on chain, so this is the one
                // flavour that needs the network to answer at all.
                let freer = try? await DirectoryService(fapi: session.fapi).freer(byId: id)
                party.home = freer?.home
                party.pubkey = freer?.pubkey
                party.name = (try? session.contacts.get(fid: id))??.name
                if let peer = (try? session.peers.get(fid: id)) ?? nil {
                    party.lastSeen = peer.lastSeenAt.map {
                        Date(timeIntervalSince1970: Double($0) / 1000)
                    }
                    party.lastDeliveryMethod = peer.lastDeliveryMethod?.rawValue
                    party.fudpReachable = peer.fudpReachable ?? false
                }

            case .team:
                let team = try session.teams.get(id: id)
                party.name = team?.stdName
                party.desc = team?.desc
                party.owner = team?.owner
                party.home = team?.home
                party.members = team?.members ?? []
                party.lastHeight = team?.lastHeight
                party.lastTxId = team?.lastTxId

            case .square:
                let square = try session.squares.get(id: id)
                party.name = square?.name
                party.desc = square?.desc
                party.home = square?.home
                party.members = square?.members ?? []
                party.lastHeight = square?.lastHeight
                party.lastTxId = square?.lastTxId
                // No owner to read: a square has none. What stands in
                // its place is the coin-day price of the next change and
                // the list of who has paid it before, and those are the
                // two facts a square's details were missing.
                party.namers = square?.namers ?? []
                party.cddToUpdate = square?.cddToUpdate

            case .room:
                let room = try session.rooms.get(id: id)
                party.name = room?.name
                party.desc = room?.desc
                party.owner = room?.owner
                party.home = room?.home
                party.members = room?.members ?? []
            }

            party.weAreMember = party.members.contains(session.liveFid)
            party.messageCount = (try? session.messages.count(in: conversation.id)) ?? 0

            // One round trip for the whole home map, rather than one per
            // service — see `HomeServiceResolver.resolveBatch`.
            if let home = party.home, !home.isEmpty {
                party.resolvedHome = await session.homeServices.resolveBatch(home)
                party.rawDock = home[ServiceName.dock]
                party.resolvedDock = party.resolvedHome[ServiceName.dock]
            }
            if let dock = party.resolvedDock {
                party.dockIsOurs = await session.dockRegistry.isOwnDock(dock)
            }
            // A P2P party's messages rest on *our* DOCK, so the question
            // "is it polled" is about ours, not theirs.
            party.dockIsPolled = await session.dockRegistry.dockUrl(
                forTarget: id, type: conversation.type
            ) != nil

            return .success(party)
        } catch {
            return .failure(error)
        }
    }
}
