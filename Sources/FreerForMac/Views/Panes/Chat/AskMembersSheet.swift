import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Ask specific people for something — Android's `AskSymkeyActivity` and
/// `AskRoomInfoActivity`, which are one screen with two payloads — or,
/// for a room's owner, send its details to chosen members (Android's
/// "Share room info" and "Share symkey", which pick recipients the same
/// way).
///
/// **Who you ask is a choice, not a broadcast.** Asking everyone tells
/// the whole group that this device lost the key, and in a room that
/// list is exactly the people whose opinion of you it affects. It also
/// costs a message each, on somebody's DOCK, paid for by us. So the
/// members are listed and the user picks.
///
/// The answers arrive on a later receive, through ``SignalRouter``, and
/// several answers are harmless: ``SymkeyStore`` never overwrites, so the
/// second copy of a key we already hold is a no-op rather than a race.
///
/// **Every question is recorded before it goes out.** A key from anyone
/// but the entity's owner is admitted only as the answer to a request
/// this device made (FIMP §4.2), so an ask that did not write to
/// ``KeyAsksStore`` would have its answers dropped on arrival.
struct AskMembersSheet: View {

    /// What is being asked for. The two differ in what comes back and in
    /// whose answer counts, which is why the sheet says both.
    enum Ask: Identifiable, Hashable {
        var id: Self { self }

        /// `version` nil asks for whatever is missing from this
        /// transcript — the thread menu's question. One version named is
        /// a single unreadable row asking for the key *it* needs, which is
        /// the only thing that can open it.
        case symkey(version: Int64?)
        case roomInfo
        /// Not a question: the owner sends the room's details, current
        /// key included, to the members picked.
        case shareRoomInfo

        static let symkey = Ask.symkey(version: nil)

        var isSymkey: Bool {
            if case .symkey = self { return true }
            return false
        }

        /// The one version this ask is for, when it is for one.
        var namedVersion: Int64? {
            if case .symkey(let version) = self { return version }
            return nil
        }

        var title: String {
            switch self {
            case .symkey(let version):
                guard let version else { return "Ask for the key" }
                return "Ask for \(SymkeyVersionText.inProse(version))"
            case .roomInfo:      return "Ask for this room's details"
            case .shareRoomInfo: return "Share this room's details"
            }
        }

        var requestType: RequestType {
            switch self {
            case .symkey:                  return .symkey
            case .roomInfo, .shareRoomInfo: return .roomInfo
            }
        }
    }

    let session: ActiveSession
    let style: ChatModeStyle
    let conversation: Conversation
    let ask: Ask
    let onClose: () -> Void
    let onSent: (String) -> Void

    @State private var members: [String] = []
    @State private var owner: String?
    @State private var chosen: Set<String> = []
    @State private var error: String?
    /// Whether we already hold a key for this entity. Only a caption —
    /// asking again is legitimate (a rotation we missed, a room whose
    /// membership drifted), so it informs rather than disables.
    @State private var alreadyHeld = false
    /// The key versions this conversation has messages sealed under and
    /// this device does not hold, oldest first.
    ///
    /// **This is what turns a request into a useful one.** A request
    /// naming no version asks for whatever the responder has now
    /// (FIMP4V3 §5.1), and their current version is usually the one we
    /// already hold — so the member missing an *old* key could ask
    /// forever and be handed the newest one every time. FIMP4V3 §7.4
    /// says recovery asks for the missing version, and this is how we
    /// know which that is.
    @State private var missingVersions: [Int64] = []

    /// What this ask will actually name: the one version a row asked for,
    /// or everything this transcript is missing.
    private var wantedVersions: [Int64] {
        guard ask.isSymkey else { return [] }
        if let named = ask.namedVersion { return [named] }
        return missingVersions
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(ask.title).font(.title3.bold())
                Spacer()
                Button("Cancel", role: .cancel, action: onClose)
            }

            Text(explanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if members.isEmpty {
                Text("This \(style.noun) lists nobody to ask on this device — not even you. Refresh it first.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                HStack {
                    Button(chosen.count == members.count ? "Select none" : "Select all") {
                        chosen = chosen.count == members.count ? [] : Set(members)
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    Spacer()
                    Text("\(chosen.count) of \(members.count) selected")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                list
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button(ask == .shareRoomInfo
                       ? "Send to \(chosen.count) member\(chosen.count == 1 ? "" : "s")"
                       : "Send request\(chosen.count == 1 ? "" : "s")") { send() }
                    .buttonStyle(.borderedProminent)
                    .disabled(chosen.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 480, height: 420)
        .onAppear(perform: load)
    }

    /// Which versions the request will name, when it names any. Said out
    /// loud because "ask for the key" is ambiguous the moment a key has
    /// been rotated, and the answer the user gets back depends entirely
    /// on which one was asked for.
    private var versionNote: String {
        guard ask.isSymkey, !wantedVersions.isEmpty else { return "" }
        let list = wantedVersions.map(versionPhrase).joined(separator: ", ")
        if ask.namedVersion != nil {
            return "This asks for **\(list)** — the key one message in this transcript was sealed with. "
        }
        return wantedVersions.count == 1
            ? "This asks for **\(list)** — the version this conversation needs and this device does not hold. "
            : "This asks for **\(list)** — the versions this conversation needs and this device does not hold, in one request naming them all. "
    }

    /// One version, as a person should read it: the time it was minted,
    /// with the clock only when another key shares its day. Never the raw
    /// number — see ``SymkeyVersionText``.
    private func versionPhrase(_ version: Int64) -> String {
        SymkeyVersionText.inProse(
            version,
            withTime: SymkeyVersionText.needsTime(version, among: wantedVersions + heldVersions)
        )
    }

    /// Versions this device already holds — only for deciding whether a
    /// date alone is ambiguous.
    private var heldVersions: [Int64] {
        (try? session.symkeys.versions(for: conversation.targetId)) ?? []
    }

    /// Whose answer can actually be applied — the part that decides who
    /// to tick, and the part a user has no way of guessing.
    private var explanation: String {
        switch ask {
        case .symkey where style.mode == .team:
            return "Any member who holds the team's key can send it. \(versionNote)It arrives on a later receive and is stored sealed to this identity."
        case .symkey:
            return "Any member who holds the room's key can send it. \(versionNote)Nothing here replaces a key already on this Mac — a copy that differs is kept beside it and tried when opening."
        case .roomInfo:
            return "Only the **owner's** answer can rewrite who is in this room — a member's answer still carries the name and the key, which is usually the part that was missing. The owner is ticked for you."
        case .shareRoomInfo:
            return "Each member picked gets the room's membership, name, DOCK and current key, sealed to them — the same message an invitation is. Nothing is rotated. A member with no published DOCK has nowhere to receive it and is skipped."
        }
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(members, id: \.self) { fid in
                    Button {
                        if chosen.contains(fid) { chosen.remove(fid) } else { chosen.insert(fid) }
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 8) {
                                Image(systemName: chosen.contains(fid) ? "checkmark.square.fill" : "square")
                                    .foregroundStyle(chosen.contains(fid) ? style.tint : .secondary)
                                FidAvatarView(fid: fid, size: 22)
                                Text(fid.elidingMiddle(head: 8, tail: 8))
                                    .font(.callout)
                                if fid == owner { ChatChip("owner", color: style.tint) }
                                if fid == session.liveFid { ChatChip("your other devices", color: style.tint) }
                                Spacer(minLength: 0)
                            }
                            if fid == session.liveFid, ask != .shareRoomInfo {
                                Text(ownRowHint)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .padding(.leading, 26)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .padding(.vertical, 5)
                    Divider()
                }
            }
        }
    }

    /// What ticking our own FID actually does — the one row whose
    /// meaning is not obvious, because on the face of it it reads as
    /// asking yourself a question you already know you cannot answer.
    ///
    /// It is not. The request goes out on the ordinary P2P route
    /// addressed to this identity, and **every device signed in as this
    /// identity collects it** — so the one that still holds the key
    /// answers, and this one does not (a device with no key has nothing
    /// to reply with, so its own copy is a silent no-op). It is the only
    /// thing to tick for a re-installed **owner**, whose other device is
    /// the only copy of the key that exists.
    private var ownRowHint: String {
        alreadyHeld
            ? "Your other devices signed in as this identity. This device already holds a key — an answer can still bring a newer version."
            : "Your other devices signed in as this identity. Whichever one still holds the key answers; this one stays quiet."
    }

    // MARK: - actions

    private func load() {
        do {
            let me = session.liveFid
            switch style.mode {
            case .room:
                let room = try session.rooms.get(id: conversation.targetId)
                owner = room?.owner
                members = ask == .shareRoomInfo
                    // An owner telling the room: there is nobody to tell
                    // but the others.
                    ? (room?.others(than: me) ?? [])
                    : roster(all: room?.members, owner: room?.owner, me: me)
            case .team:
                let team = try session.teams.get(id: conversation.targetId)
                owner = team?.owner
                members = roster(all: team?.members, owner: team?.owner, me: me)
            case .square, .p2p:
                // Neither has a key, so neither reaches this sheet.
                members = []
            }
            alreadyHeld = (try? session.symkeys.has(entityId: conversation.targetId)) ?? false
            missingVersions = sealedVersionsNotHeld()
            // The owner is the answer that counts most in both cases, so
            // it starts ticked; everything else is the user's call —
            // except when the owner *is* us, where the only useful tick
            // is our own row, and pre-ticking it is what makes the
            // re-installed owner's one path out of this the default.
            if ask == .shareRoomInfo { chosen = Set(members) }
            else if let owner, members.contains(owner) { chosen = [owner] }
            else if members.contains(me) { chosen = [me] }
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    /// Who to offer, our own FID **first**.
    ///
    /// It used to be filtered out, on the reading that asking yourself
    /// is a no-op. It is not: an identity is not a device, and a second
    /// Mac signed in as this FID has the identity and none of the keys.
    /// The request travels the ordinary P2P route to this FID, and the
    /// device that still holds the key answers it like any member's —
    /// see ``KeyExchange/requests(entityId:kind:from:to:now:)``. Leaving
    /// it out left a re-installed owner, whose other device is the only
    /// holder in existence, with nobody to ask.
    ///
    /// It leads because it is the one row the user cannot reconstruct
    /// for themselves, and the owner keeps its chip wherever it lands.
    private func roster(all: [String]?, owner: String?, me: String) -> [String] {
        let listed = all ?? []
        let others = listed.filter { $0 != me }
        // Only if we are actually in the entity — the sheet is reachable
        // for a room whose membership has drifted past us, and offering
        // to ask ourselves about one we are not in would be a request
        // every responder is right to ignore.
        guard listed.contains(me) || owner == me else { return others }
        return [me] + others
    }

    private func share() {
        do {
            let (outbound, unreachable) = try session.roomService.shareInfo(
                conversation.targetId,
                to: Array(chosen),
                as: session.liveFid,
                pubkeys: { fid in try session.knownPubkey(of: fid) },
                homes: { fid in try session.knownHome(of: fid) }
            )
            for message in outbound {
                guard let to = message.targetId else { continue }
                try session.outbox.enqueue(message, in: Conversation.id(type: .p2p, targetId: to))
            }
            Task { _ = try? await session.courier.drainOutbox(as: session.liveFid) }
            onSent(unreachable.isEmpty
                   ? "\(outbound.count) update(s) queued."
                   : "\(outbound.count) update(s) queued. \(unreachable.count) member(s) publish no DOCK, so there is nowhere to leave one for them.")
            onClose()
        } catch {
            self.error = String(describing: error)
        }
    }

    /// The versions this transcript needs and this device lacks.
    ///
    /// Read from the sealed rows themselves rather than from the
    /// conversation's cached `symkeyVersion`, because the cache names
    /// the newest version seen and the rows we cannot read are usually
    /// older than that.
    private func sealedVersionsNotHeld() -> [Int64] {
        guard style.mode == .team || style.mode == .room else { return [] }
        let held = Set((try? session.symkeys.versions(for: conversation.targetId)) ?? [])
        let sealed = (try? session.messages.sealed(in: conversation.id)) ?? []
        return Set(sealed.compactMap(\.symkeyVersion)).subtracting(held).sorted()
    }

    private func send() {
        if ask == .shareRoomInfo { return share() }
        do {
            let versions = wantedVersions
            // **Every question sent is recorded before it goes.** A key
            // arriving from a member who is not the entity's owner is
            // admitted only as the answer to a request this device made
            // (FIMP §4.2), matched by `requestId` against
            // ``KeyAsksStore``. An ask that sent messages without
            // recording them would therefore have every answer dropped
            // on arrival — the request would go out, the member would
            // answer, and nothing would happen, for good.
            //
            // The cooldown is asked first, per person per version
            // (§7.4), so a second press inside two minutes does not pay
            // to ask the same people the same thing again.
            let asked = Array(chosen)
            let recordedVersions = versions.isEmpty
                ? [KeyAsksStore.currentVersion]
                : versions
            var allowed: Set<String> = []
            var waiting: [(fid: String, until: Date)] = []
            for version in recordedVersions {
                let gate = try session.keyAsks.askable(
                    asked, entityId: conversation.targetId, version: version
                )
                allowed.formUnion(gate.allowed)
                waiting.append(contentsOf: gate.waiting)
            }
            guard !allowed.isEmpty else {
                let soonest = waiting.map(\.until).min() ?? Date()
                let seconds = max(1, Int(soonest.timeIntervalSinceNow.rounded(.up)))
                error = "Already asked \(waiting.count == 1 ? "them" : "them all") just now. "
                    + "Askable again in \(seconds)s."
                return
            }

            // Three shapes, and which one it is depends on what is
            // actually missing:
            //
            // - several versions → one `SYMKEY_HISTORY` naming them all
            //   (FIMP4V3 §5.2). One message instead of one per version,
            //   on somebody's DOCK, paid for by us.
            // - exactly one → a plain `SYMKEY` naming it (§5.1).
            // - none, because nothing is sealed → a version-less
            //   `SYMKEY`, which asks for the current key. That is the new
            //   joiner who holds nothing, and it is what they need.
            var outbound: [ImMessage] = []
            if versions.count > 1 {
                outbound = KeyExchange.historyRequests(
                    entityId: conversation.targetId,
                    versions: versions,
                    from: session.liveFid,
                    to: Array(allowed)
                )
            } else {
                outbound = KeyExchange.requests(
                    entityId: conversation.targetId,
                    kind: ask.requestType,
                    version: versions.first,
                    from: session.liveFid,
                    to: Array(allowed)
                )
            }
            var sent: [(fid: String, requestId: String)] = []
            for message in outbound {
                guard let to = message.targetId else { continue }
                try session.outbox.enqueue(message, in: Conversation.id(type: .p2p, targetId: to))
                if let requestId = message.id { sent.append((fid: to, requestId: requestId)) }
            }
            // One request may name several versions, and an answer to any
            // of them carries that one request's id — so each version
            // asked about records the same ids.
            for version in recordedVersions {
                try session.keyAsks.record(
                    entityId: conversation.targetId,
                    version: version,
                    kind: ask.requestType,
                    sent: sent
                )
            }
            Task { _ = try? await session.courier.drainOutbox(as: session.liveFid) }
            let forWhat = versions.isEmpty
                ? ""
                : " for \(versions.map(versionPhrase).joined(separator: ", "))"
            let skipped = waiting.isEmpty
                ? ""
                : " \(Set(waiting.map(\.fid)).count) were asked too recently to ask again."
            onSent("Asked \(sent.count) member\(sent.count == 1 ? "" : "s")\(forWhat). The answer arrives on a later receive.\(skipped)")
            onClose()
        } catch {
            self.error = String(describing: error)
        }
    }
}
