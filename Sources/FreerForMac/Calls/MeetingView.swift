import SwiftUI
import Combine
import FCDomain
import FCUI

/// Who the meeting's people are: the app's ``ChatNameBook``, so a meeting
/// names people the way the chat does, and the session it resolves them in.
/// Called like a function for the name to draw.
@MainActor
struct MeetingNames {
    let book: ChatNameBook
    let session: ActiveSession?

    /// The CID where one is known; the FID, shortened, where not.
    func callAsFunction(_ fid: String) -> String {
        book.cid(of: fid) ?? CallCenter.short(fid)
    }

    /// Ask after these FIDs' CIDs; each row redraws as its answer lands.
    func resolve(_ fids: [String]) {
        guard let session else { return }
        book.resolve(fids, session: session)
    }

    /// Every name a member can be searched by besides their FID: the CID
    /// known now and what the address book holds.
    func searchKeys(_ fids: [String]) -> [String: [String]] {
        guard let session else { return [:] }
        return MemberSearch.contactKeys(fids, session: session)
    }
}

/// The meeting panel (VOICE_SPEC §10), over the main window: who is in it and
/// who is speaking, mute and hand, and the host's controls (§7.2). It says the
/// meeting is end-to-end encrypted and where it runs, and warns when audio
/// claimed to be from someone could not be verified (§5.1). All state lives in
/// ``MeetingCenter``; this only shows it.
struct MeetingView: View {
    let meetings: MeetingCenter
    let names: MeetingNames
    @State private var now = Date()
    @State private var confirmEnd = false
    @State private var confirmKick: MacMeetingSession.Participant?
    @State private var picking = false
    @State private var controlError: String?
    private let clock = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        if meetings.visible, !meetings.isActive, let m = meetings.ringing {
            ringingPanel(m)
        } else if meetings.visible {
            let _ = meetings.revision // redraw when the session changes
            let s = meetings.session
            let people = s?.participants ?? []
            let speaking = s?.speaking ?? []
            let paused = s?.pausedSsrcs ?? []
            VStack(alignment: .leading, spacing: 8) {
                Text(meetings.title.isEmpty ? "Meeting" : meetings.title).font(.headline).lineLimit(1)
                Text(status(people.count)).foregroundStyle(.secondary)
                Label("End-to-end encrypted", systemImage: "lock.fill").font(.caption).foregroundStyle(.secondary)
                if let host = meetings.relayHost {
                    Text("Relayed via \(host)").font(.caption).foregroundStyle(.secondary)
                }
                if let fid = s?.unverifiedFids.first {
                    Text("Audio claimed to be from \(names(fid)) could not be verified and is silenced.")
                        .font(.caption).foregroundStyle(.red)
                }
                if !people.isEmpty {
                    Divider()
                    ScrollView {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(people) { p in row(p, host: s?.isHost == true, speaking: speaking, paused: paused) }
                        }
                    }
                    .frame(maxHeight: 220)
                    // Somebody joining is somebody to name.
                    .task(id: people.map(\.fid)) { names.resolve(people.map(\.fid)) }
                }
                if let controlError {
                    Text(controlError).font(.caption).foregroundStyle(.red)
                }
                buttons(s)
            }
            .padding(16)
            .frame(width: 320, alignment: .leading)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            .shadow(radius: 8)
            .padding(16)
            .onReceive(clock) { now = $0 }
            .confirmationDialog("End the meeting for everyone?", isPresented: $confirmEnd, titleVisibility: .visible) {
                Button("End for everyone", role: .destructive) { meetings.endForAll() }
                Button("Cancel", role: .cancel) {}
            }
            .confirmationDialog("Remove \(confirmKick.map { names($0.fid) } ?? "") from the meeting?",
                                isPresented: Binding(get: { confirmKick != nil }, set: { if !$0 { confirmKick = nil } }),
                                titleVisibility: .visible, presenting: confirmKick) { p in
                Button("Remove", role: .destructive) { control("kick", p.fid) }
                Button("Cancel", role: .cancel) { confirmKick = nil }
            }
            .sheet(isPresented: $picking) {
                MemberPickerSheet(title: "Invite to the meeting", members: meetings.invitable(), names: names,
                                  confirm: "Invite") { meetings.invite($0) }
            }
        }
    }

    /// A new meeting ringing: who started what, and Join or Decline.
    private func ringingPanel(_ m: MeetingBoard.Meeting) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Incoming meeting").font(.headline)
            Text(meetings.ringText(m, names: names.callAsFunction)).font(.title3).bold().lineLimit(2)
                .task(id: m.hostFid) { names.resolve([m.hostFid]) }
            if m.invited {
                Text("Only invited members").font(.caption).foregroundStyle(.secondary)
            }
            Label("End-to-end encrypted", systemImage: "lock.fill").font(.caption).foregroundStyle(.secondary)
            if let controlError {
                Text(controlError).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Button("Join") {
                    controlError = nil
                    Task { controlError = await meetings.answerRing() }
                }
                .buttonStyle(.borderedProminent).tint(.green)
                Button("Decline", role: .destructive) { meetings.declineRing() }
            }
        }
        .padding(16)
        .frame(width: 300, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .shadow(radius: 8)
        .padding(16)
    }

    private func status(_ count: Int) -> String {
        switch meetings.phase {
        case .connecting: return "Connecting…"
        case .inMeeting:
            let since = meetings.session?.joinedAtMs ?? -1
            let clock = since > 0 ? CallText.formatDuration(Int64(now.timeIntervalSince1970 * 1000) - since) + " · " : ""
            return clock + (count == 1 ? "1 participant" : "\(count) participants")
        case .ended, .idle: return meetings.endReason ?? ""
        }
    }

    private func row(_ p: MacMeetingSession.Participant, host: Bool, speaking: Set<UInt32>, paused: Set<UInt32>) -> some View {
        let talking = speaking.contains(p.ssrc)
        var state: [String] = []
        if p.hand { state.append("✋") }
        if p.host { state.append("host") }
        if talking { state.append("speaking") }
        if p.mutedByHost == "locked" { state.append("mute locked") } else if p.mutedByHost != nil { state.append("muted by host") }
        if !p.verified { state.append("not verified") } else if paused.contains(p.ssrc) { state.append("audio paused") }
        return HStack {
            Image(systemName: talking ? "waveform" : "person.fill").frame(width: 16).foregroundStyle(talking ? .green : .secondary)
            Text(names(p.fid) + (p.me ? " (you)" : "")).fontWeight(talking ? .bold : .regular).lineLimit(1)
            Spacer()
            Text(state.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary).lineLimit(1)
        }
        .contentShape(Rectangle())
        .contextMenu {
            // The host's controls for one participant (§7.2).
            if host && !p.me {
                if p.mutedByHost == nil {
                    Button("Mute") { control("mute", p.ssrc) }
                    Button("Mute and lock") { control("lockMute", p.ssrc) }
                } else {
                    Button("Unmute") { control("unmute", p.ssrc) }
                }
                Button("Pin as speaker") { control("pin", p.ssrc) }
                Button("Unpin") { control("unpin", p.ssrc) }
                Button("Make host") { control("handoverHost", p.fid) }
                Divider()
                Button("Remove…", role: .destructive) { confirmKick = p }
            }
        }
    }

    @ViewBuilder private func buttons(_ s: MacMeetingSession?) -> some View {
        let live = meetings.isActive
        HStack {
            if live {
                Toggle("Mute", isOn: Binding(get: { s?.isMuted ?? false }, set: { meetings.setMuted($0) }))
                    .toggleStyle(.button)
                    .disabled(s?.mutedByHost == "locked") // a locked mute is the host's to lift (§7.2)
                Toggle("✋", isOn: Binding(get: { s?.handRaised ?? false }, set: { meetings.setHand($0) }))
                    .toggleStyle(.button)
                    .help("Raise hand")
                if s?.isHost == true && meetings.meeting?.invited == true {
                    // Only chosen people hold its key: the host brings in more by inviting them (Decision 20).
                    Button("Invite…") { picking = true }
                }
                Spacer()
                if s?.isHost == true {
                    Button("End") { confirmEnd = true }.help("End the meeting for everyone")
                }
                Button("Leave", role: .destructive) { meetings.leave() }.buttonStyle(.borderedProminent).tint(.red)
            } else {
                Spacer()
                Button("Close") { meetings.close() }
            }
        }
    }

    private func control(_ action: String, _ target: Any) {
        controlError = nil
        meetings.control(action, target: target) { error in
            if let error { controlError = "The relay refused: \(error)" }
        }
    }
}

/// Choose members of a Room or Team: whom to meet with, or whom to invite.
struct MemberPickerSheet: View {
    let title: String
    let members: [String]
    let names: MeetingNames
    let confirm: String
    let onPick: ([String]) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var chosen = Set<String>()
    /// Narrows the rows drawn; whoever is ticked stays chosen while hidden.
    @State private var query = ""
    /// What the address book knows of each member, read once on appear.
    @State private var contactKeys: [String: [String]] = [:]

    private var shown: [String] {
        MemberSearch.filter(members, by: query) { fid in
            [names.book.cid(of: fid)].compactMap { $0 } + (contactKeys[fid] ?? [])
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.headline)
            if members.isEmpty {
                Text("There is no one else to choose.").foregroundStyle(.secondary)
            } else {
                if members.count >= MemberSearch.threshold {
                    HStack {
                        Text("\(chosen.count) of \(members.count) chosen")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        SearchField("Search name, FID…", text: $query, minWidth: 120, maxWidth: 180)
                    }
                }
                List(shown, id: \.self) { fid in
                    Toggle(isOn: Binding(get: { chosen.contains(fid) },
                                         set: { if $0 { chosen.insert(fid) } else { chosen.remove(fid) } })) {
                        Text(names(fid)).lineLimit(1)
                    }
                }
                .frame(minHeight: 200)
                .overlay {
                    if shown.isEmpty {
                        Label("No member matches “\(query)”", systemImage: "magnifyingglass")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button(confirm) {
                    onPick(members.filter(chosen.contains))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(chosen.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 380)
        .onAppear {
            // Their CIDs are on the way before anybody types one.
            names.resolve(members)
            contactKeys = names.searchKeys(members)
        }
    }
}
