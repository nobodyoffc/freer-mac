import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Change a room's name, description, DOCK and CALL service — the Mac
/// port of Android's `ChatActivity.showUpdateRoomDialog`.
///
/// **`home` is edited, never rebuilt.** The record travels whole, so a
/// map built from these two boxes would delete every entry they do not
/// draw. Only the DOCK and CALL entries change; an empty box removes its
/// own entry and nothing else.
///
/// **Owner only, and this sheet is not what enforces that.**
/// ``RoomService/update(_:name:desc:home:as:pubkeys:homes:now:)`` checks;
/// the menu simply does not offer the item to anyone else. A rule
/// enforced by whether a button was drawn is not enforced.
///
/// **Saving sends.** A room's record exists only on the devices that
/// hold it, so a change the owner keeps to themselves is a change
/// nobody else has — and a DOCK change that did not travel would leave
/// every member collecting from a server this room no longer uses,
/// which reads on their screen as the conversation simply stopping.
struct RoomSettingsSheet: View {

    let session: ActiveSession
    let roomId: String
    let onClose: () -> Void
    /// Handed the summary to show, so it survives this sheet closing.
    let onSaved: (String) -> Void

    @State private var name = ""
    @State private var desc = ""
    @State private var dock = ""
    @State private var call = ""
    /// The stored home, which the two boxes are laid over.
    @State private var storedHome: [String: String]?
    @State private var pickingDock = false
    @State private var pickingCall = false
    @State private var loaded = false
    @State private var working = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "door.left.hand.closed").foregroundStyle(ChatModeStyle.of(.room).tint)
                Text("Room settings").font(.title3.bold())
                Spacer()
            }

            VStack(alignment: .leading, spacing: 4) {
                LabeledField("Room name") {
                    TextField("", text: $name, prompt: Text("required"))
                        .fieldInputStyle()
                }
                LabeledField("Description") {
                    TextField("", text: $desc, prompt: Text("optional"))
                        .fieldInputStyle()
                }
                LabeledField(
                    "DOCK",
                    hint: "Where this room's messages rest until each member collects them. Changing it moves the whole room — every member is sent the new address, and anyone who does not get the message keeps looking at the old one."
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $dock, prompt: Text("service id, or host:port"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                        Button {
                            pickingDock = true
                        } label: {
                            Label("Find…", systemImage: "server.rack")
                        }
                        .help("Search the chain for a server that offers DOCK.")
                    }
                }
                LabeledField(
                    "CALL",
                    hint: "The relay this room's meetings run on, paid by whoever starts one. Empty: each host's own CALL service."
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $call, prompt: Text("service id, or fudp://host:port"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                        Button {
                            pickingCall = true
                        } label: {
                            Label("Find…", systemImage: "phone")
                        }
                        .help("Search the chain for a server that offers CALL.")
                    }
                }
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onClose() }
                Button(working ? "Saving…" : "Save and tell everyone") { save() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(working || name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 460)
        .onAppear(perform: load)
        .sheet(isPresented: $pickingDock) {
            ServicePickerSheet(
                session: session,
                component: ServiceName.dock,
                title: "Choose this room's DOCK",
                initialQuery: dock
            ) { service in
                dock = service.sid
                pickingDock = false
            } onCancel: {
                pickingDock = false
            }
        }
        .sheet(isPresented: $pickingCall) {
            ServicePickerSheet(
                session: session,
                component: ServiceName.call,
                title: "Choose this room's CALL service",
                initialQuery: call
            ) { service in
                call = service.sid
                pickingCall = false
            } onCancel: {
                pickingCall = false
            }
        }
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        do {
            guard let room = try session.rooms.get(id: roomId) else {
                error = "This room is not on this Mac any more."
                return
            }
            name = room.name ?? ""
            desc = room.desc ?? ""
            storedHome = room.home
            dock = room.home?[ServiceName.dock] ?? ""
            call = HomeServiceResolver.displayValue(room.home?[ServiceName.call])
        } catch {
            self.error = String(describing: error)
        }
    }

    private func save() {
        working = true
        error = nil
        let trimmedDock = dock.trimmingCharacters(in: .whitespaces)
        // DOCK stays as typed, as before; CALL is written in the prefixed
        // form. An empty box removes its entry, and only its own.
        var home = (storedHome ?? [:]).filter { k, _ in !GroupHome.isKey(k, ofKind: "DOCK") }
        if !trimmedDock.isEmpty { home[ServiceName.dock] = trimmedDock }
        home = GroupHome.editing(home, key: ServiceName.call, kind: "CALL", value: call)
        do {
            let (_, outbound, unreachable) = try session.roomService.update(
                roomId,
                name: name.trimmingCharacters(in: .whitespaces),
                desc: desc.trimmingCharacters(in: .whitespaces),
                // An empty map means "no home", which the service reads
                // as clearing it.
                home: home,
                as: session.liveFid,
                pubkeys: { fid in try session.knownPubkey(of: fid) },
                homes: { fid in try session.knownHome(of: fid) }
            )
            // The name is on the room record; the chat list draws it from
            // its own row, and nothing else would ever bring the two back
            // together.
            try session.roomConversations.sync(roomId)
            for message in outbound {
                guard let to = message.targetId else { continue }
                try session.outbox.enqueue(message, in: Conversation.id(type: .p2p, targetId: to))
            }
            Task { _ = try? await session.courier.drainOutbox(as: session.liveFid) }

            var summary = "Saved. \(outbound.count) update(s) queued."
            if !unreachable.isEmpty {
                summary += " \(unreachable.count) member(s) publish no DOCK, so there is nowhere to leave one for them."
            }
            working = false
            onSaved(summary)
        } catch {
            working = false
            self.error = String(describing: error)
        }
    }
}
