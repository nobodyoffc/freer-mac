import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - what the compose sheet is doing

/// The three things the publish form can be opened for. One sheet rather
/// than three, because Android's `CreateServiceActivity` and
/// `UpdateServiceActivity` are 1 637 lines that differ in two places:
/// which button is shown, and whether the carve carries a `sid`.
enum ServiceComposeTarget: Identifiable {
    /// A new registration, from nothing.
    case new
    /// A local draft — still editable, still free.
    case draft(Service)
    /// An on-chain record being amended. The SID does not move; only
    /// what the record says does.
    case update(Service)

    var id: String {
        switch self {
        case .new:            return "new"
        case .draft(let s):   return "draft:\(s.sid)"
        case .update(let s):  return "update:\(s.sid)"
        }
    }

    var service: Service? {
        switch self {
        case .new:                          return nil
        case .draft(let s), .update(let s): return s
        }
    }

    var isUpdate: Bool {
        if case .update = self { return true }
        return false
    }
}

// MARK: - publish / update

/// Register or amend a service — the Mac port of Android's
/// `CreateServiceActivity` and `UpdateServiceActivity`.
///
/// **The byte budget is the whole design, and it is tightest here.** A
/// service can name five id lists, two maps and thirteen prices, all
/// into one uncompressed OP_RETURN; four protocol ids and four code ids
/// are already 550-odd bytes before a word of description. Android
/// checks nothing: you fill the form, press Publish, and the
/// transaction fails at broadcast with a message about script size.
/// Here the remaining bytes are counted live off the *encoded* envelope
/// and the carve button turns off before the user can pay for a
/// transaction that cannot relay.
///
/// **An update resends everything.** The op replaces the record's
/// mutable half, so a field left blank here is a field cleared on chain
/// — and on a service that includes the endpoint under `home`, which is
/// how every client finds it. The form loads the current record rather
/// than opening empty, and the warning above the buttons says so.
///
/// **The type is free text.** Java wraps it in a four-value
/// `ServiceType` enum and calls `valueOf` on whatever the user typed, so
/// anything but those four exact constant names throws — including the
/// `FAPI@No1_NrC7` form the chain actually stores, because `valueOf`
/// wants the underscore spelling. Worse, `UpdateServiceActivity` fills
/// the field from `fetchServiceType().name()`, which is `OTHER` for
/// every unrecognised type, so updating a service whose type Java does
/// not know rewrites that type to `OTHER`. Here it is a string with
/// suggestions, and it round-trips whatever the chain holds.
struct PublishServiceSheet: View {
    let session: ActiveSession
    let target: ServiceComposeTarget

    enum Result {
        case published(Service)
        case updated(String)
        case draft
        case cancelled
    }

    let onDone: (Result) -> Void

    init(
        session: ActiveSession,
        target: ServiceComposeTarget,
        onDone: @escaping (Result) -> Void
    ) {
        self.session = session
        self.target = target
        self.onDone = onDone
        let s = target.service
        _stdName = State(initialValue: s?.stdName ?? "")
        _type = State(initialValue: s?.type ?? "")
        _ver = State(initialValue: s?.ver ?? "")
        _desc = State(initialValue: s?.desc ?? "")
        _components = State(initialValue: s?.components ?? [])
        _homeRows = State(initialValue: HomeRow.rows(from: s?.home))
        _localNameRows = State(initialValue: HomeRow.rows(from: s?.localNames))
        _protocols = State(initialValue: s?.protocols ?? [])
        _codes = State(initialValue: s?.codes ?? [])
        _serviceIds = State(initialValue: s?.services ?? [])
        _waiters = State(initialValue: s?.waiters ?? [])
        _pricing = State(initialValue: s?.pricing ?? ServiceFeip.Pricing())
    }

    @State private var stdName: String
    @State private var type: String
    @State private var ver: String
    @State private var desc: String
    @State private var components: [String]
    @State private var homeRows: [HomeRow]
    @State private var localNameRows: [HomeRow]
    @State private var protocols: [String]
    @State private var codes: [String]
    @State private var serviceIds: [String]
    @State private var waiters: [String]
    @State private var pricing: ServiceFeip.Pricing
    @State private var names: [String: String] = [:]

    @State private var pick: FidPickerRequest?
    @State private var pickingProtocols = false
    @State private var pickingCodes = false
    @State private var showPricing = false
    @State private var busy = false
    @State private var error: String?

    private var trimmedName: String {
        stdName.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var home: [String: String]? {
        let map = HomeRow.map(from: homeRows)
        return map.isEmpty ? nil : map
    }

    private var localNames: [String: String]? {
        let map = HomeRow.map(from: localNameRows)
        return map.isEmpty ? nil : map
    }

    private var remaining: Int {
        ServiceFeip.remainingDescBytes(
            sid: target.isUpdate ? (target.service?.sid ?? "") : nil,
            stdName: trimmedName,
            localNames: localNames,
            desc: desc,
            type: type,
            components: components.isEmpty ? nil : components,
            ver: ver,
            home: home,
            waiters: waiters.isEmpty ? nil : waiters,
            protocols: protocols.isEmpty ? nil : protocols,
            codes: codes.isEmpty ? nil : codes,
            services: serviceIds.isEmpty ? nil : serviceIds,
            pricing: pricing
        )
    }

    private var canCarve: Bool {
        !trimmedName.isEmpty && remaining >= 0 && session.canSign && !busy
    }

    private var heading: String {
        switch target {
        case .new:    return "Publish a service"
        case .draft:  return "Edit draft"
        case .update: return "Update this service"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(heading).font(.title3.bold())

            Text("Everything below goes onto the chain in the clear, signed by \(session.liveFid.elidingMiddle(head: 8, tail: 8)). Registering does not start anything — the record points at a server you are already running, and nothing on chain checks that it answers.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if target.isUpdate {
                Label("An update replaces what the record says. A field left blank here is a field cleared on chain — including the endpoint under Home, which is how clients find this service.", systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 10) {
                        field("Standard name") {
                            TextField("e.g. DOCK@No1_NrC7", text: $stdName)
                                .textFieldStyle(.roundedBorder)
                        }
                        field("Version") {
                            TextField("e.g. 3", text: $ver)
                                .textFieldStyle(.roundedBorder)
                        }
                        .frame(maxWidth: 120)
                    }

                    field("Type") {
                        HStack(spacing: 6) {
                            TextField("e.g. FAPI@No1_NrC7", text: $type)
                                .textFieldStyle(.roundedBorder)
                            Menu("Common") {
                                ForEach(Self.knownTypes, id: \.self) { t in
                                    Button(t) { type = t }
                                }
                            }
                            .fixedSize()
                        }
                    }
                    .help("Free text. The component list below is what a client filters on — the type only says this is an FC service at all.")

                    field("Description") {
                        VStack(alignment: .leading, spacing: 4) {
                            TextEditor(text: $desc)
                                .font(.body)
                                .frame(minHeight: 70, maxHeight: 140)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(Color(NSColor.separatorColor))
                                )
                            HStack {
                                Text(remaining >= 0
                                     ? "\(remaining) bytes left"
                                     : "\(-remaining) bytes over the limit")
                                    .font(.caption.monospacedDigit())
                                    .foregroundStyle(remaining < 0 ? .red : (remaining < 256 ? .orange : .secondary))
                                Spacer()
                                Text("The whole registration rides in one transaction — \(ServiceFeip.maxOpReturnSize) bytes for everything on this form, and each protocol or code id is 64 of them.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }

                    field("Components it offers") {
                        ComponentListEditor(components: $components)
                    }

                    field("Where to reach it") {
                        VStack(alignment: .leading, spacing: 4) {
                            HomeMapEditor(
                                rows: $homeRows,
                                emptyText: "Nowhere — a service with no endpoint is a claim that something exists, not something a client can call.",
                                keyPlaceholder: "API",
                                valuePlaceholder: "https://…",
                                addLabel: "Add an endpoint"
                            )
                            if home?.keys.contains(where: { $0.lowercased() == "api" }) != true {
                                // The resolver reads `API` (either case)
                                // and nothing else. A home map without it
                                // resolves to no URL at all, which is a
                                // silent failure at the far end.
                                Text("No API key yet — clients read the endpoint from `API`, so a home map without one leaves this service unreachable.")
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                            }
                        }
                    }

                    field("Local names") {
                        HomeMapEditor(
                            rows: $localNameRows,
                            emptyText: "None — readers see the standard name.",
                            keyPlaceholder: "zh",
                            valuePlaceholder: "what to call it in that language",
                            addLabel: "Add a local name"
                        )
                    }

                    field("Code it runs") {
                        CodeIdListEditor(
                            session: session,
                            ids: $codes,
                            onPick: { pickingCodes = true }
                        )
                    }

                    field("Protocols it speaks") {
                        ProtocolIdListEditor(
                            session: session,
                            ids: $protocols,
                            onPick: { pickingProtocols = true }
                        )
                    }

                    field("Other services it depends on") {
                        SidListEditor(session: session, ids: $serviceIds)
                    }

                    field("Waiters") {
                        VStack(alignment: .leading, spacing: 6) {
                            if waiters.isEmpty {
                                Text("Nobody — the owner is the only contact for this service.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            } else {
                                ForEach(waiters, id: \.self) { fid in
                                    HStack(spacing: 6) {
                                        FidAvatarView(fid: fid, size: 20)
                                        CopyableText(
                                            display: names[fid] ?? fid.elidingMiddle(head: 8, tail: 8),
                                            copy: fid,
                                            font: .system(.caption, design: .monospaced)
                                        )
                                        Button {
                                            waiters.removeAll { $0 == fid }
                                        } label: {
                                            Image(systemName: "xmark.circle.fill")
                                                .foregroundStyle(.secondary)
                                        }
                                        .buttonStyle(.plain)
                                        Spacer()
                                    }
                                }
                            }
                            Button {
                                pick = .many(
                                    title: "Add waiters",
                                    subtitle: "They are listed as serving this service. A waiter is not a co-owner — only you can carve against the record.",
                                    excluded: Set(waiters)
                                )
                            } label: {
                                Label("Add waiters", systemImage: "person.badge.plus")
                            }
                            .controlSize(.small)
                        }
                    }

                    // Thirteen fields behind a disclosure, because most
                    // services are free and the ones that are not have an
                    // operator who came here on purpose.
                    DisclosureGroup(isExpanded: $showPricing) {
                        PricingEditor(pricing: $pricing)
                            .padding(.top, 6)
                    } label: {
                        HStack(spacing: 6) {
                            Text("Pricing and limits").font(.caption).foregroundStyle(.secondary)
                            if !pricing.isEmpty {
                                Text("\(pricing.wirePairs.count) set")
                                    .font(.caption2)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(Capsule().fill(Color.green.opacity(0.15)))
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            if !session.canSign {
                Text("This identity is watch-only, so it cannot sign a carve. You can still save a draft and publish it later from an identity that holds the key.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Cancel") { onDone(.cancelled) }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                if !target.isUpdate {
                    // An on-chain record has no draft to fall back to:
                    // saving a "draft" of something already published
                    // would make a second row claiming to be the same
                    // record.
                    Button(target.service == nil ? "Save draft" : "Save changes") { saveDraft() }
                        .disabled(busy || trimmedName.isEmpty)
                }
                Button(target.isUpdate ? "Update on chain" : "Publish on chain") {
                    Task { await carve() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canCarve)
            }
        }
        .padding(20)
        .frame(width: 640)
        .frame(minHeight: 500, maxHeight: 780)
        .onAppear { showPricing = !pricing.isEmpty }
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                for p in picked where !waiters.contains(p.fid) {
                    waiters.append(p.fid)
                    if let cid = p.cid, !cid.isEmpty { names[p.fid] = cid }
                }
                pick = nil
            } onCancel: { pick = nil }
        }
        .sheet(isPresented: $pickingProtocols) {
            ProtocolPickerSheet(session: session, excluded: Set(protocols)) { picked in
                pickingProtocols = false
                for id in picked where !protocols.contains(id) {
                    protocols.append(id)
                }
            } onCancel: { pickingProtocols = false }
        }
        .sheet(isPresented: $pickingCodes) {
            CodePickerSheet(session: session, excluded: Set(codes)) { picked in
                pickingCodes = false
                for id in picked where !codes.contains(id) {
                    codes.append(id)
                }
            } onCancel: { pickingCodes = false }
        }
    }

    /// The four `ServiceType` constants Java knows, spelled the way the
    /// chain stores them. Suggestions, not a whitelist — see the type's
    /// note.
    private static let knownTypes = [
        "FAPI@No1_NrC7", "NASA@RPC", "NODE", "OTHER"
    ]

    /// Persist the draft, and return it.
    ///
    /// **Editing moves the row's key.** A draft's id is a digest of the
    /// payload it will carve, so changing a field changes the id — that
    /// is what makes an unchanged draft's id stable across a reload. The
    /// old key is therefore deleted rather than updated in place;
    /// `addedAt` is carried over so "when did I start this" survives the
    /// move.
    @discardableResult
    private func persistDraft() throws -> Service {
        var draft = Service.createLocal(
            stdName: trimmedName,
            localNames: localNames,
            desc: clean(desc),
            type: clean(type),
            components: components.isEmpty ? nil : components,
            ver: clean(ver),
            home: home,
            waiters: waiters.isEmpty ? nil : waiters,
            protocols: protocols.isEmpty ? nil : protocols,
            codes: codes.isEmpty ? nil : codes,
            services: serviceIds.isEmpty ? nil : serviceIds,
            pricing: pricing,
            owner: session.liveFid
        )
        if case .draft(let editing) = target {
            draft.addedAt = editing.addedAt
            if editing.sid != draft.sid {
                try session.services.removeDraft(id: editing.sid)
            }
        }
        try session.services.upsertDraft(draft)
        return draft
    }

    private func saveDraft() {
        error = nil
        do {
            try persistDraft()
            onDone(.draft)
        } catch {
            self.error = "Couldn't save the draft: \(error)"
        }
    }

    private func carve() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            if case .update(let service) = target {
                let txid = try await session.carveServiceUpdateOnChain(
                    sid: service.sid,
                    stdName: trimmedName,
                    localNames: localNames,
                    desc: clean(desc),
                    type: clean(type),
                    components: components.isEmpty ? nil : components,
                    ver: clean(ver),
                    home: home,
                    waiters: waiters.isEmpty ? nil : waiters,
                    protocols: protocols.isEmpty ? nil : protocols,
                    codes: codes.isEmpty ? nil : codes,
                    services: serviceIds.isEmpty ? nil : serviceIds,
                    pricing: pricing
                )
                onDone(.updated(txid))
                return
            }
            // Write the edits down before spending anything. The carve
            // rekeys the stored draft to the txid, so the stored row has
            // to be the one being carved — and if the broadcast fails,
            // the user's edits are on disk rather than lost with the
            // sheet.
            var draftId: String?
            if case .draft = target { draftId = try persistDraft().sid }
            let service = try await session.carveServicePublishOnChain(
                stdName: trimmedName,
                localNames: localNames,
                desc: clean(desc),
                type: clean(type),
                components: components.isEmpty ? nil : components,
                ver: clean(ver),
                home: home,
                waiters: waiters.isEmpty ? nil : waiters,
                protocols: protocols.isEmpty ? nil : protocols,
                codes: codes.isEmpty ? nil : codes,
                services: serviceIds.isEmpty ? nil : serviceIds,
                pricing: pricing,
                draftId: draftId
            )
            onDone(.published(service))
        } catch {
            self.error = target.isUpdate
                ? "Couldn't update: \(error)"
                : "Couldn't publish: \(error)"
        }
    }

    private func clean(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
    }

    @ViewBuilder
    private func field(_ label: String, @ViewBuilder value: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            value()
        }
    }
}

// MARK: - components

/// The component list, edited as toggles over the well-known names plus
/// a free-text add.
///
/// **A mistyped component is a service nobody finds.** The component
/// list is what every picker on the network filters on — Files searches
/// `DISK@No1_NrC7`, the message path searches `DOCK@No1_NrC7` — and it
/// is matched by exact value, not by prefix or by fuzzy score. Android
/// asks for it as a comma-separated field and accepts whatever is typed.
/// The four the network actually looks for are one click each here, and
/// anything else can still be typed.
struct ComponentListEditor: View {
    @Binding var components: [String]

    @State private var typed = ""

    private static let wellKnown = [
        ServiceName.fapi, ServiceName.dock, ServiceName.disk, ServiceName.road
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                ForEach(Self.wellKnown, id: \.self) { name in
                    let on = components.contains(name)
                    Button {
                        if on {
                            components.removeAll { $0 == name }
                        } else {
                            components.append(name)
                        }
                    } label: {
                        Text(name.split(separator: "@").first.map(String.init) ?? name)
                            .font(.caption2.bold())
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(Capsule().fill(
                                on ? Color.teal.opacity(0.25) : Color.secondary.opacity(0.12)
                            ))
                            .foregroundStyle(on ? Color.teal : Color.secondary)
                    }
                    .buttonStyle(.plain)
                    .help(name)
                }
                Spacer()
            }

            let extras = components.filter { !Self.wellKnown.contains($0) }
            if !extras.isEmpty {
                ForEach(extras, id: \.self) { name in
                    HStack(spacing: 6) {
                        Text(name).font(.caption)
                        Button {
                            components.removeAll { $0 == name }
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        Spacer()
                    }
                }
            }

            HStack(spacing: 6) {
                TextField("another component, e.g. NASA@No1_NrC7", text: $typed)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.caption, design: .monospaced))
                    .onSubmit { addTyped() }
                Button("Add") { addTyped() }
                    .controlSize(.small)
                    .disabled(typed.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            if components.isEmpty {
                Text("Nothing — a service that offers no component is invisible to every picker on the network, which all filter on this list.")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }
        }
    }

    private func addTyped() {
        let name = typed.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !components.contains(name) else { return }
        components.append(name)
        typed = ""
    }
}

// MARK: - the code list

/// The code ids a service claims to be running, edited as a list.
///
/// The same shape as ``ProtocolIdListEditor`` and for the same reason:
/// each entry is a 64-hex record id that nothing validates, so it is
/// picked from the registry by default and typed only when somebody sent
/// you one.
struct CodeIdListEditor: View {
    let session: ActiveSession
    @Binding var ids: [String]
    let onPick: () -> Void

    @State private var typed = ""
    @State private var names: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if ids.isEmpty {
                Text("None — the registration does not say which implementation is running here.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(ids, id: \.self) { id in
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.left.forwardslash.chevron.right")
                            .foregroundStyle(.secondary)
                        if let name = names[id], !name.isEmpty {
                            Text(name).font(.caption)
                        }
                        CopyableText.elidingMiddle(
                            id, head: 8, tail: 8,
                            font: .system(.caption2, design: .monospaced)
                        )
                        .foregroundStyle(.secondary)
                        Button {
                            ids.removeAll { $0 == id }
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        Spacer()
                    }
                }
            }

            HStack(spacing: 6) {
                Button {
                    onPick()
                } label: {
                    Label("Pick from the registry", systemImage: "list.bullet.rectangle")
                }
                .controlSize(.small)

                TextField("or paste a code ID", text: $typed)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.caption, design: .monospaced))
                    .onSubmit { addTyped() }

                Button("Add") { addTyped() }
                    .controlSize(.small)
                    .disabled(typed.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .task(id: ids) { await resolveNames() }
    }

    private func addTyped() {
        let id = typed.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !id.isEmpty, !ids.contains(id) else { return }
        ids.append(id)
        typed = ""
    }

    private func resolveNames() async {
        let wanted = ids.filter { names[$0] == nil }
        guard !wanted.isEmpty else { return }
        if let found = try? await session.codeService.fetchCodesByIds(wanted) {
            for (id, code) in found { names[id] = code.displayName }
        }
    }
}

/// Pick code records out of the live registry — the Mac stand-in for
/// Android's "open `CodeActivity` in pick mode" hop.
struct CodePickerSheet: View {
    let session: ActiveSession
    let excluded: Set<String>
    let onPick: ([String]) -> Void
    let onCancel: () -> Void

    @State private var rows: [Code] = []
    @State private var selection: Set<String> = []
    @State private var searchText = ""
    @State private var loading = false
    @State private var error: String?
    @State private var didLoad = false

    private var filtered: [Code] {
        let available = rows.filter { !excluded.contains($0.id) }
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return available }
        return available.filter { $0.matches(query: q) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pick the code this service runs").font(.title3.bold())
            Text("The live code registry. Each one you tick adds its 64-character record id to the carve, so the byte budget on the form behind this will move.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                SearchField("Search the registry…", text: $searchText, minWidth: 200)
                Spacer()
                if loading { ProgressView().controlSize(.small) }
                Button {
                    Task { await load() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
                .disabled(loading)
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(filtered) { code in
                        HStack(spacing: 8) {
                            Toggle("", isOn: Binding(
                                get: { selection.contains(code.id) },
                                set: { on in
                                    if on { selection.insert(code.id) } else { selection.remove(code.id) }
                                }
                            ))
                            .labelsHidden()

                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(code.displayName).font(.body)
                                        .lineLimit(1).truncationMode(.middle)
                                    if let ver = code.ver, !ver.isEmpty {
                                        Text("v\(ver)").font(.caption2).foregroundStyle(.tertiary)
                                    }
                                    ForEach((code.langs ?? []).prefix(2), id: \.self) { lang in
                                        Text(lang).font(.caption2).foregroundStyle(.tertiary)
                                    }
                                }
                                CopyableText.elidingMiddle(
                                    code.id, head: 10, tail: 10,
                                    font: .system(.caption2, design: .monospaced)
                                )
                                .foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                        .padding(.vertical, 6)
                        .padding(.horizontal, 10)
                        Divider()
                    }
                    if filtered.isEmpty && !loading {
                        Text(rows.isEmpty
                             ? "Nothing live in the code registry yet."
                             : "No code record matches “\(searchText)”.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .padding(16)
                    }
                }
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 10))
            }

            HStack {
                Button("Cancel") { onCancel() }
                Spacer()
                Text("\(selection.count) selected").font(.caption).foregroundStyle(.secondary)
                Button("Add") { onPick(Array(selection)) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(selection.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 560)
        .frame(minHeight: 380, maxHeight: 620)
        .onAppear {
            guard !didLoad else { return }
            didLoad = true
            Task { await load() }
        }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        error = nil
        do {
            let page = try await session.codeService.fetchCodes(
                active: true, closed: false, size: 100
            )
            rows = page.codes
        } catch {
            self.error = "Couldn't load the code registry: \(error)"
        }
    }
}

// MARK: - the dependency list

/// SIDs of other services this one leans on. Typed or pasted rather than
/// picked: unlike codes and protocols, the thing being named here is
/// usually one the operator already runs and has the SID for, and a
/// registry picker over the whole service index would be a second copy
/// of the pane this sheet was opened from.
struct SidListEditor: View {
    let session: ActiveSession
    @Binding var ids: [String]

    @State private var typed = ""
    @State private var names: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if ids.isEmpty {
                Text("None — this service does not declare a dependency on another.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(ids, id: \.self) { id in
                    HStack(spacing: 6) {
                        Image(systemName: "server.rack").foregroundStyle(.secondary)
                        if let name = names[id], !name.isEmpty {
                            Text(name).font(.caption)
                        }
                        CopyableText.elidingMiddle(
                            id, head: 8, tail: 8,
                            font: .system(.caption2, design: .monospaced)
                        )
                        .foregroundStyle(.secondary)
                        Button {
                            ids.removeAll { $0 == id }
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        Spacer()
                    }
                }
            }

            HStack(spacing: 6) {
                TextField("paste a SID", text: $typed)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.caption, design: .monospaced))
                    .onSubmit { addTyped() }
                Button("Add") { addTyped() }
                    .controlSize(.small)
                    .disabled(typed.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .task(id: ids) { await resolveNames() }
    }

    private func addTyped() {
        let id = typed.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !id.isEmpty, !ids.contains(id) else { return }
        ids.append(id)
        typed = ""
    }

    private func resolveNames() async {
        let wanted = ids.filter { names[$0] == nil }
        guard !wanted.isEmpty else { return }
        if let found = try? await session.serviceRegistry.fetchServicesByIds(wanted) {
            for (id, service) in found { names[id] = service.displayName }
        }
    }
}

// MARK: - pricing

/// The thirteen pricing and configuration fields.
///
/// **Text, not numbers.** The chain carries every one of them as a
/// decimal string, and a `Double` round-trip would re-serialise the
/// operator's `"0.10"` as `0.1` — a different record from the one they
/// typed. What is validated is that a figure *looks* numeric, which is
/// shown as a warning rather than enforced: the chain will take whatever
/// it is given, and refusing to carve a price a server might well
/// understand is not this form's call.
struct PricingEditor: View {
    @Binding var pricing: ServiceFeip.Pricing

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                money("Currency", $pricing.currency, placeholder: "FCH", numeric: false)
                money("Per request", $pricing.pricePerRequest)
                money("Per KB", $pricing.pricePerKB)
            }
            HStack(spacing: 10) {
                money("Per KB in", $pricing.pricePerKBIn)
                money("Per KB out", $pricing.pricePerKBOut)
                money("Per KB per day", $pricing.pricePerKBDay)
            }
            HStack(spacing: 10) {
                money("Minimum payment", $pricing.minPayment)
                money("Minimum credit", $pricing.minCredit)
                money("Session days", $pricing.sessionDays)
            }
            HStack(spacing: 10) {
                money("Max item bytes", $pricing.maxDataSize)
                money("Data expires (days)", $pricing.dataExpiresInDays)
                money("Consume via share", $pricing.consumeViaShare, numeric: false)
            }
            HStack(spacing: 10) {
                money("Order via share", $pricing.orderViaShare, numeric: false)
                Spacer()
            }
            Text("Every field is optional and every one goes on chain as text. Max item bytes is the ceiling a DOCK enforces per item — leave it unset and the server applies its own default.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private func money(
        _ label: String,
        _ value: Binding<String?>,
        placeholder: String = "",
        numeric: Bool = true
    ) -> some View {
        let text = Binding(
            get: { value.wrappedValue ?? "" },
            set: { value.wrappedValue = $0.isEmpty ? nil : $0 }
        )
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            TextField(placeholder, text: text)
                .textFieldStyle(.roundedBorder)
                .font(.system(.caption, design: .monospaced))
            if numeric, let raw = value.wrappedValue,
               !raw.trimmingCharacters(in: .whitespaces).isEmpty,
               Double(raw.trimmingCharacters(in: .whitespaces)) == nil {
                Text("not a number")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }
        }
    }
}

// MARK: - detail

/// Every field of one service, untruncated and copyable — the Mac
/// analogue of Android's service detail card and its `ServiceCardContainer`.
struct ServiceDetailSheet: View {
    let session: ActiveSession
    let service: Service
    let name: (String) -> String?
    let onClose: () -> Void

    /// record id → name, resolved so the code and protocol lists read as
    /// words rather than sixty-four hex characters each.
    @State private var linkedNames: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Text(service.displayName)
                    .font(.title3.bold())
                    .lineLimit(2)
                    .truncationMode(.middle)
                Spacer()
                stateChip
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let desc = service.desc, !desc.isEmpty {
                        field("Description") {
                            CopyableText(desc, font: .body)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    HStack(alignment: .top, spacing: 24) {
                        if let type = service.type, !type.isEmpty {
                            field("Type") { Text(type).font(.caption) }
                        }
                        if let ver = service.ver, !ver.isEmpty {
                            field("Version") { Text(ver).font(.caption) }
                        }
                    }

                    if let components = service.components, !components.isEmpty {
                        field("Components it offers") {
                            VStack(alignment: .leading, spacing: 3) {
                                ForEach(components, id: \.self) { c in
                                    Text(c).font(.system(.caption, design: .monospaced))
                                }
                                Text("What every picker on the network filters on — matched by exact value.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }

                    if let home = service.home, !home.isEmpty {
                        field("Where to reach it") {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(home.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                                    HStack(spacing: 6) {
                                        Text(key).font(.caption).foregroundStyle(.secondary)
                                        CopyableText(value, font: .system(.caption, design: .monospaced))
                                    }
                                }
                                if service.apiUrl == nil {
                                    Text("No API key — clients read the endpoint from `API`, so nothing here resolves to a URL.")
                                        .font(.caption2)
                                        .foregroundStyle(.orange)
                                }
                            }
                        }
                    }

                    if let localNames = service.localNames, !localNames.isEmpty {
                        field("Local names") {
                            VStack(alignment: .leading, spacing: 3) {
                                ForEach(localNames.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                                    HStack(spacing: 6) {
                                        Text(key).font(.caption2).foregroundStyle(.tertiary)
                                        Text(value).font(.caption)
                                    }
                                }
                            }
                        }
                    }

                    field("Owner") { fidValue(service.owner) }
                    if let dealer = service.dealer, !dealer.isEmpty, dealer != service.owner {
                        field("Dealer") { fidValue(dealer) }
                    }

                    linkedList("Code it runs", service.codes, symbol: "chevron.left.forwardslash.chevron.right")
                    linkedList("Protocols it speaks", service.protocols, symbol: "doc.text")
                    linkedList("Other services it depends on", service.services, symbol: "server.rack")

                    if let waiters = service.waiters, !waiters.isEmpty {
                        field("Waiters") {
                            VStack(alignment: .leading, spacing: 5) {
                                ForEach(waiters, id: \.self) { fid in
                                    fidValue(fid)
                                }
                            }
                        }
                    }

                    let prices = service.pricing.wirePairs
                    if !prices.isEmpty {
                        field("Pricing and limits") {
                            VStack(alignment: .leading, spacing: 3) {
                                ForEach(prices, id: \.0) { key, value in
                                    HStack(spacing: 6) {
                                        Text(key).font(.caption2).foregroundStyle(.tertiary)
                                        Text(value).font(.system(.caption, design: .monospaced))
                                    }
                                }
                                Text("What the operator says they charge. Nothing on chain enforces it — the server does.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }

                    if service.isClosed, let statement = service.closeStatement, !statement.isEmpty {
                        field("Closing statement") {
                            CopyableText(statement, font: .caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    HStack(spacing: 24) {
                        field("Rating") {
                            Text(service.tRate.map { String(format: "%.2f", $0) } ?? "—")
                                .font(.caption)
                        }
                        field("CDD burned for it") {
                            Text(service.tCdd.map { "\($0)" } ?? "—")
                                .font(.caption.monospacedDigit())
                        }
                    }

                    field("SID") {
                        CopyableText.elidingMiddle(
                            service.sid, head: 12, tail: 12,
                            font: .system(.caption, design: .monospaced)
                        )
                    }

                    if let txid = service.lastTxId, !txid.isEmpty, txid != service.sid {
                        field("Last transaction") {
                            CopyableText.elidingMiddle(
                                txid, head: 12, tail: 12,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                    }

                    HStack(spacing: 24) {
                        if let t = service.birthTime {
                            field("Published") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let t = service.lastTime {
                            field("Last change") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let h = service.lastHeight, h != ServicesStore.unconfirmedHeight {
                            field("Height") {
                                Text("\(h)").font(.caption.monospacedDigit())
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack {
                Spacer()
                Button("Done", action: onClose)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560)
        .frame(minHeight: 380, maxHeight: 700)
        .task { await resolveLinked() }
    }

    @ViewBuilder
    private func linkedList(_ label: String, _ ids: [String]?, symbol: String) -> some View {
        if let ids, !ids.isEmpty {
            field(label) {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(ids, id: \.self) { id in
                        HStack(spacing: 6) {
                            Image(systemName: symbol).foregroundStyle(.secondary)
                            if let n = linkedNames[id], !n.isEmpty {
                                Text(n).font(.caption)
                            }
                            CopyableText.elidingMiddle(
                                id, head: 10, tail: 10,
                                font: .system(.caption2, design: .monospaced)
                            )
                            .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    /// Three registries, one for each id list. Best-effort: an id no
    /// registry has heard of keeps its hex, which is itself worth seeing
    /// — it usually means the id is wrong.
    private func resolveLinked() async {
        if let codes = service.codes, !codes.isEmpty,
           let found = try? await session.codeService.fetchCodesByIds(codes) {
            for (id, code) in found { linkedNames[id] = code.displayName }
        }
        if let protocols = service.protocols, !protocols.isEmpty,
           let found = try? await session.protocolService.fetchProtocolsByIds(protocols) {
            for (id, spec) in found { linkedNames[id] = spec.displayName }
        }
        if let services = service.services, !services.isEmpty,
           let found = try? await session.serviceRegistry.fetchServicesByIds(services) {
            for (id, s) in found { linkedNames[id] = s.displayName }
        }
    }

    @ViewBuilder
    private var stateChip: some View {
        switch service.state {
        case .closed:    chip("Closed", color: .red)
        case .stopped:   chip("Stopped", color: .orange)
        case .draft:     chip("Draft", color: .gray)
        case .broadcast: chip("Broadcast, unconfirmed", color: .orange)
        case .live:      chip("In force", color: .blue)
        }
    }

    @ViewBuilder
    private func fidValue(_ fid: String?) -> some View {
        if let fid, !fid.isEmpty {
            HStack(spacing: 6) {
                FidAvatarView(fid: fid, size: 22)
                CopyableText(
                    display: name(fid) ?? fid.elidingMiddle(head: 10, tail: 10),
                    copy: fid,
                    font: .system(.caption, design: .monospaced)
                )
            }
        } else {
            Text("—").font(.caption).foregroundStyle(.tertiary)
        }
    }

    @ViewBuilder
    private func field(_ label: String, @ViewBuilder value: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            value()
        }
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }
}

// MARK: - close

/// Retire services permanently, with a reason — the Mac port of
/// Android's `CloseServiceActivity`.
///
/// A sheet rather than an alert because closing takes a statement, and
/// because it is the one op in this pane that nothing undoes — the user
/// should see which records they picked, and be told plainly that
/// Recover does not apply, before the carve goes out.
struct CloseServiceSheet: View {
    let session: ActiveSession
    let services: [Service]
    let onDone: (String?) -> Void

    @State private var statement = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(services.count == 1 ? "Close this service" : "Close \(services.count) services")
                .font(.title3.bold())

            VStack(alignment: .leading, spacing: 4) {
                ForEach(services) { service in
                    HStack(spacing: 6) {
                        Image(systemName: "server.rack")
                            .foregroundStyle(.secondary)
                        Text(service.displayName)
                            .font(.body)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if let ver = service.ver, !ver.isEmpty {
                            Text("v\(ver)").font(.caption).foregroundStyle(.tertiary)
                        }
                        Spacer()
                    }
                }
            }

            Label("Closing is permanent. The record stays on the chain and stays readable, flagged closed, but there is no op that reopens it — Recover only undoes a Stop.", systemImage: "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)

            Text("Anyone holding this SID keeps resolving it until they refresh, and the server carries on answering until you turn it off. Closing retires the registration, not the daemon.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 4) {
                Text("Closing statement").font(.caption).foregroundStyle(.secondary)
                TextField("why, or which service replaces it — optional", text: $statement)
                    .textFieldStyle(.roundedBorder)
                Text("The last thing you will ever be able to say about this service on chain, and the only place to point people at its replacement.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            Text("One carve for all \(services.count) — one miner fee, and it pays nobody.")
                .font(.caption)
                .foregroundStyle(.tertiary)

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            HStack {
                Button("Cancel") { onDone(nil) }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Close permanently", role: .destructive) { Task { await close() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || services.isEmpty || !session.canSign)
            }
        }
        .padding(20)
        .frame(width: 500)
    }

    private func close() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            let txid = try await session.carveServiceCloseOnChain(
                sids: services.map(\.sid),
                closeStatement: statement.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            onDone(txid)
        } catch {
            self.error = "Couldn't close: \(error)"
        }
    }
}
