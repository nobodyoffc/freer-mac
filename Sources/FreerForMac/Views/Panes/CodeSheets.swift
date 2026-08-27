import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - what the compose sheet is doing

/// The three things the publish form can be opened for. One sheet rather
/// than three, because Android's `CreateCodeActivity` and
/// `UpdateCodeActivity` are 761 lines that differ in two places: which
/// button is shown, and whether the carve carries a `codeId`.
enum CodeComposeTarget: Identifiable {
    /// A new registration, from nothing.
    case new
    /// A local draft — still editable, still free.
    case draft(Code)
    /// An on-chain record being amended. The id does not move; only what
    /// the record says does.
    case update(Code)

    var id: String {
        switch self {
        case .new:            return "new"
        case .draft(let c):   return "draft:\(c.id)"
        case .update(let c):  return "update:\(c.id)"
        }
    }

    var code: Code? {
        switch self {
        case .new:                          return nil
        case .draft(let c), .update(let c): return c
        }
    }

    var isUpdate: Bool {
        if case .update = self { return true }
        return false
    }
}

// MARK: - publish / update

/// Register or amend a code record — the Mac port of Android's
/// `CreateCodeActivity` and `UpdateCodeActivity`.
///
/// **The byte budget is the whole design, and it bites sooner here than
/// it does for a protocol.** The registration goes into an OP_RETURN
/// uncompressed and unencrypted, and every entry in `protocols` is a
/// 64-character record id — four of them are a quarter of the budget
/// before a word of description is typed. Android checks nothing: you
/// fill the form, press Publish, and the transaction fails at broadcast
/// with a message about script size. Here the remaining bytes are
/// counted live off the *encoded* envelope and the carve button turns
/// off before the user can pay for a transaction that cannot relay.
///
/// **An update resends everything.** The op replaces the record's
/// mutable half, so a field left blank here is a field cleared on chain
/// — which is why the form loads the current record rather than opening
/// empty, and why the warning above the buttons says so.
struct PublishCodeSheet: View {
    let session: ActiveSession
    let target: CodeComposeTarget

    enum Result {
        case published(Code)
        case updated(String)
        case draft
        case cancelled
    }

    let onDone: (Result) -> Void

    init(
        session: ActiveSession,
        target: CodeComposeTarget,
        onDone: @escaping (Result) -> Void
    ) {
        self.session = session
        self.target = target
        self.onDone = onDone
        let code = target.code
        _name = State(initialValue: code?.name ?? "")
        _ver = State(initialValue: code?.ver ?? "")
        _did = State(initialValue: code?.did ?? "")
        _desc = State(initialValue: code?.desc ?? "")
        _langsText = State(initialValue: (code?.langs ?? []).joined(separator: ", "))
        _protocols = State(initialValue: code?.protocols ?? [])
        _waiters = State(initialValue: code?.waiters ?? [])
        _homeRows = State(initialValue: HomeRow.rows(from: code?.home))
    }

    @State private var name: String
    @State private var ver: String
    @State private var did: String
    @State private var desc: String
    /// Languages, as typed. Android's field exactly — and unlike the
    /// `home` map, a comma-separated list of language names has nothing
    /// in it a separator can be confused with. What it will actually
    /// carve is shown back as chips underneath, so the parse is never a
    /// guess the user cannot see.
    @State private var langsText: String
    @State private var protocols: [String]
    @State private var waiters: [String]
    @State private var homeRows: [HomeRow]
    @State private var names: [String: String] = [:]

    @State private var pick: FidPickerRequest?
    @State private var pickingProtocols = false
    @State private var busy = false
    @State private var error: String?

    private var trimmedName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The languages the carve will carry, in the order typed, empties
    /// and duplicates dropped.
    private var langs: [String] {
        var seen = Set<String>()
        var out: [String] = []
        for part in langsText.split(separator: ",") {
            let t = part.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !t.isEmpty, seen.insert(t.lowercased()).inserted else { continue }
            out.append(t)
        }
        return out
    }

    private var home: [String: String]? {
        let map = HomeRow.map(from: homeRows)
        return map.isEmpty ? nil : map
    }

    private var remaining: Int {
        CodeFeip.remainingDescBytes(
            codeId: target.isUpdate ? (target.code?.id ?? "") : nil,
            name: trimmedName, ver: ver, did: did, desc: desc,
            langs: langs.isEmpty ? nil : langs,
            home: home,
            protocols: protocols.isEmpty ? nil : protocols,
            waiters: waiters.isEmpty ? nil : waiters
        )
    }

    private var canCarve: Bool {
        !trimmedName.isEmpty && remaining >= 0 && session.canSign && !busy
    }

    private var heading: String {
        switch target {
        case .new:    return "Publish a code record"
        case .draft:  return "Edit draft"
        case .update: return "Update this code record"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(heading).font(.title3.bold())

            Text("Everything below goes onto the chain in the clear, signed by \(session.liveFid.elidingMiddle(head: 8, tail: 8)). The registration is public and permanent; the code itself is not carved, only pointed at.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if target.isUpdate {
                Label("An update replaces what the record says. A field left blank here is a field cleared on chain.", systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 10) {
                        field("Name") {
                            TextField("What the implementation is called", text: $name)
                                .textFieldStyle(.roundedBorder)
                        }
                        field("Version") {
                            TextField("e.g. 1.4.2", text: $ver)
                                .textFieldStyle(.roundedBorder)
                        }
                        .frame(maxWidth: 140)
                    }

                    field("Description") {
                        VStack(alignment: .leading, spacing: 4) {
                            TextEditor(text: $desc)
                                .font(.body)
                                .frame(minHeight: 80, maxHeight: 160)
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
                                Text("The whole registration rides in one transaction — \(CodeFeip.maxOpReturnSize) bytes for everything on this form, and each protocol id is 64 of them.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }

                    field("Languages") {
                        VStack(alignment: .leading, spacing: 5) {
                            TextField("swift, c, rust — comma separated", text: $langsText)
                                .textFieldStyle(.roundedBorder)
                            if langs.isEmpty {
                                Text("None — the registration does not say what it is written in.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            } else {
                                // What will actually be carved, read back
                                // from the parse rather than from the box.
                                HStack(spacing: 4) {
                                    ForEach(langs, id: \.self) { lang in
                                        Text(lang)
                                            .font(.caption2)
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Capsule().fill(Color.secondary.opacity(0.15)))
                                    }
                                }
                            }
                        }
                    }

                    field("Protocols it speaks") {
                        ProtocolIdListEditor(
                            session: session,
                            ids: $protocols,
                            onPick: { pickingProtocols = true }
                        )
                    }

                    field("Artefact DID") {
                        TextField("digest of the code being registered", text: $did)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    }
                    .help("The code itself is not carved. This is its digest, so whoever fetches it can check it is what was registered.")

                    field("Where to get it") {
                        HomeMapEditor(rows: $homeRows)
                    }

                    field("Waiters") {
                        VStack(alignment: .leading, spacing: 6) {
                            if waiters.isEmpty {
                                Text("Nobody — the owner is the only contact for this implementation.")
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
                                    subtitle: "They are listed as serving this implementation. A waiter is not a co-owner — only you can carve against the record.",
                                    excluded: Set(waiters)
                                )
                            } label: {
                                Label("Add waiters", systemImage: "person.badge.plus")
                            }
                            .controlSize(.small)
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
                    Button(target.code == nil ? "Save draft" : "Save changes") { saveDraft() }
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
        .frame(width: 620)
        .frame(minHeight: 480, maxHeight: 760)
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
    }

    /// Persist the draft, and return it.
    ///
    /// **Editing moves the row's key.** A draft's id is a digest of the
    /// payload it will carve, so changing a field changes the id — that
    /// is what makes an unchanged draft's id stable across a reload. The
    /// old key is therefore deleted rather than updated in place;
    /// `addedAt` is carried over so "when did I start this" survives the
    /// move.
    @discardableResult
    private func persistDraft() throws -> Code {
        var draft = Code.createLocal(
            name: trimmedName,
            ver: clean(ver), did: clean(did), desc: clean(desc),
            langs: langs.isEmpty ? nil : langs,
            home: home,
            protocols: protocols.isEmpty ? nil : protocols,
            waiters: waiters.isEmpty ? nil : waiters,
            owner: session.liveFid
        )
        if case .draft(let editing) = target {
            draft.addedAt = editing.addedAt
            if editing.id != draft.id {
                try session.codes.removeDraft(id: editing.id)
            }
        }
        try session.codes.upsertDraft(draft)
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
            if case .update(let code) = target {
                let txid = try await session.carveCodeUpdateOnChain(
                    codeId: code.id,
                    name: trimmedName,
                    ver: clean(ver), did: clean(did), desc: clean(desc),
                    langs: langs.isEmpty ? nil : langs,
                    home: home,
                    protocols: protocols.isEmpty ? nil : protocols,
                    waiters: waiters.isEmpty ? nil : waiters
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
            if case .draft = target { draftId = try persistDraft().id }
            let code = try await session.carveCodePublishOnChain(
                name: trimmedName,
                ver: clean(ver), did: clean(did), desc: clean(desc),
                langs: langs.isEmpty ? nil : langs,
                home: home,
                protocols: protocols.isEmpty ? nil : protocols,
                waiters: waiters.isEmpty ? nil : waiters,
                draftId: draftId
            )
            onDone(.published(code))
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

// MARK: - the protocol list

/// The protocol ids a code record claims to speak, edited as a list.
///
/// **Ids are picked, not typed, by default.** Each entry is a 64-hex
/// protocol record id; a hand-typed one that is wrong is not rejected by
/// anything — the chain stores whatever string it is given, and the
/// record ends up claiming to implement a protocol that does not exist.
/// Android binds a picker here for exactly this reason
/// (`bindEntityIdField(… ProtocolActivity.class)`), and so does this. A
/// paste field is still offered underneath, because an id somebody sent
/// you in a message is a real way to get one.
struct ProtocolIdListEditor: View {
    let session: ActiveSession
    @Binding var ids: [String]
    let onPick: () -> Void

    @State private var typed = ""
    /// protocol id → name, filled in for whatever is already on the list
    /// so the user sees words rather than sixty-four hex characters.
    @State private var names: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if ids.isEmpty {
                Text("None — the registration does not say which specifications this implements.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(ids, id: \.self) { id in
                    HStack(spacing: 6) {
                        Image(systemName: "doc.text")
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

                TextField("or paste a protocol ID", text: $typed)
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

    /// Names for the ids already on the list. Best-effort: an id the
    /// registry has never seen keeps its hex, which is itself worth
    /// seeing — it usually means the id is wrong.
    private func resolveNames() async {
        let wanted = ids.filter { names[$0] == nil }
        guard !wanted.isEmpty else { return }
        if let found = try? await session.protocolService.fetchProtocolsByIds(wanted) {
            for (id, spec) in found { names[id] = spec.displayName }
        }
    }
}

/// Pick protocols out of the live registry — the Mac stand-in for
/// Android's "open `ProtocolActivity` in pick mode" hop.
///
/// Only live records are offered. A stopped or closed protocol can still
/// be implemented, but choosing one from a list is almost never what
/// somebody means to do, and the paste field in
/// ``ProtocolIdListEditor`` is there for the case where it is.
struct ProtocolPickerSheet: View {
    let session: ActiveSession
    let excluded: Set<String>
    let onPick: ([String]) -> Void
    let onCancel: () -> Void

    @State private var rows: [ProtocolSpec] = []
    @State private var selection: Set<String> = []
    @State private var searchText = ""
    @State private var loading = false
    @State private var error: String?
    @State private var didLoad = false

    private var filtered: [ProtocolSpec] {
        let available = rows.filter { !excluded.contains($0.id) }
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return available }
        return available.filter { $0.matches(query: q) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pick the protocols this implements").font(.title3.bold())
            Text("The live protocol registry. Each one you tick adds its 64-character record id to the carve, so the byte budget on the form behind this will move.")
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
                    ForEach(filtered) { spec in
                        HStack(spacing: 8) {
                            Toggle("", isOn: Binding(
                                get: { selection.contains(spec.id) },
                                set: { on in
                                    if on { selection.insert(spec.id) } else { selection.remove(spec.id) }
                                }
                            ))
                            .labelsHidden()

                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(spec.displayName).font(.body)
                                        .lineLimit(1).truncationMode(.middle)
                                    if let ver = spec.ver, !ver.isEmpty {
                                        Text("v\(ver)").font(.caption2).foregroundStyle(.tertiary)
                                    }
                                    if let sn = spec.sn, !sn.isEmpty {
                                        Text("sn \(sn)").font(.caption2).foregroundStyle(.tertiary)
                                    }
                                }
                                CopyableText.elidingMiddle(
                                    spec.id, head: 10, tail: 10,
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
                             ? "Nothing live in the protocol registry yet."
                             : "No protocol matches “\(searchText)”.")
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
            let page = try await session.protocolService.fetchProtocols(
                active: true, closed: false, size: 100
            )
            rows = page.protocols
        } catch {
            self.error = "Couldn't load the protocol registry: \(error)"
        }
    }
}

// MARK: - detail

/// Every field of one code record, untruncated and copyable — the Mac
/// analogue of Android's code detail card.
struct CodeDetailSheet: View {
    let session: ActiveSession
    let code: Code
    let name: (String) -> String?
    let onClose: () -> Void

    /// protocol id → name, resolved from the protocol registry so the
    /// list of what this implements reads as words.
    @State private var protocolNames: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Text(code.displayName)
                    .font(.title3.bold())
                    .lineLimit(2)
                    .truncationMode(.middle)
                Spacer()
                stateChip
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let desc = code.desc, !desc.isEmpty {
                        field("Description") {
                            CopyableText(desc, font: .body)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    HStack(alignment: .top, spacing: 24) {
                        if let ver = code.ver, !ver.isEmpty {
                            field("Version") { Text(ver).font(.caption) }
                        }
                        if let langs = code.langs, !langs.isEmpty {
                            field("Languages") {
                                Text(langs.joined(separator: ", ")).font(.caption)
                            }
                        }
                    }

                    field("Owner") { fidValue(code.owner) }

                    if let protocols = code.protocols, !protocols.isEmpty {
                        field("Protocols it speaks") {
                            VStack(alignment: .leading, spacing: 5) {
                                ForEach(protocols, id: \.self) { id in
                                    HStack(spacing: 6) {
                                        Image(systemName: "doc.text")
                                            .foregroundStyle(.secondary)
                                        if let n = protocolNames[id], !n.isEmpty {
                                            Text(n).font(.caption)
                                        }
                                        CopyableText.elidingMiddle(
                                            id, head: 10, tail: 10,
                                            font: .system(.caption2, design: .monospaced)
                                        )
                                        .foregroundStyle(.secondary)
                                    }
                                }
                                Text("A claim, not a proof — nothing on chain checks that the code does what these say.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }

                    if let waiters = code.waiters, !waiters.isEmpty {
                        field("Waiters") {
                            VStack(alignment: .leading, spacing: 5) {
                                ForEach(waiters, id: \.self) { fid in
                                    fidValue(fid)
                                }
                            }
                        }
                    }

                    if let home = code.home, !home.isEmpty {
                        field("Where to get it") {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(home.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                                    HStack(spacing: 6) {
                                        Text(key).font(.caption).foregroundStyle(.secondary)
                                        CopyableText(value, font: .system(.caption, design: .monospaced))
                                    }
                                }
                            }
                        }
                    }

                    if let did = code.did, !did.isEmpty {
                        field("Artefact DID") {
                            CopyableText.elidingMiddle(
                                did, head: 12, tail: 12,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                    }

                    if code.isClosed, let statement = code.closeStatement, !statement.isEmpty {
                        field("Closing statement") {
                            CopyableText(statement, font: .caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    HStack(spacing: 24) {
                        field("Rating") {
                            Text(code.tRate.map { String(format: "%.2f", $0) } ?? "—")
                                .font(.caption)
                        }
                        field("CDD burned for it") {
                            Text(code.tCdd.map { "\($0)" } ?? "—")
                                .font(.caption.monospacedDigit())
                        }
                    }

                    field("Code ID") {
                        CopyableText.elidingMiddle(
                            code.id, head: 12, tail: 12,
                            font: .system(.caption, design: .monospaced)
                        )
                    }

                    if let txid = code.lastTxId, !txid.isEmpty, txid != code.id {
                        field("Last transaction") {
                            CopyableText.elidingMiddle(
                                txid, head: 12, tail: 12,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                    }

                    HStack(spacing: 24) {
                        if let t = code.birthTime {
                            field("Published") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let t = code.lastTime {
                            field("Last change") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let h = code.lastHeight, h != CodesStore.unconfirmedHeight {
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
        .frame(width: 540)
        .frame(minHeight: 360, maxHeight: 660)
        .task {
            let ids = code.protocols ?? []
            guard !ids.isEmpty else { return }
            if let found = try? await session.protocolService.fetchProtocolsByIds(ids) {
                for (id, spec) in found { protocolNames[id] = spec.displayName }
            }
        }
    }

    @ViewBuilder
    private var stateChip: some View {
        switch code.state {
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

/// Retire code records permanently, with a reason — the Mac port of
/// Android's `CloseCodeActivity`.
///
/// A sheet rather than an alert because closing takes a statement, and
/// because it is the one op in this pane that nothing undoes — the user
/// should see which records they picked, and be told plainly that
/// Recover does not apply, before the carve goes out.
struct CloseCodeSheet: View {
    let session: ActiveSession
    let codes: [Code]
    let onDone: (String?) -> Void

    @State private var statement = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(codes.count == 1 ? "Close this code record" : "Close \(codes.count) code records")
                .font(.title3.bold())

            VStack(alignment: .leading, spacing: 4) {
                ForEach(codes) { code in
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.left.forwardslash.chevron.right")
                            .foregroundStyle(.secondary)
                        Text(code.displayName)
                            .font(.body)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if let ver = code.ver, !ver.isEmpty {
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

            VStack(alignment: .leading, spacing: 4) {
                Text("Closing statement").font(.caption).foregroundStyle(.secondary)
                TextField("why, or what replaces it — optional", text: $statement)
                    .textFieldStyle(.roundedBorder)
                Text("The last thing you will ever be able to say about this code record on chain.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            Text("One carve for all \(codes.count) — one miner fee, and it pays nobody.")
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
                    .disabled(busy || codes.isEmpty || !session.canSign)
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private func close() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            let txid = try await session.carveCodeCloseOnChain(
                codeIds: codes.map(\.id),
                closeStatement: statement.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            onDone(txid)
        } catch {
            self.error = "Couldn't close: \(error)"
        }
    }
}
