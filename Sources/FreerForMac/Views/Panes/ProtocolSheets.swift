import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - what the compose sheet is doing

/// The three things the publish form can be opened for. One sheet
/// rather than three, because Android's `CreateProtocolActivity` and
/// `UpdateProtocolActivity` are 1 100 lines that differ in two places:
/// which button is shown, and whether the carve carries a `pid`.
enum ProtocolComposeTarget: Identifiable {
    /// A new registration, from nothing.
    case new
    /// A local draft — still editable, still free.
    case draft(ProtocolSpec)
    /// An on-chain record being amended. The id does not move; only
    /// what the record says does.
    case update(ProtocolSpec)

    var id: String {
        switch self {
        case .new:            return "new"
        case .draft(let s):   return "draft:\(s.id)"
        case .update(let s):  return "update:\(s.id)"
        }
    }

    var spec: ProtocolSpec? {
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

/// Register or amend a protocol — the Mac port of Android's
/// `CreateProtocolActivity` and `UpdateProtocolActivity`.
///
/// **The byte budget is the whole design, as it is for a proof.** The
/// registration goes into an OP_RETURN uncompressed and unencrypted, so
/// the ceiling is reached by an ordinary paragraph of description plus a
/// handful of waiters. Android checks nothing: you fill the form, press
/// Publish, and the transaction fails at broadcast with a message about
/// script size. Here the remaining bytes are counted live off the
/// *encoded* envelope and the carve button turns off before the user can
/// pay for a transaction that cannot relay.
///
/// **An update resends everything.** The op replaces the record's
/// mutable half, so a field left blank here is a field cleared on chain
/// — which is why the form loads the current record rather than opening
/// empty, and why the warning above the buttons says so.
struct PublishProtocolSheet: View {
    let session: ActiveSession
    let target: ProtocolComposeTarget

    enum Result {
        case published(ProtocolSpec)
        case updated(String)
        case draft
        case cancelled
    }

    let onDone: (Result) -> Void

    init(
        session: ActiveSession,
        target: ProtocolComposeTarget,
        onDone: @escaping (Result) -> Void
    ) {
        self.session = session
        self.target = target
        self.onDone = onDone
        let spec = target.spec
        _name = State(initialValue: spec?.name ?? "")
        _type = State(initialValue: spec?.type ?? "")
        _sn = State(initialValue: spec?.sn ?? "")
        _ver = State(initialValue: spec?.ver ?? "")
        _did = State(initialValue: spec?.did ?? "")
        _desc = State(initialValue: spec?.desc ?? "")
        _lang = State(initialValue: spec?.lang ?? "")
        _preDid = State(initialValue: spec?.prePid ?? "")
        _waiters = State(initialValue: spec?.waiters ?? [])
        _homeRows = State(initialValue: HomeRow.rows(from: spec?.home))
    }

    @State private var name: String
    @State private var type: String
    @State private var sn: String
    @State private var ver: String
    @State private var did: String
    @State private var desc: String
    @State private var lang: String
    @State private var preDid: String
    @State private var waiters: [String]
    @State private var homeRows: [HomeRow]
    @State private var names: [String: String] = [:]

    @State private var pick: FidPickerRequest?
    @State private var busy = false
    @State private var error: String?

    private var trimmedName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var home: [String: String]? {
        let map = HomeRow.map(from: homeRows)
        return map.isEmpty ? nil : map
    }

    private var remaining: Int {
        ProtocolFeip.remainingDescBytes(
            pid: target.isUpdate ? (target.spec?.id ?? "") : nil,
            sn: sn, name: trimmedName, type: type, ver: ver, did: did,
            desc: desc, lang: lang, home: home,
            preDid: preDid, waiters: waiters.isEmpty ? nil : waiters
        )
    }

    private var canCarve: Bool {
        !trimmedName.isEmpty && remaining >= 0 && session.canSign && !busy
    }

    private var heading: String {
        switch target {
        case .new:    return "Publish a protocol"
        case .draft:  return "Edit draft"
        case .update: return "Update this protocol"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(heading).font(.title3.bold())

            Text("Everything below goes onto the chain in the clear, signed by \(session.liveFid.elidingMiddle(head: 8, tail: 8)). The registration is public and permanent; the specification document itself is not carved, only pointed at.")
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
                    field("Name") {
                        TextField("What the protocol is called", text: $name)
                            .textFieldStyle(.roundedBorder)
                    }

                    HStack(spacing: 10) {
                        field("Type") {
                            TextField("e.g. FEIP", text: $type)
                                .textFieldStyle(.roundedBorder)
                        }
                        field("Serial number") {
                            TextField("the protocol's own sn", text: $sn)
                                .textFieldStyle(.roundedBorder)
                        }
                        .help("The number this protocol goes by — not the FEIP envelope's sn, which is always 1 for a protocol registration.")
                        field("Version") {
                            TextField("e.g. 3", text: $ver)
                                .textFieldStyle(.roundedBorder)
                        }
                        field("Language") {
                            TextField("en", text: $lang)
                                .textFieldStyle(.roundedBorder)
                        }
                        .frame(maxWidth: 90)
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
                                Text("The whole registration rides in one transaction — \(ProtocolFeip.maxOpReturnSize) bytes for everything on this form.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }

                    field("Document DID") {
                        TextField("digest of the specification document", text: $did)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    }
                    .help("The spec itself is not carved. This is its digest, so a reader who fetches the document can check it is the one that was registered.")

                    field("Supersedes") {
                        TextField("id of the protocol record this replaces", text: $preDid)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    }
                    .help("A published version is not editable in place: a new version is a new record that points back at the old one.")

                    field("Where it lives") {
                        HomeMapEditor(rows: $homeRows)
                    }

                    field("Waiters") {
                        VStack(alignment: .leading, spacing: 6) {
                            if waiters.isEmpty {
                                Text("Nobody — the owner is the only contact for this protocol.")
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
                                    subtitle: "They are listed as serving this protocol. A waiter is not a co-owner — only you can carve against the record.",
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
                    // protocol.
                    Button(target.spec == nil ? "Save draft" : "Save changes") { saveDraft() }
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
    private func persistDraft() throws -> ProtocolSpec {
        var draft = ProtocolSpec.createLocal(
            name: trimmedName,
            type: clean(type), sn: clean(sn), ver: clean(ver), did: clean(did),
            desc: clean(desc), lang: clean(lang), home: home,
            preDid: clean(preDid),
            waiters: waiters.isEmpty ? nil : waiters,
            owner: session.liveFid
        )
        if case .draft(let editing) = target {
            draft.addedAt = editing.addedAt
            if editing.id != draft.id {
                try session.protocols.removeDraft(id: editing.id)
            }
        }
        try session.protocols.upsertDraft(draft)
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
            if case .update(let spec) = target {
                let txid = try await session.carveProtocolUpdateOnChain(
                    pid: spec.id,
                    name: trimmedName,
                    type: clean(type), sn: clean(sn), ver: clean(ver), did: clean(did),
                    desc: clean(desc), lang: clean(lang), home: home,
                    preDid: clean(preDid),
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
            let spec = try await session.carveProtocolPublishOnChain(
                name: trimmedName,
                type: clean(type), sn: clean(sn), ver: clean(ver), did: clean(did),
                desc: clean(desc), lang: clean(lang), home: home,
                preDid: clean(preDid),
                waiters: waiters.isEmpty ? nil : waiters,
                draftId: draftId
            )
            onDone(.published(spec))
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

// MARK: - the home map

/// One label → URL pair, with a stable identity so SwiftUI can edit a
/// list of them without rows swapping under the cursor.
struct HomeRow: Identifiable, Equatable {
    let id = UUID()
    var key: String
    var value: String

    static func rows(from map: [String: String]?) -> [HomeRow] {
        guard let map, !map.isEmpty else { return [] }
        // Sorted, because a dictionary has no order and an editor whose
        // rows shuffle between openings is unusable.
        return map.sorted { $0.key < $1.key }.map { HomeRow(key: $0.key, value: $0.value) }
    }

    static func map(from rows: [HomeRow]) -> [String: String] {
        var out: [String: String] = [:]
        for row in rows {
            let key = row.key.trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { continue }
            out[key] = row.value.trimmingCharacters(in: .whitespaces)
        }
        return out
    }
}

/// Label/URL pairs, edited as pairs.
///
/// Android asks for this as one text field of comma-separated
/// `key:value` items and parses it with `indexOf(':')` — which splits
/// `https://example.com` at the scheme, so any URL typed without a label
/// becomes the key `https` pointing at `//example.com` (**Android issue
/// C21**). Two fields per row cannot be ambiguous about which half is
/// which.
///
/// The four labels are parameters because the same editor serves three
/// different maps — a protocol's `home`, a service's `home`, and a
/// service's `localNames`, which is language tag → name and has no URL
/// in it at all.
struct HomeMapEditor: View {
    @Binding var rows: [HomeRow]
    var emptyText = "Nowhere — the registration names the protocol without saying where to read it."
    var keyPlaceholder = "label"
    var valuePlaceholder = "https://…"
    var addLabel = "Add a location"

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if rows.isEmpty {
                Text(emptyText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            ForEach($rows) { $row in
                HStack(spacing: 6) {
                    TextField(keyPlaceholder, text: $row.key)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 120)
                    TextField(valuePlaceholder, text: $row.value)
                        .textFieldStyle(.roundedBorder)
                    Button {
                        rows.removeAll { $0.id == row.id }
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            Button {
                rows.append(HomeRow(key: "", value: ""))
            } label: {
                Label(addLabel, systemImage: "plus")
            }
            .controlSize(.small)
        }
    }
}

// MARK: - detail

/// Every field of one protocol record, untruncated and copyable — the
/// Mac analogue of Android's protocol detail card.
struct ProtocolDetailSheet: View {
    let session: ActiveSession
    let spec: ProtocolSpec
    let name: (String) -> String?
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Text(spec.displayName)
                    .font(.title3.bold())
                    .lineLimit(2)
                    .truncationMode(.middle)
                Spacer()
                stateChip
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let desc = spec.desc, !desc.isEmpty {
                        field("Description") {
                            CopyableText(desc, font: .body)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    HStack(alignment: .top, spacing: 24) {
                        if let type = spec.type, !type.isEmpty {
                            field("Type") { Text(type).font(.caption) }
                        }
                        if let sn = spec.sn, !sn.isEmpty {
                            field("Serial number") { Text(sn).font(.caption.monospacedDigit()) }
                        }
                        if let ver = spec.ver, !ver.isEmpty {
                            field("Version") { Text(ver).font(.caption) }
                        }
                        if let lang = spec.lang, !lang.isEmpty {
                            field("Language") { Text(lang).font(.caption) }
                        }
                    }

                    field("Owner") { fidValue(spec.owner) }

                    if let waiters = spec.waiters, !waiters.isEmpty {
                        field("Waiters") {
                            VStack(alignment: .leading, spacing: 5) {
                                ForEach(waiters, id: \.self) { fid in
                                    fidValue(fid)
                                }
                            }
                        }
                    }

                    if let home = spec.home, !home.isEmpty {
                        field("Where it lives") {
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

                    if let did = spec.did, !did.isEmpty {
                        field("Document DID") {
                            CopyableText.elidingMiddle(
                                did, head: 12, tail: 12,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                    }

                    if let pre = spec.prePid, !pre.isEmpty {
                        field("Supersedes") {
                            CopyableText.elidingMiddle(
                                pre, head: 12, tail: 12,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                    }

                    if spec.isClosed, let statement = spec.closeStatement, !statement.isEmpty {
                        field("Closing statement") {
                            CopyableText(statement, font: .caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    HStack(spacing: 24) {
                        field("Rating") {
                            Text(spec.tRate.map { String(format: "%.2f", $0) } ?? "—")
                                .font(.caption)
                        }
                        field("CDD burned for it") {
                            Text(spec.tCdd.map { "\($0)" } ?? "—")
                                .font(.caption.monospacedDigit())
                        }
                    }

                    field("Protocol ID") {
                        CopyableText.elidingMiddle(
                            spec.id, head: 12, tail: 12,
                            font: .system(.caption, design: .monospaced)
                        )
                    }

                    if let txid = spec.lastTxId, !txid.isEmpty, txid != spec.id {
                        field("Last transaction") {
                            CopyableText.elidingMiddle(
                                txid, head: 12, tail: 12,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                    }

                    HStack(spacing: 24) {
                        if let t = spec.birthTime {
                            field("Published") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let t = spec.lastTime {
                            field("Last change") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let h = spec.lastHeight, h != ProtocolsStore.unconfirmedHeight {
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
    }

    @ViewBuilder
    private var stateChip: some View {
        switch spec.state {
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

/// Retire protocols permanently, with a reason.
///
/// A sheet rather than an alert because closing takes a statement, and
/// because it is the one op in this pane that nothing undoes — the user
/// should see which records they picked, and be told plainly that
/// Recover does not apply, before the carve goes out.
struct CloseProtocolSheet: View {
    let session: ActiveSession
    let specs: [ProtocolSpec]
    let onDone: (String?) -> Void

    @State private var statement = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(specs.count == 1 ? "Close this protocol" : "Close \(specs.count) protocols")
                .font(.title3.bold())

            VStack(alignment: .leading, spacing: 4) {
                ForEach(specs) { spec in
                    HStack(spacing: 6) {
                        Image(systemName: "doc.text")
                            .foregroundStyle(.secondary)
                        Text(spec.displayName)
                            .font(.body)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if let ver = spec.ver, !ver.isEmpty {
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
                Text("The last thing you will ever be able to say about this protocol on chain.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            Text("One carve for all \(specs.count) — one miner fee, and it pays nobody.")
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
                    .disabled(busy || specs.isEmpty || !session.canSign)
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
            let txid = try await session.carveProtocolCloseOnChain(
                pids: specs.map(\.id),
                closeStatement: statement.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            onDone(txid)
        } catch {
            self.error = "Couldn't close: \(error)"
        }
    }
}
