import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - what the compose sheet is doing

/// The three things the publish form can be opened for. One sheet rather
/// than three, because Android's `CreateAppActivity` and
/// `UpdateAppActivity` are 1 141 lines that differ in two places: which
/// button is shown, and whether the carve carries an `aid`.
enum AppComposeTarget: Identifiable {
    /// A new registration, from nothing.
    case new
    /// A local draft — still editable, still free.
    case draft(AppRecord)
    /// An on-chain record being amended. The AID does not move; only
    /// what the record says does.
    case update(AppRecord)

    var id: String {
        switch self {
        case .new:            return "new"
        case .draft(let a):   return "draft:\(a.id)"
        case .update(let a):  return "update:\(a.id)"
        }
    }

    var app: AppRecord? {
        switch self {
        case .new:                          return nil
        case .draft(let a), .update(let a): return a
        }
    }

    var isUpdate: Bool {
        if case .update = self { return true }
        return false
    }
}

// MARK: - publish / update

/// Register or amend an app — the Mac port of Android's
/// `CreateAppActivity` and `UpdateAppActivity`.
///
/// **An update resends everything.** The op replaces the record's
/// mutable half, so a field left blank here is a field cleared on chain.
/// That is not a hypothetical on this record: Android passes
/// `downloads: null` on every update, so amending an app from there
/// erases every build link it was offering (**Android issue C23**). The
/// form loads the current record, downloads included, and submits all of
/// it.
///
/// **The byte budget is spent mostly on downloads.** A build row is a
/// URL plus a 64-character digest, so three platforms cost more than the
/// whole rest of a typical record. The remaining bytes are counted live
/// off the *encoded* envelope and the carve button turns off before the
/// user can pay for a transaction that cannot relay.
struct PublishAppSheet: View {
    let session: ActiveSession
    let target: AppComposeTarget

    enum Result {
        case published(AppRecord)
        case updated(String)
        case draft
        case cancelled
    }

    let onDone: (Result) -> Void

    init(
        session: ActiveSession,
        target: AppComposeTarget,
        onDone: @escaping (Result) -> Void
    ) {
        self.session = session
        self.target = target
        self.onDone = onDone
        let a = target.app
        _stdName = State(initialValue: a?.stdName ?? "")
        _ver = State(initialValue: a?.ver ?? "")
        _desc = State(initialValue: a?.desc ?? "")
        _typesText = State(initialValue: (a?.types ?? []).joined(separator: ", "))
        _homeRows = State(initialValue: HomeRow.rows(from: a?.home))
        _localNameRows = State(initialValue: HomeRow.rows(from: a?.localNames))
        _downloads = State(initialValue: a?.downloads ?? [])
        _protocols = State(initialValue: a?.protocols ?? [])
        _codes = State(initialValue: a?.codes ?? [])
        _serviceIds = State(initialValue: a?.services ?? [])
        _waiters = State(initialValue: a?.waiters ?? [])
    }

    @State private var stdName: String
    @State private var ver: String
    @State private var desc: String
    /// Types, as typed. A comma-separated list of short words has
    /// nothing in it a comma can be confused with — and what will
    /// actually be carved is echoed back as chips underneath, so the
    /// parse is never a guess the user cannot see.
    @State private var typesText: String
    @State private var homeRows: [HomeRow]
    @State private var localNameRows: [HomeRow]
    @State private var downloads: [AppRecord.Download]
    @State private var protocols: [String]
    @State private var codes: [String]
    @State private var serviceIds: [String]
    @State private var waiters: [String]
    @State private var names: [String: String] = [:]

    @State private var pick: FidPickerRequest?
    @State private var pickingProtocols = false
    @State private var pickingCodes = false
    @State private var busy = false
    @State private var error: String?

    private var trimmedName: String {
        stdName.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The types the carve will carry, in the order typed, empties and
    /// duplicates dropped.
    private var types: [String] {
        var seen = Set<String>()
        var out: [String] = []
        for part in typesText.split(separator: ",") {
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

    private var localNames: [String: String]? {
        let map = HomeRow.map(from: localNameRows)
        return map.isEmpty ? nil : map
    }

    /// Only the rows worth carving — the same pruning the builder does,
    /// so the budget and the chips agree with the payload.
    private var carvableDownloads: [AppRecord.Download] {
        downloads.compactMap(\.pruned)
    }

    private var remaining: Int {
        AppFeip.remainingDescBytes(
            aid: target.isUpdate ? (target.app?.id ?? "") : nil,
            stdName: trimmedName,
            localNames: localNames,
            types: types.isEmpty ? nil : types,
            desc: desc,
            ver: ver,
            home: home,
            downloads: carvableDownloads.isEmpty ? nil : carvableDownloads,
            waiters: waiters.isEmpty ? nil : waiters,
            protocols: protocols.isEmpty ? nil : protocols,
            codes: codes.isEmpty ? nil : codes,
            services: serviceIds.isEmpty ? nil : serviceIds
        )
    }

    private var canCarve: Bool {
        !trimmedName.isEmpty && remaining >= 0 && session.canSign && !busy
    }

    private var heading: String {
        switch target {
        case .new:    return "Publish an app"
        case .draft:  return "Edit draft"
        case .update: return "Update this app"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(heading).font(.title3.bold())

            Text("Everything below goes onto the chain in the clear, signed by \(session.liveFid.elidingMiddle(head: 8, tail: 8)). The app itself is not carved — only where to get it and what digest it should have.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if target.isUpdate {
                Label("An update replaces what the record says. A field left blank here is a field cleared on chain — downloads included.", systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 10) {
                        field("Standard name") {
                            TextField("What the app is called", text: $stdName)
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
                                Text("The whole registration rides in one transaction — \(AppFeip.maxOpReturnSize) bytes for everything on this form, and a download row costs its link plus its digest.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }

                    field("Types") {
                        VStack(alignment: .leading, spacing: 5) {
                            TextField("wallet, im, browser — comma separated", text: $typesText)
                                .textFieldStyle(.roundedBorder)
                            if types.isEmpty {
                                Text("None — the registration does not say what kind of app this is.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            } else {
                                // What will actually be carved, read back
                                // from the parse rather than from the box.
                                HStack(spacing: 4) {
                                    ForEach(types, id: \.self) { type in
                                        Text(type)
                                            .font(.caption2)
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Capsule().fill(Color.secondary.opacity(0.15)))
                                    }
                                }
                            }
                        }
                    }

                    field("Downloads") {
                        DownloadsEditor(downloads: $downloads)
                    }

                    field("Where to read about it") {
                        HomeMapEditor(
                            rows: $homeRows,
                            emptyText: "Nowhere — the registration names the app without saying where to read about it.",
                            keyPlaceholder: "site",
                            valuePlaceholder: "https://…",
                            addLabel: "Add a link"
                        )
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

                    field("Code it is built from") {
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

                    field("Services it talks to") {
                        SidListEditor(session: session, ids: $serviceIds)
                    }

                    field("Waiters") {
                        VStack(alignment: .leading, spacing: 6) {
                            if waiters.isEmpty {
                                Text("Nobody — the owner is the only contact for this app.")
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
                                    subtitle: "They are listed as serving this app. A waiter is not a co-owner — only you can carve against the record.",
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
                    Button(target.app == nil ? "Save draft" : "Save changes") { saveDraft() }
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

    /// Persist the draft, and return it.
    ///
    /// **Editing moves the row's key.** A draft's id is a digest of the
    /// payload it will carve, so changing a field changes the id — that
    /// is what makes an unchanged draft's id stable across a reload. The
    /// old key is therefore deleted rather than updated in place;
    /// `addedAt` is carried over so "when did I start this" survives the
    /// move.
    @discardableResult
    private func persistDraft() throws -> AppRecord {
        var draft = AppRecord.createLocal(
            stdName: trimmedName,
            localNames: localNames,
            types: types.isEmpty ? nil : types,
            desc: clean(desc),
            ver: clean(ver),
            home: home,
            downloads: carvableDownloads.isEmpty ? nil : carvableDownloads,
            waiters: waiters.isEmpty ? nil : waiters,
            protocols: protocols.isEmpty ? nil : protocols,
            codes: codes.isEmpty ? nil : codes,
            services: serviceIds.isEmpty ? nil : serviceIds,
            owner: session.liveFid
        )
        if case .draft(let editing) = target {
            draft.addedAt = editing.addedAt
            if editing.id != draft.id {
                try session.apps.removeDraft(id: editing.id)
            }
        }
        try session.apps.upsertDraft(draft)
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
            if case .update(let app) = target {
                let txid = try await session.carveAppUpdateOnChain(
                    aid: app.id,
                    stdName: trimmedName,
                    localNames: localNames,
                    types: types.isEmpty ? nil : types,
                    desc: clean(desc),
                    ver: clean(ver),
                    home: home,
                    downloads: carvableDownloads.isEmpty ? nil : carvableDownloads,
                    waiters: waiters.isEmpty ? nil : waiters,
                    protocols: protocols.isEmpty ? nil : protocols,
                    codes: codes.isEmpty ? nil : codes,
                    services: serviceIds.isEmpty ? nil : serviceIds
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
            let app = try await session.carveAppPublishOnChain(
                stdName: trimmedName,
                localNames: localNames,
                types: types.isEmpty ? nil : types,
                desc: clean(desc),
                ver: clean(ver),
                home: home,
                downloads: carvableDownloads.isEmpty ? nil : carvableDownloads,
                waiters: waiters.isEmpty ? nil : waiters,
                protocols: protocols.isEmpty ? nil : protocols,
                codes: codes.isEmpty ? nil : codes,
                services: serviceIds.isEmpty ? nil : serviceIds,
                draftId: draftId
            )
            onDone(.published(app))
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

// MARK: - downloads

/// One row per platform build: OS, link, digest.
///
/// **The field Android does not have.** Both its activities pass `null`
/// where downloads go, so an app published from there cannot say where
/// to get it, and an app *updated* from there loses the links somebody
/// else carved (**Android issue C23**). This is the whole of what makes
/// the record useful, so it gets a proper editor rather than a text
/// field.
///
/// **The digest is the part worth insisting on.** A link alone asks the
/// reader to trust whatever the host serves today; the digest is what
/// turns the record into a check on the download. Nothing enforces it —
/// the reader has to do the hashing — but the claim is signed and
/// permanent, so a substituted binary is provably not the one that was
/// registered. A row without one still carves; it just says less, and
/// the editor says so.
struct DownloadsEditor: View {
    @Binding var downloads: [AppRecord.Download]

    /// Platforms worth one click. Free text underneath, because the OS
    /// string is the publisher's and the chain does not police it.
    private static let commonOS = ["macos", "windows", "linux", "android", "ios"]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if downloads.isEmpty {
                Text("None — nobody reading this record will know where to get the app.")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            ForEach($downloads) { $row in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        TextField("os", text: Binding(
                            get: { row.os ?? "" },
                            set: { row.os = $0.isEmpty ? nil : $0 }
                        ))
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 90)

                        TextField("https://… where to download it", text: Binding(
                            get: { row.link ?? "" },
                            set: { row.link = $0.isEmpty ? nil : $0 }
                        ))
                        .textFieldStyle(.roundedBorder)

                        Button {
                            let id = row.id
                            downloads.removeAll { $0.id == id }
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                    HStack(spacing: 6) {
                        TextField("digest of that file — what a reader checks it against", text: Binding(
                            get: { row.did ?? "" },
                            set: { row.did = $0.isEmpty ? nil : $0 }
                        ))
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.caption, design: .monospaced))
                        if (row.did ?? "").trimmingCharacters(in: .whitespaces).isEmpty {
                            Text("no digest — the link is unverifiable")
                                .font(.caption2)
                                .foregroundStyle(.orange)
                        }
                    }
                }
                .padding(.bottom, 2)
            }

            HStack(spacing: 6) {
                Menu("Add a build") {
                    ForEach(Self.commonOS, id: \.self) { os in
                        Button(os) { downloads.append(AppRecord.Download(os: os)) }
                    }
                    Divider()
                    Button("Other…") { downloads.append(AppRecord.Download()) }
                }
                .fixedSize()
                Spacer()
            }
        }
    }
}

// MARK: - detail

/// Every field of one app record, untruncated and copyable — the Mac
/// analogue of Android's app detail card, plus the downloads it never
/// showed.
struct AppDetailSheet: View {
    let session: ActiveSession
    let app: AppRecord
    let name: (String) -> String?
    let onClose: () -> Void

    /// record id → name, resolved so the code, protocol and service
    /// lists read as words rather than sixty-four hex characters each.
    @State private var linkedNames: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Text(app.displayName)
                    .font(.title3.bold())
                    .lineLimit(2)
                    .truncationMode(.middle)
                Spacer()
                stateChip
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let desc = app.desc, !desc.isEmpty {
                        field("Description") {
                            CopyableText(desc, font: .body)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    HStack(alignment: .top, spacing: 24) {
                        if let ver = app.ver, !ver.isEmpty {
                            field("Version") { Text(ver).font(.caption) }
                        }
                        if let types = app.types, !types.isEmpty {
                            field("Types") {
                                Text(types.joined(separator: ", ")).font(.caption)
                            }
                        }
                    }

                    if let downloads = app.downloads, !downloads.isEmpty {
                        field("Downloads") {
                            VStack(alignment: .leading, spacing: 8) {
                                ForEach(downloads) { d in
                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(spacing: 6) {
                                            Image(systemName: "arrow.down.circle")
                                                .foregroundStyle(.secondary)
                                            if let os = d.os, !os.isEmpty {
                                                Text(os).font(.caption.bold())
                                            }
                                            if let link = d.link, !link.isEmpty {
                                                CopyableText(
                                                    link,
                                                    font: .system(.caption, design: .monospaced)
                                                )
                                                .foregroundStyle(.blue)
                                                .lineLimit(1)
                                                .truncationMode(.middle)
                                            }
                                        }
                                        if let did = d.did, !did.isEmpty {
                                            HStack(spacing: 6) {
                                                Text("digest")
                                                    .font(.caption2)
                                                    .foregroundStyle(.tertiary)
                                                CopyableText.elidingMiddle(
                                                    did, head: 10, tail: 10,
                                                    font: .system(.caption2, design: .monospaced)
                                                )
                                                .foregroundStyle(.secondary)
                                            }
                                        } else {
                                            Text("No digest — nothing to check the download against.")
                                                .font(.caption2)
                                                .foregroundStyle(.orange)
                                        }
                                    }
                                }
                                Text("Check the file you download against the digest yourself. The chain records the claim and signs it; it cannot verify what a host serves.")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }

                    field("Owner") { fidValue(app.owner) }

                    if let home = app.home, !home.isEmpty {
                        field("Where to read about it") {
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

                    if let localNames = app.localNames, !localNames.isEmpty {
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

                    linkedList("Code it is built from", app.codes,
                               symbol: "chevron.left.forwardslash.chevron.right")
                    linkedList("Protocols it speaks", app.protocols, symbol: "doc.text")
                    linkedList("Services it talks to", app.services, symbol: "server.rack")

                    if let waiters = app.waiters, !waiters.isEmpty {
                        field("Waiters") {
                            VStack(alignment: .leading, spacing: 5) {
                                ForEach(waiters, id: \.self) { fid in
                                    fidValue(fid)
                                }
                            }
                        }
                    }

                    if app.isClosed, let statement = app.closeStatement, !statement.isEmpty {
                        field("Closing statement") {
                            CopyableText(statement, font: .caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    HStack(spacing: 24) {
                        field("Rating") {
                            Text(app.tRate.map { String(format: "%.2f", $0) } ?? "—")
                                .font(.caption)
                        }
                        field("CDD burned for it") {
                            Text(app.tCdd.map { "\($0)" } ?? "—")
                                .font(.caption.monospacedDigit())
                        }
                    }

                    field("App ID") {
                        CopyableText.elidingMiddle(
                            app.id, head: 12, tail: 12,
                            font: .system(.caption, design: .monospaced)
                        )
                    }

                    if let txid = app.lastTxId, !txid.isEmpty, txid != app.id {
                        field("Last transaction") {
                            CopyableText.elidingMiddle(
                                txid, head: 12, tail: 12,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                    }

                    HStack(spacing: 24) {
                        if let t = app.birthTime {
                            field("Published") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let t = app.lastTime {
                            field("Last change") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let h = app.lastHeight, h != AppsStore.unconfirmedHeight {
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
        if let codes = app.codes, !codes.isEmpty,
           let found = try? await session.codeService.fetchCodesByIds(codes) {
            for (id, code) in found { linkedNames[id] = code.displayName }
        }
        if let protocols = app.protocols, !protocols.isEmpty,
           let found = try? await session.protocolService.fetchProtocolsByIds(protocols) {
            for (id, spec) in found { linkedNames[id] = spec.displayName }
        }
        if let services = app.services, !services.isEmpty,
           let found = try? await session.serviceRegistry.fetchServicesByIds(services) {
            for (id, s) in found { linkedNames[id] = s.displayName }
        }
    }

    @ViewBuilder
    private var stateChip: some View {
        switch app.state {
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

/// Retire app records permanently, with a reason — the Mac port of
/// Android's `CloseAppActivity`.
///
/// A sheet rather than an alert because closing takes a statement, and
/// because it is the one op in this pane that nothing undoes — the user
/// should see which records they picked, and be told plainly that
/// Recover does not apply, before the carve goes out.
struct CloseAppSheet: View {
    let session: ActiveSession
    let apps: [AppRecord]
    let onDone: (String?) -> Void

    @State private var statement = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(apps.count == 1 ? "Close this app" : "Close \(apps.count) apps")
                .font(.title3.bold())

            VStack(alignment: .leading, spacing: 4) {
                ForEach(apps) { app in
                    HStack(spacing: 6) {
                        Image(systemName: "app.badge")
                            .foregroundStyle(.secondary)
                        Text(app.displayName)
                            .font(.body)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if let ver = app.ver, !ver.isEmpty {
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

            Text("It does not uninstall anything. Copies people already have keep working, and the download links keep resolving until whoever hosts them takes them down.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 4) {
                Text("Closing statement").font(.caption).foregroundStyle(.secondary)
                TextField("why, or which app replaces it — optional", text: $statement)
                    .textFieldStyle(.roundedBorder)
                Text("The last thing you will ever be able to say about this app on chain, and the only place to name its successor.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            Text("One carve for all \(apps.count) — one miner fee, and it pays nobody.")
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
                    .disabled(busy || apps.isEmpty || !session.canSign)
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
            let txid = try await session.carveAppCloseOnChain(
                aids: apps.map(\.id),
                closeStatement: statement.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            onDone(txid)
        } catch {
            self.error = "Couldn't close: \(error)"
        }
    }
}
