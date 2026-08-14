import SwiftUI
import FCCore
import FCDomain
import FCUI

/// On-chain mail — the Mac port of Android's `MailActivity` /
/// `ReadMailActivity` / `DeleteMailActivity` / `MailDeletedActivity`.
///
/// Three tabs over one store: Inbox (what others sent us), Sent (what we
/// sent), Deleted (mail whose newest carve is a delete — kept, because
/// the chain can recover it).
///
/// **Bodies are sealed at rest**, so the pane decrypts as it goes: only
/// the rows it is about to draw, and only once per pane life. That is
/// why the list is paginated rather than rendering the whole mailbox —
/// each row costs an ECDH the first time it appears.
///
/// **The envelope is public.** Sender, recipient, time and the notice
/// fee are ordinary indexed fields on the chain; only the body is
/// encrypted. The pane says so out loud rather than letting the padlocks
/// imply more privacy than there is.
struct MailView: View {
    let session: ActiveSession

    private enum Tab: String, CaseIterable, Identifiable {
        case inbox = "Inbox"
        case sent = "Sent"
        case deleted = "Deleted"
        var id: String { rawValue }
    }

    @State private var tab: Tab = .inbox
    @State private var rows: [Mail] = []
    @State private var loadError: String?
    @State private var search = ""
    @State private var visibleLimit = 50

    @State private var syncing = false
    @State private var syncError: String?
    @State private var syncSummary: String?
    @State private var didAutoSync = false

    @State private var showCompose = false
    @State private var composePreset: MailComposeSheet.Preset?
    @State private var readingMail: Mail?
    @State private var pendingDelete: Mail?
    @State private var carving = false
    @State private var carveTxid: String?

    /// mail id → decrypted body, in memory only, for this pane's life.
    /// Never written back to the store — see ``MailsStore``.
    @State private var bodies: [String: String] = [:]

    // MARK: - derived

    private var tabRows: [Mail] {
        let me = session.liveFid
        switch tab {
        case .inbox:   return rows.filter { !$0.isDeleted && $0.isIncoming(for: me) }
        case .sent:    return rows.filter { !$0.isDeleted && !$0.isIncoming(for: me) }
        case .deleted: return rows.filter(\.isDeleted)
        }
    }

    /// Search runs over rows *with their decrypted bodies attached*, so
    /// a query matches text the reader can actually see. A sealed body
    /// contributes nothing — see `Mail.matches(query:)`.
    private var filtered: [Mail] {
        let needle = search.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else { return tabRows }
        return tabRows.filter { withBody($0).matches(query: needle) }
    }

    private var visible: [Mail] { Array(filtered.prefix(visibleLimit)) }

    private var unreadCount: Int {
        rows.filter { $0.unread == true && !$0.isDeleted }.count
    }

    private func withBody(_ mail: Mail) -> Mail {
        guard let id = mail.id, let body = bodies[id] else { return mail }
        var m = mail
        m.content = body
        return m
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            toolbar
            banner

            if let err = loadError {
                card {
                    Label("Couldn't load mail", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    CopyableText(err, font: .callout).foregroundStyle(.red)
                }
            } else {
                list
            }

            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 560)
        .onAppear {
            reload()
            if !didAutoSync {
                didAutoSync = true
                Task { await syncFromChain() }
            }
        }
        .onChange(of: tab) { _, _ in visibleLimit = 50 }
        .onChange(of: search) { _, _ in visibleLimit = 50 }
        .sheet(isPresented: $showCompose) {
            MailComposeSheet(
                session: session,
                preset: composePreset,
                onSent: { txid in
                    showCompose = false
                    composePreset = nil
                    syncError = nil
                    carveTxid = txid
                    tab = .sent
                    reload()
                },
                onCancel: {
                    showCompose = false
                    composePreset = nil
                }
            )
        }
        .sheet(item: $readingMail) { mail in
            MailReadSheet(
                session: session,
                mail: withBody(mail),
                onClose: { readingMail = nil; reload() },
                onReply: { original in
                    readingMail = nil
                    composePreset = replyPreset(to: original)
                    showCompose = true
                },
                onDelete: { original in
                    readingMail = nil
                    pendingDelete = original
                }
            )
        }
        .alert(
            pendingDelete?.isDeleted == true ? "Recover this mail?" : "Delete this mail?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingDelete = nil }
            if let mail = pendingDelete, mail.isDeleted {
                Button("Recover on-chain") {
                    pendingDelete = nil
                    Task { await setDeleted(mail, deleted: false) }
                }
                .disabled(!session.canSign)
            } else if let mail = pendingDelete {
                Button("Delete on-chain", role: .destructive) {
                    pendingDelete = nil
                    Task { await setDeleted(mail, deleted: true) }
                }
                .disabled(!session.canSign)
            }
            Button("Remove from this device", role: .destructive) {
                if let mail = pendingDelete { removeLocally(mail) }
                pendingDelete = nil
            }
        } message: {
            if pendingDelete?.isDeleted == true {
                Text("Carves a recover record so this mail comes back on every device (small miner fee). Removing it from this device instead just hides it here — the next chain sync brings it back.")
            } else {
                Text("Carves a delete record so the mail is marked deleted on every device (small miner fee). It stays recoverable. Removing it from this device instead only hides it here — the next chain sync brings it back, because the mail still exists on the chain.")
            }
        }
    }

    // MARK: - chrome

    private var toolbar: some View {
        HStack(spacing: 12) {
            Picker("", selection: $tab) {
                ForEach(Tab.allCases) { t in
                    if t == .inbox && unreadCount > 0 {
                        Text("Inbox (\(unreadCount))").tag(t)
                    } else {
                        Text(t.rawValue).tag(t)
                    }
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 260)

            Spacer()

            SearchField("Search sender, body, id…", text: $search, minWidth: 140)
                .help("Matches the correspondents, their names, the id, and the body of any mail that has been decrypted")

            if unreadCount > 0 {
                Button("Mark all read") { markAllRead() }
                    .help("Clears the unread count without opening each mail")
            }

            Button {
                Task { await syncFromChain() }
            } label: {
                if syncing {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
            .disabled(syncing)
            .help("Pull mail sent to or from this FID")

            Button {
                composePreset = nil
                showCompose = true
            } label: {
                Label("Write", systemImage: "square.and.pencil")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!session.canSign)
            .help(session.canSign
                  ? "Write a new mail"
                  : "Watch-only identity — no key to sign or encrypt a mail with")
        }
    }

    @ViewBuilder
    private var banner: some View {
        if let err = syncError {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                CopyableText("Chain sync failed: \(err)", font: .caption)
                    .foregroundStyle(.orange)
            }
        } else if let txid = carveTxid {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.seal").foregroundStyle(.green)
                CopyableText(
                    display: "Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). It settles once a block confirms it.",
                    copy: txid,
                    font: .caption
                )
                .foregroundStyle(.green)
            }
        } else if let summary = syncSummary {
            CopyableText(summary, font: .caption).foregroundStyle(.secondary)
        }
    }

    // MARK: - list

    @ViewBuilder
    private var list: some View {
        if tabRows.isEmpty {
            emptyCard
        } else if visible.isEmpty {
            card {
                Label("No matches", systemImage: "magnifyingglass")
                    .foregroundStyle(.secondary)
                Text("Nothing in \(tab.rawValue) matches “\(search)”. Bodies are searchable once they have been decrypted; a mail sealed to a key you don't have here can only be found by its correspondent or id.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(visible) { mail in
                        row(mail)
                            .padding(.vertical, 10)
                            .padding(.horizontal, 16)
                        Divider()
                    }
                    if filtered.count > visible.count {
                        Button {
                            visibleLimit += 50
                            decryptVisible()
                        } label: {
                            Label(
                                "Load \(min(50, filtered.count - visible.count)) more of \(filtered.count)",
                                systemImage: "chevron.down"
                            )
                            .font(.callout)
                        }
                        .buttonStyle(.borderless)
                        .padding(12)
                    }
                }
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    private var emptyCard: some View {
        card {
            switch tab {
            case .inbox:
                Label("No mail", systemImage: "tray")
                    .foregroundStyle(.secondary)
                Text("Mail sent to this FID lands here. Each one is a transaction that pays you a small notice fee — which is why the sender, the recipient and the time are public, and only the body is encrypted.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .sent:
                Label("Nothing sent yet", systemImage: "paperplane")
                    .foregroundStyle(.secondary)
                Text("Mail you send is readable by you afterwards — it is encrypted to both keys, not just the recipient's.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .deleted:
                Label("Nothing deleted", systemImage: "trash")
                    .foregroundStyle(.secondary)
                Text("Deleted mail is kept here rather than thrown away, because a delete is a chain record you can undo.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder
    private func row(_ mail: Mail) -> some View {
        let me = session.liveFid
        let other = mail.counterparty(for: me) ?? "?"

        HStack(alignment: .top, spacing: 12) {
            ZStack(alignment: .topLeading) {
                FidAvatarView(fid: other, size: 40)
                if mail.unread == true {
                    Circle()
                        .fill(Color.accentColor)
                        .frame(width: 9, height: 9)
                        .offset(x: -3, y: -1)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(mail.counterpartyName(for: me).map(displayName) ?? "?")
                        .font(mail.unread == true ? .body.bold() : .body)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    if mail.lastHeight == MailsStore.unconfirmedHeight {
                        chip("Pending", color: .orange)
                    }
                    if mail.isDeleted {
                        chip("Deleted", color: .red)
                    }
                    if let fee = mail.noticeFee, fee > 0 {
                        chip(
                            "\(mail.isIncoming(for: me) ? "+" : "−")\(NoticeFee.coinString(satoshis: fee)) F",
                            color: mail.isIncoming(for: me) ? .green : .secondary
                        )
                    }

                    Spacer(minLength: 8)

                    if let t = mail.birthTime {
                        Text(Self.dateFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(t))))
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                preview(mail)
            }

            HStack(spacing: 4) {
                if !mail.isDeleted {
                    Button {
                        composePreset = replyPreset(to: mail)
                        showCompose = true
                    } label: {
                        Image(systemName: "arrowshape.turn.up.left")
                    }
                    .buttonStyle(.borderless)
                    .disabled(!session.canSign)
                    .help("Reply")
                }

                Button(role: mail.isDeleted ? nil : .destructive) {
                    pendingDelete = mail
                } label: {
                    Image(systemName: mail.isDeleted ? "arrow.uturn.backward" : "trash")
                }
                .buttonStyle(.borderless)
                .help(mail.isDeleted ? "Recover or remove" : "Delete")
            }
            .foregroundStyle(.secondary)
        }
        .contentShape(Rectangle())
        .onTapGesture { open(mail) }
    }

    @ViewBuilder
    private func preview(_ mail: Mail) -> some View {
        if let id = mail.id, let body = bodies[id] {
            Text(body)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        } else if mail.decrypted == false {
            HStack(spacing: 4) {
                Image(systemName: "lock.slash")
                Text(session.canSign
                     ? "Sealed to a key this identity doesn't hold"
                     : "Watch-only identity — no key to open this")
            }
            .font(.caption)
            .foregroundStyle(.tertiary)
        } else {
            Text(mail.id.map { "id \($0.elidingMiddle(head: 8, tail: 8))" } ?? "")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
    }

    private func displayName(_ raw: String) -> String {
        (try? FchAddress(fid: raw)) != nil ? raw.elidingMiddle(head: 8, tail: 8) : raw
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    private func card(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8, content: content)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    // MARK: - actions

    private func reload() {
        do {
            rows = try session.mails.all()
            loadError = nil
            decryptVisible()
        } catch {
            loadError = String(describing: error)
        }
    }

    /// Decrypt the bodies of the rows about to be drawn, once each.
    /// Sealed rows we already failed on are not retried — the key hasn't
    /// changed since a moment ago.
    private func decryptVisible() {
        guard session.canSign else { return }
        let needed = visible.compactMap(\.id).filter { bodies[$0] == nil }
        guard !needed.isEmpty, let priv = try? session.livePrikey() else { return }
        for mail in visible {
            guard let id = mail.id, bodies[id] == nil, mail.cipher != nil else { continue }
            var copy = mail
            if copy.parseDetail(privkey: priv), let text = copy.content {
                bodies[id] = text
            }
        }
    }

    private func open(_ mail: Mail) {
        readingMail = mail
        guard let id = mail.id, mail.unread == true else { return }
        _ = try? session.mails.markRead(id: id)
        // Reflect it immediately; `reload()` on sheet close re-reads.
        if let index = rows.firstIndex(where: { $0.id == id }) {
            rows[index].unread = false
        }
    }

    private func markAllRead() {
        do {
            _ = try session.mails.markAllRead()
            reload()
        } catch {
            loadError = String(describing: error)
        }
    }

    /// Android's `MailActivity.makeReplyHead`: `Re: <first 48 chars>` +
    /// the id of the mail being answered, then a rule. Kept identical so
    /// a reply written here reads the same in the Android client — mail
    /// has no threading, and this quoted head is all a reader gets.
    /// It costs bytes from a tight budget, which the compose counter
    /// shows immediately.
    private func replyPreset(to mail: Mail) -> MailComposeSheet.Preset {
        var head = ""
        if let body = mail.id.flatMap({ bodies[$0] }) {
            let brief = body.count > 48 ? String(body.prefix(48)) + "..." : body
            head = "Re: \(brief)\nID:\(mail.id ?? "")\n----\n"
        }
        return MailComposeSheet.Preset(
            recipient: mail.counterparty(for: session.liveFid) ?? "",
            body: head,
            replyingTo: mail
        )
    }

    private func syncFromChain() async {
        guard !syncing else { return }
        syncing = true
        syncError = nil
        defer { syncing = false }
        do {
            let priv = try? session.livePrikey()
            let result = try await session.mailService.syncOnChainMails(
                fid: session.liveFid,
                privkey: priv,
                into: session.mails,
                contacts: session.contacts
            )
            carveTxid = nil
            if result.total == 0 {
                syncSummary = "No new mail on-chain."
            } else {
                var parts = ["\(result.merged) mail\(result.merged == 1 ? "" : "s") synced"]
                if result.newUnread > 0 { parts.append("\(result.newUnread) new") }
                if result.deleted > 0 { parts.append("\(result.deleted) deleted") }
                if result.undecryptable > 0 {
                    parts.append("\(result.undecryptable) could not be decrypted")
                    parts.append(contentsOf: result.failureReasons)
                }
                syncSummary = parts.joined(separator: " · ")
            }
            reload()
        } catch {
            syncError = String(describing: error)
        }
    }

    /// Carve a delete (or recover) and flip the local row immediately so
    /// the mail moves tabs now rather than at the next sync. The chain
    /// confirms it afterwards; if the carve never lands, the next sync
    /// puts the row back where it belongs.
    private func setDeleted(_ mail: Mail, deleted: Bool) async {
        guard let id = mail.id, session.canSign, !carving else { return }
        carving = true
        syncError = nil
        carveTxid = nil
        defer { carving = false }
        do {
            carveTxid = try await session.carveMailDeleteOnChain(
                mailIds: [id], recover: !deleted
            )
            var updated = mail
            updated.active = !deleted
            if deleted { updated.unread = false }
            try session.mails.upsert(updated)
            reload()
        } catch {
            syncError = String(describing: error)
        }
    }

    private func removeLocally(_ mail: Mail) {
        guard let id = mail.id else { return }
        do {
            _ = try session.mails.remove(id: id)
            bodies[id] = nil
            reload()
        } catch {
            loadError = String(describing: error)
        }
    }
}
