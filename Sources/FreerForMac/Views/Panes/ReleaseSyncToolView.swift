import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// The Release Sync pane, under Tools in the sidebar.
struct ReleaseSyncPaneView: View {
    let session: ActiveSession

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            ScrollView {
                ReleaseSyncToolView(session: session)
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(NSColor.controlBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 480)
    }
}

/// Release Sync: after a GitHub release, publish or update the protocols,
/// codes and apps that changed, signed by this identity. See
/// RELEASE_SYNC_SPEC.md.
///
/// Scan → review → carve. Nothing is spent before the user presses Carve
/// and confirms the count.
struct ReleaseSyncToolView: View {
    let session: ActiveSession

    struct RepoRow: Identifiable {
        var id: String { path }
        let path: String
        var manifest: ReleaseManifest?
        var manifestError: String?
        var releases: [GitHubReleases.Release] = []
        var tag: String?
        var releaseError: String?
    }

    @State private var repos: [RepoRow] = []
    @State private var busy: String?
    @State private var plan: ReleasePlan?
    @State private var scans: [RepoScan] = []
    @State private var chain: ReleaseChainState?
    @State private var choices: [String: String] = [:]
    @State private var selected: Set<String> = []
    @State private var error: String?
    @State private var events: [ReleaseRunEvent] = []
    @State private var confirming = false
    @State private var runTask: Task<Void, Never>?
    @StateObject private var reviews = ReleaseReviewCoordinator()
    @AppStorage("releaseSync.reviewEach") private var reviewEach = true

    private static let reposKey = "releaseSync.repos"
    private var signer: String { session.liveFid }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Release Sync").font(.headline)
            Text("Publishes or updates the protocols, codes and apps of your repos on chain, signed by \(signer.elidingMiddle(head: 8, tail: 6)). Each repo needs a \(ReleaseManifest.fileName) at its root.")
                .font(.callout).foregroundStyle(.secondary)
            if !session.canSign {
                CopyableLabel("This identity is watch-only, so it can scan but not carve.", systemImage: "eye")
                    .foregroundStyle(.orange).font(.callout)
            }

            reposSection

            HStack {
                Button(plan == nil ? "Scan" : "Scan again") { Task { await scan() } }
                    .disabled(busy != nil || repos.isEmpty || runTask != nil)
                if let busy {
                    ProgressView().controlSize(.small)
                    Text(busy).font(.caption).foregroundStyle(.secondary)
                }
            }
            if let error {
                CopyableLabel(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.callout)
            }
            if let plan { planSection(plan) }
            if !events.isEmpty { runLog }
        }
        .onAppear(perform: loadRepos)
        // One sheet for the whole reviewed run: a review page, or what the
        // carve just approved is doing. The approval dialog is its own
        // window, so it opens on top.
        .sheet(isPresented: $reviews.isOpen) {
            Group {
                if let pending = reviews.pending {
                    reviewSheet(pending.draft)
                } else {
                    ReleaseRunWorkingView(title: reviews.working.title,
                                          step: reviews.stopRequested ? "Stopping after this carve…" : reviews.working.step,
                                          status: reviews.done == 0 ? nil : reviews.status,
                                          stop: stopAfterCurrent)
                }
            }
            .interactiveDismissDisabled()
        }
        .alert("Carve \(selected.count) \(selected.count == 1 ? "record" : "records")?", isPresented: $confirming) {
            Button("Carve", role: .destructive) { startRun() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Each is a transaction signed by \(signer) and paid in miner fees. With “Confirm before signing” on, each one is shown for approval before it is signed and broadcast; declining one skips it. Documents and code archives are carved onto DISK permanently, and archives are uploaded to their GitHub releases.")
        }
    }

    // MARK: - repos

    private var reposSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Repos").font(.subheadline.bold())
                Spacer()
                Button("Add Folder…", action: addRepo).disabled(runTask != nil)
            }
            if repos.isEmpty {
                Text("Add the folders of your local clones: Freeverse, FreerForMac, Freer, FreeverseExplorer.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach($repos) { $repo in
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(URL(fileURLWithPath: repo.path).lastPathComponent).bold()
                        if let m = repo.manifest {
                            Text("\(m.github) · \(m.codes?.count ?? 0) codes · \(m.apps?.count ?? 0) apps · protocols in \((m.protocolDirs ?? []).joined(separator: ", ").ifEmpty("—"))")
                                .font(.caption).foregroundStyle(.secondary)
                        } else if let e = repo.manifestError {
                            Text(e).font(.caption).foregroundStyle(.orange)
                        }
                        if let e = repo.releaseError {
                            Text(e).font(.caption).foregroundStyle(.orange)
                        }
                    }
                    Spacer()
                    if !repo.releases.isEmpty {
                        Picker("Release", selection: $repo.tag) {
                            ForEach(repo.releases, id: \.tagName) { r in
                                Text(r.tagName + (r.isPrerelease ? " (pre)" : "")).tag(Optional(r.tagName))
                            }
                        }
                        .labelsHidden().frame(maxWidth: 220)
                    }
                    Button {
                        repos.removeAll { $0.path == repo.path }
                        saveRepos()
                    } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless).disabled(runTask != nil)
                }
            }
        }
    }

    private func addRepo() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Add"
        guard panel.runModal() == .OK else { return }
        for url in panel.urls where !repos.contains(where: { $0.path == url.path }) {
            repos.append(RepoRow(path: url.path))
        }
        saveRepos()
        refreshRepos()
    }

    private func loadRepos() {
        guard repos.isEmpty else { return }
        let paths = UserDefaults.standard.stringArray(forKey: Self.reposKey) ?? []
        repos = paths.map { RepoRow(path: $0) }
        refreshRepos()
    }

    private func saveRepos() {
        UserDefaults.standard.set(repos.map(\.path), forKey: Self.reposKey)
    }

    /// Reads each manifest and lists its GitHub releases (via `gh`).
    private func refreshRepos() {
        for row in repos where row.manifest == nil && row.manifestError == nil {
            let path = row.path
            Task {
                let result: (ReleaseManifest?, String?, [GitHubReleases.Release], String?) = await Task.detached {
                    do {
                        let m = try ReleaseManifest.load(repo: URL(fileURLWithPath: path))
                        guard !(m.codes ?? []).isEmpty || !(m.apps ?? []).isEmpty else { return (m, nil, [], nil) }
                        do {
                            return (m, nil, try GitHubReleases(repo: m.github).releases(), nil)
                        } catch {
                            return (m, nil, [], "Cannot list releases: \(error)")
                        }
                    } catch {
                        return (nil, String(describing: error), [], nil)
                    }
                }.value
                guard let i = repos.firstIndex(where: { $0.path == path }) else { return }
                repos[i].manifest = result.0
                repos[i].manifestError = result.1
                repos[i].releases = result.2
                repos[i].releaseError = result.3
                repos[i].tag = ReleaseScanner.defaultTag(result.2)
            }
        }
    }

    // MARK: - scan

    private var workDir: URL { session.dataDirectory.appendingPathComponent("release-sync/work") }
    private var logURL: URL { session.dataDirectory.appendingPathComponent("release-sync/\(signer).json") }

    private func scan() async {
        error = nil
        events = []
        busy = "Reading \(signer.elidingMiddle(head: 6, tail: 4))'s registry…"
        defer { busy = nil }
        do {
            let fetched = try await ReleaseChainState.fetch(owner: signer, fapi: session.fapi)
            let scanner = ReleaseScanner(workDir: workDir)
            var out: [RepoScan] = []
            for row in repos where row.manifest != nil {
                busy = "Scanning \(URL(fileURLWithPath: row.path).lastPathComponent)…"
                let root = URL(fileURLWithPath: row.path), tag = row.tag
                out.append(try await Task.detached { try await scanner.scan(root: root, tag: tag) }.value)
            }
            scans = out
            chain = fetched
            replan()
        } catch {
            self.error = "Scan failed: \(error)"
        }
    }

    private func replan() {
        guard let chain else { return }
        let p = ReleasePlanner.plan(scans: scans, chain: chain, owner: signer, choices: choices,
                                    log: ReleaseRunLog.load(logURL))
        plan = p
        selected = Set(carvable(p).filter { carveJson($0.key, in: p).error == nil }.map(\.key))
    }

    // MARK: - plan

    struct Row: Identifiable {
        var id: String { key }
        let key: String
        let kind: String
        let title: String
        let detail: String
        let action: ReleaseAction
    }

    private func rows(_ plan: ReleasePlan) -> [Row] {
        plan.protocols.map { Row(key: ReleasePlanner.choiceKey(protocol: $0.doc.ref), kind: "Protocol",
                                 title: "\($0.doc.ref)V\($0.doc.ver) \($0.doc.name)", detail: $0.doc.relativePath, action: $0.action) }
        + plan.codes.map { Row(key: ReleasePlanner.choiceKey(code: $0.local.entry.name), kind: "Code",
                               title: "\($0.local.entry.name) \($0.local.tag)",
                               detail: "\($0.local.fileCount) files, \(ByteCountFormatter.string(fromByteCount: Int64($0.local.byteCount), countStyle: .file))",
                               action: $0.action) }
        + plan.apps.map { Row(key: ReleasePlanner.choiceKey(app: $0.local.entry.stdName), kind: "App",
                              title: "\($0.local.entry.stdName) \($0.local.tag)", detail: $0.local.asset.name, action: $0.action) }
    }

    private func carvable(_ plan: ReleasePlan) -> [Row] { rows(plan).filter { $0.action.carves } }

    /// The carve's JSON as it would go out (ids from this run shown as
    /// placeholders), or why it cannot.
    private func carveJson(_ key: String, in plan: ReleasePlan) -> (json: String?, error: String?) {
        do {
            if let item = plan.protocols.first(where: { ReleasePlanner.choiceKey(protocol: $0.doc.ref) == key }) {
                return (try ReleaseCarves.protocolCarve(item).json(), nil)
            }
            if let item = plan.codes.first(where: { ReleasePlanner.choiceKey(code: $0.local.entry.name) == key }) {
                return (try ReleaseCarves.codeCarve(item, ids: nil).json(), nil)
            }
            if let item = plan.apps.first(where: { ReleasePlanner.choiceKey(app: $0.local.entry.stdName) == key }) {
                return (try ReleaseCarves.appCarve(item, ids: nil).json(), nil)
            }
        } catch {
            return (nil, String(describing: error))
        }
        return (nil, nil)
    }

    @ViewBuilder
    private func planSection(_ plan: ReleasePlan) -> some View {
        let all = rows(plan)
        let todo = all.filter { $0.action.carves }
        let attention = all.filter {
            switch $0.action {
            case .blocked, .ambiguous, .invalid: return true
            default: return false
            }
        }
        let unchanged = all.filter { if case .unchanged = $0.action { return true }; return false }
        let pendingRows = all.filter { if case .pending = $0.action { return true }; return false }

        Divider()
        // The buttons keep their full labels; when the pane is narrow it
        // is the summary that wraps.
        HStack {
            Text("\(todo.count) to carve · \(pendingRows.count) pending · \(attention.count) need attention · \(unchanged.count) unchanged")
                .font(.subheadline.bold())
                .layoutPriority(-1)
            Spacer()
            Group {
                Button("Select All") { selected = Set(todo.filter { carveJson($0.key, in: plan).error == nil }.map(\.key)) }
                    .disabled(runTask != nil)
                Button("Select None") { selected = [] }.disabled(runTask != nil)
                if runTask != nil {
                    Button("Stop", action: stopRun)
                } else {
                    Button {
                        confirming = true
                    } label: {
                        Text("Carve \(selected.count) \(selected.count == 1 ? "record" : "records")").frame(minWidth: 90)
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(selected.isEmpty || !session.canSign)
                }
            }
            .fixedSize()
        }

        Toggle("Review each record before carving", isOn: $reviewEach)
            .disabled(runTask != nil)
            .help("Open the Publish or Update page for each record, with the fields that come from the repo locked. Edits to codes and apps are written back to freeverse-release.json.")

        ForEach(todo) { row in carveRow(row, plan) }

        if !pendingRows.isEmpty {
            Text("Pending").font(.subheadline.bold()).padding(.top, 6)
            Text("Carved, not on chain yet. Scan again after the next block.")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(pendingRows) { row in pendingRow(row) }
        }
        if !attention.isEmpty {
            Text("Needs attention").font(.subheadline.bold()).padding(.top, 6)
            ForEach(attention) { row in attentionRow(row) }
        }
        if !plan.problems.isEmpty {
            DisclosureGroup("\(plan.problems.count) skipped files and warnings") {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(plan.problems, id: \.self) { Text($0).font(.caption).textSelection(.enabled) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        let orphans = plan.orphanProtocols.map { "Protocol \($0.type ?? "")\($0.sn ?? "") \($0.name ?? "") · \($0.id.prefix(12))…" }
            + plan.orphanCodes.map { "Code \($0.name ?? "") · \($0.id.prefix(12))…" }
            + plan.orphanApps.map { "App \($0.stdName ?? "") · \($0.id.prefix(12))…" }
        if !orphans.isEmpty {
            DisclosureGroup("\(orphans.count) on chain but not in these repos (left alone)") {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(orphans, id: \.self) { Text($0).font(.caption).textSelection(.enabled) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        if !unchanged.isEmpty {
            DisclosureGroup("\(unchanged.count) unchanged") {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(unchanged) { Text("\($0.kind) \($0.title)").font(.caption) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func carveRow(_ row: Row, _ plan: ReleasePlan) -> some View {
        let built = carveJson(row.key, in: plan)
        let isOn = Binding(
            get: { selected.contains(row.key) },
            set: { if $0 { selected.insert(row.key) } else { selected.remove(row.key) } })
        return VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Toggle("", isOn: isOn).labelsHidden().disabled(built.error != nil || runTask != nil)
                badge(row.action)
                Text("\(row.kind) · \(row.title)").bold()
                Text(row.detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Spacer()
                status(for: row.key)
            }
            if let e = built.error {
                Text(e).font(.caption).foregroundStyle(.red).textSelection(.enabled)
            } else if let json = built.json {
                DisclosureGroup("OP_RETURN, \(json.utf8.count) bytes") {
                    Text(json).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }.font(.caption)
            }
        }
        .padding(8)
        .background(Color(NSColor.textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private func attentionRow(_ row: Row) -> some View {
        HStack(alignment: .firstTextBaseline) {
            badge(row.action)
            Text("\(row.kind) · \(row.title)").bold()
            switch row.action {
            case .blocked(let id, let reason):
                Text("\(reason) (\(id.prefix(12))…)").font(.caption).foregroundStyle(.secondary)
            case .invalid(let why):
                Text(why).font(.caption).foregroundStyle(.secondary)
            case .ambiguous(let ids):
                Text("\(ids.count) records on chain; pick the one to update:").font(.caption)
                Picker("", selection: Binding(
                    get: { choices[row.key] },
                    set: { choices[row.key] = $0; replan() })) {
                    Text("—").tag(Optional<String>.none)
                    ForEach(ids, id: \.self) { Text($0.prefix(16) + "…").tag(Optional($0)) }
                }.labelsHidden().frame(maxWidth: 200)
            default:
                EmptyView()
            }
            Spacer()
        }
        .font(.callout)
    }

    private func pendingRow(_ row: Row) -> some View {
        HStack(alignment: .firstTextBaseline) {
            badge(row.action)
            Text("\(row.kind) · \(row.title)").bold()
            if case .pending(_, let txid, let since, let stale) = row.action {
                CopyableText(display: String(txid.prefix(12)) + "…", copy: txid,
                             font: .system(.caption, design: .monospaced))
                Text(since, style: .relative).font(.caption).foregroundStyle(.secondary)
                Text("ago").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if stale {
                    Text("Possibly dropped").font(.caption).foregroundStyle(.orange)
                    Button("Carve Again") {
                        try? ReleaseRunLog.forget(row.key, at: logURL)
                        replan()
                    }
                    .fixedSize()
                    .disabled(runTask != nil)
                    .help("Forget this carve so it can be carved again. Check the txid first: if it did confirm, carving again makes a duplicate.")
                }
            } else {
                Spacer()
            }
        }
        .font(.callout)
    }

    private func badge(_ action: ReleaseAction) -> some View {
        let (text, color): (String, Color) = {
            switch action {
            case .publish: return ("publish", .green)
            case .update: return ("update", .blue)
            case .unchanged: return ("same", .secondary)
            case .blocked: return ("blocked", .orange)
            case .ambiguous: return ("choose", .orange)
            case .invalid: return ("invalid", .red)
            case .pending(_, _, _, let stale): return ("pending", stale ? .orange : .purple)
            }
        }()
        return Text(text).font(.caption.bold()).foregroundStyle(color)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .overlay(RoundedRectangle(cornerRadius: 4).stroke(color.opacity(0.6)))
    }

    @ViewBuilder
    private func status(for key: String) -> some View {
        if let last = events.last(where: { $0.key == key }) {
            switch last {
            case .carved(_, let txid):
                CopyableText(display: String(txid.prefix(12)) + "…", copy: txid, font: .system(.caption, design: .monospaced))
                    .foregroundStyle(.green)
            case .failed(_, let why):
                Text(why).font(.caption).foregroundStyle(.red).lineLimit(2).help(why)
            case .skipped(_, let why):
                Text(why).font(.caption).foregroundStyle(.secondary)
            case .step(_, let what):
                Text(what + "…").font(.caption).foregroundStyle(.secondary)
            default:
                EmptyView()
            }
        }
    }

    // MARK: - run

    private func startRun() {
        guard let plan else { return }
        let keys = selected
        events = []
        runTask = Task { @MainActor in
            defer { runTask = nil }
            var runner = ReleaseRunner(backend: SessionReleaseBackend(session: session), logURL: logURL)
            let reviewing = reviewEach
            if reviewing {
                runner.reviewer = CoordinatorReviewer(coordinator: reviews)
                let titles = Dictionary(uniqueKeysWithValues: rows(plan).map { ($0.key, "\($0.kind) \($0.title)") })
                reviews.begin(titles: titles, total: keys.count)
            }
            defer { if reviewing { reviews.finish() } }
            do {
                // Each carve goes through the wallet's usual approval: the
                // transaction dialog when "confirm before signing" is on.
                try await runner.run(plan, selected: keys) { event in
                    Task { @MainActor in
                        events.append(event)
                        reviews.note(event)
                    }
                }
            } catch is CancellationError {
                events.append(.failed(key: "", "stopped"))
            } catch {
                self.error = "Run stopped: \(error)"
            }
            // What went out is pending now; the chain state is the
            // scan's, so this needs no new fetch.
            replan()
            let manifests = Set(events.compactMap { if case .manifestUpdated(let f) = $0 { return f }; return nil })
            let written = events.compactMap { if case .pidWritten(let f) = $0 { return f }; return nil }
            var notes: [String] = []
            if !written.isEmpty {
                notes.append("PIDs were written into \(written.count) documents. Commit them: \(written.joined(separator: ", "))")
            }
            if !manifests.isEmpty {
                notes.append("Review edits were written into \(manifests.sorted().joined(separator: ", ")). Commit them too.")
            }
            if !notes.isEmpty { self.error = notes.joined(separator: "\n") }
        }
    }

    // MARK: - review

    private func stopRun() {
        runTask?.cancel()
        reviews.answer(.failure(CancellationError()))
    }

    /// Stop from the working state. A carve may be mid-broadcast, and
    /// cancelling it would leave it unknown whether it went out, so the run
    /// stops at the next review instead. Waiting for a block has nothing in
    /// flight, so that stops at once.
    private func stopAfterCurrent() {
        if reviews.isWaitingForBlock {
            stopRun()
        } else {
            reviews.stopRequested = true
        }
    }

    @ViewBuilder
    private func reviewSheet(_ draft: ReleaseDraft) -> some View {
        switch draft {
        case .protocol(let c):
            let spec = ProtocolSpec(id: c.targetId ?? "release-review", type: c.type, sn: c.sn, ver: c.ver, did: c.did,
                                    name: c.name, lang: c.lang, desc: c.desc, prePid: c.preDid, home: c.home,
                                    owner: signer, waiters: c.waiters)
            PublishProtocolSheet(
                session: session, target: c.targetId == nil ? .draft(spec) : .update(spec),
                review: ReleaseReview(original: c, status: reviews.status) { decision in
                    switch decision {
                    case .carve(let edited): reviews.answer(.success(.protocol(edited)))
                    case .skip: reviews.answer(.success(nil))
                    case .stop: reviews.answer(.failure(CancellationError()))
                    }
                }
            ) { _ in }
        case .code(let c):
            let code = Code(id: c.targetId ?? "release-review", name: c.name, ver: c.ver, did: c.did, desc: c.desc,
                            langs: c.langs, home: c.home, protocols: c.protocols, waiters: c.waiters, owner: signer)
            PublishCodeSheet(
                session: session, target: c.targetId == nil ? .draft(code) : .update(code),
                review: ReleaseReview(original: c, status: reviews.status) { decision in
                    switch decision {
                    case .carve(let edited): reviews.answer(.success(.code(edited)))
                    case .skip: reviews.answer(.success(nil))
                    case .stop: reviews.answer(.failure(CancellationError()))
                    }
                }
            ) { _ in }
        case .app(let c):
            let app = AppRecord(id: c.targetId ?? "release-review", stdName: c.stdName, localNames: c.localNames,
                                types: c.types, desc: c.desc, ver: c.ver, home: c.home, downloads: c.downloads,
                                waiters: c.waiters, protocols: c.protocols, codes: c.codes, services: c.services,
                                owner: signer)
            PublishAppSheet(
                session: session, target: c.targetId == nil ? .draft(app) : .update(app),
                review: ReleaseReview(original: c, status: reviews.status) { decision in
                    switch decision {
                    case .carve(let edited): reviews.answer(.success(.app(edited)))
                    case .skip: reviews.answer(.success(nil))
                    case .stop: reviews.answer(.failure(CancellationError()))
                    }
                }
            ) { _ in }
        }
    }

    private var runLog: some View {
        DisclosureGroup("Run log (\(events.count))") {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(Array(events.enumerated()), id: \.offset) { _, e in
                    Text(e.line).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private extension ReleaseRunEvent {
    var key: String? {
        switch self {
        case .step(let k, _), .carved(let k, _), .skipped(let k, _), .failed(let k, _): return k
        default: return nil
        }
    }

    var line: String {
        switch self {
        case .step(let k, let s): return "\(k): \(s)"
        case .carved(let k, let t): return "\(k): carved \(t)"
        case .skipped(let k, let s): return "\(k): skipped, \(s)"
        case .failed(let k, let s): return "\(k): FAILED \(s)"
        case .waiting(let n): return "waiting for a block: \(n) carves unconfirmed"
        case .pidWritten(let f): return "wrote PID into \(f)"
        case .manifestUpdated(let f): return "wrote review edits into \(f)"
        }
    }
}

private extension String {
    func ifEmpty(_ fallback: String) -> String { isEmpty ? fallback : self }
}


/// Hands each carve of a run to the Release Sync pane, which shows it in
/// its Publish/Update sheet, waits for the user's answer, and in between
/// shows what the approved carve is doing.
@MainActor
final class ReleaseReviewCoordinator: ObservableObject {
    struct Pending: Identifiable {
        let id = UUID()
        let draft: ReleaseDraft
        let resume: (Result<ReleaseDraft?, Error>) -> Void
    }

    struct Working {
        var title: String
        var step: String
    }

    @Published var isOpen = false
    @Published var pending: Pending?
    @Published var working = Working(title: "Starting", step: "Preparing the first record…")
    @Published private(set) var done = 0
    @Published private(set) var previous: ReleaseRunStatus.Outcome?
    @Published var stopRequested = false
    @Published private(set) var isWaitingForBlock = false
    private var total = 0
    private var titles: [String: String] = [:]

    var status: ReleaseRunStatus {
        ReleaseRunStatus(position: "Record \(min(done + 1, max(total, 1))) of \(total)", previous: previous)
    }

    func begin(titles: [String: String], total: Int) {
        self.titles = titles
        self.total = total
        done = 0
        previous = nil
        stopRequested = false
        isWaitingForBlock = false
        working = Working(title: "Starting", step: "Preparing the first record…")
        isOpen = true
    }

    func finish() {
        if let open = pending {
            pending = nil
            open.resume(.failure(CancellationError()))
        }
        isOpen = false
    }

    func ask(_ draft: ReleaseDraft) async throws -> ReleaseDraft? {
        if stopRequested { throw CancellationError() }
        return try await withCheckedThrowingContinuation { continuation in
            pending = Pending(draft: draft) { continuation.resume(with: $0) }
        }
    }

    /// Answers the open review, if any. Answering twice is harmless.
    func answer(_ result: Result<ReleaseDraft?, Error>) {
        guard let open = pending else { return }
        // Show the working state before the sheet would otherwise sit on
        // a page whose button has already been pressed.
        if case .success(let draft?) = result {
            working = Working(title: titles[Self.key(of: draft)] ?? "Carving", step: "Preparing…")
        } else {
            working = Working(title: "Next record", step: "Preparing…")
        }
        pending = nil
        open.resume(result)
    }

    func note(_ event: ReleaseRunEvent) {
        if case .waiting = event { isWaitingForBlock = true } else { isWaitingForBlock = false }
        switch event {
        case .step(let key, let what):
            working = Working(title: titles[key] ?? key, step: Self.describe(what))
        case .carved(let key, let txid):
            done += 1
            previous = .carved(title: titles[key] ?? key, txid: txid)
            working = Working(title: "Next record", step: "Preparing…")
        case .skipped(let key, _):
            guard titles[key] != nil else { return }
            done += 1
            previous = .skipped(title: titles[key]!)
        case .failed(let key, let why):
            guard titles[key] != nil else { return }
            done += 1
            previous = .failed(title: titles[key]!, reason: why)
        case .waiting(let n):
            working = Working(title: "Waiting for a block",
                              step: "\(n) carves are unconfirmed. The run goes on when some confirm; it checks every 30 seconds.")
        case .pidWritten, .manifestUpdated:
            break
        }
    }

    static func describe(_ step: String) -> String {
        if step == "carving" {
            return "Signing and broadcasting. Approve the transaction if the dialog asks."
        }
        return step.prefix(1).uppercased() + step.dropFirst() + "…"
    }

    static func key(of draft: ReleaseDraft) -> String {
        switch draft {
        case .protocol(let c): return ReleasePlanner.choiceKey(protocol: ProtocolRef(type: c.type, sn: c.sn))
        case .code(let c): return ReleasePlanner.choiceKey(code: c.name)
        case .app(let c): return ReleasePlanner.choiceKey(app: c.stdName)
        }
    }
}

struct CoordinatorReviewer: ReleaseReviewer {
    let coordinator: ReleaseReviewCoordinator

    func review(_ draft: ReleaseDraft) async throws -> ReleaseDraft? {
        try await coordinator.ask(draft)
    }
}
