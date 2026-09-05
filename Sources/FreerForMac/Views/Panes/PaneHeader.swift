import SwiftUI
import FCDomain
import FCUI

/// The FID bar — the strip at the top of every detail pane, and the Mac
/// answer to Android's `layout_fid_card` on the home screen.
///
/// Android can afford a tall card because its home screen is one screen
/// among many. Here the same information has to ride along above twenty-
/// odd panes, so the card's two stacked rows become two *columns*: who
/// you are on the left, what you're worth on the right. That keeps the
/// bar the same height it was when it only showed a name and an FID.
///
/// **Everything here is one FAPI call.** Balance, cash count, CD, weight,
/// reputation, hot, the CID and the nobody flag all arrive together in
/// `base.freerByIds`, cached per-FID by ``AppState/liveFidInfo``. The bar
/// itself never fetches — if it did, every pane switch would hit the
/// network — it only renders what the cache holds and offers a refresh.
///
/// Metrics hide individually when they are null or zero, exactly as
/// Android's `HomeActivity` does, so a brand-new FID shows a clean bar
/// rather than a row of dashes.
struct PaneHeader: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession

    @State private var showQr = false
    @State private var showDetails = false
    @State private var showAvatar = false
    @State private var editingLabel = false
    @State private var labelDraft = ""
    @State private var labelError: String?

    private var info: LiveFidInfo? { appState.liveFidInfo }

    /// The live identity's local label. Reads `identityRevision` first
    /// so an edit made in this bar's own popover redraws it — the label
    /// lives in the encrypted `Setting`, which SwiftUI cannot observe.
    private var liveLabel: String {
        _ = appState.identityRevision
        return session.liveKeyInfo.label
    }

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            // The avatar is the only picture this app has of an
            // identity, and at 56 points it is a thumbnail. Clicking it
            // opens the real thing, big enough to look at and to copy
            // or save as a file.
            Button { showAvatar = true } label: {
                FidAvatarView(
                    fid: session.liveFid,
                    size: 56,
                    isNobody: info?.isNobody == true
                )
            }
            .buttonStyle(.plain)
            .help("Show this avatar full size — copy or save the image")

            VStack(alignment: .leading, spacing: 3) {
                nameLine
                labelLine
            }

            Spacer(minLength: 12)

            valueRail
        }
        .sheet(isPresented: $showQr) {
            QrDisplaySheet(
                title: info?.hasCid == true ? (info?.displayName ?? "My FID") : "My FID",
                content: session.liveFid
            ) { showQr = false }
        }
        .sheet(isPresented: $showDetails) {
            FidDetailSheet(session: session) { showDetails = false }
        }
        .sheet(isPresented: $showAvatar) {
            FidAvatarSheet(
                fid: session.liveFid,
                title: info?.hasCid == true ? info?.displayName : nonEmptyLabel,
                isNobody: info?.isNobody == true
            ) { showAvatar = false }
        }
    }

    /// The local label, or nil when it is unset — the avatar sheet
    /// wants a name to print or none at all, not an empty line.
    private var nonEmptyLabel: String? {
        let label = liveLabel
        return label.isEmpty ? nil : label
    }

    // MARK: - identity column

    private var nameLine: some View {
        HStack(spacing: 8) {
            // With a CID registered, the CID is the name and the FID
            // rides beside it. Without one the FID *is* the name, and
            // printing it twice would just be noise.
            if let info, info.hasCid {
                Text(info.displayName)
                    .font(.title2).bold()
                    .lineLimit(1)
                    .truncationMode(.middle)
                CopyableText.elidingMiddle(
                    session.liveFid, head: 6, tail: 6,
                    font: .system(.caption, design: .monospaced),
                    color: .secondary
                )
            } else {
                CopyableText.elidingMiddle(
                    session.liveFid, head: 10, tail: 8,
                    font: .system(.title3, design: .monospaced)
                )
            }

            Button { showQr = true } label: {
                Image(systemName: "qrcode")
            }
            .buttonStyle(.borderless)
            .help("Show this FID as a QR code for someone to scan")

            // The bar shows what fits above every pane; this opens what
            // does not — the whole FID, the pubkey, and the rest of the
            // on-chain record. Its own button because a click on the FID
            // itself already means "copy".
            Button { showDetails = true } label: {
                Image(systemName: "info.circle")
            }
            .buttonStyle(.borderless)
            .help("Show everything known about this identity")

            Image(systemName: identity.symbol)
                .foregroundStyle(identity.tint)
                .help(identity.help)

            if let err = appState.liveFidInfoError {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .help("Couldn't refresh on-chain stats — \(err)")
            }
        }
    }

    private var labelLine: some View {
        HStack(spacing: 12) {
            labelControl
            if let info, info.hasMetrics {
                metric("scalemass", info.weight, help:
                    "Weight — this FID's share of the chain's total coin-days.")
                metric("hand.thumbsup", info.reputation, help:
                    "Reputation — the CDD-weighted score others have carved about this FID.")
                metric("flame", info.hot, help:
                    "Hot — how much recent activity surrounds this FID.")
            }
        }
    }

    @ViewBuilder
    private var labelControl: some View {
        let label = liveLabel
        Button {
            labelDraft = label
            labelError = nil
            editingLabel = true
        } label: {
            if label.isEmpty {
                Label("Add label", systemImage: "tag")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                HStack(spacing: 4) {
                    Image(systemName: "tag.fill")
                    Text(label).lineLimit(1).truncationMode(.tail)
                }
                .font(.caption.bold())
                .foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.plain)
        .help(label.isEmpty
              ? "Give this identity a private name — stored locally, never carved on-chain."
              : "Rename this identity. The label is local to this vault.")
        .popover(isPresented: $editingLabel, arrowEdge: .bottom) {
            labelEditor
        }
    }

    private var labelEditor: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Label for this identity")
                .font(.headline)
            Text("Private to this vault — it is never carved on-chain and nobody else sees it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("e.g. daily spending", text: $labelDraft)
                .textFieldStyle(.roundedBorder)
                .frame(width: 260)
                .onSubmit { commitLabel() }
            if let labelError {
                Text(labelError)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { editingLabel = false }
                Button("Save") { commitLabel() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
    }

    @ViewBuilder
    private func metric(_ symbol: String, _ value: Int64?, help: String) -> some View {
        if let value, value != 0 {
            HStack(spacing: 3) {
                Image(systemName: symbol).font(.caption2)
                Text(Self.compact(value)).font(.caption.monospacedDigit())
            }
            .foregroundStyle(.secondary)
            .help(help)
        }
    }

    /// Which key situation the live FID is in. Replaces the old text
    /// caption with a single icon — that is what buys the second line
    /// for the label and metrics without making the bar taller.
    private var identity: (symbol: String, tint: Color, help: String) {
        let kind = session.liveKeyInfo.kind
        if session.canSign {
            return ("key.fill", .blue, "\(kind.rawValue) — this vault holds the private key and can sign.")
        }
        switch kind {
        case .multisig:
            return ("person.2.fill", .purple,
                    "Multisig — spending needs the other signers too.")
        case .watched:
            return ("eye", .orange,
                    "Watch-only — no private key here. Transactions can be built but must be signed elsewhere.")
        default:
            return ("key.slash", .orange,
                    "No private key for this identity — watch only.")
        }
    }

    // MARK: - value column

    private var valueRail: some View {
        HStack(spacing: 18) {
            value(
                Self.formatBalance(info?.balance),
                unit: "F",
                help: "Balance — spendable FCH for this FID. Click for the cash behind it."
            )
            value(
                info?.cash.map { Self.compact($0) },
                unit: "C",
                help: "Cash — how many separate UTXOs make up that balance."
            )
            value(
                info?.cd.map { Self.compact($0) },
                unit: nil,
                symbol: "bolt.fill",
                help: "CD — coin-days accumulated, the fuel most on-chain operations are priced in."
            )

            Button {
                Task { await appState.refreshLiveFidInfo() }
            } label: {
                if appState.liveFidInfoLoading {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "arrow.clockwise")
                }
            }
            .buttonStyle(.borderless)
            .disabled(appState.liveFidInfoLoading)
            .help(refreshHelp)
        }
    }

    @ViewBuilder
    private func value(
        _ text: String?,
        unit: String?,
        symbol: String? = nil,
        help: String
    ) -> some View {
        Button {
            appState.selectedPane = .cash
        } label: {
            HStack(spacing: 3) {
                Text(text ?? "—")
                    .font(.system(.callout, design: .rounded).bold())
                    .monospacedDigit()
                if let unit {
                    Text(unit)
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)
                }
                if let symbol {
                    Image(systemName: symbol)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .buttonStyle(.plain)
        .contentShape(Rectangle())
        .help(help)
    }

    private var refreshHelp: String {
        guard let fetchedAt = info?.fetchedAt else {
            return "Load this FID's on-chain stats"
        }
        let when = fetchedAt.formatted(.relative(presentation: .named))
        return "Refresh on-chain stats — last updated \(when)"
    }

    // MARK: - actions

    private func commitLabel() {
        do {
            try session.setLabel(labelDraft, forFid: session.liveFid)
            editingLabel = false
            // The label lives in the Setting, not in any observable
            // AppState field, so nudge SwiftUI to re-read it.
            appState.bumpIdentityRevision()
        } catch {
            labelError = String(describing: error)
        }
    }

    // MARK: - format

    /// Android's `formatLargeNumber`: three significant-ish digits plus a
    /// magnitude suffix, so a rail of numbers stays the same width no
    /// matter how rich the identity is.
    static func compact(_ n: Int64) -> String {
        let abs = Swift.abs(n)
        switch abs {
        case 1_000_000_000...:
            return String(format: "%.1fb", Double(n) / 1_000_000_000)
        case 1_000_000...:
            return String(format: "%.1fm", Double(n) / 1_000_000)
        case 1_000...:
            return String(format: "%.1fk", Double(n) / 1_000)
        default:
            return String(n)
        }
    }

    /// Satoshis → coins, then Android's `formatBalance` banding: whole
    /// coins once you have thousands, a compact suffix past 100k, and
    /// full precision for the small amounts where every digit matters.
    static func formatBalance(_ satoshis: Int64?) -> String? {
        guard let satoshis else { return nil }
        let coins = Double(satoshis) / Double(Cash.satoshisPerBch)
        if coins >= 100_000 { return compact(Int64(coins)) }
        if coins >= 1_000 { return String(Int64(coins)) }
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        return f.string(from: NSNumber(value: coins)) ?? "0"
    }
}
