import SwiftUI
import FCDomain
import FCUI

/// Settings › Identity: the on-chain records that say who a FID is — its CID
/// (FEIP3), its master (FEIP6) and its DOCK and DISK (FEIP9 Home). The
/// CID and DOCK/DISK forms live in ``CidCarveForm`` and ``HomeCarveForm``,
/// which the getting-started checklist also opens as dialogs.
///
/// **The master is here and not on the checklist.** It names another FID
/// of your own as this one's owner, which a beginner does not have, and it
/// is permanent. The row only shows state and opens ``SetMasterSheet``,
/// which carries the warnings.
struct IdentitySettingsSection: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession

    @State private var pendingMaster: PendingIdentityCarve?

    private var info: LiveFidInfo? { appState.knownLiveFidInfo }

    private var carveBlocker: String? {
        IdentityCarve.blocker(session: session, info: info)
    }

    var body: some View {
        Section {
            if let carveBlocker {
                CarveBlockerLabel(text: carveBlocker)
            }
            CidCarveForm(session: session)
            masterRow
            HomeCarveForm(session: session)
        } header: {
            Text("Identity")
        } footer: {
            Text("Your CID is the name people find you by; the last characters of your FID are added to keep it unique, and registering one puts your pubkey on the chain. A master is optional and permanent: only set one to a FID of your own that you trust completely. Your DOCK holds messages while you're offline and your DISK keeps your files — until both are on the chain, nobody has anywhere to reach you. Each is a carve with a small fee, and shows here once a block confirms it.")
                .font(.caption)
        }
        .onAppear(perform: loadPending)
        // A refresh is what clears a carve that has landed.
        .onChange(of: info) { _, _ in loadPending() }
        // The master sheet records its carve before any refresh.
        .onChange(of: appState.identityRevision) { _, _ in loadPending() }
    }

    // MARK: - master

    @ViewBuilder
    private var masterRow: some View {
        LabeledField("Master", hint: masterHint) {
            HStack(spacing: 8) {
                if let master = chainMaster {
                    CopyableText.elidingMiddle(master, font: .callout.monospaced())
                    Text("Permanent").font(.caption).foregroundStyle(.secondary)
                } else if session.liveFid != session.mainFid {
                    Text("Only the main FID can have a master.")
                        .font(.callout).foregroundStyle(.secondary)
                } else {
                    Text("None").font(.callout).foregroundStyle(.secondary)
                    Button("Set master…") { appState.openSetMaster() }
                        .disabled(carveBlocker != nil || IdentityCarve.isWaiting(pendingMaster))
                }
                Spacer(minLength: 0)
            }
        }
        if chainMaster == nil, session.liveFid == session.mainFid {
            CarveOutcome(error: nil, pending: pendingMaster, what: "the master")
        }
    }

    /// The master the chain holds for the main FID. Read from the live
    /// record only while living as the main; the local KeyInfo is written on
    /// broadcast and can name a master whose carve never landed.
    private var chainMaster: String? {
        guard session.liveFid == session.mainFid,
              let master = info?.master?.trimmingCharacters(in: .whitespaces),
              !master.isEmpty else { return nil }
        return master
    }

    private var masterHint: String? {
        if chainMaster != nil {
            return "The first master is the only one: the protocol ignores any later master carve."
        }
        guard session.liveFid == session.mainFid else { return nil }
        return "Another FID of yours that can recover this one. Setting it puts your prikey on the chain, sealed to the master, for good."
    }

    private func loadPending() {
        pendingMaster = try? session.pendingIdentityCarves.get(fid: session.mainFid, kind: .master)
    }
}
