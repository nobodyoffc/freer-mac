import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Name another FID as this main FID's master — the Mac port of
/// Android's `SetMasterActivity`.
///
/// **This sheet exists to slow the user down.** Every other carve in
/// this app publishes something *about* you; this one publishes your
/// private key, sealed to the master's pubkey, in a record that never
/// goes away. The protocol states the consequence in its own required
/// sentence — "The master owns all my rights." — and the UI here says
/// the same thing in the user's terms before the tx-approval dialog
/// ever appears, because that dialog shows a fee and a byte count,
/// which is not a warning.
///
/// So: the danger panel is not collapsible, the confirm button is
/// destructive-red rather than prominent-blue, and it stays disabled
/// until the user types the master's FID back in by hand. Typing it is
/// not theatre — it is the one check that catches a mis-click in the
/// picker, which is the realistic way this goes wrong.
///
/// **A master must have a published pubkey.** You cannot encrypt to a
/// FID, only to a key, so a FID that has never signed anything cannot
/// be a master. That is checked here rather than at carve time so the
/// user learns it while choosing instead of after confirming.
struct SetMasterSheet: View {
    let session: ActiveSession
    let onDone: (String) -> Void
    let onCancel: () -> Void

    @State private var candidate: PickedFid?
    @State private var candidateFreer: Freer?
    @State private var loading = false
    @State private var loadError: String?

    @State private var typedConfirmation = ""
    @State private var carving = false
    @State private var carveError: String?

    @State private var pick: FidPickerRequest?

    private var currentMaster: String? {
        guard let m = session.mainKeyInfo.master,
              !m.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return m
    }

    /// The master's 33-byte pubkey — from the picked row when it
    /// already carried one, else from the record we fetched.
    private var candidatePubkey: Data? {
        if let pk = candidate?.pubkey, pk.count == 33 { return pk }
        return candidateFreer.flatMap { KeyInfo.from(freer: $0)?.pubkey }
    }

    /// Why this candidate can't be set, or nil when it can.
    private var blockReason: String? {
        guard let fid = candidate?.fid else { return nil }
        if fid == session.mainFid {
            return "That's this FID itself — a FID cannot be its own master."
        }
        if fid == currentMaster {
            return "Already the master of this FID."
        }
        if loading { return nil }
        if candidateFreer == nil {
            return "No on-chain record for this FID yet, so it has no published pubkey."
        }
        if candidatePubkey == nil {
            return "This FID has never published a pubkey — nothing has been signed from it — so there is no key to seal your private key to."
        }
        return nil
    }

    private var confirmationMatches: Bool {
        guard let fid = candidate?.fid else { return false }
        return typedConfirmation.trimmingCharacters(in: .whitespaces) == fid
    }

    private var canCarve: Bool {
        candidate != nil && blockReason == nil && candidatePubkey != nil
            && confirmationMatches && !carving && !loading
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    dangerPanel
                    choosePanel
                    if candidate != nil { confirmPanel }
                    if let err = carveError {
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: "xmark.octagon.fill")
                            CopyableText(err, font: .callout)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .foregroundStyle(.red)
                    }
                }
                .padding(16)
            }

            Divider()
            footer
        }
        .frame(minWidth: 580, minHeight: 560)
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                pick = nil
                if let one = picked.first { adopt(one) }
            } onCancel: {
                pick = nil
            }
        }
    }

    // MARK: - panels

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "key.horizontal.fill")
                .font(.title2)
                .foregroundStyle(.red)
            VStack(alignment: .leading, spacing: 2) {
                Text("Set master")
                    .font(.title2).bold()
                if let m = currentMaster {
                    CopyableText(
                        display: "Current master: \(m.elidingMiddle(head: 8, tail: 8))",
                        copy: m,
                        font: .caption
                    )
                    .foregroundStyle(.secondary)
                } else {
                    Text("No master set for this FID.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var dangerPanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill")
                Text("This hands over your identity")
                    .font(.headline)
            }
            .foregroundStyle(.red)

            Text("Setting a master publishes **your private key** on chain, encrypted to the master's public key. The record is permanent and public.")
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 4) {
                bullet("Whoever holds the master's private key can decrypt yours.")
                bullet("From then on they can spend this FID's coins, sign as it, and read everything ever encrypted to it.")
                bullet("It cannot be undone. Naming a different master later leaves the first record on chain, so the first master keeps your key.")
            }
            .font(.callout)

            Text("The protocol states it as: “\(MasterFeip.promise)”")
                .font(.caption.italic())
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Text("If you only want another identity to appear in your person menu, add it as a watched FID instead — that publishes nothing.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color.red.opacity(0.10))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(Color.red.opacity(0.35), lineWidth: 1)
        )
    }

    private func bullet(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("•")
            Text(text).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
    }

    private var choosePanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Master")
                .font(.caption.bold())
                .foregroundStyle(.secondary)
                .textCase(.uppercase)

            HStack(spacing: 10) {
                if let c = candidate {
                    FidAvatarView(fid: c.fid, size: 36)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(c.cid?.isEmpty == false ? c.name : "No CID")
                            .font(.body)
                            .lineLimit(1)
                        CopyableText(
                            display: c.fid.elidingMiddle(head: 10, tail: 10),
                            copy: c.fid,
                            font: .caption.monospaced()
                        )
                        .foregroundStyle(.secondary)
                    }
                } else {
                    ZStack {
                        Circle().fill(Color.secondary.opacity(0.12))
                            .frame(width: 36, height: 36)
                        Image(systemName: "person.fill.questionmark")
                            .foregroundStyle(.secondary)
                    }
                    Text("No one chosen yet.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if loading { ProgressView().controlSize(.small) }
                Button {
                    pick = .one(
                        title: "Choose a master",
                        subtitle: "The FID that will own all this identity's rights.",
                        excluded: [session.mainFid]
                    )
                } label: {
                    Label(candidate == nil ? "Choose…" : "Change…",
                          systemImage: "person.text.rectangle")
                }
            }

            if let err = loadError {
                Label(err, systemImage: "xmark.octagon.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let reason = blockReason {
                Label(reason, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let pk = candidatePubkey {
                let hex = Hex.encode(pk)
                CopyableText(
                    display: "pubkey: \(hex.elidingMiddle(head: 10, tail: 10))",
                    copy: hex,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
        }
    }

    private var confirmPanel: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Type the master's FID to confirm")
                .font(.caption.bold())
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            TextField("", text: $typedConfirmation, prompt: Text(candidate?.fid ?? ""))
                .font(.system(.body, design: .monospaced))
                .fieldInputStyle()
                .disabled(blockReason != nil || candidatePubkey == nil)
            Text(confirmationMatches
                 ? "Matches."
                 : "Retype it exactly — this is the check that catches a wrong pick.")
                .font(.caption)
                .foregroundStyle(confirmationMatches ? .green : .secondary)
        }
    }

    private var footer: some View {
        HStack {
            Text("A carve fee is paid from this FID, and the tx is confirmed separately.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button("Cancel", role: .cancel) { onCancel() }
                .keyboardShortcut(.cancelAction)
            Button(role: .destructive) {
                Task { await carve() }
            } label: {
                if carving {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Carving…")
                    }
                } else {
                    Text("Set master")
                }
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)
            .disabled(!canCarve)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - actions

    /// Take a pick and make sure we hold its on-chain record: the
    /// pubkey decides whether this FID can be a master at all, and the
    /// picker may have produced a purely local contact.
    private func adopt(_ picked: PickedFid) {
        candidate = picked
        typedConfirmation = ""
        carveError = nil
        loadError = nil
        candidateFreer = picked.freer
        // A row that already knows the pubkey needs no round trip; one
        // that doesn't (a local contact, a typed FID) has to be asked
        // about, because the pubkey is what decides whether this FID
        // can be a master at all.
        if picked.pubkey?.count != 33, picked.freer?.pubkey?.isEmpty != false {
            Task { await loadRecord(for: picked.fid) }
        }
    }

    @MainActor
    private func loadRecord(for fid: String) async {
        loading = true
        defer { loading = false }
        do {
            let freer = try await session.directory.freer(byId: fid)
            // Ignore a reply for a FID the user has since changed away
            // from — the picker can be reopened while this is in flight.
            guard candidate?.fid == fid else { return }
            candidateFreer = freer
        } catch {
            guard candidate?.fid == fid else { return }
            loadError = String(describing: error)
        }
    }

    @MainActor
    private func carve() async {
        guard canCarve, let fid = candidate?.fid, let pubkey = candidatePubkey else { return }
        carving = true
        carveError = nil
        defer { carving = false }
        do {
            let txid = try await session.carveMasterOnChain(
                masterFid: fid, masterPubkey: pubkey
            )
            onDone(txid)
        } catch {
            carveError = String(describing: error)
        }
    }
}
