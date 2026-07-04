import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Add or edit a single contact. Locally-editable fields live in the
/// form; on-chain identity facts (cid / pubkey / balance / cross-chain
/// addresses / etc.) come from the **Look up** button, which calls
/// `base.freerByIds` against the active FAPI server. The looked-up
/// `Freer` is held in state and merged into the contact at save time.
/// The CID is set on-chain by the Freer themself and is never editable
/// here.
struct ContactEditorSheet: View {
    let session: ActiveSession
    let mode: ContactsView.EditorMode
    let onSaved: () -> Void
    let onCancel: () -> Void

    @State private var fid: String = ""
    @State private var titlesInput: String = ""
    @State private var memo: String = ""
    @State private var seeStatement: Bool = false
    @State private var seeWritings: Bool = false

    @State private var saveError: String?
    @State private var saving: Bool = false

    @State private var lookedUpFreer: Freer?
    @State private var lookingUp: Bool = false
    @State private var lookupError: String?
    @State private var lookupKnownOffChain: Bool = false

    private var isEdit: Bool {
        if case .edit = mode { return true }
        return false
    }

    private var fidLooksValid: Bool {
        (try? FchAddress(fid: fid)) != nil
    }

    private var canSave: Bool {
        !saving && fidLooksValid
    }

    private var canLookup: Bool {
        !lookingUp && fidLooksValid
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            Form {
                Section {
                    LabeledField(
                        "FID",
                        hint: (!fid.isEmpty && !fidLooksValid)
                            ? "Not a valid FCH mainnet address."
                            : nil,
                        hintIsError: true
                    ) {
                        HStack(spacing: 8) {
                            TextField("", text: $fid, prompt: Text("F…"))
                                .font(.system(.body, design: .monospaced))
                                .fieldInputStyle()
                                .disabled(isEdit)
                                .onChange(of: fid) { _, _ in
                                    // Stale results once the user retypes.
                                    lookedUpFreer = nil
                                    lookupKnownOffChain = false
                                    lookupError = nil
                                }

                            Button {
                                Task { await runLookup() }
                            } label: {
                                if lookingUp {
                                    HStack(spacing: 4) {
                                        ProgressView().controlSize(.small)
                                        Text("Looking up…")
                                    }
                                } else {
                                    Label("Look up", systemImage: "magnifyingglass")
                                }
                            }
                            .disabled(!canLookup)
                            .help("Fetch the on-chain Freer record (cid, pubkey, balance) from the configured FAPI server.")
                        }
                    }

                    if let err = lookupError {
                        HStack(alignment: .top, spacing: 4) {
                            Image(systemName: "xmark.octagon.fill")
                            CopyableText(err, font: .caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .foregroundStyle(.red)
                        .font(.caption)
                    } else if lookupKnownOffChain {
                        HStack(spacing: 6) {
                            Image(systemName: "questionmark.circle")
                            Text("No on-chain record — this FID hasn't registered a Freer yet. You can still save the contact locally.")
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .foregroundStyle(.orange)
                        .font(.caption)
                    } else if let f = lookedUpFreer {
                        onChainStatus(f)
                    }
                } header: {
                    Text(isEdit ? "Identity" : "New contact")
                }

                Section {
                    LabeledField(
                        "Titles",
                        hint: "Comma-separated. Shown under the contact's name."
                    ) {
                        TextField("", text: $titlesInput,
                                  prompt: Text("Friend, Engineer"))
                            .fieldInputStyle()
                    }

                    LabeledField("Memo") {
                        TextEditor(text: $memo)
                            .font(.body)
                            .frame(minHeight: 70, maxHeight: 140)
                            .padding(6)
                            .background(
                                RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    .fill(Color(nsColor: .textBackgroundColor))
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    .strokeBorder(Color.secondary.opacity(0.3), lineWidth: 0.5)
                            )
                    }
                } header: {
                    Text("Detail")
                }

                Section("Permissions") {
                    Toggle("See statement", isOn: $seeStatement)
                    Toggle("See writings",  isOn: $seeWritings)
                }

                if let err = saveError {
                    Section {
                        CopyableText(err, font: .callout)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            footer
        }
        .frame(minWidth: 540, minHeight: 580)
        .onAppear { loadFromMode() }
    }

    private var header: some View {
        HStack(spacing: 12) {
            if !fid.isEmpty, fidLooksValid {
                FidAvatarView(fid: fid, size: 40)
            } else {
                ZStack {
                    Circle()
                        .fill(Color.secondary.opacity(0.15))
                        .frame(width: 40, height: 40)
                    Image(systemName: "person.crop.circle")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                }
            }
            Text(isEdit ? "Edit contact" : "Add contact")
                .font(.title2).bold()
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var footer: some View {
        HStack {
            Spacer()
            Button("Cancel", role: .cancel) { onCancel() }
                .keyboardShortcut(.cancelAction)
            Button {
                Task { await save() }
            } label: {
                if saving {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Saving…")
                    }
                    .frame(width: 100)
                } else {
                    Text("Save").frame(width: 100)
                }
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .disabled(!canSave)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    @ViewBuilder
    private func onChainStatus(_ f: Freer) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                Text("On-chain record").font(.caption.bold())
                    .foregroundStyle(.green)
                Spacer()
            }
            if let cid = f.cid, !cid.isEmpty {
                CopyableText(
                    display: "cid: \(cid)",
                    copy: cid,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
            if let pkHex = f.pubkey, !pkHex.isEmpty {
                CopyableText(
                    display: "pubkey: \(pkHex.elidingMiddle(head: 10, tail: 10))",
                    copy: pkHex,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
            HStack(spacing: 12) {
                if let bal = f.balance {
                    Text("balance: \(formatBch(bal))")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                if let h = f.lastHeight {
                    Text("last block: \(h)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.tertiary)
                }
                if let cd = f.cdd {
                    Text("cdd: \(cd)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Color.green.opacity(0.08))
        )
    }

    private func formatBch(_ sats: Int64) -> String {
        let bch = Double(sats) / 100_000_000.0
        let f = NumberFormatter()
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = 8
        return (f.string(from: NSNumber(value: bch)) ?? "0") + " FCH"
    }

    // MARK: - load / lookup / save

    private func loadFromMode() {
        if case .edit(let c) = mode {
            fid = c.id
            titlesInput = (c.titles ?? []).joined(separator: ", ")
            memo = c.memo ?? ""
            seeStatement = c.seeStatement ?? false
            seeWritings = c.seeWritings ?? false
            // Surface what we already know about the on-chain side
            // so the editor doesn't pretend the contact is "fresh"
            // when it isn't. Pubkey lives in `Contact` as 33 raw
            // bytes; reconstitute hex for the status panel.
            let pkHex = c.pubkey?
                .map { String(format: "%02x", $0) }
                .joined()
            if c.cid != nil || pkHex != nil || c.lastHeight != nil {
                var f = Freer()
                f.cid = c.cid
                f.pubkey = pkHex
                f.balance = c.balance
                f.lastHeight = c.lastHeight
                f.cdd = c.cdd
                lookedUpFreer = f
            }
        }
    }

    @MainActor
    private func runLookup() async {
        guard fidLooksValid else { return }
        lookingUp = true
        lookupError = nil
        lookupKnownOffChain = false
        defer { lookingUp = false }
        do {
            let freer = try await session.directory.freer(byId: fid)
            if let freer {
                lookedUpFreer = freer
            } else {
                lookedUpFreer = nil
                lookupKnownOffChain = true
            }
        } catch {
            lookedUpFreer = nil
            lookupError = String(describing: error)
        }
    }

    @MainActor
    private func save() async {
        guard fidLooksValid else { return }
        saving = true
        saveError = nil
        defer { saving = false }

        let titles = titlesInput
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let titlesField: [String]? = titles.isEmpty ? nil : titles
        let memoField: String? = memo.isEmpty ? nil : memo

        do {
            switch mode {
            case .create:
                var c = Contact(
                    id: fid,
                    titles: titlesField,
                    memo: memoField,
                    seeStatement: seeStatement,
                    seeWritings: seeWritings
                )
                if let f = lookedUpFreer {
                    c = c.merging(f)
                }
                try session.contacts.upsert(c)

            case .edit(let original):
                var c = original
                if let f = lookedUpFreer {
                    c = c.merging(f)
                }
                c.titles = titlesField
                c.memo = memoField
                c.seeStatement = seeStatement
                c.seeWritings = seeWritings
                try session.contacts.upsert(c)
            }
            onSaved()
        } catch {
            saveError = String(describing: error)
        }
    }
}
