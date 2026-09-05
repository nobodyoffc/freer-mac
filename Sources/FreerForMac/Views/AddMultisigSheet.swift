import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Register a multisig group this FID already belongs to — the Mac
/// port of Android's `AddMultisigFidActivity`, plus the paste path
/// Android leaves to its detail screen.
///
/// **Two ways in, because the index only knows funded groups.** A
/// group exists as soon as its members' keys do, but `base.search`
/// learns of one only when coins move through its address. So:
///
///   - **Found** — ask the chain which groups list this FID as a
///     member. Complete for any group that has ever been used.
///   - **Redeem script** — paste the script another member sent you.
///     The only route for a group created moments ago, and the reason
///     ``CreateMultisigSheet`` pushes so hard on sharing it.
///
/// Either way the group is rebuilt from the script itself, so what
/// gets registered is what the coins are actually locked to rather
/// than a description of it.
struct AddMultisigSheet: View {
    let session: ActiveSession
    let onAdded: (Int) -> Void
    let onCancel: () -> Void

    private enum Tab: String, CaseIterable, Identifiable {
        case found = "Found"
        case paste = "Redeem script"
        var id: String { rawValue }
    }

    @State private var tab: Tab = .found
    @State private var found: [Multisig] = []
    @State private var loading = false
    @State private var loadError: String?
    @State private var loaded = false
    @State private var selected: Set<String> = []

    @State private var scriptText = ""
    @State private var scriptLabel = ""
    @State private var parsed: Multisig?
    @State private var parseError: String?

    @State private var saveError: String?

    private var alreadyRegistered: Set<String> {
        Set(session.setting.keyInfoMap.keys)
    }

    private var addable: [Multisig] {
        found.filter { g in
            guard let id = g.id else { return false }
            return !alreadyRegistered.contains(id)
        }
    }

    private var already: [Multisig] {
        found.filter { g in
            guard let id = g.id else { return false }
            return alreadyRegistered.contains(id)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Picker("", selection: $tab) {
                ForEach(Tab.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 16)
            .padding(.bottom, 10)
            Divider()

            switch tab {
            case .found: foundContent
            case .paste: pasteContent
            }

            Divider()
            footer
        }
        .frame(minWidth: 580, minHeight: 500)
        .task {
            guard !loaded else { return }
            await load()
        }
    }

    // MARK: - header / footer

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "person.3.fill")
                .font(.title2)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text("Add multisig group")
                    .font(.title2).bold()
                Text("Groups this FID can sign for.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if tab == .found {
                Button {
                    Task { await load() }
                } label: {
                    if loading {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .disabled(loading)
                .help("Ask the chain again")
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 12)
        .padding(.bottom, 10)
    }

    private var footer: some View {
        HStack {
            if let err = saveError {
                CopyableText(err, font: .caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Registering a group is local — it publishes nothing and costs nothing.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button("Cancel", role: .cancel) { onCancel() }
                .keyboardShortcut(.cancelAction)
            Button(addButtonTitle) { add() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(tab == .found ? selected.isEmpty : parsed == nil)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var addButtonTitle: String {
        tab == .found && selected.count > 1 ? "Add \(selected.count)" : "Add"
    }

    // MARK: - found

    @ViewBuilder
    private var foundContent: some View {
        if loading && found.isEmpty {
            centered {
                ProgressView()
                Text("Looking for groups…").foregroundStyle(.secondary)
            }
        } else if let err = loadError {
            centered {
                Image(systemName: "xmark.octagon.fill").font(.title).foregroundStyle(.red)
                CopyableText(err, font: .callout)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else if found.isEmpty {
            centered {
                // `person.3.slash` does not exist, and a name that does
                // not resolve renders as nothing — so this empty state
                // was headed by a blank gap rather than by an icon.
                // `person.2.slash` is the nearest symbol that ships.
                Image(systemName: "person.2.slash").font(.title).foregroundStyle(.secondary)
                Text("No groups found.").font(.headline)
                Text("The chain only knows a group once coins have moved through it. A group created just now will not appear here — paste its redeem script instead.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 380)
                Button("Paste a redeem script") { tab = .paste }
                    .buttonStyle(.link)
            }
        } else {
            List {
                if !addable.isEmpty {
                    Section("Found") {
                        ForEach(addable, id: \.id) { groupRow($0, registered: false) }
                    }
                }
                if !already.isEmpty {
                    Section("Already registered") {
                        ForEach(already, id: \.id) { groupRow($0, registered: true) }
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    private func groupRow(_ group: Multisig, registered: Bool) -> some View {
        let id = group.id ?? ""
        return HStack(spacing: 10) {
            if registered {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.secondary).frame(width: 16)
            } else {
                Toggle("", isOn: Binding(
                    get: { selected.contains(id) },
                    set: { on in
                        if on { selected.insert(id) } else { selected.remove(id) }
                    }
                ))
                .labelsHidden()
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(thresholdText(group)).font(.body)
                    if group.label?.isEmpty == false {
                        Text(group.label!).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                CopyableText(
                    display: id.elidingMiddle(head: 10, tail: 10),
                    copy: id,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
                Text(memberSummary(group))
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            Spacer()
            if registered {
                Text("registered").font(.caption).foregroundStyle(.tertiary)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            guard !registered else { return }
            if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
        }
    }

    private func thresholdText(_ group: Multisig) -> String {
        guard let m = group.m, let n = group.n else { return "multisig" }
        return "\(m)-of-\(n)"
    }

    private func memberSummary(_ group: Multisig) -> String {
        let fids = group.fids ?? []
        guard !fids.isEmpty else { return "members unknown" }
        let mine = fids.contains(session.mainFid) ? "you + " : ""
        return "\(mine)\(fids.count - (fids.contains(session.mainFid) ? 1 : 0)) other(s)"
    }

    // MARK: - paste

    private var pasteContent: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Paste the redeem script another member sent you. The group is rebuilt from the script itself, so what gets registered is exactly what the coins are locked to.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                LabeledField("Redeem script", hint: "Hex, starting with the threshold opcode.") {
                    TextEditor(text: $scriptText)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 90)
                        .overlay(
                            RoundedRectangle(cornerRadius: 5)
                                .stroke(Color.secondary.opacity(0.3))
                        )
                        .onChange(of: scriptText) { _, _ in reparse() }
                }

                LabeledField("Label", hint: "Optional.") {
                    TextField("", text: $scriptLabel, prompt: Text("House fund"))
                        .fieldInputStyle()
                }

                if let parseError {
                    Label(parseError, systemImage: "xmark.octagon.fill")
                        .font(.callout)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                } else if let parsed {
                    parsedPanel(parsed)
                }
            }
            .padding(16)
        }
    }

    @ViewBuilder
    private func parsedPanel(_ group: Multisig) -> some View {
        let isMember = group.contains(session.mainFid)
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: isMember ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                Text("\(thresholdText(group)) group").font(.caption.bold())
            }
            .foregroundStyle(isMember ? .green : .orange)

            if let id = group.id {
                CopyableText(display: id, copy: id, font: .callout.monospaced())
            }
            ForEach(Array((group.fids ?? []).enumerated()), id: \.offset) { index, fid in
                HStack(spacing: 6) {
                    Text("\(index + 1).")
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                    CopyableText(
                        display: fid.elidingMiddle(head: 8, tail: 8),
                        copy: fid,
                        font: .caption.monospaced()
                    )
                    .foregroundStyle(.secondary)
                    if fid == session.mainFid {
                        Text("you").font(.caption2)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Capsule().fill(Color.accentColor.opacity(0.18)))
                    }
                }
            }
            if !isMember {
                Text("This FID is not one of the members, so this Setting could never sign for the group.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill((isMember ? Color.green : Color.orange).opacity(0.08))
        )
    }

    private func centered<C: View>(@ViewBuilder _ content: () -> C) -> some View {
        VStack(spacing: 10) { content() }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(24)
    }

    // MARK: - actions

    @MainActor
    private func load() async {
        guard !loading else { return }
        loading = true
        loadError = nil
        defer {
            loading = false
            loaded = true
        }
        do {
            let page = try await session.directory.myMultisigs(of: session.mainFid)
            found = page.groups
            selected.formIntersection(Set(page.groups.compactMap(\.id)))
        } catch {
            loadError = String(describing: error)
        }
    }

    private func reparse() {
        let trimmed = scriptText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            parsed = nil
            parseError = nil
            return
        }
        do {
            parsed = try Multisig(redeemScriptHex: trimmed)
            parseError = nil
        } catch {
            parsed = nil
            parseError = String(describing: error)
        }
    }

    private func add() {
        saveError = nil
        switch tab {
        case .paste:
            guard let parsed else { return }
            do {
                _ = try session.addMultisigFid(
                    parsed, label: scriptLabel.trimmingCharacters(in: .whitespaces)
                )
                onAdded(1)
            } catch {
                saveError = String(describing: error)
            }
        case .found:
            var added = 0
            for group in addable {
                guard let id = group.id, selected.contains(id) else { continue }
                do {
                    // Rebuild from the script rather than trusting the
                    // indexed fields: the script is what the coins are
                    // locked to, and a record whose stated m/n differs
                    // from it would register a group that cannot spend.
                    let rebuilt = group.redeemScript.flatMap { try? Multisig(redeemScriptHex: $0) } ?? group
                    _ = try session.addMultisigFid(rebuilt, label: group.label ?? "")
                    added += 1
                } catch {
                    saveError = String(describing: error)
                    break
                }
            }
            if added > 0 { onAdded(added) }
        }
    }
}
