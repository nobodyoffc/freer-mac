import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Create a multisig group — the Mac port of Android's
/// `CreateMultisigIdActivity`.
///
/// **Creating a group publishes nothing and costs nothing.** A multisig
/// address is `hash160` of a redeem script built from its members'
/// public keys, so it exists the moment those keys do; there is no
/// registration and nobody to ask. What this sheet produces is an
/// address and the script behind it, saved locally so the coins sent
/// there can be spent later.
///
/// **Which means losing the script loses the coins.** Every member
/// needs the same group recorded — same members, same order, same m —
/// or they cannot rebuild the redeem script and the money stays where
/// it is forever. The sheet says so, and offers the script for export
/// before it saves.
///
/// **Order is part of the identity.** `OP_CHECKMULTISIG` reads
/// signatures and pubkeys in one pass, so the same three people in a
/// different order are a different address. The member list here is
/// explicitly ordered and reorderable, rather than a set.
struct CreateMultisigSheet: View {
    let session: ActiveSession
    let onCreated: (KeyInfo) -> Void
    let onCancel: () -> Void

    /// Members, in redeem-script order. The main FID starts here
    /// because a group it is not in could never be spent from by this
    /// Setting — ``ActiveSession/addMultisigFid(_:label:)`` refuses it.
    @State private var members: [PickedFid] = []
    @State private var threshold = 2
    @State private var label = ""
    @State private var pick: FidPickerRequest?
    @State private var saveError: String?
    @State private var seeded = false

    private var memberKeys: [String] {
        members.compactMap { $0.pubkey.map(Hex.encode) }
    }

    /// Everyone in the list has a published key, so the script can
    /// actually be built.
    private var missingKeys: [PickedFid] {
        members.filter { $0.pubkey?.count != 33 }
    }

    private var group: Multisig? {
        guard members.count >= 2, missingKeys.isEmpty,
              threshold >= 1, threshold <= members.count
        else { return nil }
        return try? Multisig(pubkeys: memberKeys, m: threshold)
    }

    private var includesMain: Bool {
        members.contains { $0.fid == session.mainFid }
    }

    private var blockReason: String? {
        if members.count < 2 { return "A group needs at least two members." }
        if members.count > 15 { return "A group cannot have more than 15 members." }
        if let first = missingKeys.first {
            return "\(first.fid.elidingMiddle(head: 8, tail: 8)) has never published a pubkey — nothing has been signed from it — so it cannot be in a group."
        }
        if !includesMain {
            return "This FID is not in the group, so this Setting could never sign for it."
        }
        if let existing = group?.id, session.setting.keyInfoMap[existing] != nil {
            return "This exact group is already registered."
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    membersPanel
                    thresholdPanel
                    addressPanel
                    warningPanel
                    if let saveError {
                        Label(saveError, systemImage: "xmark.octagon.fill")
                            .font(.callout)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(16)
            }
            Divider()
            footer
        }
        .frame(minWidth: 600, minHeight: 620)
        .onAppear(perform: seedWithMain)
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                pick = nil
                adopt(picked)
            } onCancel: {
                pick = nil
            }
        }
    }

    // MARK: - panels

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "person.3.sequence.fill")
                .font(.title2)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text("Create multisig group")
                    .font(.title2).bold()
                Text("An address that needs several people to spend from it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var membersPanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Members")
                    .font(.caption.bold())
                    .textCase(.uppercase)
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    pick = .many(
                        title: "Choose group members",
                        subtitle: "Everyone who can sign for this address. Each needs a published pubkey.",
                        preselected: members,
                        excluded: []
                    )
                } label: {
                    Label(members.isEmpty ? "Choose…" : "Edit…", systemImage: "person.2.badge.plus")
                }
            }

            if members.isEmpty {
                Text("No members yet.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(members.enumerated()), id: \.element.fid) { index, member in
                        memberRow(index: index, member: member)
                        if index < members.count - 1 { Divider() }
                    }
                }
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color.secondary.opacity(0.06))
                )
                Text("Order matters — the same people in a different order make a different address.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func memberRow(index: Int, member: PickedFid) -> some View {
        HStack(spacing: 10) {
            Text("\(index + 1)")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .frame(width: 18, alignment: .trailing)
            FidAvatarView(fid: member.fid, size: 26)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(member.cid?.isEmpty == false ? member.name : "No CID")
                        .lineLimit(1)
                    if member.fid == session.mainFid {
                        Text("you")
                            .font(.caption2)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Capsule().fill(Color.accentColor.opacity(0.18)))
                    }
                }
                CopyableText(
                    display: member.fid.elidingMiddle(head: 10, tail: 10),
                    copy: member.fid,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
            Spacer()
            if member.pubkey?.count != 33 {
                Image(systemName: "key.slash")
                    .foregroundStyle(.orange)
                    .help("No published pubkey — this FID cannot be in a group")
            }
            Button {
                move(from: index, by: -1)
            } label: { Image(systemName: "chevron.up") }
                .buttonStyle(.borderless)
                .disabled(index == 0)
            Button {
                move(from: index, by: 1)
            } label: { Image(systemName: "chevron.down") }
                .buttonStyle(.borderless)
                .disabled(index == members.count - 1)
            Button(role: .destructive) {
                members.remove(at: index)
                clampThreshold()
            } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    private var thresholdPanel: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Signatures required")
                .font(.caption.bold())
                .textCase(.uppercase)
                .foregroundStyle(.secondary)
            HStack(spacing: 12) {
                Stepper(value: $threshold, in: 1...max(1, members.count)) {
                    Text("**\(threshold)** of \(max(members.count, 1))")
                }
                .frame(maxWidth: 220)
                Spacer()
            }
            Text(thresholdNote)
                .font(.caption)
                .foregroundStyle(threshold == members.count && members.count > 1 ? .orange : .secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var thresholdNote: String {
        if members.count > 1 && threshold == members.count {
            return "Every member must sign. If any one of them loses their key, the coins are stuck for good."
        }
        if threshold == 1 {
            return "Any single member can spend alone — this is a shared address, not a shared decision."
        }
        return "Any \(threshold) of the \(members.count) members can spend together."
    }

    @ViewBuilder
    private var addressPanel: some View {
        if let group, let address = group.id {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                    Text("Group address").font(.caption.bold())
                        .foregroundStyle(.green)
                }
                CopyableText(display: address, copy: address, font: .body.monospaced())
                if let script = group.redeemScript {
                    CopyableText(
                        display: "redeem script: \(script.elidingMiddle(head: 12, tail: 12))",
                        copy: script,
                        font: .caption.monospaced()
                    )
                    .foregroundStyle(.secondary)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color.green.opacity(0.08))
            )
        } else if let reason = blockReason {
            Label(reason, systemImage: "exclamationmark.triangle.fill")
                .font(.callout)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var warningPanel: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill")
                Text("Everyone needs a copy of this group").font(.headline)
            }
            .foregroundStyle(.orange)
            Text("The address is public, but spending from it needs the redeem script — the members, their order, and the threshold. It is not stored on chain anywhere. If every member loses it, the coins cannot be moved by anyone, ever.")
                .fixedSize(horizontal: false, vertical: true)
            Text("Copy the redeem script above and give it to each member before sending anything here.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Color.orange.opacity(0.10))
        )
    }

    private var footer: some View {
        HStack {
            LabeledField("Label", hint: nil) {
                TextField("", text: $label, prompt: Text("House fund"))
                    .fieldInputStyle()
            }
            .frame(maxWidth: 260)
            Spacer()
            Button("Cancel", role: .cancel) { onCancel() }
                .keyboardShortcut(.cancelAction)
            Button("Create") { create() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(group == nil || blockReason != nil)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - actions

    /// Start with the main FID in the list. It has to be a member for
    /// the group to be registerable at all, so putting it there is a
    /// head start rather than a decision made for the user — it can be
    /// removed, and the block reason then explains why that fails.
    private func seedWithMain() {
        guard !seeded else { return }
        seeded = true
        let info = session.mainKeyInfo
        members = [PickedFid(
            fid: session.mainFid,
            cid: info.activeCid,
            pubkey: info.pubkey,
            source: .myKey
        )]
    }

    /// Keep the order the user arranged: picks already in the list stay
    /// where they are, new ones go on the end. Re-sorting to the
    /// picker's order would silently change the group's address.
    private func adopt(_ picked: [PickedFid]) {
        let chosen = Set(picked.map(\.fid))
        var next = members.filter { chosen.contains($0.fid) }
        for p in picked where !next.contains(where: { $0.fid == p.fid }) {
            next.append(p)
        }
        members = next
        clampThreshold()
    }

    private func move(from index: Int, by offset: Int) {
        let target = index + offset
        guard members.indices.contains(target) else { return }
        members.swapAt(index, target)
    }

    private func clampThreshold() {
        threshold = min(max(1, threshold), max(1, members.count))
    }

    private func create() {
        guard let group else { return }
        do {
            let info = try session.addMultisigFid(
                group, label: label.trimmingCharacters(in: .whitespaces)
            )
            onCreated(info)
        } catch {
            saveError = String(describing: error)
        }
    }
}
