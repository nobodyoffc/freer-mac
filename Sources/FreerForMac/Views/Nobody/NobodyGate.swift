import AppKit
import SwiftUI
import FCCore
import FCDomain
import FCUI

/// What going ahead with a nobody would cost. The sentences match
/// Android's `nobody_consequence_*` strings, so both apps say the same
/// thing about the same risk. See `NOBODY_SPEC.md`.
enum NobodyConsequence {
    case send, sendFrom, encrypt, mail, multisig, master
    case team, room, teamOwner, rate, contact, chat, importKey

    var text: String {
        switch self {
        case .send:
            return "Anything sent to it can be taken by anyone."
        case .sendFrom:
            return "The sender's private key is public. Anyone can spend the same cash first, so this transaction may never confirm."
        case .encrypt:
            return "Anyone can decrypt what you encrypt to it."
        case .mail:
            return "Anyone can read this mail and reply as the recipient."
        case .multisig:
            return "Anyone can sign as this member, so the multisig needs fewer real signatures than it appears."
        case .master:
            return "Setting a master publishes your private key encrypted to the master. Anyone can decrypt it and take this identity for good."
        case .team:
            return "Anyone can read the team's messages and act as these members, including giving their consent."
        case .room:
            return "Anyone can read the room's messages and speak as these members."
        case .teamOwner:
            return "Anyone could run the team as its owner."
        case .rate:
            return "Anyone can act as it, so its reputation means nothing. The coin days you destroy to rate it are wasted."
        case .contact:
            return "Anyone can speak as it, change its CID, and read what you send it."
        case .chat:
            return "Anyone can read this conversation and write as it."
        case .importKey:
            return "Anyone can spend this key's funds, read its messages and act as it. Use it only as a public identity."
        }
    }
}

/// Lines shown under a nobody's name wherever the consequence needs saying.
enum NobodyText {
    static let identity = "Nobody: this identity's private key is public. Anyone can act as it."
    static let selfIdentity = "This identity's private key is public. Anyone can spend its funds, read its messages and act as it."
    static let receive = "This address's private key is public. Anything paid here can be taken by anyone."
    static let sender = "The sender is a nobody: its private key is public, so anyone could have sent this."
    static let inviter = "The inviter is a nobody: its private key is public, so anyone could have sent this invitation."
    static let partner = "This identity is a nobody: its private key is public, so messages from it can be written by anyone and cannot be trusted."
    static let signature = "Valid, but the signer is a nobody: its private key is public, so anyone could have signed this. It proves nothing."
    static let consensus = "Nobody members' private keys are public: anyone can give their consent."
    static let contentHidden = "[Content from an unverifiable (nobody) identity is not shown]"
}

/// The confirmation before any action that involves a nobody.
///
/// **Never a block.** The user may mean it — funding the public board,
/// encrypting something they intend to publish. But the consequence is
/// said plainly and nothing proceeds until they choose to.
///
/// **An app-modal alert, not a sheet.** Most of these actions start from
/// inside a sheet, and SwiftUI will not reliably stack another — the same
/// reason ``TxApprovalHost`` uses a window. `NSAlert.runModal()` sits above
/// whatever is open.
@MainActor
enum NobodyGate {

    /// True when none of `fids` is a nobody, or the user chose to go ahead.
    /// Unknown FIDs are checked against the nobody index first; if that
    /// fails, the decision rests on what is already known.
    static func confirm(
        _ fids: [String?],
        _ consequence: NobodyConsequence,
        session: ActiveSession?
    ) async -> Bool {
        let candidates = fids.compactMap { $0 }.filter { !$0.isEmpty }
        guard !candidates.isEmpty else { return true }
        let registry = NobodyRegistry.shared
        if let session, !registry.unknown(among: candidates).isEmpty {
            let directory = session.directory
            await registry.resolve(candidates, retryFailed: true) { fids in
                await directory.nobodyFids(among: fids)
            }
        }
        let nobodies = registry.nobodies(among: candidates)
        guard !nobodies.isEmpty else { return true }
        return ask(nobodies, consequence)
    }

    /// ``confirm(_:_:session:)`` for hex pubkeys; anything that isn't one is ignored.
    static func confirm(
        pubkeys: [String],
        _ consequence: NobodyConsequence,
        session: ActiveSession?
    ) async -> Bool {
        await confirm(pubkeys.map { NobodyRegistry.fid(ofPubkeyHex: $0) }, consequence, session: session)
    }

    private static func ask(_ nobodies: [String], _ consequence: NobodyConsequence) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.icon = badgeIcon()
        alert.messageText = "Nobody identity"
        let list = nobodies.map { "• \($0)" }.joined(separator: "\n")
        alert.informativeText = "Private key published on chain:\n\(list)\n\n\(consequence.text)"
        // Cancel first: Return must never be the risky answer.
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Proceed Anyway")
        return alert.runModal() == .alertSecondButtonReturn
    }

    /// Tell the user, once per FID, that one of their own keys is a nobody.
    static func alertOwnKeyIfNeeded(_ fid: String) {
        guard NobodyRegistry.shared.claimOwnKeyAlert(fid) else { return }
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.icon = badgeIcon()
        alert.messageText = "Your private key is public"
        alert.informativeText = "The private key of \(fid) has been published on chain. Anyone can spend its funds, read its messages and act as it. Move your funds to a key only you hold."
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private static func badgeIcon() -> NSImage? {
        let renderer = ImageRenderer(content: NobodyBadge(diameter: 56).padding(4))
        renderer.scale = 2
        return renderer.nsImage
    }
}
