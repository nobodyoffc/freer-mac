import Foundation

/// Sidebar selection in ``HomeView``. Each case maps to one detail
/// pane.
///
/// **Every case appears in the sidebar automatically.** The sidebar
/// iterates `allCases` grouped by ``group``, and the detail view
/// switches exhaustively, so adding a case here is the only edit
/// needed to ship a new pane — and forgetting the detail arm is a
/// compile error.
///
/// This used to be a claim rather than a fact: the sidebar hardcoded
/// two arrays of cases, so a new case compiled fine, satisfied the
/// exhaustive switch, and was still unreachable because nothing listed
/// it. That is exactly how the Files pane shipped invisible.
enum WalletPane: String, Hashable, CaseIterable, Identifiable {
    // Wallet. Cash sits above Transactions because the coins you hold
    // are the state, and the transactions are the history of it.
    // Compose sits under Send because it is the same act with the
    // decisions handed back to you.
    case overview
    case send
    case compose
    case cash
    case transactions

    // Society
    case contacts
    case chat
    case mail
    case news

    // Finance
    case proofs
    case tokens

    // Personal
    case files
    case secrets

    // Publish
    case publishText
    case publishStatement
    case publishImage
    case publishSound
    case publishVideo

    // Construct
    case protocols
    case services
    case codes
    case apps

    // Tools
    case crypto
    case convert
    /// SSH, with an ed25519 key derived from the main FID. Sits under
    /// Tools rather than System because it is a workbench you point at
    /// something, not a setting.
    case terminal

    // System
    case logs
    case settings

    var id: String { rawValue }

    /// Sidebar heading a pane sits under. Declaration order within a
    /// group is the display order, and the order of these cases is the
    /// order of the headings.
    enum Group: String, CaseIterable, Identifiable {
        /// Your own money: what you hold, what you move, what moved.
        case wallet = "Wallet"
        /// Everything addressed to or from other people.
        case society = "Society"
        /// Value that isn't the base coin — proofs of a contract's
        /// state, and the tokens issued against them.
        case finance = "Finance"
        /// Yours alone: nothing here is sent anywhere by opening it.
        case personal = "Personal"
        /// Putting something on chain for everyone — one pane per kind
        /// of thing published.
        case publish = "Publish"
        /// Protocol, Service, Code and App — the four records that
        /// register what the network is *made of*, as opposed to what
        /// passes through it. They share one lifecycle (publish →
        /// update → stop ⇄ recover → close), one owner-and-waiters
        /// shape and one rate op, so they share a heading.
        case construct = "Construct"
        /// Workbenches: you point them at something rather than
        /// browsing what the chain holds. Crypto and Converter act on
        /// whatever you paste in and keep nothing; Terminal is the one
        /// that saves records of its own — the servers you connect to.
        case tools = "Tools"
        /// The app itself. Last, because it is about the app rather
        /// than about anything you do with it.
        case system = "System"

        var id: String { rawValue }
    }

    var group: Group {
        switch self {
        case .overview, .send, .compose, .cash, .transactions:
            return .wallet
        case .contacts, .chat, .mail, .news:
            return .society
        case .proofs, .tokens:
            return .finance
        case .files, .secrets:
            return .personal
        case .publishText, .publishStatement, .publishImage, .publishSound, .publishVideo:
            return .publish
        case .protocols, .services, .codes, .apps:
            return .construct
        case .crypto, .convert, .terminal:
            return .tools
        case .logs, .settings:
            return .system
        }
    }

    /// Panes in this group, in declaration order.
    static func panes(in group: Group) -> [WalletPane] {
        allCases.filter { $0.group == group }
    }

    var title: String {
        switch self {
        case .overview:     return "Overview"
        case .send:         return "Send"
        case .compose:      return "Compose"
        case .cash:         return "Cash"
        case .transactions: return "Transactions"
        case .contacts:     return "Contacts"
        case .chat:         return "Chat"
        case .mail:         return "Mail"
        case .news:         return "News"
        case .proofs:       return "Proofs"
        case .tokens:       return "Tokens"
        case .files:        return "Files"
        case .secrets:      return "Secrets"
        case .publishText:  return "Text"
        case .publishStatement: return "Statement"
        case .publishImage: return "Image"
        case .publishSound: return "Sound"
        case .publishVideo: return "Video"
        case .protocols:    return "Protocols"
        case .services:     return "Services"
        case .codes:        return "Code"
        case .apps:         return "Apps"
        case .crypto:       return "Crypto"
        case .convert:      return "Converter"
        case .terminal:     return "Terminal"
        case .logs:         return "Logs"
        case .settings:     return "Settings"
        }
    }

    /// Whether this pane is useless without a private key for the
    /// live FID.
    ///
    /// **The predicate is capability, not "is this the main FID".** A
    /// servant has a key (``KeyKind/canSign``), and a multisig FID will
    /// once co-signing ships, so a rule written against `liveFid ==
    /// mainFid` would close the very panes those identities exist to
    /// use. Gating on ``ActiveSession/canSign`` means they open by
    /// themselves the day they get a key.
    ///
    /// Two independent reasons put a pane here, and Chat and Mail have
    /// both:
    ///
    ///   - **Nothing to read.** Every message in a DOCK and every HAT on
    ///     a DISK is sealed to its FID's key. Without one, Chat and Mail
    ///     render a wall of ciphertext and Secrets renders nothing.
    ///
    /// Plus, for the DOCK-backed pair: a DOCK connection *is* a FUDP
    /// handshake, which needs the connecting FID's privkey (see
    /// ``DockRegistry/Connect``). A watch-only identity cannot open the
    /// socket, never mind decrypt what comes back.
    ///
    /// **The Publish panes used to be here, and are not any more.** The
    /// note that put them here said they were "carve forms with no
    /// browse mode at all", which was true of the placeholders and
    /// false the moment Phase 8.8 shipped: every one of them opens on a
    /// **Discover** tab that reads the whole chain's shelf, and nothing
    /// a published record holds is encrypted — that is the point of
    /// publishing. `PublishService` says so in its own header ("no key
    /// is needed to read"). So they browse like Proofs and Tokens do,
    /// with their compose buttons gated on `canSign` one by one.
    ///
    /// **What is deliberately *not* here.** Reading is not writing.
    /// News is public chain data and says so in its own header. Proofs
    /// and Tokens list what the live FID holds — "a token ledger is
    /// public, so a watch-only identity can watch a balance it cannot
    /// move". Contacts, Files and the four Construct panes all have
    /// real browse modes, and their write buttons are already gated on
    /// `canSign` one by one. Closing those would be the odd result of
    /// showing a watched FID's coins in Wallet while hiding its tokens.
    ///
    /// **Terminal is the case that proves the rule.** It plainly needs
    /// a private key — it cannot authenticate without one — and it is
    /// still not here, because the key it needs is the **main** FID's,
    /// derived through `ActiveSession.sshIdentity()`, and that is
    /// available whenever the vault is unlocked. `needsKey` asks about
    /// the *live* identity, so putting Terminal here would close your
    /// servers the moment you switched to a watched FID to look at a
    /// balance. The pane raises its own banner in the one case that
    /// really does close it: a main FID with no privkey.
    var needsKey: Bool {
        switch self {
        case .chat, .mail, .secrets:
            return true
        case .overview, .send, .compose, .cash, .transactions,
             .contacts, .news, .proofs, .tokens, .files,
             .publishText, .publishStatement, .publishImage, .publishSound, .publishVideo,
             .protocols, .services, .codes, .apps,
             .crypto, .convert, .terminal, .logs, .settings:
            return false
        }
    }

    /// Why this pane is closed, for the sidebar tooltip. Nil when it is
    /// open.
    var closedReason: String? {
        switch self {
        case .chat, .mail:
            return "Watch-only identity — no key to open a DOCK with, or to decrypt what it holds. Switch to your main FID."
        case .secrets:
            return "Watch-only identity — no key to decrypt these with. Switch to your main FID."
        default:
            return nil
        }
    }

    var systemImage: String {
        switch self {
        case .overview:     return "house"
        case .send:         return "paperplane"
        case .compose:      return "square.stack.3d.up"
        case .cash:         return "banknote"
        case .transactions: return "list.bullet"
        case .contacts:     return "person.2"
        case .chat:         return "bubble.left.and.bubble.right"
        case .mail:         return "envelope"
        case .news:         return "newspaper"
        case .proofs:       return "checkmark.seal"
        case .tokens:       return "circle.grid.2x2"
        case .files:        return "folder"
        case .secrets:      return "lock.shield"
        case .publishText:  return "doc.text"
        case .publishStatement: return "text.quote"
        case .publishImage: return "photo"
        case .publishSound: return "waveform"
        case .publishVideo: return "film"
        case .protocols:    return "doc.text.magnifyingglass"
        case .services:     return "server.rack"
        case .codes:        return "chevron.left.forwardslash.chevron.right"
        case .apps:         return "app.badge"
        case .crypto:       return "wrench.and.screwdriver"
        case .convert:      return "arrow.left.arrow.right"
        case .terminal:     return "terminal"
        case .logs:         return "exclamationmark.bubble"
        case .settings:     return "gearshape"
        }
    }
}
