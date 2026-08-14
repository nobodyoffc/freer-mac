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
    case overview
    case send
    case receive
    case transactions
    case contacts
    case mail
    case files
    case secrets
    case tools
    case settings

    var id: String { rawValue }

    /// Sidebar heading a pane sits under. Declaration order within a
    /// group is the display order.
    enum Group: String, CaseIterable, Identifiable {
        case wallet = "Wallet"
        case network = "Network"

        var id: String { rawValue }
    }

    var group: Group {
        switch self {
        case .overview, .send, .receive, .transactions:
            return .wallet
        case .contacts, .mail, .files, .secrets, .tools, .settings:
            return .network
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
        case .receive:      return "Receive"
        case .transactions: return "Transactions"
        case .contacts:     return "Contacts"
        case .mail:         return "Mail"
        case .files:        return "Files"
        case .secrets:      return "Secrets"
        case .tools:        return "Tools"
        case .settings:     return "Settings"
        }
    }

    var systemImage: String {
        switch self {
        case .overview:     return "house"
        case .send:         return "paperplane"
        case .receive:      return "tray.and.arrow.down"
        case .transactions: return "list.bullet"
        case .contacts:     return "person.2"
        case .mail:         return "envelope"
        case .files:        return "folder"
        case .secrets:      return "lock.shield"
        case .tools:        return "wrench.and.screwdriver"
        case .settings:     return "gearshape"
        }
    }
}
