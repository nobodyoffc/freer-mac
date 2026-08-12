import Foundation

/// Sidebar selection in ``HomeView``. Each case maps to one detail
/// pane. Defined in one place so the sidebar list and the detail
/// switch can never drift apart.
enum WalletPane: String, Hashable, CaseIterable, Identifiable {
    case overview
    case send
    case receive
    case transactions
    case contacts
    case secrets
    case tools
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview:     return "Overview"
        case .send:         return "Send"
        case .receive:      return "Receive"
        case .transactions: return "Transactions"
        case .contacts:     return "Contacts"
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
        case .secrets:      return "lock.shield"
        case .tools:        return "wrench.and.screwdriver"
        case .settings:     return "gearshape"
        }
    }
}
