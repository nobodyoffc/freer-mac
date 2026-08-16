import SwiftUI
import FCDomain

/// Everything about a chat flavour that shows on screen, in one table.
///
/// **Why this is a table and not four `switch`es scattered through the
/// views.** The four flavours are four different security models — a
/// square is public and unencrypted, a room is sealed to a membership
/// only its owner knows, a team is sealed to a membership the chain
/// publishes, a P2P chat is sealed to one person — and the user's only
/// defence against confusing them is that they never look alike. That
/// only holds if the colour, the word and the sentence are decided
/// **once** and read everywhere: the tab, the list row, the transcript
/// header and the composer footer. Four separate `switch`es is how a
/// square ends up red in one place and green in another.
///
/// The colours follow Android, where they are already a warning system
/// rather than decoration: a square is **red** in the toolbar label and
/// in the banner (`chat_info_square`, `Color.RED`), a team is amber
/// (`#FF8800`). Nothing else in this app is red, which is the point.
struct ChatModeStyle: Identifiable {

    let mode: ImType

    var id: String { mode.rawValue }

    /// The tab label, and the pane heading.
    var title: String {
        switch mode {
        case .p2p:    return "Chats"
        case .room:   return "Rooms"
        case .team:   return "Teams"
        case .square: return "Squares"
        }
    }

    /// The word for one of these, mid-sentence.
    var noun: String {
        switch mode {
        case .p2p:    return "chat"
        case .room:   return "room"
        case .team:   return "team"
        case .square: return "square"
        }
    }

    var systemImage: String {
        switch mode {
        case .p2p:    return "bubble.left.and.bubble.right"
        case .room:   return "lock.circle"
        case .team:   return "person.3"
        case .square: return "megaphone"
        }
    }

    /// The one colour this flavour is drawn in, everywhere.
    var tint: Color {
        switch mode {
        case .p2p:    return .accentColor
        case .room:   return .purple
        case .team:   return .orange
        case .square: return .red
        }
    }

    /// Whether this flavour's chrome should shout. Only the square does:
    /// it is the one where a reasonable expectation of privacy is
    /// simply wrong.
    var isPublic: Bool { mode == .square }

    /// The padlock — or its absence, which is the part worth seeing
    /// without reading.
    var sealingIcon: String {
        switch mode {
        case .p2p:    return "lock.fill"
        case .room:   return "lock.fill"
        case .team:   return "lock.fill"
        case .square: return "globe"
        }
    }

    /// What sealing this flavour gets, said plainly under the composer.
    var sealingNote: String {
        switch mode {
        case .p2p:
            return "Encrypted to them. Your copy stays on this Mac; the copy that travels is readable only by the two of you."
        case .room:
            return "Encrypted with this room's key. Members who join later cannot read what came before."
        case .team:
            return "Encrypted with this team's key. Who is in the team is public on the chain; what is said is not."
        case .square:
            return "Not encrypted. Anyone may join a square, so treat everything here as public."
        }
    }

    /// The longer description, for the empty state and the new-thread
    /// sheet — what this flavour *is*, in terms of who can get in.
    var summary: String {
        switch mode {
        case .p2p:
            return "A direct conversation with one FID. Nothing about it is on the chain and nobody else can read it."
        case .room:
            return "A private group nobody can enumerate: no carve, no on-chain member list. The owner decides who is in it, and everyone else holds a copy of what the owner last said."
        case .team:
            return "A group whose membership lives on the chain. Joining and leaving are transactions, and who belongs is public — messages are sealed with the team's key."
        case .square:
            return "An open group. Anyone may join, so there is no key and no privacy: every message here is in the clear."
        }
    }

    /// What the primary button in this tab makes.
    var newActionTitle: String {
        switch mode {
        case .p2p:    return "New chat"
        case .room:   return "New room"
        case .team:   return "Join a team"
        case .square: return "Join a square"
        }
    }

    /// What the empty list should say.
    var emptyTitle: String {
        switch mode {
        case .p2p:    return "No chats yet"
        case .room:   return "No rooms yet"
        case .team:   return "No teams yet"
        case .square: return "No squares yet"
        }
    }

    /// Whether this flavour's list is populated by an on-chain sync
    /// rather than by local action. Teams and squares are found by
    /// asking the chain what this FID belongs to; rooms and chats are
    /// made here.
    var syncsFromChain: Bool {
        mode == .team || mode == .square
    }

    static let all: [ChatModeStyle] = [
        .init(mode: .p2p), .init(mode: .room), .init(mode: .team), .init(mode: .square)
    ]

    static func of(_ mode: ImType) -> ChatModeStyle { .init(mode: mode) }
}
