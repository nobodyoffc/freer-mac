import Foundation
import FCDomain
import FCUI

extension UnreadMention {
    /// The group's name, as the thread list shows it.
    var groupName: String {
        conversation.displayName.flatMap { $0.isEmpty ? nil : $0 }
            ?? conversation.targetId.elidingMiddle()
    }
}
