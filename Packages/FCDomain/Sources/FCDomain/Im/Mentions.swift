import Foundation

/// `@somebody` in a group's messages.
///
/// **A mention is text, nothing more.** The wire has no field for one, so
/// a mention is `@` and the person's CID — or their FID, when they have no
/// CID — written into the message, which every client shows as it is.
/// Whoever reads it as themselves is the one mentioned: the receiver looks
/// for its own CID or FID after an `@`.
///
/// An `@` counts only at the start of the text or after a space, so an
/// address like `a@b` is not read as a mention of `b`; a name ends at a
/// space, the next `@`, or the punctuation that follows it.
///
/// The rules are Android's `Mentions` too, case for case — see
/// `MentionsTests` and `MentionsTest`: a mention must be found the same
/// way on every device.
public enum Mentions {

    /// Punctuation that ends a name: `@Alice,` mentions Alice.
    private static let trailing = CharacterSet(charactersIn: ",.;:!?)]}>\"'，。；：！？、）】》」』")

    /// One `@name` in a text, the `@` included in `range`.
    public struct Token: Equatable, Sendable {
        public let range: Range<String.Index>
        public let name: String
    }

    /// Every `@name` in `text`, in order.
    public static func tokens(in text: String) -> [Token] {
        var found: [Token] = []
        var i = text.startIndex
        while i < text.endIndex {
            guard text[i] == "@",
                  i == text.startIndex || text[text.index(before: i)].isWhitespace
            else {
                i = text.index(after: i)
                continue
            }
            // A name ends at a space, the next `@`, or punctuation — which
            // in Chinese follows it with no space: `@张三，你好`.
            var end = text.index(after: i)
            while end < text.endIndex, !text[end].isWhitespace, text[end] != "@",
                  !(text[end].unicodeScalars.first.map(trailing.contains) ?? false) {
                end = text.index(after: end)
            }
            if end > text.index(after: i) {
                found.append(Token(range: i..<end, name: String(text[text.index(after: i)..<end])))
            }
            i = end > i ? end : text.index(after: i)
        }
        return found
    }

    /// Whether `text` mentions the identity whose FID and CID these are.
    public static func mentions(_ text: String?, fid: String, cid: String?) -> Bool {
        guard let text, text.contains("@") else { return false }
        let names = Set([fid, cid ?? ""].filter { !$0.isEmpty })
        return tokens(in: text).contains { names.contains($0.name) }
    }

    /// Whether `message` is a text that mentions the identity.
    public static func mentions(_ message: ImMessage, fid: String, cid: String?) -> Bool {
        message.type != .p2p && message.contentType == .text
            && mentions(message.content, fid: fid, cid: cid)
    }

    /// The name being typed after an `@` at the end of `draft` — "" right
    /// after the `@` itself — or nil when the draft does not end in one.
    /// A composer that cannot report its cursor uses the end of the draft
    /// instead, which is where a name is typed almost every time.
    public static func pendingQuery(in draft: String) -> String? {
        guard let at = draft.lastIndex(of: "@") else { return nil }
        if at > draft.startIndex, !draft[draft.index(before: at)].isWhitespace { return nil }
        let typed = draft[draft.index(after: at)...]
        if typed.contains(where: \.isWhitespace) { return nil }
        return String(typed)
    }

    /// `draft` with the `@name` being typed at its end — or, when none is,
    /// nothing — replaced by `@handle `.
    public static func complete(_ draft: String, with handle: String) -> String {
        var base = draft
        if pendingQuery(in: draft) != nil, let at = draft.lastIndex(of: "@") {
            base = String(draft[..<at])
        } else if !base.isEmpty, base.last?.isWhitespace == false {
            base += " "
        }
        return base + "@" + handle + " "
    }
}

/// A group thread with messages naming the live identity that it has not
/// yet seen.
public struct UnreadMention: Identifiable, Sendable {
    public var id: String { conversation.id }
    public let conversation: Conversation
    /// How many of them.
    public let count: Int
}

extension ActiveSession {

    /// Every group thread with an unseen message naming us, most recent
    /// first. `myCid` is how a group names us besides our FID.
    ///
    /// Unseen means unread for another member's message. Our own — an `@`
    /// of ourselves, which is how a message is flagged for our other
    /// devices — is filed as read wherever it arrives, so for those
    /// ``SeenSelfMentions`` stands in for the flag.
    public func unreadMentions(myCid: String?, type: ImType? = nil) -> [UnreadMention] {
        let types = type.map { [$0] } ?? [.room, .team, .square]
        let seen = SeenSelfMentions.ids(in: self)
        var found: [UnreadMention] = []
        for type in types where type != .p2p {
            for conversation in (try? conversations.visible(type: type)) ?? [] {
                let unread = conversation.unreadCount ?? 0
                // The unread messages, and never fewer than the last few:
                // our own are not counted unread, so the count cannot say
                // whether one of them is new.
                let limit = max(min(unread, 200), SeenSelfMentions.window)
                guard let recent = try? messages.page(in: conversation.id, limit: limit) else { continue }
                let count = recent.messages.filter { m in
                    guard Mentions.mentions(m, fid: liveFid, cid: myCid) else { return false }
                    if m.isOutgoing(from: liveFid) {
                        return m.id.map { !seen.contains($0) } ?? false
                    }
                    return m.unread == true
                }.count
                if count > 0 { found.append(UnreadMention(conversation: conversation, count: count)) }
            }
        }
        return found.sorted { ($0.conversation.lastMessageTime ?? 0) > ($1.conversation.lastMessageTime ?? 0) }
    }
}

/// The messages we wrote that `@` ourselves, already seen on this device.
///
/// The chat service files whatever our own FID sent as read — on the
/// device it was typed on, that is true — so arriving from another device
/// such a message raises no unread count and has no unread flag to clear.
/// This list stands in for that flag: one of ours that names us and is
/// not on it is news. Sending one here, or having its thread on screen,
/// puts it on the list.
///
/// In the vault's encrypted store, keyed by FID.
public enum SeenSelfMentions {
    private static let namespace = "im.seenselfmentions.v1"
    /// How far back a thread is looked through for one.
    public static let window = 50
    /// How many ids are kept, oldest dropped first.
    static let kept = 1000

    public static func ids(in session: ActiveSession) -> Set<String> {
        Set((try? session.storage.get([String].self, namespace: namespace, key: session.liveFid)) ?? [])
    }

    /// Of `messages`, the ones we wrote that name us have been seen.
    public static func markSeen(_ messages: [ImMessage], in session: ActiveSession, myCid: String?) {
        let fresh = messages.filter {
            $0.isOutgoing(from: session.liveFid) && Mentions.mentions($0, fid: session.liveFid, cid: myCid)
        }.compactMap(\.id)
        guard !fresh.isEmpty else { return }
        var list = (try? session.storage.get([String].self, namespace: namespace, key: session.liveFid)) ?? []
        let known = Set(list)
        let added = fresh.filter { !known.contains($0) }
        guard !added.isEmpty else { return }
        list += added
        if list.count > kept { list.removeFirst(list.count - kept) }
        try? session.storage.put(list, namespace: namespace, key: session.liveFid)
    }
}
