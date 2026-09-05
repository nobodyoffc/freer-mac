import Foundation
import FCCore

/// The well-known **first-FCH request board**: a public inbox built on a
/// *nobody* freer, and the wire template the posts on it use.
///
/// A nobody FID is one whose private key has been published, so it can be
/// neither owned nor trusted: anyone can decrypt what is addressed to it,
/// and anyone can speak as it. That is exactly what makes it usable as a
/// notice board. A newcomer whose balance is zero cannot carve, cannot
/// register a DOCK of their own, and has nothing to pay a fee with — but
/// they can still park a message at a server that will hold it, and every
/// existing freer can read it, because the key to open it is public.
///
/// **This type owns the board's identity and its template, and nothing
/// else.** Posting to it is ``FirstFchBoard/post(note:as:privkey:)``,
/// reading it is ``FirstFchBoard/fetch(newerThan:)`` — the same split
/// Android draws between `NobodyBoard` and `NewcomerBoard`.
///
/// **Nothing that arrives from here is actionable.** Anyone on earth can
/// write as this FID, so a board item is a FID and a sentence to read,
/// never a tappable card, a link, or a payment request. The only thing a
/// helper does with one is send coins to the FID it names, from their own
/// identity, through the ordinary approval path — see ``FirstFchBoard``.
public enum NobodyBoard {

    /// The default nobody freer. Its private key is public **by
    /// design**; publishing it here is not a leak, it is the mechanism.
    /// The FID below is what ``prikey`` derives to — see the test.
    public static let defaultNobodyFid = "FHG8DW2eHQ5wNAJQnLNKzYUSo2YKt7ffff"
    public static let defaultNobodyPrikeyHex =
        "d710ff828229c8fd9923407a5ebfb4a27a42504a1d69ae7ec95b9cc2c7073226"

    /// Wire prefix of a templated request: `FIRST_FCH_REQUEST|fid|note`.
    ///
    /// A template rather than free text because the reader is a list of
    /// payees, not a transcript: the FID has to be machine-readable to
    /// become a transaction output, and everything that does not parse is
    /// simply not shown. That is also the spam filter — a stranger
    /// shouting into the board writes a row nobody's app renders.
    public static let requestPrefix = "FIRST_FCH_REQUEST|"

    /// How much of a note travels. Long enough for "just installed, thanks",
    /// short enough that the board cannot be used as free storage.
    public static let noteMaxCharacters = 100

    /// The board's private key. Published by design — this is a nobody.
    public static let prikey: Data = (try? Hex.decode(defaultNobodyPrikeyHex)) ?? Data()

    /// The board's public key, derived rather than looked up. The chain
    /// holds the same value under ``defaultNobodyFid``, but a post has to
    /// work for someone whose balance is zero and whose network is bad,
    /// and deriving it locally cannot fail either way.
    public static let pubkey: Data = (try? Secp256k1.publicKey(fromPrivateKey: prikey)) ?? Data()

    public static func isDefaultNobody(_ fid: String?) -> Bool {
        fid == defaultNobodyFid
    }

    // MARK: - the template

    /// Build the content of a request post.
    ///
    /// The note is flattened and clipped here rather than validated: a
    /// newcomer typing into a box is not the place to refuse a post over
    /// a newline.
    public static func buildRequest(from requesterFid: String, note: String?) -> String {
        var clean = (note ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\n", with: " ")
        if clean.count > noteMaxCharacters {
            clean = String(clean.prefix(noteMaxCharacters))
        }
        return requestPrefix + requesterFid + "|" + clean
    }

    /// One parsed request on the board.
    public struct Request: Equatable, Sendable, Identifiable {
        /// Who is asking — and, to a helper, the payee.
        public let requesterFid: String
        public let note: String
        /// The **server's** `createTime`, not the sender's timestamp.
        /// See ``FirstFchBoard`` for why that distinction is the whole
        /// defence of the cursor.
        public let createTime: Int64

        /// Keyed on the FID: one row per asker, however many times they
        /// posted.
        public var id: String { requesterFid }

        public init(requesterFid: String, note: String, createTime: Int64) {
            self.requesterFid = requesterFid
            self.note = note
            self.createTime = createTime
        }
    }

    /// Parse a board post. Returns nil for anything that is not a
    /// well-formed request, which is most of what a public inbox holds.
    public static func parseRequest(_ content: String?, createTime: Int64?) -> Request? {
        guard let content, content.hasPrefix(requestPrefix) else { return nil }
        let rest = content.dropFirst(requestPrefix.count)
        let fid: Substring
        let note: Substring
        if let sep = rest.firstIndex(of: "|") {
            fid = rest[rest.startIndex..<sep]
            note = rest[rest.index(after: sep)...]
        } else {
            fid = rest
            note = ""
        }
        guard !fid.isEmpty, fid.count <= 40, note.count <= noteMaxCharacters else { return nil }
        return Request(
            requesterFid: String(fid),
            note: String(note),
            createTime: createTime ?? 0
        )
    }

    // MARK: - reading a post

    /// Decode one item off the board and open its body.
    ///
    /// **Opening is not optional.** A post travels through a DOCK, which
    /// is a third party, so it is sealed to the board's pubkey like any
    /// other P2P message — the rule the transport applies to everything,
    /// with no exception for a message that happens to be public. Decoding
    /// the wire bytes alone therefore yields an envelope whose `content`
    /// is nil, and a reader that stopped there would render the whole
    /// board as empty rather than as unreadable.
    ///
    /// Returns nil when the bytes are not a message, or when the body will
    /// not open — both of which a public inbox will contain.
    public static func openPost(wireBytes: Data) -> ImMessage? {
        guard !wireBytes.isEmpty else { return nil }
        guard var message = try? ImMessage.fromWireBytes(wireBytes) else { return nil }
        if message.isSealed, !message.openBody(privkey: prikey) { return nil }
        return message
    }
}
