import Foundation
import FCCore

/// Sharing a file in a chat — the port of Android's `FileShareHelper`
/// and `ChatActivity.startHatTransfer`.
///
/// **Every share goes through DISK, whatever its size.** There is no
/// inline path for a small file and no separate path for a large one:
/// the sender encrypts the bytes, uploads them, and sends a *reference*.
/// That is worth being deliberate about, because the obvious
/// optimisation — small files inline — would mean two receive paths, two
/// failure modes, and a size threshold to argue about forever.
///
/// The reference is a ``Hat`` carrying **the plaintext file key and the
/// DISK locations of the cipher copies**, which is the whole trick: the
/// recipient can fetch and decrypt without holding any key of their own
/// and without the sender's private key ever being involved. It also
/// means the message body *is* the capability — anyone who reads the
/// message can read the file, and nobody who cannot read the message
/// can. For a room or a team that is exactly right, since the message
/// itself is already sealed to the group.
///
/// The local copy of the HAT never carries that plaintext key: only the
/// one that goes on the wire does. See
/// ``HatSyncService/shareableHat(from:)``.
public struct FileShareService {

    private let files: FileVault
    private let hats: HatsStore
    private let sync: HatSyncService

    public init(files: FileVault, hats: HatsStore, sync: HatSyncService) {
        self.files = files
        self.hats = hats
        self.sync = sync
    }

    // MARK: - sending

    /// Register `url`, upload it, and build the message that shares it.
    ///
    /// `onPrepared` fires after the file is hashed and registered but
    /// **before** the upload, carrying the HAT's DID. Android does the
    /// same, and the reason is worth keeping: a chat that shows nothing
    /// until a 100 MB upload finishes looks broken, so the pane draws
    /// the bubble immediately and tracks progress against that DID.
    ///
    /// The returned message is not sent — that is ``ChatService``'s job,
    /// and keeping the two apart means an upload that succeeded while
    /// the send failed leaves a file on DISK and a message in the
    /// outbox, rather than a half-done operation with no name.
    public func share(
        fileAt url: URL,
        in conversation: Conversation,
        as liveFid: String,
        ownPubkey: Data,
        desc: String? = nil,
        permanent: Bool = false,
        onPrepared: (@Sendable (Hat) -> Void)? = nil,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil,
        now: Date = Date()
    ) async throws -> ImMessage {
        let name = url.lastPathComponent
        let registered = try files.registerFile(
            at: url,
            name: name,
            desc: desc ?? "Shared in \(conversation.type.rawValue.lowercased()) chat",
            types: Self.mimeTypes(for: url)
        )
        guard let hatId = registered.id else { throw Failure.registrationFailed(name) }
        onPrepared?(registered)

        let result = try await sync.upload(
            hatId: hatId,
            permanent: permanent,
            ownPubkey: ownPubkey,
            progress: progress
        )
        let shareable = try sync.shareableHat(from: result)

        return ImMessage.hat(
            type: conversation.type,
            from: liveFid,
            to: conversation.targetId,
            hatJson: shareable.wireJson(),
            now: now
        )
    }

    // MARK: - receiving

    /// The file a `HAT` message is offering, merged into our own store
    /// so it can be downloaded.
    ///
    /// Merging is what makes the offer actionable — ``HatSyncService``
    /// downloads by id, so a HAT that only ever existed inside a message
    /// body could not be fetched. Returns nil when the body is not a
    /// HAT, which is an ordinary outcome for a message from a newer
    /// client.
    ///
    /// **The record is stored as it arrived, plaintext key included.**
    /// That key is not a secret being leaked: it is a capability the
    /// sender chose to hand us, and it is the only way to open the
    /// bytes. What it must never do is travel further — nothing
    /// re-shares a received HAT without going through
    /// ``share(fileAt:in:as:ownPubkey:desc:permanent:onPrepared:progress:now:)``
    /// again, which uploads a fresh copy under a fresh key.
    @discardableResult
    public func accept(_ message: ImMessage) throws -> Hat? {
        guard message.contentType == .hat,
              let json = message.content, !json.isEmpty,
              let offered = try? Hat.fromJson(json),
              let id = offered.id, !id.isEmpty
        else { return nil }

        // A HAT we already hold keeps its own local state — where the
        // bytes are, whether we have them — and takes only what the
        // offer adds: the key and the locations to fetch from.
        if var existing = try hats.hat(id: id) {
            if existing.key == nil { existing.key = offered.key }
            for loca in offered.locas ?? [] { existing.addLoca(loca) }
            for cipherId in offered.cipherIds ?? [] { existing.addCipherId(cipherId) }
            try hats.upsert(existing)
            return existing
        }
        try hats.upsert(offered)
        return offered
    }

    /// Fetch the bytes a HAT message offers, decrypting with the key it
    /// carried. Returns where they landed.
    ///
    /// No private key is needed — see the type's note — which is what
    /// lets a room member open a file shared by someone whose keys they
    /// have never held.
    @discardableResult
    public func download(
        _ message: ImMessage,
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> URL {
        guard let hat = try accept(message), let id = hat.id else {
            throw Failure.notAFileShare
        }
        return try await sync.download(hatId: id, progress: progress)
    }

    /// What the pane needs to draw a file bubble without opening the
    /// store: name, size, and whether the bytes are already here.
    public func offer(in message: ImMessage) -> Offer? {
        guard message.contentType == .hat,
              let json = message.content,
              let hat = try? Hat.fromJson(json),
              let id = hat.id
        else { return nil }
        let local = (try? files.localURL(hatId: id)) ?? nil
        return Offer(
            hatId: id,
            name: hat.name ?? id,
            size: hat.size,
            localURL: local,
            hasKey: !(hat.key ?? "").isEmpty
        )
    }

    public struct Offer: Equatable, Sendable {
        public let hatId: String
        public let name: String
        public let size: Int64?
        /// Where the bytes are, if we already have them.
        public let localURL: URL?
        /// Whether the offer carried a key. Without one the file can
        /// only be fetched if it happens to be public and
        /// content-addressed.
        public let hasKey: Bool

        public var isDownloaded: Bool { localURL != nil }
    }

    // MARK: - helpers

    /// A best-effort MIME type from the extension, so a receiver can
    /// pick an icon. Purely cosmetic — nothing routes on it.
    static func mimeTypes(for url: URL) -> [String]? {
        let ext = url.pathExtension.lowercased()
        guard !ext.isEmpty else { return nil }
        let known: [String: String] = [
            "txt": "text/plain", "md": "text/markdown", "json": "application/json",
            "pdf": "application/pdf", "zip": "application/zip",
            "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
            "gif": "image/gif", "heic": "image/heic", "webp": "image/webp",
            "mp3": "audio/mpeg", "m4a": "audio/mp4", "aac": "audio/aac",
            "mp4": "video/mp4", "mov": "video/quicktime",
        ]
        return known[ext].map { [$0] }
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case registrationFailed(String)
        case notAFileShare

        public var description: String {
            switch self {
            case .registrationFailed(let name):
                return "FileShareService: could not register \(name)"
            case .notAFileShare:
                return "FileShareService: that message is not a file share"
            }
        }
    }
}
