import Foundation

/// Which of the three media protocols a record belongs to — Image
/// (FEIP24), Sound (FEIP23) or Video (FEIP25).
///
/// **These three protocols are identical.** Not similar: identical.
/// Same entity fields, same five ops, same lifecycle, same CDD rules,
/// same OP_RETURN envelope. What differs between them is a serial
/// number, a name, an index, and how the subject field is spelled —
/// `imageId` / `soundId` / `videoId`. Nothing else, anywhere.
///
/// So they are one implementation with three configurations rather
/// than three files. That is the opposite of the call made for the
/// Construct four, and the reason is that Construct's records really
/// did differ — Code's `protocols`, Service's prices, App's
/// `downloads` — while these differ in no field at all. Text stays its
/// own type because it has `type` and Remark because it has `onDid`;
/// three copies of a file with *no* distinguishing field would only
/// drift apart.
///
/// **The subject key is the whole hazard.** One spelling per protocol,
/// applied to the op that names a record — and a carve that names a
/// `soundId` on the video index is accepted by the client, rejected by
/// the parser and lost. It is defined once here, and the carve tests
/// assert each protocol's key is present *and* the other two absent.
public enum MediaKind: String, CaseIterable, Sendable, Identifiable, Codable {
    case image
    case sound
    case video

    public var id: String { rawValue }

    /// The FEIP registry entry this kind is. Numbers and names are read
    /// from there rather than respelled here, so a protocol bump has
    /// one place to happen.
    public var feip: FeipProtocol {
        switch self {
        case .image: return .image
        case .sound: return .sound
        case .video: return .video
        }
    }

    public var sn: String { feip.sn }
    public var ver: String { feip.ver }
    /// The `name` in the OP_RETURN envelope — `Image`, `Sound`, `Video`.
    public var protocolName: String { feip.protocolName }

    /// The chain index, and Java's `IndicesNames` value.
    public var index: String { rawValue }

    /// The op field naming one record: `imageId` / `soundId` /
    /// `videoId`.
    public var subjectKey: String { "\(rawValue)Id" }

    /// The op field naming several: `imageIds` / `soundIds` /
    /// `videoIds`.
    public var subjectsKey: String { "\(rawValue)Ids" }

    /// Store namespace. Spelled out rather than derived so that a
    /// rename of this enum cannot silently orphan a user's drafts.
    public var namespace: String {
        switch self {
        case .image: return "images.v1"
        case .sound: return "sounds.v1"
        case .video: return "videos.v1"
        }
    }

    /// Display label. English only for now; Phase 11 localises.
    public var label: String { protocolName }

    /// Plural, for the counts and empty states a pane writes.
    public var plural: String {
        switch self {
        case .image: return "images"
        case .sound: return "sounds"
        case .video: return "videos"
        }
    }

    /// SF Symbol for the pane and its empty states.
    public var symbol: String {
        switch self {
        case .image: return "photo"
        case .sound: return "waveform"
        case .video: return "film"
        }
    }

    /// What the file-picker filter and the `format` hint should suggest.
    public var noun: String {
        switch self {
        case .image: return "image"
        case .sound: return "audio file"
        case .video: return "video"
        }
    }
}
