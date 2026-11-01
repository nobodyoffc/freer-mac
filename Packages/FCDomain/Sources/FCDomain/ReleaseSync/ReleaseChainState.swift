import Foundation
import FCTransport

/// Everything one FID has registered: its protocols, codes and apps, in
/// every state. Release Sync diffs the local repos against this.
///
/// Stopped and closed records are fetched too. A stopped record is still
/// the one an update must target; closed ones are dropped by the planner.
public struct ReleaseChainState: Sendable {
    public var protocols: [ProtocolSpec]
    public var codes: [Code]
    public var apps: [AppRecord]
    /// Texts, images, sounds and videos, deleted ones included.
    public var works: [WorkRecord]
    public var bestHeight: Int64?

    public init(protocols: [ProtocolSpec] = [], codes: [Code] = [], apps: [AppRecord] = [],
                works: [WorkRecord] = [], bestHeight: Int64? = nil) {
        self.protocols = protocols
        self.codes = codes
        self.apps = apps
        self.works = works
        self.bestHeight = bestHeight
    }

    /// Pages each registry to its end. A page shorter than asked for is
    /// the last one; the server never returns a short page otherwise.
    /// - Parameter works: also fetch the owner's texts and media, which
    ///   only a repo with `works` needs.
    public static func fetch(owner: String, fapi: any FapiCalling, works: Bool = false,
                             pageSize: Int = 100) async throws -> ReleaseChainState {
        var state = ReleaseChainState()

        let protocolService = ProtocolService(fapi: fapi)
        var after: [String]? = nil
        while true {
            let page = try await protocolService.fetchProtocols(owner: owner, after: after, size: pageSize)
            state.protocols += page.protocols
            state.bestHeight = page.bestHeight ?? state.bestHeight
            guard page.protocols.count == pageSize, let last = page.last, !last.isEmpty else { break }
            after = last
        }

        let codeService = CodeService(fapi: fapi)
        after = nil
        while true {
            let page = try await codeService.fetchCodes(owner: owner, after: after, size: pageSize)
            state.codes += page.codes
            guard page.codes.count == pageSize, let last = page.last, !last.isEmpty else { break }
            after = last
        }

        let appService = AppService(fapi: fapi)
        after = nil
        while true {
            let page = try await appService.fetchApps(owner: owner, after: after, size: pageSize)
            state.apps += page.apps
            guard page.apps.count == pageSize, let last = page.last, !last.isEmpty else { break }
            after = last
        }

        guard works else { return state }
        let publish = PublishService(fapi: fapi)
        for kind in WorkKind.allCases {
            after = nil
            while true {
                let rows: [WorkRecord], last: [String]?
                if let media = kind.media {
                    let page = try await publish.fetchMedia(kind: media, publisher: owner, deleted: nil, after: after, size: pageSize)
                    rows = page.rows.map { WorkRecord($0, kind: kind) }
                    last = page.last
                } else {
                    let page = try await publish.fetchTexts(publisher: owner, deleted: nil, after: after, size: pageSize)
                    rows = page.rows.map { WorkRecord($0) }
                    last = page.last
                }
                state.works += rows
                guard rows.count == pageSize, let last, !last.isEmpty else { break }
                after = last
            }
        }
        return state
    }
}
