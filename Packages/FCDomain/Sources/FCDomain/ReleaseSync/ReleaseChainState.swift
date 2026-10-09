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
    public var bestHeight: Int64?

    public init(protocols: [ProtocolSpec] = [], codes: [Code] = [], apps: [AppRecord] = [], bestHeight: Int64? = nil) {
        self.protocols = protocols
        self.codes = codes
        self.apps = apps
        self.bestHeight = bestHeight
    }

    /// Pages each registry to its end. A page shorter than asked for is
    /// the last one; the server never returns a short page otherwise.
    public static func fetch(owner: String, fapi: any FapiCalling, pageSize: Int = 100) async throws -> ReleaseChainState {
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
        return state
    }
}
