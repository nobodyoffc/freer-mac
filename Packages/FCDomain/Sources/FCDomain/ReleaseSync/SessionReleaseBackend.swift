import Foundation
import FCCore

/// ``ReleaseSyncBackend`` over a live session: carves are signed by its
/// live FID, files become HATs in its Files and are carved onto DISK
/// unencrypted, so anyone can fetch a document by the DID on chain.
public struct SessionReleaseBackend: ReleaseSyncBackend, @unchecked Sendable {
    let session: ActiveSession

    public init(session: ActiveSession) {
        self.session = session
    }

    public func storeOnDisk(_ file: URL, name: String) async throws {
        // An app-managed copy: the repo file may change after this run
        // (the next PID fill, an edit), and the HAT must keep its bytes.
        let did = Hex.encode(try Hash.doubleSha256(fileAt: file)).lowercased()
        let copy = session.files.defaultLocalURL(did: did)
        if !FileManager.default.fileExists(atPath: copy.path) {
            try FileManager.default.createDirectory(at: copy.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: file, to: copy)
        }
        let hat = try session.files.registerFile(at: copy, name: name)
        guard let id = hat.id else { return }
        // Already carved permanently: nothing to pay for twice.
        if let item = try? await session.disk.check(did: id), item.expire == nil {
            return
        }
        try await session.hatSync.uploadRaw(hatId: id, permanent: true)
    }

    public func uploadAsset(_ file: URL, repo: String, tag: String) async throws {
        try await Task.detached {
            try GitHubReleases(repo: repo).upload(file, tag: tag)
        }.value
    }

    public func carveProtocol(_ c: ProtocolCarve) async throws -> String {
        if let pid = c.targetId {
            return try await session.carveProtocolUpdateOnChain(
                pid: pid, name: c.name, type: c.type, sn: c.sn, ver: c.ver, did: c.did,
                desc: c.desc, lang: c.lang, home: c.home, preDid: c.preDid, waiters: c.waiters)
        }
        return try await session.carveProtocolPublishOnChain(
            name: c.name, type: c.type, sn: c.sn, ver: c.ver, did: c.did,
            desc: c.desc, lang: c.lang, home: c.home, preDid: c.preDid, waiters: c.waiters).id
    }

    public func carveCode(_ c: CodeCarve) async throws -> String {
        if let codeId = c.targetId {
            return try await session.carveCodeUpdateOnChain(
                codeId: codeId, name: c.name, ver: c.ver, did: c.did, desc: c.desc,
                langs: c.langs, home: c.home, protocols: c.protocols, waiters: c.waiters)
        }
        return try await session.carveCodePublishOnChain(
            name: c.name, ver: c.ver, did: c.did, desc: c.desc,
            langs: c.langs, home: c.home, protocols: c.protocols, waiters: c.waiters).id
    }

    public func carveApp(_ c: AppCarve) async throws -> String {
        if let aid = c.targetId {
            return try await session.carveAppUpdateOnChain(
                aid: aid, stdName: c.stdName, localNames: c.localNames, types: c.types, desc: c.desc,
                ver: c.ver, home: c.home, downloads: c.downloads, waiters: c.waiters,
                protocols: c.protocols, codes: c.codes, services: c.services)
        }
        return try await session.carveAppPublishOnChain(
            stdName: c.stdName, localNames: c.localNames, types: c.types, desc: c.desc,
            ver: c.ver, home: c.home, downloads: c.downloads, waiters: c.waiters,
            protocols: c.protocols, codes: c.codes, services: c.services).id
    }

    public func isConfirmed(kind: ReleaseEntityKind, id: String, txid: String) async throws -> Bool {
        switch kind {
        case .protocol:
            return try await session.protocolService.fetchProtocolsByIds([id])[id]?.lastTxId == txid
        case .code:
            return try await session.codeService.fetchCodesByIds([id])[id]?.lastTxId == txid
        case .app:
            return try await session.appService.fetchAppsByIds([id])[id]?.lastTxId == txid
        }
    }
}
