import Foundation

/// Writes review edits back to a repo's `freeverse-release.json`, so the
/// next scan agrees with what was carved instead of proposing to undo it.
///
/// Only fields the user changed in review are written: comparing with the
/// carve as it was offered, not with the manifest, keeps a description
/// clipped to fit the OP_RETURN from replacing the manifest's full text.
/// Links are written as the manifest's own references where they map back
/// (`FEIP1`, a code name), and as raw ids where the user added one.
public enum ReleaseManifestEditor {

    /// - Returns: whether the manifest changed.
    @discardableResult
    public static func writeBack(original: CodeCarve, reviewed: CodeCarve, item: CodePlanItem) throws -> Bool {
        guard original != reviewed else { return false }
        let entryRefs = item.local.entry.protocols ?? []
        return try edit(root: item.repo.root) { manifest in
            guard let i = manifest.codes?.firstIndex(where: { $0.name == item.local.entry.name }) else { return }
            if reviewed.desc != original.desc { manifest.codes![i].desc = reviewed.desc }
            if reviewed.langs != original.langs { manifest.codes![i].langs = reviewed.langs }
            if reviewed.protocols != original.protocols {
                manifest.codes![i].protocols = refs(reviewed.protocols, offered: original.protocols, as: entryRefs)
            }
        }
    }

    @discardableResult
    public static func writeBack(original: AppCarve, reviewed: AppCarve, item: AppPlanItem) throws -> Bool {
        guard original != reviewed else { return false }
        let entry = item.local.entry
        return try edit(root: item.repo.root) { manifest in
            guard let i = manifest.apps?.firstIndex(where: { $0.stdName == entry.stdName }) else { return }
            if reviewed.desc != original.desc { manifest.apps![i].desc = reviewed.desc }
            if reviewed.types != original.types { manifest.apps![i].types = reviewed.types }
            if reviewed.localNames != original.localNames { manifest.apps![i].localNames = reviewed.localNames }
            if reviewed.protocols != original.protocols {
                manifest.apps![i].protocols = refs(reviewed.protocols, offered: original.protocols, as: entry.protocols ?? [])
            }
            if reviewed.codes != original.codes {
                manifest.apps![i].codes = refs(reviewed.codes, offered: original.codes, as: entry.codes ?? [])
            }
        }
    }

    /// Ids back to manifest references: an id that was offered keeps the
    /// reference it was resolved from, a new one is written raw.
    static func refs(_ ids: [String]?, offered: [String]?, as manifestRefs: [String]) -> [String]? {
        guard let ids, !ids.isEmpty else { return nil }
        var byId: [String: String] = [:]
        for (id, ref) in zip(offered ?? [], manifestRefs) { byId[id] = ref }
        return ids.map { byId[$0] ?? $0 }
    }

    static func edit(root: URL, _ change: (inout ReleaseManifest) -> Void) throws -> Bool {
        let before = try ReleaseManifest.load(repo: root)
        var after = before
        change(&after)
        guard after != before else { return false }
        try after.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        var data = try encoder.encode(after)
        data.append(0x0A)
        try data.write(to: root.appendingPathComponent(ReleaseManifest.fileName), options: .atomic)
        return true
    }
}
