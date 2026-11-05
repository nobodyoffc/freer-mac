import Foundation

/// Merging a HAT that arrives from elsewhere — an export from another
/// device, a record pasted in — into the one already held for the same
/// DID. Mirror of `Hat.mergeImport` in FC-AJDK `Hat.java`.
///
/// An import used to *replace* the held record, which could silently
/// drop the `cipherIds` and `key` that reach the user's encrypted
/// backups, or a name they chose. Merging loses nothing:
///
/// - `name` stays, unless it is missing or still the did-prefix
///   placeholder;
/// - every other single-valued field is only filled when missing — two
///   records with one DID describe the same bytes, so what is held is
///   kept;
/// - `aids`, `pids`, `locas` and `cipherIds` are unioned, held entries
///   first;
/// - `Leaked` is true if either side says so;
/// - `last` only moves forward.
///
/// The incoming record's `local://` entries are always dropped: they are
/// paths on the device that exported it, never a copy on this one.
extension Hat {

    public static func mergeImport(_ existing: Hat?, _ incoming: Hat) -> Hat {
        var incoming = incoming
        incoming.locas = union(nil, incoming.locas?.filter { !$0.hasPrefix(localLocationPrefix) })
        guard var out = existing else { return incoming }

        if let id = out.id, blankToNil(out.name) == nil || out.name == String(id.prefix(8)) {
            out.name = incoming.name ?? out.name
        }
        out.hAlg = out.hAlg ?? incoming.hAlg
        out.size = out.size ?? incoming.size
        out.born = out.born ?? incoming.born
        if let l = incoming.last, (out.last ?? Int64.min) < l { out.last = l }
        if blankToNil(out.desc) == nil { out.desc = incoming.desc }
        if out.types?.isEmpty ?? true { out.types = incoming.types }
        out.aids = union(out.aids, incoming.aids)
        out.pids = union(out.pids, incoming.pids)
        out.srcDid = out.srcDid ?? incoming.srcDid
        out.preDid = out.preDid ?? incoming.preDid
        out.tDid = out.tDid ?? incoming.tDid
        out.tSize = out.tSize ?? incoming.tSize
        out.offset = out.offset ?? incoming.offset
        out.rawDid = out.rawDid ?? incoming.rawDid
        out.key = out.key ?? incoming.key
        out.kCipher = out.kCipher ?? incoming.kCipher
        if out.leaked == true || incoming.leaked == true { out.leaked = true }
        else { out.leaked = out.leaked ?? incoming.leaked }
        out.cipherIds = union(out.cipherIds, incoming.cipherIds)
        out.rank = out.rank ?? incoming.rank
        out.state = out.state ?? incoming.state
        out.locas = union(out.locas, incoming.locas)
        return out
    }
}
