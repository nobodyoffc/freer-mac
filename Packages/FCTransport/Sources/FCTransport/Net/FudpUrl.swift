import Foundation

/// Canonical form for a FUDP endpoint, and the parser that gets there —
/// the port of `FapiClient.normalizeUrl` / `parseFudpUrl`.
///
/// **Why a canonical form is load-bearing.** A DOCK address arrives from
/// three places that disagree about spelling: a service record's `API`
/// home value (`fudp://host:port`, sometimes bare `host:port`), the
/// user's own Settings field (always bare `host:port`), and whatever a
/// peer wrote into their `home`. Two of the decisions the send path
/// makes are *equality* decisions — is this DOCK our own, so a put is a
/// plain store rather than a forward? do we already hold a client for
/// it? — and string equality over un-normalised URLs answers both
/// wrongly. The symptom is not an error: it is a message that quietly
/// takes the forwarding path to a server that is already on the other
/// end of the socket.
///
/// So every URL entering the DOCK layer is normalised once, on the way
/// in, and compared only in that form.
public enum FudpUrl {

    /// The port a bare host means. Matches `FapiClient.DEFAULT_PORT`.
    public static let defaultPort: UInt16 = 8500

    public static let scheme = "fudp://"

    /// `host:port` → `fudp://host:port`, with the scheme, any path and
    /// any query stripped, and the default port filled in.
    ///
    /// Returns nil for input that cannot name a host — an empty string,
    /// a malformed port, a hostname with doubled or leading dots. A nil
    /// here is an address we could never have reached, which is why the
    /// callers treat it as "no DOCK" rather than as an error.
    public static func normalize(_ url: String?) -> String? {
        guard let hostPort = self.hostPort(url) else { return nil }
        return "\(scheme)\(hostPort.host):\(hostPort.port)"
    }

    /// The host and port a URL names, ready for a socket.
    public static func hostPort(_ url: String?) -> (host: String, port: UInt16)? {
        guard var text = url?.trimmingCharacters(in: .whitespacesAndNewlines),
              !text.isEmpty
        else { return nil }

        // Any scheme, not just fudp://: a service record may publish
        // its endpoint as https://host:port, and the transport is FUDP
        // either way — the scheme names the API, not the wire.
        if let separator = text.range(of: "://") {
            text = String(text[separator.upperBound...])
        }
        if let slash = text.firstIndex(of: "/") { text = String(text[..<slash]) }
        if let query = text.firstIndex(of: "?") { text = String(text[..<query]) }
        guard !text.isEmpty else { return nil }

        var host = text
        var port = defaultPort
        // `lastIndex` rather than `firstIndex` so a bare IPv6 literal
        // loses only its port, never its address.
        if let colon = text.lastIndex(of: ":") {
            let tail = String(text[text.index(after: colon)...])
            if !tail.isEmpty {
                guard let parsed = UInt16(tail) else { return nil }
                port = parsed
            }
            host = String(text[..<colon])
        }

        guard !host.isEmpty,
              !host.contains(".."),
              !host.hasPrefix("."),
              !host.hasSuffix(".")
        else { return nil }
        return (host, port)
    }

    /// Whether two URLs name the same endpoint, whatever they were
    /// spelled like. Un-normalisable input never matches anything —
    /// including itself — because an address we cannot parse is not
    /// evidence of anything.
    public static func sameEndpoint(_ lhs: String?, _ rhs: String?) -> Bool {
        guard let a = normalize(lhs), let b = normalize(rhs) else { return false }
        return a == b
    }
}
