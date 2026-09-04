import Foundation

/// One saved SSH destination.
///
/// Deliberately thin: host, port, user and a label. Everything else
/// `ssh` already knows how to read out of `~/.ssh/config`, and
/// re-implementing `Host` aliases, `ProxyJump` or per-host key
/// algorithms here would be a worse copy of a file the user may
/// already maintain. `host` is passed to `ssh` verbatim, so a
/// `~/.ssh/config` alias works as a host and brings its own settings
/// with it.
///
/// Stored in ``SshServersStore``, whose rows are AES-256-GCM encrypted
/// at rest like every other row in the vault — so the list of machines
/// a user administers is not readable from the SQLite file.
public struct SshServer: Codable, Equatable, Hashable, Sendable, Identifiable {

    /// A UUID string, **not** `user@host:port`.
    ///
    /// Two entries for one machine is a legitimate thing to want — the
    /// same box as `root` and as a service account, or one entry per
    /// project on a shared host — and a natural key would silently
    /// merge them on save.
    public var id: String

    /// What the list shows. Falls back to ``target`` when empty, so a
    /// user who does not want to name things never has to.
    public var label: String

    /// Hostname, IP, or a `Host` alias from `~/.ssh/config`.
    public var host: String

    /// Omitted from the command line when 22, so `ssh` uses whatever
    /// `~/.ssh/config` says.
    public var port: Int

    /// Remote login name.
    public var user: String

    public var memo: String?

    /// Which credential opens this server. **Optional so old rows keep
    /// decoding** — a non-optional field added to a `Codable` struct
    /// makes every row written before it fail to decode, which here
    /// would silently empty the server list. Read it through
    /// ``credentialKind``, never directly.
    public var identity: Identity?

    public var pinnedAt: Date?

    /// Drives the default sort — the box you used last is the one you
    /// most likely want next.
    public var lastUsedAt: Date?

    public var addedAt: Date
    public var updatedAt: Date

    public init(
        id: String = UUID().uuidString,
        label: String = "",
        host: String,
        port: Int = 22,
        user: String,
        memo: String? = nil,
        identity: Identity? = nil,
        pinnedAt: Date? = nil,
        lastUsedAt: Date? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.label = label
        self.host = host
        self.port = port
        self.user = user
        self.memo = memo
        self.identity = identity
        self.pinnedAt = pinnedAt
        self.lastUsedAt = lastUsedAt
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }

    /// `user@host`, with `:port` only when it is not the default.
    public var target: String {
        port == 22 ? "\(user)@\(host)" : "\(user)@\(host):\(port)"
    }

    /// Display name — label if there is one, else the target. Mirrors
    /// ``Contact/name``.
    public var name: String {
        label.isEmpty ? target : label
    }

    /// What this server authenticates with, with the default applied.
    public var credentialKind: Identity {
        identity ?? .freer
    }

    /// Which private key opens a server.
    ///
    /// The Freer key is the point of this pane, but it is not the only
    /// key anyone has: a machine you already administer has your own
    /// key in its `authorized_keys`, and telling you to install a
    /// second one just to use this terminal would be the app putting
    /// itself first. So the derived key is the default, not the rule.
    public enum Identity: Codable, Equatable, Hashable, Sendable {

        /// The ed25519 key derived from the main FID, served by Freer's
        /// own in-process agent. Nothing is written to disk.
        case freer

        /// A private key file you already have, usually under `~/.ssh`.
        /// Freer's agent is not started at all for these — `ssh` reads
        /// the file itself, and prompts in the terminal if it has a
        /// passphrase.
        case keyFile(path: String)

        /// Whatever `ssh` would do on its own: your `~/.ssh/config`,
        /// your default keys, your own agent. Freer adds no options.
        case systemDefaults

        /// Short label for the list and the picker.
        public var summary: String {
            switch self {
            case .freer: return "Freer key"
            case let .keyFile(path): return (path as NSString).lastPathComponent
            case .systemDefaults: return "System ssh"
            }
        }
    }
}
