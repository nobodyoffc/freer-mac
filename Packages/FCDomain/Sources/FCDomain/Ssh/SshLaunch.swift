import Foundation

/// How to invoke `/usr/bin/ssh` so that it authenticates with our
/// in-process agent and nothing else.
///
/// Kept out of the view so the argument vector and the environment can
/// be asserted in tests. Getting either subtly wrong does not crash —
/// it makes `ssh` quietly fall back to password auth, which looks
/// exactly like "the key feature does not work".
public enum SshLaunch {

    public static let executable = "/usr/bin/ssh"

    /// What ``arguments(for:credential:)`` should make `ssh` authenticate
    /// with. Resolved by the caller from ``SshServer/credentialKind``,
    /// so this enum carries paths rather than policy.
    public enum Credential: Equatable {
        /// Freer's derived key, through Freer's own agent.
        case freerAgent(publicKeyPath: String, socketPath: String)
        /// A private key file the user already has.
        case keyFile(path: String)
        /// Nothing added — `ssh` uses `~/.ssh/config` and the user's
        /// own agent and default keys.
        case systemDefaults
    }

    /// The argument vector, excluding `argv[0]`.
    ///
    /// Four options, each load-bearing:
    ///
    ///   - **`-i <public key>`** — `ssh_config(5)` on `IdentityFile`:
    ///     *"You can also specify a public key file to use the
    ///     corresponding private key that is loaded in ssh-agent(1)
    ///     when the private key file is not present locally."* That
    ///     sentence is why no private key ever has to exist on disk:
    ///     `ssh` reads the `.pub`, then asks the agent to sign.
    ///   - **`IdentitiesOnly=yes`** — without it `ssh` offers every
    ///     key in `~/.ssh` first and can exhaust the server's
    ///     `MaxAuthTries` before it ever reaches ours.
    ///   - **`IdentityAgent=<socket>`** — the one that is easy to think
    ///     redundant with `SSH_AUTH_SOCK` and is not. `ssh_config(5)`:
    ///     *"This option overrides the SSH_AUTH_SOCK environment
    ///     variable."* Anyone running 1Password, Secretive or
    ///     gpg-agent has `IdentityAgent` in `~/.ssh/config`, and
    ///     without this flag their config would win and our agent
    ///     would never be consulted. A command-line `-o` beats the
    ///     config file, so this is the authoritative form.
    ///   - **`AddKeysToAgent=no`** — we are the agent; nothing should
    ///     try to add anything to us (we would refuse anyway).
    ///
    /// Deliberately **not** set: `StrictHostKeyChecking` (the
    /// first-connect fingerprint prompt is a feature, and it is
    /// answered in the PTY), `PreferredAuthentications` and `BatchMode`
    /// (password fallback is the entire first-run story — you log in
    /// by password once, paste the key, and the next connection is
    /// keyless).
    /// - Note: the four options above apply to ``Credential/freerAgent``
    ///   only. For a key file we pass `-i` and `IdentitiesOnly=yes` but
    ///   **not** `IdentityAgent`, so the user's own agent still answers
    ///   for a `ProxyJump` hop and a passphrase prompt lands in the
    ///   terminal. For ``Credential/systemDefaults`` we add nothing at
    ///   all: the whole point is to let `ssh` behave as it would from a
    ///   shell, so any option we injected would be an option the user
    ///   did not ask for and cannot see.
    public static func arguments(for server: SshServer, credential: Credential) -> [String] {
        var args: [String] = []

        switch credential {
        case let .freerAgent(publicKeyPath, socketPath):
            args += [
                "-i", publicKeyPath,
                "-o", "IdentitiesOnly=yes",
                "-o", "AddKeysToAgent=no",
                "-o", "IdentityAgent=\(socketPath)"
            ]
        case let .keyFile(path):
            args += [
                "-i", path,
                "-o", "IdentitiesOnly=yes",
                "-o", "AddKeysToAgent=no"
            ]
        case .systemDefaults:
            break
        }

        if server.port != 22 {
            args += ["-p", String(server.port)]
        }
        args.append("\(server.user)@\(server.host)")
        return args
    }

    /// The child's environment, as `KEY=VALUE` strings.
    ///
    /// **Built from scratch on purpose.** SwiftTerm's `startProcess`
    /// hands this array straight to `execve` as `envp` — it replaces
    /// the environment rather than merging into it — and its own
    /// default helper deliberately omits `PATH`. So everything the
    /// child needs has to be listed here.
    ///
    /// `HOME` is the one that would be missed: it is where `ssh` looks
    /// for `~/.ssh/config` and `~/.ssh/known_hosts`, and without it the
    /// host-key prompt would recur on every connection.
    ///
    /// `DISPLAY` and `SSH_ASKPASS` are **omitted on purpose**: with
    /// those set, `ssh` may decide to pop a GUI password panel instead
    /// of prompting on the terminal it was given. We have a real TTY;
    /// keep the prompt in it.
    public static func environment(credential: Credential) -> [String] {
        let source = ProcessInfo.processInfo.environment

        // Honour the user's locale when it can carry UTF-8, since it
        // reaches the remote shell and decides how it renders. A
        // non-UTF-8 locale would mangle box drawing and CJK.
        let lang = source["LANG"].flatMap { $0.uppercased().contains("UTF-8") ? $0 : nil }
            ?? "en_US.UTF-8"

        var env = [
            "TERM=xterm-256color",          // must match TerminalOptions.termName
            "COLORTERM=truecolor",
            "LANG=\(lang)",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME=\(NSHomeDirectory())"
        ]

        switch credential {
        case let .freerAgent(_, socketPath):
            // For ProxyJump hops, which re-exec ssh without our -o flags.
            env.append("SSH_AUTH_SOCK=\(socketPath)")
        case .keyFile, .systemDefaults:
            // Hand the user's own agent through untouched. Overwriting
            // it here would break exactly the setups these two modes
            // exist to support.
            if let existing = source["SSH_AUTH_SOCK"] {
                env.append("SSH_AUTH_SOCK=\(existing)")
            }
        }

        for key in ["USER", "LOGNAME", "TMPDIR", "SHELL"] {
            if let value = source[key] { env.append("\(key)=\(value)") }
        }
        return env
    }

    /// Whether `/usr/bin/ssh` is actually there and runnable.
    ///
    /// Worth checking before spawning because the failure mode
    /// otherwise is silent: SwiftTerm's `startProcess` returns without
    /// error if `forkpty` or the exec fails, and no delegate callback
    /// ever fires.
    public static var sshIsAvailable: Bool {
        FileManager.default.isExecutableFile(atPath: executable)
    }

    /// Turn the raw status SwiftTerm reports into something a human can
    /// read.
    ///
    /// **This is a `waitpid` status, not an exit code.** SwiftTerm's
    /// `LocalProcess` calls `waitpid` and passes the status word
    /// straight through to the delegate, so `ssh` exiting 255 arrives
    /// as 65280 (`255 << 8`). Printing it raw is how "weird number in
    /// the status bar" bug reports happen.
    public static func exitDescription(rawStatus: Int32?) -> String {
        guard let status = rawStatus else { return "Disconnected." }
        if status & 0x7f == 0 {
            let code = (status >> 8) & 0xff
            if code == 0 { return "Session ended." }
            // 255 is ssh's own catch-all for a connection that never
            // established — bad host, refused, auth exhausted.
            if code == 255 { return "ssh could not connect (exit 255)." }
            return "Session ended with exit code \(code)."
        }
        let signal = status & 0x7f
        return "Session killed by signal \(signal)."
    }
}
