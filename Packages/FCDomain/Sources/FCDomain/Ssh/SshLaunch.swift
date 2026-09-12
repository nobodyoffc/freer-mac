import Foundation

/// How to invoke `/usr/bin/ssh` — and its siblings `scp` and `sftp` —
/// so that they authenticate with our in-process agent and nothing
/// else.
///
/// Kept out of the view so the argument vector and the environment can
/// be asserted in tests. Getting either subtly wrong does not crash —
/// it makes `ssh` quietly fall back to password auth, which looks
/// exactly like "the key feature does not work".
public enum SshLaunch {

    public static let executable = "/usr/bin/ssh"
    public static let scpExecutable = "/usr/bin/scp"
    public static let sftpExecutable = "/usr/bin/sftp"

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

    /// What one session runs on its server.
    ///
    /// **Every kind runs in a PTY, in a tab, as a session like any
    /// other.** Two reasons, both of which a background `Process` would
    /// break: a password, a host-key prompt or a key passphrase can only
    /// be answered on a terminal (without one, `ssh` reaches for
    /// `SSH_ASKPASS`, which we withhold on purpose); and the agent stops
    /// with the last *running* session, so a transfer the session list
    /// did not know about would lose its key halfway through.
    public enum Kind: Equatable, Sendable {
        /// An interactive login shell.
        case shell
        /// Log in once — by password, if that is all the server takes —
        /// and append this line to `~/.ssh/authorized_keys` unless the
        /// key is already there.
        case installKey(authorizedKeysLine: String)
        /// Log in once and delete every `~/.ssh/authorized_keys` line
        /// holding this key, leaving the rest of the file as it was.
        case removeKey(authorizedKeysLine: String)
        /// Interactive `sftp`, started in `~/Downloads` so a `get`
        /// lands somewhere the user will look.
        case sftp
        /// `scp -r` these local paths into a folder on the server that
        /// already exists — see ``normalizedRemoteDirectory(_:)``. Empty,
        /// or `~`, is the home directory.
        case upload(localPaths: [String], remoteDirectory: String = "")
        /// `ssh -N` holding these forwards open, and nothing else.
        case tunnel([SshPortForward])
    }

    /// One program to start: which binary, with what, and where.
    public struct Invocation: Equatable, Sendable {
        public let executable: String
        public let arguments: [String]
        /// Only `sftp` has a use for this — its `get` writes here — but
        /// every kind gets one, since the app's own working directory is
        /// `/` inside a bundle and whatever the shell was under `swift run`.
        public let currentDirectory: String

        /// `argv[0]`, so `ps` shows `scp` and not the full path.
        public var execName: String {
            (executable as NSString).lastPathComponent
        }

        /// The invocation as a line you could paste into a shell —
        /// quoted, because the install command is itself a quoted script
        /// and a naive join would print something that does not run.
        public var commandLine: String {
            ([execName] + arguments).map(SshLaunch.shellQuoted).joined(separator: " ")
        }
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case unsafeAuthorizedKeysLine
        case nothingToUpload
        case relativeUploadPath(String)
        case badRemoteDirectory
        case badForwards(String)

        public var description: String {
            switch self {
            case .unsafeAuthorizedKeysLine:
                return "The key line holds characters that cannot be sent safely inside a remote command."
            case .nothingToUpload:
                return "Nothing to upload."
            case let .relativeUploadPath(path):
                return "\(path) is not an absolute path."
            case .badRemoteDirectory:
                return "The folder on the server cannot contain line breaks or other control characters."
            case let .badForwards(reason):
                return reason
            }
        }
    }

    // MARK: - Invocations

    /// The program, arguments and directory for one kind of session.
    public static func invocation(
        _ kind: Kind,
        server: SshServer,
        credential: Credential
    ) throws -> Invocation {
        let home = NSHomeDirectory()
        switch kind {
        case .shell:
            return Invocation(
                executable: executable,
                arguments: arguments(for: server, credential: credential),
                currentDirectory: home
            )

        case let .installKey(line):
            // No `-t`: the password prompt is read from the local tty
            // whether or not the remote side gets one, and a remote pty
            // would only add `\r` to the script's output.
            return Invocation(
                executable: executable,
                arguments: arguments(for: server, credential: credential)
                    + [try installKeyRemoteCommand(authorizedKeysLine: line)],
                currentDirectory: home
            )

        case let .removeKey(line):
            // The install's shape, for the install's reasons.
            return Invocation(
                executable: executable,
                arguments: arguments(for: server, credential: credential)
                    + [try removeKeyRemoteCommand(authorizedKeysLine: line)],
                currentDirectory: home
            )

        case .sftp:
            return Invocation(
                executable: sftpExecutable,
                arguments: credentialOptions(credential)
                    + portOptions(server, flag: "-P")
                    + [fileTransferTarget(server)],
                currentDirectory: downloadsDirectory()
            )

        case let .upload(paths, remoteDirectory):
            guard !paths.isEmpty else { throw Failure.nothingToUpload }
            // Absolute paths are what make the argument list
            // unambiguous: `scp` reads anything with a colon before its
            // first slash as `host:path`, so a local file called
            // `a:b` would be fetched from a machine named `a`. A leading
            // `/` also means no path can be read as an option.
            if let relative = paths.first(where: { !$0.hasPrefix("/") }) {
                throw Failure.relativeUploadPath(relative)
            }
            let directory = try normalizedRemoteDirectory(remoteDirectory)
            // `-s` is SFTP, scp's default since OpenSSH 9.0 — spelled out
            // because the destination field depends on it. The legacy
            // protocol hands the remote path to the login shell, where a
            // space splits it and a `$` expands; over SFTP it arrives as
            // typed. `-r` is harmless on plain files and required for
            // folders, so it is always passed rather than decided per drop.
            return Invocation(
                executable: scpExecutable,
                arguments: credentialOptions(credential)
                    + portOptions(server, flag: "-P")
                    + ["-s", "-r", "--"]
                    + paths
                    + [fileTransferTarget(server) + ":" + directory],
                currentDirectory: home
            )

        case let .tunnel(forwards):
            guard !forwards.isEmpty else { throw Failure.badForwards("A tunnel needs at least one port forward.") }
            if let error = SshPortForward.firstProblem(in: forwards) { throw Failure.badForwards(error) }
            // `ExitOnForwardFailure`: without it a port already taken on
            // this Mac is a warning scrolled past, and the tab sits
            // there "connected", forwarding nothing.
            var args = credentialOptions(credential) + ["-N", "-o", "ExitOnForwardFailure=yes"]
            for forward in forwards {
                args += ["-L", forward.specification]
            }
            args += portOptions(server, flag: "-p")
            args.append("\(server.user)@\(server.host)")
            return Invocation(executable: executable, arguments: args, currentDirectory: home)
        }
    }

    /// The argument vector for a login shell, excluding `argv[0]`.
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
    /// by password once, install the key, and the next connection is
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
        credentialOptions(credential)
            + portOptions(server, flag: "-p")
            + ["\(server.user)@\(server.host)"]
    }

    /// The credential half of every invocation. `scp` and `sftp` take
    /// `-i` and `-o` exactly as `ssh` does and pass them straight
    /// through, so one list serves all three.
    private static func credentialOptions(_ credential: Credential) -> [String] {
        switch credential {
        case let .freerAgent(publicKeyPath, socketPath):
            return [
                "-i", publicKeyPath,
                "-o", "IdentitiesOnly=yes",
                "-o", "AddKeysToAgent=no",
                "-o", "IdentityAgent=\(socketPath)"
            ]
        case let .keyFile(path):
            return [
                "-i", path,
                "-o", "IdentitiesOnly=yes",
                "-o", "AddKeysToAgent=no"
            ]
        case .systemDefaults:
            return []
        }
    }

    /// Omitted for 22, so `~/.ssh/config` can say otherwise.
    ///
    /// **The flag is a parameter because it differs, and the wrong one
    /// is silent.** `ssh` takes `-p`; `scp` and `sftp` take `-P`. To
    /// `scp`, `-p` means "preserve modification times" — so reusing the
    /// ssh spelling would upload happily to port 22 of the same host
    /// name, or fail against the wrong daemon, and never mention the
    /// port at all.
    private static func portOptions(_ server: SshServer, flag: String) -> [String] {
        server.port == 22 ? [] : [flag, String(server.port)]
    }

    /// `user@host` for `scp` and `sftp`, which split `host:path` on the
    /// colon and so need an IPv6 literal in brackets. `ssh` does not,
    /// and is handed the host unchanged.
    private static func fileTransferTarget(_ server: SshServer) -> String {
        "\(server.user)@\(SshPortForward.bracketed(server.host))"
    }

    /// An upload's destination as scp's target path.
    ///
    /// **Always a directory, and one that must exist.** The trailing
    /// slash is what makes it so: without one, a single file sent to a
    /// folder name that is not there is written *as* that name — the
    /// PDF quietly becomes a file called `backups` — whereas with it
    /// scp stops and says the path does not exist. `~` and the empty
    /// string both become the empty path, which is the home directory
    /// with or without the server's `expand-path` extension.
    ///
    /// Control characters are refused: nothing a person types into a
    /// folder field contains one, and a newline in a remote path is a
    /// file nobody can find again.
    public static func normalizedRemoteDirectory(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw Failure.badRemoteDirectory
        }
        if trimmed.isEmpty || trimmed == "~" || trimmed == "~/" { return "" }
        return trimmed.hasSuffix("/") ? trimmed : trimmed + "/"
    }

    /// The path in an OSC 7 working-directory report, or nil.
    ///
    /// The report is `file://host/path`, percent-encoded. The host is
    /// the remote machine's own name for itself and adds nothing the
    /// server entry does not say, so only the path is kept. A bare
    /// absolute path is accepted too, since not every shell snippet
    /// bothers with the URL. It is remote-controlled text, so anything
    /// that decodes to a control character is dropped.
    public static func reportedDirectory(_ report: String) -> String? {
        var text = report
        if text.hasPrefix("file://") {
            text.removeFirst("file://".count)
            guard let slash = text.firstIndex(of: "/") else { return nil }
            text = String(text[slash...])
        }
        guard text.hasPrefix("/") else { return nil }
        let path = text.removingPercentEncoding ?? text
        guard !path.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { return nil }
        return path
    }

    private static func downloadsDirectory() -> String {
        let fm = FileManager.default
        if let url = fm.urls(for: .downloadsDirectory, in: .userDomainMask).first,
           fm.fileExists(atPath: url.path) {
            return url.path
        }
        return NSHomeDirectory()
    }

    // MARK: - Installing the key

    /// The remote command that puts one `authorized_keys` line in place.
    ///
    /// Wrapped as `exec sh -c '<script>'` because `ssh` hands a remote
    /// command to the user's **login shell**, which may be fish or
    /// tcsh, where `2>/dev/null` and `$(…)` mean something else or
    /// nothing. Every such shell passes a single-quoted word through
    /// untouched, so the script inside must contain no single quote, no
    /// backslash and no newline — which is why the key line is
    /// validated against a character set before it is spliced in.
    ///
    /// What the script does, in the order that matters:
    ///   - **Idempotent on the key, not the line.** It greps for
    ///     `type blob`, so the same key under another comment — or
    ///     behind an `options` prefix someone added by hand — counts as
    ///     installed and is not added twice.
    ///   - **Newline before append.** A file whose last line has no
    ///     newline would otherwise glue our key onto the end of someone
    ///     else's, breaking both. `ssh-copy-id` checks the same thing.
    ///   - **`umask 077` and the two `chmod`s.** `sshd`'s `StrictModes`
    ///     ignores an `authorized_keys` that group or others can write,
    ///     and says so only in the server's log.
    ///   - **`restorecon`** where it exists: on SELinux a freshly made
    ///     `~/.ssh` gets the wrong label and key auth fails the same
    ///     quiet way.
    static func installKeyRemoteCommand(authorizedKeysLine line: String) throws -> String {
        let key = try checkedKey(line)
        let file = ".ssh/authorized_keys"
        let script = [
            "cd || exit 1",
            "umask 077",
            "mkdir -p .ssh || exit 1",
            "if grep -qF \"\(key)\" \(file) 2>/dev/null; then echo \"The key was already in ~/\(file).\"; exit 0; fi",
            "if [ -s \(file) ] && [ -n \"$(tail -c 1 \(file))\" ]; then echo >> \(file) || exit 1; fi",
            "echo \"\(line)\" >> \(file) || exit 1",
            "chmod 700 .ssh",
            "chmod 600 \(file)",
            "if command -v restorecon >/dev/null 2>&1; then restorecon -F .ssh \(file); fi",
            "echo \"Key added to ~/\(file).\""
        ].joined(separator: "; ")
        return "exec sh -c '\(script)'"
    }

    /// `type blob` from a key line that is safe to splice into a
    /// single-quoted script — no quote, backslash, `$`, backtick or
    /// newline can get through the character set.
    private static func checkedKey(_ line: String) throws -> String {
        let allowed = CharacterSet(
            charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=:@._- "
        )
        let fields = line.split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count >= 2,
              !fields.contains(where: \.isEmpty),
              line.unicodeScalars.allSatisfy(allowed.contains)
        else { throw Failure.unsafeAuthorizedKeysLine }
        return "\(fields[0]) \(fields[1])"
    }

    // MARK: - Removing the key

    /// The remote command that takes every `authorized_keys` line
    /// holding this key out, and leaves every other line as it was.
    ///
    /// Wrapped and checked exactly as the install is. What the script
    /// does, in the order that matters:
    ///   - **Matches the key, not the line**, with the install's own
    ///     grep — so a key the install would call present is one this
    ///     takes out, under any comment and behind any options.
    ///   - **"Not there" is success**, and says which: no file, or no
    ///     such line. A file it cannot read is a failure, not absence.
    ///   - **Rewrites in place — `cat tmp > file`, never `mv`.** A
    ///     rename puts a new inode where the old one was: it drops the
    ///     SELinux label, turns a symlinked `authorized_keys` (config
    ///     management does this) into a plain file, and hands the owner
    ///     to whoever ran it. Writing through the existing file keeps
    ///     all of that, and the mode.
    ///   - **Nothing is truncated until the new contents exist.** The
    ///     filtered copy goes to a temp file beside it first, so a full
    ///     disk fails there with the original untouched; the rewrite
    ///     after it is shorter by at least a line and needs no space
    ///     the file does not already hold. Should the rewrite fail
    ///     anyway, the temp file is kept and named — by then it is the
    ///     only complete copy.
    ///   - **`grep -v` exits 1 when it prints nothing**, which is what
    ///     happens when ours was the only key. Only 2 is an error.
    ///
    /// Only `~/.ssh/authorized_keys`, the file the install writes. A
    /// copy in `authorized_keys2`, or under a custom
    /// `AuthorizedKeysFile`, is not looked for.
    static func removeKeyRemoteCommand(authorizedKeysLine line: String) throws -> String {
        "exec " + (try removeKeyCommand(authorizedKeysLine: line))
    }

    /// The same removal as a line to paste into a shell you are already
    /// in. No `exec`: that would replace the shell and end the session
    /// the moment the script finished. The script's `cd` and `exit`
    /// happen inside `sh -c` and leave the shell where it was.
    public static func removeKeyCommand(authorizedKeysLine line: String) throws -> String {
        let key = try checkedKey(line)
        let file = ".ssh/authorized_keys"
        let script = [
            "cd || exit 1",
            "umask 077",
            "f=\(file)",
            "[ -e $f ] || { echo \"There is no ~/\(file), so the key was not in it.\"; exit 0; }",
            "grep -qF \"\(key)\" $f; s=$?",
            "[ $s -eq 1 ] && { echo \"The key was not in ~/\(file).\"; exit 0; }",
            "[ $s -eq 0 ] || exit 1",
            "[ -w $f ] || { echo \"~/\(file) is not writable.\"; exit 1; }",
            "t=$(mktemp $f.XXXXXX) || exit 1",
            "grep -vF \"\(key)\" $f > \"$t\"",
            "[ $? -le 1 ] || { rm -f \"$t\"; exit 1; }",
            "cat \"$t\" > $f || { echo \"Could not rewrite ~/\(file). What it should hold is in ~/$t.\"; exit 1; }",
            "rm -f \"$t\"",
            "echo \"Key removed from ~/\(file).\""
        ].joined(separator: "; ")
        return "sh -c '\(script)'"
    }

    /// POSIX single-quoting, only where it is needed.
    static func shellQuoted(_ word: String) -> String {
        let plain = CharacterSet(
            charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-"
        )
        if !word.isEmpty, word.unicodeScalars.allSatisfy(plain.contains) { return word }
        return "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    // MARK: - Environment

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
    /// host-key prompt would recur on every connection. `PATH` matters
    /// more for `scp` and `sftp` than for `ssh`: both find the `ssh`
    /// they run through it.
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

    // MARK: - Status

    /// Whether `/usr/bin/ssh` is actually there and runnable.
    public static var sshIsAvailable: Bool {
        isAvailable(executable)
    }

    /// Worth checking before spawning because the failure mode
    /// otherwise is silent: SwiftTerm's `startProcess` returns without
    /// error if `forkpty` or the exec fails, and no delegate callback
    /// ever fires.
    public static func isAvailable(_ path: String) -> Bool {
        FileManager.default.isExecutableFile(atPath: path)
    }

    /// Turn the raw status SwiftTerm reports into something a human can
    /// read.
    ///
    /// **This is a `waitpid` status, not an exit code.** SwiftTerm's
    /// `LocalProcess` calls `waitpid` and passes the status word
    /// straight through to the delegate, so `ssh` exiting 255 arrives
    /// as 65280 (`255 << 8`). Printing it raw is how "weird number in
    /// the status bar" bug reports happen.
    public static func exitDescription(rawStatus: Int32?, kind: Kind = .shell) -> String {
        guard let status = rawStatus else { return "Disconnected." }
        guard status & 0x7f == 0 else {
            return "Session killed by signal \(status & 0x7f)."
        }
        let code = (status >> 8) & 0xff
        switch kind {
        case .shell:
            if code == 0 { return "Session ended." }
            // 255 is ssh's own catch-all for a connection that never
            // established — bad host, refused, auth exhausted.
            if code == 255 { return "ssh could not connect (exit 255)." }
            return "Session ended with exit code \(code)."
        case .installKey:
            if code == 0 { return "The key is in the server's authorized_keys." }
            if code == 255 {
                return "ssh could not log in (exit 255). The server has to accept a password, or a key you already have, this once."
            }
            return "Could not install the key (exit \(code))."
        case .removeKey:
            if code == 0 { return "The Freer key is not in the server's authorized_keys." }
            if code == 255 { return "ssh could not log in (exit 255)." }
            return "Could not remove the key (exit \(code))."
        case .sftp:
            if code == 0 { return "SFTP session ended." }
            if code == 255 { return "sftp could not connect (exit 255)." }
            return "SFTP session ended with exit code \(code)."
        case let .upload(_, directory):
            // scp says 1 for everything from a refused login to one
            // unreadable file; the reason is on the line above. A
            // missing folder gets named because, once there is a field
            // to mistype it in, it is the likeliest of them.
            let folder = directory.trimmingCharacters(in: .whitespaces)
            let isHome = folder.isEmpty || folder == "~" || folder == "~/"
            if code == 0 {
                return isHome
                    ? "Upload finished — the files are in your home directory on the server."
                    : "Upload finished — the files are in \(folder) on the server."
            }
            return isHome
                ? "Upload failed (exit \(code))."
                : "Upload failed (exit \(code)). scp does not create folders — check that \(folder) exists."
        case .tunnel:
            if code == 0 { return "Tunnel closed." }
            if code == 255 {
                return "ssh could not connect, or could not open a forward — is the local port already in use? (exit 255)"
            }
            return "Tunnel closed with exit code \(code)."
        }
    }
}
