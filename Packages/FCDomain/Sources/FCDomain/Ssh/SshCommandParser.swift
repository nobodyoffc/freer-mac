import Foundation

/// Reads a pasted `ssh` command line back into the fields of an
/// ``SshServer``.
///
/// **The command line is the format people already have.** A server
/// arrives from a provider's console, a colleague's message or a
/// project README as one line — `ssh -p 50227 -i ~/.ssh/box user@host`
/// — and retyping it into four fields is four chances to transpose a
/// digit of a port that will then fail with nothing but a timeout. So
/// the line is parsed once and the fields are filled in, where they
/// stay editable: this is a shortcut into the editor, not a second way
/// to save a server.
///
/// **What it understands is what an ``SshServer`` can hold.** Host,
/// user, port, identity file and `-L` forwards map onto stored fields;
/// everything else `ssh` accepts is reported in ``Parsed/ignored`` so
/// the pane can say what was dropped rather than pretend the whole
/// line was honoured. That matters most for `-J`: a jump host silently
/// discarded would leave a server entry that cannot reach its box at
/// all (put the `ProxyJump` in `~/.ssh/config` and the alias as the
/// host instead — see ``SshServer``).
public enum SshCommandParser {

    /// What one pasted line said, in the editor's terms.
    public struct Parsed: Equatable {
        public var host: String
        public var user: String?
        /// Nil when the line named no port, so the editor keeps its own
        /// default rather than writing 22 over a field the user set.
        public var port: Int?
        /// As typed, `~` included — ``SshLaunch`` is handed an expanded
        /// path at connect time, and a stored `~` survives a different
        /// home directory.
        public var identityFile: String?
        public var forwards: [SshPortForward]
        /// Options that were understood as options but cannot be
        /// stored, each as a short phrase for the UI ("jump host -J
        /// bastion").
        public var ignored: [String]

        public init(
            host: String,
            user: String? = nil,
            port: Int? = nil,
            identityFile: String? = nil,
            forwards: [SshPortForward] = [],
            ignored: [String] = []
        ) {
            self.host = host
            self.user = user
            self.port = port
            self.identityFile = identityFile
            self.forwards = forwards
            self.ignored = ignored
        }
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case empty
        case unbalancedQuote
        case noHost
        case missingValue(String)
        case badPort(String)
        case badForward(String)

        public var description: String {
            switch self {
            case .empty:
                return "Paste an ssh command, like ssh -p 22 user@host."
            case .unbalancedQuote:
                return "There is an opening quote with no closing one."
            case .noHost:
                return "No host in that line — it needs a user@host or a host."
            case let .missingValue(flag):
                return "\(flag) is there with nothing after it."
            case let .badPort(text):
                return "\"\(text)\" is not a port from 1 to 65535."
            case let .badForward(text):
                return "-L \(text) is not a forward this can store: local:host:remote."
            }
        }
    }

    /// `ssh` flags that take the next word as their value. Getting this
    /// list wrong is what makes a parser eat the host: `-o` followed by
    /// `StrictHostKeyChecking=no` and then `user@host` reads the option
    /// value as the target unless `-o` is known to consume one.
    private static let flagsWithValue: Set<Character> = [
        "B", "b", "c", "D", "E", "e", "F", "I", "i", "J", "L", "l",
        "m", "O", "o", "P", "p", "Q", "R", "S", "W", "w"
    ]

    /// Flags that stand alone, so `-tt` and `-vvv` bundle. Anything not
    /// in either set is treated as value-less and reported, which is the
    /// safe way to be wrong about a flag from a newer OpenSSH.
    private static let boolFlags: Set<Character> = [
        "4", "6", "A", "a", "C", "f", "G", "g", "K", "k", "M", "N",
        "n", "q", "s", "T", "t", "V", "v", "X", "x", "Y", "y"
    ]

    /// Parse one pasted line.
    ///
    /// The `ssh` word is optional and so is everything before it, which
    /// is what makes a line copied out of a shell history — `$ ssh …`,
    /// `sudo ssh …`, `sshpass -p … ssh …` — parse as the ssh command it
    /// contains rather than as its wrapper's arguments.
    public static func parse(_ text: String) throws -> Parsed {
        var tokens = try tokenize(text)
        guard !tokens.isEmpty else { throw Failure.empty }

        // The **first** `ssh` word, not the last: a remote command can
        // itself be an ssh — `ssh gateway ssh inner` — and stripping to
        // the last one would save the inner box under the gateway's
        // options.
        if let program = tokens.firstIndex(where: { ($0 as NSString).lastPathComponent == "ssh" }) {
            tokens.removeFirst(program + 1)
        }
        guard !tokens.isEmpty else { throw Failure.noHost }

        var parsed = Parsed(host: "")
        var target: String?
        var index = 0

        while index < tokens.count {
            let token = tokens[index]
            index += 1

            if token == "--" { continue }
            guard token.hasPrefix("-"), token.count > 1 else {
                // **Options keep coming after the host.** `ssh` runs
                // its option parser a second time once it has the
                // target, so `ssh box -p 2222` is as valid as `ssh -p
                // 2222 box` — a parser that stopped at the operand
                // would read the port as part of a remote command and
                // save the box on 22. The *second* operand is where
                // the remote command really starts, and it is taken
                // whole, however long.
                guard target == nil else {
                    let command = ([token] + tokens[index...]).joined(separator: " ")
                    parsed.ignored.append("remote command \(command)")
                    break
                }
                target = token
                continue
            }

            var rest = Substring(token.dropFirst())
            while let flag = rest.first {
                rest = rest.dropFirst()
                if flagsWithValue.contains(flag) {
                    // `-p50227` is as legal as `-p 50227`.
                    let value: String
                    if !rest.isEmpty {
                        value = String(rest)
                        rest = ""
                    } else {
                        guard index < tokens.count else { throw Failure.missingValue("-\(flag)") }
                        value = tokens[index]
                        index += 1
                    }
                    try apply(flag: flag, value: value, to: &parsed)
                } else {
                    if !boolFlags.contains(flag) {
                        parsed.ignored.append("-\(flag)")
                    }
                }
            }
        }

        guard let target else { throw Failure.noHost }
        try applyTarget(target, to: &parsed)
        guard !parsed.host.isEmpty else { throw Failure.noHost }
        if let error = SshPortForward.firstProblem(in: parsed.forwards) {
            throw Failure.badForward(error)
        }
        return parsed
    }

    private static func apply(flag: Character, value: String, to parsed: inout Parsed) throws {
        switch flag {
        case "p", "P":
            guard let port = Int(value), (1...65535).contains(port) else { throw Failure.badPort(value) }
            parsed.port = port
        case "l":
            parsed.user = value
        case "i":
            parsed.identityFile = value
        case "L":
            let (forward, narrowed) = try forward(value)
            parsed.forwards.append(forward)
            if let narrowed { parsed.ignored.append(narrowed) }
        case "J":
            parsed.ignored.append("jump host -J \(value)")
        case "R", "D", "W":
            parsed.ignored.append("-\(flag) \(value)")
        case "o":
            parsed.ignored.append("-o \(value)")
        case "F":
            parsed.ignored.append("config file -F \(value)")
        default:
            parsed.ignored.append("-\(flag)")
        }
    }

    /// `-L` in the two shapes that fit our model: `local:host:remote`,
    /// and the four-field form whose bind address we can only honour as
    /// loopback — ``SshPortForward/specification`` always binds
    /// `127.0.0.1`, on purpose, so a `-L 0.0.0.0:…` pasted here is
    /// narrowed rather than obeyed, and says so.
    ///
    /// Unix-socket forwards and `-L port:host:port` with an IPv6 literal
    /// unbracketed are not accepted: both would store something the
    /// tunnel could not open.
    private static func forward(_ spec: String) throws -> (SshPortForward, narrowed: String?) {
        var fields = splitForward(spec)
        var bindAddress: String?
        if fields.count == 4 {
            bindAddress = fields.removeFirst()
        }
        guard fields.count == 3,
              let local = Int(fields[0]), let remote = Int(fields[2]),
              !fields[1].isEmpty
        else { throw Failure.badForward(spec) }
        let narrowed = bindAddress.flatMap { address -> String? in
            let loopback = ["", "localhost", "127.0.0.1", "::1"]
            guard !loopback.contains(address) else { return nil }
            return "bind address \(address) on -L, narrowed to this Mac's loopback"
        }
        return (SshPortForward(localPort: local, remoteHost: fields[1], remotePort: remote), narrowed)
    }

    /// Split on colons, keeping a bracketed IPv6 literal whole.
    private static func splitForward(_ spec: String) -> [String] {
        var fields: [String] = []
        var current = ""
        var depth = 0
        for character in spec {
            switch character {
            case "[": depth += 1; current.append(character)
            case "]": depth -= 1; current.append(character)
            case ":" where depth == 0: fields.append(current); current = ""
            default: current.append(character)
            }
        }
        fields.append(current)
        return fields.map { field in
            field.hasPrefix("[") && field.hasSuffix("]") ? String(field.dropFirst().dropLast()) : field
        }
    }

    /// The operand: `user@host`, a bare host, or an `ssh://` URL.
    ///
    /// Applied after the options, because that is the order `ssh`
    /// resolves them in: given both `-l bob` and `alice@host`, the one
    /// on the target wins and the connection is alice's.
    private static func applyTarget(_ target: String, to parsed: inout Parsed) throws {
        var rest = target
        if let range = rest.range(of: "ssh://") {
            rest = String(rest[range.upperBound...])
            // `ssh://host:port/path` — the path is not ours to keep.
            if let slash = rest.firstIndex(of: "/") { rest = String(rest[..<slash]) }
        }
        if let at = rest.lastIndex(of: "@") {
            let user = String(rest[..<at])
            if !user.isEmpty { parsed.user = user }
            rest = String(rest[rest.index(after: at)...])
        }
        // A port on the target only appears in the URL form; `host:22`
        // without a scheme is not something `ssh` accepts, so a colon
        // outside brackets is only read as a port when there is one
        // colon and digits follow it.
        if rest.hasPrefix("["), let close = rest.firstIndex(of: "]") {
            let literal = String(rest[rest.index(after: rest.startIndex)..<close])
            let after = String(rest[rest.index(after: close)...])
            if after.hasPrefix(":") {
                let text = String(after.dropFirst())
                guard let port = Int(text), (1...65535).contains(port) else { throw Failure.badPort(text) }
                parsed.port = port
            }
            rest = literal
        } else if rest.filter({ $0 == ":" }).count == 1,
                  let colon = rest.firstIndex(of: ":") {
            let text = String(rest[rest.index(after: colon)...])
            guard let port = Int(text), (1...65535).contains(port) else { throw Failure.badPort(text) }
            parsed.port = port
            rest = String(rest[..<colon])
        }
        parsed.host = rest
    }

    /// Split a line the way a shell would: quotes group, a backslash
    /// escapes the next character, and unquoted whitespace separates.
    ///
    /// Not because anything here is executed — the fields end up in a
    /// form, and the argument vector is built from scratch by
    /// ``SshLaunch`` — but because a key path with a space in it is
    /// quoted in the line people paste, and splitting on whitespace
    /// alone would hand `-i` half a path.
    static func tokenize(_ text: String) throws -> [String] {
        var tokens: [String] = []
        var current = ""
        var started = false
        var quote: Character?
        var iterator = text.makeIterator()

        while let character = iterator.next() {
            if let open = quote {
                if character == open {
                    quote = nil
                } else if character == "\\", open == "\"" {
                    if let escaped = iterator.next() { current.append(escaped) }
                } else {
                    current.append(character)
                }
                continue
            }
            switch character {
            case "'", "\"":
                quote = character
                started = true
            case "\\":
                if let escaped = iterator.next(), !escaped.isNewline {
                    current.append(escaped)
                    started = true
                }
            case _ where character.isWhitespace:
                if started { tokens.append(current) }
                current = ""
                started = false
            default:
                current.append(character)
                started = true
            }
        }
        guard quote == nil else { throw Failure.unbalancedQuote }
        if started { tokens.append(current) }

        // A line copied with its prompt: `$ ssh …` or `% ssh …`.
        if let first = tokens.first, first == "$" || first == "%" || first == "#" {
            tokens.removeFirst()
        }
        return tokens
    }
}
