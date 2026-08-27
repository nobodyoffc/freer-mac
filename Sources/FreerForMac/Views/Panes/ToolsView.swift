import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Crypto tools pane — the Mac port of Android's `tools/` activities:
/// Encrypt, Decrypt, Sign, Verify, Hash, Random. Each tool is a small
/// form over the FCCore/FCDomain primitives; results are click-to-copy.
/// TOTP lives with Secrets (Phase 8.2), not here.
struct ToolsView: View {
    let session: ActiveSession

    private enum Tool: String, CaseIterable, Identifiable {
        case encrypt = "Encrypt"
        case decrypt = "Decrypt"
        case sign = "Sign"
        case verify = "Verify"
        case hash = "Hash"
        case random = "Random"
        var id: String { rawValue }
    }

    @State private var tool: Tool = .encrypt

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            Picker("Tool", selection: $tool) {
                ForEach(Tool.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            ScrollView {
                Group {
                    switch tool {
                    case .encrypt: EncryptToolView(session: session)
                    case .decrypt: DecryptToolView(session: session)
                    case .sign:    SignToolView(session: session)
                    case .verify:  VerifyToolView()
                    case .hash:    HashToolView()
                    case .random:  RandomToolView()
                    }
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }

            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 480)
    }
}

// MARK: - Shared bits
//
// `ToolTextEditor`, `ToolResultTable` and `errorText` live in
// ToolFormControls.swift, shared with ConvertView.

/// Result block: monospaced, click-to-copy, hidden until non-empty.
private struct ToolResult: View {
    let label: String
    let text: String

    var body: some View {
        if !text.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                ScrollView(.horizontal) {
                    CopyableText(text, font: .system(.body, design: .monospaced))
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
    }
}

// MARK: - Encrypt

private struct EncryptToolView: View {
    let session: ActiveSession

    private enum KeyMode: String, CaseIterable, Identifiable {
        case password = "Password"
        case symkey = "Symkey"
        case pubkey = "Pubkey"
        var id: String { rawValue }
    }

    @State private var text = ""
    @State private var key = ""
    @State private var mode: KeyMode = .password
    @State private var hexAsBytes = false
    @State private var result = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Encrypt text").font(.headline)

            ToolTextEditor(placeholder: "Text to be encrypted", text: $text)
            Toggle("Treat text as hex bytes", isOn: $hexAsBytes)

            Picker("Key type", selection: $mode) {
                ForEach(KeyMode.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)

            TextField(keyHint, text: $key)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))

            HStack {
                Button("Encrypt", action: encrypt)
                    .keyboardShortcut(.defaultAction)
                    .disabled(text.isEmpty || key.isEmpty)
                Button("Clear") {
                    text = ""; key = ""; result = ""; error = nil
                    hexAsBytes = false; mode = .password
                }
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }
            ToolResult(label: "Cipher (CryptoDataStr JSON)", text: result)
        }
    }

    private var keyHint: String {
        switch mode {
        case .password: return "Password"
        case .symkey:   return "Symkey — 32 bytes in hex"
        case .pubkey:   return "Public key — 33 bytes in hex"
        }
    }

    private func encrypt() {
        result = ""; error = nil
        let plaintext: Data
        if hexAsBytes {
            guard let bytes = Data(fcHex: text.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                error = "Text is not valid hex"; return
            }
            plaintext = bytes
        } else {
            plaintext = Data(text.utf8)
        }
        do {
            switch mode {
            case .password:
                result = try TextCipher.encryptWithPassword(plaintext, password: Data(key.utf8))
            case .symkey:
                guard let symkey = Data(fcHex: key), symkey.count == 32 else {
                    error = "The symkey should be 32 bytes in hex"; return
                }
                result = try TextCipher.encryptWithSymkey(plaintext, symkey: symkey)
            case .pubkey:
                guard let pubkey = Data(fcHex: key), pubkey.count == 33 else {
                    error = "It is not a public key (33 bytes hex)"; return
                }
                result = try TextCipher.encryptWithPubkey(plaintext, pubkey: pubkey)
            }
        } catch {
            self.error = "Encryption failed: \(errorText(error))"
        }
    }
}

// MARK: - Decrypt

private struct DecryptToolView: View {
    let session: ActiveSession

    @State private var cipher = ""
    @State private var key = ""
    @State private var useMyKey = true
    @State private var toHex = false
    @State private var result = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Decrypt a cipher").font(.headline)

            ToolTextEditor(placeholder: "Cipher (CryptoDataStr JSON)", text: $cipher)

            if session.canSign {
                Toggle("Use my private key (for pubkey-encrypted ciphers)", isOn: $useMyKey)
            }
            if !(session.canSign && useMyKey) {
                TextField("Password, symkey hex, or privkey hex — per the cipher's type", text: $key)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
            }
            Toggle("Show result as hex", isOn: $toHex)

            HStack {
                Button("Decrypt", action: decrypt)
                    .keyboardShortcut(.defaultAction)
                    .disabled(cipher.isEmpty)
                Button("Clear") {
                    cipher = ""; key = ""; result = ""; error = nil; toHex = false
                }
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }
            ToolResult(label: "Plaintext", text: result)
        }
    }

    private func decrypt() {
        result = ""; error = nil
        do {
            let envelope = try TextCipher.parse(cipher)
            let plaintext: Data
            switch envelope.type {
            case "Password":
                guard !key.isEmpty, !(session.canSign && useMyKey) else {
                    error = "This cipher needs its password — uncheck “Use my private key” and type it"
                    return
                }
                plaintext = try TextCipher.decrypt(envelope: envelope, password: Data(key.utf8))
            case "Symkey":
                guard let symkey = Data(fcHex: key), symkey.count == 32 else {
                    error = "This cipher needs its 32-byte symkey in hex"
                    return
                }
                plaintext = try TextCipher.decrypt(envelope: envelope, symkey: symkey)
            case "AsyOneWay", "AsyTwoWay", nil:
                let privkey: Data
                if session.canSign && useMyKey {
                    privkey = try session.livePrikey()
                } else if let parsed = Data(fcHex: key), parsed.count == 32 {
                    privkey = parsed
                } else {
                    error = "This cipher needs a 32-byte private key in hex"
                    return
                }
                plaintext = try AsyOneWayCipher.decrypt(cipherString: cipher, privkey: privkey)
            case .some(let other):
                error = "Unsupported cipher type '\(other)'"
                return
            }
            result = toHex ? plaintext.fcToolsPaneHex : (String(data: plaintext, encoding: .utf8) ?? plaintext.fcToolsPaneHex)
        } catch {
            self.error = "Failed to decrypt: \(errorText(error))"
        }
    }
}

// MARK: - Sign

private struct SignToolView: View {
    let session: ActiveSession

    @State private var message = ""
    @State private var alg: MsgSignature.Alg = .ecdsa
    @State private var symkeyHex = ""
    @State private var result = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Sign a message").font(.headline)

            ToolTextEditor(placeholder: "Text to be signed", text: $message)

            Picker("Algorithm", selection: $alg) {
                Text("ECDSA").tag(MsgSignature.Alg.ecdsa)
                Text("Schnorr").tag(MsgSignature.Alg.schnorr)
                Text("Symkey").tag(MsgSignature.Alg.symkey)
            }
            .pickerStyle(.segmented)

            if alg == .symkey {
                TextField("Symkey — 32 bytes in hex", text: $symkeyHex)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
            } else if !session.canSign {
                Label("Watch-only — the live FID has no private key to sign with", systemImage: "eye")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            HStack {
                Button("Sign", action: sign)
                    .keyboardShortcut(.defaultAction)
                    .disabled(message.isEmpty || (alg != .symkey && !session.canSign))
                Button("Clear") {
                    message = ""; symkeyHex = ""; result = ""; error = nil; alg = .ecdsa
                }
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }
            ToolResult(label: "Signature JSON", text: result)
        }
    }

    private func sign() {
        result = ""; error = nil
        do {
            let signature: MsgSignature
            if alg == .symkey {
                guard let symkey = Data(fcHex: symkeyHex), !symkey.isEmpty else {
                    error = "The symkey should be hex"; return
                }
                signature = MsgSignature.sign(message: message, symkey: symkey)
            } else {
                signature = try MsgSignature.sign(
                    message: message, privkey: session.livePrikey(), alg: alg
                )
            }
            result = signature.toJson()
        } catch {
            self.error = "Failed to sign: \(errorText(error))"
        }
    }
}

// MARK: - Verify

private struct VerifyToolView: View {
    @State private var signatureJson = ""
    @State private var key = ""
    @State private var verdict: Bool?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Verify a signature").font(.headline)

            ToolTextEditor(placeholder: "Signature JSON", text: $signatureJson)

            TextField("Symkey hex (symkey signatures) or FID (when the JSON lacks one)", text: $key)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))

            HStack {
                Button("Verify", action: verify)
                    .keyboardShortcut(.defaultAction)
                    .disabled(signatureJson.isEmpty)
                Button("Clear") {
                    signatureJson = ""; key = ""; verdict = nil; error = nil
                }
                if let verdict {
                    Label(
                        verdict ? "Valid" : "Invalid",
                        systemImage: verdict ? "checkmark.seal.fill" : "xmark.seal.fill"
                    )
                    .foregroundStyle(verdict ? .green : .red)
                }
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }
        }
    }

    private func verify() {
        verdict = nil; error = nil
        do {
            var signature = try MsgSignature.fromJson(signatureJson)
            let trimmedKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
            if signature.alg == .symkey {
                guard let symkey = Data(fcHex: trimmedKey), !symkey.isEmpty else {
                    error = "Symkey (hex) required for a symmetric signature"
                    return
                }
                verdict = signature.verify(symkey: symkey)
            } else {
                // Like Android: a FID typed into the key box fills a
                // missing fid field.
                if signature.fid == nil, !trimmedKey.isEmpty {
                    signature.fid = trimmedKey
                }
                verdict = signature.verify()
            }
        } catch {
            self.error = "Not a valid signature: \(errorText(error))"
            verdict = false
        }
    }
}

// MARK: - Hash

private struct HashToolView: View {
    private enum Algorithm: String, CaseIterable, Identifiable {
        case sha256 = "SHA256"
        case sha256x2 = "SHA256x2"
        case sha1 = "SHA1"
        case md5 = "MD5"
        case keccak256 = "Keccak256"
        case ripemd160 = "RIPEMD160"
        var id: String { rawValue }
    }

    @State private var text = ""
    @State private var algorithm: Algorithm = .sha256
    @State private var asHex = false
    @State private var fileName: String?
    @State private var fileData: Data?
    @State private var result = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Hash text or a file").font(.headline)

            ToolTextEditor(placeholder: "Text to be hashed", text: $text)
                .opacity(fileData == nil ? 1 : 0.5)
                .disabled(fileData != nil)
            Toggle("Treat text as hex bytes", isOn: $asHex)
                .disabled(fileData != nil)

            HStack {
                Button {
                    pickFile()
                } label: {
                    Label(fileName ?? "Hash a file…", systemImage: "doc")
                }
                if fileData != nil {
                    Button("Use text instead") { fileName = nil; fileData = nil }
                }
            }

            Picker("Algorithm", selection: $algorithm) {
                ForEach(Algorithm.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)

            HStack {
                Button("Hash", action: hash)
                    .keyboardShortcut(.defaultAction)
                    .disabled(text.isEmpty && fileData == nil)
                Button("Clear") {
                    text = ""; result = ""; error = nil
                    asHex = false; fileName = nil; fileData = nil
                }
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }
            ToolResult(label: "Digest (hex)", text: result)
        }
    }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            fileData = try Data(contentsOf: url)
            fileName = url.lastPathComponent
            error = nil
        } catch {
            self.error = "Failed to read file: \(error.localizedDescription)"
        }
    }

    private func hash() {
        result = ""; error = nil
        let input: Data
        if let fileData {
            input = fileData
        } else if asHex {
            guard let bytes = Data(fcHex: text.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                error = "Text is not valid hex"; return
            }
            input = bytes
        } else {
            input = Data(text.utf8)
        }
        let digest: Data
        switch algorithm {
        case .sha256:    digest = Hash.sha256(input)
        case .sha256x2:  digest = Hash.doubleSha256(input)
        case .sha1:      digest = Hash.sha1(input)
        case .md5:       digest = Hash.md5(input)
        case .keccak256: digest = Hash.keccak256(input)
        case .ripemd160: digest = Hash.ripemd160(input)
        }
        result = digest.fcToolsPaneHex
    }
}

// MARK: - Random

private struct RandomToolView: View {
    private enum Format: String, CaseIterable, Identifiable {
        case hex = "Hex"
        case base58 = "Base58"
        case base32 = "Base32"
        case integer = "Integer"
        var id: String { rawValue }
    }

    @State private var countText = "32"
    @State private var format: Format = .hex
    @State private var result = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Random bytes").font(.headline)

            HStack {
                TextField("Bytes", text: $countText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 80)
                ForEach([1, 4, 8, 16, 32], id: \.self) { n in
                    Button("\(n)") { countText = "\(n)" }
                        .buttonStyle(.bordered)
                }
            }

            Picker("Format", selection: $format) {
                ForEach(Format.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)

            HStack {
                Button("New", action: generate)
                    .keyboardShortcut(.defaultAction)
                Button("Clear") { result = ""; error = nil; countText = "32" }
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }
            ToolResult(label: "Random value", text: result)
        }
    }

    private func generate() {
        result = ""; error = nil
        guard let count = Int(countText), count > 0, count <= 1024 else {
            error = "Byte count must be between 1 and 1024"
            return
        }
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            error = "SecRandomCopyBytes failed (\(status))"
            return
        }
        switch format {
        case .hex:
            result = bytes.fcToolsPaneHex
        case .base58:
            result = Base58.encode(bytes)
        case .base32:
            result = Base32.encode(bytes)
        case .integer:
            // Java: new BigInteger(1, bytes).toString() — unsigned
            // big-endian decimal.
            result = bytes.reduce(into: "0") { acc, byte in
                acc = decimalMultiplyAdd(acc, by: 256, plus: Int(byte))
            }
        }
    }

    /// Decimal-string arithmetic so a 1024-byte value needs no BigInt
    /// dependency: acc = acc * m + a.
    private func decimalMultiplyAdd(_ decimal: String, by m: Int, plus a: Int) -> String {
        var carry = a
        var digits = Array(decimal.utf8.reversed().map { Int($0 - 48) })
        for i in digits.indices {
            let v = digits[i] * m + carry
            digits[i] = v % 10
            carry = v / 10
        }
        while carry > 0 {
            digits.append(carry % 10)
            carry /= 10
        }
        while digits.count > 1 && digits.last == 0 { digits.removeLast() }
        return String(decoding: digits.reversed().map { UInt8($0 + 48) }, as: UTF8.self)
    }
}

// MARK: - hex helpers

private extension Data {
    var fcToolsPaneHex: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Strict hex → bytes; nil on odd length or non-hex characters.
    init?(fcHex s: String) {
        guard s.count % 2 == 0 else { return nil }
        var data = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let byte = UInt8(s[idx..<next], radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        self = data
    }
}
