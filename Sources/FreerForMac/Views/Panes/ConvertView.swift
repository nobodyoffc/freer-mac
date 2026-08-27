import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Converter pane — the Mac port of Android's `convert/` activities:
/// Script, Prikey, Pubkey, Address, JSON, String, Time.
///
/// Android ships these as seven separate activities behind a popup
/// menu; here they are seven segments of one pane, the same shape
/// ``ToolsView`` uses for Android's `tools/` activities. Every result
/// is click-to-copy.
struct ConvertView: View {
    let session: ActiveSession

    /// Declaration order matches Android's converter menu.
    private enum Converter: String, CaseIterable, Identifiable {
        case script = "Script"
        case prikey = "Prikey"
        case pubkey = "Pubkey"
        case address = "Address"
        case json = "JSON"
        case string = "String"
        case time = "Time"
        var id: String { rawValue }
    }

    @State private var converter: Converter = .address

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            Picker("Converter", selection: $converter) {
                ForEach(Converter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            ScrollView {
                Group {
                    switch converter {
                    case .script:  ScriptConvertView()
                    case .prikey:  PrikeyConvertView(session: session)
                    case .pubkey:  PubkeyConvertView(session: session)
                    case .address: AddressConvertView(session: session)
                    case .json:    JsonConvertView()
                    case .string:  StringConvertView()
                    case .time:    TimeConvertView()
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

// MARK: - Script

private struct ScriptConvertView: View {
    @State private var input = ""
    @State private var result = ""
    @State private var resultLabel = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Script ⇄ ASM").font(.headline)
            Text("Hex disassembles to ASM; anything else assembles back to hex.")
                .font(.caption)
                .foregroundStyle(.secondary)

            ToolTextEditor(placeholder: "Script hex, or ASM", text: $input, minHeight: 90)

            HStack {
                Button("Convert", action: convert)
                    .keyboardShortcut(.defaultAction)
                    .disabled(input.trimmed.isEmpty)
                Button("Clear") { input = ""; result = ""; error = nil }
            }

            if let error { ConvertError(error) }
            ToolResultTable(rows: result.isEmpty ? [] : [(resultLabel, result)])
        }
    }

    private func convert() {
        result = ""; error = nil
        let text = input.trimmed
        do {
            // A script is hex or it is ASM; nothing legal is both,
            // since ASM always carries opcode names or whitespace.
            if Hex.isHex(text) {
                result = try ScriptAsm.disassemble(try Hex.decode(text))
                resultLabel = "ASM"
            } else {
                result = Hex.encode(try ScriptAsm.assemble(text))
                resultLabel = "Hex"
            }
        } catch {
            self.error = errorText(error)
        }
    }
}

// MARK: - Prikey

private struct PrikeyConvertView: View {
    let session: ActiveSession

    private enum Format: String, CaseIterable, Identifiable {
        case wifCompressed = "WIF compressed"
        case wifUncompressed = "WIF uncompressed"
        case hex = "Hex"
        var id: String { rawValue }
    }

    @State private var input = ""
    @State private var format: Format = .wifCompressed
    @State private var result = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Private key formats").font(.headline)

            Label(
                "A private key is the whole of an identity. Anything shown here spends "
                    + "everything the key holds — don't paste it anywhere you don't control.",
                systemImage: "exclamationmark.triangle"
            )
            .font(.caption)
            .foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)

            TextField("Private key — 64 hex characters, or WIF", text: $input)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))

            if session.canSign {
                Button {
                    useMyKey()
                } label: {
                    Label("Use my private key", systemImage: "key")
                }
                .buttonStyle(.link)
            }

            Picker("Format", selection: $format) {
                ForEach(Format.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)

            HStack {
                Button("Convert", action: convert)
                    .keyboardShortcut(.defaultAction)
                    .disabled(input.trimmed.isEmpty)
                Button("Clear") { input = ""; result = ""; error = nil }
            }

            if let error { ConvertError(error) }
            ToolResultTable(rows: result.isEmpty ? [] : [(format.rawValue, result)])
        }
    }

    private func useMyKey() {
        error = nil
        do {
            input = Hex.encode(try session.livePrikey())
        } catch {
            self.error = errorText(error)
        }
    }

    private func convert() {
        result = ""; error = nil
        do {
            let privkey = try WifPrivkey.privkey32(from: input)
            switch format {
            case .hex:
                result = Hex.encode(privkey)
            case .wifCompressed:
                result = WifPrivkey.encode(privkey: privkey, compressed: true)
            case .wifUncompressed:
                result = WifPrivkey.encode(privkey: privkey, compressed: false)
            }
        } catch {
            self.error = errorText(error)
        }
    }
}

// MARK: - Pubkey

private struct PubkeyConvertView: View {
    let session: ActiveSession

    @State private var input = ""
    @State private var rows: [(String, String)] = []
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Public key formats").font(.headline)

            ToolTextEditor(
                placeholder: "Public key — compressed or uncompressed hex, or Base58",
                text: $input
            )

            if session.liveKeyInfo.pubkey != nil {
                Button {
                    useMyKey()
                } label: {
                    Label("Use my public key", systemImage: "person.crop.circle")
                }
                .buttonStyle(.link)
            }

            HStack {
                Button("Convert", action: convert)
                    .keyboardShortcut(.defaultAction)
                    .disabled(input.trimmed.isEmpty)
                Button("Clear") { input = ""; rows = []; error = nil }
            }

            if let error { ConvertError(error) }
            ToolResultTable(rows: rows)
        }
    }

    private func useMyKey() {
        error = nil
        guard let pubkey = session.liveKeyInfo.pubkey else {
            error = "This identity has no stored public key"
            return
        }
        input = Hex.encode(pubkey)
    }

    private func convert() {
        rows = []; error = nil
        do {
            let pubkey33 = try PubkeyFormats.pubkey33(from: input)
            let wif = try PubkeyFormats.wifForms(ofPubkey33: pubkey33)
            rows = [
                ("FID", try FchAddress(publicKey: try Hex.decode(pubkey33)).fid),
                ("Compressed hex", pubkey33),
                ("Uncompressed hex", try PubkeyFormats.decompress(pubkey33: pubkey33)),
                ("WIF uncompressed", wif.uncompressed),
                ("WIF compressed, version 0", wif.compressedWithVersion0),
                ("WIF compressed, no version", wif.compressedWithoutVersion),
            ]
        } catch {
            self.error = errorText(error)
        }
    }
}

// MARK: - Address

private struct AddressConvertView: View {
    let session: ActiveSession

    @State private var input = ""
    @State private var rows: [(String, String)] = []
    @State private var note: String?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Addresses across chains").font(.headline)

            ToolTextEditor(placeholder: "Public key, or an address", text: $input)

            Button {
                input = session.liveFid
                error = nil
            } label: {
                Label("Use my FID", systemImage: "person.crop.circle")
            }
            .buttonStyle(.link)

            HStack {
                Button("Convert", action: convert)
                    .keyboardShortcut(.defaultAction)
                    .disabled(input.trimmed.isEmpty)
                Button("Clear") { input = ""; rows = []; note = nil; error = nil }
            }

            if let error { ConvertError(error) }
            if let note {
                Text(note)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ToolResultTable(rows: rows)
        }
    }

    private func convert() {
        rows = []; note = nil; error = nil
        let text = input.trimmed
        do {
            if PubkeyFormats.isPubkey(text) || text.count == 50 || text.count == 51 {
                rows = try ChainAddresses.fromPubkey(text).map { ($0.0.rawValue, $0.1) }
            } else {
                let hash160 = try ChainAddresses.hash160(fromAddress: text)
                rows = try ChainAddresses.fromHash160(hash160).map { ($0.0.rawValue, $0.1) }
                // Worth stating plainly: the omission is the correct
                // answer, not a gap. ETH and TRX hash different bytes,
                // so from an address alone there is nothing to derive
                // — and a plausible guess would be unspendable.
                note = "Bitcoin is shown in its segwit form here. ETH and TRX are absent "
                    + "by necessity: their addresses hash the public key itself, which an "
                    + "address does not contain. Convert from the public key to see them."
            }
        } catch {
            self.error = errorText(error)
        }
    }
}

// MARK: - JSON

private struct JsonConvertView: View {
    @State private var input = ""
    @State private var result = ""
    @State private var resultLabel = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("JSON ⇄ formatted").font(.headline)
            Text("Compact JSON expands; expanded JSON compacts. Key order and number "
                 + "literals are preserved exactly.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ToolTextEditor(placeholder: "JSON", text: $input, minHeight: 120)

            HStack {
                Button("Convert", action: convert)
                    .keyboardShortcut(.defaultAction)
                    .disabled(input.trimmed.isEmpty)
                Button("Clear") { input = ""; result = ""; error = nil }
            }

            if let error { ConvertError(error) }
            ToolResultTable(rows: result.isEmpty ? [] : [(resultLabel, result)])
        }
    }

    private func convert() {
        result = ""; error = nil
        do {
            if JsonFormatter.looksPretty(input) {
                result = try JsonFormatter.minify(input)
                resultLabel = "Compact"
            } else {
                result = try JsonFormatter.prettyPrint(input)
                resultLabel = "Formatted"
            }
        } catch {
            self.error = errorText(error)
        }
    }
}

// MARK: - String

private struct StringConvertView: View {
    /// `nil` means auto-detect.
    @State private var encoding: StringCodec.Encoding?
    @State private var input = ""
    @State private var rows: [(String, String)] = []
    @State private var detected: String?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Text encodings").font(.headline)

            ToolTextEditor(placeholder: "Text to decode", text: $input)

            Picker("Read as", selection: $encoding) {
                Text("Auto").tag(StringCodec.Encoding?.none)
                ForEach(StringCodec.Encoding.allCases, id: \.self) { e in
                    Text(e.rawValue).tag(StringCodec.Encoding?.some(e))
                }
            }
            .pickerStyle(.segmented)

            HStack {
                Button("Decode", action: decode)
                    .keyboardShortcut(.defaultAction)
                    .disabled(input.trimmed.isEmpty)
                Button("Clear") { input = ""; rows = []; detected = nil; error = nil }
            }

            if let error { ConvertError(error) }
            if let detected {
                Text(detected).font(.caption).foregroundStyle(.secondary)
            }
            ToolResultTable(rows: rows)
        }
    }

    private func decode() {
        rows = []; detected = nil; error = nil
        do {
            let bytes: Data
            if let encoding {
                bytes = try StringCodec.decode(input, as: encoding)
                detected = "Read as \(encoding.rawValue)."
            } else {
                let (data, guessed) = try StringCodec.decodeDetecting(input)
                bytes = data
                // Auto-detect is a guess between overlapping alphabets;
                // saying which reading was taken is what lets the user
                // notice it took the wrong one.
                detected = "Read as \(guessed.rawValue) — pick an encoding above to override."
            }
            rows = StringCodec.renderAll(bytes).map { ($0.0.rawValue, $0.1) }
        } catch {
            self.error = errorText(error)
        }
    }
}

// MARK: - Time

/// Five views of one instant, each editable, all kept in step.
///
/// Editing any field recomputes the other four. `syncing` guards the
/// write-back so a recompute doesn't re-enter through the field it just
/// wrote — the same guard Android's `isUpdating` flag provides.
private struct TimeConvertView: View {
    private enum Field: String, CaseIterable, Identifiable {
        case seconds = "Unix seconds"
        case millis = "Unix milliseconds"
        case height = "Block height"
        case fcDate = "FcDate (Y.D.H.M)"
        case localTime = "Local time"
        var id: String { rawValue }

        var placeholder: String {
            switch self {
            case .seconds:   return "1577836802"
            case .millis:    return "1577836802000"
            case .height:    return "0"
            case .fcDate:    return "0.0.0.0"
            case .localTime: return "2020-01-01 00:00:02"
            }
        }
    }

    @State private var values: [Field: String] = [:]
    @State private var error: String?
    @State private var syncing = false

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        // Four-digit years: a two-digit year (what Android uses) is
        // ambiguous in a tool whose whole job is unambiguous conversion.
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Time, height and FcDate").font(.headline)
            Text("Edit any field; the rest follow. Heights are approximate — one block per "
                 + "minute is the target interval, not the measured one.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(Field.allCases) { field in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(field.rawValue).font(.caption).foregroundStyle(.secondary)
                        ToolValueActions(label: field.rawValue, value: values[field] ?? "")
                        Spacer(minLength: 0)
                    }
                    TextField(field.placeholder, text: binding(for: field))
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                }
            }

            HStack {
                Button("Now") { sync(from: .millis, value: String(nowMillis())) }
                    .keyboardShortcut(.defaultAction)
                Button("Clear") {
                    syncing = true
                    values = [:]
                    error = nil
                    syncing = false
                }
            }

            if let error { ConvertError(error) }
        }
        .onAppear {
            if values.isEmpty { sync(from: .millis, value: String(nowMillis())) }
        }
    }

    private func nowMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    private func binding(for field: Field) -> Binding<String> {
        Binding(
            get: { values[field] ?? "" },
            set: { newValue in
                values[field] = newValue
                guard !syncing else { return }
                sync(from: field, value: newValue)
            }
        )
    }

    /// Resolve the edited field to an instant in milliseconds, then
    /// rewrite every *other* field from it. A field that fails to parse
    /// leaves the rest alone rather than blanking them, so a half-typed
    /// value doesn't wipe the screen.
    private func sync(from source: Field, value: String) {
        let text = value.trimmed
        guard !text.isEmpty else { error = nil; return }

        let millis: Int64
        do {
            millis = try instantMillis(from: source, text: text)
        } catch {
            self.error = errorText(error)
            return
        }
        self.error = nil

        syncing = true
        defer { syncing = false }

        let seconds = Int64((Double(millis) / 1000).rounded(.down))
        let height = FcDate.height(fromUnixSeconds: seconds)

        var next: [Field: String] = [
            .seconds: String(seconds),
            .millis: String(millis),
            .height: String(height),
            .localTime: Self.formatter.string(
                from: Date(timeIntervalSince1970: Double(millis) / 1000)
            ),
            // Pre-genesis instants have no FcDate; blank beats a lie.
            .fcDate: (try? FcDate(height: height))?.text ?? "",
        ]
        next[source] = value  // leave the field being typed in untouched
        values = next
    }

    private func instantMillis(from source: Field, text: String) throws -> Int64 {
        switch source {
        case .millis:
            guard let v = Int64(text) else { throw ConvertFailure.notANumber(text) }
            return v
        case .seconds:
            guard let v = Int64(text) else { throw ConvertFailure.notANumber(text) }
            return v * 1000
        case .height:
            guard let v = Int64(text) else { throw ConvertFailure.notANumber(text) }
            return (FcDate.genesisUnixSeconds + v * 60) * 1000
        case .fcDate:
            return (try FcDate(text: text).approximateUnixSeconds) * 1000
        case .localTime:
            guard let date = Self.formatter.date(from: text) else {
                throw ConvertFailure.notATime(text)
            }
            return Int64(date.timeIntervalSince1970 * 1000)
        }
    }
}

// MARK: - Shared bits

private enum ConvertFailure: Error, CustomStringConvertible {
    case notANumber(String)
    case notATime(String)

    var description: String {
        switch self {
        case let .notANumber(text):  return "'\(text)' is not a whole number"
        case let .notATime(text):    return "'\(text)' is not a time — use yyyy-MM-dd HH:mm:ss"
        }
    }
}

/// Error line, click-to-copy like every other value in the pane.
private struct ConvertError: View {
    private let message: String
    init(_ message: String) { self.message = message }

    var body: some View {
        CopyableText(message, font: .caption)
            .foregroundStyle(.red)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
