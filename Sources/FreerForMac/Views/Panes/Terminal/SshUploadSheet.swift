import SwiftUI
import FCDomain
import FCUI

/// Where an upload goes — asked once per upload, from Upload… and from a
/// drop alike.
///
/// A sheet rather than a field inside the open panel because a drop has
/// no panel, and two ways in to one upload should not ask two different
/// questions.
struct SshUploadSheet: View {

    let server: SshServer
    let paths: [String]
    /// The directory a running shell on this server last reported, if
    /// one did.
    let shellDirectory: String?
    let onUpload: (String) -> Void
    let onCancel: () -> Void

    @State private var destination: String

    init(
        server: SshServer,
        paths: [String],
        shellDirectory: String?,
        onUpload: @escaping (String) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.server = server
        self.paths = paths
        self.shellDirectory = shellDirectory
        self.onUpload = onUpload
        self.onCancel = onCancel
        // `~` rather than an empty field for a server with no history:
        // an empty box reads as "not chosen yet", and the home
        // directory is a choice.
        _destination = State(initialValue: server.lastUploadDirectory ?? "~")
    }

    private var problem: String? {
        do {
            _ = try SshLaunch.normalizedRemoteDirectory(destination)
            return nil
        } catch {
            return "\(error)"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label("Upload to \(server.name)", systemImage: "arrow.up.doc")
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                Spacer()
            }
            .padding(16)

            Divider()

            VStack(alignment: .leading, spacing: 16) {
                LabeledField(paths.count == 1 ? "Item" : "\(paths.count) items") {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(Array(paths.enumerated()), id: \.offset) { _, path in
                                Label((path as NSString).lastPathComponent,
                                      systemImage: isDirectory(path) ? "folder" : "doc")
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .help(path)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 110)
                }

                LabeledField(
                    "Folder on \(server.target)",
                    hint: problem ?? "~ is your home directory, and a path without a leading / starts there. The folder must already exist — scp does not create it.",
                    hintIsError: problem != nil
                ) {
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("~", text: $destination)
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                            .autocorrectionDisabled()
                        if let shellDirectory,
                           shellDirectory != destination.trimmingCharacters(in: .whitespaces) {
                            Button {
                                destination = shellDirectory
                            } label: {
                                Label("Use the shell's directory: \(shellDirectory)", systemImage: "terminal")
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
            }
            .padding(20)

            Spacer(minLength: 0)
            Divider()

            HStack {
                Spacer()
                Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction)
                Button("Upload") {
                    onUpload(destination.trimmingCharacters(in: .whitespaces))
                }
                .keyboardShortcut(.defaultAction)
                .disabled(problem != nil)
            }
            .padding(16)
        }
        .frame(width: 520, height: 400)
    }

    private func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }
}
