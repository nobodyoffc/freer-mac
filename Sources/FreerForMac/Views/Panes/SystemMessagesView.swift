import SwiftUI
import FCDomain
import FCUI

/// What the app has been doing, and what it has quietly failed at.
///
/// **Why a page rather than alerts.** Almost everything under chat fails
/// softly on purpose: an unresolvable DOCK is "no route", a refusing
/// server is "retry later", a lookup that 404s is "no such record".
/// Each is right on its own — none should interrupt a send with a dialog
/// — and together they add up to an app that stops working and says
/// nothing about it. This is where those go, so "it isn't sending and I
/// don't know why" has an answer that does not require a debugger.
///
/// It is a log, not an inbox: nothing here needs acknowledging, and
/// nothing blocks on being read.
struct SystemMessagesView: View {

    let session: ActiveSession

    @State private var messages: [SystemMessage] = []
    @State private var minimumLevel: SystemMessage.Level = .info
    @State private var expanded: Set<UUID> = []
    @State private var observer: UUID?

    private var filtered: [SystemMessage] {
        messages.filter { $0.level <= minimumLevel }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PaneHeader(session: session)
                .padding(.horizontal, 20)
                .padding(.top, 16)

            Text("Connection, delivery and lookup events — newest first.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 20)
                .padding(.top, 10)

            controls
                .padding(.horizontal, 20)
                .padding(.vertical, 10)

            Divider()

            if filtered.isEmpty {
                emptyState
            } else {
                list
            }
        }
        .onAppear {
            reload()
            // Live: a failure that happens while this page is open
            // should appear on it, not on the next visit.
            observer = SystemLog.shared.observe { _ in
                Task { @MainActor in reload() }
            }
        }
        .onDisappear {
            if let observer { SystemLog.shared.stopObserving(observer) }
            observer = nil
        }
    }

    // MARK: - chrome

    private var controls: some View {
        HStack(spacing: 12) {
            Picker("", selection: $minimumLevel) {
                Text("Errors").tag(SystemMessage.Level.error)
                Text("Warnings & errors").tag(SystemMessage.Level.warning)
                Text("Everything").tag(SystemMessage.Level.info)
            }
            .labelsHidden()
            .frame(width: 190)

            Text(countSummary)
                .font(.caption)
                .foregroundStyle(.secondary)

            Spacer()

            Button {
                copyAll()
            } label: {
                Label("Copy all", systemImage: "doc.on.doc")
            }
            .disabled(filtered.isEmpty)
            .help("Copy every listed entry, with its detail, as plain text")

            Button {
                SystemLog.shared.clear()
                reload()
            } label: {
                Label("Clear", systemImage: "trash")
            }
            .disabled(messages.isEmpty)
        }
    }

    private var countSummary: String {
        let errors = messages.count { $0.level == .error }
        let warnings = messages.count { $0.level == .warning }
        if errors == 0 && warnings == 0 { return "Nothing wrong so far." }
        var parts: [String] = []
        if errors > 0 { parts.append("\(errors) error\(errors == 1 ? "" : "s")") }
        if warnings > 0 { parts.append("\(warnings) warning\(warnings == 1 ? "" : "s")") }
        return parts.joined(separator: " · ")
    }

    private var emptyState: some View {
        VStack(spacing: 6) {
            Spacer()
            Image(systemName: "checkmark.circle")
                .font(.largeTitle)
                .foregroundStyle(.tertiary)
            Text(messages.isEmpty ? "Nothing recorded yet." : "Nothing at this level.")
                .foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var list: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(filtered) { message in
                    row(message)
                    Divider()
                }
            }
        }
    }

    private func row(_ message: SystemMessage) -> some View {
        let isExpanded = expanded.contains(message.id)
        return VStack(alignment: .leading, spacing: 5) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: icon(message.level))
                    .foregroundStyle(tint(message.level))
                    .font(.caption)

                Text(message.source)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .frame(width: 74, alignment: .leading)

                // Single click copies, matching how every other id and
                // status string in the app behaves.
                CopyableText(
                    display: message.summary,
                    copy: copyText(message)
                )
                .multilineTextAlignment(.leading)

                Spacer(minLength: 8)

                Text(Self.stamp.string(from: message.at))
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.tertiary)

                if message.detail != nil {
                    Button {
                        if isExpanded { expanded.remove(message.id) }
                        else { expanded.insert(message.id) }
                    } label: {
                        Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                            .font(.caption2)
                    }
                    .buttonStyle(.borderless)
                    .help("Show the full detail")
                }
            }

            if isExpanded, let detail = message.detail {
                Text(detail)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.leading, 90)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 8)
    }

    private func icon(_ level: SystemMessage.Level) -> String {
        switch level {
        case .error:   return "xmark.octagon.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .info:    return "info.circle"
        }
    }

    private func tint(_ level: SystemMessage.Level) -> Color {
        switch level {
        case .error:   return .red
        case .warning: return .orange
        case .info:    return .secondary
        }
    }

    private static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    // MARK: - actions

    private func reload() {
        messages = SystemLog.shared.all
    }

    private func copyText(_ message: SystemMessage) -> String {
        var text = "[\(Self.stamp.string(from: message.at))] "
            + "\(message.level.rawValue.uppercased()) \(message.source): \(message.summary)"
        if let detail = message.detail { text += "\n    \(detail)" }
        return text
    }

    private func copyAll() {
        let text = filtered.map(copyText).joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
