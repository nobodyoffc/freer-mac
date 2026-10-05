import SwiftUI
import FCUI
import FCDomain
import Combine

/// The call card (VOICE_SPEC §10): calling, ringing and in a call, over the
/// main window. It always says the call is end-to-end encrypted and how it
/// travels, and warns when audio claimed to be from someone could not be
/// verified (§5.1). All state lives in ``CallCenter``; this only shows it.
struct CallView: View {
    let calls: CallCenter
    @State private var now = Date()
    private let clock = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        if calls.phase != .idle {
            VStack(alignment: .leading, spacing: 10) {
                Text(title).font(.headline)
                Text(CallCenter.short(calls.peerFid ?? "")).font(.title3).bold().textSelection(.enabled)
                Text(status).foregroundStyle(.secondary)
                Label("End-to-end encrypted", systemImage: "lock.fill").font(.caption).foregroundStyle(.secondary)
                Text(CallText.realVoiceNotice).font(.caption).foregroundStyle(.secondary)
                if calls.direct {
                    Text("Direct").font(.caption).foregroundStyle(.secondary)
                } else if let host = calls.relayHost {
                    Text("Relayed via \(host)").font(.caption).foregroundStyle(.secondary)
                }
                if let fid = calls.unverifiedFid {
                    CopyableText("Audio claimed to be from \(CallCenter.short(fid)) could not be verified and is silenced.")
                        .font(.caption).foregroundStyle(.red)
                }
                buttons
            }
            .padding(16)
            .frame(width: 280, alignment: .leading)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            .shadow(radius: 8)
            .padding(16)
            .onReceive(clock) { now = $0 }
            .onChange(of: calls.phase) { _, phase in
                if phase == .ended && !calls.failed {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { calls.dismiss() }
                }
            }
        }
    }

    private var title: String {
        switch calls.phase {
        case .ringingIn: return "Incoming voice call"
        default: return "Voice call"
        }
    }

    private var status: String {
        switch calls.phase {
        case .calling: return "Calling…"
        case .ringingIn: return "Ringing"
        case .connecting: return "Connecting…"
        case .connected:
            let s = max(0, (Int64(now.timeIntervalSince1970 * 1000) - calls.connectedAtMs) / 1000)
            return String(format: "%d:%02d", s / 60, s % 60)
        case .ended: return calls.endReason ?? "Call ended"
        case .idle: return ""
        }
    }

    @ViewBuilder private var buttons: some View {
        HStack {
            switch calls.phase {
            case .ringingIn:
                Button("Answer") { calls.answer() }.buttonStyle(.borderedProminent).tint(.green)
                Button("Decline", role: .destructive) { calls.decline() }
            case .calling, .connecting, .connected:
                if calls.phase == .connected {
                    Toggle("Mute", isOn: Bindable(calls).muted).toggleStyle(.button)
                }
                Button("Hang up", role: .destructive) { calls.hangup() }.buttonStyle(.borderedProminent).tint(.red)
            case .ended:
                Button("Close") { calls.dismiss() }
            case .idle:
                EmptyView()
            }
        }
    }
}

/// The relay to call through and answer on before a CALL service is on chain.
struct CallSettingsSheet: View {
    let calls: CallCenter
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    @State private var relay = ""
    @State private var alwaysRelay = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Call settings").font(.headline)
            if CallCenter.testRelayAllowed {
                Text("Test relay (debug builds only): calls go through it instead of the callee's CALL service, and this Mac answers on it too. Leave empty to use CALL services from the chain.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                TextField("fudp://host:port", text: $relay).textFieldStyle(.roundedBorder)
            }
            Toggle("Available for calls", isOn: Bindable(appState).availableForCalls)
            Text("Keep Freer running in the menu bar when its window is closed, so calls and meetings still ring. Quit it from the menu bar icon.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Toggle("Always relay", isOn: $alwaysRelay)
            Text("Never connect directly to the other side of a call, so they never learn this Mac's IP address. Calls with contacts otherwise try a direct path, which is faster and costs no relay fee.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") {
                    if CallCenter.testRelayAllowed { calls.testRelay = relay }
                    calls.alwaysRelay = alwaysRelay
                    dismiss()
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 420)
        .onAppear {
            relay = calls.testRelay
            alwaysRelay = calls.alwaysRelay
        }
    }
}
