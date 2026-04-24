import SwiftUI
import FCCore
import FCTransport
import FCStorage
import FCDomain
import FCUI

struct ContentView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("Freer for macOS")
                .font(.largeTitle)
                .bold()
            Text("Phase 0 scaffold — wallet features land in Phase 7.")
                .foregroundStyle(.secondary)
            Divider().padding(.vertical, 8)
            VStack(alignment: .leading, spacing: 4) {
                Text("FCCore v\(FCCore.version)")
                Text("FCTransport v\(FCTransport.version)")
                Text("FCStorage v\(FCStorage.version)")
                Text("FCDomain v\(FCDomain.version)")
                Text("FCUI v\(FCUI.version)")
            }
            .font(.system(.body, design: .monospaced))
        }
        .padding(32)
    }
}

#Preview {
    ContentView()
}
