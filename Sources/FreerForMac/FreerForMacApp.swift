import SwiftUI

@main
struct FreerForMacApp: App {

    var body: some Scene {
        WindowGroup("Freer") {
            PlaceholderView()
                .frame(minWidth: 720, minHeight: 480)
        }
        .windowResizability(.contentSize)
    }
}

/// Phase 5.7c migration placeholder: the old auth flow used a
/// passphrase-derives-privkey model that turned out to be wrong.
/// Phase 5.7d wires the new Configure → Main FID → Live FID flow.
private struct PlaceholderView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "wrench.and.screwdriver")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("Migrating identity model").font(.title2).bold()
            Text("Phase 5.7c is in flight. The new password-vault flow lands in 5.7d.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 460)
        }
        .padding(40)
    }
}
