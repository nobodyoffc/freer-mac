import SwiftUI

@main
struct FreerForMacApp: App {
    var body: some Scene {
        WindowGroup("Freer") {
            ContentView()
                .frame(minWidth: 900, minHeight: 600)
        }
        .windowResizability(.contentSize)
    }
}
