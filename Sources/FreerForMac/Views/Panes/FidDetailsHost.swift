import SwiftUI
import FCDomain

/// Opening a FID's details page, from anywhere, without every caller
/// knowing where the sheet lives.
///
/// **Why an environment action and not a field on ``AppState``.** A FID
/// appears in nearly every pane *and* inside nearly every sheet — the
/// sender in the mail reader, the owner in a service's detail sheet,
/// the publisher in a code's. AppKit will only let one sheet hang off a
/// given presenter at a time, so a single presenter at the window would
/// silently swallow every request made from inside another sheet, which
/// is most of them. An environment action lets each presenting context
/// install its own: ``HomeView`` hosts one for the panes, a sheet that
/// shows FIDs hosts its own, and the nearest one wins.
///
/// Callers never see the difference — they read ``inspectFid`` and call
/// it. The default is a no-op, so a view rendered outside any host
/// (a preview, a test) does nothing rather than crashing.
private struct InspectFidKey: EnvironmentKey {
    static let defaultValue: (String) -> Void = { _ in }
}

extension EnvironmentValues {
    /// Open the details page for a FID. See ``View/fidDetailsHost(session:)``.
    var inspectFid: (String) -> Void {
        get { self[InspectFidKey.self] }
        set { self[InspectFidKey.self] = newValue }
    }
}

/// Which FID a host is currently showing. A wrapper rather than a bare
/// `String?` so `.sheet(item:)` can key on it — and so asking for a
/// second FID while the first is up rebuilds the sheet instead of
/// leaving stale content in place.
private struct InspectedFid: Identifiable, Equatable {
    let fid: String
    var id: String { fid }
}

private struct FidDetailsHost: ViewModifier {
    let session: ActiveSession
    @State private var target: InspectedFid?

    func body(content: Content) -> some View {
        content
            .environment(\.inspectFid) { fid in
                // Guard here rather than at every call site: panes pass
                // optional record fields straight through, and a row
                // with no publisher should do nothing rather than open
                // a page about the empty string.
                let trimmed = fid.trimmingCharacters(in: .whitespaces)
                guard !trimmed.isEmpty else { return }
                target = InspectedFid(fid: trimmed)
            }
            .sheet(item: $target) { inspected in
                FidDetailSheet(session: session, fid: inspected.fid) {
                    target = nil
                }
                // The details page shows FIDs of its own — a master, a
                // group member, a rater — so it hosts its own presenter
                // and those open in turn.
                .fidDetailsHost(session: session)
            }
    }
}

extension View {
    /// Install a FID-details presenter at this level, so anything
    /// inside can call `@Environment(\.inspectFid)`.
    ///
    /// Put one on every context that can present a sheet and shows a
    /// FID: the window's root, and each sheet that draws ids.
    func fidDetailsHost(session: ActiveSession) -> some View {
        modifier(FidDetailsHost(session: session))
    }
}
