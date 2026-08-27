import Foundation
import Observation
import FCDomain

/// The one place a signing request becomes a modal.
///
/// The wallet's signing paths live far from SwiftUI — they are `async`
/// functions on a struct, called from panes, from background carves,
/// from the chat outbox — and any of them may need to ask a human a
/// question. This is the adapter: ``ask(_:)`` parks the caller on a
/// continuation and publishes the request, the root view draws it, and
/// the user's answer resumes whoever was waiting.
///
/// **Requests queue rather than replace.** Two carves can be in flight
/// at once (the outbox retries while the user sends a mail), and
/// dropping one of them would either sign something unapproved or hang
/// a caller forever. Only one dialog is on screen at a time; the rest
/// wait their turn.
///
/// **Cancellation resolves to "no".** If the app tears the session
/// down — lock the vault, switch identity — every parked caller is
/// answered `false`, because a question nobody can answer must not
/// become a signature.
///
/// **Isolation.** The class is not `@MainActor`-annotated, because
/// ``AppState`` — which owns it and calls ``cancelAll()`` from its own
/// non-isolated teardown paths — is not either. Instead every mutation
/// of the published state hops to the main actor explicitly: ``ask``
/// is the one entry point reachable from a background task, and it
/// enqueues inside `Task { @MainActor }`. The rest is called from
/// SwiftUI, which is already there.
@Observable
final class TxApprovalCenter: @unchecked Sendable {

    struct Request: Identifiable {
        let id = UUID()
        let preview: TxPreview
        @ObservationIgnored let resume: (Bool) -> Void
    }

    /// The request currently on screen, if any.
    private(set) var current: Request?

    /// Requests waiting for the current one to be answered.
    @ObservationIgnored private var queue: [Request] = []

    /// How many are waiting behind the current one — shown in the
    /// dialog so an unexpected queue doesn't look like a stuck app.
    var waitingCount: Int { queue.count }

    /// The gate handed to ``ActiveSession/txApprover``.
    func approver() -> TxApprover {
        { [weak self] preview in
            guard let self else { return false }
            return await self.ask(preview)
        }
    }

    func ask(_ preview: TxPreview) async -> Bool {
        await withCheckedContinuation { continuation in
            Task { @MainActor in
                let request = Request(preview: preview) { approved in
                    continuation.resume(returning: approved)
                }
                if current == nil {
                    current = request
                } else {
                    queue.append(request)
                }
            }
        }
    }

    /// Answer the request on screen and promote the next one.
    func answer(_ approved: Bool) {
        guard let request = current else { return }
        current = queue.isEmpty ? nil : queue.removeFirst()
        request.resume(approved)
    }

    /// Refuse everything outstanding — used when the session goes
    /// away underneath the dialog.
    func cancelAll() {
        let pending = ([current].compactMap { $0 }) + queue
        current = nil
        queue = []
        for request in pending { request.resume(false) }
    }
}
