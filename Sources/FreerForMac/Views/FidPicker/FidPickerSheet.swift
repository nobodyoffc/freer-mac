import SwiftUI
import FCCore
import FCDomain
import FCUI

/// What a caller wants picked. Carried as one value so a host view can
/// drive the picker with a single `@State FidPickerRequest?` and
/// `.sheet(item:)`, instead of five parallel booleans.
///
/// ```swift
/// @State private var pick: FidPickerRequest?
/// …
/// Button("Add people") {
///     pick = .many(title: "Invite to this room", excluding: Set(members))
/// }
/// .sheet(item: $pick) { request in
///     FidPickerSheet(session: session, request: request) { picked in
///         members.append(contentsOf: picked.map(\.fid))
///         pick = nil
///     } onCancel: { pick = nil }
/// }
/// ```
struct FidPickerRequest: Identifiable {

    let id = UUID()
    var title: String
    /// One line under the title saying what the pick is for. The picker
    /// is used from a dozen places; without this the user has only the
    /// window it came from to tell them why they're choosing.
    var subtitle: String?
    var mode: FidPickMode
    var confirmTitle: String
    /// Seed the search box — normally whatever the user had already
    /// typed in the field that opened the picker. A non-empty seed also
    /// runs the chain search immediately: they've typed it once and
    /// asked to find it, so making them press Search again is a step
    /// for nothing.
    var initialQuery: String
    var preselected: [PickedFid]
    /// Restrict the picker to these FIDs (a room's members, a group's
    /// signers). Nil means the whole chain is fair game.
    var pool: [String]?
    /// FIDs shown but refused — normally what the caller already holds.
    var excluded: Set<String>

    init(
        title: String,
        subtitle: String? = nil,
        mode: FidPickMode = .many,
        confirmTitle: String? = nil,
        initialQuery: String = "",
        preselected: [PickedFid] = [],
        pool: [String]? = nil,
        excluded: Set<String> = []
    ) {
        self.title = title
        self.subtitle = subtitle
        self.mode = mode
        self.confirmTitle = confirmTitle ?? (mode == .one ? "Choose" : "Add")
        self.initialQuery = initialQuery
        self.preselected = preselected
        self.pool = pool
        self.excluded = excluded
    }

    /// Pick exactly one — the sheet closes on the click.
    static func one(
        title: String = "Find someone",
        subtitle: String? = nil,
        initialQuery: String = "",
        pool: [String]? = nil,
        excluded: Set<String> = []
    ) -> FidPickerRequest {
        FidPickerRequest(
            title: title, subtitle: subtitle, mode: .one,
            initialQuery: initialQuery, pool: pool, excluded: excluded
        )
    }

    /// Pick any number — the sheet closes on Add.
    static func many(
        title: String = "Find people",
        subtitle: String? = nil,
        confirmTitle: String? = nil,
        initialQuery: String = "",
        preselected: [PickedFid] = [],
        pool: [String]? = nil,
        excluded: Set<String> = []
    ) -> FidPickerRequest {
        FidPickerRequest(
            title: title, subtitle: subtitle, mode: .many,
            confirmTitle: confirmTitle, initialQuery: initialQuery,
            preselected: preselected, pool: pool, excluded: excluded
        )
    }
}

/// The app's one way to find and choose FIDs — Android's
/// `SearchFidsOnChainActivity` as a sheet.
///
/// Hands back ``PickedFid`` values rather than bare strings, because
/// every caller that receives a FID immediately wants the CID to show
/// and the pubkey to encrypt with, and the picker has both in hand at
/// the moment of the pick. Making them re-fetch is how a sheet ends up
/// with three slightly different copies of "look this person up".
///
/// In ``FidPickMode/one`` the click is the answer and the sheet closes;
/// in ``FidPickMode/many`` picks accumulate in a tray and Add returns
/// them in the order chosen.
struct FidPickerSheet: View {

    let request: FidPickerRequest
    let onPicked: ([PickedFid]) -> Void
    let onCancel: () -> Void

    @State private var model: FidSearchModel

    init(
        session: ActiveSession,
        request: FidPickerRequest,
        onPicked: @escaping ([PickedFid]) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.request = request
        self.onPicked = onPicked
        self.onCancel = onCancel
        _model = State(initialValue: FidSearchModel(
            session: session,
            mode: request.mode,
            query: request.initialQuery,
            preselected: request.preselected,
            pool: request.pool,
            excluded: request.excluded
        ))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            FidPickerView(model: model)
                .padding(.horizontal, 16)
                .padding(.bottom, 12)

            Divider()
            footer
        }
        .frame(minWidth: 560, minHeight: 520)
        .onChange(of: model.selected) { _, selection in
            // One-shot mode: the click *is* the confirmation. Waiting
            // for a button here would make the simple case — pick the
            // person you already searched for — take two clicks.
            guard request.mode == .one, !selection.isEmpty else { return }
            Task { onPicked(await model.confirm()) }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                Image(systemName: "person.text.rectangle")
                    .font(.title2)
                    .foregroundStyle(.tint)
                Text(request.title).font(.title2).bold()
                Spacer()
            }
            if let subtitle = request.subtitle {
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
        .padding(.bottom, 10)
    }

    private var footer: some View {
        HStack(spacing: 10) {
            if model.mode == .one, model.enriching {
                // The click already closed the question; this is the
                // last pubkey lookup finishing.
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Looking up…").font(.caption).foregroundStyle(.secondary)
                }
            } else if model.mode == .many, !model.selected.isEmpty {
                Text("\(model.selected.count) selected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Cancel", role: .cancel) { onCancel() }
                .keyboardShortcut(.cancelAction)
            if model.mode == .many {
                Button {
                    Task { onPicked(await model.confirm()) }
                } label: {
                    if model.enriching {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Adding…")
                        }
                        .frame(minWidth: 80)
                    } else {
                        Text(request.confirmTitle).frame(minWidth: 80)
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!model.canConfirm)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}
