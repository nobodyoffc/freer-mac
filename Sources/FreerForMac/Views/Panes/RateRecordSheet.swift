import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Rate a published record 0–5 — the Mac port of Android's
/// `RateActivity`, generalised past the four kinds it covers to all ten
/// protocols that define a `rate` op.
///
/// **A rating is a weighted average, not a vote.** The ten protocols
/// fold each rating into the record's `tRate` as
/// `tRate ← (tRate·tCdd + rate·cdd) / (tCdd + cdd)`, where `cdd` is the
/// coin-days this transaction destroys. So the score picks a direction
/// and the **weight** decides how far the average actually moves: one
/// coin-day next to a record with thousands behind it barely registers,
/// and a thousand can halve a reputation built over a year. That is why
/// the weight sits on this sheet as a real field rather than a hidden
/// default.
///
/// **It pays the publisher nothing.** The carve names the record in its
/// payload, so a rating is a statement about a work, not a transfer to
/// whoever made it — the same shape as ``RateFreerSheet``, which rates
/// people rather than records.
///
/// **There is no un-rate.** None of the ten protocols defines one. A
/// second rating does not replace the first, it adds another row and
/// moves the mean again, which is why a previous rating from this
/// identity is shown before the button rather than after.
struct RateRecordSheet: View {

    let session: ActiveSession
    let kind: RatableKind
    let subjectId: String
    /// What to call the record on screen — a title or a name, whatever
    /// the caller shows in its own list.
    let title: String
    /// The record's owner or publisher, when the caller knows it. Used
    /// for the self-rating guard, which every one of the ten parsers
    /// applies by discarding the carve after taking the fee.
    let owner: String?
    /// The record's current CDD-weighted mean, for context beside the
    /// score being chosen.
    let currentRate: Float?
    /// Coin-days already behind that mean — how much weight a new
    /// rating is arguing with.
    let currentCdd: Int64?

    let onDone: (String) -> Void
    let onCancel: () -> Void

    @State private var score: RateScore = .five
    @State private var cause = ""
    @State private var weightText = "1"

    @State private var quote: ActiveSession.RecordRateQuote?
    @State private var loading = true
    @State private var loadError: String?

    @State private var carving = false
    @State private var carveError: String?

    /// Coin-days this identity has to spend, as far as the cached cash
    /// snapshot knows — nil when it knows nothing, which is not the
    /// same as zero.
    @State private var availableCd: Int64?

    private var weightCd: Int64? {
        let trimmed = weightText.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed.allSatisfy(\.isNumber) else { return nil }
        return Int64(trimmed)
    }

    /// Why this rating can't be sent, or nil when it can. Every refusal
    /// is one the chain would make anyway — checked here so the user
    /// learns it before paying a fee to find out.
    private var blockReason: String? {
        if let owner, owner == session.liveFid {
            return "You are the \(kind.ownerNoun) of this \(kind.label.lowercased()). The protocol ignores a rating from its own \(kind.ownerNoun), so the carve would cost the fee and change nothing."
        }
        if !session.canSign {
            return "This identity has no private key on this Mac, so it cannot sign a rating."
        }
        if subjectId.isEmpty {
            return "This record has no on-chain id yet — it cannot be rated until its publish confirms."
        }
        if loading { return nil }
        guard let weightCd else { return "The weight has to be a whole number of coin-days." }
        if weightCd < 1 { return "A rating has to destroy at least 1 coin-day to be counted." }
        if let availableCd, weightCd > availableCd {
            return "This identity holds about \(Self.grouped(availableCd)) coin-days, which is less than the weight you asked for."
        }
        // Asked of the builder rather than estimated: the limit is on
        // encoded bytes, and a counter that guessed would let a cause
        // full of emoji through and refuse one that fits.
        if (try? ActiveSession.rateCarve(
            kind: kind, subjectId: subjectId, rate: score.rawValue, cause: cause
        )) == nil {
            return "The cause is too long to fit in the carve — shorten it."
        }
        return nil
    }

    /// Bytes the cause will occupy once encoded, against its budget.
    /// Only drawn once there is something to count.
    private var causeBudget: (used: Int, remaining: Int)? {
        let trimmed = cause.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return (
            trimmed.utf8.count,
            ActiveSession.remainingCauseBytes(
                kind: kind, subjectId: subjectId, rate: score, cause: trimmed
            )
        )
    }

    private var canSend: Bool { blockReason == nil && !carving && !loading }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let loadError {
                        problem(loadError, warning: true)
                    }
                    if let already = quote?.alreadyRated, !already.isEmpty {
                        alreadyRatedPanel(already)
                    }
                    scorePanel
                    weightPanel
                    causePanel
                    costPanel
                    if let carveError {
                        problem(carveError)
                    }
                }
                .padding(16)
            }

            Divider()
            footer
        }
        .frame(width: 580, height: 680)
        .task { await load() }
    }

    // MARK: - chrome

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.title3.bold())
                    .lineLimit(2)
                    .truncationMode(.middle)
                HStack(spacing: 10) {
                    Text(kind.label)
                        .font(.caption2.bold())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.accentColor.opacity(0.15)))
                        .foregroundStyle(Color.accentColor)
                    standing
                }
            }
            Spacer()
            if loading { ProgressView().controlSize(.small) }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    /// The mean a new rating is joining, and the weight already behind
    /// it. Both or neither: a mean with no coin-days under it says
    /// nothing about how hard it is to move.
    private var standing: some View {
        HStack(spacing: 10) {
            HStack(spacing: 4) {
                Text("Rating").font(.caption2).foregroundStyle(.tertiary)
                Text(currentRate.map { String(format: "%.2f", $0) } ?? "—")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 4) {
                Text("Weight").font(.caption2).foregroundStyle(.tertiary)
                Text(currentCdd.map { "\(Self.grouped($0)) CDD" } ?? "—")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 10) {
            if let blockReason, !loading {
                Text(blockReason)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(3)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction)
            Button {
                Task { await send() }
            } label: {
                if carving {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Rate \(score.rawValue)", systemImage: "star.fill")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!canSend)
        }
        .padding(12)
    }

    // MARK: - panels

    /// Six buttons rather than a slider or a star row.
    ///
    /// **0 is a verdict, not an absence.** A star row makes "no stars"
    /// look like "not answered", and this app used to refuse 0
    /// outright, which quietly made 1 the worst thing it could say. Six
    /// equal targets, each labelled, say what the protocol actually
    /// accepts.
    private var scorePanel: some View {
        panel("Your rating") {
            HStack(spacing: 6) {
                ForEach(RateScore.allCases) { value in
                    scoreButton(value)
                }
            }
            caption(
                "\(score.rawValue) — \(score.label). Folded into this \(kind.label.lowercased())'s "
                    + "average by the coin-days below, not counted as one vote among many."
            )
        }
    }

    private func scoreButton(_ value: RateScore) -> some View {
        let tint = Self.tint(for: value)
        let chosen = score == value
        return Button {
            score = value
        } label: {
            VStack(spacing: 3) {
                Text("\(value.rawValue)")
                    .font(.title3.bold().monospacedDigit())
                Text(value.label)
                    .font(.system(size: 9))
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(tint.opacity(chosen ? 0.22 : 0.06))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(tint.opacity(chosen ? 0.8 : 0), lineWidth: 1.5)
            )
            .foregroundStyle(chosen ? tint : Color.secondary)
        }
        .buttonStyle(.plain)
    }

    /// **The real control on this sheet**, for the same reason it is on
    /// ``RateFreerSheet``: "how many coin-days is a strong opinion" is
    /// not a question most people can answer cold, and one extra zero
    /// here spends ten times the stake.
    private var weightPanel: some View {
        panel("Weight") {
            HStack(spacing: 8) {
                TextField("", text: $weightText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 110)
                    .monospacedDigit()
                Text("coin-days")
                    .foregroundStyle(.secondary)
                Spacer()
                ForEach(Self.presets, id: \.self) { preset in
                    Button(Self.grouped(preset)) { weightText = String(preset) }
                        .buttonStyle(.link)
                        .disabled(availableCd.map { preset > $0 } ?? false)
                }
            }
            caption(movementNote)
            caption(availableNote)
        }
    }

    /// What this weight actually does to the mean, computed rather than
    /// described — the formula is the protocol's, and seeing the result
    /// before signing is the difference between a considered rating and
    /// a guess.
    private var movementNote: String {
        guard let weightCd, weightCd > 0 else {
            return "A rating's force is the coin-days it destroys. The coin-days are spent, not lent."
        }
        guard let current = currentRate, let cdd = currentCdd, cdd > 0 else {
            return "Nothing has rated this \(kind.label.lowercased()) yet, so this rating becomes its average outright."
        }
        let moved = (Double(current) * Double(cdd) + Double(score.rawValue) * Double(weightCd))
            / Double(cdd + weightCd)
        return String(
            format: "At %@ coin-days this moves the average from %.2f to about %.2f.",
            Self.grouped(weightCd), current, moved
        )
    }

    /// What the vault thinks it can spend, hedged honestly. The cached
    /// snapshot can be stale and does not know about coins reserved by
    /// a build in flight, so this reads as "about".
    private var availableNote: String {
        guard let availableCd else {
            return "Coin selection takes whole cashes, so it may destroy more than you ask for — "
                + "the approval sheet shows the real number before you sign."
        }
        return "This identity holds about \(Self.grouped(availableCd)) coin-days. Selection takes whole "
            + "cashes, so it may destroy more than you ask for — the approval sheet shows the real "
            + "number before you sign."
    }

    private var causePanel: some View {
        panel("Cause (optional)") {
            TextEditor(text: $cause)
                .font(.body)
                .frame(height: 70)
                .padding(4)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color(NSColor.separatorColor))
                )
            HStack {
                caption(
                    "Why you rated it this way. Public and permanent, like everything else in the "
                        + "carve. Left blank, the field is omitted rather than carved empty."
                )
                Spacer(minLength: 8)
                if let budget = causeBudget {
                    Text("\(Self.grouped(Int64(budget.used))) bytes · \(Self.grouped(Int64(budget.remaining))) left")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(budget.remaining < 0 ? Color.orange : Color.secondary)
                }
            }
        }
    }

    /// What this transaction actually does, in the order somebody
    /// deciding to send it would ask.
    private var costPanel: some View {
        panel("What gets carved") {
            costRow("About", "\(kind.label) \(subjectId.elidingMiddle(head: 8, tail: 8))")
            costRow("Rating", "\(score.rawValue) — \(score.label)")
            costRow("Coin-days", "at least \(weightCd.map(Self.grouped) ?? "—")")
            costRow("Paid to them", "nothing")
            caption(
                "A rating names the record in the carve itself, so nothing is sent to whoever "
                    + "published it. What it costs you is the miner fee and the coin-days above, "
                    + "and the coin-days are not a fee: they are the weight."
            )
        }
    }

    private func costRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 90, alignment: .leading)
            Text(value).font(.callout.monospacedDigit())
            Spacer(minLength: 0)
        }
    }

    /// None of the ten protocols has an update op. Rating a record a
    /// second time does not replace the first, it adds another — worth
    /// saying before somebody "fixes" a rating and drags the mean twice
    /// as far instead.
    private func alreadyRatedPanel(_ rows: [RatingHist]) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(rows.count == 1
                     ? "You have rated this \(kind.label.lowercased()) before."
                     : "You have rated this \(kind.label.lowercased()) \(rows.count) times before.")
                    .font(.callout)
                ForEach(rows) { row in
                    Text(Self.summary(of: row))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text("There is no way to change a rating — a new one adds to the old, it does not replace it.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.10)))
    }

    // MARK: - building blocks

    private func panel<Content: View>(
        _ title: String, @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption)
                .fontWeight(.semibold)
                .textCase(.uppercase)
                .tracking(0.5)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 8) {
                content()
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color(NSColor.controlBackgroundColor))
            )
        }
    }

    private func caption(_ text: String) -> some View {
        Text(text)
            .font(.caption2)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func problem(_ text: String, warning: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: warning ? "exclamationmark.triangle.fill" : "xmark.octagon.fill")
            CopyableText(text, font: .callout, color: warning ? .orange : .red)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .foregroundStyle(warning ? Color.orange : Color.red)
    }

    private static let presets: [Int64] = [1, 10, 100, 1_000]

    /// Red at the bottom, green at the top, and a deliberate step at 3:
    /// the mean these feed is a number people read as a verdict, so the
    /// colour should not imply 2 and 3 are the same kind of answer.
    static func tint(for score: RateScore) -> Color {
        switch score {
        case .zero, .one: return .red
        case .two:        return .orange
        case .three:      return .yellow
        case .four:       return .mint
        case .five:       return .green
        }
    }

    static func grouped(_ n: Int64) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? String(n)
    }

    static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    /// One history row as a line — score, weight, when.
    static func summary(of row: RatingHist) -> String {
        let value = row.rate.map(String.init) ?? "—"
        let weight = row.cdd.map { "\(grouped($0)) CDD" } ?? "unknown weight"
        guard let time = row.time else { return "\(value) · \(weight)" }
        let seconds = time > 10_000_000_000 ? Double(time) / 1000 : Double(time)
        return "\(value) · \(weight) · \(stamp.string(from: Date(timeIntervalSince1970: seconds)))"
    }

    // MARK: - work

    private func load() async {
        loading = true
        loadError = nil
        defer { loading = false }
        // The cached snapshot, not a refresh: this is a hint next to a
        // field, and making the sheet wait on the network to show it
        // would be the wrong trade. Zero reads as *unknown*, not as a
        // ceiling — an identity whose cashes have never been fetched on
        // this Mac has an empty snapshot, and blocking a rating on that
        // would refuse a perfectly fundable carve.
        let cached = (try? session.wallet.cachedSnapshot(forAddress: session.liveFid))?
            .cashes
            .filter { !$0.pendingSpend }
            .reduce(Int64(0)) { $0 + ($1.cd ?? 0) }
        availableCd = (cached ?? 0) > 0 ? cached : nil
        do {
            quote = try await session.quoteRecordRating(
                of: kind, subjectId: subjectId, owner: owner
            )
        } catch {
            loadError = "Couldn't check this \(kind.label.lowercased()) before rating — \(error)"
        }
    }

    private func send() async {
        guard let weightCd else { return }
        carving = true
        carveError = nil
        defer { carving = false }
        do {
            let txid = try await session.carveRecordRateOnChain(
                kind: kind,
                subjectId: subjectId,
                rate: score,
                cause: cause,
                owner: owner,
                weightCd: weightCd
            )
            onDone(txid)
        } catch {
            carveError = "\(error)"
        }
    }
}
