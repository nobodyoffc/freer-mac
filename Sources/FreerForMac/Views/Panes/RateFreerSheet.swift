import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Rate another FID good or bad — the Mac port of Android's
/// `RateFreerActivity`, and the one act on an otherwise read-only
/// details page.
///
/// **A rating is not a like.** FEIP16 weighs it by the coin-days the
/// transaction destroys: a good rating adds that number to the ratee's
/// ``Freer/reputation``, a bad one subtracts it, and either way the
/// same number is added to their `hot`. So the interesting control on
/// this sheet is not the thumb, it is the **weight** — how much of your
/// own accumulated coin-days you are willing to burn to say it. One
/// coin-day is a shrug; a thousand is a statement, and it is gone
/// either way.
///
/// **It pays the ratee nothing.** The carve names them in its
/// `data.fid` (see ``ReputationFeip``), so a rating is a statement
/// about someone, not a transfer to them — worth saying on the sheet,
/// because "does rating cost me anything" is the obvious question and
/// the honest answer is *the miner fee, and the coin-days, which are
/// the point*.
///
/// The weight is a floor, not an exact amount: coin selection takes
/// whole cashes and cannot split a coin-day off one. Whatever it picks,
/// the transaction-approval sheet shows the coin-days that will really
/// be destroyed before anything is signed, and that is the number that
/// counts — so this sheet promises "at least", never "exactly".
struct RateFreerSheet: View {

    let session: ActiveSession
    let ratee: String
    /// The ratee's chain record, when the caller already has it. Saved
    /// re-fetching what the details sheet just read; nil is fine, the
    /// quote loads it.
    let freer: Freer?
    let onDone: (String) -> Void
    let onCancel: () -> Void

    @State private var rate: Rate = .good
    @State private var cause = ""
    @State private var weightText = "1"

    @State private var quote: ActiveSession.RateQuote?
    @State private var loading = true
    @State private var loadError: String?

    @State private var carving = false
    @State private var carveError: String?

    /// Coin-days this identity has to spend, as far as the cached cash
    /// snapshot knows — and nil when it knows nothing, which is not the
    /// same as zero. A known figure caps the weight so the sheet can
    /// refuse before the carve does; an unknown one caps nothing, and
    /// coin selection has the last word either way.
    @State private var availableCd: Int64?

    /// The weight as a number, or nil while the field holds something
    /// that isn't one.
    private var weightCd: Int64? {
        let trimmed = weightText.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed.allSatisfy(\.isNumber) else { return nil }
        return Int64(trimmed)
    }

    private var record: Freer? { quote?.freer ?? freer }

    /// Why this rating can't be sent, or nil when it can. Every refusal
    /// is one the chain would make anyway — checked here so the user
    /// learns it before paying a fee to find out.
    private var blockReason: String? {
        if ratee == session.liveFid {
            return "You are living as this FID — a FID cannot rate itself."
        }
        if !session.canSign {
            return "This identity has no private key on this Mac, so it cannot sign a rating."
        }
        if loading { return nil }
        if record == nil {
            return "This FID has no on-chain record. FEIP16 only applies a rating to a FID that has one, so the carve would cost the fee and change nothing."
        }
        guard let weightCd else { return "The weight has to be a whole number of coin-days." }
        if weightCd < 1 { return "A rating has to destroy at least 1 coin-day to be counted." }
        if let availableCd, weightCd > availableCd {
            return "This identity holds about \(Self.grouped(availableCd)) coin-days, which is less than the weight you asked for."
        }
        // Asked of the builder rather than estimated: the limit is on
        // encoded bytes, and a counter that guessed would let a cause
        // full of emoji through and refuse one that fits.
        if (try? ReputationFeip.carve(ratee: ratee, rate: rate, cause: cause)) == nil {
            return "The cause is too long to fit in the carve — shorten it."
        }
        return nil
    }

    /// Bytes the cause will occupy once encoded, against its budget.
    /// Only drawn once there is something to count.
    private var causeBudget: (used: Int, total: Int)? {
        let trimmed = cause.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return (trimmed.utf8.count, ReputationFeip.maxCauseBytes(ratee: ratee, rate: rate))
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
                    verdictPanel
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
        .frame(width: 560, height: 640)
        .task { await load() }
    }

    // MARK: - chrome

    private var header: some View {
        HStack(spacing: 12) {
            FidAvatarView(fid: ratee, size: 40, isNobody: record?.isNobody == true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    NobodyChip(fid: ratee, force: record?.isNobody == true, compact: false)
                    Text(record?.cid ?? ratee.elidingMiddle(head: 10, tail: 10))
                        .font(.title3.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                HStack(spacing: 10) {
                    standing("Reputation", record?.reputation)
                    standing("Hot", record?.hot)
                }
            }
            Spacer()
            if loading { ProgressView().controlSize(.small) }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private func standing(_ label: String, _ value: Int64?) -> some View {
        HStack(spacing: 4) {
            Text(label).font(.caption2).foregroundStyle(.tertiary)
            Text(value.map(Self.grouped) ?? "—")
                .font(.caption.monospacedDigit())
                .foregroundStyle(
                    (value ?? 0) < 0 ? Color.red : Color.secondary
                )
        }
    }

    private var footer: some View {
        HStack(spacing: 10) {
            if let blockReason, !loading {
                Text(blockReason)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(2)
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
                    Label(
                        rate == .good ? "Rate good" : "Rate bad",
                        systemImage: rate == .good ? "hand.thumbsup.fill" : "hand.thumbsdown.fill"
                    )
                }
            }
            .buttonStyle(.borderedProminent)
            .tint(rate == .good ? .green : .red)
            .disabled(!canSend)
        }
        .padding(12)
    }

    // MARK: - panels

    /// The thumb. Two big targets rather than a segmented control,
    /// because this is the sheet's decision and a rating carved the
    /// wrong way cannot be taken back — there is no update op, only
    /// another rating pulling the other way.
    private var verdictPanel: some View {
        panel("Your verdict") {
            HStack(spacing: 10) {
                verdictButton(.good, "hand.thumbsup.fill", "Good", .green)
                verdictButton(.bad, "hand.thumbsdown.fill", "Bad", .red)
            }
            caption(
                rate == .good
                    ? "Adds the weight below to this FID's reputation."
                    : "Subtracts the weight below from this FID's reputation. Reputation can go negative."
            )
        }
    }

    private func verdictButton(
        _ value: Rate, _ symbol: String, _ title: String, _ tint: Color
    ) -> some View {
        Button {
            rate = value
        } label: {
            HStack(spacing: 6) {
                Image(systemName: symbol)
                Text(title)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(tint.opacity(rate == value ? 0.22 : 0.06))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(tint.opacity(rate == value ? 0.8 : 0), lineWidth: 1.5)
            )
            .foregroundStyle(rate == value ? tint : Color.secondary)
        }
        .buttonStyle(.plain)
    }

    /// **The real control on this sheet.** Presets rather than a bare
    /// field first, because "how many coin-days is a strong opinion" is
    /// not a question most people can answer cold, and a typo of one
    /// extra zero here spends ten times the stake.
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
            caption(
                "A rating's force is the coin-days it destroys — \(rate == .good ? "added to" : "subtracted from") "
                    + "this FID's reputation, and added to their hot either way. The coin-days are spent, not lent."
            )
            caption(availableNote)
        }
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
                    "Public and permanent, like everything else in the carve. Left blank, the field is "
                        + "omitted rather than carved empty."
                )
                Spacer(minLength: 8)
                if let budget = causeBudget {
                    Text("\(Self.grouped(Int64(budget.used))) / \(Self.grouped(Int64(budget.total))) bytes")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(budget.used > budget.total ? Color.orange : Color.secondary)
                }
            }
        }
    }

    /// What this transaction actually does, in the order somebody
    /// deciding to send it would ask.
    private var costPanel: some View {
        panel("What gets carved") {
            costRow("About", ratee.elidingMiddle(head: 10, tail: 10))
            costRow("Verdict", rate == .good ? "good" : "bad")
            costRow("Coin-days", "at least \(weightCd.map(Self.grouped) ?? "—")")
            costRow("Paid to them", "nothing")
            caption(
                "A rating names its subject in the carve itself, so nothing is sent to them — "
                    + "you can rate a FID you have never paid and would never pay. What it costs "
                    + "you is the miner fee and the coin-days above, and the coin-days are not a "
                    + "fee: they are the weight."
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

    /// FEIP16 has no update op. Rating someone a second time does not
    /// replace the first rating, it adds another — which is worth
    /// saying before somebody "fixes" a rating and doubles it instead.
    private func alreadyRatedPanel(_ rows: [RepuHist]) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(rows.count == 1
                     ? "You have rated this FID before."
                     : "You have rated this FID \(rows.count) times before.")
                    .font(.callout)
                ForEach(rows) { row in
                    Text(summary(of: row))
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

    private func summary(of row: RepuHist) -> String {
        let verdict = row.kind.map { $0 == .good ? "Good" : "Bad" } ?? (row.rate ?? "—")
        let weight = row.hot.map { "\(Self.grouped($0)) CDD" } ?? "unknown weight"
        guard let time = row.time else { return "\(verdict) · \(weight)" }
        let seconds = time > 10_000_000_000 ? Double(time) / 1000 : Double(time)
        return "\(verdict) · \(weight) · \(Self.stamp.string(from: Date(timeIntervalSince1970: seconds)))"
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

    private static func grouped(_ n: Int64) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? String(n)
    }

    private static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    // MARK: - work

    private func load() async {
        loading = true
        loadError = nil
        defer { loading = false }
        // The cached snapshot, not a refresh: this is a hint next to a
        // field, and making the sheet wait on the network to show it
        // would be the wrong trade. The carve refreshes for real.
        // Zero reads as *unknown*, not as a ceiling: an identity whose
        // cashes have never been fetched on this Mac has an empty
        // snapshot, and blocking a rating on that would refuse a
        // perfectly fundable carve. A real zero is caught by coin
        // selection, which knows.
        let cached = (try? session.wallet.cachedSnapshot(forAddress: session.liveFid))?
            .cashes
            .filter { !$0.pendingSpend }
            .reduce(Int64(0)) { $0 + ($1.cd ?? 0) }
        availableCd = (cached ?? 0) > 0 ? cached : nil
        do {
            quote = try await session.quoteRating(of: ratee)
        } catch {
            loadError = "Couldn't check this FID before rating — \(error)"
        }
    }

    private func send() async {
        guard let weightCd else { return }
        // Rating a nobody spends coin days on a reputation anyone can wear.
        guard await NobodyGate.confirm([ratee], .rate, session: session) else { return }
        carving = true
        carveError = nil
        defer { carving = false }
        do {
            let txid = try await session.rateOnChain(
                ratee: ratee,
                rate: rate,
                cause: cause,
                weightCd: weightCd
            )
            onDone(txid)
        } catch {
            carveError = "\(error)"
        }
    }
}
