import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The ratings one record has received — who, how much, and now why.
///
/// **The record carries the average; this carries the argument.** A
/// `tRate` of 3.4 is the CDD-weighted mean of rows nobody could see
/// until the history was read, and a mean is exactly the statistic that
/// hides how it was made: 3.4 from forty balanced opinions and 3.4 from
/// one 5 and one 1 with a thousand coin-days behind it are the same
/// number and not the same fact. So the weight is shown on every row,
/// and the rows are ordered newest first rather than by weight — the
/// point is to be readable, not to rank.
///
/// Ratings carved before `cause` existed simply have none; that is not
/// an error state and is not drawn as one.
struct RatingHistoryView: View {

    let session: ActiveSession
    let kind: RatableKind
    let subjectId: String
    /// Resolved names for the FIDs on show, when the caller has them.
    var name: (String) -> String? = { _ in nil }

    @State private var rows: [RatingHist] = []
    @State private var cursor: [String]?
    @State private var total: Int64?
    @State private var loading = false
    @State private var loadError: String?
    @State private var loadedOnce = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            heading

            if let loadError {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                    CopyableText(loadError, font: .caption, color: .orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                .foregroundStyle(.orange)
            }

            if rows.isEmpty {
                if loading {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Reading ratings…").font(.caption).foregroundStyle(.secondary)
                    }
                } else if loadedOnce && loadError == nil {
                    Text("No ratings yet.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                        if index > 0 { Divider() }
                        rowView(row)
                    }
                }
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color(NSColor.controlBackgroundColor))
                )

                if cursor != nil {
                    Button {
                        Task { await loadMore() }
                    } label: {
                        if loading {
                            ProgressView().controlSize(.small)
                        } else {
                            Text("Load more")
                        }
                    }
                    .buttonStyle(.link)
                    .disabled(loading)
                }
            }
        }
        .task(id: subjectId) { await reload() }
    }

    private var heading: some View {
        HStack(spacing: 6) {
            Text("Ratings")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let total, total > 0 {
                Text("\(total)")
                    .font(.caption2.monospacedDigit())
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.secondary.opacity(0.15)))
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if loading && !rows.isEmpty {
                ProgressView().controlSize(.small)
            }
        }
    }

    private func rowView(_ row: RatingHist) -> some View {
        HStack(alignment: .top, spacing: 10) {
            scoreBadge(row)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    FidValue(row.signer, name: row.signer.flatMap(name))
                    Spacer(minLength: 0)
                    Text(weightText(row))
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                if let cause = row.cause?.trimmingCharacters(in: .whitespacesAndNewlines),
                   !cause.isEmpty {
                    CopyableText(cause, font: .caption)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let when = timeText(row) {
                    Text(when).font(.caption2).foregroundStyle(.tertiary)
                }
            }
        }
        .padding(10)
    }

    /// The score, coloured the way the rating sheet colours it, so the
    /// same number reads the same in both places.
    ///
    /// A row outside 0–5 still renders, uncoloured. Those can exist:
    /// the five Publish parsers bounded `rate` only recently, and a 9
    /// indexed before that is still on chain and still in the mean.
    private func scoreBadge(_ row: RatingHist) -> some View {
        let tint = row.score.map(RateRecordSheet.tint(for:)) ?? .secondary
        return Text(row.rate.map(String.init) ?? "—")
            .font(.callout.bold().monospacedDigit())
            .frame(width: 26, height: 26)
            .background(RoundedRectangle(cornerRadius: 6).fill(tint.opacity(0.18)))
            .foregroundStyle(tint)
    }

    private func weightText(_ row: RatingHist) -> String {
        guard let cdd = row.cdd else { return "weight unknown" }
        return "\(RateRecordSheet.grouped(cdd)) CDD"
    }

    private func timeText(_ row: RatingHist) -> String? {
        guard let time = row.time else { return nil }
        let seconds = time > 10_000_000_000 ? Double(time) / 1000 : Double(time)
        return RateRecordSheet.stamp.string(from: Date(timeIntervalSince1970: seconds))
    }

    // MARK: - work

    private func reload() async {
        guard !subjectId.isEmpty else {
            rows = []; cursor = nil; total = nil; loadedOnce = true
            return
        }
        loading = true
        loadError = nil
        defer { loading = false; loadedOnce = true }
        do {
            let page = try await session.ratingService.ratings(of: kind, subjectId: subjectId)
            rows = page.ratings
            cursor = page.last
            total = page.total
        } catch {
            loadError = "Couldn't read the ratings — \(error)"
        }
    }

    private func loadMore() async {
        guard let cursor, !loading else { return }
        loading = true
        defer { loading = false }
        do {
            let page = try await session.ratingService.ratings(
                of: kind, subjectId: subjectId, after: cursor
            )
            // Appended by id rather than blindly, because a page
            // boundary that lands on rows sharing a height can repeat
            // one, and a duplicated rating reads as a second opinion.
            let known = Set(rows.compactMap(\.id))
            rows.append(contentsOf: page.ratings.filter { $0.id.map { !known.contains($0) } ?? false })
            self.cursor = page.last
            if let t = page.total { total = t }
        } catch {
            loadError = "Couldn't read more ratings — \(error)"
        }
    }
}

/// The compact "3.4 from 12k CDD" pair a detail sheet shows beside its
/// other fields, so a record's standing is legible without opening the
/// history.
///
/// Draws an em dash rather than `0.00` when nothing has rated the
/// record: an unrated record and a record rated zero are different
/// facts, and `tRate` is nil for the first and 0 for the second.
struct RatingSummaryView: View {
    let tRate: Float?
    let tCdd: Int64?

    var body: some View {
        HStack(spacing: 6) {
            if let tRate {
                Text(String(format: "%.2f", tRate))
                    .font(.caption.bold().monospacedDigit())
                    .foregroundStyle(tint)
                Text("/ 5").font(.caption2).foregroundStyle(.tertiary)
                if let tCdd, tCdd > 0 {
                    Text("· \(RateRecordSheet.grouped(tCdd)) CDD")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("—").font(.caption).foregroundStyle(.tertiary)
                Text("unrated").font(.caption2).foregroundStyle(.tertiary)
            }
        }
    }

    private var tint: Color {
        guard let tRate else { return .secondary }
        return RateRecordSheet.tint(for: RateScore(rawValue: Int(tRate.rounded())) ?? .three)
    }
}
