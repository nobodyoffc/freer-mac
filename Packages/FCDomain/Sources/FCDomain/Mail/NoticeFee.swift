import Foundation

/// What it costs to mail someone.
///
/// A mail is addressed by **paying its recipient** — the FEIP carve
/// names no `to`, so the transaction's recipient output *is* the
/// address. That payment is the "notice fee": a FID can publish one
/// (FEIP `NoticeFee`, sn 10, landing on ``Freer/noticeFee``) to charge
/// strangers for their attention, and a sender's own preferences cap
/// what they are willing to pay before the mail is written.
///
/// **Everything here is satoshis.** The chain's `Freer.noticeFee` is a
/// decimal string in *coins*, and it is converted exactly once, at the
/// edge, by ``satoshis(coinString:)``. Android does not do this: it
/// carries the published fee as a `double` of coins while carrying the
/// fee a received mail actually paid as a `Long` of satoshis, then
/// compares and assigns between the two (Android issue C9). Keeping one
/// unit inside this type is the whole defence against that.
public enum NoticeFee {

    public static let satsPerCoin: Int64 = 100_000_000

    /// `MailManager.DEFAULT_MAIL_FEE_SATOSHI` — what you pay a FID that
    /// has published no fee of its own. 0.0001 F.
    public static let defaultFeeSats: Int64 = 10_000

    /// `MailManager.DEFAULT_MAX_PAYING_NOTICE_FEE` = "100", i.e. 100 F.
    /// A ceiling this high is not really a spending limit; it is a
    /// guard against a typo or a hostile `noticeFee` on someone's
    /// on-chain record turning a mail into a donation.
    public static let defaultMaxPayingSats: Int64 = 100 * satsPerCoin

    /// The payment cannot be smaller than this, whatever the recipient
    /// asks for, because an output below the dust threshold is not
    /// relayable — and with no output the mail has no recipient at all.
    /// So a FID that publishes a fee of zero still gets paid dust: the
    /// output is the addressing, not the charge.
    public static let minimumPayableSats = CoinSelector.dustThresholdSats

    /// What to pay, or why we won't.
    public enum Decision: Equatable, Sendable {
        /// Pay this many satoshis to the recipient.
        case pay(Int64)
        /// The recipient charges more than this sender is willing to
        /// pay. Android returns a bare `-1` here; carrying both numbers
        /// lets the UI say which limit was hit and by how much.
        case refuse(requested: Int64, limit: Int64)

        public var satoshis: Int64? {
            if case .pay(let sats) = self { return sats }
            return nil
        }
    }

    /// Decide the fee for a mail to a recipient whose on-chain record
    /// says `recipientNoticeFee` (a coin-denominated decimal string, or
    /// nil when they publish none).
    ///
    /// Ports `MailManager.calculateMailFee` plus the reply rule in
    /// `CreateMailActivity.sendMail`, with **one deliberate
    /// divergence**: the pay-back bump is subject to the same limit as
    /// everything else. Android applies the cap first and the bump
    /// afterwards, so replying can pay any amount at all — someone who
    /// mails you with a large notice fee attached could make your reply
    /// return it regardless of the ceiling you set. A maximum that a
    /// remote party can step around is not a maximum.
    ///
    /// - Parameters:
    ///   - recipientNoticeFee: their published fee, in coins.
    ///   - maxPayingSats: this sender's ceiling.
    ///   - payBack: whether to match what a correspondent paid us when
    ///     replying (`PAY_BACK_NOTICE_FEE`, on by default in Android).
    ///   - receivedNoticeFeeSats: the ``Mail/noticeFee`` of the mail
    ///     being replied to, i.e. what they paid us. Nil for a fresh
    ///     mail — the bump only applies to replies.
    public static func decide(
        recipientNoticeFee: String?,
        maxPayingSats: Int64 = defaultMaxPayingSats,
        payBack: Bool = true,
        receivedNoticeFeeSats: Int64? = nil
    ) -> Decision {
        var amount = satoshis(coinString: recipientNoticeFee) ?? defaultFeeSats

        if payBack, let received = receivedNoticeFeeSats, received > amount {
            amount = received
        }
        if amount > maxPayingSats {
            return .refuse(requested: amount, limit: maxPayingSats)
        }
        return .pay(max(amount, minimumPayableSats))
    }

    // MARK: - units

    /// Parse a coin-denominated decimal string into satoshis. Returns
    /// nil for anything that isn't a usable non-negative number, which
    /// the caller reads as "no fee published" and falls back to the
    /// default — the same shape as Android's null check, but it also
    /// absorbs the garbage `Double.parseDouble` would throw on.
    ///
    /// Uses `Decimal`, not `Double`: 0.0001 F is not representable in
    /// binary floating point, and a fee that arrives one satoshi light
    /// because of a rounding artefact would be a mail the recipient
    /// filters out.
    ///
    /// The grammar is checked before parsing, because `Decimal(string:)`
    /// stops at the first character it doesn't understand and reports
    /// success on the prefix. `"1,5"` would parse as **1** — a third of
    /// what a European-formatted record meant to charge — and `"0x10"`
    /// as 0. Silently paying the wrong amount is worse than treating the
    /// record as unpublished.
    public static func satoshis(coinString: String?) -> Int64? {
        guard let raw = coinString?.trimmingCharacters(in: .whitespacesAndNewlines),
              isPlainDecimal(raw),
              let coins = Decimal(string: raw, locale: Locale(identifier: "en_US_POSIX")),
              coins >= 0
        else { return nil }

        var scaled = coins * Decimal(satsPerCoin)
        var rounded = Decimal()
        NSDecimalRound(&rounded, &scaled, 0, .plain)
        // Beyond Int64 this is not a fee, it is a typo or an attack.
        guard rounded <= Decimal(Int64.max) else { return nil }
        return NSDecimalNumber(decimal: rounded).int64Value
    }

    /// Digits with at most one `.`, and at least one digit — no sign, no
    /// exponent, no separators, nothing trailing.
    static func isPlainDecimal(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 40 else { return false }
        var seenDot = false
        var digits = 0
        for ch in s {
            if ch == "." {
                if seenDot { return false }
                seenDot = true
            } else if ch.isASCII, ch.isNumber {
                digits += 1
            } else {
                return false
            }
        }
        return digits > 0
    }

    /// Satoshis back to the coin-denominated string the `NoticeFee` FEIP
    /// and the UI use. Trailing zeros are trimmed so 10 000 sat reads as
    /// `0.0001`, not `0.00010000`.
    public static func coinString(satoshis: Int64) -> String {
        let coins = Decimal(satoshis) / Decimal(satsPerCoin)
        var s = NSDecimalNumber(decimal: coins).stringValue
        if s.contains(".") {
            while s.hasSuffix("0") { s.removeLast() }
            if s.hasSuffix(".") { s.removeLast() }
        }
        return s
    }
}
