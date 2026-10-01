import Foundation
import FCTransport

/// Paying a DOCK so it serves us again.
///
/// A FAPI server keeps a prepaid balance per FID and bills **every**
/// call by the bytes it moves — `dock.fetch` and `dock.put`, but also
/// `base.search`, `base.cashValid` and the rest. Once the balance and
/// the service's small credit allowance are spent, the server answers
/// 402 to everything. Topping up is an ordinary FCH payment to the
/// service's **dealer**: the server watches that address and credits
/// the *payer* — the FID that spent the inputs — after one confirmation
/// (FC-JDK `FapiServer.queryNewCashesForDealer`).
///
/// **Paying while broke.** Nothing that costs anything can be asked, so
/// both halves of the payment come from the two things the server gives
/// away, the same pair Android's `AutoRechargeManager` uses:
///
///   - *who to pay* from the PING/PONG service advert (``PongInfoAsking``),
///     which sits below the billing gate;
///   - *what to pay with* from the 402 itself: the server attaches the
///     payer's spendable cashes, enough for its minimum payment, and
///     lets that FID broadcast **one** `base.broadcastTx` free within
///     60 seconds (`FapiServer.sendPaymentRequiredWithCashes`).
///
/// So the payment is built from exactly those cashes and broadcast
/// through that same server, straight after asking for them.
///
/// **Always paid from the main FID.** Every DOCK connection this app
/// opens is handshaked with the main's key (``DockRegistry`` polls as the
/// main), so the main is the account the server charges. A top-up from
/// a sub-identity would credit a FID the DOCK never sees.
public struct DockTopUp: Sendable {

    public enum Source: Sendable {
        /// The server described itself in its PONG.
        case advert
        /// Found on the chain by matching its address.
        case chain
    }

    /// The server that asked to be paid. Normalised.
    public let dockUrl: String
    /// Its service record, as far as we know it. An advert carries only
    /// the identity and pricing fields.
    public let service: Service
    public let source: Source
    /// Where the payment goes.
    public let dealer: String
    /// The FID that pays, and the one the server credits.
    public let payer: String
    /// The smallest payment the service publishes, if any.
    public let minPaymentSats: Int64?
    /// Cashes the server attached to its 402 — what a FID with no
    /// balance there can pay from. Empty when the server still serves
    /// us (the shortfall was a single large fetch) or found nothing.
    public let offeredCashes: [Cash]

    public var offeredSats: Int64 { offeredCashes.reduce(0) { $0 + $1.value } }

    /// What this Mac's cash cache can add on top of the offered cashes,
    /// for a payment larger than the server's minimum.
    public let localSats: Int64

    /// What the sheet offers first. With offered cashes, the minimum
    /// payment, which is what the server picked them to cover; without,
    /// the minimum or 0.01 F, whichever is more — at typical prices
    /// months of messages, and a sum nobody will miss.
    public var suggestedSats: Int64 {
        if !offeredCashes.isEmpty, let minPaymentSats { return minPaymentSats }
        return max(minPaymentSats ?? 0, Self.floorSuggestionSats)
    }

    public static let floorSuggestionSats: Int64 = NoticeFee.satsPerCoin / 100

    /// The API asked to draw a 402 out of a broke account. Any billed
    /// call would do; this one is the cheapest to have succeed by
    /// accident when the account is not broke after all.
    static let probeApi = "base.health"

    public enum Failure: Error, CustomStringConvertible {
        case noConnection(dockUrl: String)
        case unidentified(dockUrl: String, reason: String)
        case noDealer(service: String)
        case expectedCashes
        case broadcastRefused(reason: String, usedLocal: Bool)

        public var description: String {
            switch self {
            case .noConnection(let url):
                return "Could not connect to \(url), so there is nobody to ask who to pay. Try again in a minute."
            case let .unidentified(url, reason):
                return "\(url) does not say who it is, and looking it up on the chain failed: \(reason)"
            case .noDealer(let name):
                return "\(name) publishes no dealer, so there is no address to pay."
            case .expectedCashes:
                return "The server no longer offers cashes to pay from, so the payment cannot be built. Close this and open it again."
            case let .broadcastRefused(reason, usedLocal):
                let hint = usedLocal
                    ? " Some of the cashes came from this Mac's cache, and one may already be spent; refresh the Cash pane, or pay no more than the server offered."
                    : ""
                return "The payment was not accepted: \(reason).\(hint) Close this and open it again to get a new free broadcast."
            }
        }
    }

    /// The services a PONG advert names. Values arrive as strings or
    /// numbers depending on the server's JSON writer, so both are taken.
    public static func services(fromPongInfo data: Data) -> [Service] {
        guard !data.isEmpty,
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let list = root["services"] as? [[String: Any]]
        else { return [] }
        func text(_ any: Any?) -> String? {
            switch any {
            case let s as String: return s.isEmpty ? nil : s
            case let n as NSNumber: return n.stringValue
            default: return nil
            }
        }
        return list.map { item in
            var service = Service(
                stdName: text(item["name"]),
                type: text(item["type"]),
                components: item["components"] as? [String],
                ver: text(item["ver"]),
                dealerPubkey: text(item["dealerPubkey"]),
                pricePerKB: text(item["pricePerKB"]),
                minPayment: text(item["minPayment"]),
                minCredit: text(item["minCredit"])
            )
            service.id = text(item["sid"])
            return service
        }
    }

    /// The dealer FID a record names: its `dealer`, else the FID of its
    /// `dealerPubkey`.
    static func dealer(of service: Service) -> String? {
        if let d = service.dealer?.trimmingCharacters(in: .whitespaces), !d.isEmpty { return d }
        return service.dealerPubkey.flatMap(Service.dealerFid(ofPubkey:))
    }
}

extension ActiveSession {

    /// Who to pay, how much, and with what, to get `dockUrl` serving us
    /// again.
    ///
    /// The server is asked first, through its free PONG advert. Only if
    /// it advertises nothing usable do we fall back to the resolver's
    /// cache and then a chain search for a DOCK record at this address —
    /// which goes through our own server and may itself be refused.
    public func dockTopUp(for dockUrl: String, timeoutMs: Int = 15_000) async throws -> DockTopUp {
        let url = FudpUrl.normalize(dockUrl) ?? dockUrl
        guard let client = await dockRegistry.client(for: url) else {
            throw DockTopUp.Failure.noConnection(dockUrl: url)
        }

        var service: Service?
        var source = DockTopUp.Source.advert
        if let asker = client as? PongInfoAsking,
           let info = try? await asker.pongInfo(timeoutMs: 5_000) {
            let advertised = DockTopUp.services(fromPongInfo: info)
                .filter { DockTopUp.dealer(of: $0) != nil }
            service = advertised.first { $0.offers(ServiceName.dock) } ?? advertised.first
        }
        if service == nil {
            source = .chain
            service = await homeServices.cachedService(url: url)
            if service == nil {
                do {
                    service = try await directory.service(
                        at: url, offering: [ServiceName.dock], timeoutMs: timeoutMs
                    )
                } catch {
                    throw DockTopUp.Failure.unidentified(dockUrl: url, reason: String(describing: error))
                }
            }
        }
        guard let service else {
            throw DockTopUp.Failure.unidentified(
                dockUrl: url, reason: "no DOCK record on the chain names this address."
            )
        }
        guard let dealer = DockTopUp.dealer(of: service) else {
            throw DockTopUp.Failure.noDealer(service: service.displayName)
        }

        let offered = await cashesOffered(by: client)
        return DockTopUp(
            dockUrl: url,
            service: service,
            source: source,
            dealer: dealer,
            payer: mainFid,
            minPaymentSats: NoticeFee.satoshis(coinString: service.minPayment).flatMap { $0 > 0 ? $0 : nil },
            offeredCashes: offered,
            localSats: offered.isEmpty ? 0 : wallet
                .localTopUpCashes(fromAddress: mainFid, excluding: offered)
                .reduce(0) { $0 + $1.value }
        )
    }

    /// Pay `amount` satoshis to the DOCK's dealer from the main FID, and
    /// let the next fetch pass ask that DOCK again rather than wait out
    /// its cooldown. The credit lands once the payment confirms; until
    /// then the server keeps saying 402, which the courier takes quietly.
    ///
    /// When the server offered cashes, they are asked for **again** here
    /// rather than reused from ``dockTopUp(for:timeoutMs:)``: the free
    /// broadcast they come with lasts 60 seconds, and the user may have
    /// spent longer than that reading the sheet. The broadcast then goes
    /// through that same server, the only one that granted the pass.
    @discardableResult
    public func payDockTopUp(
        _ topUp: DockTopUp,
        amount: Int64,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> WalletService.SendResult {
        let privkey = try mainPrikey()
        let result: WalletService.SendResult
        if topUp.offeredCashes.isEmpty {
            result = try await wallet.send(
                fromAddress: topUp.payer, privkey: privkey,
                to: topUp.dealer, amount: amount,
                feePerByte: feePerByte, timeoutMs: timeoutMs
            )
        } else {
            guard let client = await dockRegistry.client(for: topUp.dockUrl) else {
                throw DockTopUp.Failure.noConnection(dockUrl: topUp.dockUrl)
            }
            let fresh = await cashesOffered(by: client)
            guard !fresh.isEmpty else { throw DockTopUp.Failure.expectedCashes }
            let wallet = wallet(over: client)
            let inputs = try wallet.topUpInputs(
                offered: fresh, fromAddress: topUp.payer, amount: amount, feePerByte: feePerByte
            )
            do {
                result = try await wallet.send(
                    fromAddress: topUp.payer, privkey: privkey,
                    to: topUp.dealer, amount: amount,
                    feePerByte: feePerByte, using: inputs, timeoutMs: timeoutMs
                )
            } catch let refusal as WalletService.Failure {
                // Only the server's answer to the broadcast is reworded;
                // a decline in the approval dialog, or a cash the wallet
                // itself will not spend, already says what happened.
                guard case .fapiNonZeroCode = refusal else { throw refusal }
                // The free pass is spent by the attempt, whatever came
                // of it. Reopening asks for a new 402 and a new pass.
                throw DockTopUp.Failure.broadcastRefused(
                    reason: String(describing: refusal),
                    usedLocal: inputs.count > fresh.count
                )
            }
        }
        await dockRegistry.markTopUpSent(topUp.dockUrl, txid: result.remoteTxid)
        return result
    }

    /// The payer's cashes a broke server attaches to its 402, which also
    /// opens its one free broadcast. Empty when the call went through —
    /// the account is not broke at the gate — or the server found none.
    /// Anything not owned by the payer is dropped: the server picked
    /// these, and signing for someone else's coin would only fail later.
    private func cashesOffered(by client: any FapiCalling) async -> [Cash] {
        guard let reply = try? await client.call(
            api: DockTopUp.probeApi, params: nil, fcdsl: nil, binary: nil,
            sid: nil, via: nil, maxCost: nil, timeoutMs: 10_000
        ),
              reply.response.code == DockService.Failure.paymentRequiredCode,
              let data = reply.response.data,
              let cashes = try? JSONDecoder().decode([Cash].self, from: data)
        else { return [] }
        return cashes.filter { $0.owner == mainFid }
    }
}
