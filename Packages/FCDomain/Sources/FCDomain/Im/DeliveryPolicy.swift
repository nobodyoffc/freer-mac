import Foundation

/// Which routes to try, in which order, to get one message to one peer
/// — the decision half of Android's `P2pHandler.sendP2p`, lifted out of
/// the sending code so it can be reasoned about and tested without a
/// network.
///
/// The order is **direct, then relay, then store-and-forward**, and it
/// is an order of *preference*, not of likelihood:
///
/// 1. **FUDP direct** reaches the peer's own device and nobody else's.
///    It only works when they are online and have registered a FUDP
///    endpoint, so it is tried first and expected to fail often.
/// 2. **ROAD relay** hands the sealed envelope to a relay that forwards
///    it live. Still only works if the peer is online; the relay learns
///    who is talking to whom, which is why it is opt-in.
/// 3. **DOCK** stores the envelope until the peer next comes looking.
///    It is the only route that works for someone who is offline, so it
///    is the default and the last resort at once.
///
/// Within DOCK the preference is the recipient's **own** DOCK before our
/// own DOCK's forwarding service. Android spells out why and it is worth
/// keeping: a direct put is one hop and the sender pays only that DOCK's
/// ingress and storage, so it works even when our own DOCK will not
/// forward or we cannot afford the forwarding fee.
public enum DeliveryPolicy {

    /// One route, with what the sender needs in order to take it.
    public enum Route: Equatable, Sendable {
        case fudpDirect
        case roadRelay(url: String)
        /// Straight to the recipient's DOCK.
        case recipientDock(url: String)
        /// Our DOCK, forwarding to the recipient's.
        case ownDockForward(recipientDockUrl: String?)

        /// The ``DeliveryMethod`` to stamp on a message this route
        /// delivered. Both DOCK routes end with the envelope stored, so
        /// both report `dockStored` — the difference between them is who
        /// paid, not what happened.
        public var deliveryMethod: DeliveryMethod {
            switch self {
            case .fudpDirect: return .fudpDirect
            case .roadRelay: return .roadRelay
            case .recipientDock, .ownDockForward: return .dockStored
            }
        }
    }

    /// What the sender currently knows it can do. Every field is a fact
    /// about *this attempt* — a setting the user chose, or an address we
    /// managed to resolve — so a route missing from the plan is always
    /// traceable to one of them being absent.
    public struct Capabilities: Equatable, Sendable {
        /// The user's `useFudpDirect` setting.
        public var fudpDirectEnabled: Bool
        /// Whether the peer has a FUDP endpoint we could reach.
        public var peerFudpReachable: Bool
        /// The user's `useRoadRelay` setting. Off by default: a relay
        /// sees the metadata even though it cannot read the body.
        public var roadRelayEnabled: Bool
        /// The peer's ROAD, resolved from their `Freer.home`.
        public var roadUrl: String?
        /// The peer's DOCK, resolved from their `Freer.home`.
        public var recipientDockUrl: String?
        /// Whether we have a DOCK of our own that could forward.
        public var ownDockAvailable: Bool

        public init(
            fudpDirectEnabled: Bool = false,
            peerFudpReachable: Bool = false,
            roadRelayEnabled: Bool = false,
            roadUrl: String? = nil,
            recipientDockUrl: String? = nil,
            ownDockAvailable: Bool = false
        ) {
            self.fudpDirectEnabled = fudpDirectEnabled
            self.peerFudpReachable = peerFudpReachable
            self.roadRelayEnabled = roadRelayEnabled
            self.roadUrl = roadUrl
            self.recipientDockUrl = recipientDockUrl
            self.ownDockAvailable = ownDockAvailable
        }
    }

    /// The routes to try, best first. An empty plan means there is no
    /// way to reach this peer at all — which is a *permanent* failure
    /// for this attempt, not something retrying will fix, since nothing
    /// in the plan depends on the network being up.
    public static func plan(_ capabilities: Capabilities) -> [Route] {
        var routes: [Route] = []

        if capabilities.fudpDirectEnabled, capabilities.peerFudpReachable {
            routes.append(.fudpDirect)
        }
        if capabilities.roadRelayEnabled, let road = capabilities.roadUrl, !road.isEmpty {
            routes.append(.roadRelay(url: road))
        }
        if let dock = capabilities.recipientDockUrl, !dock.isEmpty {
            routes.append(.recipientDock(url: dock))
        }
        if capabilities.ownDockAvailable {
            routes.append(.ownDockForward(recipientDockUrl: capabilities.recipientDockUrl))
        }
        return routes
    }

    /// How to report a plan that came to nothing.
    ///
    /// An empty plan is permanent: we have no address for this peer and
    /// no DOCK of our own, and no amount of waiting changes either. A
    /// plan that existed but whose every route failed is transient: the
    /// addresses were real, the network was not.
    public static func outcome(plan: [Route], allRoutesFailed: Bool) -> SendResult {
        if plan.isEmpty { return .failPermanent }
        return allRoutesFailed ? .retryTransient : .success
    }
}
