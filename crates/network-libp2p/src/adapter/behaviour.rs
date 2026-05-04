//! libp2p network behaviour definition.

use libp2p::StreamProtocol;
use libp2p::connection_limits::Behaviour as ConnectionLimitsBehaviour;
use libp2p::gossipsub::Behaviour as GossipsubBehaviour;
use libp2p::identify::Behaviour as IdentifyBehaviour;
use libp2p::kad::Behaviour as KadBehaviour;
use libp2p::kad::store::MemoryStore as KadMemoryStore;
use libp2p::swarm::NetworkBehaviour;
use libp2p_stream::Behaviour as StreamBehaviour;

/// Protocol identifier for request/response streams.
pub const REQUEST_PROTOCOL: StreamProtocol = StreamProtocol::new("/hyperscale/request/1.0.0");

/// Protocol identifier for fire-and-forget notification streams.
pub const NOTIFY_PROTOCOL: StreamProtocol = StreamProtocol::new("/hyperscale/notify/1.0.0");

/// libp2p network behaviour combining gossipsub, Kademlia, and raw streams.
#[derive(NetworkBehaviour)]
pub(super) struct Behaviour {
    /// Gossipsub for efficient broadcast.
    pub(super) gossipsub: GossipsubBehaviour,

    /// Kademlia DHT for peer discovery.
    pub(super) kademlia: KadBehaviour<KadMemoryStore>,

    /// Raw streams for request/response (replaces `request_response`).
    /// `RequestManager` owns all timeout logic; this is just a "dumb pipe".
    pub(super) stream: StreamBehaviour,

    /// Identify protocol for peer versioning.
    pub(super) identify: IdentifyBehaviour,

    /// Connection limits to prevent storms.
    pub(super) limits: ConnectionLimitsBehaviour,
}
