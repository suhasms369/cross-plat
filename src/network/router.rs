use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::network::peer::{SharedPeerState, PeerStatus};
use crate::network::gossip::GossipTable;

/// Which node currently has mouse+keyboard control.
#[derive(Debug, Clone, PartialEq)]
pub enum ActiveNode {
    /// This local machine has control.
    Local,
    /// A remote peer has control. Input events are forwarded to them.
    Remote(String),
}

/// Result of a routing decision.
#[derive(Debug, Clone)]
pub enum RouteDecision {
    /// Send input to this direct peer name.
    SendTo(String),
    /// No live path available — block cursor at edge.
    Block,
    /// Stay local.
    Local,
}

pub struct Router {
    config:       Arc<Config>,
    peers:        Arc<Mutex<HashMap<String, SharedPeerState>>>,
    gossip_table: GossipTable,
    pub active:   Arc<Mutex<ActiveNode>>,
}

impl Router {
    pub fn new(
        config: Arc<Config>,
        peers:  Arc<Mutex<HashMap<String, SharedPeerState>>>,
        gossip_table: GossipTable,
    ) -> Self {
        Self {
            config,
            peers,
            gossip_table,
            active: Arc::new(Mutex::new(ActiveNode::Local)),
        }
    }

    /// Called when cursor hits an edge.
    /// Returns the peer name to hand off to (which might be indirect via gossip).
    pub async fn route_edge(&self, edge: &str) -> RouteDecision {
        let target_name = match edge {
            "left"  => self.config.left_neighbor(),
            "right" => self.config.right_neighbor(),
            _       => return RouteDecision::Block,
        };

        let target = match target_name {
            Some(t) => t,
            None    => return RouteDecision::Block, // we're at the end of the topology
        };

        // Check if target is a direct peer and alive
        if let Some(alive) = self.peer_alive(target).await {
            if alive {
                return RouteDecision::SendTo(target.to_string());
            }
        }

        // Target is down or unknown directly. Try gossip table for 2-hop route.
        // E.g. target=C is down, but we learned about C via B, and B is alive.
        // We send EdgeHandoff to B, which relays to C if it can.
        // In our mesh topology this degrades gracefully.
        let gossip = self.gossip_table.lock().await;
        if let Some(indirect) = gossip.get(target) {
            if indirect.status == crate::network::protocol::PeerStatus::Up {
                // Route via the peer who told us about this node
                let via = indirect.via.clone();
                drop(gossip);
                if let Some(true) = self.peer_alive(&via).await {
                    tracing::info!("Routing to {} via {} (gossip fallback)", target, via);
                    return RouteDecision::SendTo(via);
                }
            }
        }

        tracing::warn!("No live path to {} edge ({}) — blocking cursor", edge, target);
        RouteDecision::Block
    }

    /// Forward all current input to the active remote peer, or handle locally.
    pub async fn current_destination(&self) -> RouteDecision {
        let active = self.active.lock().await.clone();
        match active {
            ActiveNode::Local => RouteDecision::Local,
            ActiveNode::Remote(ref peer) => {
                if let Some(true) = self.peer_alive(peer).await {
                    RouteDecision::SendTo(peer.clone())
                } else {
                    // Remote went down — snap back to local
                    tracing::warn!("Active peer {} went down — snapping back to local", peer);
                    *self.active.lock().await = ActiveNode::Local;
                    RouteDecision::Local
                }
            }
        }
    }

    pub async fn set_active(&self, node: ActiveNode) {
        let mut a = self.active.lock().await;
        tracing::info!("Active node: {:?} → {:?}", *a, node);
        *a = node;
    }

    async fn peer_alive(&self, name: &str) -> Option<bool> {
        let peers = self.peers.lock().await;
        let ps = peers.get(name)?;
        let s = ps.lock().await;
        Some(s.status == PeerStatus::Authenticated)
    }
}
