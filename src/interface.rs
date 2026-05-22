use std::net::{IpAddr, SocketAddr};
use crate::events::WgEvent;
use crate::net::Ipv4Network;
use crate::types::{PrivateKey, PublicKey};

pub struct Peer {
    pub public_key: PublicKey,
    /// Inner IP ranges this peer is allowed to use as a source (CIDR).
    pub allowed_ips: Vec<Ipv4Network>,
    /// Real outer UDP endpoint. None until we hear from the peer.
    pub endpoint: Option<SocketAddr>,
}

impl Peer {
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.allowed_ips.iter().any(|net| net.contains(ip))
    }

    pub fn first_ip(&self) -> Option<IpAddr> {
        self.allowed_ips.first().map(|net| IpAddr::V4(net.addr))
    }
}

pub struct Interface {
    pub name: String,
    pub private_key: PrivateKey,
    pub listen_port: u16,
    pub address: Ipv4Network,
    pub peers: Vec<Peer>,
}

impl Interface {
    pub fn new(name: &str, private_key: PrivateKey, listen_port: u16, address: Ipv4Network) -> Self {
        Self { name: name.to_string(), private_key, listen_port, address, peers: Vec::new() }
    }

    pub fn add_peer(
        &mut self,
        public_key: PublicKey,
        allowed_ips: Vec<Ipv4Network>,
        endpoint: Option<SocketAddr>,
    ) {
        self.peers.push(Peer { public_key, allowed_ips, endpoint });
    }

    /// Outbound: find the peer whose allowed_ips covers `dst`, encrypt (stub), send to endpoint.
    pub fn send(&self, dst: IpAddr, _payload: &[u8]) -> WgEvent {
        match self.route_outbound(dst) {
            Some(peer) => match peer.endpoint {
                Some(ep) => WgEvent::Sent { inner_dst: dst, peer: peer.public_key.clone(), outer_dst: ep },
                None => WgEvent::NoEndpoint { inner_dst: dst, peer: peer.public_key.clone() },
            },
            None => WgEvent::NoRoute { inner_dst: dst },
        }
    }

    /// Inbound: decrypt (stub), check allowed_ips, update endpoint on roam.
    pub fn recv(
        &mut self,
        outer_src: SocketAddr,
        from_key: &PublicKey,
        inner_src: IpAddr,
        _payload: &[u8],
    ) -> Vec<WgEvent> {
        let mut events = Vec::new();

        let Some(idx) = self.peers.iter().position(|p| &p.public_key == from_key) else {
            // Unknown key — in a real implementation this would be silently dropped.
            return events;
        };

        if !self.peers[idx].allows(inner_src) {
            events.push(WgEvent::Dropped {
                outer_src,
                peer: from_key.clone(),
                inner_src,
                reason: "not in allowed_ips",
            });
            return events;
        }

        // Roaming: valid packet from a new outer address → update endpoint silently.
        let prev = self.peers[idx].endpoint;
        if prev != Some(outer_src) {
            events.push(WgEvent::Roamed {
                peer: from_key.clone(),
                old_endpoint: prev,
                new_endpoint: outer_src,
            });
            self.peers[idx].endpoint = Some(outer_src);
        }

        events.push(WgEvent::Received {
            outer_src,
            peer: from_key.clone(),
            inner_src,
        });
        events
    }

    // --- Helpers used by the web server to simulate actions ---

    /// Send a test packet to the given peer (looked up by key label).
    pub fn simulate_send(&self, peer_key: &str) -> WgEvent {
        match self.peers.iter().find(|p| p.public_key.0 == peer_key) {
            Some(peer) => match peer.first_ip() {
                Some(ip) => self.send(ip, b"ping"),
                None => WgEvent::NoRoute { inner_dst: "0.0.0.0".parse().unwrap() },
            },
            None => WgEvent::NoRoute { inner_dst: "0.0.0.0".parse().unwrap() },
        }
    }

    /// Simulate receiving a packet from a peer (using their known endpoint as outer src).
    pub fn simulate_recv(&mut self, peer_key: &str) -> Vec<WgEvent> {
        let Some(idx) = self.peers.iter().position(|p| p.public_key.0 == peer_key) else {
            return vec![];
        };
        let outer_src = self.peers[idx]
            .endpoint
            .unwrap_or_else(|| "203.0.113.1:51820".parse().unwrap());
        let inner_src = match self.peers[idx].first_ip() {
            Some(ip) => ip,
            None => return vec![],
        };
        let key = self.peers[idx].public_key.clone();
        self.recv(outer_src, &key, inner_src, b"pong")
    }

    /// Simulate a peer roaming to a new outer IP (derived from a simple counter).
    pub fn simulate_roam(&mut self, peer_key: &str, roam_counter: u8) -> Vec<WgEvent> {
        let Some(idx) = self.peers.iter().position(|p| p.public_key.0 == peer_key) else {
            return vec![];
        };
        // Generate a new outer IP that differs from the current one.
        let new_outer: SocketAddr = format!("198.18.0.{}:51820", roam_counter).parse().unwrap();
        let inner_src = match self.peers[idx].first_ip() {
            Some(ip) => ip,
            None => return vec![],
        };
        let key = self.peers[idx].public_key.clone();
        self.recv(new_outer, &key, inner_src, b"roaming")
    }

    fn route_outbound(&self, dst: IpAddr) -> Option<&Peer> {
        self.peers.iter().find(|p| p.allows(dst))
    }
}
