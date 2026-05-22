use std::net::{IpAddr, SocketAddr};
use crate::events::WgEvent;
use crate::net::Ipv4Network;
use crate::types::{PrivateKey, PublicKey};

pub struct Peer {
    pub public_key: PublicKey,
    pub allowed_ips: Vec<Ipv4Network>,
    pub endpoint: Option<SocketAddr>,
    /// Symmetric session key derived from the Noise_IKpsk2 handshake. None until first use.
    pub session_key: Option<String>,
    /// Outbound ChaCha20-Poly1305 nonce counter. Incremented on every sent packet.
    pub send_nonce: u64,
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
    pub public_key: PublicKey,
    pub listen_port: u16,
    pub address: Ipv4Network,
    pub peers: Vec<Peer>,
}

/// Produce a deterministic-looking 32-byte hex session key for the demo.
/// XORs bytes from both key labels with a position-dependent constant.
fn fake_session_key(peer_key: &str, iface_key: &str) -> String {
    let pb = peer_key.as_bytes();
    let ib = iface_key.as_bytes();
    (0u8..32)
        .map(|i| {
            let p = pb[usize::from(i) % pb.len().max(1)];
            let k = ib[usize::from(i) % ib.len().max(1)];
            format!("{:02x}", p ^ k ^ i.wrapping_mul(37))
        })
        .collect()
}

impl Interface {
    pub fn new(
        name: &str,
        private_key: PrivateKey,
        public_key: PublicKey,
        listen_port: u16,
        address: Ipv4Network,
    ) -> Self {
        Self { name: name.to_string(), private_key, public_key, listen_port, address, peers: Vec::new() }
    }

    pub fn add_peer(
        &mut self,
        public_key: PublicKey,
        allowed_ips: Vec<Ipv4Network>,
        endpoint: Option<SocketAddr>,
    ) {
        self.peers.push(Peer {
            public_key,
            allowed_ips,
            endpoint,
            session_key: None,
            send_nonce: 0,
        });
    }

    /// Outbound: find peer by allowed_ips, run handshake if needed, encrypt (stub), send.
    pub fn send(&mut self, dst: IpAddr, _payload: &[u8]) -> Vec<WgEvent> {
        let Some(idx) = self.peers.iter().position(|p| p.allows(dst)) else {
            return vec![WgEvent::NoRoute { inner_dst: dst }];
        };

        let Some(ep) = self.peers[idx].endpoint else {
            return vec![WgEvent::NoEndpoint { inner_dst: dst, peer: self.peers[idx].public_key.clone() }];
        };

        let mut events = Vec::new();

        if self.peers[idx].session_key.is_none() {
            let sk = fake_session_key(&self.peers[idx].public_key.0, &self.private_key.0);
            self.peers[idx].session_key = Some(sk.clone());
            events.push(WgEvent::HandshakeCompleted {
                peer: self.peers[idx].public_key.clone(),
                session_key: sk,
            });
        }

        let nonce = self.peers[idx].send_nonce;
        self.peers[idx].send_nonce += 1;

        events.push(WgEvent::Sent {
            inner_dst: dst,
            peer: self.peers[idx].public_key.clone(),
            outer_dst: ep,
            nonce,
        });
        events
    }

    /// Inbound: decrypt (stub), run handshake if needed, check allowed_ips, update endpoint on roam.
    pub fn recv(
        &mut self,
        outer_src: SocketAddr,
        from_key: &PublicKey,
        inner_src: IpAddr,
        _payload: &[u8],
    ) -> Vec<WgEvent> {
        let mut events = Vec::new();

        let Some(idx) = self.peers.iter().position(|p| &p.public_key == from_key) else {
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

        if self.peers[idx].session_key.is_none() {
            let sk = fake_session_key(&from_key.0, &self.private_key.0);
            self.peers[idx].session_key = Some(sk.clone());
            events.push(WgEvent::HandshakeCompleted {
                peer: from_key.clone(),
                session_key: sk,
            });
        }

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

    pub fn simulate_send(&mut self, peer_key: &str) -> Vec<WgEvent> {
        let ip = self.peers.iter()
            .find(|p| p.public_key.0 == peer_key)
            .and_then(|p| p.first_ip());
        match ip {
            Some(ip) => self.send(ip, b"ping"),
            None => vec![WgEvent::NoRoute { inner_dst: "0.0.0.0".parse().unwrap() }],
        }
    }

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

    pub fn simulate_roam(&mut self, peer_key: &str, roam_counter: u8) -> Vec<WgEvent> {
        let Some(idx) = self.peers.iter().position(|p| p.public_key.0 == peer_key) else {
            return vec![];
        };
        let new_outer: SocketAddr = format!("198.18.0.{}:51820", roam_counter).parse().unwrap();
        let inner_src = match self.peers[idx].first_ip() {
            Some(ip) => ip,
            None => return vec![],
        };
        let key = self.peers[idx].public_key.clone();
        self.recv(new_outer, &key, inner_src, b"roaming")
    }
}
