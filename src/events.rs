use std::net::{IpAddr, SocketAddr};
use crate::types::PublicKey;

#[derive(Debug, Clone)]
pub enum WgEvent {
    HandshakeCompleted {
        peer: PublicKey,
        session_key: String,
    },
    Sent {
        inner_dst: IpAddr,
        peer: PublicKey,
        outer_dst: SocketAddr,
        nonce: u64,
    },
    NoRoute {
        inner_dst: IpAddr,
    },
    NoEndpoint {
        inner_dst: IpAddr,
        peer: PublicKey,
    },
    Received {
        outer_src: SocketAddr,
        peer: PublicKey,
        inner_src: IpAddr,
    },
    Dropped {
        outer_src: SocketAddr,
        peer: PublicKey,
        inner_src: IpAddr,
        reason: &'static str,
    },
    Roamed {
        peer: PublicKey,
        old_endpoint: Option<SocketAddr>,
        new_endpoint: SocketAddr,
    },
}
