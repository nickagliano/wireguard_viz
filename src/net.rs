use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Minimal IPv4 CIDR block (e.g. "10.0.0.2/32", "10.0.0.0/24").
/// Enough for cryptokey routing lookups — no IPv6 needed for this demo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Network {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Network {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(v4) = ip else { return false };
        let mask = mask_from_prefix(self.prefix_len);
        u32::from(self.addr) & mask == u32::from(v4) & mask
    }
}

fn mask_from_prefix(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { !0u32 << (32 - prefix) }
}

impl FromStr for Ipv4Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_s, prefix_s) = s.split_once('/').ok_or("missing /")?;
        let addr: Ipv4Addr = addr_s.parse().map_err(|e| format!("{e}"))?;
        let prefix_len: u8 = prefix_s.parse().map_err(|e| format!("{e}"))?;
        Ok(Self { addr, prefix_len })
    }
}

impl fmt::Display for Ipv4Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}
