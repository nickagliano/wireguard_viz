/// Opaque stand-in for a real 256-bit private key.
/// In a real implementation this would be a Curve25519 scalar.
#[derive(Clone, Debug)]
pub struct PrivateKey(pub String);

impl PrivateKey {
    pub fn new(label: &str) -> Self {
        Self(label.to_string())
    }
}

/// Opaque stand-in for a real 256-bit public key.
/// In a real implementation this would be a Curve25519 point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey(pub String);

impl PublicKey {
    pub fn new(label: &str) -> Self {
        Self(label.to_string())
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
