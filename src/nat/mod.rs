#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    None,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
}

#[derive(Debug, Clone)]
pub struct NatDetectionResult {
    pub nat_type: NatType,
    pub public_address: Option<std::net::SocketAddr>,
    pub local_address: std::net::SocketAddr,
}

pub struct NatDetector;

impl NatDetector {
    pub fn new() -> Self {
        Self
    }

    pub async fn detect(&self) -> crate::Result<NatDetectionResult> {
        Err(anyhow::anyhow!(
            "Detecção de NAT não implementada: \
             algoritmo exato não extraído dos binários (RvUESClient.dll)"
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pStrategy {
    UdpDirect,
    UdpNatHolePunch,
    UdpTeredo,
    TcpDirect,
    TcpNat,
    Relay,
}
