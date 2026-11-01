use crate::protocol::RosNodeAddress;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeVisualStatus {
    Unknown,
    Applicant,
    Connecting,
    Connected,
    Disconnected,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub node_address: RosNodeAddress,
    pub alias: Option<String>,
    pub status: NodeVisualStatus,
    pub region: Option<String>,
}

pub struct PeerManager {
    pub peers: Vec<Peer>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self { peers: Vec::new() }
    }

    pub async fn refresh_from_server(&mut self) -> Result<()> {
        Err(anyhow::anyhow!(
            "Atualização de peers não implementada (ROLClient_GetNodes)"
        ))
    }

    pub fn find_by_address(&self, addr: &std::net::SocketAddr) -> Option<&Peer> {
        self.peers
            .iter()
            .find(|p| p.node_address.ip == addr.ip() && p.node_address.port == addr.port())
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}
