use crate::Result;

#[derive(Debug, Clone)]
pub struct VirtualNetwork {
    pub network_id: uuid::Uuid,
    pub name: String,
    pub subnet: Option<String>,
    pub members: Vec<crate::protocol::RosNodeAddress>,
}

pub struct NetworkManager {
    pub networks: Vec<VirtualNetwork>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            networks: Vec::new(),
        }
    }

    pub async fn join_network(&mut self, _network_id: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "Entrada em rede não implementada (ROLClient_JoinNetwork)"
        ))
    }

    pub async fn leave_network(&mut self, _network_id: &str) -> Result<()> {
        Err(anyhow::anyhow!("Saída de rede não implementada"))
    }

    pub async fn add_route(&self, _dest: &str, _gateway: std::net::Ipv4Addr) -> Result<()> {
        Err(anyhow::anyhow!(
            "Manipulação de rotas não implementada (netlink)"
        ))
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}
