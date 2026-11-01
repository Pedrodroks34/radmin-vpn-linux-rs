//! # Módulo `network` — Gerenciamento de redes virtuais e rotas
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - Serviço Windows manipula rotas via IPHLPAPI:
//!   `CreateIpNetEntry`, `DeleteIpForwardEntry2`, `NotifyRouteChange2`,
//!   `ConvertInterfaceGuidToLuid`, `GetAdaptersAddresses`, `GetAdaptersInfo`.
//! - `ROLClient_SetVirtualAddresses` define endereços virtuais do dispositivo.
//! - `ROLClient_ManageNetwork2`, `ManageNetwork`, `CreateNetwork`,
//!   `DeleteNetwork`, `EnableNetwork`, `LeaveNetwork`, `UpdateNetwork`.
//!
//! **Desconhecido:**
//! - Faixa de IP das redes virtuais (não encontrada estaticamente).
//! - Como os IPs são atribuídos a cada membro.
//! - Isolamento entre redes (VLAN-like?).

use crate::Result;

/// Rede virtual do Radmin VPN
#[derive(Debug, Clone)]
pub struct VirtualNetwork {
    pub network_id: uuid::Uuid,
    pub name: String,
    pub subnet: Option<String>, // CIDR (a confirmar via REA dinâmica)
    pub members: Vec<crate::protocol::RosNodeAddress>,
}

/// Gerenciador de rede virtual (placeholder)
pub struct NetworkManager {
    pub networks: Vec<VirtualNetwork>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self { networks: Vec::new() }
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
        Err(anyhow::anyhow!("Manipulação de rotas não implementada (netlink)"))
    }
}
