//! # Módulo `peer` — Descoberta e gerenciamento de membros (nós)
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - `ROLClient_GetNodes` e `ROLClient_GetNodeRegionSupport` — obtenha nós e suporte regional.
//! - `ROLClient_EnumPublicNetworks` — enumere redes públicas.
//! - `VCNodeMapEntry`, `VCUiNode`, `VCUiNetworkItem` — nós e itens de rede na UI.
//! - `USNodeVisualStatus`, `W4ENodeVisualStatus` — status visual (aplicant, connecting, disconnected).
//! - `ChatRegionSupportCache` — cache de suporte de região para chat.
//!
//! **Desconhecido:**
//! - Formato da lista de nós retornada pelo servidor.
//! - Como peers são selecionados para comunicação direta vs relay.
//! - Detecção de entrada/saída de membros.

use crate::protocol::RosNodeAddress;
use crate::Result;

/// Status visual de um nó (inferido da GUI QML: node_applicant, node_connecting, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeVisualStatus {
    Unknown,
    Applicant,   // solicitando entrada
    Connecting,  // estabelecendo conexão
    Connected,   // conectado
    Disconnected,
}

/// Um membro/peer na rede virtual
#[derive(Debug, Clone)]
pub struct Peer {
    pub node_address: RosNodeAddress,
    pub alias: Option<String>,
    pub status: NodeVisualStatus,
    pub region: Option<String>,
}

/// Gerenciador de peers (placeholder)
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
        self.peers.iter().find(|p| p.node_address.ip == addr.ip() && p.node_address.port == addr.port())
    }
}
