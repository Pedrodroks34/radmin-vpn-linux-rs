//! # Módulo `relay` — Servidores de retransmissão
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - Strings do serviço incluem "Connections Relay" — conexões via relay.
//! - `ROLClient_ReportRServerInfo` — reporta informações do servidor de relay/ROS.
//! - `NeedMasterAddress` — resolução de endereço do nó mestre (pode ser relay).
//!
//! **Desconhecido:**
//! - Endereços dos servidores de relay.
//! - Protocolo de comunicação com relay.
//! - Quando o relay é usado (fallback apenas ou sempre para certos NATs?).

use crate::Result;

/// Servidor de relay
#[derive(Debug, Clone)]
pub struct RelayServer {
    pub address: std::net::SocketAddr,
    pub region: Option<String>,
    pub load: Option<u32>,
}

/// Cliente de relay (placeholder)
pub struct RelayClient;

impl RelayClient {
    pub async fn connect(&self, _server: &RelayServer) -> Result<()> {
        Err(anyhow::anyhow!(
            "Conexão com relay não implementada (endereços desconhecidos)"
        ))
    }
}
