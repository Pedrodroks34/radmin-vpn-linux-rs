//! # Módulo `discovery` — Descoberta da infraestrutura do Radmin VPN
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - Não há IPs de servidores Radmin hardcoded nos binários.
//! - String `https://%hs/dns-query` indica uso de **DNS-over-HTTPS**.
//! - Lista de resolvers públicos hardcoded em `RvROLClient.dll`:
//!   Cloudflare (1.1.1.1, 1.0.0.1), Google (8.8.8.8, 8.8.4.4),
//!   OpenDNS (208.67.222.222/.220), Quad9 (9.9.9.9–13),
//!   130.59.31.248/251, AliDNS (223.5.5.5/223.6.6.6).
//! - `ROLClient_GetNodeRegionSupport` sugere servidores regionais.
//! - `ROLClient_EnumPublicNetworks` lista redes públicas.
//!
//! **Desconhecido:**
//! - Nome DNS dos servidores ROS (não encontrado estaticamente).
//! - Endpoint exato do DoH e formato da requisição.
//! - Endereços dos servidores de relay ("Connections Relay").

use crate::Result;
use serde::{Deserialize, Serialize};

/// Configuração de descoberta de servidores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub doh_endpoint: Option<String>,      // https://%hs/dns-query — preencher após REA dinâmica
    pub resolvers: Vec<String>, // fallback de resolvers públicos (ex: "1.1.1.1")
    pub ros_hostname: Option<String>,      // nome do servidor ROS (a descobrir)
}

/// Resultado da descoberta de um servidor ROS
#[derive(Debug, Clone)]
pub struct DiscoveredServer {
    pub hostname: String,
    pub addresses: Vec<std::net::SocketAddr>,
    pub region: Option<String>,
}

/// Descobre o endereço do servidor ROS via DNS/DoH
pub async fn discover_ros_server(config: &DiscoveryConfig) -> Result<Vec<DiscoveredServer>> {
    // Placeholder: implementar após obtenção do hostname real dos servidores
    // e do endpoint DoH oficial.
    let _ = config;
    Err(anyhow::anyhow!(
        "Descoberta de servidor ROS não implementada: \
         hostname do ROS e endpoint DoH ainda não foram extraídos dos binários \
         (requer análise dinâmica ou decompilação)."
    ))
}

/// Resolvedor de endereços de nó (equivalente a ROLClient_GetNodes)
pub struct NodeResolver;

impl NodeResolver {
    pub fn new() -> Self {
        Self
    }

    pub async fn resolve_nodes(&self) -> Result<Vec<crate::protocol::RosNodeAddress>> {
        Err(anyhow::anyhow!(
            "Resolução de nós não implementada (aguardando detalhes do protocolo ROS)"
        ))
    }
}
