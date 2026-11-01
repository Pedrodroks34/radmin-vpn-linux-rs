use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub doh_endpoint: Option<String>,
    pub resolvers: Vec<String>,
    pub ros_hostname: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredServer {
    pub hostname: String,
    pub addresses: Vec<std::net::SocketAddr>,
    pub region: Option<String>,
}

pub async fn discover_ros_server(config: &DiscoveryConfig) -> Result<Vec<DiscoveredServer>> {

    let _ = config;
    Err(anyhow::anyhow!(
        "Descoberta de servidor ROS não implementada: \
         hostname do ROS e endpoint DoH ainda não foram extraídos dos binários \
         (requer análise dinâmica ou decompilação)."
    ))
}

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
