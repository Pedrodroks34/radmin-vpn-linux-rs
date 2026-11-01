use crate::Result;

#[derive(Debug, Clone)]
pub struct RelayServer {
    pub address: std::net::SocketAddr,
    pub region: Option<String>,
    pub load: Option<u32>,
}

pub struct RelayClient;

impl RelayClient {
    pub async fn connect(&self, _server: &RelayServer) -> Result<()> {
        Err(anyhow::anyhow!(
            "Conexão com relay não implementada (endereços desconhecidos)"
        ))
    }
}
