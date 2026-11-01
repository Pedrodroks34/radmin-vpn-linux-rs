use crate::transport::{ChannelConfig, ChannelType, TcpChannel};
use crate::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, warn};

pub const DEFAULT_RELAY_PORT: u16 = 17351;

#[derive(Debug, Clone)]
pub struct RelayServer {
    pub address: SocketAddr,
    pub region: Option<String>,
    pub load: Option<u32>,
}

impl RelayServer {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            region: None,
            load: None,
        }
    }
}

pub struct RelayClient {
    server: RelayServer,
    channel: Option<TcpChannel>,
}

impl RelayClient {
    pub fn new(server: RelayServer) -> Self {
        Self {
            server,
            channel: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.channel.is_some()
    }

    pub fn server(&self) -> &RelayServer {
        &self.server
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("Conectando ao servidor TcpRelay em {}", self.server.address);
        let mut config = ChannelConfig::default();
        config.channel_type = ChannelType::Relay;
        config.connect_timeout = Duration::from_secs(5);

        let channel = TcpChannel::connect(&self.server.address.to_string(), config).await?;
        self.channel = Some(channel);
        info!("Conexão com TcpRelay estabelecida");
        Ok(())
    }

    /// Encapsula e envia dados destinados a um nó peer através do canal de relay.
    pub async fn send_to_peer(&mut self, peer_node_id: u64, data: &[u8]) -> Result<()> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Relay não está conectado"))?;

        // Encapsulamento de relay: [8 bytes node_id BE][payload]
        let mut packet = Vec::with_capacity(8 + data.len());
        packet.extend_from_slice(&peer_node_id.to_be_bytes());
        packet.extend_from_slice(data);

        channel.send(packet).await
    }

    /// Recebe dados despachados pelo canal de relay. Retorna (origem_peer_node_id, payload).
    pub async fn receive_from_peer(&mut self) -> Result<(u64, Vec<u8>)> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Relay não está conectado"))?;

        let frame = channel.receive().await?;
        if frame.payload.len() < 8 {
            return Err(anyhow::anyhow!("Payload de relay truncado (< 8 bytes)"));
        }

        let peer_node_id = u64::from_be_bytes(frame.payload[0..8].try_into().unwrap());
        let data = frame.payload[8..].to_vec();

        Ok((peer_node_id, data))
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut channel) = self.channel.take() {
            let _ = channel.close().await;
        }
        Ok(())
    }
}

/// Gerenciador de seleção de rota (Direct P2P vs Relay Fallback)
pub struct PathSelector {
    direct_timeout: Duration,
}

impl Default for PathSelector {
    fn default() -> Self {
        Self {
            direct_timeout: Duration::from_secs(5),
        }
    }
}

impl PathSelector {
    pub fn new(direct_timeout: Duration) -> Self {
        Self { direct_timeout }
    }

    /// Tenta conexão P2P direta; se falhar ou expirar o timeout, faz fallback para relay.
    pub async fn connect_with_fallback(
        &self,
        direct_addr: SocketAddr,
        relay_server: RelayServer,
    ) -> Result<PathConnection> {
        info!("Tentando caminho direto P2P com {}", direct_addr);
        let mut config = ChannelConfig::default();
        config.connect_timeout = self.direct_timeout;

        match TcpChannel::connect(&direct_addr.to_string(), config).await {
            Ok(direct_channel) => {
                info!(
                    "Conexão P2P direta estabelecida com sucesso com {}",
                    direct_addr
                );
                Ok(PathConnection::Direct(direct_channel))
            }
            Err(e) => {
                warn!(
                    "Caminho P2P direto falhou ({}). Acionando fallback para TcpRelay em {}",
                    e, relay_server.address
                );
                let mut relay = RelayClient::new(relay_server);
                relay.connect().await?;
                Ok(PathConnection::Relay(relay))
            }
        }
    }
}

pub enum PathConnection {
    Direct(TcpChannel),
    Relay(RelayClient),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TcpChannelListener;

    #[tokio::test]
    async fn test_relay_client_loopback() {
        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();
            let frame = server_ch.receive().await.unwrap();
            assert_eq!(frame.payload.len(), 8 + 4);
            let peer_id = u64::from_be_bytes(frame.payload[0..8].try_into().unwrap());
            assert_eq!(peer_id, 0x1122334455667788);
            assert_eq!(&frame.payload[8..], &[1, 2, 3, 4]);

            // Responde para o peer
            let mut resp = Vec::new();
            resp.extend_from_slice(&0x9988776655443322u64.to_be_bytes());
            resp.extend_from_slice(&[5, 6, 7, 8]);
            server_ch.send(resp).await.unwrap();
        });

        let mut client = RelayClient::new(RelayServer::new(addr));
        client.connect().await.unwrap();
        client
            .send_to_peer(0x1122334455667788, &[1, 2, 3, 4])
            .await
            .unwrap();

        let (from_peer, data) = client.receive_from_peer().await.unwrap();
        assert_eq!(from_peer, 0x9988776655443322);
        assert_eq!(data, vec![5, 6, 7, 8]);

        handle.await.unwrap();
        client.disconnect().await.unwrap();
    }
}
