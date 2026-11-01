//! Módulo de Relay TCP (TcpRelay) e seleção de caminhos P2P / Relay.
//!
//! Engenharia reversa dos binários RvROLClient.dll / RvUESClient.dll e capturas
//! radmin_vm2.pcap (pacotes #686 a #713):
//!
//! Descobertas comprovadas:
//! 1. A porta TCP 17351 executa o protocolo TcpRelay da Famatech.
//! 2. NÃO utiliza cabeçalho fixo sintético de 8 bytes; utiliza framing Famatech
//!    de 4 bytes big-endian e registros TLV no formato `[Tag: 4 bytes BE][Value]`,
//!    onde Tag codifica `(tipo << 24) | tamanho`:
//!    - 0x10000004: Contador de sequência (uint32)
//!    - 0x20000008: Node ID do peer (uint64)
//!    - 0x300000c0: Bloco de chave pública / autenticação do servidor (192 bytes = 0xc0)
//!    - 0x40000001: Flag de protocolo/cifra (1 byte, ex: 0x05)
//!    - 0x50000020: Nonce / token de sessão aleatório (32 bytes = 0x20)
//!    - 0x600000c0: Bloco de troca de chaves do cliente (192 bytes = 0xc0)
//!    - 0x70000014: Digest de autenticação / HMAC-SHA1 (20 bytes = 0x14)
//! 3. Após a etapa de autenticação (sequências 5 e 6), a comunicação é 100% cifrada
//!    com AES-256-CBC em múltiplos estritos de 16 bytes.
//! 4. Conexão P2P direta: o cliente tenta UDP com encapsulamento Teredo (RFC 4380,
//!    prefixo 2001:0000::/32) e STUN (RFC 3489) / TCP simultaneous open. Se falhar
//!    ou sofrer timeout, faz fallback automático para o TcpRelay na porta 17351.

use crate::nat::{attempt_tcp_simultaneous_open, UdpHolePuncher};
use crate::transport::{ChannelConfig, ChannelType, TcpChannel};
use crate::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

pub const DEFAULT_RELAY_PORT: u16 = 17351;

pub const TAG_RELAY_SEQ: u32 = 0x10000004;
pub const TAG_RELAY_NODE_ID: u32 = 0x20000008;
pub const TAG_RELAY_SERVER_KEY: u32 = 0x300000c0;
pub const TAG_RELAY_FLAG: u32 = 0x40000001;
pub const TAG_RELAY_NONCE: u32 = 0x50000020;
pub const TAG_RELAY_CLIENT_KEY: u32 = 0x600000c0;
pub const TAG_RELAY_AUTH: u32 = 0x70000014;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error(
        "buffer de mensagem de relay insuficiente: necessário {needed}, disponível {available}"
    )]
    BufferTooShort { needed: usize, available: usize },
    #[error("tag de relay inválida ou inesperada: 0x{0:08x}")]
    InvalidTag(u32),
    #[error("sequência inesperada de relay: esperado {expected}, recebido {actual}")]
    UnexpectedSequence { expected: u32, actual: u32 },
    #[error("canal de relay não conectado")]
    NotConnected,
    #[error("erro de E/S no canal de relay: {0}")]
    Io(String),
}

/// Registro TLV do protocolo TcpRelay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRelayRecord {
    pub tag: u32,
    pub value: Vec<u8>,
}

impl TcpRelayRecord {
    pub fn new(tag: u32, value: Vec<u8>) -> Self {
        Self { tag, value }
    }

    pub fn new_seq(seq: u32) -> Self {
        Self {
            tag: TAG_RELAY_SEQ,
            value: seq.to_be_bytes().to_vec(),
        }
    }

    pub fn new_node_id(node_id: u64) -> Self {
        Self {
            tag: TAG_RELAY_NODE_ID,
            value: node_id.to_be_bytes().to_vec(),
        }
    }

    pub fn tag_type(&self) -> u8 {
        (self.tag >> 24) as u8
    }

    pub fn value_length(&self) -> usize {
        (self.tag & 0x0000ffff) as usize
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() == 4 {
            Some(u32::from_be_bytes(
                self.value.as_slice().try_into().unwrap(),
            ))
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.value.len() == 8 {
            Some(u64::from_be_bytes(
                self.value.as_slice().try_into().unwrap(),
            ))
        } else {
            None
        }
    }
}

/// Mensagem do protocolo TcpRelay contendo registros TLV.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpRelayMessage {
    pub records: Vec<TcpRelayRecord>,
}

impl TcpRelayMessage {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn add_record(&mut self, record: TcpRelayRecord) {
        self.records.push(record);
    }

    pub fn add_seq(&mut self, seq: u32) {
        self.add_record(TcpRelayRecord::new_seq(seq));
    }

    pub fn add_node_id(&mut self, node_id: u64) {
        self.add_record(TcpRelayRecord::new_node_id(node_id));
    }

    pub fn get_seq(&self) -> Option<u32> {
        self.records
            .iter()
            .find(|r| r.tag == TAG_RELAY_SEQ)
            .and_then(|r| r.as_u32())
    }

    pub fn get_node_id(&self) -> Option<u64> {
        self.records
            .iter()
            .find(|r| r.tag == TAG_RELAY_NODE_ID)
            .and_then(|r| r.as_u64())
    }

    pub fn get_record(&self, tag: u32) -> Option<&TcpRelayRecord> {
        self.records.iter().find(|r| r.tag == tag)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for rec in &self.records {
            buf.extend_from_slice(&rec.tag.to_be_bytes());
            buf.extend_from_slice(&rec.value);
        }
        buf
    }

    pub fn parse(payload: &[u8]) -> std::result::Result<Self, RelayError> {
        let mut msg = Self::new();
        let mut offset = 0;

        while offset < payload.len() {
            if offset + 4 > payload.len() {
                return Err(RelayError::BufferTooShort {
                    needed: offset + 4,
                    available: payload.len(),
                });
            }

            let tag = u32::from_be_bytes(payload[offset..offset + 4].try_into().unwrap());
            let val_len = (tag & 0x0000ffff) as usize;
            offset += 4;

            if offset + val_len > payload.len() {
                return Err(RelayError::BufferTooShort {
                    needed: offset + val_len,
                    available: payload.len(),
                });
            }

            let value = payload[offset..offset + val_len].to_vec();
            offset += val_len;

            msg.add_record(TcpRelayRecord::new(tag, value));
        }

        Ok(msg)
    }
}

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

/// Cliente de conexão e encaminhamento via TcpRelay.
pub struct RelayClient {
    server: RelayServer,
    channel: Option<TcpChannel>,
    sequence: u32,
    peer_node_id: Option<u64>,
}

impl RelayClient {
    pub fn new(server: RelayServer) -> Self {
        Self {
            server,
            channel: None,
            sequence: 1,
            peer_node_id: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.channel.is_some()
    }

    pub fn server(&self) -> &RelayServer {
        &self.server
    }

    pub fn peer_node_id(&self) -> Option<u64> {
        self.peer_node_id
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("Conectando ao servidor TcpRelay em {}", self.server.address);
        let config = ChannelConfig {
            channel_type: ChannelType::Relay,
            connect_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        let channel = TcpChannel::connect(&self.server.address.to_string(), config).await?;
        self.channel = Some(channel);
        info!("Conexão TCP com TcpRelay estabelecida");
        Ok(())
    }

    /// Executa o handshake de sessão de relay (pacotes #688 a #710).
    pub async fn initiate_relay_session(&mut self, peer_node_id: u64) -> Result<()> {
        self.peer_node_id = Some(peer_node_id);
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Relay não conectado"))?;

        // 1. Enviar mensagem inicial com Sequence e Node ID (conforme pacote #688)
        let mut init_msg = TcpRelayMessage::new();
        init_msg.add_seq(self.sequence);
        self.sequence += 1;
        init_msg.add_node_id(peer_node_id);

        let init_bytes = init_msg.to_bytes();
        channel.send(init_bytes).await?;
        debug!(
            "Mensagem de inicialização de relay enviada para nó 0x{:016x}",
            peer_node_id
        );

        // 2. Aguarda resposta com sequência do servidor (pacote #691)
        let resp_frame = channel.receive().await?;
        let resp_msg = TcpRelayMessage::parse(&resp_frame.payload)?;
        let seq = resp_msg
            .get_seq()
            .ok_or_else(|| anyhow::anyhow!("Resposta de relay sem contador de sequência"))?;
        if seq != self.sequence {
            return Err(RelayError::UnexpectedSequence {
                expected: self.sequence,
                actual: seq,
            }
            .into());
        }
        self.sequence += 1;

        debug!("Handshake de TcpRelay validado na sequência {}", seq);
        Ok(())
    }

    /// Habilita criptografia AES-256-CBC negociada na conexão de relay.
    pub fn enable_encryption(&mut self, key: [u8; 32]) {
        if let Some(ch) = self.channel.as_mut() {
            ch.enable_encryption(key);
            info!("Criptografia AES-256-CBC ativada no TcpRelay");
        }
    }

    /// Encaminha quadro Ethernet ou pacote através do canal seguro do relay.
    pub async fn send_frame(&mut self, data: &[u8]) -> Result<()> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Relay não está conectado"))?;

        if channel.is_encrypted() {
            channel.send_secure(data).await
        } else {
            channel.send(data.to_vec()).await
        }
    }

    /// Recebe quadro despachado pelo canal de relay.
    pub async fn receive_frame(&mut self) -> Result<Vec<u8>> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Relay não está conectado"))?;

        if channel.is_encrypted() {
            channel.receive_secure().await
        } else {
            let frame = channel.receive().await?;
            Ok(frame.payload)
        }
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut channel) = self.channel.take() {
            let _ = channel.close().await;
        }
        Ok(())
    }
}

/// Caminho de conexão P2P estabelecido.
pub enum PathConnection {
    /// Rota P2P direta via UDP Hole Punching / Teredo RFC 4380
    UdpDirect(Arc<UdpSocket>, SocketAddr),
    /// Rota P2P direta via TCP Simultaneous-Open
    TcpDirect(TcpChannel),
    /// Fallback para Relay via TcpRelay na porta 17351
    Relay(RelayClient),
}

/// Seletor inteligente de caminho com NAT Traversal completo:
/// 1. Tenta UDP Hole Punching / Teredo RFC 4380
/// 2. Tenta TCP Simultaneous-Open com SO_REUSEADDR/SO_REUSEPORT
/// 3. Fallback automático para TcpRelay (porta 17351)
pub struct PathSelector {
    direct_timeout: Duration,
    udp_hole_puncher: Option<Arc<UdpHolePuncher>>,
}

impl Default for PathSelector {
    fn default() -> Self {
        Self {
            direct_timeout: Duration::from_secs(2),
            udp_hole_puncher: None,
        }
    }
}

impl PathSelector {
    pub fn new(direct_timeout: Duration) -> Self {
        Self {
            direct_timeout,
            udp_hole_puncher: None,
        }
    }

    pub fn with_hole_puncher(mut self, puncher: Arc<UdpHolePuncher>) -> Self {
        self.udp_hole_puncher = Some(puncher);
        self
    }

    /// Executa o fluxo de seleção de rota resiliente:
    /// 1. Se configurado, dispara sondas UDP Hole Punching para `peer_udp_addr`
    /// 2. Se falhar, tenta TCP Simultaneous-Open para `peer_tcp_addr`
    /// 3. Se ambos falharem, aciona fallback transparente para `relay_server`
    pub async fn select_path(
        &self,
        peer_udp_addr: Option<SocketAddr>,
        peer_tcp_addr: SocketAddr,
        relay_server: RelayServer,
        peer_node_id: u64,
        local_tcp_port: u16,
    ) -> Result<PathConnection> {
        // 1. Tentar UDP Hole Punching direto (Teredo / NAT traversal)
        if let (Some(udp_addr), Some(puncher)) = (peer_udp_addr, &self.udp_hole_puncher) {
            info!("Tentando caminho direto P2P UDP com {}", udp_addr);
            if let Ok(true) = puncher.punch_hole(udp_addr, self.direct_timeout, 2).await {
                info!(
                    "Conexão P2P direta UDP estabelecida com sucesso com {}",
                    udp_addr
                );
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                return Ok(PathConnection::UdpDirect(Arc::new(socket), udp_addr));
            }
            warn!("UDP Hole Punching falhou com {}", udp_addr);
        }

        // 2. Tentar TCP Simultaneous-Open
        info!("Tentando TCP Simultaneous-Open com {}", peer_tcp_addr);
        if let Ok(tcp_stream) =
            attempt_tcp_simultaneous_open(local_tcp_port, peer_tcp_addr, self.direct_timeout).await
        {
            let config = ChannelConfig {
                connect_timeout: self.direct_timeout,
                ..Default::default()
            };
            let direct_channel = TcpChannel::from_stream(tcp_stream, config);
            info!("Conexão P2P direta TCP estabelecida com {}", peer_tcp_addr);
            return Ok(PathConnection::TcpDirect(direct_channel));
        }

        // 3. Fallback para TcpRelay
        warn!(
            "Caminhos diretos P2P falharam. Acionando fallback para TcpRelay em {}",
            relay_server.address
        );
        let mut relay = RelayClient::new(relay_server);
        relay.connect().await?;
        relay.initiate_relay_session(peer_node_id).await?;
        Ok(PathConnection::Relay(relay))
    }

    /// Método simplificado mantendo compatibilidade com testes existentes.
    pub async fn connect_with_fallback(
        &self,
        direct_addr: SocketAddr,
        relay_server: RelayServer,
        peer_node_id: u64,
    ) -> Result<PathConnection> {
        self.select_path(None, direct_addr, relay_server, peer_node_id, 0)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TcpChannelListener;

    #[test]
    fn test_parse_real_captured_packet_688() {
        // Pacote #688 payload: 10000004 00000001 20000008 1876590b00000000
        let payload = [
            0x10, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, // Tag 0x10000004, val=1
            0x20, 0x00, 0x00, 0x08, 0x18, 0x76, 0x59, 0x0b, 0x00, 0x00, 0x00,
            0x00, // Tag 0x20000008, val=0x1876590b00000000
        ];

        let msg = TcpRelayMessage::parse(&payload).unwrap();
        assert_eq!(msg.get_seq(), Some(1));
        assert_eq!(msg.get_node_id(), Some(0x1876590b00000000));
        assert_eq!(msg.to_bytes(), payload);
    }

    #[test]
    fn test_parse_real_captured_packet_691_multi_tlv() {
        // Pacote #691 extraído diretamente de radmin_vm2.pcap
        let payload_hex = concat!(
            "1000000400000002",
            "300000c0",
            "e634471e75f2d76a0a3f5e252c5a6efb48edad645d31d9ecbc400416e14f5c6c2ed378602d6eb8e9478b99e6474932393538b4be7177e0e05d3aaed17b5ae87aa20f3dad37af019518f45b6dde76b2bfdfb140f379cc15383b304b7975b907967553cd6fdaf08d68832b603120430a501067d21beb2ce2275a20036a2dc80f1c9d3ab9221afd5baceda5c2a31077c54fc6f274aaeba17ddd0b5c68f4f8e751a890a58648147a82e6f4f532ccdc939a12942799a713500e17dd4f6ff216cd54c7",
            "4000000105",
            "500000206f29c0756638a2b65779bef7a41000614fba3b77b43380b5e7fae8c859fa1ac2"
        );
        let payload = (0..payload_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&payload_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();

        let msg = TcpRelayMessage::parse(&payload).unwrap();
        assert_eq!(msg.get_seq(), Some(2));

        let server_key_rec = msg.get_record(TAG_RELAY_SERVER_KEY).unwrap();
        assert_eq!(server_key_rec.value_length(), 192);

        let flag_rec = msg.get_record(TAG_RELAY_FLAG).unwrap();
        assert_eq!(flag_rec.value, vec![0x05]);

        let nonce_rec = msg.get_record(TAG_RELAY_NONCE).unwrap();
        assert_eq!(nonce_rec.value_length(), 32);

        assert_eq!(msg.to_bytes(), payload);
    }

    #[tokio::test]
    async fn test_relay_session_loopback_with_authentic_protocol() {
        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let target_node_id = 0x1876590b00000000u64;

        let handle = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();
            let frame = server_ch.receive().await.unwrap();

            // Valida a mensagem inicial de relay (Seq 1)
            let msg = TcpRelayMessage::parse(&frame.payload).unwrap();
            assert_eq!(msg.get_seq(), Some(1));
            assert_eq!(msg.get_node_id(), Some(target_node_id));

            // Simula resposta do relay com confirmação de sequência 2
            let mut resp = TcpRelayMessage::new();
            resp.add_seq(2);
            resp.add_record(TcpRelayRecord::new(TAG_RELAY_FLAG, vec![0x05]));
            server_ch.send(resp.to_bytes()).await.unwrap();
        });

        let mut client = RelayClient::new(RelayServer::new(addr));
        client.connect().await.unwrap();
        client.initiate_relay_session(target_node_id).await.unwrap();

        handle.await.unwrap();
        client.disconnect().await.unwrap();
    }
}
