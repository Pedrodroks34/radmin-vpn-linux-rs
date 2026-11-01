//! # Módulo `transport` — Transporte de dados (canais, sockets)
//!
//! ## Evidências da engenharia reversa (REA)
//!
//! **Confirmado:**
//! - `ROLClient_Send`, `ROLClient_Receive`, `ROLClient_WaitForSend`,
//!   `ROLClient_ShutdownChannel` — envio/recebimento em canais.
//! - `ROLClient_SetMaxPacketSize`, `ROLClient_SetPriority`, `ROLClient_SetChannelCounters`.
//! - `RvROLClient.dll` usa `WS2_32` (WSASend, WSARecv, getaddrinfo, WSAPoll,
//!   WSAEventSelect) e `CreateIoCompletionPort` (FamRT IOCP).
//! - Classes `VIClnPacket` (pacotes de cliente) e `CMessageQueueEx` (filas de mensagem).
//!
//! **Fortemente provável:**
//! - Canais podem ser UDP ou TCP (conforme strings "Connections UDP/...", "Connections TCP/...").
//! - Pacotes são enfileirados e enviados de forma assíncrona via IOCP.
//!
//! **Desconhecido:**
//! - Estrutura binária de `VIClnPacket`.
//! - Tamanho máximo de pacote padrão.
//! - Protocolo de retransmissão e ACKs sobre UDP.

use crate::protocol::framing::{FrameParser, FramedPacket, FramingError, FRAME_HEADER_SIZE};
use crate::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Tipo de canal de transporte (inferido das strings do serviço)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    UdpDirect,
    UdpNat,
    TcpDirect,
    TcpNat,
    Relay,
    Teredo,
}

/// Configuração de canal (equivalente a SetMaxPacketSize / SetPriority / SetChannelCounters)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub channel_type: ChannelType,
    pub max_packet_size: usize,
    pub priority: u32,
    pub compression: bool,
    pub encryption: bool,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            channel_type: ChannelType::UdpDirect,
            max_packet_size: 1400,  // placeholder — não confirmado
            priority: 0,
            compression: false,
            encryption: true,
        }
    }
}

/// Pacote de transporte (equivalente a VIClnPacket — estrutura placeholder)
#[derive(Debug, Clone)]
pub struct TransportPacket {
    pub channel_id: u32,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl TransportPacket {
    pub fn new(channel_id: u32, payload: Vec<u8>) -> Self {
        Self {
            channel_id,
            sequence: 0,  // preencher após REA dinâmica
            payload,
        }
    }
}

/// Erro de transporte
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("erro de framing: {0}")]
    Framing(#[from] crate::protocol::framing::FramingError),
    #[error("erro de I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("conexão fechada")]
    ConnectionClosed,
    #[error("buffer overflow: tamanho excede o limite")]
    BufferOverflow,
}

/// Canal TCP com parser de framing integrado
pub struct TcpChannel {
    writer: tokio::net::tcp::OwnedWriteHalf,
    rx: mpsc::Receiver<FramedPacket>,
    max_packet_size: usize,
    config: ChannelConfig,
}

impl TcpChannel {
    /// Cria um novo canal TCP conectado a um endereço
    pub async fn connect(addr: &str, config: ChannelConfig) -> Result<Self> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        
        let max_packet_size = config.max_packet_size.max(FRAME_HEADER_SIZE);
        
        let (mut read_half, write_half) = stream.into_split();
        let (tx, rx) = mpsc::channel(32);
        
        // Inicia task de leitura em background
        tokio::spawn(async move {
            Self::read_loop(read_half, tx, max_packet_size).await;
        });
        
        Ok(Self {
            writer: write_half,
            rx,
            max_packet_size,
            config,
        })
    }
    
    /// Cria um canal a partir de um stream aceito (para servidores)
    pub fn from_stream(stream: tokio::net::TcpStream, config: ChannelConfig) -> Self {
        let max_packet_size = config.max_packet_size.max(FRAME_HEADER_SIZE);
        
        let (mut read_half, write_half) = stream.into_split();
        let (tx, rx) = mpsc::channel(32);
        
        tokio::spawn(async move {
            Self::read_loop(read_half, tx, max_packet_size).await;
        });
        
        Self {
            writer: write_half,
            rx,
            max_packet_size,
            config,
        }
    }
    
    /// Loop de leitura em background
    async fn read_loop(mut stream: tokio::net::tcp::OwnedReadHalf, tx: mpsc::Sender<FramedPacket>, max_packet_size: usize) {
        let mut buffer = [0u8; 65536];
        let mut parser = FrameParser::new();
        let mut read_buffer = Vec::new();
        
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    // EOF: verifica se há dados incompletos no buffer
                    if let Err(e) = parser.finish() {
                        eprintln!("Frame truncado ao finalizar: {}", e);
                    }
                    break;
                }
                Ok(n) => {
                    read_buffer.extend_from_slice(&buffer[..n]);
                    
                    // Tenta extrair frames completos
                    match parser.feed(&read_buffer) {
                        Ok(frames) => {
                            for frame in frames {
                                let _ = tx.send(frame).await;
                            }
                            // Limpa bytes consumidos do buffer
                            let remaining = parser.buffered_len();
                            if remaining > 0 {
                                read_buffer.drain(..read_buffer.len() - remaining);
                            } else {
                                read_buffer.clear();
                            }
                        }
                        Err(e) => {
                            eprintln!("Erro de framing: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Erro de leitura: {}", e);
                    break;
                }
            }
        }
    }
    
    /// Envia um frame (payload já pronto)
    pub async fn send_frame(&mut self, packet: FramedPacket) -> Result<()> {
        let bytes = packet.to_bytes();
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }
    
    /// Envia payload bruto (o framing é feito internamente)
    pub async fn send(&mut self, payload: Vec<u8>) -> Result<()> {
        if payload.len() > self.max_packet_size {
            return Err(anyhow::Error::from(TransportError::BufferOverflow));
        }
        
        let packet = FramedPacket::new(payload)?;
        self.send_frame(packet).await
    }
    
    /// Recebe o próximo frame completo
    pub async fn receive(&mut self) -> Result<FramedPacket> {
        self.rx.recv().await
            .ok_or_else(|| anyhow::Error::from(TransportError::ConnectionClosed))
    }
    
    /// Tenta receber um frame sem bloquear
    pub fn try_receive(&mut self) -> Result<FramedPacket> {
        self.rx.try_recv()
            .map_err(|_| anyhow::Error::from(TransportError::ConnectionClosed))
    }
    
    /// Fecha a conexão
    pub async fn close(&mut self) -> Result<()> {
        self.writer.shutdown().await?;
        Ok(())
    }
    
    /// Retorna a configuração do canal
    pub fn config(&self) -> &ChannelConfig {
        &self.config
    }
}

/// Listener TCP para aceitar conexões de entrada
pub struct TcpChannelListener {
    listener: tokio::net::TcpListener,
    config: ChannelConfig,
}

impl TcpChannelListener {
    /// Cria um listener em um endereço
    pub async fn bind(addr: &str, config: ChannelConfig) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        Ok(Self { listener, config })
    }
    
    /// Aceita a próxima conexão
    pub async fn accept(&self) -> Result<TcpChannel> {
        let (stream, _) = self.listener.accept().await?;
        Ok(TcpChannel::from_stream(stream, self.config.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::framing::{FramedPacket, FrameParser, MAX_PAYLOAD_SIZE, FRAME_HEADER_SIZE};
    
    #[tokio::test]
    async fn test_tcp_channel_send_receive_frame() {
        // Teste de integração básica com o parser de framing
        let config = ChannelConfig::default();
        
        // Cria listener em localhost
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Conecta cliente
        let mut client = tokio::net::TcpStream::connect(&addr.to_string()).await.unwrap();
        
        // Aceita conexão
        let (mut server, _) = listener.accept().await.unwrap();
        
        // Cliente envia frame
        let test_payload = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03];
        let pkt = FramedPacket::new(test_payload.clone()).unwrap();
        let bytes = pkt.to_bytes();
        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();
        
        // Servidor recebe
        let mut parser = FrameParser::new();
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        let frames = parser.feed(&buf[..n]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, test_payload);
        
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_tcp_channel_fragmented_receive() {
        // Teste de recepção fragmentada
        let config = ChannelConfig::default();
        
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let mut client = tokio::net::TcpStream::connect(&addr.to_string()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        
        // Cria frame grande
        let payload = vec![0xaa; 1000];
        let pkt = FramedPacket::new(payload.clone()).unwrap();
        let bytes = pkt.to_bytes();
        
        // Envia fragmentado: primeiro cabeçalho + metade do payload
        let half = FRAME_HEADER_SIZE + payload.len() / 2;
        client.write_all(&bytes[..half]).await.unwrap();
        
        // Servidor tenta ler - pode não ter frame completo
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        let mut parser = FrameParser::new();
        let frames = parser.feed(&buf[..n]).unwrap();
        
        // Pode ou não ter frame completo (depende do timing)
        // Mas o buffer deve ter os bytes parciais
        if frames.is_empty() {
            assert!(parser.buffered_len() > 0);
        }
        
        // Envia o restante
        client.write_all(&bytes[half..]).await.unwrap();
        client.flush().await.unwrap();
        
        // Aguarda um pouco para a leitura
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        let mut buf2 = [0u8; 1024];
        let n2 = server.read(&mut buf2).await.unwrap();
        let mut parser2 = FrameParser::new();
        let mut all_data = Vec::new();
        all_data.extend_from_slice(&buf[..n]);
        all_data.extend_from_slice(&buf2[..n2]);
        let frames = parser2.feed(&all_data).unwrap();
        
        // Deve ter pelo menos 1 frame completo
        assert!(!frames.is_empty());
        assert_eq!(frames[0].payload, payload);
        
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_multiple_frames_in_one_read() {
        let config = ChannelConfig::default();
        
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let mut client = tokio::net::TcpStream::connect(&addr.to_string()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        
        // Envia dois frames concatenados
        let pkt1 = FramedPacket::new(vec![1, 2, 3]).unwrap();
        let pkt2 = FramedPacket::new(vec![4, 5, 6]).unwrap();
        let mut bytes = pkt1.to_bytes();
        bytes.extend_from_slice(&pkt2.to_bytes());
        
        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();
        
        // Servidor deve receber ambos os frames
        let mut parser = FrameParser::new();
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        let frames = parser.feed(&buf[..n]).unwrap();
        
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload, vec![1, 2, 3]);
        assert_eq!(frames[1].payload, vec![4, 5, 6]);
        
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_tcp_channel_disconnect_with_partial_frame() {
        let config = ChannelConfig::default();
        
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let mut client = tokio::net::TcpStream::connect(&addr.to_string()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        
        // Envia apenas o cabeçalho (4 bytes)
        client.write_all(&[0x00, 0x00, 0x00, 0x20]).await.unwrap(); // 32 bytes esperados
        client.flush().await.unwrap();
        
        // Fecha conexão do lado do cliente
        client.shutdown().await.unwrap();
        
        // Servidor tenta ler - deve receber EOF ou erro
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(n, 4); // Apenas o cabeçalho foi recebido
        
        // Parser deve ter 4 bytes no buffer (cabeçalho incompleto)
        let mut parser = FrameParser::new();
        let _ = parser.feed(&buf[..n]);
        assert_eq!(parser.buffered_len(), 4);
        
        server.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_tcp_channel_oversized_payload_rejection() {
        let mut parser = FrameParser::new();
        
        // Tenta alimentar com cabeçalho indicando payload maior que o limite
        let result = parser.feed(&[
            0x00, 0x01, 0x00, 0x01, // 65537 em big-endian (> 65535)
        ]);
        
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FramingError::PayloadTooLarge { .. }
        ));
    }
}