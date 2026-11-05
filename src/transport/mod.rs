use crate::crypto::FamatechCipherState;
use crate::protocol::framing::{FrameParser, FramedPacket, FRAME_HEADER_SIZE};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    UdpDirect,
    UdpNat,
    TcpDirect,
    TcpNat,
    Relay,
    Teredo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub channel_type: ChannelType,
    pub max_packet_size: usize,
    pub priority: u32,
    pub compression: bool,
    pub encryption: bool,
    pub connect_timeout: Duration,
    pub keepalive_interval: Duration,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            channel_type: ChannelType::TcpDirect,
            max_packet_size: 1400,
            priority: 0,
            compression: false,
            encryption: true,
            connect_timeout: Duration::from_secs(5),
            keepalive_interval: Duration::from_secs(10),
        }
    }
}

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
            sequence: 0,
            payload,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("erro de framing: {0}")]
    Framing(#[from] crate::protocol::framing::FramingError),
    #[error("erro de criptografia: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("erro de I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("conexão fechada")]
    ConnectionClosed,
    #[error("buffer overflow: tamanho excede o limite")]
    BufferOverflow,
    #[error("timeout ao aguardar operação")]
    Timeout,
    #[error("criptografia não habilitada neste canal")]
    EncryptionNotEnabled,
}

pub struct TcpChannel {
    writer: tokio::net::tcp::OwnedWriteHalf,
    rx: mpsc::Receiver<FramedPacket>,
    max_packet_size: usize,
    config: ChannelConfig,
    cipher: Option<FamatechCipherState>,
}

impl TcpChannel {
    pub async fn connect(addr: &str, config: ChannelConfig) -> Result<Self> {
        let stream =
            tokio::time::timeout(config.connect_timeout, tokio::net::TcpStream::connect(addr))
                .await
                .map_err(|_| TransportError::Timeout)??;

        let max_packet_size = config.max_packet_size.max(FRAME_HEADER_SIZE);
        let (read_half, write_half) = stream.into_split();
        let (tx, rx) = mpsc::channel(64);

        tokio::spawn(async move {
            Self::read_loop(read_half, tx, max_packet_size).await;
        });

        Ok(Self {
            writer: write_half,
            rx,
            max_packet_size,
            config,
            cipher: None,
        })
    }

    pub async fn connect_with_retry(
        addr: &str,
        config: ChannelConfig,
        max_retries: u32,
        initial_backoff: Duration,
    ) -> Result<Self> {
        let mut backoff = initial_backoff;
        let mut attempts = 0;

        loop {
            attempts += 1;
            match Self::connect(addr, config.clone()).await {
                Ok(channel) => {
                    info!("Conectado a {} após {} tentativa(s)", addr, attempts);
                    return Ok(channel);
                }
                Err(e) => {
                    if attempts >= max_retries {
                        error!(
                            "Falha ao conectar a {} após {} tentativas: {}",
                            addr, attempts, e
                        );
                        return Err(e);
                    }
                    warn!(
                        "Tentativa {}/{} de conexão a {} falhou ({}); aguardando {:?}",
                        attempts, max_retries, addr, e, backoff
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                }
            }
        }
    }

    pub fn from_stream(stream: tokio::net::TcpStream, config: ChannelConfig) -> Self {
        let max_packet_size = config.max_packet_size.max(FRAME_HEADER_SIZE);
        let (read_half, write_half) = stream.into_split();
        let (tx, rx) = mpsc::channel(64);

        tokio::spawn(async move {
            Self::read_loop(read_half, tx, max_packet_size).await;
        });

        Self {
            writer: write_half,
            rx,
            max_packet_size,
            config,
            cipher: None,
        }
    }

    pub fn enable_encryption(&mut self, key: [u8; 32]) {
        self.cipher = Some(FamatechCipherState::new(key));
    }

    pub fn enable_cipher(&mut self, cipher: FamatechCipherState) {
        self.cipher = Some(cipher);
    }

    pub fn clear_cipher(&mut self) {
        if let Some(ref mut cipher) = self.cipher {
            cipher.clear();
        }
        self.cipher = None;
    }

    pub fn cipher(&self) -> Option<&FamatechCipherState> {
        self.cipher.as_ref()
    }

    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    async fn read_loop(
        mut stream: tokio::net::tcp::OwnedReadHalf,
        tx: mpsc::Sender<FramedPacket>,
        _max_packet_size: usize,
    ) {
        let mut buffer = [0u8; 65536];
        let mut parser = FrameParser::new();

        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    if let Err(e) = parser.finish() {
                        debug!("Frame truncado ao finalizar: {}", e);
                    }
                    break;
                }
                Ok(n) => match parser.feed(&buffer[..n]) {
                    Ok(frames) => {
                        for frame in frames {
                            if tx.send(frame).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Erro de framing: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    debug!("Erro de leitura no socket: {}", e);
                    break;
                }
            }
        }
    }

    pub async fn send_frame(&mut self, packet: FramedPacket) -> Result<()> {
        let bytes = packet.to_bytes();
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn send(&mut self, payload: Vec<u8>) -> Result<()> {
        if payload.len() > self.max_packet_size {
            return Err(anyhow::Error::from(TransportError::BufferOverflow));
        }

        let packet = FramedPacket::new(payload)?;
        self.send_frame(packet).await
    }

    pub async fn send_secure(&mut self, plaintext: &[u8]) -> Result<()> {
        let ciphertext = match &mut self.cipher {
            Some(cipher) => cipher.encrypt(plaintext)?,
            None => return Err(TransportError::EncryptionNotEnabled.into()),
        };

        let packet = FramedPacket::new(ciphertext)?;
        self.send_frame(packet).await
    }

    pub async fn receive(&mut self) -> Result<FramedPacket> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| anyhow::Error::from(TransportError::ConnectionClosed))
    }

    pub async fn receive_secure(&mut self) -> Result<Vec<u8>> {
        let frame = self.receive().await?;
        match &mut self.cipher {
            Some(cipher) => {
                let plaintext = cipher.decrypt(&frame.payload)?;
                Ok(plaintext)
            }
            None => Err(TransportError::EncryptionNotEnabled.into()),
        }
    }

    pub fn try_receive(&mut self) -> Result<FramedPacket> {
        self.rx
            .try_recv()
            .map_err(|_| anyhow::Error::from(TransportError::ConnectionClosed))
    }

    pub async fn close(&mut self) -> Result<()> {
        self.writer.shutdown().await?;
        Ok(())
    }

    pub fn config(&self) -> &ChannelConfig {
        &self.config
    }
}

pub struct TcpChannelListener {
    listener: tokio::net::TcpListener,
    config: ChannelConfig,
}

impl TcpChannelListener {
    pub async fn bind(addr: &str, config: ChannelConfig) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        Ok(Self { listener, config })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn accept(&self) -> Result<TcpChannel> {
        let (stream, _) = self.listener.accept().await?;
        Ok(TcpChannel::from_stream(stream, self.config.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::framing::{FrameParser, FramedPacket, FramingError};

    #[tokio::test]
    async fn test_tcp_channel_send_receive_frame() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(&addr.to_string())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let test_payload = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03];
        let pkt = FramedPacket::new(test_payload.clone()).unwrap();
        let bytes = pkt.to_bytes();
        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();

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
    async fn test_tcp_channel_secure_exchange() {
        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.listener.local_addr().unwrap();

        let mut client_channel = TcpChannel::connect(&addr.to_string(), ChannelConfig::default())
            .await
            .unwrap();
        let mut server_channel = listener.accept().await.unwrap();

        let shared_key = [0x42u8; 32];
        client_channel.enable_encryption(shared_key);
        server_channel.enable_encryption(shared_key);

        let secret_msg = b"Ethernet Frame Data 0123456789".to_vec();
        client_channel.send_secure(&secret_msg).await.unwrap();

        let received = server_channel.receive_secure().await.unwrap();
        assert_eq!(received, secret_msg);

        let response = b"ACK Ethernet Frame".to_vec();
        server_channel.send_secure(&response).await.unwrap();

        let client_received = client_channel.receive_secure().await.unwrap();
        assert_eq!(client_received, response);
    }

    #[tokio::test]
    async fn test_tcp_channel_fragmented_receive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(&addr.to_string())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let payload = vec![0xaa; 1000];
        let pkt = FramedPacket::new(payload.clone()).unwrap();
        let bytes = pkt.to_bytes();

        let half = FRAME_HEADER_SIZE + payload.len() / 2;
        client.write_all(&bytes[..half]).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        let mut parser = FrameParser::new();
        let frames = parser.feed(&buf[..n]).unwrap();

        if frames.is_empty() {
            assert!(parser.buffered_len() > 0);
        }

        client.write_all(&bytes[half..]).await.unwrap();
        client.flush().await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mut buf2 = [0u8; 1024];
        let n2 = server.read(&mut buf2).await.unwrap();
        let mut parser2 = FrameParser::new();
        let mut all_data = Vec::new();
        all_data.extend_from_slice(&buf[..n]);
        all_data.extend_from_slice(&buf2[..n2]);
        let frames = parser2.feed(&all_data).unwrap();

        assert!(!frames.is_empty());
        assert_eq!(frames[0].payload, payload);

        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_frames_in_one_read() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(&addr.to_string())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let pkt1 = FramedPacket::new(vec![1, 2, 3]).unwrap();
        let pkt2 = FramedPacket::new(vec![4, 5, 6]).unwrap();
        let mut bytes = pkt1.to_bytes();
        bytes.extend_from_slice(&pkt2.to_bytes());

        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();

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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(&addr.to_string())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        client.write_all(&[0x00, 0x00, 0x00, 0x20]).await.unwrap();
        client.flush().await.unwrap();

        client.shutdown().await.unwrap();

        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(n, 4);

        let mut parser = FrameParser::new();
        let _ = parser.feed(&buf[..n]);
        assert_eq!(parser.buffered_len(), 4);

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_channel_oversized_payload_rejection() {
        let mut parser = FrameParser::new();

        let result = parser.feed(&[0x00, 0x01, 0x00, 0x01]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FramingError::PayloadTooLarge { .. }
        ));
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    async fn channel_pair() -> (TcpChannel, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (
            TcpChannel::from_stream(client, ChannelConfig::default()),
            server,
        )
    }

    fn wire(payload: &[u8]) -> Vec<u8> {
        FramedPacket::new(payload.to_vec()).unwrap().to_bytes()
    }

    #[tokio::test]
    async fn partial_frame_is_not_duplicated_across_reads() {
        let (mut ch, mut server) = channel_pair().await;
        let a = vec![0x11; 10];
        let b = vec![0x22; 300];
        let c = vec![0x33; 7];
        let wb = wire(&b);

        let mut first = wire(&a);
        first.extend_from_slice(&wb[..100]);
        server.write_all(&first).await.unwrap();
        server.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut second = wb[100..].to_vec();
        second.extend_from_slice(&wire(&c));
        server.write_all(&second).await.unwrap();
        server.flush().await.unwrap();

        assert_eq!(ch.receive().await.unwrap().payload, a);
        assert_eq!(ch.receive().await.unwrap().payload, b);
        assert_eq!(ch.receive().await.unwrap().payload, c);
    }

    #[tokio::test]
    async fn byte_by_byte_delivery_preserves_every_frame() {
        let (mut ch, mut server) = channel_pair().await;
        let payloads: Vec<Vec<u8>> = (1..=4u8).map(|i| vec![i; 20 * i as usize]).collect();
        let stream: Vec<u8> = payloads.iter().flat_map(|p| wire(p)).collect();

        let writer = tokio::spawn(async move {
            for byte in stream {
                server.write_all(&[byte]).await.unwrap();
                server.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            server
        });

        for expected in &payloads {
            assert_eq!(&ch.receive().await.unwrap().payload, expected);
        }
        let _server = writer.await.unwrap();
    }
}
