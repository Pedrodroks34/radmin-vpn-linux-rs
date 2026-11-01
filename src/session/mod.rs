pub mod handshake;

pub use handshake::{HandshakeNegotiator, HandshakeStage, HANDSHAKE_MAGIC};

use crate::protocol::tlv::{TlvMessage, TlvTag};
use crate::protocol::{AuthSessionId, RosNodeAddress};
use crate::transport::{ChannelConfig, TcpChannel};
use crate::Result;
use openssl::rsa::Rsa;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, info, warn};

pub const RADMIN_DEFAULT_PORT: u16 = 17301;
pub const RADMIN_RELAY_PORT: u16 = 17351;
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const INITIAL_MAGIC: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Disconnected,
    Connecting,
    ConnectedUnencrypted,
    Handshaking,
    KeyExchange,
    SessionActive,
    Reconnecting,
    Failed(String),
}

#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub keepalives_sent: u64,
    pub last_activity: Option<Instant>,
}

#[derive(Debug)]
pub struct Session {
    pub session_id: Option<AuthSessionId>,
    pub state: SessionState,
    pub nodes: Vec<RosNodeAddress>,
    pub connected_since: Option<SystemTime>,
    pub stats: SessionStats,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            session_id: None,
            state: SessionState::Disconnected,
            nodes: Vec::new(),
            connected_since: None,
            stats: SessionStats::default(),
        }
    }
}

pub struct SessionManager {
    session: Session,
    channel: Option<TcpChannel>,
    rsa_key: Option<Rsa<openssl::pkey::Private>>,
    server_addr: Option<String>,
    negotiator: Option<HandshakeNegotiator>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            session: Session::default(),
            channel: None,
            rsa_key: None,
            server_addr: None,
            negotiator: None,
        }
    }

    pub fn state(&self) -> SessionState {
        self.session.state.clone()
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn stats(&self) -> &SessionStats {
        &self.session.stats
    }

    pub fn negotiator(&self) -> Option<&HandshakeNegotiator> {
        self.negotiator.as_ref()
    }

    /// Gera ou carrega a chave RSA de 2048 bits para o handshake de autenticação.
    pub fn ensure_rsa_key(&mut self) -> Result<()> {
        if self.rsa_key.is_none() {
            let rsa = Rsa::generate(2048)?;
            self.rsa_key = Some(rsa);
        }
        Ok(())
    }

    /// Conecta ao servidor e executa a máquina de estados do handshake.
    pub async fn connect(&mut self, addr: &str) -> Result<()> {
        self.server_addr = Some(addr.to_string());
        self.session.state = SessionState::Connecting;
        info!("Iniciando conexão de sessão com {}", addr);

        let config = ChannelConfig {
            connect_timeout: Duration::from_secs(5),
            keepalive_interval: KEEPALIVE_INTERVAL,
            ..Default::default()
        };

        let channel =
            match TcpChannel::connect_with_retry(addr, config, 3, Duration::from_millis(500)).await
            {
                Ok(ch) => ch,
                Err(e) => {
                    let err_msg = format!("Falha de conexão com {}: {}", addr, e);
                    self.session.state = SessionState::Failed(err_msg.clone());
                    return Err(anyhow::anyhow!(err_msg));
                }
            };

        self.channel = Some(channel);
        self.session.state = SessionState::ConnectedUnencrypted;

        // Executa a sequência de handshake real aguardando confirmação do servidor
        if let Err(e) = self.perform_handshake().await {
            let err_msg = format!("Handshake falhou: {}", e);
            self.session.state = SessionState::Failed(err_msg.clone());
            return Err(anyhow::anyhow!(err_msg));
        }

        Ok(())
    }

    /// Executa o fluxo de handshake observado nos PCAPs:
    /// 1. Envia magic frame unencrypted (0x03000000)
    /// 2. Aguarda e valida a resposta de confirmação de magic do servidor
    /// 3. Envia TLV com RSA public key (0x090001ca) e session token (0x010001df)
    /// 4. Aguarda e valida a resposta de chave/token do servidor
    /// 5. Ativa criptografia AES-256-CBC negociada e transiciona para SessionActive
    async fn perform_handshake(&mut self) -> Result<()> {
        self.ensure_rsa_key()?;
        let rsa = self.rsa_key.as_ref().unwrap();

        let mut negotiator = HandshakeNegotiator::new();
        negotiator.set_rsa_key(rsa.clone());

        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Canal TCP ausente"))?;

        // 1. Enviar magic header inicial (0x03000000 em frame de 4 bytes)
        self.session.state = SessionState::Handshaking;
        let magic_bytes = negotiator.build_magic_packet();
        channel.send(magic_bytes.clone()).await?;
        self.session.stats.tx_bytes += 4 + magic_bytes.len() as u64;
        self.session.stats.tx_packets += 1;

        // 2. Aguardar resposta de magic do servidor com timeout
        let magic_resp = tokio::time::timeout(HANDSHAKE_TIMEOUT, channel.receive())
            .await
            .map_err(|_| {
                anyhow::anyhow!("Timeout aguardando confirmação de magic do servidor")
            })??;
        self.session.stats.rx_bytes += 4 + magic_resp.payload.len() as u64;
        self.session.stats.rx_packets += 1;
        negotiator.verify_magic_response(&magic_resp.payload)?;

        // 3. Transicionar para KeyExchange e enviar TLV com chave pública RSA
        self.session.state = SessionState::KeyExchange;
        let hello_bytes = negotiator.build_client_hello()?;
        channel.send(hello_bytes.clone()).await?;
        self.session.stats.tx_bytes += 4 + hello_bytes.len() as u64;
        self.session.stats.tx_packets += 1;

        // 4. Aguardar resposta real de chave/token do servidor com timeout
        let server_resp = tokio::time::timeout(HANDSHAKE_TIMEOUT, channel.receive())
            .await
            .map_err(|_| {
                anyhow::anyhow!("Timeout aguardando resposta de chave/token do servidor")
            })??;
        self.session.stats.rx_bytes += 4 + server_resp.payload.len() as u64;
        self.session.stats.rx_packets += 1;

        let key_opt = negotiator.process_server_response(&server_resp.payload)?;
        if let Some(key) = key_opt {
            channel.enable_encryption(key);
            info!("Criptografia AES-256-CBC ativada no canal da sessão");
        }

        // 5. Só ativa a sessão após a confirmação exigida
        self.session.state = SessionState::SessionActive;
        self.session.connected_since = Some(SystemTime::now());
        self.session.stats.last_activity = Some(Instant::now());
        self.negotiator = Some(negotiator);

        info!("Sessão estabelecida e confirmada pelo servidor com sucesso!");
        Ok(())
    }

    /// Habilita criptografia AES no canal subjacente usando a chave de 256 bits negociada.
    pub fn enable_session_cipher(&mut self, session_key: [u8; 32]) {
        if let Some(channel) = self.channel.as_mut() {
            channel.enable_encryption(session_key);
            info!("Criptografia AES-256-CBC ativada na sessão");
        }
    }

    /// Envia pacote de keepalive periódico.
    pub async fn send_keepalive(&mut self) -> Result<()> {
        if self.session.state != SessionState::SessionActive {
            return Ok(());
        }

        let channel = match self.channel.as_mut() {
            Some(ch) => ch,
            None => return Ok(()),
        };

        let now_millis = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut tlv = TlvMessage::new();
        tlv.add_u64(TlvTag::TAG_TIMESTAMP, now_millis);
        let bytes = tlv.to_bytes();

        let res = if channel.is_encrypted() {
            channel.send_secure(&bytes).await
        } else {
            channel.send(bytes).await
        };

        match res {
            Ok(_) => {
                self.session.stats.keepalives_sent += 1;
                self.session.stats.last_activity = Some(Instant::now());
                debug!("Keepalive de sessão enviado com sucesso");
                Ok(())
            }
            Err(e) => {
                warn!("Falha ao enviar keepalive: {}", e);
                self.session.state = SessionState::Reconnecting;
                Err(e)
            }
        }
    }

    /// Envia dados (quadros de túnel ou comandos) através do canal seguro da sessão.
    pub async fn send_data(&mut self, data: &[u8]) -> Result<()> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Sessão desconectada"))?;

        if channel.is_encrypted() {
            channel.send_secure(data).await?;
        } else {
            channel.send(data.to_vec()).await?;
        }

        self.session.stats.tx_bytes += data.len() as u64;
        self.session.stats.tx_packets += 1;
        self.session.stats.last_activity = Some(Instant::now());
        Ok(())
    }

    /// Recebe dados do canal seguro da sessão.
    pub async fn receive_data(&mut self) -> Result<Vec<u8>> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Sessão desconectada"))?;

        let data = if channel.is_encrypted() {
            channel.receive_secure().await?
        } else {
            let frame = channel.receive().await?;
            frame.payload
        };

        self.session.stats.rx_bytes += data.len() as u64;
        self.session.stats.rx_packets += 1;
        self.session.stats.last_activity = Some(Instant::now());
        Ok(data)
    }

    /// Encerra a sessão e libera o canal TCP.
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut channel) = self.channel.take() {
            let _ = channel.close().await;
        }
        self.session.state = SessionState::Disconnected;
        self.session.connected_since = None;
        info!("Sessão desconectada");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TcpChannelListener;
    use openssl::rsa::Padding;

    #[tokio::test]
    async fn test_session_state_transitions() {
        let mut session = SessionManager::new();
        assert_eq!(session.state(), SessionState::Disconnected);

        // Inicia um listener simulando o servidor Radmin oficial
        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();

            // 1. Receber magic inicial [03 00 00 00]
            let magic_frame = server_ch.receive().await.unwrap();
            assert_eq!(magic_frame.payload, INITIAL_MAGIC);

            // Servidor confirma com magic de volta
            server_ch.send(INITIAL_MAGIC.to_vec()).await.unwrap();

            // 2. Receber frame com TLVs de handshake (Client Hello)
            let tlv_frame = server_ch.receive().await.unwrap();
            let msg = TlvMessage::parse(&tlv_frame.payload).unwrap();
            assert_eq!(msg.get_u32(TlvTag::TAG_SESSION_TOKEN), Some(1));
            assert_eq!(msg.get_u32(TlvTag::TAG_PEER_STATUS), Some(2));
            assert!(msg.get_buffer(TlvTag::TAG_RSA_PUBLIC_KEY).is_some());

            // 3. Servidor envia confirmação de sessão (Pacote #687)
            let pkt_687_payload = vec![
                0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x01, 0xdf, 0x00, 0x00, 0x00, 0x02,
            ];
            server_ch.send(pkt_687_payload).await.unwrap();
        });

        session.connect(&addr.to_string()).await.unwrap();
        assert_eq!(session.state(), SessionState::SessionActive);
        assert!(session.session().connected_since.is_some());
        assert!(session.negotiator().is_some());

        handle.await.unwrap();

        session.disconnect().await.unwrap();
        assert_eq!(session.state(), SessionState::Disconnected);
    }

    #[tokio::test]
    async fn test_session_handshake_with_rsa_key_exchange() {
        let mut session = SessionManager::new();

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let expected_key = [0x55u8; 32];

        let handle = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();

            // 1. Magic
            let _ = server_ch.receive().await.unwrap();
            server_ch.send(INITIAL_MAGIC.to_vec()).await.unwrap();

            // 2. Client Hello
            let tlv_frame = server_ch.receive().await.unwrap();
            let msg = TlvMessage::parse(&tlv_frame.payload).unwrap();
            let pub_key_raw = msg.get_buffer(TlvTag::TAG_RSA_PUBLIC_KEY).unwrap();
            assert_eq!(pub_key_raw.len(), 256);

            // Reconstitui RSA público do cliente para cifrar a chave AES de sessão
            let n = openssl::bn::BigNum::from_slice(pub_key_raw).unwrap();
            let e = openssl::bn::BigNum::from_u32(65537).unwrap();
            let client_rsa = Rsa::from_public_components(n, e).unwrap();

            let mut encrypted_session_block = vec![0u8; 256];
            client_rsa
                .public_encrypt(&expected_key, &mut encrypted_session_block, Padding::PKCS1)
                .unwrap();

            // 3. Servidor responde com o bloco RSA de 256 bytes
            server_ch.send(encrypted_session_block).await.unwrap();

            // 4. Receber dados cifrados subsequentes
            let enc_data = server_ch.receive().await.unwrap();
            assert_eq!(enc_data.payload.len() % 16, 0);
        });

        session.connect(&addr.to_string()).await.unwrap();
        assert_eq!(session.state(), SessionState::SessionActive);

        // Enviar dados cifrados
        session.send_data(b"ping").await.unwrap();

        handle.await.unwrap();
        session.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_session_handshake_bad_magic_rejected() {
        let mut session = SessionManager::new();

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();
            let _ = server_ch.receive().await.unwrap();
            // Servidor envia magic incorreto
            server_ch.send(vec![0xde, 0xad, 0xbe, 0xef]).await.unwrap();
        });

        let res = session.connect(&addr.to_string()).await;
        assert!(res.is_err());
        match session.state() {
            SessionState::Failed(err) => assert!(err.contains("magic de handshake inválido")),
            other => panic!("Esperado Failed, obtido {:?}", other),
        }

        handle.await.unwrap();
    }
}
