pub mod control;
pub mod control_handshake;
pub mod handshake;

pub use control::{
    ControlConnection, ControlConnectionState, ControlSessionError, ControlStats,
    DEFAULT_CONTROL_TIMEOUT, RADMIN_CONTROL_PORT,
};
#[cfg(any(test, feature = "srp-test-emulator"))]
pub use control_handshake::{ControlServerSession, ControlServerState};

pub use control_handshake::{
    decode_identity, decode_items, encode_identity, encode_item, find_item, get_srp_prime_n,
    ControlClientNegotiator, ControlClientState, ControlHandshakeError, ControlItem,
    ControlStepOutput, CONTROL_SESSION_KEY_SIZE, RADMIN_SRP1536_MODULUS_LEN,
    RADMIN_SRP1536_PRIME_HEX, RADMIN_SRP_DIGEST_LEN, RADMIN_SRP_GENERATOR, RADMIN_SRP_K,
    RADMIN_SRP_KDF_KEY_LEN, SHELPER_PROTOCOL_VERSION, TAG_GENERATOR, TAG_IDENTITY, TAG_MODULUS,
    TAG_PROOF, TAG_PUBLIC_EPHEMERAL, TAG_SALT, TAG_STEP,
};
pub use handshake::{
    HandshakeError, HandshakeNegotiator, HandshakeStage, HandshakeStepOutput, RSessionServer,
    DEFAULT_RSA_PUBLIC_EXPONENT, HANDSHAKE_MAGIC, RSESSION_AES256_KEY_SIZE,
    RSESSION_CLIENT_HEADER_SIZE, RSESSION_KEY_MATERIAL_SIZE, RSESSION_PLAINTEXT_SIZE,
    RSESSION_RSA_BLOCK_SIZE, RSESSION_SERVER_TOKEN_SIZE, SHELPER_NETWORK_PROTOCOL_VERSION,
};

use crate::protocol::{AuthSessionId, RosNodeAddress};
use crate::transport::{ChannelConfig, TcpChannel};
use crate::Result;
use openssl::bn::BigNum;
use openssl::pkey::Public;
use openssl::rsa::Rsa;
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;
use tracing::{info, warn};

pub const RADMIN_DEFAULT_PORT: u16 = 17301;
pub const RADMIN_RELAY_PORT: u16 = 17351;
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const INITIAL_MAGIC: [u8; 4] = HANDSHAKE_MAGIC;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("sessão encerrada permanentemente (Closed); não pode ser reutilizada")]
    SessionClosed,
    #[error("operação inválida no estado atual da sessão: {state:?}")]
    InvalidState { state: SessionState },
    #[error("sessão não está ativa e autenticada (estado atual: {state:?})")]
    SessionNotActive { state: SessionState },
    #[error("canal criptográfico não está instalado na sessão")]
    EncryptionNotInstalled,
    #[error("chave pública RSA-2048 do servidor não configurada para o handshake RSession")]
    MissingServerPublicKey,
    #[error("timeout aguardando resposta de handshake do servidor")]
    HandshakeTimeout,
}

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
    Closed,
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
    negotiator: Option<HandshakeNegotiator>,
    server_public_key: Option<Rsa<Public>>,
    client_params: [u32; 3],
    server_token: Option<u32>,
    server_addr: Option<String>,
    handshake_timeout: Duration,
    connect_retries: u32,
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
            negotiator: None,
            server_public_key: None,
            client_params: [0, 0, 0],
            server_token: None,
            server_addr: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            connect_retries: 3,
        }
    }

    pub fn with_server_public_key(
        client_params: [u32; 3],
        server_public_key: Rsa<Public>,
    ) -> Result<Self> {
        let mut mgr = Self::new();
        mgr.set_client_params(client_params);
        mgr.set_server_public_key(server_public_key)?;
        Ok(mgr)
    }

    pub fn set_server_public_key_components(
        &mut self,
        modulus: &[u8],
        exponent: &[u8],
    ) -> Result<()> {
        if modulus.is_empty() || exponent.is_empty() {
            return Err(
                HandshakeError::InvalidRsaKey("módulo ou expoente RSA vazio".to_string()).into(),
            );
        }
        let n = BigNum::from_slice(modulus).map_err(|e| {
            HandshakeError::InvalidRsaKey(format!("BN_bin2bn(modulus) falhou: {e}"))
        })?;
        let e = BigNum::from_slice(exponent).map_err(|e| {
            HandshakeError::InvalidRsaKey(format!("BN_bin2bn(exponent) falhou: {e}"))
        })?;
        let pub_key = Rsa::from_public_components(n, e).map_err(|err| {
            HandshakeError::InvalidRsaKey(format!("Rsa::from_public_components falhou: {err}"))
        })?;
        self.set_server_public_key(pub_key)
    }

    pub fn set_server_public_key(&mut self, pub_key: Rsa<Public>) -> Result<()> {
        if pub_key.size() as usize != RSESSION_RSA_BLOCK_SIZE {
            return Err(HandshakeError::InvalidRsaKey(format!(
                "tamanho de chave RSA inválido: {} bytes (esperado {} bytes)",
                pub_key.size(),
                RSESSION_RSA_BLOCK_SIZE
            ))
            .into());
        }
        self.server_public_key = Some(pub_key);
        Ok(())
    }

    pub fn set_client_params(&mut self, client_params: [u32; 3]) {
        self.client_params = client_params;
    }

    pub fn set_handshake_timeout(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    pub fn set_connect_retries(&mut self, retries: u32) {
        self.connect_retries = retries.max(1);
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

    pub fn server_token(&self) -> Option<u32> {
        self.server_token
    }

    pub fn is_active(&self) -> bool {
        self.session.state == SessionState::SessionActive && self.is_encrypted()
    }

    pub fn is_encrypted(&self) -> bool {
        self.channel.as_ref().is_some_and(|ch| ch.is_encrypted())
    }

    pub async fn connect_tcp(&mut self, addr: &str) -> Result<()> {
        if self.session.state == SessionState::Closed {
            return Err(SessionError::SessionClosed.into());
        }

        self.cleanup_resources().await;

        self.server_addr = Some(addr.to_string());
        self.session.state = SessionState::Connecting;
        info!("Iniciando conexão TCP de sessão com {}", addr);

        let config = ChannelConfig {
            connect_timeout: self.handshake_timeout,
            keepalive_interval: KEEPALIVE_INTERVAL,
            ..ChannelConfig::default()
        };

        let channel = match TcpChannel::connect_with_retry(
            addr,
            config,
            self.connect_retries,
            Duration::from_millis(200),
        )
        .await
        {
            Ok(ch) => ch,
            Err(e) => {
                let err_msg = format!("Falha de conexão TCP com {addr}: {e}");
                return Err(self.fail_session(err_msg).await);
            }
        };

        self.channel = Some(channel);
        self.session.state = SessionState::ConnectedUnencrypted;
        Ok(())
    }

    pub async fn connect(&mut self, addr: &str) -> Result<()> {
        self.connect_tcp(addr).await?;
        self.perform_handshake().await
    }

    pub async fn perform_handshake(&mut self) -> Result<()> {
        if self.session.state == SessionState::Closed {
            return Err(SessionError::SessionClosed.into());
        }

        if self.session.state != SessionState::ConnectedUnencrypted {
            let current = self.session.state.clone();
            let err_msg = format!(
                "perform_handshake exige estado ConnectedUnencrypted, encontrado {current:?}"
            );
            return Err(self.fail_session(err_msg).await);
        }

        let server_pub_key = match self.server_public_key.as_ref() {
            Some(pk) => {
                let n = pk.n().to_owned().map_err(|e| anyhow::anyhow!(e))?;
                let e = pk.e().to_owned().map_err(|e| anyhow::anyhow!(e))?;
                Rsa::from_public_components(n, e).map_err(|e| anyhow::anyhow!(e))?
            }
            None => {
                return Err(self
                    .fail_session(SessionError::MissingServerPublicKey.to_string())
                    .await);
            }
        };

        let mut negotiator =
            match HandshakeNegotiator::with_server_public_key(self.client_params, server_pub_key) {
                Ok(neg) => neg,
                Err(e) => {
                    return Err(self
                        .fail_session(format!("Falha ao inicializar RSession: {e}"))
                        .await);
                }
            };

        self.session.state = SessionState::Handshaking;
        let step1 = match negotiator.get_next_buffer(None) {
            Ok(step) => step,
            Err(e) => {
                return Err(self
                    .fail_session(format!("Falha no Estado 0 do handshake: {e}"))
                    .await);
            }
        };

        let rsa_block = match step1.output {
            Some(pkt) if pkt.len() == RSESSION_RSA_BLOCK_SIZE && !step1.is_complete => pkt,
            _ => {
                return Err(self
                    .fail_session("Estado 0 não produziu bloco RSA de 256 bytes".to_string())
                    .await);
            }
        };

        {
            let channel = match self.channel.as_mut() {
                Some(ch) => ch,
                None => {
                    return Err(self.fail_session("Canal TCP ausente no handshake").await);
                }
            };

            if let Err(e) = channel.send(rsa_block.clone()).await {
                return Err(self
                    .fail_session(format!("Falha ao enviar bloco RSA de 256 bytes: {e}"))
                    .await);
            }
        }
        self.session.stats.tx_bytes += (4 + rsa_block.len()) as u64;
        self.session.stats.tx_packets += 1;

        self.session.state = SessionState::KeyExchange;
        let timeout_duration = self.handshake_timeout;

        let response_frame = {
            let channel = match self.channel.as_mut() {
                Some(ch) => ch,
                None => {
                    return Err(self
                        .fail_session("Canal TCP ausente na troca de chaves")
                        .await);
                }
            };

            match tokio::time::timeout(timeout_duration, channel.receive()).await {
                Ok(Ok(frame)) => frame,
                Ok(Err(e)) => {
                    return Err(self
                        .fail_session(format!(
                            "Conexão encerrada ou inválida aguardando token do servidor: {e}"
                        ))
                        .await);
                }
                Err(_) => {
                    return Err(self
                        .fail_session(SessionError::HandshakeTimeout.to_string())
                        .await);
                }
            }
        };

        self.session.stats.rx_bytes += (4 + response_frame.payload.len()) as u64;
        self.session.stats.rx_packets += 1;

        let step2 = match negotiator.get_next_buffer(Some(&response_frame.payload)) {
            Ok(step) => step,
            Err(e) => {
                return Err(self
                    .fail_session(format!("Resposta de servidor inválida no Estado 2: {e}"))
                    .await);
            }
        };

        if !step2.is_complete || !negotiator.is_established() {
            return Err(self
                .fail_session("Handshake RSession incompleto após Estado 2".to_string())
                .await);
        }

        let server_token = match negotiator.get_server_token() {
            Ok(tok) => tok,
            Err(e) => {
                return Err(self
                    .fail_session(format!("Token do servidor indisponível: {e}"))
                    .await);
            }
        };

        let cipher = match negotiator.create_cipher() {
            Ok(c) => c,
            Err(e) => {
                return Err(self
                    .fail_session(format!("Material de chave de sessão indisponível: {e}"))
                    .await);
            }
        };

        {
            let channel = match self.channel.as_mut() {
                Some(ch) => ch,
                None => {
                    return Err(self
                        .fail_session("Canal TCP ausente ao instalar chave AES-256")
                        .await);
                }
            };
            channel.enable_cipher(cipher);
            if !channel.is_encrypted() {
                return Err(self
                    .fail_session(SessionError::EncryptionNotInstalled.to_string())
                    .await);
            }
        }

        self.server_token = Some(server_token);
        self.negotiator = Some(negotiator);
        self.session.state = SessionState::SessionActive;
        self.session.connected_since = Some(SystemTime::now());
        self.session.stats.last_activity = Some(Instant::now());

        info!(
            "Sessão RSession estabelecida e canal AES-256-CBC ativado (token: 0x{:08x})",
            server_token
        );
        Ok(())
    }

    pub async fn activate_from_negotiator(
        &mut self,
        negotiator: HandshakeNegotiator,
    ) -> Result<()> {
        if self.session.state == SessionState::Closed {
            return Err(SessionError::SessionClosed.into());
        }

        if !negotiator.is_established() {
            return Err(self
                .fail_session(
                    "Tentativa de ativar sessão sem handshake RSession concluído e sem material de chave"
                        .to_string(),
                )
                .await);
        }

        let token = match negotiator.get_server_token() {
            Ok(t) => t,
            Err(e) => {
                return Err(self
                    .fail_session(format!("Token ausente no negociador: {e}"))
                    .await);
            }
        };

        let cipher = match negotiator.create_cipher() {
            Ok(c) => c,
            Err(e) => {
                return Err(self
                    .fail_session(format!("Chave ausente no negociador: {e}"))
                    .await);
            }
        };

        let channel = match self.channel.as_mut() {
            Some(ch) => ch,
            None => {
                return Err(self
                    .fail_session("Canal TCP ausente ao ativar sessão".to_string())
                    .await);
            }
        };

        channel.enable_cipher(cipher);
        self.server_token = Some(token);
        self.negotiator = Some(negotiator);
        self.session.state = SessionState::SessionActive;
        self.session.connected_since = Some(SystemTime::now());
        self.session.stats.last_activity = Some(Instant::now());
        Ok(())
    }

    pub async fn send_data(&mut self, data: &[u8]) -> Result<()> {
        if self.session.state == SessionState::Closed {
            return Err(SessionError::SessionClosed.into());
        }
        if self.session.state != SessionState::SessionActive {
            return Err(SessionError::SessionNotActive {
                state: self.session.state.clone(),
            }
            .into());
        }

        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Sessão desconectada"))?;

        if !channel.is_encrypted() {
            return Err(SessionError::EncryptionNotInstalled.into());
        }

        if let Err(e) = channel.send_secure(data).await {
            warn!("Erro ao enviar dados cifrados na sessão: {}", e);
            return Err(self
                .fail_session(format!("Falha de envio no canal seguro: {e}"))
                .await);
        }

        self.session.stats.tx_bytes += data.len() as u64;
        self.session.stats.tx_packets += 1;
        self.session.stats.last_activity = Some(Instant::now());
        Ok(())
    }

    pub async fn receive_data(&mut self) -> Result<Vec<u8>> {
        if self.session.state == SessionState::Closed {
            return Err(SessionError::SessionClosed.into());
        }
        if self.session.state != SessionState::SessionActive {
            return Err(SessionError::SessionNotActive {
                state: self.session.state.clone(),
            }
            .into());
        }

        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Sessão desconectada"))?;

        if !channel.is_encrypted() {
            return Err(SessionError::EncryptionNotInstalled.into());
        }

        let data = match channel.receive_secure().await {
            Ok(pt) => pt,
            Err(e) => {
                warn!("Erro ao receber/decifrar dados na sessão: {}", e);
                return Err(self
                    .fail_session(format!("Falha de recepção/decifragem no canal seguro: {e}"))
                    .await);
            }
        };

        self.session.stats.rx_bytes += data.len() as u64;
        self.session.stats.rx_packets += 1;
        self.session.stats.last_activity = Some(Instant::now());
        Ok(data)
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        if self.session.state == SessionState::Closed {
            return Err(SessionError::SessionClosed.into());
        }
        self.cleanup_resources().await;
        self.session.state = SessionState::Disconnected;
        info!("Sessão desconectada e estado criptográfico limpo");
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        self.cleanup_resources().await;
        self.session.state = SessionState::Closed;
        info!("Sessão encerrada permanentemente (Closed)");
        Ok(())
    }

    async fn cleanup_resources(&mut self) {
        if let Some(mut negotiator) = self.negotiator.take() {
            negotiator.clear();
        }
        if let Some(mut channel) = self.channel.take() {
            channel.clear_cipher();
            let _ = channel.close().await;
        }
        self.server_token = None;
        self.session.connected_since = None;
    }

    async fn fail_session(&mut self, reason: impl Into<String>) -> anyhow::Error {
        let reason = reason.into();
        self.cleanup_resources().await;
        self.session.state = SessionState::Failed(reason.clone());
        anyhow::anyhow!(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TcpChannelListener;

    fn generate_server_keypair() -> (Rsa<openssl::pkey::Private>, Rsa<Public>) {
        let priv_key = Rsa::generate(2048).unwrap();
        let n = priv_key.n().to_owned().unwrap();
        let e = priv_key.e().to_owned().unwrap();
        let pub_key = Rsa::from_public_components(n, e).unwrap();
        (priv_key, pub_key)
    }

    #[tokio::test]
    async fn test_session_full_handshake_and_encrypted_data_exchange() {
        let (server_priv, server_pub) = generate_server_keypair();
        let expected_params = [0x01020304, 0x05060708, 0x090a0b0c];
        let expected_token = 0xCAFEBABE_u32;

        let mut session =
            SessionManager::with_server_public_key(expected_params, server_pub).unwrap();
        assert_eq!(session.state(), SessionState::Disconnected);
        assert!(!session.is_active());

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();
            let mut rsession_srv =
                RSessionServer::create_server(expected_token, server_priv).unwrap();

            let frame1 = server_ch.receive().await.unwrap();
            assert_eq!(frame1.payload.len(), RSESSION_RSA_BLOCK_SIZE);

            let srv_step = rsession_srv.get_next_buffer(Some(&frame1.payload)).unwrap();
            assert!(srv_step.is_complete);
            assert_eq!(rsession_srv.get_client_params().unwrap(), expected_params);

            let token_bytes = srv_step.output.unwrap();
            assert_eq!(token_bytes.len(), RSESSION_SERVER_TOKEN_SIZE);
            server_ch.send(token_bytes).await.unwrap();

            let srv_cipher = rsession_srv.create_cipher().unwrap();
            server_ch.enable_cipher(srv_cipher);

            let msg1 = server_ch.receive_secure().await.unwrap();
            assert_eq!(msg1, b"Pacote seguro #1 C->S");

            let msg2 = server_ch.receive_secure().await.unwrap();
            assert_eq!(msg2, b"Pacote seguro #2 C->S");

            server_ch
                .send_secure(b"Resposta segura #1 S->C")
                .await
                .unwrap();
            server_ch
                .send_secure(b"Resposta segura #2 S->C")
                .await
                .unwrap();
        });

        session.connect(&addr.to_string()).await.unwrap();
        assert_eq!(session.state(), SessionState::SessionActive);
        assert!(session.is_active());
        assert!(session.is_encrypted());
        assert_eq!(session.server_token(), Some(expected_token));
        assert!(session.session().connected_since.is_some());

        session.send_data(b"Pacote seguro #1 C->S").await.unwrap();
        session.send_data(b"Pacote seguro #2 C->S").await.unwrap();

        let reply1 = session.receive_data().await.unwrap();
        assert_eq!(reply1, b"Resposta segura #1 S->C");

        let reply2 = session.receive_data().await.unwrap();
        assert_eq!(reply2, b"Resposta segura #2 S->C");

        server_task.await.unwrap();

        session.close().await.unwrap();
        assert_eq!(session.state(), SessionState::Closed);
        assert!(!session.is_active());
        assert!(!session.is_encrypted());
    }

    #[tokio::test]
    async fn test_tcp_connected_unencrypted_is_not_active_session() {
        let (_server_priv, server_pub) = generate_server_keypair();
        let mut session = SessionManager::with_server_public_key([1, 2, 3], server_pub).unwrap();

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let _accept_task = tokio::spawn(async move {
            let _srv = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        session.connect_tcp(&addr.to_string()).await.unwrap();
        assert_eq!(session.state(), SessionState::ConnectedUnencrypted);
        assert!(!session.is_active());
        assert!(!session.is_encrypted());

        let send_err = session
            .send_data(b"dados nao autorizados")
            .await
            .unwrap_err();
        assert!(send_err.to_string().contains("ConnectedUnencrypted"));

        let recv_err = session.receive_data().await.unwrap_err();
        assert!(recv_err.to_string().contains("ConnectedUnencrypted"));
    }

    #[tokio::test]
    async fn test_token_without_key_cannot_activate_session() {
        let (_server_priv, server_pub) = generate_server_keypair();
        let mut session = SessionManager::with_server_public_key([1, 2, 3], server_pub).unwrap();

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let _accept_task = tokio::spawn(async move {
            let _srv = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        session.connect_tcp(&addr.to_string()).await.unwrap();
        assert_eq!(session.state(), SessionState::ConnectedUnencrypted);

        let unestablished = HandshakeNegotiator::new();
        let err = session
            .activate_from_negotiator(unestablished)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("sem handshake RSession concluído e sem material de chave"));
        assert!(matches!(session.state(), SessionState::Failed(_)));
        assert!(!session.is_active());
    }

    #[tokio::test]
    async fn test_handshake_rejects_invalid_server_token_size_and_closes_channel() {
        let (_server_priv, server_pub) = generate_server_keypair();
        let mut session = SessionManager::with_server_public_key([1, 2, 3], server_pub).unwrap();

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();
            let frame1 = server_ch.receive().await.unwrap();
            assert_eq!(frame1.payload.len(), RSESSION_RSA_BLOCK_SIZE);

            server_ch.send(vec![0xAA; 12]).await.unwrap();
        });

        let err = session.connect(&addr.to_string()).await.unwrap_err();
        assert!(err.to_string().contains("esperado 4 bytes, recebido 12"));
        assert!(matches!(session.state(), SessionState::Failed(_)));
        assert!(!session.is_active());
        assert!(!session.is_encrypted());
        assert!(session.server_token().is_none());

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_fails_on_server_disconnect_or_timeout() {
        let (_server_priv, server_pub) = generate_server_keypair();
        let mut session = SessionManager::with_server_public_key([1, 2, 3], server_pub).unwrap();
        session.set_handshake_timeout(Duration::from_millis(150));

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();
            let _ = server_ch.receive().await.unwrap();
            server_ch.close().await.unwrap();
        });

        let err = session.connect(&addr.to_string()).await.unwrap_err();
        assert!(matches!(session.state(), SessionState::Failed(_)));
        assert!(!session.is_active());
        assert!(err.to_string().contains("aguardando token do servidor"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_closed_session_cannot_be_reused() {
        let (server_priv, server_pub) = generate_server_keypair();
        let mut session = SessionManager::with_server_public_key([1, 2, 3], server_pub).unwrap();

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();
            let mut rsession_srv = RSessionServer::create_server(777, server_priv).unwrap();
            let frame1 = server_ch.receive().await.unwrap();
            let srv_step = rsession_srv.get_next_buffer(Some(&frame1.payload)).unwrap();
            server_ch.send(srv_step.output.unwrap()).await.unwrap();
        });

        session.connect(&addr.to_string()).await.unwrap();
        assert_eq!(session.state(), SessionState::SessionActive);
        server_task.await.unwrap();

        session.close().await.unwrap();
        assert_eq!(session.state(), SessionState::Closed);

        assert_eq!(
            session
                .send_data(b"teste")
                .await
                .unwrap_err()
                .downcast_ref::<SessionError>(),
            Some(&SessionError::SessionClosed)
        );
        assert_eq!(
            session
                .receive_data()
                .await
                .unwrap_err()
                .downcast_ref::<SessionError>(),
            Some(&SessionError::SessionClosed)
        );
        assert_eq!(
            session
                .connect(&addr.to_string())
                .await
                .unwrap_err()
                .downcast_ref::<SessionError>(),
            Some(&SessionError::SessionClosed)
        );
        assert_eq!(
            session
                .perform_handshake()
                .await
                .unwrap_err()
                .downcast_ref::<SessionError>(),
            Some(&SessionError::SessionClosed)
        );
    }
}
