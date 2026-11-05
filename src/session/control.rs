
use crate::session::control_handshake::{
    ControlClientNegotiator, ControlHandshakeError, SHELPER_PROTOCOL_VERSION,
};
use crate::transport::{ChannelConfig, TcpChannel};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info};
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

pub const RADMIN_CONTROL_PORT: u16 = 17301;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlSessionError {
    #[error("conexão de controle permanentemente fechada")]
    Closed,

    #[error("operação inválida no estado atual: {state:?}")]
    InvalidState { state: ControlConnectionState },

    #[error("conexão de controle não está ativa/cifrada (estado atual: {state:?})")]
    NotActive { state: ControlConnectionState },

    #[error("timeout aguardando resposta do servidor de controle")]
    Timeout,

    #[error("erro no handshake de controle SRP-6a: {0}")]
    Handshake(#[from] ControlHandshakeError),

    #[error("canal de transporte indisponível")]
    NoTransport,

    #[error("falha de I/O na conexão: {0}")]
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlConnectionState {
    Disconnected,
    Connecting,
    ConnectedUnencrypted,
    VersionExchange,
    SrpHandshake,
    SessionActive,
    Failed(String),
    Closed,
}

#[derive(Debug, Clone, Default)]
pub struct ControlStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub last_activity: Option<Instant>,
}

pub struct ControlConnection {
    username: String,
    password: Zeroizing<String>,
    server_addr: Option<String>,
    state: ControlConnectionState,
    channel: Option<TcpChannel>,
    negotiator: Option<ControlClientNegotiator>,
    timeout: Duration,
    stats: ControlStats,
}

impl std::fmt::Debug for ControlConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlConnection")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("server_addr", &self.server_addr)
            .field("state", &self.state)
            .field("timeout", &self.timeout)
            .field("stats", &self.stats)
            .finish()
    }
}

impl ControlConnection {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password: Zeroizing::new(password),
            server_addr: None,
            state: ControlConnectionState::Disconnected,
            channel: None,
            negotiator: None,
            timeout: DEFAULT_CONTROL_TIMEOUT,
            stats: ControlStats::default(),
        }
    }

    pub fn state(&self) -> &ControlConnectionState {
        &self.state
    }

    pub fn is_active(&self) -> bool {
        self.state == ControlConnectionState::SessionActive
    }

    pub fn stats(&self) -> &ControlStats {
        &self.stats
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub async fn connect(&mut self, addr: &str) -> Result<(), ControlSessionError> {
        if self.state == ControlConnectionState::Closed {
            return Err(ControlSessionError::Closed);
        }

        self.server_addr = Some(addr.to_string());
        self.state = ControlConnectionState::Connecting;
        info!(server = %addr, user = %self.username, "Conectando ao canal de controle...");

        let config = ChannelConfig {
            connect_timeout: self.timeout,
            keepalive_interval: Duration::from_secs(15),
            ..Default::default()
        };

        let channel = match TcpChannel::connect(addr, config).await {
            Ok(ch) => ch,
            Err(e) => {
                let msg = format!("Falha de conexão TCP com {addr}: {e}");
                error!("{msg}");
                self.state = ControlConnectionState::Failed(msg);
                return Err(ControlSessionError::Io(format!("{e}")));
            }
        };

        self.channel = Some(channel);
        self.state = ControlConnectionState::ConnectedUnencrypted;

        if let Err(e) = self.perform_control_handshake().await {
            self.fail_session(format!("Falha no handshake de controle: {e}"))
                .await;
            return Err(e);
        }

        self.state = ControlConnectionState::SessionActive;
        self.stats.last_activity = Some(Instant::now());
        info!(server = %addr, "Conexão de controle autenticada e cifrada com sucesso!");

        Ok(())
    }

    async fn perform_control_handshake(&mut self) -> Result<(), ControlSessionError> {
        let channel = self
            .channel
            .as_mut()
            .ok_or(ControlSessionError::NoTransport)?;

        self.state = ControlConnectionState::VersionExchange;
        let version_pkt = ControlClientNegotiator::create_version_packet();
        debug!("Enviando pacote de versão de protocolo ({SHELPER_PROTOCOL_VERSION})...");

        channel
            .send(version_pkt.to_vec())
            .await
            .map_err(|e| ControlSessionError::Io(format!("Envio da versão falhou: {e}")))?;
        self.stats.tx_bytes += 4;
        self.stats.tx_packets += 1;

        let version_frame = tokio::time::timeout(self.timeout, channel.receive())
            .await
            .map_err(|_| ControlSessionError::Timeout)?
            .map_err(|e| ControlSessionError::Io(format!("Recebimento da versão falhou: {e}")))?;
        self.stats.rx_bytes += version_frame.payload.len() as u64;
        self.stats.rx_packets += 1;

        let mut negotiator =
            ControlClientNegotiator::new(self.username.clone(), (*self.password).clone());
        negotiator.process_version_response(&version_frame.payload)?;

        self.state = ControlConnectionState::SrpHandshake;
        let step1_out = negotiator.step(None)?;
        let step1_buf = step1_out
            .buffer_to_send
            .ok_or_else(|| ControlHandshakeError::InvalidState("Step 1 sem buffer".into()))?;

        channel
            .send(step1_buf.clone())
            .await
            .map_err(|e| ControlSessionError::Io(format!("Envio do Step 1 falhou: {e}")))?;
        self.stats.tx_bytes += step1_buf.len() as u64;
        self.stats.tx_packets += 1;

        let step2_frame = tokio::time::timeout(self.timeout, channel.receive())
            .await
            .map_err(|_| ControlSessionError::Timeout)?
            .map_err(|e| ControlSessionError::Io(format!("Recebimento do Step 2 falhou: {e}")))?;
        self.stats.rx_bytes += step2_frame.payload.len() as u64;
        self.stats.rx_packets += 1;

        let step3_out = negotiator.step(Some(&step2_frame.payload))?;
        let step3_buf = step3_out
            .buffer_to_send
            .ok_or_else(|| ControlHandshakeError::InvalidState("Step 3 sem buffer".into()))?;

        channel
            .send(step3_buf.clone())
            .await
            .map_err(|e| ControlSessionError::Io(format!("Envio do Step 3 falhou: {e}")))?;
        self.stats.tx_bytes += step3_buf.len() as u64;
        self.stats.tx_packets += 1;

        let step4_frame = tokio::time::timeout(self.timeout, channel.receive())
            .await
            .map_err(|_| ControlSessionError::Timeout)?
            .map_err(|e| ControlSessionError::Io(format!("Recebimento do Step 4 falhou: {e}")))?;
        self.stats.rx_bytes += step4_frame.payload.len() as u64;
        self.stats.rx_packets += 1;

        let step5_out = negotiator.step(Some(&step4_frame.payload))?;
        let step5_buf = step5_out
            .buffer_to_send
            .ok_or_else(|| ControlHandshakeError::InvalidState("Step 5 sem buffer".into()))?;

        channel
            .send(step5_buf.clone())
            .await
            .map_err(|e| ControlSessionError::Io(format!("Envio do Step 5 falhou: {e}")))?;
        self.stats.tx_bytes += step5_buf.len() as u64;
        self.stats.tx_packets += 1;

        let step6_frame = tokio::time::timeout(self.timeout, channel.receive())
            .await
            .map_err(|_| ControlSessionError::Timeout)?
            .map_err(|e| ControlSessionError::Io(format!("Recebimento do Step 6 falhou: {e}")))?;
        self.stats.rx_bytes += step6_frame.payload.len() as u64;
        self.stats.rx_packets += 1;

        let step6_out = negotiator.step(Some(&step6_frame.payload))?;
        if !step6_out.is_complete || !negotiator.is_established() {
            return Err(ControlSessionError::Handshake(
                ControlHandshakeError::InvalidState("Handshake não estabelecido no Step 6".into()),
            ));
        }

        let cipher_state = negotiator.create_cipher_state()?;
        channel.enable_cipher(cipher_state);

        self.negotiator = Some(negotiator);
        debug!("Cifra de sessão ativada no transporte TCP da conexão de controle");

        Ok(())
    }

    pub async fn send_message(&mut self, payload: &[u8]) -> Result<(), ControlSessionError> {
        if !self.is_active() {
            return Err(ControlSessionError::NotActive {
                state: self.state.clone(),
            });
        }
        let channel = self
            .channel
            .as_mut()
            .ok_or(ControlSessionError::NoTransport)?;

        channel.send_secure(payload).await.map_err(|e| {
            ControlSessionError::Io(format!("Envio de mensagem cifrada falhou: {e}"))
        })?;

        self.stats.tx_bytes += payload.len() as u64;
        self.stats.tx_packets += 1;
        self.stats.last_activity = Some(Instant::now());
        Ok(())
    }

    pub async fn recv_message(&mut self) -> Result<Vec<u8>, ControlSessionError> {
        if !self.is_active() {
            return Err(ControlSessionError::NotActive {
                state: self.state.clone(),
            });
        }
        let channel = self
            .channel
            .as_mut()
            .ok_or(ControlSessionError::NoTransport)?;

        let plaintext = tokio::time::timeout(self.timeout, channel.receive_secure())
            .await
            .map_err(|_| ControlSessionError::Timeout)?
            .map_err(|e| {
                ControlSessionError::Io(format!("Recebimento de mensagem cifrada falhou: {e}"))
            })?;

        self.stats.rx_bytes += plaintext.len() as u64;
        self.stats.rx_packets += 1;
        self.stats.last_activity = Some(Instant::now());
        Ok(plaintext)
    }

    pub async fn close(&mut self) {
        self.password.zeroize();
        if let Some(mut neg) = self.negotiator.take() {
            neg.clear();
        }
        if let Some(mut ch) = self.channel.take() {
            ch.clear_cipher();
            let _ = ch.close().await;
        }
        self.state = ControlConnectionState::Closed;
        info!("Conexão de controle encerrada e material criptográfico destruído.");
    }

    async fn fail_session(&mut self, reason: String) {
        self.password.zeroize();
        if let Some(mut neg) = self.negotiator.take() {
            neg.clear();
        }
        if let Some(mut ch) = self.channel.take() {
            ch.clear_cipher();
            let _ = ch.close().await;
        }
        self.state = ControlConnectionState::Failed(reason);
    }
}

impl Drop for ControlConnection {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(neg) = self.negotiator.as_mut() {
            neg.clear();
        }
        if let Some(ch) = self.channel.as_mut() {
            ch.clear_cipher();
        }
    }
}
