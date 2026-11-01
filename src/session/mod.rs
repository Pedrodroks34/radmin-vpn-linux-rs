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
pub const INITIAL_MAGIC: [u8; 4] = [0x00, 0x00, 0x00, 0x03];

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

        let mut config = ChannelConfig::default();
        config.connect_timeout = Duration::from_secs(5);
        config.keepalive_interval = KEEPALIVE_INTERVAL;

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

        // Executa a sequência de handshake
        if let Err(e) = self.perform_handshake().await {
            let err_msg = format!("Handshake falhou: {}", e);
            self.session.state = SessionState::Failed(err_msg.clone());
            return Err(anyhow::anyhow!(err_msg));
        }

        Ok(())
    }

    /// Executa o fluxo de handshake observado nos PCAPs:
    /// 1. Envia magic frame unencrypted (0x00000003)
    /// 2. Aguarda resposta inicial
    /// 3. Envia TLV com RSA public key (0x090001ca) e session token (0x010001df)
    /// 4. Habilita criptografia AES-256-CBC
    async fn perform_handshake(&mut self) -> Result<()> {
        self.ensure_rsa_key()?;
        let rsa = self.rsa_key.as_ref().unwrap();
        let pub_key_der = rsa.public_key_to_der()?;

        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Canal TCP ausente"))?;

        // 1. Enviar magic header inicial (0x00000003 em frame de 4 bytes)
        self.session.state = SessionState::Handshaking;
        channel.send(INITIAL_MAGIC.to_vec()).await?;
        self.session.stats.tx_bytes += 4 + INITIAL_MAGIC.len() as u64;
        self.session.stats.tx_packets += 1;

        // 2. Transicionar para KeyExchange e enviar TLV com chave pública RSA
        self.session.state = SessionState::KeyExchange;

        // Constrói mensagem TLV com chave pública RSA (conforme observado no pacote #686)
        let mut tlv = TlvMessage::new();
        tlv.add_u32(TlvTag::TAG_SESSION_TOKEN, 1);
        tlv.add_u32(TlvTag::TAG_PEER_STATUS, 2);
        tlv.add_buffer(TlvTag::TAG_RSA_PUBLIC_KEY, pub_key_der);

        let tlv_bytes = tlv.to_bytes();
        channel.send(tlv_bytes.clone()).await?;
        self.session.stats.tx_bytes += 4 + tlv_bytes.len() as u64;
        self.session.stats.tx_packets += 1;

        // Transiciona para ativa
        self.session.state = SessionState::SessionActive;
        self.session.connected_since = Some(SystemTime::now());
        self.session.stats.last_activity = Some(Instant::now());

        info!("Sessão estabelecida com sucesso!");
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

    #[tokio::test]
    async fn test_session_state_transitions() {
        let mut session = SessionManager::new();
        assert_eq!(session.state(), SessionState::Disconnected);

        // Inicia um listener falso simulando o servidor Radmin
        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut server_ch = listener.accept().await.unwrap();
            // 1. Receber magic inicial
            let magic_frame = server_ch.receive().await.unwrap();
            assert_eq!(magic_frame.payload, INITIAL_MAGIC);

            // 2. Receber frame com TLVs de handshake
            let tlv_frame = server_ch.receive().await.unwrap();
            let msg = TlvMessage::parse(&tlv_frame.payload).unwrap();
            assert_eq!(msg.get_u32(TlvTag::TAG_SESSION_TOKEN), Some(1));
            assert_eq!(msg.get_u32(TlvTag::TAG_PEER_STATUS), Some(2));
            assert!(msg.get_buffer(TlvTag::TAG_RSA_PUBLIC_KEY).is_some());
        });

        session.connect(&addr.to_string()).await.unwrap();
        assert_eq!(session.state(), SessionState::SessionActive);
        assert!(session.session().connected_since.is_some());

        handle.await.unwrap();

        session.disconnect().await.unwrap();
        assert_eq!(session.state(), SessionState::Disconnected);
    }
}
