//! Comunicação Inter-Processos (IPC) entre GUI/CLI e o serviço daemon Radmin VPN.
//!
//! Protocolo IPC no Linux:
//! - Unix Domain Socket com permissões restritas (0600 para o socket, 0700 para o diretório).
//! - Caminho padrão: `/run/radmin-vpn/gui.sock` (com fallback para `~/.config/radmin-vpn/gui.sock` ou temporário).
//! - Handshake inicial: Estrutura binária de 25 bytes (`0x19` bytes):
//!   `[u32 magic=4][u32 flags=1][u32 pid][u32 reserved=0][u32 buf_size=0x80][u32 version=1][u8 status=1]`
//! - Despacho de Comandos:
//!   - 0x03ec (1004): SwitchPower (conectar/ligar túnel)
//!   - 0x03ed (1005): JoinNetwork (entrar em rede)
//!   - 0x03ee (1006): CreateNetwork (criar nova rede)
//!   - 0x03ef (1007): Disconnect (desconectar/desligar túnel)
//!   - 0x03f0 (1008): LeaveNetwork (sair de rede)
//!   - 0x03f1 (1009): EnumNetworks (listar redes)
//!   - 0x03f2 (1010): GetNodeInfo (consultar informações do nó)
//!   - 0x03f6 (1014): QueryStatus / Handshake check

use crate::Result;
use bytes::BufMut;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

pub const IPC_HANDSHAKE_SIZE: usize = 25;
pub const IPC_DEFAULT_MAGIC: u32 = 0x00000004;
pub const IPC_DEFAULT_FLAGS: u32 = 0x00000001;
pub const IPC_DEFAULT_BUF_SIZE: u32 = 0x00000080;
pub const IPC_DEFAULT_VERSION: u32 = 0x00000001;
pub const IPC_STATUS_READY: u8 = 0x01;

/// Resolve o caminho padrão do socket IPC, verificando /run e /tmp com base no usuário e existência.
pub fn resolve_socket_path() -> PathBuf {
    let system_path = PathBuf::from(crate::GUI_CHANNEL_PATH);
    if system_path.exists() {
        return system_path;
    }
    let uid = unsafe { libc::getuid() };
    let user_path = PathBuf::from(format!("/tmp/radmin-vpn-{}/gui.sock", uid));
    if user_path.exists() {
        return user_path;
    }
    if unsafe { libc::geteuid() } == 0 {
        system_path
    } else {
        user_path
    }
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("tamanho insuficiente para handshake IPC: esperado 25 bytes, recebido {0}")]
    HandshakeTruncated(usize),
    #[error("magic IPC inválido: esperado 0x{expected:08x}, recebido 0x{actual:08x}")]
    InvalidMagic { expected: u32, actual: u32 },
    #[error("código de comando IPC desconhecido: 0x{0:04x}")]
    UnknownCommand(u16),
    #[error("erro de E/S no socket IPC: {0}")]
    Io(#[from] std::io::Error),
    #[error("desconexão prematura do cliente/servidor IPC")]
    Disconnected,
    #[error("falha na serialização/deserialização: {0}")]
    Serialization(String),
}

/// Cabeçalho de handshake inicial de 25 bytes enviado ao conectar no socket/pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcHandshake {
    pub magic: u32,
    pub flags: u32,
    pub client_pid: u32,
    pub reserved: u32,
    pub buf_size: u32,
    pub version: u32,
    pub status: u8,
}

impl Default for IpcHandshake {
    fn default() -> Self {
        Self {
            magic: IPC_DEFAULT_MAGIC,
            flags: IPC_DEFAULT_FLAGS,
            client_pid: std::process::id(),
            reserved: 0,
            buf_size: IPC_DEFAULT_BUF_SIZE,
            version: IPC_DEFAULT_VERSION,
            status: IPC_STATUS_READY,
        }
    }
}

impl IpcHandshake {
    pub fn new(pid: u32) -> Self {
        Self {
            client_pid: pid,
            ..Default::default()
        }
    }

    pub fn to_bytes(&self) -> [u8; IPC_HANDSHAKE_SIZE] {
        let mut buf = [0u8; IPC_HANDSHAKE_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..12].copy_from_slice(&self.client_pid.to_le_bytes());
        buf[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        buf[16..20].copy_from_slice(&self.buf_size.to_le_bytes());
        buf[20..24].copy_from_slice(&self.version.to_le_bytes());
        buf[24] = self.status;
        buf
    }

    pub fn parse(buf: &[u8]) -> std::result::Result<Self, IpcError> {
        if buf.len() < IPC_HANDSHAKE_SIZE {
            return Err(IpcError::HandshakeTruncated(buf.len()));
        }

        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if magic != IPC_DEFAULT_MAGIC {
            return Err(IpcError::InvalidMagic {
                expected: IPC_DEFAULT_MAGIC,
                actual: magic,
            });
        }

        let flags = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let client_pid = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let reserved = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let buf_size = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let version = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let status = buf[24];

        Ok(Self {
            magic,
            flags,
            client_pid,
            reserved,
            buf_size,
            version,
            status,
        })
    }
}

/// Identificadores numéricos dos comandos IPC do Radmin VPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum IpcCommandId {
    SwitchPower = 0x03ec,   // 1004
    JoinNetwork = 0x03ed,   // 1005
    CreateNetwork = 0x03ee, // 1006
    Disconnect = 0x03ef,    // 1007
    LeaveNetwork = 0x03f0,  // 1008
    EnumNetworks = 0x03f1,  // 1009
    GetNodeInfo = 0x03f2,   // 1010
    QueryStatus = 0x03f6,   // 1014
}

impl IpcCommandId {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x03ec => Some(Self::SwitchPower),
            0x03ed => Some(Self::JoinNetwork),
            0x03ee => Some(Self::CreateNetwork),
            0x03ef => Some(Self::Disconnect),
            0x03f0 => Some(Self::LeaveNetwork),
            0x03f1 => Some(Self::EnumNetworks),
            0x03f2 => Some(Self::GetNodeInfo),
            0x03f6 => Some(Self::QueryStatus),
            _ => None,
        }
    }
}

/// Comandos de alto nível transmitidos via IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcCommand {
    SwitchPower {
        enable: bool,
    },
    JoinNetwork {
        network_name: String,
        password: String,
    },
    CreateNetwork {
        network_name: String,
        password: String,
    },
    Disconnect,
    LeaveNetwork {
        network_id: u64,
    },
    EnumNetworks,
    GetNodeInfo {
        node_id: u64,
    },
    QueryStatus,
}

impl IpcCommand {
    pub fn command_id(&self) -> IpcCommandId {
        match self {
            Self::SwitchPower { .. } => IpcCommandId::SwitchPower,
            Self::JoinNetwork { .. } => IpcCommandId::JoinNetwork,
            Self::CreateNetwork { .. } => IpcCommandId::CreateNetwork,
            Self::Disconnect => IpcCommandId::Disconnect,
            Self::LeaveNetwork { .. } => IpcCommandId::LeaveNetwork,
            Self::EnumNetworks => IpcCommandId::EnumNetworks,
            Self::GetNodeInfo { .. } => IpcCommandId::GetNodeInfo,
            Self::QueryStatus => IpcCommandId::QueryStatus,
        }
    }

    /// Serializa o comando em framing binário:
    /// `[u16 command_id][u32 payload_len][json payload]`
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let payload = serde_json::to_vec(self)?;
        let mut buf = Vec::with_capacity(6 + payload.len());
        buf.put_u16_le(self.command_id() as u16);
        buf.put_u32_le(payload.len() as u32);
        buf.extend_from_slice(&payload);
        Ok(buf)
    }

    /// Desserializa o comando a partir do buffer estruturado.
    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < 6 {
            return Err(anyhow::anyhow!("Buffer IPC truncado (< 6 bytes)"));
        }
        let raw_id = u16::from_le_bytes(buf[0..2].try_into().unwrap());
        let _cmd_id = IpcCommandId::from_u16(raw_id).ok_or(IpcError::UnknownCommand(raw_id))?;
        let len = u32::from_le_bytes(buf[2..6].try_into().unwrap()) as usize;
        if buf.len() < 6 + len {
            return Err(anyhow::anyhow!(
                "Payload de comando IPC truncado: esperado {}, disponível {}",
                len,
                buf.len() - 6
            ));
        }
        let cmd = serde_json::from_slice(&buf[6..6 + len])?;
        Ok(cmd)
    }
}

/// Resposta do serviço para o cliente IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcResponse {
    Success {
        message: String,
    },
    Error {
        code: u32,
        message: String,
    },
    Status {
        connected: bool,
        virtual_ip: Option<String>,
        active_network: Option<String>,
        peers_online: usize,
    },
    NetworkList {
        networks: Vec<String>,
    },
    NodeInfo {
        node_id: u64,
        virtual_ip: Option<String>,
        online: bool,
    },
}

impl IpcResponse {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let payload = serde_json::to_vec(self)?;
        let mut buf = Vec::with_capacity(4 + payload.len());
        buf.put_u32_le(payload.len() as u32);
        buf.extend_from_slice(&payload);
        Ok(buf)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(anyhow::anyhow!(
                "Buffer de resposta IPC truncado (< 4 bytes)"
            ));
        }
        let len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        if buf.len() < 4 + len {
            return Err(anyhow::anyhow!(
                "Payload de resposta IPC truncado: esperado {}, disponível {}",
                len,
                buf.len() - 4
            ));
        }
        let resp = serde_json::from_slice(&buf[4..4 + len])?;
        Ok(resp)
    }
}

/// Handler abstrato para processar comandos do daemon.
pub trait IpcHandler: Send + Sync + 'static {
    fn handle(
        &self,
        cmd: IpcCommand,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IpcResponse> + Send + '_>>;
}

/// Servidor IPC que escuta requisições de controle da GUI ou CLI via Unix Domain Socket.
pub struct IpcServer {
    socket_path: PathBuf,
    listener: Option<UnixListener>,
}

impl IpcServer {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            listener: None,
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Inicia o listener garantindo permissões seguras (0700 dir, 0600 socket)
    /// e removendo sockets órfãos anteriores se existirem.
    pub fn bind(&mut self) -> Result<()> {
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
            // Permissão restrita no diretório pai: 0700
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        // Permissão restrita no arquivo do socket: 0600
        let _ = std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600));

        self.listener = Some(listener);
        info!("IPC Server ouvindo com segurança em {:?}", self.socket_path);
        Ok(())
    }

    /// Aceita uma conexão e valida o handshake inicial de 25 bytes.
    pub async fn accept_client(&self) -> Result<(UnixStream, IpcHandshake)> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Listener IPC não inicializado"))?;

        let (mut stream, _addr) = listener.accept().await?;

        // 1. Receber handshake do cliente (25 bytes)
        let mut handshake_buf = [0u8; IPC_HANDSHAKE_SIZE];
        stream.read_exact(&mut handshake_buf).await?;
        let client_handshake = IpcHandshake::parse(&handshake_buf)?;
        debug!(
            "Cliente IPC conectado (PID: {})",
            client_handshake.client_pid
        );

        // 2. Responder com handshake do servidor
        let server_handshake = IpcHandshake::new(std::process::id());
        stream.write_all(&server_handshake.to_bytes()).await?;

        Ok((stream, client_handshake))
    }

    /// Executa o loop assíncrono do servidor atendendo múltiplos clientes concorrentes
    /// com despacho real de comandos e encerramento gracioso via shutdown channel.
    pub async fn run_loop<H: IpcHandler>(
        mut self,
        handler: Arc<H>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        self.bind()?;
        let listener = self.listener.take().unwrap();

        info!("Loop de processamento IPC iniciado");

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((mut stream, _addr)) => {
                            let handler_clone = handler.clone();
                            tokio::spawn(async move {
                                // 1. Handshake do cliente
                                let mut handshake_buf = [0u8; IPC_HANDSHAKE_SIZE];
                                if let Err(e) = stream.read_exact(&mut handshake_buf).await {
                                    warn!("Falha ao ler handshake IPC do cliente: {}", e);
                                    return;
                                }
                                if let Err(e) = IpcHandshake::parse(&handshake_buf) {
                                    warn!("Handshake IPC inválido do cliente: {}", e);
                                    return;
                                }
                                // Responde com handshake do servidor
                                let server_hs = IpcHandshake::new(std::process::id());
                                if let Err(e) = stream.write_all(&server_hs.to_bytes()).await {
                                    warn!("Falha ao responder handshake IPC: {}", e);
                                    return;
                                }

                                // 2. Loop de leitura de comandos deste cliente
                                loop {
                                    let mut cmd_header = [0u8; 6];
                                    match stream.read_exact(&mut cmd_header).await {
                                        Ok(_) => {},
                                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                            debug!("Cliente IPC desconectou");
                                            break;
                                        }
                                        Err(e) => {
                                            debug!("Erro de leitura IPC do cliente: {}", e);
                                            break;
                                        }
                                    }

                                    let payload_len = u32::from_le_bytes(cmd_header[2..6].try_into().unwrap()) as usize;
                                    let mut payload = vec![0u8; payload_len];
                                    if let Err(e) = stream.read_exact(&mut payload).await {
                                        warn!("Falha ao ler payload do comando IPC: {}", e);
                                        break;
                                    }

                                    let mut full_cmd = Vec::with_capacity(6 + payload_len);
                                    full_cmd.extend_from_slice(&cmd_header);
                                    full_cmd.extend_from_slice(&payload);

                                    let cmd = match IpcCommand::deserialize(&full_cmd) {
                                        Ok(c) => c,
                                        Err(e) => {
                                            warn!("Comando IPC malformado: {}", e);
                                            let err_resp = IpcResponse::Error {
                                                code: 400,
                                                message: format!("Comando inválido: {}", e),
                                            };
                                            if let Ok(b) = err_resp.serialize() {
                                                let _ = stream.write_all(&b).await;
                                            }
                                            continue;
                                        }
                                    };

                                    let resp = handler_clone.handle(cmd).await;
                                    match resp.serialize() {
                                        Ok(resp_bytes) => {
                                            if let Err(e) = stream.write_all(&resp_bytes).await {
                                                warn!("Falha ao enviar resposta IPC: {}", e);
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!("Falha ao serializar resposta IPC: {}", e);
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Erro ao aceitar conexão IPC: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Sinal de encerramento IPC recebido. Finalizando servidor...");
                    break;
                }
            }
        }

        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
        Ok(())
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// Cliente IPC para comunicação com o daemon em execução.
pub struct IpcClient {
    stream: UnixStream,
    server_handshake: IpcHandshake,
}

impl IpcClient {
    pub async fn connect<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
        let mut stream = UnixStream::connect(socket_path).await?;

        // 1. Enviar handshake do cliente (25 bytes)
        let my_handshake = IpcHandshake::new(std::process::id());
        stream.write_all(&my_handshake.to_bytes()).await?;

        // 2. Receber handshake de confirmação do servidor (25 bytes)
        let mut server_buf = [0u8; IPC_HANDSHAKE_SIZE];
        stream.read_exact(&mut server_buf).await?;
        let server_handshake = IpcHandshake::parse(&server_buf)?;

        Ok(Self {
            stream,
            server_handshake,
        })
    }

    pub fn server_pid(&self) -> u32 {
        self.server_handshake.client_pid
    }

    pub async fn send_command(&mut self, cmd: &IpcCommand) -> Result<IpcResponse> {
        let bytes = cmd.serialize()?;
        self.stream.write_all(&bytes).await?;

        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let payload_len = u32::from_le_bytes(len_buf) as usize;

        let mut payload = vec![0u8; payload_len];
        self.stream.read_exact(&mut payload).await?;

        let mut complete_buf = Vec::with_capacity(4 + payload_len);
        complete_buf.extend_from_slice(&len_buf);
        complete_buf.extend_from_slice(&payload);

        IpcResponse::deserialize(&complete_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_handshake_serialization_roundtrip() {
        let handshake = IpcHandshake::new(12345);
        let bytes = handshake.to_bytes();
        assert_eq!(bytes.len(), IPC_HANDSHAKE_SIZE);

        let parsed = IpcHandshake::parse(&bytes).unwrap();
        assert_eq!(parsed.magic, IPC_DEFAULT_MAGIC);
        assert_eq!(parsed.flags, IPC_DEFAULT_FLAGS);
        assert_eq!(parsed.client_pid, 12345);
        assert_eq!(parsed.buf_size, IPC_DEFAULT_BUF_SIZE);
        assert_eq!(parsed.version, IPC_DEFAULT_VERSION);
        assert_eq!(parsed.status, IPC_STATUS_READY);
    }

    #[test]
    fn test_ipc_handshake_invalid_magic_rejected() {
        let mut bytes = IpcHandshake::new(100).to_bytes();
        bytes[0] = 0xff; // Corrompe o magic
        let err = IpcHandshake::parse(&bytes).unwrap_err();
        match err {
            IpcError::InvalidMagic { expected, actual } => {
                assert_eq!(expected, IPC_DEFAULT_MAGIC);
                assert_eq!(actual, 0x000000ff);
            }
            _ => panic!("Esperado InvalidMagic"),
        }
    }

    #[test]
    fn test_ipc_command_serialization_roundtrip() {
        let cmd = IpcCommand::JoinNetwork {
            network_name: "MinhaRede".to_string(),
            password: "segredo123".to_string(),
        };
        let bytes = cmd.serialize().unwrap();
        let parsed = IpcCommand::deserialize(&bytes).unwrap();
        assert_eq!(cmd, parsed);

        let cmd2 = IpcCommand::SwitchPower { enable: true };
        let bytes2 = cmd2.serialize().unwrap();
        let parsed2 = IpcCommand::deserialize(&bytes2).unwrap();
        assert_eq!(cmd2, parsed2);
    }

    #[test]
    fn test_ipc_response_serialization_roundtrip() {
        let resp = IpcResponse::Status {
            connected: true,
            virtual_ip: Some("26.12.34.56".to_string()),
            active_network: Some("TestNet".to_string()),
            peers_online: 5,
        };
        let bytes = resp.serialize().unwrap();
        let parsed = IpcResponse::deserialize(&bytes).unwrap();
        assert_eq!(resp, parsed);
    }

    struct MockHandler;
    impl IpcHandler for MockHandler {
        fn handle(
            &self,
            cmd: IpcCommand,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IpcResponse> + Send + '_>> {
            Box::pin(async move {
                match cmd {
                    IpcCommand::QueryStatus => IpcResponse::Status {
                        connected: true,
                        virtual_ip: Some("26.1.2.3".to_string()),
                        active_network: Some("RedeMock".to_string()),
                        peers_online: 2,
                    },
                    IpcCommand::JoinNetwork { network_name, .. } => IpcResponse::Success {
                        message: format!("Conectado a {}", network_name),
                    },
                    IpcCommand::EnumNetworks => IpcResponse::NetworkList {
                        networks: vec!["RedeMock".to_string()],
                    },
                    IpcCommand::GetNodeInfo { node_id } => IpcResponse::NodeInfo {
                        node_id,
                        virtual_ip: Some("26.1.2.99".to_string()),
                        online: true,
                    },
                    _ => IpcResponse::Success {
                        message: "OK".to_string(),
                    },
                }
            })
        }
    }

    #[tokio::test]
    async fn test_ipc_server_client_full_lifecycle_and_multiclient() {
        let temp_dir = std::env::temp_dir();
        let sock_path = temp_dir.join(format!("radmin_test_ipc_mc_{}.sock", std::process::id()));

        let server = IpcServer::new(&sock_path);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let srv_sock_path = sock_path.clone();
        let handler = Arc::new(MockHandler);

        let server_handle = tokio::spawn(async move {
            server.run_loop(handler, shutdown_rx).await.unwrap();
        });

        // Aguarda inicialização do socket
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cliente 1
        let mut client1 = IpcClient::connect(&srv_sock_path).await.unwrap();
        assert_eq!(client1.server_pid(), std::process::id());

        let resp1 = client1
            .send_command(&IpcCommand::QueryStatus)
            .await
            .unwrap();
        match resp1 {
            IpcResponse::Status {
                connected,
                virtual_ip,
                ..
            } => {
                assert!(connected);
                assert_eq!(virtual_ip, Some("26.1.2.3".to_string()));
            }
            _ => panic!("Resposta inesperada"),
        }

        // Cliente 2 concorrente
        let mut client2 = IpcClient::connect(&srv_sock_path).await.unwrap();
        let resp2 = client2
            .send_command(&IpcCommand::JoinNetwork {
                network_name: "RedeNova".to_string(),
                password: "123".to_string(),
            })
            .await
            .unwrap();

        match resp2 {
            IpcResponse::Success { message } => assert_eq!(message, "Conectado a RedeNova"),
            _ => panic!("Resposta inesperada"),
        }

        // Encerramento gracioso
        shutdown_tx.send(()).unwrap();
        server_handle.await.unwrap();

        assert!(!sock_path.exists());
    }
}
