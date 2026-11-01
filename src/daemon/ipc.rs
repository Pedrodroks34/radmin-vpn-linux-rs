//! Comunicação Inter-Processos (IPC) entre GUI/CLI e o serviço daemon Radmin VPN.
//!
//! Engenharia reversa dos binários RvRvpnGui.exe (FUN_004e8eb0, FUN_004e2ac0)
//! e RvControlSvc.exe (0x40f040, 0x40f0c4, 0x51a420):
//! - No Windows oficial: Named Pipe `\\.\pipe\RadminVpnGuiChannel`.
//! - No Linux: Unix Domain Socket em `/run/radmin-vpn/gui.sock` (com fallback
//!   para diretório de usuário ou caminho configurado).
//! - Handshake inicial: Estrutura binária de 25 bytes (0x19 bytes):
//!   `[u32 magic=4][u32 flags=1][u32 pid][u32 reserved=0][u32 buf_size=0x80][u32 version=1][u8 status=1]`
//! - Comandos de serviço FamRT/Qt5:
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
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info};

pub const IPC_HANDSHAKE_SIZE: usize = 25;
pub const IPC_DEFAULT_MAGIC: u32 = 0x00000004;
pub const IPC_DEFAULT_FLAGS: u32 = 0x00000001;
pub const IPC_DEFAULT_BUF_SIZE: u32 = 0x00000080;
pub const IPC_DEFAULT_VERSION: u32 = 0x00000001;
pub const IPC_STATUS_READY: u8 = 0x01;

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
    /// `[u16 command_id][u32 payload_len][json/binary payload]`
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
        let _cmd_id =
            IpcCommandId::from_u16(raw_id).ok_or_else(|| IpcError::UnknownCommand(raw_id))?;
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

    /// Inicia o listener removendo sockets órfãos anteriores se existirem.
    pub fn bind(&mut self) -> Result<()> {
        if let Some(parent) = self.socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        self.listener = Some(listener);
        info!("IPC Server ouvindo em {:?}", self.socket_path);
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

    #[tokio::test]
    async fn test_ipc_server_client_handshake_and_exchange() {
        let temp_dir = std::env::temp_dir();
        let sock_path = temp_dir.join(format!("radmin_test_ipc_{}.sock", std::process::id()));

        let mut server = IpcServer::new(&sock_path);
        server.bind().unwrap();

        let srv_sock_path = sock_path.clone();
        let server_task = tokio::spawn(async move {
            let (mut stream, handshake) = server.accept_client().await.unwrap();
            assert_eq!(handshake.magic, IPC_DEFAULT_MAGIC);

            // Ler comando enviado pelo cliente
            let mut cmd_header = [0u8; 6];
            stream.read_exact(&mut cmd_header).await.unwrap();
            let len = u32::from_le_bytes(cmd_header[2..6].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).await.unwrap();

            let mut full_cmd = Vec::new();
            full_cmd.extend_from_slice(&cmd_header);
            full_cmd.extend_from_slice(&payload);
            let cmd = IpcCommand::deserialize(&full_cmd).unwrap();
            assert_eq!(cmd, IpcCommand::QueryStatus);

            // Responder ao cliente
            let resp = IpcResponse::Status {
                connected: true,
                virtual_ip: Some("26.1.2.3".to_string()),
                active_network: Some("RedeEngReversa".to_string()),
                peers_online: 3,
            };
            let resp_bytes = resp.serialize().unwrap();
            stream.write_all(&resp_bytes).await.unwrap();
        });

        let mut client = IpcClient::connect(&srv_sock_path).await.unwrap();
        assert_eq!(client.server_pid(), std::process::id());

        let resp = client.send_command(&IpcCommand::QueryStatus).await.unwrap();
        match resp {
            IpcResponse::Status {
                connected,
                virtual_ip,
                active_network,
                peers_online,
            } => {
                assert!(connected);
                assert_eq!(virtual_ip, Some("26.1.2.3".to_string()));
                assert_eq!(active_network, Some("RedeEngReversa".to_string()));
                assert_eq!(peers_online, 3);
            }
            _ => panic!("Resposta inesperada"),
        }

        server_task.await.unwrap();
        let _ = std::fs::remove_file(&sock_path);
    }
}
