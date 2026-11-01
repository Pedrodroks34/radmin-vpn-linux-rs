//! Mensagens do protocolo de controle e gerenciamento de redes/peers do Radmin VPN.
//!
//! Engenharia reversa a partir da tabela de descritores de propriedades do
//! RvControlSvc.exe (endereço 0x00498fe0 e função 0x4aec20):
//!
//! Principais tags TLV de controle:
//! - 0x010001d8 (TAG_CLIENT_VERSION): Versão do cliente (uint32)
//! - 0x010001db (TAG_MACHINE_ID): ID único da máquina/instalação (uint32)
//! - 0x010001de (TAG_VIRTUAL_IPV4): Endereço IPv4 virtual atribuído (26.x.x.x, uint32)
//! - 0x010001df (TAG_SESSION_TOKEN): Token identificador da sessão ativa (uint32)
//! - 0x0100032b (TAG_PEER_STATUS): Estado do peer (1=Offline, 2=Online, 3=Connecting)
//! - 0x020001d5 (TAG_NETWORK_ID): Identificador único da rede Radmin (uint64)
//! - 0x020001e1 (TAG_TIMESTAMP): Timestamp em milissegundos UTC (uint64)
//! - 0x090001ca (TAG_RSA_PUBLIC_KEY): Chave pública RSA-2048 (256 bytes)
//! - 0x090001dc (TAG_NETWORK_NAME): Nome da rede virtual (string UTF-8)
//! - 0x090001dd (TAG_PASSWORD_HASH): Hash da senha da rede (32 bytes SHA-256)
//! - 0x090001e0 (TAG_VIRTUAL_IPV6): Endereço IPv6 virtual / Teredo (16 bytes)

use crate::protocol::tlv::{TlvMessage, TlvTag};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use thiserror::Error;

pub const TAG_CLIENT_VERSION: TlvTag = TlvTag(0x010001d8);
pub const TAG_MACHINE_ID: TlvTag = TlvTag(0x010001db);
pub const TAG_VIRTUAL_IPV4: TlvTag = TlvTag(0x010001de);
pub const TAG_SESSION_TOKEN: TlvTag = TlvTag(0x010001df);
pub const TAG_PEER_STATUS: TlvTag = TlvTag(0x0100032b);
pub const TAG_NETWORK_ID: TlvTag = TlvTag(0x020001d5);
pub const TAG_TIMESTAMP: TlvTag = TlvTag(0x020001e1);
pub const TAG_RSA_PUBLIC_KEY: TlvTag = TlvTag(0x090001ca);
pub const TAG_NETWORK_NAME: TlvTag = TlvTag(0x090001dc);
pub const TAG_PASSWORD_HASH: TlvTag = TlvTag(0x090001dd);
pub const TAG_VIRTUAL_IPV6: TlvTag = TlvTag(0x090001e0);
pub const TAG_NODE_ID: TlvTag = TlvTag(0x02000008);

#[derive(Debug, Error)]
pub enum ControlProtocolError {
    #[error("tag obrigatória ausente: 0x{0:08x}")]
    MissingRequiredTag(u32),
    #[error("tipo de dado TLV inválido para tag 0x{tag:08x}: esperado {expected}")]
    InvalidTagType { tag: u32, expected: &'static str },
    #[error("tamanho inválido para endereço IPv4: esperado 4 bytes, encontrado {0}")]
    InvalidIpv4Length(usize),
    #[error("formato UTF-8 inválido para nome da rede: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

/// Estado de conectividade de um peer na rede virtual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum PeerStatus {
    Offline = 1,
    Online = 2,
    Connecting = 3,
    Unknown(u32),
}

impl From<u32> for PeerStatus {
    fn from(val: u32) -> Self {
        match val {
            1 => Self::Offline,
            2 => Self::Online,
            3 => Self::Connecting,
            other => Self::Unknown(other),
        }
    }
}

impl From<PeerStatus> for u32 {
    fn from(status: PeerStatus) -> Self {
        match status {
            PeerStatus::Offline => 1,
            PeerStatus::Online => 2,
            PeerStatus::Connecting => 3,
            PeerStatus::Unknown(v) => v,
        }
    }
}

/// Mensagens de controle de alto nível trocadas com a infraestrutura oficial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    Login {
        client_version: u32,
        machine_id: u32,
        session_token: u32,
    },
    LoginResponse {
        session_token: u32,
        virtual_ip: Ipv4Addr,
        node_id: u64,
    },
    JoinNetwork {
        network_name: String,
        password_hash: Vec<u8>,
    },
    LeaveNetwork {
        network_id: u64,
    },
    NetworkInfo {
        network_id: u64,
        name: String,
        member_count: u32,
    },
    PeerInfo {
        node_id: u64,
        virtual_ip: Ipv4Addr,
        status: PeerStatus,
        last_seen_ms: u64,
    },
    Keepalive {
        session_token: u32,
        timestamp_ms: u64,
    },
}

impl ControlMessage {
    /// Converte a mensagem estruturada em `TlvMessage` com as tags do binário oficial.
    pub fn to_tlv(&self) -> TlvMessage {
        let mut msg = TlvMessage::new();
        match self {
            Self::Login {
                client_version,
                machine_id,
                session_token,
            } => {
                msg.add_u32(TAG_CLIENT_VERSION, *client_version);
                msg.add_u32(TAG_MACHINE_ID, *machine_id);
                msg.add_u32(TAG_SESSION_TOKEN, *session_token);
            }
            Self::LoginResponse {
                session_token,
                virtual_ip,
                node_id,
            } => {
                msg.add_u32(TAG_SESSION_TOKEN, *session_token);
                msg.add_u32(TAG_VIRTUAL_IPV4, u32::from(virtual_ip.to_bits()));
                msg.add_u64(TAG_NODE_ID, *node_id);
            }
            Self::JoinNetwork {
                network_name,
                password_hash,
            } => {
                msg.add_buffer(TAG_NETWORK_NAME, network_name.as_bytes().to_vec());
                msg.add_buffer(TAG_PASSWORD_HASH, password_hash.clone());
            }
            Self::LeaveNetwork { network_id } => {
                msg.add_u64(TAG_NETWORK_ID, *network_id);
            }
            Self::NetworkInfo {
                network_id,
                name,
                member_count,
            } => {
                msg.add_u64(TAG_NETWORK_ID, *network_id);
                msg.add_buffer(TAG_NETWORK_NAME, name.as_bytes().to_vec());
                msg.add_u32(TAG_PEER_STATUS, *member_count);
            }
            Self::PeerInfo {
                node_id,
                virtual_ip,
                status,
                last_seen_ms,
            } => {
                msg.add_u64(TAG_NODE_ID, *node_id);
                msg.add_u32(TAG_VIRTUAL_IPV4, u32::from(virtual_ip.to_bits()));
                msg.add_u32(TAG_PEER_STATUS, (*status).into());
                msg.add_u64(TAG_TIMESTAMP, *last_seen_ms);
            }
            Self::Keepalive {
                session_token,
                timestamp_ms,
            } => {
                msg.add_u32(TAG_SESSION_TOKEN, *session_token);
                msg.add_u64(TAG_TIMESTAMP, *timestamp_ms);
            }
        }
        msg
    }

    /// Serializa diretamente para bytes no framing de controle TLV.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_tlv().to_bytes()
    }

    /// Tenta desserializar uma mensagem a partir de `TlvMessage`.
    pub fn from_tlv(msg: &TlvMessage) -> Result<Self> {
        // 1. Verificar se é Keepalive
        if let (Some(token), Some(ts)) =
            (msg.get_u32(TAG_SESSION_TOKEN), msg.get_u64(TAG_TIMESTAMP))
        {
            if msg.records.len() == 2 {
                return Ok(Self::Keepalive {
                    session_token: token,
                    timestamp_ms: ts,
                });
            }
        }

        // 2. Verificar se é Login
        if let (Some(ver), Some(mach), Some(token)) = (
            msg.get_u32(TAG_CLIENT_VERSION),
            msg.get_u32(TAG_MACHINE_ID),
            msg.get_u32(TAG_SESSION_TOKEN),
        ) {
            return Ok(Self::Login {
                client_version: ver,
                machine_id: mach,
                session_token: token,
            });
        }

        // 3. Verificar se é LoginResponse
        if let (Some(token), Some(ip_bits), Some(node_id)) = (
            msg.get_u32(TAG_SESSION_TOKEN),
            msg.get_u32(TAG_VIRTUAL_IPV4),
            msg.get_u64(TAG_NODE_ID),
        ) {
            return Ok(Self::LoginResponse {
                session_token: token,
                virtual_ip: Ipv4Addr::from_bits(ip_bits),
                node_id,
            });
        }

        // 4. Verificar se é PeerInfo
        if let (Some(node_id), Some(ip_bits), Some(st), Some(ts)) = (
            msg.get_u64(TAG_NODE_ID),
            msg.get_u32(TAG_VIRTUAL_IPV4),
            msg.get_u32(TAG_PEER_STATUS),
            msg.get_u64(TAG_TIMESTAMP),
        ) {
            return Ok(Self::PeerInfo {
                node_id,
                virtual_ip: Ipv4Addr::from_bits(ip_bits),
                status: PeerStatus::from(st),
                last_seen_ms: ts,
            });
        }

        // 5. Verificar se é JoinNetwork
        if let (Some(name_bytes), Some(pwd)) = (
            msg.get_buffer(TAG_NETWORK_NAME),
            msg.get_buffer(TAG_PASSWORD_HASH),
        ) {
            let network_name = String::from_utf8(name_bytes.to_vec())?;
            return Ok(Self::JoinNetwork {
                network_name,
                password_hash: pwd.to_vec(),
            });
        }

        // 6. Verificar se é LeaveNetwork
        if let Some(net_id) = msg.get_u64(TAG_NETWORK_ID) {
            if msg.records.len() == 1 {
                return Ok(Self::LeaveNetwork { network_id: net_id });
            }
        }

        // 7. Verificar se é NetworkInfo
        if let (Some(net_id), Some(name_bytes), Some(members)) = (
            msg.get_u64(TAG_NETWORK_ID),
            msg.get_buffer(TAG_NETWORK_NAME),
            msg.get_u32(TAG_PEER_STATUS),
        ) {
            let name = String::from_utf8(name_bytes.to_vec())?;
            return Ok(Self::NetworkInfo {
                network_id: net_id,
                name,
                member_count: members,
            });
        }

        Err(anyhow::anyhow!(
            "Mensagem TLV não corresponde a nenhum padrão de controle conhecido"
        ))
    }

    /// Desserializa a partir dos bytes de payload bruto.
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let tlv = TlvMessage::parse(payload)?;
        Self::from_tlv(&tlv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_message_roundtrip() {
        let msg = ControlMessage::Login {
            client_version: 0x02010495, // 2.1.4951
            machine_id: 0x00aabbcc,
            session_token: 1,
        };

        let bytes = msg.to_bytes();
        let parsed = ControlMessage::parse(&bytes).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_login_response_roundtrip() {
        let msg = ControlMessage::LoginResponse {
            session_token: 42,
            virtual_ip: Ipv4Addr::new(26, 12, 34, 56),
            node_id: 0x0102030405060708,
        };

        let bytes = msg.to_bytes();
        let parsed = ControlMessage::parse(&bytes).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_join_network_roundtrip() {
        let msg = ControlMessage::JoinNetwork {
            network_name: "RedeAmigos".to_string(),
            password_hash: vec![0xaa; 32],
        };

        let bytes = msg.to_bytes();
        let parsed = ControlMessage::parse(&bytes).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_peer_info_roundtrip() {
        let msg = ControlMessage::PeerInfo {
            node_id: 0xdeadbeefcafebabe,
            virtual_ip: Ipv4Addr::new(26, 100, 200, 1),
            status: PeerStatus::Online,
            last_seen_ms: 1700000000000,
        };

        let bytes = msg.to_bytes();
        let parsed = ControlMessage::parse(&bytes).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_keepalive_roundtrip() {
        let msg = ControlMessage::Keepalive {
            session_token: 99,
            timestamp_ms: 1730480000000,
        };

        let bytes = msg.to_bytes();
        let parsed = ControlMessage::parse(&bytes).unwrap();
        assert_eq!(msg, parsed);
    }
}
