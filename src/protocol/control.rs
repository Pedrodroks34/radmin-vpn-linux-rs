
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
pub const TAG_MEMBER_COUNT: TlvTag = TlvTag(0x010001e3);
pub const TAG_NETWORK_ID: TlvTag = TlvTag(0x020001d5);
pub const TAG_TIMESTAMP: TlvTag = TlvTag(0x020001e1);
pub const TAG_RSA_PUBLIC_KEY: TlvTag = TlvTag(0x090001ca);
pub const TAG_NETWORK_NAME: TlvTag = TlvTag(0x090001dc);
pub const TAG_PASSWORD_HASH: TlvTag = TlvTag(0x090001dd);
pub const TAG_VIRTUAL_IPV6: TlvTag = TlvTag(0x090001e0);
pub const TAG_NODE_ID: TlvTag = TlvTag(0x02000008);

pub fn hash_network_password(password: &str) -> [u8; 20] {
    openssl::sha::sha1(password.as_bytes())
}

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
                msg.add_u32(TAG_VIRTUAL_IPV4, virtual_ip.to_bits());
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
                msg.add_u32(TAG_MEMBER_COUNT, *member_count);
            }
            Self::PeerInfo {
                node_id,
                virtual_ip,
                status,
                last_seen_ms,
            } => {
                msg.add_u64(TAG_NODE_ID, *node_id);
                msg.add_u32(TAG_VIRTUAL_IPV4, virtual_ip.to_bits());
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

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_tlv().to_bytes()
    }

    pub fn from_tlv(msg: &TlvMessage) -> Result<Self> {
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

        if let Some(net_id) = msg.get_u64(TAG_NETWORK_ID) {
            if msg.records.len() == 1 {
                return Ok(Self::LeaveNetwork { network_id: net_id });
            }
        }

        if let (Some(net_id), Some(name_bytes)) = (
            msg.get_u64(TAG_NETWORK_ID),
            msg.get_buffer(TAG_NETWORK_NAME),
        ) {
            let members = msg
                .get_u32(TAG_MEMBER_COUNT)
                .or_else(|| msg.get_u32(TAG_PEER_STATUS))
                .unwrap_or(0);
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
        let hash = hash_network_password("secret123");
        assert_eq!(hash.len(), 20); // SHA-1 / CALG_SHA1 0x8004
        let msg = ControlMessage::JoinNetwork {
            network_name: "RedeAmigos".to_string(),
            password_hash: hash.to_vec(),
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
