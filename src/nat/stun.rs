use openssl::rand::rand_bytes;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StunError {
    #[error("tamanho de cabeçalho STUN inválido (< 20 bytes): {0}")]
    InvalidHeaderSize(usize),
    #[error("tipo de mensagem inesperado: esperado 0x{expected:04x}, recebido 0x{received:04x}")]
    UnexpectedMessageType { expected: u16, received: u16 },
    #[error("id de transação não coincide")]
    TransactionIdMismatch,
    #[error("atributo MAPPED-ADDRESS ausente na resposta STUN")]
    MissingMappedAddress,
    #[error("endereço com família não suportada (esperado IPv4): {0}")]
    UnsupportedAddressFamily(u8),
    #[error("timeout na consulta STUN")]
    Timeout,
    #[error("erro de socket: {0}")]
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMappedAddress {
    pub ip: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct StunMessage {
    pub msg_type: u16,
    pub transaction_id: [u8; 16],
    pub mapped_address: Option<StunMappedAddress>,
}

impl StunMessage {
    pub fn new_binding_request() -> Self {
        let mut tid = [0u8; 16];
        // Coloca o Magic Cookie nos primeiros 4 bytes para compatibilidade RFC 5389 / 3489
        tid[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        let _ = rand_bytes(&mut tid[4..16]);

        Self {
            msg_type: STUN_BINDING_REQUEST,
            transaction_id: tid,
            mapped_address: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);
        buf.extend_from_slice(&self.msg_type.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // Message length = 0 para Request simples
        buf.extend_from_slice(&self.transaction_id);
        buf
    }

    pub fn parse(buf: &[u8]) -> Result<Self, StunError> {
        if buf.len() < 20 {
            return Err(StunError::InvalidHeaderSize(buf.len()));
        }

        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let mut tid = [0u8; 16];
        tid.copy_from_slice(&buf[4..20]);

        let mut mapped_address = None;
        let mut offset = 20;
        let end = (20 + msg_len).min(buf.len());

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > end {
                break;
            }

            let attr_val = &buf[offset..offset + attr_len];
            offset += attr_len;

            // STUN attributes are padded to 4-byte boundaries
            let padding = (4 - (attr_len % 4)) % 4;
            offset += padding;

            if attr_type == ATTR_MAPPED_ADDRESS && attr_val.len() >= 8 {
                let family = attr_val[1];
                if family == 0x01 {
                    let port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
                    let ip = Ipv4Addr::new(attr_val[4], attr_val[5], attr_val[6], attr_val[7]);
                    mapped_address = Some(StunMappedAddress { ip, port });
                }
            } else if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_val.len() >= 8 {
                let family = attr_val[1];
                if family == 0x01 {
                    let xor_port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
                    let port = xor_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

                    let xor_ip_raw =
                        u32::from_be_bytes([attr_val[4], attr_val[5], attr_val[6], attr_val[7]]);
                    let ip_raw = xor_ip_raw ^ STUN_MAGIC_COOKIE;
                    let ip = Ipv4Addr::from(ip_raw);
                    mapped_address = Some(StunMappedAddress { ip, port });
                }
            }
        }

        Ok(Self {
            msg_type,
            transaction_id: tid,
            mapped_address,
        })
    }
}

pub struct StunClient;

impl StunClient {
    pub async fn query_binding(
        server_addr: SocketAddr,
        local_bind_port: u16,
        timeout: Duration,
    ) -> Result<StunMappedAddress, StunError> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", local_bind_port))
            .await
            .map_err(|e| StunError::Io(e.to_string()))?;

        let req = StunMessage::new_binding_request();
        let req_bytes = req.to_bytes();

        socket
            .send_to(&req_bytes, server_addr)
            .await
            .map_err(|e| StunError::Io(e.to_string()))?;

        let mut buf = [0u8; 1024];
        let (n, _from) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| StunError::Timeout)?
            .map_err(|e| StunError::Io(e.to_string()))?;

        let resp = StunMessage::parse(&buf[..n])?;
        if resp.msg_type != STUN_BINDING_RESPONSE {
            return Err(StunError::UnexpectedMessageType {
                expected: STUN_BINDING_RESPONSE,
                received: resp.msg_type,
            });
        }

        if resp.transaction_id != req.transaction_id {
            return Err(StunError::TransactionIdMismatch);
        }

        resp.mapped_address.ok_or(StunError::MissingMappedAddress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_binding_request_serialization() {
        let req = StunMessage::new_binding_request();
        assert_eq!(req.msg_type, STUN_BINDING_REQUEST);
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(&bytes[0..2], &STUN_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&bytes[2..4], &[0x00, 0x00]);
        assert_eq!(&bytes[4..8], &STUN_MAGIC_COOKIE.to_be_bytes());
    }

    #[test]
    fn test_stun_mapped_address_parsing() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes()); // attr length = 12
        let tid = [0x55u8; 16];
        resp.extend_from_slice(&tid);

        // Atributo MAPPED_ADDRESS (0x0001)
        resp.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes()); // len = 8
        resp.extend_from_slice(&[0x00, 0x01]); // 0x01 = IPv4
        resp.extend_from_slice(&12345u16.to_be_bytes()); // Port 12345
        resp.extend_from_slice(&[192, 168, 1, 100]); // IP 192.168.1.100

        let parsed = StunMessage::parse(&resp).unwrap();
        assert_eq!(parsed.msg_type, STUN_BINDING_RESPONSE);
        assert_eq!(parsed.transaction_id, tid);
        let mapped = parsed.mapped_address.unwrap();
        assert_eq!(mapped.port, 12345);
        assert_eq!(mapped.ip, Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_stun_xor_mapped_address_parsing() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        let tid = [0x77u8; 16];
        resp.extend_from_slice(&tid);

        let target_port: u16 = 54321;
        let target_ip = Ipv4Addr::new(203, 0, 113, 195);

        let xor_port = target_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let xor_ip = u32::from(target_ip) ^ STUN_MAGIC_COOKIE;

        // Atributo XOR_MAPPED_ADDRESS (0x0020)
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]); // IPv4
        resp.extend_from_slice(&xor_port.to_be_bytes());
        resp.extend_from_slice(&xor_ip.to_be_bytes());

        let parsed = StunMessage::parse(&resp).unwrap();
        let mapped = parsed.mapped_address.unwrap();
        assert_eq!(mapped.port, target_port);
        assert_eq!(mapped.ip, target_ip);
    }
}
