
use crate::Result;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

pub const TEREDO_PREFIX: [u8; 4] = [0x20, 0x01, 0x00, 0x00];
pub const IPV6_HEADER_LEN: usize = 40;

#[derive(Debug, Error)]
pub enum TeredoError {
    #[error("tamanho insuficiente para cabeçalho IPv6/Teredo: necessário 40 bytes, recebido {0}")]
    TruncatedHeader(usize),
    #[error("endereço IPv6 não possui prefixo Teredo (2001:0000::/32): {0}")]
    NotTeredoPrefix(Ipv6Addr),
    #[error("erro de E/S no socket UDP Teredo: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout aguardando resposta de hole punching direto")]
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeredoAddress {
    pub server_ipv4: Ipv4Addr,
    pub flags: u16,
    pub mapped_port: u16,
    pub client_ipv4: Ipv4Addr,
}

impl TeredoAddress {
    pub fn new(server_ipv4: Ipv4Addr, flags: u16, mapped_port: u16, client_ipv4: Ipv4Addr) -> Self {
        Self {
            server_ipv4,
            flags,
            mapped_port,
            client_ipv4,
        }
    }

    pub fn to_ipv6(&self) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        octets[0..4].copy_from_slice(&TEREDO_PREFIX);
        octets[4..8].copy_from_slice(&self.server_ipv4.octets());
        octets[8..10].copy_from_slice(&self.flags.to_be_bytes());

        let obfuscated_port = self.mapped_port ^ 0xFFFF;
        octets[10..12].copy_from_slice(&obfuscated_port.to_be_bytes());

        let client_bits = u32::from_ne_bytes(self.client_ipv4.octets()) ^ 0xFFFFFFFF;
        octets[12..16].copy_from_slice(&client_bits.to_ne_bytes());

        Ipv6Addr::from(octets)
    }

    pub fn from_ipv6(addr: &Ipv6Addr) -> std::result::Result<Self, TeredoError> {
        let octets = addr.octets();
        if octets[0..4] != TEREDO_PREFIX {
            return Err(TeredoError::NotTeredoPrefix(*addr));
        }

        let server_ipv4 = Ipv4Addr::new(octets[4], octets[5], octets[6], octets[7]);
        let flags = u16::from_be_bytes([octets[8], octets[9]]);

        let raw_port = u16::from_be_bytes([octets[10], octets[11]]);
        let mapped_port = raw_port ^ 0xFFFF;

        let raw_client = u32::from_ne_bytes([octets[12], octets[13], octets[14], octets[15]]);
        let client_bits = raw_client ^ 0xFFFFFFFF;
        let client_ipv4 = Ipv4Addr::from(client_bits.to_ne_bytes());

        Ok(Self {
            server_ipv4,
            flags,
            mapped_port,
            client_ipv4,
        })
    }

    pub fn client_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(self.client_ipv4), self.mapped_port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeredoDecapsulated {
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
    pub payload: Vec<u8>,
}

pub struct TeredoPacket;

impl TeredoPacket {
    pub fn encapsulate(src: &Ipv6Addr, dst: &Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(IPV6_HEADER_LEN + payload.len());
        buf.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        let len = payload.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.push(next_header);
        buf.push(64); // Hop Limit
        buf.extend_from_slice(&src.octets());
        buf.extend_from_slice(&dst.octets());
        buf.extend_from_slice(payload);
        buf
    }

    pub fn decapsulate(buf: &[u8]) -> std::result::Result<TeredoDecapsulated, TeredoError> {
        if buf.len() < IPV6_HEADER_LEN {
            return Err(TeredoError::TruncatedHeader(buf.len()));
        }

        let version = buf[0] >> 4;
        if version != 6 {
            return Err(TeredoError::TruncatedHeader(0));
        }

        let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let next_header = buf[6];
        let hop_limit = buf[7];

        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&buf[8..24]);
        let src_ip = Ipv6Addr::from(src_bytes);

        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&buf[24..40]);
        let dst_ip = Ipv6Addr::from(dst_bytes);

        let available = buf.len() - IPV6_HEADER_LEN;
        let take_len = payload_len.min(available);
        let payload = buf[IPV6_HEADER_LEN..IPV6_HEADER_LEN + take_len].to_vec();

        Ok(TeredoDecapsulated {
            src_ip,
            dst_ip,
            next_header,
            hop_limit,
            payload,
        })
    }
}

pub struct UdpHolePuncher {
    local_socket: UdpSocket,
}

impl UdpHolePuncher {
    pub async fn bind(local_port: u16) -> Result<Self> {
        Self::bind_addr(SocketAddr::from(([0, 0, 0, 0], local_port))).await
    }

    pub async fn bind_addr(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            local_socket: socket,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local_socket.local_addr()?)
    }

    pub async fn punch_hole(
        &self,
        peer_addr: SocketAddr,
        timeout: Duration,
        max_attempts: usize,
    ) -> Result<bool> {
        info!("Iniciando UDP Hole Punching com {}", peer_addr);
        let probe_magic = b"RADMIN_P2P_PROBE";

        for attempt in 1..=max_attempts {
            debug!(
                "Tentativa {} de envio de sonda UDP para {}",
                attempt, peer_addr
            );
            if let Err(e) = self.local_socket.send_to(probe_magic, peer_addr).await {
                warn!("Falha ao enviar sonda UDP: {}", e);
            }

            let attempt_timeout = timeout / max_attempts as u32;
            let mut buf = [0u8; 64];

            let res =
                tokio::time::timeout(attempt_timeout, self.local_socket.recv_from(&mut buf)).await;
            if let Ok(Ok((n, from_addr))) = res {
                if (from_addr == peer_addr
                    || (from_addr.port() == peer_addr.port()
                        && (from_addr.ip() == peer_addr.ip()
                            || peer_addr.ip().is_unspecified()
                            || from_addr.ip().is_loopback())))
                    && n >= probe_magic.len()
                    && &buf[..probe_magic.len()] == probe_magic
                {
                    info!(
                        "UDP Hole Punching bem-sucedido com {}! Rota direta confirmada.",
                        peer_addr
                    );
                    let _ = self
                        .local_socket
                        .send_to(b"RADMIN_P2P_ACK", from_addr)
                        .await;
                    return Ok(true);
                }
            }
        }

        warn!("UDP Hole Punching com {} esgotou o tempo limite", peer_addr);
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_teredo_address_roundtrip() {
        let server_ip = Ipv4Addr::new(20, 201, 205, 4);
        let client_ip = Ipv4Addr::new(177, 112, 79, 226);
        let port = 58137;
        let flags = 0x04d7;

        let teredo = TeredoAddress::new(server_ip, flags, port, client_ip);
        let ipv6 = teredo.to_ipv6();

        let parsed = TeredoAddress::from_ipv6(&ipv6).unwrap();
        assert_eq!(parsed.server_ipv4, server_ip);
        assert_eq!(parsed.client_ipv4, client_ip);
        assert_eq!(parsed.mapped_port, port);
        assert_eq!(parsed.flags, flags);
    }

    #[test]
    fn test_parse_real_captured_packet_10_teredo_ipv6() {
        let raw_hex =
            "6002e6a9001411802001000014c9cd0404d71ce64e8fb01d2001000014c9cd042c092a0544c438d8";
        let raw = (0..raw_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();

        let decap = TeredoPacket::decapsulate(&raw).unwrap();
        assert_eq!(decap.next_header, 17); // UDP
        assert_eq!(decap.hop_limit, 128); // 0x80

        let src_teredo = TeredoAddress::from_ipv6(&decap.src_ip).unwrap();
        assert_eq!(src_teredo.server_ipv4, Ipv4Addr::new(20, 201, 205, 4));
        assert_eq!(src_teredo.mapped_port, 58137); // Porta real do pacote UDP #10!
    }

    #[test]
    fn test_teredo_encapsulate_and_decapsulate() {
        let src = Ipv6Addr::new(0x2001, 0, 1, 2, 3, 4, 5, 6);
        let dst = Ipv6Addr::new(0x2001, 0, 9, 8, 7, 6, 5, 4);
        let payload = b"HELLO_TEREDO_VPN";

        let frame = TeredoPacket::encapsulate(&src, &dst, 17, payload);
        assert_eq!(frame.len(), IPV6_HEADER_LEN + payload.len());

        let decap = TeredoPacket::decapsulate(&frame).unwrap();
        assert_eq!(decap.src_ip, src);
        assert_eq!(decap.dst_ip, dst);
        assert_eq!(decap.next_header, 17);
        assert_eq!(decap.payload, payload);
    }

    #[tokio::test]
    async fn test_udp_hole_punching_loopback() {
        let puncher1 = UdpHolePuncher::bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let _addr1 = puncher1.local_addr().unwrap();

        let puncher2 = UdpHolePuncher::bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr2 = puncher2.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, from) = puncher2.local_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"RADMIN_P2P_PROBE");
            puncher2
                .local_socket
                .send_to(b"RADMIN_P2P_PROBE", from)
                .await
                .unwrap();
        });

        let success = puncher1
            .punch_hole(addr2, Duration::from_millis(500), 2)
            .await
            .unwrap();

        assert!(success);
        handle.await.unwrap();
    }
}
