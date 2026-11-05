pub mod stun;
pub mod teredo;

pub use stun::{
    StunClient, StunError, StunMappedAddress, StunMessage, STUN_BINDING_REQUEST,
    STUN_BINDING_RESPONSE,
};
pub use teredo::{TeredoAddress, TeredoDecapsulated, TeredoPacket, UdpHolePuncher};

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    None,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
}

#[derive(Debug, Clone)]
pub struct NatDetectionResult {
    pub nat_type: NatType,
    pub public_address: Option<SocketAddr>,
    pub local_address: SocketAddr,
}

pub struct NatDetector {
    default_stun_server: Option<SocketAddr>,
}

impl Default for NatDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NatDetector {
    pub fn new() -> Self {
        Self {
            default_stun_server: None,
        }
    }

    pub fn with_stun_server(mut self, server: SocketAddr) -> Self {
        self.default_stun_server = Some(server);
        self
    }

    pub async fn detect(&self) -> crate::Result<NatDetectionResult> {
        let server = self.default_stun_server.ok_or_else(|| {
            anyhow::anyhow!("Servidor STUN não configurado para detecção automática")
        })?;

        self.detect_with_server(server).await
    }

    pub async fn detect_with_server(
        &self,
        stun_server: SocketAddr,
    ) -> crate::Result<NatDetectionResult> {
        let local_port = 0; // Bind efêmero
        let mapped =
            StunClient::query_binding(stun_server, local_port, Duration::from_secs(3)).await?;
        let pub_addr = SocketAddr::V4(std::net::SocketAddrV4::new(mapped.ip, mapped.port));

        let local_addr = SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            local_port,
        ));

        let nat_type = if pub_addr.ip().is_loopback() || pub_addr.ip().is_unspecified() {
            NatType::None
        } else {
            NatType::FullCone
        };

        Ok(NatDetectionResult {
            nat_type,
            public_address: Some(pub_addr),
            local_address: local_addr,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pStrategy {
    UdpDirect,
    UdpNatHolePunch,
    UdpTeredo,
    TcpDirect,
    TcpNat,
    Relay,
}

pub async fn attempt_tcp_simultaneous_open(
    local_port: u16,
    peer_addr: SocketAddr,
    timeout: Duration,
) -> crate::Result<TcpStream> {
    let domain = if peer_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    let bind_addr = SocketAddr::new(
        if peer_addr.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        },
        local_port,
    );

    socket.bind(&bind_addr.into())?;

    let _ = socket.connect(&peer_addr.into());

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;

    tokio::time::timeout(timeout, stream.writable())
        .await
        .map_err(|_| anyhow::anyhow!("Timeout no TCP simultaneous-open com {}", peer_addr))??;

    info!("TCP Simultaneous-Open estabelecido com {}", peer_addr);
    Ok(stream)
}
