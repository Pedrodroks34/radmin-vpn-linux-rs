//! # Módulo `nat` — Detecção de NAT e traversal (P2P)
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - `RvUESClient.dll` exporta `UESC_GetTcpNatType`, `UESC_GetAddress`,
//!   `UESC_Init`, `UESC_Shutdown` — detecção de tipo de NAT.
//! - Strings de log em `RvUESClient.dll`:
//!   `TcpNatChecker[%1].Bind/Connect/Recv/Send/Delta/InvalidAddress/InvalidResponce`,
//!   `TcpNatChecker[%1].DirectAddress`, `TcpNatChecker[%1].GetTcpNatType`.
//! - `RvROLClient.dll` possui classes `CPenSocket`, `USNatPenPacket`,
//!   `USNatPenWave`, `USPenGroup` — penetração de NAT (hole punching).
//! - Tipos de conexão observados em strings do serviço:
//!   UDP/direct, UDP/nat, UDP/nat/random, UDP/teredo,
//!   TCP/direct, TCP/nat, TCP/teredo, Connections Relay.
//!
//! **Fortemente provável:**
//! - O cliente sonda o tipo de NAT antes de tentar P2P direto.
//! - Se P2P falhar, há fallback para relay ou TCP através de NAT.
//!
//! **Desconhecido:**
//! - Algoritmo exato de detecção de NAT (cone, simétrico, etc.).
//! - Estrutura dos pacotes de penetração (`USNatPenPacket`).
//! - Portas e servidores STUN/TURN/relay utilizados.

/// Tipo de NAT detectado (equivalente ao relatado por UESC_GetTcpNatType)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    None,               // IP público direto
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
}

/// Resultado da detecção de NAT
#[derive(Debug, Clone)]
pub struct NatDetectionResult {
    pub nat_type: NatType,
    pub public_address: Option<std::net::SocketAddr>,
    pub local_address: std::net::SocketAddr,
}

/// Detector de NAT (placeholder — implementar após REA dinâmica)
pub struct NatDetector;

impl NatDetector {
    pub fn new() -> Self {
        Self
    }

    pub async fn detect(&self) -> crate::Result<NatDetectionResult> {
        Err(anyhow::anyhow!(
            "Detecção de NAT não implementada: \
             algoritmo exato não extraído dos binários (RvUESClient.dll)"
        ))
    }
}

/// Estratégia de conexão P2P (inferida das strings do serviço)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pStrategy {
    UdpDirect,
    UdpNatHolePunch,
    UdpTeredo,
    TcpDirect,
    TcpNat,
    Relay,
}
