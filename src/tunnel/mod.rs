//! # Módulo `tunnel` — Interface virtual TUN/TAP no Linux
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - `NetMP60.sys` é um driver NDIS miniport virtual que simula uma placa Ethernet.
//! - Device: `\Device\RVPNNETMP` / `\DosDevices\RVPNNETMP`.
//! - `.inf` declara `NCF_VIRTUAL`, `IF_TYPE_ETHERNET_CSMACD`, `NdisMedium802_3`.
//! - `NetVRadminMacAddress` — MAC atribuído ao adaptador virtual.
//! - O Windows vê uma "LAN virtual" (camada 2).
//!
//! **Inferência para Linux:**
//! - Como o driver original é L2 (Ethernet), o ideal seria TAP. Porém,
//!   TUN (L3) é mais simples e portável no Linux, aceitando tráfego IP sobre
//!   o túnel virtual.
//! - `DeviceIoControl` do serviço escreve/le frames no device do driver.
//!   No Linux, isso corresponde a leitura/escrita em `/dev/net/tun`.
//
//! **Desconhecido:**
//! - Se o encapsulamento é Ethernet puro ou IP direto dentro do driver.
//! - MTU da interface virtual.
//! - Faixa de IP atribuída (não encontrada nos binários; não há strings 26.x.x.x).

use crate::Result;
use serde::{Deserialize, Serialize};

/// Tipo de interface virtual
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelType {
    /// Camada 3 (IP) — mais simples no Linux
    Tun,
    /// Camada 2 (Ethernet) — espelha o driver NetMP60.sys
    Tap,
}

/// Configuração da interface virtual
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub tunnel_type: TunnelType,
    pub interface_name: String,
    pub mtu: u16,
    pub local_ip: Option<String>, // a confirmar via REA dinâmica
    pub remote_ip: Option<String>, // a confirmar via REA dinâmica
    pub subnet: Option<String>, // CIDR, ex: "26.0.0.0/8" (a confirmar via REA dinâmica)
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            tunnel_type: TunnelType::Tun,
            interface_name: "radmin0".to_string(),
            mtu: 1500,
            local_ip: None,
            remote_ip: None,
            subnet: None,
        }
    }
}

/// Interface virtual aberta (placeholder — usar crate `tun` após definir config)
pub struct Tunnel {
    config: TunnelConfig,
    #[allow(dead_code)]
    device: Option<std::fs::File>,
}

impl Tunnel {
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            device: None,
        }
    }

    pub async fn open(&mut self) -> Result<()> {
        Err(anyhow::anyhow!(
            "Interface TUN/TAP não aberta: implementar com crate `tun` \
             (requer cap_net_admin)"
        ))
    }

    pub async fn read_frame(&self) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("Leitura de frame não implementada"))
    }

    pub async fn write_frame(&self, _frame: &[u8]) -> Result<()> {
        Err(anyhow::anyhow!("Escrita de frame não implementada"))
    }
}
