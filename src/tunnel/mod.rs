use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelType {

    Tun,

    Tap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub tunnel_type: TunnelType,
    pub interface_name: String,
    pub mtu: u16,
    pub local_ip: Option<String>,
    pub remote_ip: Option<String>,
    pub subnet: Option<String>,
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
