//! # Módulo `daemon` — Serviço em segundo plano (equivalente a RvControlSvc.exe)
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - `RvControlSvc.exe` é um Windows Service (`StartServiceCtrlDispatcherW`,
//!   `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`).
//! - IPC com GUI via named pipe `\\.\pipe\RadminVpnGuiChannel`.
//! - Instala/remove a si mesmo e o driver (`CreateServiceW`, `DeleteService`,
//!   SetupAPI, `drvinst*`).
//! - Gerencia firewall via WFP (`fwpuclnt!FwpmFilterAdd0`, `FwpmSubLayerAdd0`, etc.).
//! - Manipula rotas via IPHLPAPI.
//! - Escreve/le no device do driver via `DeviceIoControl`.
//!
//! **Mapeamento Linux:**
//! - systemd service unit.
//! - Socket Unix para comunicação com CLI/TUI.
//! - `cap_net_admin` para TUN/TAP e rotas.
//! - nftables/iptables para firewall (equivalente a WFP).

use crate::Result;

/// Estado do daemon
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

/// Daemon principal (placeholder)
pub struct Daemon {
    state: DaemonState,
    config: crate::config::Config,
}

impl Daemon {
    pub fn new(config: crate::config::Config) -> Self {
        Self {
            state: DaemonState::Stopped,
            config,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        self.state = DaemonState::Starting;
        // Placeholder: inicializar túnel, sessão, transporte, etc.
        Err(anyhow::anyhow!(
            "Daemon não implementado: aguardando módulos de protocolo/túnel"
        ))
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.state = DaemonState::Stopped;
        Ok(())
    }

    pub fn state(&self) -> DaemonState {
        self.state
    }
}
