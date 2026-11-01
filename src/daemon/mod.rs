pub mod ipc;

use crate::Result;
use ipc::IpcServer;
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

pub struct Daemon {
    state: DaemonState,
    config: crate::config::Config,
    ipc_server: Option<IpcServer>,
}

impl Daemon {
    pub fn new(config: crate::config::Config) -> Self {
        Self {
            state: DaemonState::Stopped,
            config,
            ipc_server: None,
        }
    }

    pub fn with_ipc_socket(mut self, path: PathBuf) -> Self {
        self.ipc_server = Some(IpcServer::new(path));
        self
    }

    pub async fn start(&mut self) -> Result<()> {
        self.state = DaemonState::Starting;
        info!("Iniciando daemon do Radmin VPN...");

        // Inicializar socket IPC se configurado
        if let Some(ipc) = self.ipc_server.as_mut() {
            ipc.bind()?;
            info!("Canal IPC pronto para conexões");
        }

        self.state = DaemonState::Running;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.state = DaemonState::Stopping;
        info!("Parando daemon do Radmin VPN...");
        self.ipc_server = None;
        self.state = DaemonState::Stopped;
        Ok(())
    }

    pub fn state(&self) -> DaemonState {
        self.state
    }

    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }
}
