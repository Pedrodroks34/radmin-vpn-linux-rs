use crate::Result;

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
