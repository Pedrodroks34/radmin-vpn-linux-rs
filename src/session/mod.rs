use crate::protocol::{AuthSessionId, RosConnectionState, RosNodeAddress};
use crate::Result;

#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: Option<AuthSessionId>,
    pub state: RosConnectionState,
    pub nodes: Vec<RosNodeAddress>,
    pub connected_since: Option<std::time::SystemTime>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            session_id: None,
            state: RosConnectionState::Disconnected,
            nodes: Vec::new(),
            connected_since: None,
        }
    }
}

pub struct SessionManager {
    session: Session,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            session: Session::default(),
        }
    }

    pub fn state(&self) -> RosConnectionState {
        self.session.state
    }

    pub async fn connect(&mut self) -> Result<()> {
        Err(anyhow::anyhow!(
            "Conexão de sessão não implementada (aguardando protocolo ROS)"
        ))
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.session.state = RosConnectionState::Disconnected;
        Ok(())
    }
}
