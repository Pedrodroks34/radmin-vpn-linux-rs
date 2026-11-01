use crate::Result;

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: Option<String>,
    pub password_hash: Option<Vec<u8>>,
    pub device_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub session_id: crate::protocol::AuthSessionId,
    pub token: Option<String>,
    pub expires_at: Option<std::time::SystemTime>,
}

pub struct Authenticator;

impl Authenticator {
    pub fn new() -> Self {
        Self
    }

    pub async fn register(&self, _creds: &Credentials) -> Result<AuthenticationResult> {
        Err(anyhow::anyhow!(
            "Fluxo de autenticação não implementado: \
             handshake do ROL não extraído dos binários (requer REA dinâmica)"
        ))
    }

    pub async fn authenticate(&self, _creds: &Credentials) -> Result<AuthenticationResult> {
        Err(anyhow::anyhow!(
            "Autenticação não implementada (aguardando evidência de protocolo)"
        ))
    }
}
