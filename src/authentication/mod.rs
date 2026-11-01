//! # Módulo `authentication` — Autenticação e handshake
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - `ROLClient_Register` é o ponto de entrada de registro/autenticação.
//! - `CAuthSessionId` identifica a sessão autenticada.
//! - `ROLClient_ReportLanguage`, `ROLClient_ReportRServerInfo` são reportes pós-autenticação.
//! - `imrsdk.dll` contém código de autenticação legado (SASL/SPNEGO via DsMakeSpnA,
//!   AcquireCredentialsHandle, InitializeSecurityContext) — herdado do Radmin Server 3.
//!
//! **Desconhecido:**
//! - Algoritmo de handshake (challenge-response, certificado, token, etc.).
//! - Formato das credenciais.
//! - Validação de membros e autorização de entrada em redes.
//! - Se há autenticação de dois fatores ou conta de usuário.
//
//! ## Aviso
//!
//! Não implementar fluxo de autenticação sem evidência de captura de tráfego
//! ou decompilação de `RvROLClient.dll` / `imrsdk.dll`.

use crate::Result;

/// Credenciais de autenticação (estrutura placeholder)
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: Option<String>,
    pub password_hash: Option<Vec<u8>>,
    pub device_token: Option<String>,
}

/// Resultado de autenticação
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub session_id: crate::protocol::AuthSessionId,
    pub token: Option<String>,
    pub expires_at: Option<std::time::SystemTime>,
}

/// Autenticador (placeholder)
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
