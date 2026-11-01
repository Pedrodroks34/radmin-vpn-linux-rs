//! # Módulo `identity` — Identidade persistente do dispositivo
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - `ROLClient_Register` registra o dispositivo junto ao servidor.
//! - `CAuthSessionId` (RTTI em RvROLClient.dll) é o ID de sessão de autenticação.
//! - `ROLClient_SetVirtualAddresses` define endereços virtuais do dispositivo.
//! - Registro do Windows: `HKLM\SOFTWARE\Famatech\RadminVPN\1.0`.
//!
//! **Desconhecido:**
//! - Formato e tamanho do identificador de dispositivo.
//! - Como a identidade é persistida entre reinstalações.
//! - Se há certificado/par de chaves associado ao dispositivo.

use crate::Result;

/// Identificador persistente do dispositivo no Radmin VPN
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceId(pub String);

/// Endereço virtual atribuído pelo serviço (equivalente a SetVirtualAddresses)
#[derive(Debug, Clone)]
pub struct VirtualAddress {
    pub ip: std::net::IpAddr,
    pub subnet_mask: Option<std::net::IpAddr>,
    pub gateway: Option<std::net::IpAddr>,
}

/// Estado de identidade do dispositivo local
#[derive(Debug, Clone)]
pub struct LocalIdentity {
    pub device_id: Option<DeviceId>,
    pub auth_session: Option<crate::protocol::AuthSessionId>,
    pub virtual_address: Option<VirtualAddress>,
}

impl Default for LocalIdentity {
    fn default() -> Self {
        Self {
            device_id: None,
            auth_session: None,
            virtual_address: None,
        }
    }
}

/// Carrega/salva identidade do dispositivo (placeholder — equivalente ao Registro do Windows)
pub struct IdentityStore;

impl IdentityStore {
    pub fn load() -> Result<LocalIdentity> {
        // Placeholder: ler de arquivo de configuração em ~/.config/radmin-vpn/
        Err(anyhow::anyhow!(
            "Identidade não encontrada: registre o dispositivo primeiro (ROLClient_Register)"
        ))
    }

    pub fn save(_identity: &LocalIdentity) -> Result<()> {
        Err(anyhow::anyhow!("Persistência de identidade não implementada"))
    }
}
