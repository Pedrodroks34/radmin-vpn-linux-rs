use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceId(pub String);

#[derive(Debug, Clone)]
pub struct VirtualAddress {
    pub ip: std::net::IpAddr,
    pub subnet_mask: Option<std::net::IpAddr>,
    pub gateway: Option<std::net::IpAddr>,
}

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

pub struct IdentityStore;

impl IdentityStore {
    pub fn load() -> Result<LocalIdentity> {

        Err(anyhow::anyhow!(
            "Identidade não encontrada: registre o dispositivo primeiro (ROLClient_Register)"
        ))
    }

    pub fn save(_identity: &LocalIdentity) -> Result<()> {
        Err(anyhow::anyhow!("Persistência de identidade não implementada"))
    }
}
