use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoChannelConfig {
    pub enabled: bool,
    pub compression: bool,

}

pub struct CryptoChannel {
    config: CryptoChannelConfig,
}

impl CryptoChannel {
    pub fn new(config: CryptoChannelConfig) -> Self {
        Self { config }
    }

    pub async fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "Criptografia de canal não implementada: \
             algoritmo não extraído dos binários (CCryptoChannel)"
        ))
    }

    pub async fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "Descriptografia de canal não implementada"
        ))
    }
}
