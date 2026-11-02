pub mod famatech;

pub use famatech::{
    famatech_checksum_64, famatech_fold_md5, famatech_pad_and_sign, famatech_verify_and_unpad,
    CryptoError, FamatechCipherState, AES_256_KEY_SIZE, BLOCK_SIZE, MAX_PAD_LEN, MIN_PAD_LEN,
    PAD_BYTE, RSESSION_KEY_BUFFER_SIZE, TRAILER_SIZE,
};

use crate::Result;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoChannelConfig {
    pub enabled: bool,
    pub compression: bool,
}

impl Default for CryptoChannelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            compression: false,
        }
    }
}

pub struct CryptoChannel {
    pub config: CryptoChannelConfig,
    state: Option<Mutex<FamatechCipherState>>,
}

impl CryptoChannel {
    pub fn new(config: CryptoChannelConfig) -> Self {
        Self {
            config,
            state: None,
        }
    }

    pub fn with_key(config: CryptoChannelConfig, key: [u8; 32]) -> Self {
        Self {
            config,
            state: Some(Mutex::new(FamatechCipherState::new(key))),
        }
    }

    pub fn with_cipher_state(config: CryptoChannelConfig, cipher: FamatechCipherState) -> Self {
        Self {
            config,
            state: Some(Mutex::new(cipher)),
        }
    }

    pub fn set_key(&mut self, key: [u8; 32]) {
        self.state = Some(Mutex::new(FamatechCipherState::new(key)));
    }

    pub fn set_cipher_state(&mut self, cipher: FamatechCipherState) {
        self.state = Some(Mutex::new(cipher));
    }

    pub fn clear(&mut self) {
        if let Some(state) = self.state.take() {
            if let Ok(mut guard) = state.lock() {
                guard.clear();
            }
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.config.enabled && self.state.is_some()
    }

    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.config.enabled {
            return Ok(plaintext.to_vec());
        }

        match &self.state {
            Some(state) => {
                let mut guard = state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("falha ao obter lock do estado criptográfico"))?;
                let ct = guard.encrypt(plaintext)?;
                Ok(ct)
            }
            None => Err(anyhow::anyhow!(
                "Canal criptográfico ativo mas chave não foi negociada/configurada"
            )),
        }
    }

    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.config.enabled {
            return Ok(ciphertext.to_vec());
        }

        match &self.state {
            Some(state) => {
                let mut guard = state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("falha ao obter lock do estado criptográfico"))?;
                let pt = guard.decrypt(ciphertext)?;
                Ok(pt)
            }
            None => Err(anyhow::anyhow!(
                "Canal criptográfico ativo mas chave não foi negociada/configurada"
            )),
        }
    }
}
