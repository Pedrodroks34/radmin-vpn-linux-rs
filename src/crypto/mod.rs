//! # Módulo `crypto` — Canais criptografados
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - `ROLClient_SetCompression` e `ROLClient_DisableEncryption` existem —
//!   canais suportam compressão e criptografia opcional.
//! - Classe `CCryptoChannel` (RTTI em RvROLClient.dll) — canal criptografado.
//! - `FamCurl` com `?g_DefaultCaCertPem` — wrapper cURL com CA PEM embutida (HTTPS/DoH).
//! - `imrsdk.dll` carrega CAs Symantec/Verisign herdados.
//! - `Shelper.dll` menciona `GOST_KEY_TRANSPORT` (criptografia russa herdada, uso não confirmado).
//!
//! **Desconhecido:**
//! - Algoritmos de criptografia específicos (AES, ChaCha20, RSA, ECC, etc.).
//! - Derivação de chaves e troca de chaves.
//! - Autenticação de mensagens (HMAC, AEAD) e proteção contra replay.
//! - Se a criptografia é por canal (TLS-like) ou por pacote.
//
//! ## Regra obrigatória
//!
//! **Nunca implementar criptografia própria.** Usar `ring` / `rustls` e,
//! após REA dinâmica, mapear os algoritmos descobertos para essas bibliotecas.

use crate::Result;
use serde::{Deserialize, Serialize};

/// Configuração de um canal criptografado (equivalente a CCryptoChannel)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoChannelConfig {
    pub enabled: bool,
    pub compression: bool,
    // preencher após REA dinâmica: cipher, kdf, aead, etc.
}

/// Canal criptografado (placeholder)
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
