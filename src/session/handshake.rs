//! Reconstrução do Handshake e Troca de Chaves do Radmin VPN.
//!
//! Engenharia reversa dos binários shelper.dll (SHelper_RSAHelper_*, SHelper_CChannel_*,
//! SHelper_RSession_GetKey) e capturas radmin_17301.pcap / radmin_vm2.pcap:
//!
//! Sequência cronológica do estabelecimento de sessão:
//! 1. SYN / SYN-ACK / ACK TCP na porta 17301 (ou 17351).
//! 2. Cliente -> Servidor (Pkt #32): Magic de protocolo não cifrado:
//!    Outer len 4: [00 00 00 04], Payload: [03 00 00 00]
//! 3. Servidor -> Cliente (Pkt #40): Servidor confirma ecoando:
//!    Outer len 4: [00 00 00 04], Payload: [03 00 00 00]
//! 4. Cliente -> Servidor (Pkt #41 / #686): TLV de Client Hello (288 bytes de payload):
//!    - Tag 0x010001df (TAG_SESSION_TOKEN): valor uint32 = 1
//!    - Tag 0x0100032b (TAG_PEER_STATUS): valor uint32 = 2
//!    - Tag 0x090001ca (TAG_RSA_PUBLIC_KEY): 256 bytes da chave pública RSA-2048 do cliente
//! 5. Servidor -> Cliente (Pkt #687 / #42):
//!    - Confirmação de Session Token (ex: valor 2) ou bloco de 256 bytes cifrado com RSA
//!      contendo o segredo de sessão (chave AES-256 e semente de autenticação).
//! 6. Ambos os lados ativam AES-256-CBC:
//!    - IV inicial zerado: [0u8; 16]
//!    - Todos os frames subsequentes são múltiplos de 16 bytes com trailer Famatech
//!      (padding 0xCC, checksum aditivo de 64-bit e MD5 dobrado de 8 bytes).

use crate::crypto::famatech::FamatechCipherState;
use crate::protocol::tlv::{TlvMessage, TlvTag};
use crate::Result;
use openssl::rsa::{Padding, Rsa};
use thiserror::Error;
use tracing::{debug, info};

pub const HANDSHAKE_MAGIC: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("magic de handshake inválido: esperado {expected:?}, recebido {actual:?}")]
    InvalidMagic { expected: Vec<u8>, actual: Vec<u8> },
    #[error("chave RSA inválida ou ausente no handshake: {0}")]
    InvalidRsaKey(String),
    #[error("bloco criptográfico RSA de tamanho inválido: esperado 256 bytes, recebido {0}")]
    InvalidCryptoBlockSize(usize),
    #[error("tag obrigatória ausente na resposta de handshake: 0x{0:08x}")]
    MissingTag(u32),
    #[error("estado de handshake inesperado: {0}")]
    UnexpectedState(String),
    #[error("falha na descriptografia RSA: {0}")]
    RsaDecryptionFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStage {
    Initial,
    MagicExchanged,
    HelloSent,
    CipherActivated,
    Failed,
}

#[derive(Debug)]
pub struct HandshakeNegotiator {
    stage: HandshakeStage,
    session_token: u32,
    rsa_key: Option<Rsa<openssl::pkey::Private>>,
    session_key: Option<[u8; 32]>,
}

impl Default for HandshakeNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeNegotiator {
    pub fn new() -> Self {
        Self {
            stage: HandshakeStage::Initial,
            session_token: 1,
            rsa_key: None,
            session_key: None,
        }
    }

    pub fn stage(&self) -> HandshakeStage {
        self.stage
    }

    pub fn session_token(&self) -> u32 {
        self.session_token
    }

    pub fn session_key(&self) -> Option<[u8; 32]> {
        self.session_key
    }

    /// Inicializa a chave RSA-2048 do cliente.
    pub fn generate_rsa_key(&mut self) -> Result<()> {
        let rsa = Rsa::generate(2048)
            .map_err(|e| HandshakeError::InvalidRsaKey(format!("Geração RSA falhou: {}", e)))?;
        self.rsa_key = Some(rsa);
        Ok(())
    }

    /// Carrega chave RSA a partir de instância existente.
    pub fn set_rsa_key(&mut self, rsa: Rsa<openssl::pkey::Private>) {
        self.rsa_key = Some(rsa);
    }

    /// Retorna o frame mágico inicial a ser enviado: `[03 00 00 00]`.
    pub fn build_magic_packet(&self) -> Vec<u8> {
        HANDSHAKE_MAGIC.to_vec()
    }

    /// Valida o frame mágico de confirmação retornado pelo servidor.
    pub fn verify_magic_response(&mut self, payload: &[u8]) -> Result<()> {
        if payload != HANDSHAKE_MAGIC {
            self.stage = HandshakeStage::Failed;
            return Err(HandshakeError::InvalidMagic {
                expected: HANDSHAKE_MAGIC.to_vec(),
                actual: payload.to_vec(),
            }
            .into());
        }
        self.stage = HandshakeStage::MagicExchanged;
        debug!("Magic de handshake validado com sucesso");
        Ok(())
    }

    /// Constrói o pacote Client Hello contendo a chave pública RSA e tags TLV
    /// idênticas às capturadas no pacote #686.
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>> {
        if self.rsa_key.is_none() {
            self.generate_rsa_key()?;
        }
        let rsa = self.rsa_key.as_ref().unwrap();

        // Extrai o módulo n (256 bytes para RSA-2048)
        let n_bytes = rsa.n().to_vec();
        let mut pub_key_raw = vec![0u8; 256];
        if n_bytes.len() <= 256 {
            let offset = 256 - n_bytes.len();
            pub_key_raw[offset..].copy_from_slice(&n_bytes);
        } else {
            // Em caso de leading zero adicional de ASN.1
            pub_key_raw.copy_from_slice(&n_bytes[n_bytes.len() - 256..]);
        }

        let mut msg = TlvMessage::new();
        msg.add_u32(TlvTag::TAG_SESSION_TOKEN, self.session_token);
        msg.add_u32(TlvTag::TAG_PEER_STATUS, 2);
        msg.add_buffer(TlvTag::TAG_RSA_PUBLIC_KEY, pub_key_raw);

        self.stage = HandshakeStage::HelloSent;
        info!(
            "Client Hello construído com sucesso (Token: {})",
            self.session_token
        );
        Ok(msg.to_bytes())
    }

    /// Processa a resposta do servidor:
    /// Se for TLV com session token atualizado (ex: pacote #687):
    /// atualiza o token da sessão.
    /// Se for bloco RSA cifrado de 256 bytes (ex: pacote #42):
    /// descriptografa usando a chave privada e deriva a chave AES-256.
    pub fn process_server_response(&mut self, payload: &[u8]) -> Result<Option<[u8; 32]>> {
        // Caso 1: Bloco RSA puro de 256 bytes (negociação direta de segredo)
        if payload.len() == 256 {
            let rsa = self
                .rsa_key
                .as_ref()
                .ok_or_else(|| HandshakeError::UnexpectedState("Chave RSA ausente".to_string()))?;

            let mut decrypted = vec![0u8; 256];
            let len = rsa
                .private_decrypt(payload, &mut decrypted, Padding::PKCS1)
                .or_else(|_| rsa.private_decrypt(payload, &mut decrypted, Padding::NONE))
                .map_err(|e| {
                    HandshakeError::RsaDecryptionFailed(format!("Erro ao descriptografar: {}", e))
                })?;

            // Deriva ou extrai os 32 bytes da chave AES
            let mut key = [0u8; 32];
            if len >= 32 {
                key.copy_from_slice(&decrypted[..32]);
            } else {
                key[..len].copy_from_slice(&decrypted[..len]);
            }

            self.session_key = Some(key);
            self.stage = HandshakeStage::CipherActivated;
            info!("Chave AES-256 de sessão negociada e cifrador ativado via RSA");
            return Ok(Some(key));
        }

        // Caso 2: Mensagem TLV (ex: confirmação de token, pacote #687)
        if let Ok(tlv) = TlvMessage::parse(payload) {
            if let Some(token) = tlv.get_u32(TlvTag::TAG_SESSION_TOKEN) {
                self.session_token = token;
                debug!("Token de sessão atualizado para: {}", token);
            }

            // Se contiver bloco de criptografia TLV (0x09000304)
            if let Some(crypto_block) = tlv.get_buffer(TlvTag::TAG_HANDSHAKE_CRYPTO) {
                if crypto_block.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(crypto_block);
                    self.session_key = Some(key);
                    self.stage = HandshakeStage::CipherActivated;
                    return Ok(Some(key));
                }
            }

            return Ok(None);
        }

        Err(anyhow::anyhow!(
            "Payload de resposta de handshake não reconhecido (tamanho: {})",
            payload.len()
        ))
    }

    /// Cria uma instância inicializada do FamatechCipherState pronta para comunicação cifrada.
    pub fn create_cipher(&self) -> Result<FamatechCipherState> {
        let key = self
            .session_key
            .ok_or_else(|| anyhow::anyhow!("Chave de sessão ainda não negociada"))?;
        Ok(FamatechCipherState::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_magic_generation_and_validation() {
        let mut negotiator = HandshakeNegotiator::new();
        assert_eq!(negotiator.stage(), HandshakeStage::Initial);

        let magic = negotiator.build_magic_packet();
        assert_eq!(magic, [0x03, 0x00, 0x00, 0x00]);

        // Verificação bem-sucedida
        negotiator.verify_magic_response(&magic).unwrap();
        assert_eq!(negotiator.stage(), HandshakeStage::MagicExchanged);

        // Verificação com payload incorreto deve falhar
        let mut bad_negotiator = HandshakeNegotiator::new();
        let err = bad_negotiator.verify_magic_response(&[0, 0, 0, 0]);
        assert!(err.is_err());
        assert_eq!(bad_negotiator.stage(), HandshakeStage::Failed);
    }

    #[test]
    fn test_handshake_client_hello_format() {
        let mut negotiator = HandshakeNegotiator::new();
        let hello_bytes = negotiator.build_client_hello().unwrap();
        assert_eq!(negotiator.stage(), HandshakeStage::HelloSent);

        // Decodifica como TLV e valida os campos idênticos ao pacote #686
        let tlv = TlvMessage::parse(&hello_bytes).unwrap();
        assert_eq!(tlv.get_u32(TlvTag::TAG_SESSION_TOKEN), Some(1));
        assert_eq!(tlv.get_u32(TlvTag::TAG_PEER_STATUS), Some(2));

        let pub_key = tlv.get_buffer(TlvTag::TAG_RSA_PUBLIC_KEY).unwrap();
        assert_eq!(pub_key.len(), 256);
    }

    #[test]
    fn test_handshake_process_server_token_response_packet_687() {
        let mut negotiator = HandshakeNegotiator::new();
        let _ = negotiator.build_client_hello().unwrap();

        // Pacote #687 payload: [00000004 010001df 00000002]
        let pkt_687_payload = [
            0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x01, 0xdf, 0x00, 0x00, 0x00, 0x02,
        ];
        let key_opt = negotiator
            .process_server_response(&pkt_687_payload)
            .unwrap();
        assert!(key_opt.is_none());
        assert_eq!(negotiator.session_token(), 2);
    }

    #[test]
    fn test_handshake_rsa_key_exchange_roundtrip() {
        let mut negotiator = HandshakeNegotiator::new();
        let _ = negotiator.build_client_hello().unwrap();

        let rsa = negotiator.rsa_key.as_ref().unwrap();

        // Simula o servidor cifrando uma chave AES de 32 bytes com a chave pública do cliente
        let session_key_expected = [0x42u8; 32];
        let mut encrypted = vec![0u8; 256];
        rsa.public_encrypt(&session_key_expected, &mut encrypted, Padding::PKCS1)
            .unwrap();

        let derived_key = negotiator
            .process_server_response(&encrypted)
            .unwrap()
            .unwrap();
        assert_eq!(derived_key, session_key_expected);
        assert_eq!(negotiator.stage(), HandshakeStage::CipherActivated);

        let cipher = negotiator.create_cipher().unwrap();
        assert_eq!(cipher.key(), &session_key_expected);
    }
}
