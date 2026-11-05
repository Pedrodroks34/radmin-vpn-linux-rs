use crate::crypto::famatech::{FamatechCipherState, AES_256_KEY_SIZE, RSESSION_KEY_BUFFER_SIZE};
use openssl::bn::BigNum;
use openssl::pkey::{Private, Public};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use thiserror::Error;
use tracing::{debug, info};
use zeroize::{Zeroize, Zeroizing};

pub const RSESSION_RSA_BLOCK_SIZE: usize = 256;

pub const RSESSION_PLAINTEXT_SIZE: usize = 76;

pub const RSESSION_CLIENT_HEADER_SIZE: usize = 12;

pub const RSESSION_KEY_MATERIAL_SIZE: usize = RSESSION_KEY_BUFFER_SIZE;

pub const RSESSION_AES256_KEY_SIZE: usize = AES_256_KEY_SIZE;

pub const RSESSION_SERVER_TOKEN_SIZE: usize = 4;

pub const SHELPER_NETWORK_PROTOCOL_VERSION: u32 = 3;

pub const HANDSHAKE_MAGIC: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

pub const DEFAULT_RSA_PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandshakeError {
    #[error("chave RSA inválida ou ausente no handshake: {0}")]
    InvalidRsaKey(String),
    #[error("entrada inesperada no Estado 0 do cliente: recebido {len} bytes (esperado 0)")]
    UnexpectedInputInState0 { len: usize },
    #[error(
        "bloco criptográfico RSA de tamanho inválido: esperado {expected} bytes, recebido {actual}"
    )]
    InvalidRsaBlockSize { expected: usize, actual: usize },
    #[error("tamanho de plaintext RSA decifrado inválido: esperado {expected} bytes (0x4c), recebido {actual}")]
    InvalidDecryptedPlaintextSize { expected: usize, actual: usize },
    #[error("tamanho de token do servidor inválido no Estado 2: esperado {expected} bytes, recebido {actual}")]
    InvalidServerTokenSize { expected: usize, actual: usize },
    #[error("estado de handshake inesperado: {0}")]
    UnexpectedState(String),
    #[error("sessão RSession ainda não estabelecida (is_established == 0)")]
    SessionNotEstablished,
    #[error("falha na geração CSPRNG: {0}")]
    CsprngFailed(String),
    #[error("falha na cifragem RSA PKCS#1 v1.5: {0}")]
    RsaEncryptionFailed(String),
    #[error("falha na decifragem RSA PKCS#1 v1.5: {0}")]
    RsaDecryptionFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStage {
    ClientState0Initial,
    ServerState1WaitingClientBlock,
    ClientState2WaitingServerToken,
    State3Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeStepOutput {
    pub output: Option<Vec<u8>>,
    pub is_complete: bool,
}

#[derive(Debug)]
pub struct HandshakeNegotiator {
    stage: HandshakeStage,
    client_params: [u32; 3],
    is_established: bool,
    server_token: Option<u32>,
    server_public_key: Option<Rsa<Public>>,
    key_material: Option<[u8; RSESSION_KEY_MATERIAL_SIZE]>,
}

impl Default for HandshakeNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeNegotiator {
    pub fn new() -> Self {
        Self {
            stage: HandshakeStage::ClientState0Initial,
            client_params: [0, 0, 0],
            is_established: false,
            server_token: None,
            server_public_key: None,
            key_material: None,
        }
    }

    pub fn create_client(
        client_params: [u32; 3],
        server_modulus: &[u8],
        server_exponent: &[u8],
    ) -> Result<Self, HandshakeError> {
        let mut negotiator = Self {
            stage: HandshakeStage::ClientState0Initial,
            client_params,
            is_established: false,
            server_token: None,
            server_public_key: None,
            key_material: None,
        };
        negotiator.set_server_public_key_components(server_modulus, server_exponent)?;
        Ok(negotiator)
    }

    pub fn with_server_public_key(
        client_params: [u32; 3],
        server_public_key: Rsa<Public>,
    ) -> Result<Self, HandshakeError> {
        let mut negotiator = Self {
            stage: HandshakeStage::ClientState0Initial,
            client_params,
            is_established: false,
            server_token: None,
            server_public_key: None,
            key_material: None,
        };
        negotiator.set_server_public_key(server_public_key)?;
        Ok(negotiator)
    }

    pub fn set_client_params(&mut self, client_params: [u32; 3]) {
        self.client_params = client_params;
    }

    pub fn client_params(&self) -> [u32; 3] {
        self.client_params
    }

    pub fn set_server_public_key_components(
        &mut self,
        server_modulus: &[u8],
        server_exponent: &[u8],
    ) -> Result<(), HandshakeError> {
        if server_modulus.is_empty() || server_exponent.is_empty() {
            self.fail_and_clear();
            return Err(HandshakeError::InvalidRsaKey(
                "módulo ou expoente RSA vazio".to_string(),
            ));
        }

        let n = BigNum::from_slice(server_modulus).map_err(|e| {
            HandshakeError::InvalidRsaKey(format!("BN_bin2bn(modulus) falhou: {e}"))
        })?;
        let e = BigNum::from_slice(server_exponent).map_err(|e| {
            HandshakeError::InvalidRsaKey(format!("BN_bin2bn(exponent) falhou: {e}"))
        })?;

        let rsa = Rsa::from_public_components(n, e).map_err(|err| {
            HandshakeError::InvalidRsaKey(format!("Rsa::from_public_components falhou: {err}"))
        })?;

        self.set_server_public_key(rsa)
    }

    pub fn set_server_public_key(&mut self, rsa: Rsa<Public>) -> Result<(), HandshakeError> {
        if rsa.size() as usize != RSESSION_RSA_BLOCK_SIZE {
            self.fail_and_clear();
            return Err(HandshakeError::InvalidRsaKey(format!(
                "tamanho de chave RSA inválido: {} bytes (esperado {} bytes / 2048 bits)",
                rsa.size(),
                RSESSION_RSA_BLOCK_SIZE
            )));
        }
        self.server_public_key = Some(rsa);
        Ok(())
    }

    pub fn stage(&self) -> HandshakeStage {
        self.stage
    }

    pub fn is_established(&self) -> bool {
        self.is_established && self.stage == HandshakeStage::State3Completed
    }

    pub fn get_server_token(&self) -> Result<u32, HandshakeError> {
        if !self.is_established() {
            return Err(HandshakeError::SessionNotEstablished);
        }
        self.server_token
            .ok_or(HandshakeError::SessionNotEstablished)
    }

    pub fn get_key(&self) -> Result<&[u8; RSESSION_KEY_MATERIAL_SIZE], HandshakeError> {
        if !self.is_established() {
            return Err(HandshakeError::SessionNotEstablished);
        }
        self.key_material
            .as_ref()
            .ok_or(HandshakeError::SessionNotEstablished)
    }

    pub fn derive_aes256_key_ref(&self) -> Result<&[u8; RSESSION_AES256_KEY_SIZE], HandshakeError> {
        let key_material = self.get_key()?;
        Ok(key_material[..RSESSION_AES256_KEY_SIZE]
            .try_into()
            .expect("slice length matches RSESSION_AES256_KEY_SIZE"))
    }

    pub fn derive_aes256_key(
        &self,
    ) -> Result<Zeroizing<[u8; RSESSION_AES256_KEY_SIZE]>, HandshakeError> {
        let key_ref = self.derive_aes256_key_ref()?;
        let mut aes_key = Zeroizing::new([0u8; RSESSION_AES256_KEY_SIZE]);
        aes_key.copy_from_slice(key_ref);
        Ok(aes_key)
    }

    pub fn create_cipher(&self) -> Result<FamatechCipherState, HandshakeError> {
        let key_material = self.get_key()?;
        Ok(FamatechCipherState::from_rsession_key(key_material))
    }

    pub fn get_next_buffer(
        &mut self,
        input: Option<&[u8]>,
    ) -> Result<HandshakeStepOutput, HandshakeError> {
        match self.stage {
            HandshakeStage::ClientState0Initial => {
                if let Some(buf) = input {
                    if !buf.is_empty() {
                        let len = buf.len();
                        self.fail_and_clear();
                        return Err(HandshakeError::UnexpectedInputInState0 { len });
                    }
                }

                let pub_key = match self.server_public_key.as_ref() {
                    Some(k) => k,
                    None => {
                        self.fail_and_clear();
                        return Err(HandshakeError::InvalidRsaKey(
                            "chave pública RSA do servidor não configurada".to_string(),
                        ));
                    }
                };

                let mut key_material = [0u8; RSESSION_KEY_MATERIAL_SIZE];
                if let Err(e) = rand_bytes(&mut key_material) {
                    self.fail_and_clear();
                    return Err(HandshakeError::CsprngFailed(e.to_string()));
                }

                let mut plaintext = [0u8; RSESSION_PLAINTEXT_SIZE];
                plaintext[0..4].copy_from_slice(&self.client_params[0].to_le_bytes());
                plaintext[4..8].copy_from_slice(&self.client_params[1].to_le_bytes());
                plaintext[8..12].copy_from_slice(&self.client_params[2].to_le_bytes());
                plaintext[RSESSION_CLIENT_HEADER_SIZE..RSESSION_PLAINTEXT_SIZE]
                    .copy_from_slice(&key_material);

                let mut encrypted = vec![0u8; RSESSION_RSA_BLOCK_SIZE];
                let enc_len =
                    match pub_key.public_encrypt(&plaintext, &mut encrypted, Padding::PKCS1) {
                        Ok(len) => len,
                        Err(e) => {
                            plaintext.fill(0);
                            key_material.fill(0);
                            self.fail_and_clear();
                            return Err(HandshakeError::RsaEncryptionFailed(e.to_string()));
                        }
                    };
                plaintext.fill(0);

                if enc_len != RSESSION_RSA_BLOCK_SIZE {
                    key_material.fill(0);
                    self.fail_and_clear();
                    return Err(HandshakeError::InvalidRsaBlockSize {
                        expected: RSESSION_RSA_BLOCK_SIZE,
                        actual: enc_len,
                    });
                }

                self.key_material = Some(key_material);
                self.is_established = false;
                self.stage = HandshakeStage::ClientState2WaitingServerToken;
                info!(
                    "RSession Estado 0 -> Estado 2: bloco RSA PKCS#1 v1.5 de {} bytes gerado",
                    RSESSION_RSA_BLOCK_SIZE
                );

                Ok(HandshakeStepOutput {
                    output: Some(encrypted),
                    is_complete: false,
                })
            }

            HandshakeStage::ClientState2WaitingServerToken => {
                let buf = match input {
                    Some(b) => b,
                    None => {
                        self.fail_and_clear();
                        return Err(HandshakeError::InvalidServerTokenSize {
                            expected: RSESSION_SERVER_TOKEN_SIZE,
                            actual: 0,
                        });
                    }
                };

                if buf.len() != RSESSION_SERVER_TOKEN_SIZE {
                    let actual = buf.len();
                    self.fail_and_clear();
                    return Err(HandshakeError::InvalidServerTokenSize {
                        expected: RSESSION_SERVER_TOKEN_SIZE,
                        actual,
                    });
                }

                let token = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                self.server_token = Some(token);
                self.is_established = true;
                self.stage = HandshakeStage::State3Completed;
                debug!(
                    "RSession Estado 2 -> Estado 3: token do servidor 0x{:08x} validado, sessão estabelecida",
                    token
                );

                Ok(HandshakeStepOutput {
                    output: None,
                    is_complete: true,
                })
            }

            other => {
                self.fail_and_clear();
                Err(HandshakeError::UnexpectedState(format!(
                    "GetNextBuffer inválido no estado {other:?}"
                )))
            }
        }
    }

    pub fn clear(&mut self) {
        if let Some(ref mut key) = self.key_material {
            key.zeroize();
        }
        self.key_material = None;
        self.server_token = None;
        self.is_established = false;
    }

    fn fail_and_clear(&mut self) {
        self.clear();
        self.stage = HandshakeStage::Failed;
    }
}

impl Drop for HandshakeNegotiator {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Debug)]
pub struct RSessionServer {
    stage: HandshakeStage,
    server_token: u32,
    is_established: bool,
    client_params: Option<[u32; 3]>,
    private_key: Rsa<Private>,
    key_material: Option<[u8; RSESSION_KEY_MATERIAL_SIZE]>,
}

impl RSessionServer {
    pub fn create_server(
        server_token: u32,
        private_key: Rsa<Private>,
    ) -> Result<Self, HandshakeError> {
        if private_key.size() as usize != RSESSION_RSA_BLOCK_SIZE {
            return Err(HandshakeError::InvalidRsaKey(format!(
                "tamanho de chave privada RSA inválido: {} bytes (esperado {} bytes)",
                private_key.size(),
                RSESSION_RSA_BLOCK_SIZE
            )));
        }

        Ok(Self {
            stage: HandshakeStage::ServerState1WaitingClientBlock,
            server_token,
            is_established: false,
            client_params: None,
            private_key,
            key_material: None,
        })
    }

    pub fn stage(&self) -> HandshakeStage {
        self.stage
    }

    pub fn is_established(&self) -> bool {
        self.is_established && self.stage == HandshakeStage::State3Completed
    }

    pub fn get_client_params(&self) -> Result<[u32; 3], HandshakeError> {
        if !self.is_established() {
            return Err(HandshakeError::SessionNotEstablished);
        }
        self.client_params
            .ok_or(HandshakeError::SessionNotEstablished)
    }

    pub fn get_key(&self) -> Result<&[u8; RSESSION_KEY_MATERIAL_SIZE], HandshakeError> {
        if !self.is_established() {
            return Err(HandshakeError::SessionNotEstablished);
        }
        self.key_material
            .as_ref()
            .ok_or(HandshakeError::SessionNotEstablished)
    }

    pub fn derive_aes256_key_ref(&self) -> Result<&[u8; RSESSION_AES256_KEY_SIZE], HandshakeError> {
        let key_material = self.get_key()?;
        Ok(key_material[..RSESSION_AES256_KEY_SIZE]
            .try_into()
            .expect("slice length matches RSESSION_AES256_KEY_SIZE"))
    }

    pub fn derive_aes256_key(
        &self,
    ) -> Result<Zeroizing<[u8; RSESSION_AES256_KEY_SIZE]>, HandshakeError> {
        let key_ref = self.derive_aes256_key_ref()?;
        let mut aes_key = Zeroizing::new([0u8; RSESSION_AES256_KEY_SIZE]);
        aes_key.copy_from_slice(key_ref);
        Ok(aes_key)
    }

    pub fn create_cipher(&self) -> Result<FamatechCipherState, HandshakeError> {
        let key_material = self.get_key()?;
        Ok(FamatechCipherState::from_rsession_key(key_material))
    }

    pub fn get_next_buffer(
        &mut self,
        input: Option<&[u8]>,
    ) -> Result<HandshakeStepOutput, HandshakeError> {
        match self.stage {
            HandshakeStage::ServerState1WaitingClientBlock => {
                let buf = match input {
                    Some(b) => b,
                    None => {
                        self.fail_and_clear();
                        return Err(HandshakeError::InvalidRsaBlockSize {
                            expected: RSESSION_RSA_BLOCK_SIZE,
                            actual: 0,
                        });
                    }
                };

                if buf.len() != RSESSION_RSA_BLOCK_SIZE {
                    let actual = buf.len();
                    self.fail_and_clear();
                    return Err(HandshakeError::InvalidRsaBlockSize {
                        expected: RSESSION_RSA_BLOCK_SIZE,
                        actual,
                    });
                }

                let mut decrypted = Zeroizing::new([0u8; RSESSION_RSA_BLOCK_SIZE]);
                let dec_len =
                    match self
                        .private_key
                        .private_decrypt(buf, &mut *decrypted, Padding::PKCS1)
                    {
                        Ok(len) => len,
                        Err(e) => {
                            self.fail_and_clear();
                            return Err(HandshakeError::RsaDecryptionFailed(e.to_string()));
                        }
                    };

                if dec_len != RSESSION_PLAINTEXT_SIZE {
                    self.fail_and_clear();
                    return Err(HandshakeError::InvalidDecryptedPlaintextSize {
                        expected: RSESSION_PLAINTEXT_SIZE,
                        actual: dec_len,
                    });
                }

                let d0 = u32::from_le_bytes(decrypted[0..4].try_into().unwrap());
                let d1 = u32::from_le_bytes(decrypted[4..8].try_into().unwrap());
                let d2 = u32::from_le_bytes(decrypted[8..12].try_into().unwrap());

                let mut key_material = Zeroizing::new([0u8; RSESSION_KEY_MATERIAL_SIZE]);
                key_material.copy_from_slice(
                    &decrypted[RSESSION_CLIENT_HEADER_SIZE..RSESSION_PLAINTEXT_SIZE],
                );

                self.client_params = Some([d0, d1, d2]);
                self.key_material = Some(*key_material);
                self.is_established = true;
                self.stage = HandshakeStage::State3Completed;

                let out_token = self.server_token.to_le_bytes().to_vec();

                Ok(HandshakeStepOutput {
                    output: Some(out_token),
                    is_complete: true,
                })
            }

            other => {
                self.fail_and_clear();
                Err(HandshakeError::UnexpectedState(format!(
                    "GetNextBuffer inválido no servidor em estado {other:?}"
                )))
            }
        }
    }

    pub fn clear(&mut self) {
        if let Some(ref mut key) = self.key_material {
            key.zeroize();
        }
        self.key_material = None;
        self.client_params = None;
        self.is_established = false;
        #[cfg(test)]
        THREAD_RSESSION_SERVER_CLEANUP_COUNT.with(|c| c.set(c.get() + 1));
    }

    fn fail_and_clear(&mut self) {
        self.clear();
        self.stage = HandshakeStage::Failed;
    }
}

impl Drop for RSessionServer {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
thread_local! {
    static THREAD_RSESSION_SERVER_CLEANUP_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
impl RSessionServer {
    pub(crate) fn test_cleanup_count() -> usize {
        THREAD_RSESSION_SERVER_CLEANUP_COUNT.with(|c| c.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_server_rsa() -> (Rsa<Private>, Vec<u8>, Vec<u8>) {
        let rsa = Rsa::generate(2048).expect("geração RSA-2048 deve suceder");
        let modulus = rsa.n().to_vec();
        let exponent = rsa.e().to_vec();
        (rsa, modulus, exponent)
    }

    #[test]
    fn test_rsession_full_handshake_and_cchannel_key_installation() {
        let (server_priv, modulus, exponent) = generate_test_server_rsa();
        let client_params = [0x11223344, 0x55667788, 0x99aabbcc];
        let expected_server_token = 0xdeadbeef_u32;

        let mut client =
            HandshakeNegotiator::create_client(client_params, &modulus, &exponent).unwrap();
        let mut server = RSessionServer::create_server(expected_server_token, server_priv).unwrap();

        assert_eq!(client.stage(), HandshakeStage::ClientState0Initial);
        assert!(!client.is_established());
        assert_eq!(client.get_key(), Err(HandshakeError::SessionNotEstablished));
        assert_eq!(
            client.derive_aes256_key(),
            Err(HandshakeError::SessionNotEstablished)
        );
        assert_eq!(
            client.get_server_token(),
            Err(HandshakeError::SessionNotEstablished)
        );

        let step1 = client.get_next_buffer(None).unwrap();
        assert!(!step1.is_complete);
        assert_eq!(
            client.stage(),
            HandshakeStage::ClientState2WaitingServerToken
        );
        assert!(
            !client.is_established(),
            "Estado 2 ainda não pode marcar a sessão como estabelecida nem liberar a chave"
        );
        assert_eq!(client.get_key(), Err(HandshakeError::SessionNotEstablished));

        let client_pkt = step1.output.expect("Estado 0 deve emitir pacote de 256B");
        assert_eq!(client_pkt.len(), RSESSION_RSA_BLOCK_SIZE);

        let srv_step = server.get_next_buffer(Some(&client_pkt)).unwrap();
        assert!(srv_step.is_complete);
        assert!(server.is_established());
        assert_eq!(server.stage(), HandshakeStage::State3Completed);
        assert_eq!(server.get_client_params().unwrap(), client_params);

        let token_pkt = srv_step.output.expect("Estado 1 deve emitir token de 4B");
        assert_eq!(token_pkt.len(), RSESSION_SERVER_TOKEN_SIZE);
        assert_eq!(token_pkt, expected_server_token.to_le_bytes());

        let step2 = client.get_next_buffer(Some(&token_pkt)).unwrap();
        assert!(step2.is_complete);
        assert!(step2.output.is_none());
        assert!(client.is_established());
        assert_eq!(client.stage(), HandshakeStage::State3Completed);
        assert_eq!(client.get_server_token().unwrap(), expected_server_token);

        let client_key_64 = client.get_key().unwrap();
        let server_key_64 = server.get_key().unwrap();
        assert_eq!(client_key_64, server_key_64);
        assert_ne!(&client_key_64[0..4], &token_pkt[..]);

        let client_aes_32 = client.derive_aes256_key().unwrap();
        let server_aes_32 = server.derive_aes256_key().unwrap();
        assert_eq!(client_aes_32, server_aes_32);
        assert_eq!(&client_aes_32[..], &client_key_64[..32]);
        assert_eq!(
            client.derive_aes256_key_ref().unwrap(),
            server.derive_aes256_key_ref().unwrap()
        );

        let mut client_cipher = client.create_cipher().unwrap();
        let mut server_cipher = server.create_cipher().unwrap();

        let msg_c2s = b"Authenticated tunnel frame C->S";
        let ct_c2s = client_cipher.encrypt(msg_c2s).unwrap();
        let pt_c2s = server_cipher.decrypt(&ct_c2s).unwrap();
        assert_eq!(pt_c2s, msg_c2s);

        let msg_s2c = b"Authenticated tunnel frame S->C";
        let ct_s2c = server_cipher.encrypt(msg_s2c).unwrap();
        let pt_s2c = client_cipher.decrypt(&ct_s2c).unwrap();
        assert_eq!(pt_s2c, msg_s2c);
    }

    #[test]
    fn test_rsession_rejects_invalid_token_sizes_in_state2() {
        let (_server_priv, modulus, exponent) = generate_test_server_rsa();

        for bad_len in [0usize, 1, 2, 3, 5, 8, 16, 32, 256] {
            let mut client =
                HandshakeNegotiator::create_client([1, 2, 3], &modulus, &exponent).unwrap();
            let _ = client.get_next_buffer(None).unwrap();
            assert_eq!(
                client.stage(),
                HandshakeStage::ClientState2WaitingServerToken
            );

            let bad_input = vec![0xAAu8; bad_len];
            let err = client.get_next_buffer(Some(&bad_input)).unwrap_err();
            assert_eq!(
                err,
                HandshakeError::InvalidServerTokenSize {
                    expected: 4,
                    actual: bad_len,
                }
            );
            assert_eq!(client.stage(), HandshakeStage::Failed);
            assert!(!client.is_established());
            assert_eq!(client.get_key(), Err(HandshakeError::SessionNotEstablished));
        }
    }

    #[test]
    fn test_rsession_rejects_non_empty_input_in_state0_and_out_of_order_calls() {
        let (server_priv, modulus, exponent) = generate_test_server_rsa();

        let mut client =
            HandshakeNegotiator::create_client([1, 2, 3], &modulus, &exponent).unwrap();
        let err = client
            .get_next_buffer(Some(&[0x01, 0x02, 0x03, 0x04]))
            .unwrap_err();
        assert_eq!(err, HandshakeError::UnexpectedInputInState0 { len: 4 });
        assert_eq!(client.stage(), HandshakeStage::Failed);

        let mut client2 =
            HandshakeNegotiator::create_client([1, 2, 3], &modulus, &exponent).unwrap();
        let mut server = RSessionServer::create_server(42, server_priv).unwrap();
        let step1 = client2.get_next_buffer(None).unwrap();
        let srv_step = server.get_next_buffer(step1.output.as_deref()).unwrap();
        let step2 = client2.get_next_buffer(srv_step.output.as_deref()).unwrap();
        assert!(step2.is_complete);
        assert_eq!(client2.stage(), HandshakeStage::State3Completed);

        let extra_err = client2.get_next_buffer(None).unwrap_err();
        assert!(matches!(extra_err, HandshakeError::UnexpectedState(_)));
        assert_eq!(client2.stage(), HandshakeStage::Failed);
        assert!(!client2.is_established());
    }

    #[test]
    fn test_rsession_server_rejects_wrong_plaintext_size_or_corrupted_rsa_block() {
        let (server_priv, modulus, exponent) = generate_test_server_rsa();
        let pub_key = Rsa::from_public_components(
            BigNum::from_slice(&modulus).unwrap(),
            BigNum::from_slice(&exponent).unwrap(),
        )
        .unwrap();

        let mut wrong_size_ct = vec![0u8; RSESSION_RSA_BLOCK_SIZE];
        pub_key
            .public_encrypt(&[0x55u8; 32], &mut wrong_size_ct, Padding::PKCS1)
            .unwrap();

        let mut server = RSessionServer::create_server(100, server_priv.clone()).unwrap();
        let err = server.get_next_buffer(Some(&wrong_size_ct)).unwrap_err();
        assert_eq!(
            err,
            HandshakeError::InvalidDecryptedPlaintextSize {
                expected: RSESSION_PLAINTEXT_SIZE,
                actual: 32,
            }
        );
        assert_eq!(server.stage(), HandshakeStage::Failed);
        assert!(!server.is_established());

        let mut server2 = RSessionServer::create_server(100, server_priv).unwrap();
        let err2 = server2.get_next_buffer(Some(&[0u8; 128])).unwrap_err();
        assert_eq!(
            err2,
            HandshakeError::InvalidRsaBlockSize {
                expected: RSESSION_RSA_BLOCK_SIZE,
                actual: 128,
            }
        );
        assert_eq!(server2.stage(), HandshakeStage::Failed);
    }

    #[test]
    fn test_rsession_server_drop_initial_state() {
        let (rsa, _, _) = generate_test_server_rsa();
        let initial_count = RSessionServer::test_cleanup_count();
        {
            let server = RSessionServer::create_server(0x1234, rsa).unwrap();
            assert_eq!(
                server.stage(),
                HandshakeStage::ServerState1WaitingClientBlock
            );
            assert!(!server.is_established());
            assert!(server.get_key().is_err());
        }
        let final_count = RSessionServer::test_cleanup_count();
        assert_eq!(final_count, initial_count + 1);
    }

    #[test]
    fn test_rsession_server_drop_after_processing_valid_block() {
        let (rsa, modulus, exponent) = generate_test_server_rsa();
        let mut client = HandshakeNegotiator::new();
        client
            .set_server_public_key_components(&modulus, &exponent)
            .unwrap();
        let step1_out = client.get_next_buffer(None).unwrap();
        let rsa_block = step1_out.output.unwrap();

        let initial_count = RSessionServer::test_cleanup_count();
        {
            let mut server = RSessionServer::create_server(0x4321, rsa).unwrap();
            let step2_out = server.get_next_buffer(Some(&rsa_block)).unwrap();
            assert!(step2_out.is_complete);
            assert!(server.is_established());
            assert!(server.get_key().is_ok());
            assert_ne!(server.get_key().unwrap(), &[0u8; 64]);
        }
        let final_count = RSessionServer::test_cleanup_count();
        assert_eq!(final_count, initial_count + 1);
    }

    #[test]
    fn test_rsession_server_drop_after_full_session_established() {
        let (rsa, modulus, exponent) = generate_test_server_rsa();
        let mut client = HandshakeNegotiator::new();
        client
            .set_server_public_key_components(&modulus, &exponent)
            .unwrap();
        let step1_out = client.get_next_buffer(None).unwrap();

        let initial_count = RSessionServer::test_cleanup_count();
        {
            let mut server = RSessionServer::create_server(0x5678, rsa).unwrap();
            let step2_out = server
                .get_next_buffer(Some(&step1_out.output.unwrap()))
                .unwrap();
            let _ = client
                .get_next_buffer(Some(&step2_out.output.unwrap()))
                .unwrap();

            assert!(client.is_established());
            assert!(server.is_established());
            assert_eq!(client.get_key().unwrap(), server.get_key().unwrap());
        }
        let final_count = RSessionServer::test_cleanup_count();
        assert_eq!(final_count, initial_count + 1);
    }

    #[test]
    fn test_rsession_server_explicit_clear_followed_by_drop() {
        let (rsa, modulus, exponent) = generate_test_server_rsa();
        let mut client = HandshakeNegotiator::new();
        client
            .set_server_public_key_components(&modulus, &exponent)
            .unwrap();
        let step1_out = client.get_next_buffer(None).unwrap();

        let initial_count = RSessionServer::test_cleanup_count();
        {
            let mut server = RSessionServer::create_server(0x9999, rsa).unwrap();
            let _ = server
                .get_next_buffer(Some(&step1_out.output.unwrap()))
                .unwrap();
            assert!(server.is_established());
            assert!(server.get_key().is_ok());

            server.clear();
            assert!(!server.is_established());
            assert_eq!(server.get_key(), Err(HandshakeError::SessionNotEstablished));
            assert_eq!(
                server.derive_aes256_key().unwrap_err(),
                HandshakeError::SessionNotEstablished
            );
            assert_eq!(
                server.get_client_params(),
                Err(HandshakeError::SessionNotEstablished)
            );

            server.clear();
            assert!(!server.is_established());
        }
        let final_count = RSessionServer::test_cleanup_count();
        assert_eq!(final_count, initial_count + 3);
    }

    #[test]
    fn test_rsession_server_drop_after_processing_failure() {
        let (rsa, _, _) = generate_test_server_rsa();
        let initial_count = RSessionServer::test_cleanup_count();
        {
            let mut server = RSessionServer::create_server(0x7777, rsa).unwrap();
            let bad_input = [0xAAu8; 128];
            let res = server.get_next_buffer(Some(&bad_input));
            assert!(res.is_err());
            assert_eq!(server.stage(), HandshakeStage::Failed);
            assert!(!server.is_established());
            assert!(server.get_key().is_err());
        }
        let final_count = RSessionServer::test_cleanup_count();
        assert_eq!(final_count, initial_count + 2);
    }
}
