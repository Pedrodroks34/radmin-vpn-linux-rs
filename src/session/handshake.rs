//! Handshake criptográfico de sessão `SHelper_RSession` (`shelper.dll` e `RvROLClient.dll`).
//!
//! Evidências binárias verificadas por desmontagem estática:
//! - `shelper.dll!0x1006b860` (`SHelper_RSession_CreateClient` -> `0x1006a690` `RSession_InitClient`):
//!   Inicializa a estrutura `RSession` (`0x3c` bytes) no estado `0` (`ClientState0Initial`),
//!   armazena os 3 DWORDs de parâmetros do cliente em `+0x04..+0x0c`, zera `is_established` (`+0x10 = 0`),
//!   e carrega a chave pública RSA-2048 do servidor via `SHelper_RSAHelper_CreatePublic`
//!   (`0x100660a7` -> `0x10065848`, `BN_bin2bn` sobre módulo e expoente big-endian).
//! - `shelper.dll!0x1006b8f0` (`SHelper_RSession_CreateServer` -> `0x1006a780` `RSession_InitServer`):
//!   Inicializa `RSession` no estado `1` (`ServerState1WaitingClientBlock`), armazena o token de
//!   4 bytes do servidor em `+0x04`, zera `is_established` (`+0x10 = 0`) e carrega a chave privada RSA.
//! - `shelper.dll!0x1006bb10` -> `0x1006a2b0` (`SHelper_RSession_GetNextBuffer`):
//!   - **Estado 0 (Cliente, `0x1006a512`)**:
//!     1. Rejeita qualquer buffer de entrada não vazio (`0x1006a512..0x1006a51c`).
//!     2. Aloca um bloco plaintext de 76 bytes (`0x4c`, `0x1006a522: push 0x4c`).
//!     3. Grava os 3 DWORDs do cliente nos primeiros 12 bytes (`0..12`, `0x1006a55c..0x1006a569`).
//!     4. Gera 64 bytes (`0x40`) pseudoaleatórios criptograficamente seguros via `RAND_bytes`
//!        (`0x10063530` em `0x1006a56d: push 0x40`), salva-os em `[esi+0x30]` e copia-os para
//!        os bytes `12..76` do plaintext (`0x1006a582..0x1006a593`).
//!     5. Cifra os 76 bytes com a chave pública RSA-2048 usando `RSA_PKCS1_PADDING` (`padding = 1`,
//!        `0x10065ec0` via `0x10065ca0` em `0x1006a59c`), gerando um bloco de 256 bytes (`0x100`).
//!     6. Transiciona `state = 2` (`0x1006a5eb: mov dword ptr [esi], 0x2`) e retorna
//!        `is_complete = false` (`*is_complete = 0` em `0x1006a5fd`).
//!   - **Estado 1 (Servidor, `0x1006a30c`)**:
//!     1. Recebe o bloco RSA de 256 bytes e decifra com a chave privada usando `RSA_PKCS1_PADDING`
//!        (`0x10065de8` via `0x10065bc7` em `0x1006a354`).
//!     2. Exige que o tamanho decifrado seja exatamente `0x4c` (76 bytes)
//!        (`0x1006a36d: cmp dword ptr [ebp-0x10], 0x4c; jne 0x1006a4c2`).
//!     3. Extrai os 3 DWORDs do cliente (`0..12`) para `[esi+0x14..+0x1c]` e os 64 bytes de
//!        material de chave (`12..76`) para `[esi+0x30]` (`0x1006a41b..0x1006a468`).
//!     4. Emite o token do servidor de 4 bytes (`0x1006a472: push 0x4`, `0x1006a496`),
//!        marca `is_established = true` (`[esi+0x10] = 1`), `state = 3` (`0x1006a4bb`) e
//!        `is_complete = true`.
//!   - **Estado 2 (Cliente, `0x1006a4cc`)**:
//!     1. Exige `in_buf != NULL` e `in_len == 4` (`0x1006a4df: cmp dword ptr [ebp+0xc], 0x4; jne 0x1006a614`).
//!     2. Lê o token de 4 bytes do servidor e salva em `[esi+0x14]` (`0x1006a4e9..0x1006a4eb`).
//!     3. Transiciona `state = 3` (`0x1006a4fc`), marca `is_established = true`
//!        (`0x1006a503: mov dword ptr [esi+0x10], 0x1`) e `is_complete = true` (`0x1006a50a`).
//! - `shelper.dll!0x1006ba80` -> `0x1006a270` (`SHelper_RSession_GetKey`):
//!   Verifica `is_established != 0` (`[ecx+0x10] != 0`) e retorna os 64 bytes (`0x40`) em `[ecx+0x30]`.
//! - `RvROLClient.dll!0x100df250` (`CChannelWrapper::Create`), `0x100df470` (`SetKey`),
//!   `0x10096f0d..0x10096f21` e `0x100969de..0x10096a16`:
//!   Obtém o buffer de 64 bytes via `RSession::GetKey` (`0x100dce30` / `0x100dd330`), valida
//!   `len >= 0x20` (32 bytes) e instala `&key_material[0..32]` como chave AES-256 (`key_enc` e `key_dec`)
//!   no `SHelper_CChannel`.

use crate::crypto::famatech::{FamatechCipherState, AES_256_KEY_SIZE, RSESSION_KEY_BUFFER_SIZE};
use openssl::bn::BigNum;
use openssl::pkey::{Private, Public};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use thiserror::Error;
use tracing::{debug, info};
use zeroize::{Zeroize, Zeroizing};

/// Tamanho do bloco RSA-2048 gerado no Estado 0 do `SHelper_RSession` (`0x100` = 256 bytes).
pub const RSESSION_RSA_BLOCK_SIZE: usize = 256;

/// Tamanho exato do plaintext antes da cifragem RSA PKCS#1 v1.5 (`0x4c` = 76 bytes, `0x1006a522` / `0x1006a36d`).
pub const RSESSION_PLAINTEXT_SIZE: usize = 76;

/// Tamanho do cabeçalho de parâmetros do cliente (`3 * sizeof(u32)` = 12 bytes, `0x1006a55c..0x1006a569`).
pub const RSESSION_CLIENT_HEADER_SIZE: usize = 12;

/// Tamanho do material aleatório CSPRNG gerado em `0x1006a56d` (`0x40` = 64 bytes).
pub const RSESSION_KEY_MATERIAL_SIZE: usize = RSESSION_KEY_BUFFER_SIZE;

/// Tamanho da chave AES-256 instalada no `SHelper_CChannel` (`0x20` = 32 bytes, `RvROLClient.dll!0x100df250`).
pub const RSESSION_AES256_KEY_SIZE: usize = AES_256_KEY_SIZE;

/// Tamanho exato do token de confirmação enviado pelo servidor no Estado 2 (`0x04` = 4 bytes, `0x1006a4df`).
pub const RSESSION_SERVER_TOKEN_SIZE: usize = 4;

/// Versão de protocolo de rede exportada por `SHelper_GetNetworkProtocolVersion` (`shelper.dll!0x1006b1d0`).
pub const SHELPER_NETWORK_PROTOCOL_VERSION: u32 = 3;

/// Frame de 4 bytes `[03 00 00 00]` correspondente a `SHelper_GetNetworkProtocolVersion` (`0x1006b1d0`).
pub const HANDSHAKE_MAGIC: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

/// Expoente público RSA padrão (`65537` = `0x010001` em big-endian).
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

/// Estados reais da máquina `SHelper_RSession_GetNextBuffer` (`shelper.dll!0x1006a2b0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStage {
    /// Estado `0` (`0x1006a690` / `0x1006a512`): cliente pronto para gerar o bloco RSA de 256 bytes.
    ClientState0Initial,
    /// Estado `1` (`0x1006a780` / `0x1006a30c`): servidor aguardando o bloco RSA de 256 bytes do cliente.
    ServerState1WaitingClientBlock,
    /// Estado `2` (`0x1006a5eb` / `0x1006a4cc`): cliente enviou o bloco de 256 bytes e aguarda o token de 4 bytes.
    ClientState2WaitingServerToken,
    /// Estado `3` (`0x1006a4bb` / `0x1006a4fc`): handshake concluído com `is_established == true`.
    State3Completed,
    /// Falha terminal que invalida a tentativa de handshake e zera o material criptográfico.
    Failed,
}

/// Resultado de um passo de `get_next_buffer` (`SHelper_RSession_GetNextBuffer`, `0x1006a2b0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeStepOutput {
    /// Buffer de saída a ser transmitido ao par remoto (`Some(256B)` no Estado 0, `Some(4B)` no Estado 1, `None` no Estado 2).
    pub output: Option<Vec<u8>>,
    /// Indica se o handshake `RSession` foi concluído (`*is_complete` em `0x1006a2b0`).
    pub is_complete: bool,
}

/// Implementação fiel do lado cliente de `SHelper_RSession` (`shelper.dll!0x1006b860` / `0x1006a2b0`).
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
    /// Cria uma instância inicializada no Estado `0` (`ClientState0Initial`) com `is_established = false`.
    /// A chave pública RSA-2048 do servidor deve ser configurada via [`Self::create_client`],
    /// [`Self::set_server_public_key`] ou [`Self::set_server_public_key_components`] antes do Estado 0.
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

    /// Reproduz `SHelper_RSession_CreateClient` (`shelper.dll!0x1006b860` -> `0x1006a690` -> `0x100660a7` -> `0x10065848`):
    /// recebe os 3 DWORDs de parâmetros do cliente e os bytes big-endian brutos do módulo (`n`) e expoente (`e`)
    /// da chave pública RSA-2048 do servidor.
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

    /// Cria um negociador no Estado `0` a partir de uma chave pública RSA-2048 já construída.
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

    /// Configura os 3 DWORDs enviados nos primeiros 12 bytes do bloco plaintext de 76 bytes (`+0x04..+0x0c`).
    pub fn set_client_params(&mut self, client_params: [u32; 3]) {
        self.client_params = client_params;
    }

    pub fn client_params(&self) -> [u32; 3] {
        self.client_params
    }

    /// Constrói e valida a chave pública RSA-2048 a partir do módulo e expoente big-endian
    /// (`shelper.dll!0x100660a7` -> `0x10065848`, `BN_bin2bn`).
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

    /// Define a chave pública RSA-2048 do servidor, exigindo tamanho de bloco de 256 bytes (2048 bits).
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

    /// Reproduz `SHelper_RSession_GetServerDataOnClient` (`shelper.dll!0x1006bbb0`):
    /// retorna o token de 4 bytes enviado pelo servidor somente se `is_established == true`.
    pub fn get_server_token(&self) -> Result<u32, HandshakeError> {
        if !self.is_established() {
            return Err(HandshakeError::SessionNotEstablished);
        }
        self.server_token
            .ok_or(HandshakeError::SessionNotEstablished)
    }

    /// Reproduz `SHelper_RSession_GetKey` (`shelper.dll!0x1006ba80` -> `0x1006a270`):
    /// verifica estritamente `is_established != 0` (`[ecx+0x10] != 0`) e retorna o buffer
    /// CSPRNG de 64 bytes (`0x40`) gerado no Estado 0.
    pub fn get_key(&self) -> Result<&[u8; RSESSION_KEY_MATERIAL_SIZE], HandshakeError> {
        if !self.is_established() {
            return Err(HandshakeError::SessionNotEstablished);
        }
        self.key_material
            .as_ref()
            .ok_or(HandshakeError::SessionNotEstablished)
    }

    /// Retorna uma referência direta à chave AES-256 de 32 bytes (`0x20`) nos primeiros 32 bytes do buffer de 64 bytes.
    pub fn derive_aes256_key_ref(&self) -> Result<&[u8; RSESSION_AES256_KEY_SIZE], HandshakeError> {
        let key_material = self.get_key()?;
        Ok(key_material[..RSESSION_AES256_KEY_SIZE]
            .try_into()
            .expect("slice length matches RSESSION_AES256_KEY_SIZE"))
    }

    /// Extrai a chave AES-256 de 32 bytes (`0x20`) a partir dos primeiros 32 bytes do buffer de 64 bytes
    /// de `SHelper_RSession_GetKey`, protegida por `Zeroizing`.
    ///
    /// Nunca confunde o token de 4 bytes do servidor com a chave AES de 32 bytes.
    pub fn derive_aes256_key(
        &self,
    ) -> Result<Zeroizing<[u8; RSESSION_AES256_KEY_SIZE]>, HandshakeError> {
        let key_ref = self.derive_aes256_key_ref()?;
        let mut aes_key = Zeroizing::new([0u8; RSESSION_AES256_KEY_SIZE]);
        aes_key.copy_from_slice(key_ref);
        Ok(aes_key)
    }

    /// Cria uma instância inicializada do [`FamatechCipherState`] (`SHelper_CChannel`) somente
    /// após a conclusão completa do handshake (`is_established == true`).
    pub fn create_cipher(&self) -> Result<FamatechCipherState, HandshakeError> {
        let key_material = self.get_key()?;
        Ok(FamatechCipherState::from_rsession_key(key_material))
    }

    /// Executa a máquina de estados `SHelper_RSession_GetNextBuffer` (`shelper.dll!0x1006a2b0`).
    ///
    /// - Em [`HandshakeStage::ClientState0Initial`] (`0x1006a512`):
    ///   - Exige `input` vazio/`None`.
    ///   - Monta o plaintext de 76 bytes (`12B` header LE + `64B` CSPRNG).
    ///   - Cifra com RSA-2048 `Padding::PKCS1` (`0x10065ec0`) em um bloco de 256 bytes (`0x100`).
    ///   - Transiciona para [`HandshakeStage::ClientState2WaitingServerToken`] com `is_complete = false`.
    /// - Em [`HandshakeStage::ClientState2WaitingServerToken`] (`0x1006a4cc`):
    ///   - Exige `input` com exatamente 4 bytes (`0x1006a4df: cmp in_len, 4; jne`).
    ///   - Armazena o token de 4 bytes do servidor (`+0x14`), marca `is_established = true` (`+0x10 = 1`)
    ///     e transiciona para [`HandshakeStage::State3Completed`] com `is_complete = true`.
    /// - Qualquer tamanho inválido ou chamada fora de ordem invalida o handshake (`Failed`) e
    ///   zera o material de chave.
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

                // 0x1006a56d: gera 64 bytes (0x40) CSPRNG via RAND_bytes (0x10063530)
                let mut key_material = [0u8; RSESSION_KEY_MATERIAL_SIZE];
                if let Err(e) = rand_bytes(&mut key_material) {
                    self.fail_and_clear();
                    return Err(HandshakeError::CsprngFailed(e.to_string()));
                }

                // 0x1006a522..0x1006a593: monta plaintext de 76 bytes (0x4c)
                // [0..4]: d0 LE, [4..8]: d1 LE, [8..12]: d2 LE, [12..76]: 64B CSPRNG
                let mut plaintext = [0u8; RSESSION_PLAINTEXT_SIZE];
                plaintext[0..4].copy_from_slice(&self.client_params[0].to_le_bytes());
                plaintext[4..8].copy_from_slice(&self.client_params[1].to_le_bytes());
                plaintext[8..12].copy_from_slice(&self.client_params[2].to_le_bytes());
                plaintext[RSESSION_CLIENT_HEADER_SIZE..RSESSION_PLAINTEXT_SIZE]
                    .copy_from_slice(&key_material);

                // 0x1006a59c -> 0x10065ca0 -> 0x10065ec0: RSA_public_encrypt com RSA_PKCS1_PADDING (1)
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
                // 0x1006a4cc..0x1006a4df: exige in_buf != NULL e in_len == 4
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
                // 0x1006a2ef / 0x1006a614: qualquer chamada fora dos estados válidos falha
                self.fail_and_clear();
                Err(HandshakeError::UnexpectedState(format!(
                    "GetNextBuffer inválido no estado {other:?}"
                )))
            }
        }
    }

    /// Zera o material de chave e invalida o estado (`shelper.dll!0x1006a730` `RSession_Destroy`).
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

/// Implementação fiel do lado servidor de `SHelper_RSession` (`shelper.dll!0x1006b8f0` / `0x1006a30c`).
///
/// Utilizada para verificação de ponta a ponta da máquina de estados RSA-2048 PKCS#1 v1.5
/// (`76B` plaintext -> `256B` RSA block -> `4B` server token -> `64B` key material -> `32B` AES-256 key).
///
/// # Ciclo de Vida e Segurança de Dados
/// - `key_material`: Segredo simétrico efêmero de 64 bytes gerado pelo cliente via CSPRNG e decifrado
///   pelo servidor. É zerado deterministicamente via `Zeroize::zeroize()` tanto na chamada a `clear()`
///   quanto automaticamente via `Drop`.
/// - `private_key`: Chave privada RSA-2048 de longo prazo da infraestrutura do servidor, gerenciada pela
///   estrutura `openssl::rsa::Rsa<Private>`. A liberação de seus limbs e estruturas internas em C é governada pelo
///   destrutor de `Rsa` que chama `RSA_free()`. Trata-se de credencial estática de serviço, não de segredo efêmero de sessão.
/// - `client_params`: Metadados públicos de negociação (3 DWORDs little-endian: flags de protocolo e versão).
/// - `server_token`: Nonce de 4 bytes público transmitido em texto plano no Step 2.
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
    /// Reproduz `SHelper_RSession_CreateServer` (`shelper.dll!0x1006b8f0` -> `0x1006a780`):
    /// inicializa no Estado `1` (`ServerState1WaitingClientBlock`) com o token de 4 bytes do servidor
    /// e a chave privada RSA-2048.
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

    /// Reproduz `SHelper_RSession_GetClientDataOnServer` (`shelper.dll!0x1006bc30`):
    /// retorna os 3 DWORDs recebidos do cliente somente se `is_established == true`.
    pub fn get_client_params(&self) -> Result<[u32; 3], HandshakeError> {
        if !self.is_established() {
            return Err(HandshakeError::SessionNotEstablished);
        }
        self.client_params
            .ok_or(HandshakeError::SessionNotEstablished)
    }

    /// Reproduz `SHelper_RSession_GetKey` (`shelper.dll!0x1006ba80` -> `0x1006a270`).
    pub fn get_key(&self) -> Result<&[u8; RSESSION_KEY_MATERIAL_SIZE], HandshakeError> {
        if !self.is_established() {
            return Err(HandshakeError::SessionNotEstablished);
        }
        self.key_material
            .as_ref()
            .ok_or(HandshakeError::SessionNotEstablished)
    }

    /// Retorna uma referência direta à chave AES-256 de 32 bytes (`0..32`) no buffer de 64 bytes.
    pub fn derive_aes256_key_ref(&self) -> Result<&[u8; RSESSION_AES256_KEY_SIZE], HandshakeError> {
        let key_material = self.get_key()?;
        Ok(key_material[..RSESSION_AES256_KEY_SIZE]
            .try_into()
            .expect("slice length matches RSESSION_AES256_KEY_SIZE"))
    }

    /// Extrai a chave AES-256 de 32 bytes (`0..32`) do buffer de 64 bytes (`RvROLClient.dll!0x100df250`), protegida por `Zeroizing`.
    pub fn derive_aes256_key(
        &self,
    ) -> Result<Zeroizing<[u8; RSESSION_AES256_KEY_SIZE]>, HandshakeError> {
        let key_ref = self.derive_aes256_key_ref()?;
        let mut aes_key = Zeroizing::new([0u8; RSESSION_AES256_KEY_SIZE]);
        aes_key.copy_from_slice(key_ref);
        Ok(aes_key)
    }

    /// Cria o [`FamatechCipherState`] do servidor com a chave negociada.
    pub fn create_cipher(&self) -> Result<FamatechCipherState, HandshakeError> {
        let key_material = self.get_key()?;
        Ok(FamatechCipherState::from_rsession_key(key_material))
    }

    /// Executa o Estado `1` do servidor em `SHelper_RSession_GetNextBuffer` (`shelper.dll!0x1006a30c`).
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

                // 0x1006a354 -> 0x10065bc7 -> 0x10065de8: RSA_private_decrypt com RSA_PKCS1_PADDING (1)
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

                // 0x1006a36d: cmp dword ptr [ebp-0x10], 0x4c; jne 0x1006a4c2
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

                let mut key_material = [0u8; RSESSION_KEY_MATERIAL_SIZE];
                key_material.copy_from_slice(
                    &decrypted[RSESSION_CLIENT_HEADER_SIZE..RSESSION_PLAINTEXT_SIZE],
                );

                self.client_params = Some([d0, d1, d2]);
                self.key_material = Some(key_material);
                self.is_established = true;
                self.stage = HandshakeStage::State3Completed;

                // 0x1006a472..0x1006a49b: retorna o token de 4 bytes do servidor em little-endian
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

    /// Zera o material de chave simétrica da sessão e invalida o estado da sessão
    /// (`shelper.dll!0x1006a730` `RSession_Destroy`).
    ///
    /// Esta operação é estritamente idempotente: invocações repetidas (incluindo uma chamada explícita
    /// seguida do `Drop` automático) são seguras e não causam pânicos ou comportamentos indefinidos.
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

        // Passo 1 (Estado 0 -> Estado 2): cliente gera o bloco RSA de 256 bytes (76B plaintext)
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

        // Passo 2 (Servidor Estado 1 -> Estado 3): servidor decifra os 256B, valida 76B (0x4c),
        // extrai os 3 DWORDs + 64B CSPRNG e emite o token de 4 bytes
        let srv_step = server.get_next_buffer(Some(&client_pkt)).unwrap();
        assert!(srv_step.is_complete);
        assert!(server.is_established());
        assert_eq!(server.stage(), HandshakeStage::State3Completed);
        assert_eq!(server.get_client_params().unwrap(), client_params);

        let token_pkt = srv_step.output.expect("Estado 1 deve emitir token de 4B");
        assert_eq!(token_pkt.len(), RSESSION_SERVER_TOKEN_SIZE);
        assert_eq!(token_pkt, expected_server_token.to_le_bytes());

        // Passo 3 (Cliente Estado 2 -> Estado 3): cliente processa o token de 4 bytes
        let step2 = client.get_next_buffer(Some(&token_pkt)).unwrap();
        assert!(step2.is_complete);
        assert!(step2.output.is_none());
        assert!(client.is_established());
        assert_eq!(client.stage(), HandshakeStage::State3Completed);
        assert_eq!(client.get_server_token().unwrap(), expected_server_token);

        // Valida que o material de chave de 64B e a chave AES-256 de 32B coincidem entre cliente e servidor
        // e NÃO se confundem com o token de 4 bytes do servidor
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

        // Valida comunicação criptografada bidirecional via SHelper_CChannel (FamatechCipherState)
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

        // 1. Entrada não vazia no Estado 0 deve falhar
        let mut client =
            HandshakeNegotiator::create_client([1, 2, 3], &modulus, &exponent).unwrap();
        let err = client
            .get_next_buffer(Some(&[0x01, 0x02, 0x03, 0x04]))
            .unwrap_err();
        assert_eq!(err, HandshakeError::UnexpectedInputInState0 { len: 4 });
        assert_eq!(client.stage(), HandshakeStage::Failed);

        // 2. Chamada adicional após conclusão (Estado 3) deve falhar e invalidar
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

        // 1. Bloco RSA cifrando 32 bytes em vez de 76 bytes (0x4c) deve ser rejeitado em 0x1006a36d
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

        // 2. Bloco RSA de tamanho truncado (< 256 bytes) deve ser rejeitado
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
            // Ao sair do escopo, Drop é invocado automaticamente, limpando key_material
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
            // Drop de server com sessão estabelecida
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

            // 1. Invocação explícita de clear()
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

            // 2. Segunda chamada explícita para provar idempotência
            server.clear();
            assert!(!server.is_established());

            // 3. Ao sair do escopo, Drop é invocado novamente sobre a instância já limpa
        }
        let final_count = RSessionServer::test_cleanup_count();
        // 2 chamadas explícitas + 1 chamada no Drop = 3
        assert_eq!(final_count, initial_count + 3);
    }

    #[test]
    fn test_rsession_server_drop_after_processing_failure() {
        let (rsa, _, _) = generate_test_server_rsa();
        let initial_count = RSessionServer::test_cleanup_count();
        {
            let mut server = RSessionServer::create_server(0x7777, rsa).unwrap();
            // Bloco RSA corrompido com tamanho incorreto (128 bytes em vez de 256)
            let bad_input = [0xAAu8; 128];
            let res = server.get_next_buffer(Some(&bad_input));
            assert!(res.is_err());
            assert_eq!(server.stage(), HandshakeStage::Failed);
            assert!(!server.is_established());
            assert!(server.get_key().is_err());
            // Drop de server após transição para Failed
        }
        let final_count = RSessionServer::test_cleanup_count();
        // 1 em fail_and_clear + 1 no Drop = 2
        assert_eq!(final_count, initial_count + 2);
    }
}
