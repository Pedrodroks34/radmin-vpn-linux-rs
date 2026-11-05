
use crate::crypto::famatech::{FamatechCipherState, AES_256_KEY_SIZE};
use openssl::bn::{BigNum, BigNumContext};
use openssl::rand::rand_bytes;
use openssl::sha::sha1;
use std::ops::{Deref, DerefMut};
use thiserror::Error;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

pub const SHELPER_PROTOCOL_VERSION: u32 = 3;

pub const RADMIN_SRP1536_MODULUS_LEN: usize = 192;

pub const RADMIN_SRP_GENERATOR: u8 = 5;

pub const RADMIN_SRP_K: u32 = 3;

pub const RADMIN_SRP_DIGEST_LEN: usize = 20;

pub const RADMIN_SRP_KDF_KEY_LEN: usize = 40;

pub const CONTROL_SESSION_KEY_SIZE: usize = AES_256_KEY_SIZE;


pub const TAG_STEP: u32 = 0x10000000;

pub const TAG_IDENTITY: u32 = 0x20000000;

pub const TAG_SALT: u32 = 0x30000000;

pub const TAG_MODULUS: u32 = 0x40000000;

pub const TAG_GENERATOR: u32 = 0x50000000;

pub const TAG_PUBLIC_EPHEMERAL: u32 = 0x60000000;

pub const TAG_PROOF: u32 = 0x70000000;

pub const RADMIN_SRP1536_PRIME_HEX: &str = "\
e634471e75f2d76a0a3f5e252c5a6efb48edad645d31d9ecbc400416e14f5c6c\
2ed378602d6eb8e9478b99e6474932393538b4be7177e0e05d3aaed17b5ae87a\
a20f3dad37af019518f45b6dde76b2bfdfb140f379cc15383b304b7975b90796\
7553cd6fdaf08d68832b603120430a501067d21beb2ce2275a20036a2dc80f1c\
9d3ab9221afd5baceda5c2a31077c54fc6f274aaeba17ddd0b5c68f4f8e751a8\
90a58648147a82e6f4f532ccdc939a12942799a713500e17dd4f6ff216cd54c7";


#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlHandshakeError {
    #[error("versão de protocolo incompatível: esperado {expected}, recebido {got}")]
    InvalidProtocolVersion { expected: u32, got: u32 },

    #[error("tamanho do payload do item TLV excede o limite de 27 bits (0x07FFFFFF): {0}")]
    PayloadTooLarge(usize),

    #[error("buffer truncado ou insuficiente para decodificar item TLV no offset {0}")]
    TruncatedItemBuffer(usize),

    #[error("passo inesperado no handshake de controle: esperado {expected}, recebido {got}")]
    UnexpectedStep { expected: u32, got: u32 },

    #[error("tag obrigatória ausente no frame de controle: {tag:#010x}")]
    MissingRequiredTag { tag: u32 },

    #[error("comprimento de tag inválido para {tag:#010x}: esperado {expected}, recebido {got}")]
    InvalidTagLength {
        tag: u32,
        expected: usize,
        got: usize,
    },

    #[error("parâmetros de grupo SRP incompatíveis (módulo N ou gerador g inválidos)")]
    InvalidGroupParameters,

    #[error("chave efêmera pública do par é inválida (A mod N == 0 ou B mod N == 0)")]
    InvalidPublicEphemeral,

    #[error("falha na verificação da prova criptográfica SRP (M1 ou M2 incorreto)")]
    ProofVerificationFailed,

    #[error("operação inválida no estado atual do handshake: {0}")]
    InvalidState(String),

    #[error("falha no cálculo criptográfico com OpenSSL BigNum: {0}")]
    CryptoError(String),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlItem {
    pub tag: u32,
    pub payload: Vec<u8>,
}

impl ControlItem {
    pub fn new(tag: u32, payload: Vec<u8>) -> Self {
        Self { tag, payload }
    }
}

pub fn encode_item(tag: u32, payload: &[u8]) -> Result<Vec<u8>, ControlHandshakeError> {
    if payload.len() > 0x07FF_FFFF {
        return Err(ControlHandshakeError::PayloadTooLarge(payload.len()));
    }
    let header_val = (tag & 0xF800_0000) | (payload.len() as u32 & 0x07FF_FFFF);
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&header_val.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_items(buf: &[u8]) -> Result<Vec<ControlItem>, ControlHandshakeError> {
    let mut items = Vec::new();
    let mut offset = 0;

    while offset < buf.len() {
        if offset + 4 > buf.len() {
            return Err(ControlHandshakeError::TruncatedItemBuffer(offset));
        }

        let header_val = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        let tag = header_val & 0xF800_0000;
        let length = (header_val & 0x07FF_FFFF) as usize;

        if offset + 4 + length > buf.len() {
            return Err(ControlHandshakeError::TruncatedItemBuffer(offset));
        }

        let payload = buf[offset + 4..offset + 4 + length].to_vec();
        items.push(ControlItem { tag, payload });
        offset += 4 + length;
    }

    Ok(items)
}

pub fn find_item(items: &[ControlItem], tag: u32) -> Option<&[u8]> {
    items
        .iter()
        .find(|item| item.tag == tag)
        .map(|item| item.payload.as_slice())
}

pub fn encode_identity(username: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(username.len() * 2);
    for c in username.encode_utf16() {
        out.push((c >> 8) as u8);
        out.push((c & 0xFF) as u8);
    }
    out
}

#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn decode_identity(payload: &[u8]) -> String {
    if !payload.len().is_multiple_of(2) {
        return String::from_utf8_lossy(payload).to_string();
    }
    let u16_chars: Vec<u16> = payload
        .chunks_exact(2)
        .map(|chunk| ((chunk[0] as u16) << 8) | (chunk[1] as u16))
        .collect();
    String::from_utf16_lossy(&u16_chars)
}


pub struct SecretBigNum(pub BigNum);

impl Deref for SecretBigNum {
    type Target = BigNum;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretBigNum {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
thread_local! {
    static THREAD_SECRET_BIGNUM_DROP_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Drop for SecretBigNum {
    fn drop(&mut self) {
        self.0.clear();
        #[cfg(test)]
        THREAD_SECRET_BIGNUM_DROP_COUNT.with(|c| c.set(c.get() + 1));
    }
}

#[cfg(test)]
impl SecretBigNum {
    pub(crate) fn test_drop_count() -> usize {
        THREAD_SECRET_BIGNUM_DROP_COUNT.with(|c| c.get())
    }
}

impl std::fmt::Debug for SecretBigNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED SecretBigNum]")
    }
}

impl PartialEq for SecretBigNum {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for SecretBigNum {}

impl PartialOrd for SecretBigNum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SecretBigNum {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialEq<BigNum> for SecretBigNum {
    fn eq(&self, other: &BigNum) -> bool {
        &self.0 == other
    }
}

impl PartialOrd<BigNum> for SecretBigNum {
    fn partial_cmp(&self, other: &BigNum) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl SecretBigNum {
    pub fn new() -> Result<Self, ControlHandshakeError> {
        BigNum::new()
            .map(SecretBigNum)
            .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao criar BN: {e}")))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, ControlHandshakeError> {
        BigNum::from_slice(slice)
            .map(SecretBigNum)
            .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao carregar BN: {e}")))
    }

    pub fn from_u32(val: u32) -> Result<Self, ControlHandshakeError> {
        BigNum::from_u32(val).map(SecretBigNum).map_err(|e| {
            ControlHandshakeError::CryptoError(format!("falha ao criar BN de u32: {e}"))
        })
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}


pub fn get_srp_prime_n() -> Result<BigNum, ControlHandshakeError> {
    BigNum::from_hex_str(RADMIN_SRP1536_PRIME_HEX)
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao carregar primo N: {e}")))
}

pub fn compute_srp_x(
    username: &str,
    password: &str,
    salt: &[u8],
) -> Result<SecretBigNum, ControlHandshakeError> {
    let mut cred_buf = Zeroizing::new(Vec::with_capacity(username.len() + 1 + password.len()));
    cred_buf.extend_from_slice(username.as_bytes());
    cred_buf.push(b':');
    cred_buf.extend_from_slice(password.as_bytes());
    let h1 = Zeroizing::new(sha1(&cred_buf));

    let mut x_buf = Zeroizing::new(Vec::with_capacity(salt.len() + h1.len()));
    x_buf.extend_from_slice(salt);
    x_buf.extend_from_slice(&*h1);
    let x_bytes = Zeroizing::new(sha1(&x_buf));

    SecretBigNum::from_slice(&*x_bytes)
}

pub fn pad_bignum_bytes(bytes: &[u8], target_len: usize) -> Vec<u8> {
    if bytes.len() >= target_len {
        bytes.to_vec()
    } else {
        let mut padded = vec![0u8; target_len - bytes.len()];
        padded.extend_from_slice(bytes);
        padded
    }
}

pub fn random_srp_exponent(prime_n: &BigNum) -> Result<SecretBigNum, ControlHandshakeError> {
    let one = BigNum::from_u32(1)
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao criar BN 1: {e}")))?;
    let mut n_minus_1 = BigNum::new().map_err(|e| {
        ControlHandshakeError::CryptoError(format!("falha ao criar BN n_minus_1: {e}"))
    })?;
    n_minus_1
        .checked_sub(prime_n, &one)
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao calcular N - 1: {e}")))?;

    for _ in 0..128 {
        let mut buf = Zeroizing::new([0u8; RADMIN_SRP1536_MODULUS_LEN]);
        rand_bytes(&mut *buf).map_err(|e| {
            ControlHandshakeError::CryptoError(format!("falha no CSPRNG ao gerar expoente: {e}"))
        })?;

        let candidate = SecretBigNum::from_slice(&*buf)?;

        if *candidate > one && *candidate < n_minus_1 {
            return Ok(candidate);
        }
    }

    Err(ControlHandshakeError::CryptoError(
        "limite de tentativas excedido ao gerar expoente SRP".to_string(),
    ))
}

pub fn validate_srp_public_value(
    bytes: &[u8],
    prime_n: &BigNum,
) -> Result<BigNum, ControlHandshakeError> {
    if bytes.len() != RADMIN_SRP1536_MODULUS_LEN {
        warn!(
            got_len = bytes.len(),
            expected_len = RADMIN_SRP1536_MODULUS_LEN,
            "validate_srp_public_value: tamanho inválido para chave pública SRP"
        );
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    let val = BigNum::from_slice(bytes).map_err(|e| {
        ControlHandshakeError::CryptoError(format!("falha ao carregar BigNum público: {e}"))
    })?;

    if val.num_bits() == 0 {
        warn!("validate_srp_public_value: valor público é zero");
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    if &val >= prime_n {
        warn!("validate_srp_public_value: valor público fora do domínio (val >= N)");
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    let mut ctx = BigNumContext::new()
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em BN ctx: {e}")))?;
    let mut rem = BigNum::new()
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em BN rem: {e}")))?;
    rem.nnmod(&val, prime_n, &mut ctx)
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao calcular nnmod: {e}")))?;
    if rem.num_bits() == 0 {
        warn!("validate_srp_public_value: val mod N == 0");
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    Ok(val)
}

pub fn compute_srp_u(
    a_bytes: &[u8],
    b_bytes: &[u8],
) -> Result<(BigNum, [u8; 20]), ControlHandshakeError> {
    let pad_a = pad_bignum_bytes(a_bytes, RADMIN_SRP1536_MODULUS_LEN);
    let pad_b = pad_bignum_bytes(b_bytes, RADMIN_SRP1536_MODULUS_LEN);

    let mut buf = Vec::with_capacity(pad_a.len() + pad_b.len());
    buf.extend_from_slice(&pad_a);
    buf.extend_from_slice(&pad_b);
    let digest = sha1(&buf);

    let bn = BigNum::from_slice(&digest)
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em BN para u: {e}")))?;
    Ok((bn, digest))
}

pub fn compute_srp_kdf(s_bytes: &[u8]) -> [u8; RADMIN_SRP_KDF_KEY_LEN] {
    let mut out = [0u8; RADMIN_SRP_KDF_KEY_LEN];

    let mut buf0 = Zeroizing::new(Vec::with_capacity(s_bytes.len() + 4));
    buf0.extend_from_slice(s_bytes);
    buf0.extend_from_slice(&0u32.to_be_bytes());
    let k0 = Zeroizing::new(sha1(&buf0));

    let mut buf1 = Zeroizing::new(Vec::with_capacity(s_bytes.len() + 4));
    buf1.extend_from_slice(s_bytes);
    buf1.extend_from_slice(&1u32.to_be_bytes());
    let k1 = Zeroizing::new(sha1(&buf1));

    out[..20].copy_from_slice(&*k0);
    out[20..40].copy_from_slice(&*k1);
    out
}

pub fn compute_srp_m1(
    n_bytes: &[u8],
    g_byte: u8,
    username: &str,
    salt: &[u8],
    a_bytes: &[u8],
    b_bytes: &[u8],
    k_full: &[u8; RADMIN_SRP_KDF_KEY_LEN],
) -> [u8; RADMIN_SRP_DIGEST_LEN] {
    let h_n = sha1(n_bytes);
    let h_g = sha1(&[g_byte]);

    let mut h_xor = [0u8; 20];
    for i in 0..20 {
        h_xor[i] = h_n[i] ^ h_g[i];
    }

    let h_i = sha1(username.as_bytes());

    let mut buf = Zeroizing::new(Vec::new());
    buf.extend_from_slice(&h_xor);
    buf.extend_from_slice(&h_i);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(a_bytes);
    buf.extend_from_slice(b_bytes);
    buf.extend_from_slice(k_full);

    sha1(&buf)
}

pub fn compute_srp_m2(
    a_bytes: &[u8],
    m1: &[u8; RADMIN_SRP_DIGEST_LEN],
    k_full: &[u8; RADMIN_SRP_KDF_KEY_LEN],
) -> [u8; RADMIN_SRP_DIGEST_LEN] {
    let mut buf = Zeroizing::new(Vec::with_capacity(a_bytes.len() + m1.len() + k_full.len()));
    buf.extend_from_slice(a_bytes);
    buf.extend_from_slice(m1);
    buf.extend_from_slice(k_full);
    sha1(&buf)
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlStepOutput {
    pub buffer_to_send: Option<Vec<u8>>,
    pub is_complete: bool,
}

pub enum ControlClientState {
    State0Initial,
    State2WaitingServerParams,
    State4WaitingServerEphemeral {
        a_secret: SecretBigNum,
        a_public_bytes: Vec<u8>,
        salt: Zeroizing<Vec<u8>>,
        x_secret: SecretBigNum,
    },
    State6WaitingServerProof {
        a_public_bytes: Vec<u8>,
        m1_proof: Zeroizing<[u8; RADMIN_SRP_DIGEST_LEN]>,
        k_full: Zeroizing<[u8; RADMIN_SRP_KDF_KEY_LEN]>,
    },
    Established {
        session_key: Zeroizing<[u8; CONTROL_SESSION_KEY_SIZE]>,
        k_full: Zeroizing<[u8; RADMIN_SRP_KDF_KEY_LEN]>,
    },
    Failed(String),
}

impl std::fmt::Debug for ControlClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State0Initial => write!(f, "ControlClientState::State0Initial"),
            Self::State2WaitingServerParams => {
                write!(f, "ControlClientState::State2WaitingServerParams")
            }
            Self::State4WaitingServerEphemeral { a_public_bytes, .. } => f
                .debug_struct("ControlClientState::State4WaitingServerEphemeral")
                .field("a_secret", &"[REDACTED]")
                .field("a_public_bytes_len", &a_public_bytes.len())
                .field("salt", &"[REDACTED]")
                .field("x_secret", &"[REDACTED]")
                .finish(),
            Self::State6WaitingServerProof { a_public_bytes, .. } => f
                .debug_struct("ControlClientState::State6WaitingServerProof")
                .field("a_public_bytes_len", &a_public_bytes.len())
                .field("m1_proof", &"[REDACTED]")
                .field("k_full", &"[REDACTED]")
                .finish(),
            Self::Established { .. } => f
                .debug_struct("ControlClientState::Established")
                .field("session_key", &"[REDACTED]")
                .field("k_full", &"[REDACTED]")
                .finish(),
            Self::Failed(reason) => f
                .debug_tuple("ControlClientState::Failed")
                .field(reason)
                .finish(),
        }
    }
}

impl ControlClientState {
    pub fn clear(&mut self) {
        match self {
            ControlClientState::State4WaitingServerEphemeral {
                a_secret,
                a_public_bytes,
                salt,
                x_secret,
            } => {
                a_secret.0.clear();
                a_public_bytes.zeroize();
                salt.zeroize();
                x_secret.0.clear();
            }
            ControlClientState::State6WaitingServerProof {
                a_public_bytes,
                m1_proof,
                k_full,
            } => {
                a_public_bytes.zeroize();
                m1_proof.zeroize();
                k_full.zeroize();
            }
            ControlClientState::Established {
                session_key,
                k_full,
            } => {
                session_key.zeroize();
                k_full.zeroize();
            }
            _ => {}
        }
    }
}

pub struct ControlClientNegotiator {
    username: String,
    password: Zeroizing<String>,
    state: ControlClientState,
    version_exchanged: bool,
}

impl std::fmt::Debug for ControlClientNegotiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlClientNegotiator")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("state", &self.state)
            .field("version_exchanged", &self.version_exchanged)
            .finish()
    }
}

impl Drop for ControlClientNegotiator {
    fn drop(&mut self) {
        self.clear();
    }
}

impl ControlClientNegotiator {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password: Zeroizing::new(password),
            state: ControlClientState::State0Initial,
            version_exchanged: false,
        }
    }

    pub fn state(&self) -> &ControlClientState {
        &self.state
    }

    pub fn clear(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.state.clear();
    }

    pub fn is_version_exchanged(&self) -> bool {
        self.version_exchanged
    }

    pub fn create_version_packet() -> [u8; 4] {
        SHELPER_PROTOCOL_VERSION.to_le_bytes()
    }

    pub fn process_version_response(
        &mut self,
        response: &[u8],
    ) -> Result<(), ControlHandshakeError> {
        if response.len() < 4 {
            return Err(ControlHandshakeError::TruncatedItemBuffer(0));
        }
        let version = u32::from_le_bytes([response[0], response[1], response[2], response[3]]);
        if version != SHELPER_PROTOCOL_VERSION {
            return Err(ControlHandshakeError::InvalidProtocolVersion {
                expected: SHELPER_PROTOCOL_VERSION,
                got: version,
            });
        }
        self.version_exchanged = true;
        Ok(())
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, ControlClientState::Established { .. })
    }

    pub fn session_key_ref(&self) -> Option<&[u8; CONTROL_SESSION_KEY_SIZE]> {
        match &self.state {
            ControlClientState::Established { session_key, .. } => Some(&**session_key),
            _ => None,
        }
    }

    pub fn session_key(&self) -> Option<Zeroizing<[u8; CONTROL_SESSION_KEY_SIZE]>> {
        match &self.state {
            ControlClientState::Established { session_key, .. } => Some(session_key.clone()),
            _ => None,
        }
    }

    pub fn create_cipher_state(&self) -> Result<FamatechCipherState, ControlHandshakeError> {
        let key = match &self.state {
            ControlClientState::Established { session_key, .. } => session_key,
            _ => {
                return Err(ControlHandshakeError::InvalidState(
                    "tentativa de obter cipher state antes do handshake concluído".into(),
                ))
            }
        };
        Ok(FamatechCipherState::from_key_ref(key))
    }

    pub fn step(
        &mut self,
        in_buf: Option<&[u8]>,
    ) -> Result<ControlStepOutput, ControlHandshakeError> {
        match self.step_inner(in_buf) {
            Ok(output) => Ok(output),
            Err(e) => {
                self.state = ControlClientState::Failed(e.to_string());
                Err(e)
            }
        }
    }

    fn step_inner(
        &mut self,
        in_buf: Option<&[u8]>,
    ) -> Result<ControlStepOutput, ControlHandshakeError> {
        match std::mem::replace(
            &mut self.state,
            ControlClientState::Failed("transição interrompida".into()),
        ) {
            ControlClientState::State0Initial => {
                if in_buf.is_some() {
                    self.state = ControlClientState::Failed(
                        "State0Initial requer entrada vazia (None)".into(),
                    );
                    return Err(ControlHandshakeError::InvalidState(
                        "entrada fornecida no Estado 0 inicial".into(),
                    ));
                }

                let item_step = encode_item(TAG_STEP, &1u32.to_le_bytes())?;
                let identity_bytes = encode_identity(&self.username);
                let item_identity = encode_item(TAG_IDENTITY, &identity_bytes)?;

                let mut out_buf = Vec::with_capacity(item_step.len() + item_identity.len());
                out_buf.extend_from_slice(&item_step);
                out_buf.extend_from_slice(&item_identity);

                self.state = ControlClientState::State2WaitingServerParams;
                debug!(
                    username = %self.username,
                    bytes_len = out_buf.len(),
                    "ControlClient: emitido Step 1 (identidade)"
                );

                Ok(ControlStepOutput {
                    buffer_to_send: Some(out_buf),
                    is_complete: false,
                })
            }

            ControlClientState::State2WaitingServerParams => {
                let data = in_buf.ok_or_else(|| {
                    ControlHandshakeError::InvalidState("State2 requer dados do servidor".into())
                })?;

                let items = decode_items(data)?;

                let step_bytes = find_item(&items, TAG_STEP)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_STEP })?;
                if step_bytes.len() < 4 {
                    return Err(ControlHandshakeError::InvalidTagLength {
                        tag: TAG_STEP,
                        expected: 4,
                        got: step_bytes.len(),
                    });
                }
                let step = u32::from_le_bytes([
                    step_bytes[0],
                    step_bytes[1],
                    step_bytes[2],
                    step_bytes[3],
                ]);
                if step != 2 {
                    return Err(ControlHandshakeError::UnexpectedStep {
                        expected: 2,
                        got: step,
                    });
                }

                let salt = find_item(&items, TAG_SALT)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_SALT })?
                    .to_vec();

                let n_bytes = find_item(&items, TAG_MODULUS)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_MODULUS })?;
                let g_bytes = find_item(&items, TAG_GENERATOR)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_GENERATOR })?;

                if n_bytes.len() != RADMIN_SRP1536_MODULUS_LEN {
                    warn!(
                        got_len = n_bytes.len(),
                        expected_len = RADMIN_SRP1536_MODULUS_LEN,
                        "ControlClient: comprimento do módulo N inválido (esperado exatamente 192 bytes)"
                    );
                    return Err(ControlHandshakeError::InvalidGroupParameters);
                }

                let expected_n = get_srp_prime_n()?;
                let received_n = BigNum::from_slice(n_bytes).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("módulo N inválido: {e}"))
                })?;

                if received_n != expected_n {
                    warn!("ControlClient: módulo N recebido diverge do hardcoded oficial");
                    return Err(ControlHandshakeError::InvalidGroupParameters);
                }

                if g_bytes.len() != 1 || g_bytes[0] != RADMIN_SRP_GENERATOR {
                    warn!(
                        got = ?g_bytes,
                        expected = RADMIN_SRP_GENERATOR,
                        "ControlClient: gerador g diverge do oficial (deve ter 1 byte e valor 5)"
                    );
                    return Err(ControlHandshakeError::InvalidGroupParameters);
                }

                let x = compute_srp_x(&self.username, &self.password, &salt)?;

                let mut ctx = BigNumContext::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha ao criar BN Context: {e}"))
                })?;

                let a_secret = random_srp_exponent(&expected_n)?;

                let g_bn = BigNum::from_u32(RADMIN_SRP_GENERATOR as u32).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN g: {e}"))
                })?;

                let mut a_public = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN A: {e}"))
                })?;
                a_public
                    .mod_exp(&g_bn, &a_secret, &expected_n, &mut ctx)
                    .map_err(|e| {
                        ControlHandshakeError::CryptoError(format!("falha em mod_exp A: {e}"))
                    })?;

                let a_public_vec = pad_bignum_bytes(&a_public.to_vec(), RADMIN_SRP1536_MODULUS_LEN);

                let item_step3 = encode_item(TAG_STEP, &3u32.to_le_bytes())?;
                let item_a = encode_item(TAG_PUBLIC_EPHEMERAL, &a_public_vec)?;

                let mut out_buf = Vec::with_capacity(item_step3.len() + item_a.len());
                out_buf.extend_from_slice(&item_step3);
                out_buf.extend_from_slice(&item_a);

                self.state = ControlClientState::State4WaitingServerEphemeral {
                    a_secret,
                    a_public_bytes: a_public_vec,
                    salt: Zeroizing::new(salt),
                    x_secret: x,
                };

                debug!("ControlClient: emitido Step 3 (A: 192 bytes)");
                Ok(ControlStepOutput {
                    buffer_to_send: Some(out_buf),
                    is_complete: false,
                })
            }

            ControlClientState::State4WaitingServerEphemeral {
                a_secret,
                a_public_bytes,
                salt,
                x_secret,
            } => {
                let data = in_buf.ok_or_else(|| {
                    ControlHandshakeError::InvalidState(
                        "State4 requer dados de efêmera do servidor".into(),
                    )
                })?;

                let items = decode_items(data)?;

                let step_bytes = find_item(&items, TAG_STEP)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_STEP })?;
                if step_bytes.len() < 4 {
                    return Err(ControlHandshakeError::InvalidTagLength {
                        tag: TAG_STEP,
                        expected: 4,
                        got: step_bytes.len(),
                    });
                }
                let step = u32::from_le_bytes([
                    step_bytes[0],
                    step_bytes[1],
                    step_bytes[2],
                    step_bytes[3],
                ]);
                if step != 4 {
                    return Err(ControlHandshakeError::UnexpectedStep {
                        expected: 4,
                        got: step,
                    });
                }

                let b_bytes = find_item(&items, TAG_PUBLIC_EPHEMERAL).ok_or(
                    ControlHandshakeError::MissingRequiredTag {
                        tag: TAG_PUBLIC_EPHEMERAL,
                    },
                )?;

                let prime_n = get_srp_prime_n()?;
                let mut ctx = BigNumContext::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN ctx: {e}"))
                })?;

                let b_public = validate_srp_public_value(b_bytes, &prime_n)?;

                let (u_bn, _u_bytes) = compute_srp_u(&a_public_bytes, b_bytes)?;

                let g_bn = BigNum::from_u32(RADMIN_SRP_GENERATOR as u32).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN g: {e}"))
                })?;
                let mut v = SecretBigNum::new()?;
                v.mod_exp(&g_bn, &x_secret, &prime_n, &mut ctx)
                    .map_err(|e| {
                        ControlHandshakeError::CryptoError(format!("falha em mod_exp v: {e}"))
                    })?;

                let k_bn = BigNum::from_u32(RADMIN_SRP_K).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN k: {e}"))
                })?;
                let mut kv = SecretBigNum::new()?;
                kv.mod_mul(&k_bn, &v, &prime_n, &mut ctx).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em mod_mul kv: {e}"))
                })?;

                let mut base = SecretBigNum::new()?;
                base.mod_sub(&b_public, &kv, &prime_n, &mut ctx)
                    .map_err(|e| {
                        ControlHandshakeError::CryptoError(format!("falha em mod_sub base: {e}"))
                    })?;
                if base.num_bits() == 0 {
                    warn!("ControlClient: base (B - k*v) mod N == 0 (abortando handshake)");
                    return Err(ControlHandshakeError::InvalidPublicEphemeral);
                }

                let mut ux = SecretBigNum::new()?;
                ux.checked_mul(&u_bn, &x_secret, &mut ctx).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em mul: {e}"))
                })?;

                let mut exp = SecretBigNum::new()?;
                exp.checked_add(&a_secret, &ux).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em add: {e}"))
                })?;

                let mut s = SecretBigNum::new()?;
                s.mod_exp(&base, &exp, &prime_n, &mut ctx).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em mod_exp S: {e}"))
                })?;

                let s_bytes =
                    Zeroizing::new(pad_bignum_bytes(&s.to_vec(), RADMIN_SRP1536_MODULUS_LEN));

                let k_full = Zeroizing::new(compute_srp_kdf(&s_bytes));

                let n_vec = prime_n.to_vec();
                let m1 = Zeroizing::new(compute_srp_m1(
                    &n_vec,
                    RADMIN_SRP_GENERATOR,
                    &self.username,
                    &salt,
                    &a_public_bytes,
                    b_bytes,
                    &k_full,
                ));

                let item_step5 = encode_item(TAG_STEP, &5u32.to_le_bytes())?;
                let item_m1 = encode_item(TAG_PROOF, &*m1)?;

                let mut out_buf = Vec::with_capacity(item_step5.len() + item_m1.len());
                out_buf.extend_from_slice(&item_step5);
                out_buf.extend_from_slice(&item_m1);

                self.state = ControlClientState::State6WaitingServerProof {
                    a_public_bytes,
                    m1_proof: m1,
                    k_full,
                };

                debug!("ControlClient: emitido Step 5 (M1: 20 bytes)");
                Ok(ControlStepOutput {
                    buffer_to_send: Some(out_buf),
                    is_complete: false,
                })
            }

            ControlClientState::State6WaitingServerProof {
                a_public_bytes,
                m1_proof,
                k_full,
            } => {
                let data = in_buf.ok_or_else(|| {
                    ControlHandshakeError::InvalidState(
                        "State6 requer prova do servidor (M2)".into(),
                    )
                })?;

                let items = decode_items(data)?;

                let step_bytes = find_item(&items, TAG_STEP)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_STEP })?;
                if step_bytes.len() < 4 {
                    return Err(ControlHandshakeError::InvalidTagLength {
                        tag: TAG_STEP,
                        expected: 4,
                        got: step_bytes.len(),
                    });
                }
                let step = u32::from_le_bytes([
                    step_bytes[0],
                    step_bytes[1],
                    step_bytes[2],
                    step_bytes[3],
                ]);
                if step != 6 {
                    return Err(ControlHandshakeError::UnexpectedStep {
                        expected: 6,
                        got: step,
                    });
                }

                let m2_received = find_item(&items, TAG_PROOF)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_PROOF })?;
                if m2_received.len() != RADMIN_SRP_DIGEST_LEN {
                    return Err(ControlHandshakeError::InvalidTagLength {
                        tag: TAG_PROOF,
                        expected: RADMIN_SRP_DIGEST_LEN,
                        got: m2_received.len(),
                    });
                }

                let m2_expected = compute_srp_m2(&a_public_bytes, &m1_proof, &k_full);
                if m2_received != m2_expected {
                    warn!("ControlClient: prova M2 do servidor inválida!");
                    return Err(ControlHandshakeError::ProofVerificationFailed);
                }

                let mut session_key = Zeroizing::new([0u8; CONTROL_SESSION_KEY_SIZE]);
                session_key.copy_from_slice(&k_full[..CONTROL_SESSION_KEY_SIZE]);

                self.state = ControlClientState::Established {
                    session_key,
                    k_full,
                };

                info!("ControlClient: handshake SRP-6a estabelecido com sucesso!");
                Ok(ControlStepOutput {
                    buffer_to_send: None,
                    is_complete: true,
                })
            }

            ControlClientState::Established { .. } => Err(ControlHandshakeError::InvalidState(
                "handshake já se encontra estabelecido".into(),
            )),

            ControlClientState::Failed(reason) => Err(ControlHandshakeError::InvalidState(
                format!("handshake falhou previamente: {reason}"),
            )),
        }
    }
}


#[cfg(any(test, feature = "srp-test-emulator"))]
pub enum ControlServerState {
    State1WaitingClientIdentity,
    State3WaitingClientEphemeral {
        username: String,
        salt: Zeroizing<Vec<u8>>,
        verifier: SecretBigNum,
        b_secret: SecretBigNum,
        b_public_bytes: Vec<u8>,
    },
    State5WaitingClientProof {
        a_public_bytes: Vec<u8>,
        m1_expected: Zeroizing<[u8; RADMIN_SRP_DIGEST_LEN]>,
        m2_proof: Zeroizing<[u8; RADMIN_SRP_DIGEST_LEN]>,
        k_full: Zeroizing<[u8; RADMIN_SRP_KDF_KEY_LEN]>,
    },
    Established {
        session_key: Zeroizing<[u8; CONTROL_SESSION_KEY_SIZE]>,
        k_full: Zeroizing<[u8; RADMIN_SRP_KDF_KEY_LEN]>,
    },
    Failed(String),
}

#[cfg(any(test, feature = "srp-test-emulator"))]
impl std::fmt::Debug for ControlServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State1WaitingClientIdentity => {
                write!(f, "ControlServerState::State1WaitingClientIdentity")
            }
            Self::State3WaitingClientEphemeral {
                username,
                b_public_bytes,
                ..
            } => f
                .debug_struct("ControlServerState::State3WaitingClientEphemeral")
                .field("username", username)
                .field("salt", &"[REDACTED]")
                .field("verifier", &"[REDACTED]")
                .field("b_secret", &"[REDACTED]")
                .field("b_public_bytes_len", &b_public_bytes.len())
                .finish(),
            Self::State5WaitingClientProof { a_public_bytes, .. } => f
                .debug_struct("ControlServerState::State5WaitingClientProof")
                .field("a_public_bytes_len", &a_public_bytes.len())
                .field("m1_expected", &"[REDACTED]")
                .field("m2_proof", &"[REDACTED]")
                .field("k_full", &"[REDACTED]")
                .finish(),
            Self::Established { .. } => f
                .debug_struct("ControlServerState::Established")
                .field("session_key", &"[REDACTED]")
                .field("k_full", &"[REDACTED]")
                .finish(),
            Self::Failed(reason) => f
                .debug_tuple("ControlServerState::Failed")
                .field(reason)
                .finish(),
        }
    }
}

#[cfg(any(test, feature = "srp-test-emulator"))]
impl ControlServerState {
    pub fn clear(&mut self) {
        match self {
            ControlServerState::State3WaitingClientEphemeral {
                username,
                salt,
                verifier,
                b_secret,
                b_public_bytes,
            } => {
                username.zeroize();
                salt.zeroize();
                verifier.0.clear();
                b_secret.0.clear();
                b_public_bytes.zeroize();
            }
            ControlServerState::State5WaitingClientProof {
                a_public_bytes,
                m1_expected,
                m2_proof,
                k_full,
            } => {
                a_public_bytes.zeroize();
                m1_expected.zeroize();
                m2_proof.zeroize();
                k_full.zeroize();
            }
            ControlServerState::Established {
                session_key,
                k_full,
            } => {
                session_key.zeroize();
                k_full.zeroize();
            }
            _ => {}
        }
    }
}

#[cfg(any(test, feature = "srp-test-emulator"))]
pub struct ControlServerSession {
    username: String,
    password: Zeroizing<String>,
    salt: Zeroizing<Vec<u8>>,
    state: ControlServerState,
}

#[cfg(any(test, feature = "srp-test-emulator"))]
impl std::fmt::Debug for ControlServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlServerSession")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("salt", &"[REDACTED]")
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(any(test, feature = "srp-test-emulator"))]
impl Drop for ControlServerSession {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(any(test, feature = "srp-test-emulator"))]
impl ControlServerSession {
    pub fn new(username: String, password: String) -> Result<Self, ControlHandshakeError> {
        let mut salt = Zeroizing::new([0u8; 16]);
        rand_bytes(&mut *salt)
            .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao gerar salt: {e}")))?;

        Ok(Self {
            username,
            password: Zeroizing::new(password),
            salt: Zeroizing::new(salt.to_vec()),
            state: ControlServerState::State1WaitingClientIdentity,
        })
    }

    pub fn with_salt(username: String, password: String, salt: Vec<u8>) -> Self {
        Self {
            username,
            password: Zeroizing::new(password),
            salt: Zeroizing::new(salt),
            state: ControlServerState::State1WaitingClientIdentity,
        }
    }

    pub fn state(&self) -> &ControlServerState {
        &self.state
    }

    pub fn clear(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.salt.zeroize();
        self.state.clear();
    }

    pub fn session_key_ref(&self) -> Option<&[u8; CONTROL_SESSION_KEY_SIZE]> {
        match &self.state {
            ControlServerState::Established { session_key, .. } => Some(&**session_key),
            _ => None,
        }
    }

    pub fn session_key(&self) -> Option<Zeroizing<[u8; CONTROL_SESSION_KEY_SIZE]>> {
        match &self.state {
            ControlServerState::Established { session_key, .. } => Some(session_key.clone()),
            _ => None,
        }
    }

    pub fn create_cipher_state(&self) -> Result<FamatechCipherState, ControlHandshakeError> {
        let key = match &self.state {
            ControlServerState::Established { session_key, .. } => session_key,
            _ => {
                return Err(ControlHandshakeError::InvalidState(
                    "tentativa de obter cipher state antes do handshake concluído".into(),
                ))
            }
        };
        Ok(FamatechCipherState::from_key_ref(key))
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, ControlServerState::Established { .. })
    }

    pub fn step(&mut self, in_buf: &[u8]) -> Result<ControlStepOutput, ControlHandshakeError> {
        match self.step_inner(in_buf) {
            Ok(output) => Ok(output),
            Err(e) => {
                self.state = ControlServerState::Failed(e.to_string());
                Err(e)
            }
        }
    }

    fn step_inner(&mut self, in_buf: &[u8]) -> Result<ControlStepOutput, ControlHandshakeError> {
        match std::mem::replace(
            &mut self.state,
            ControlServerState::Failed("transição interrompida".into()),
        ) {
            ControlServerState::State1WaitingClientIdentity => {
                let items = decode_items(in_buf)?;

                let step_bytes = find_item(&items, TAG_STEP)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_STEP })?;
                if step_bytes.len() < 4 {
                    return Err(ControlHandshakeError::InvalidTagLength {
                        tag: TAG_STEP,
                        expected: 4,
                        got: step_bytes.len(),
                    });
                }
                let step = u32::from_le_bytes([
                    step_bytes[0],
                    step_bytes[1],
                    step_bytes[2],
                    step_bytes[3],
                ]);
                if step != 1 {
                    return Err(ControlHandshakeError::UnexpectedStep {
                        expected: 1,
                        got: step,
                    });
                }

                let id_bytes = find_item(&items, TAG_IDENTITY)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_IDENTITY })?;
                let received_user = decode_identity(id_bytes);
                if received_user != self.username {
                    warn!(
                        got = %received_user,
                        expected = %self.username,
                        "ControlServer: usuário incorreto"
                    );
                    return Err(ControlHandshakeError::ProofVerificationFailed);
                }

                let prime_n = get_srp_prime_n()?;
                let mut ctx = BigNumContext::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN ctx: {e}"))
                })?;

                let x = compute_srp_x(&self.username, &self.password, &self.salt)?;
                let g_bn = BigNum::from_u32(RADMIN_SRP_GENERATOR as u32).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN g: {e}"))
                })?;

                let mut v = SecretBigNum::new()?;
                v.mod_exp(&g_bn, &x, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em v: {e}")))?;

                let item_step2 = encode_item(TAG_STEP, &2u32.to_le_bytes())?;
                let item_salt = encode_item(TAG_SALT, &self.salt)?;
                let item_n = encode_item(
                    TAG_MODULUS,
                    &pad_bignum_bytes(&prime_n.to_vec(), RADMIN_SRP1536_MODULUS_LEN),
                )?;
                let item_g = encode_item(TAG_GENERATOR, &[RADMIN_SRP_GENERATOR])?;

                let mut out_buf = Vec::new();
                out_buf.extend_from_slice(&item_step2);
                out_buf.extend_from_slice(&item_salt);
                out_buf.extend_from_slice(&item_n);
                out_buf.extend_from_slice(&item_g);

                let b_secret = random_srp_exponent(&prime_n)?;

                let k_bn = BigNum::from_u32(RADMIN_SRP_K).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN k: {e}"))
                })?;
                let mut kv = SecretBigNum::new()?;
                kv.mod_mul(&k_bn, &v, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em kv: {e}")))?;

                let mut gb = SecretBigNum::new()?;
                gb.mod_exp(&g_bn, &b_secret, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em gb: {e}")))?;

                let mut b_public = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN B: {e}"))
                })?;
                b_public
                    .mod_add(&kv, &gb, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em B: {e}")))?;

                let b_public_vec = pad_bignum_bytes(&b_public.to_vec(), RADMIN_SRP1536_MODULUS_LEN);

                self.state = ControlServerState::State3WaitingClientEphemeral {
                    username: received_user,
                    salt: Zeroizing::new(self.salt.to_vec()),
                    verifier: v,
                    b_secret,
                    b_public_bytes: b_public_vec,
                };

                Ok(ControlStepOutput {
                    buffer_to_send: Some(out_buf),
                    is_complete: false,
                })
            }

            ControlServerState::State3WaitingClientEphemeral {
                username,
                salt,
                verifier,
                b_secret,
                b_public_bytes,
            } => {
                let items = decode_items(in_buf)?;

                let step_bytes = find_item(&items, TAG_STEP)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_STEP })?;
                if step_bytes.len() < 4 {
                    return Err(ControlHandshakeError::InvalidTagLength {
                        tag: TAG_STEP,
                        expected: 4,
                        got: step_bytes.len(),
                    });
                }
                let step = u32::from_le_bytes([
                    step_bytes[0],
                    step_bytes[1],
                    step_bytes[2],
                    step_bytes[3],
                ]);
                if step != 3 {
                    return Err(ControlHandshakeError::UnexpectedStep {
                        expected: 3,
                        got: step,
                    });
                }

                let a_bytes = find_item(&items, TAG_PUBLIC_EPHEMERAL).ok_or(
                    ControlHandshakeError::MissingRequiredTag {
                        tag: TAG_PUBLIC_EPHEMERAL,
                    },
                )?;

                let prime_n = get_srp_prime_n()?;
                let mut ctx = BigNumContext::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN ctx: {e}"))
                })?;

                let a_public = validate_srp_public_value(a_bytes, &prime_n)?;

                let (u_bn, _) = compute_srp_u(a_bytes, &b_public_bytes)?;

                let mut vu = SecretBigNum::new()?;
                vu.mod_exp(&verifier, &u_bn, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em vu: {e}")))?;

                let mut avu = SecretBigNum::new()?;
                avu.mod_mul(&a_public, &vu, &prime_n, &mut ctx)
                    .map_err(|e| {
                        ControlHandshakeError::CryptoError(format!("falha em avu: {e}"))
                    })?;
                if avu.num_bits() == 0 {
                    warn!("ControlServer: (A * v^u) mod N == 0 (abortando handshake)");
                    return Err(ControlHandshakeError::InvalidPublicEphemeral);
                }

                let mut s = SecretBigNum::new()?;
                s.mod_exp(&avu, &b_secret, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em S: {e}")))?;

                let s_bytes =
                    Zeroizing::new(pad_bignum_bytes(&s.to_vec(), RADMIN_SRP1536_MODULUS_LEN));

                let k_full = Zeroizing::new(compute_srp_kdf(&s_bytes));

                let n_vec = prime_n.to_vec();
                let m1_expected = Zeroizing::new(compute_srp_m1(
                    &n_vec,
                    RADMIN_SRP_GENERATOR,
                    &username,
                    &salt,
                    a_bytes,
                    &b_public_bytes,
                    &k_full,
                ));

                let m2 = Zeroizing::new(compute_srp_m2(a_bytes, &m1_expected, &k_full));

                let item_step4 = encode_item(TAG_STEP, &4u32.to_le_bytes())?;
                let item_b = encode_item(TAG_PUBLIC_EPHEMERAL, &b_public_bytes)?;

                let mut out_buf = Vec::new();
                out_buf.extend_from_slice(&item_step4);
                out_buf.extend_from_slice(&item_b);

                self.state = ControlServerState::State5WaitingClientProof {
                    a_public_bytes: a_bytes.to_vec(),
                    m1_expected,
                    m2_proof: m2,
                    k_full,
                };

                Ok(ControlStepOutput {
                    buffer_to_send: Some(out_buf),
                    is_complete: false,
                })
            }

            ControlServerState::State5WaitingClientProof {
                a_public_bytes: _,
                m1_expected,
                m2_proof,
                k_full,
            } => {
                let items = decode_items(in_buf)?;

                let step_bytes = find_item(&items, TAG_STEP)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_STEP })?;
                if step_bytes.len() < 4 {
                    return Err(ControlHandshakeError::InvalidTagLength {
                        tag: TAG_STEP,
                        expected: 4,
                        got: step_bytes.len(),
                    });
                }
                let step = u32::from_le_bytes([
                    step_bytes[0],
                    step_bytes[1],
                    step_bytes[2],
                    step_bytes[3],
                ]);
                if step != 5 {
                    return Err(ControlHandshakeError::UnexpectedStep {
                        expected: 5,
                        got: step,
                    });
                }

                let m1_received = find_item(&items, TAG_PROOF)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_PROOF })?;
                if m1_received != *m1_expected {
                    warn!("ControlServer: prova M1 do cliente inválida");
                    return Err(ControlHandshakeError::ProofVerificationFailed);
                }

                let item_step6 = encode_item(TAG_STEP, &6u32.to_le_bytes())?;
                let item_m2 = encode_item(TAG_PROOF, &*m2_proof)?;

                let mut out_buf = Vec::new();
                out_buf.extend_from_slice(&item_step6);
                out_buf.extend_from_slice(&item_m2);

                let mut session_key = Zeroizing::new([0u8; CONTROL_SESSION_KEY_SIZE]);
                session_key.copy_from_slice(&k_full[..CONTROL_SESSION_KEY_SIZE]);

                self.state = ControlServerState::Established {
                    session_key,
                    k_full,
                };

                Ok(ControlStepOutput {
                    buffer_to_send: Some(out_buf),
                    is_complete: true,
                })
            }

            ControlServerState::Established { .. } => Err(ControlHandshakeError::InvalidState(
                "servidor já estabelecido".into(),
            )),

            ControlServerState::Failed(reason) => Err(ControlHandshakeError::InvalidState(
                format!("servidor em estado de falha: {reason}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_packet() {
        let pkt = ControlClientNegotiator::create_version_packet();
        assert_eq!(pkt, [3, 0, 0, 0]);

        let mut client = ControlClientNegotiator::new("user".into(), "pass".into());
        assert!(!client.is_version_exchanged());
        assert!(client.process_version_response(&[3, 0, 0, 0]).is_ok());
        assert!(client.is_version_exchanged());

        let mut bad_client = ControlClientNegotiator::new("user".into(), "pass".into());
        assert_eq!(
            bad_client.process_version_response(&[4, 0, 0, 0]),
            Err(ControlHandshakeError::InvalidProtocolVersion {
                expected: 3,
                got: 4
            })
        );
    }

    #[test]
    fn test_item_tlv_encode_decode() {
        let payload1 = [0x01, 0x02, 0x03, 0x04];
        let encoded1 = encode_item(TAG_STEP, &payload1).unwrap();
        assert_eq!(&encoded1[..4], &[0x10, 0x00, 0x00, 0x04]);
        assert_eq!(&encoded1[4..], &payload1);

        let payload2 = vec![0xAB; 192];
        let encoded2 = encode_item(TAG_PUBLIC_EPHEMERAL, &payload2).unwrap();
        assert_eq!(&encoded2[..4], &[0x60, 0x00, 0x00, 0xC0]);
        assert_eq!(&encoded2[4..], payload2.as_slice());

        let mut combined = encoded1;
        combined.extend_from_slice(&encoded2);

        let items = decode_items(&combined).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].tag, TAG_STEP);
        assert_eq!(items[0].payload, payload1);
        assert_eq!(items[1].tag, TAG_PUBLIC_EPHEMERAL);
        assert_eq!(items[1].payload, payload2);

        assert_eq!(find_item(&items, TAG_STEP), Some(payload1.as_slice()));
        assert_eq!(find_item(&items, TAG_SALT), None);
    }

    #[test]
    fn test_item_tlv_truncated() {
        let valid = encode_item(TAG_STEP, &[1, 2, 3, 4]).unwrap();
        assert!(decode_items(&valid[..3]).is_err());
        assert!(decode_items(&valid[..6]).is_err());
        assert!(decode_items(&valid).is_ok());
    }

    #[test]
    fn test_identity_utf16_byte_swapping() {
        let username = "RadminUser";
        let encoded = encode_identity(username);
        let decoded = decode_identity(&encoded);
        assert_eq!(decoded, username);
    }

    #[test]
    fn test_srp_group_parameters() {
        let n = get_srp_prime_n().unwrap();
        assert_eq!(n.num_bits(), 1536);
        assert_eq!(RADMIN_SRP_GENERATOR, 5);
        assert_eq!(RADMIN_SRP_K, 3);
    }

    #[test]
    fn test_srp_kdf_40_bytes() {
        let s = [0x55u8; 192];
        let kdf = compute_srp_kdf(&s);
        assert_eq!(kdf.len(), 40);
        assert_ne!(&kdf[..20], &kdf[20..]);
    }

    #[test]
    fn test_full_srp_handshake_success() {
        let username = "test_user_admin";
        let password = "SuperSecretPassword123!";

        let mut client = ControlClientNegotiator::new(username.to_string(), password.to_string());
        let mut server =
            ControlServerSession::new(username.to_string(), password.to_string()).unwrap();

        assert!(!client.is_established());
        assert!(!server.is_established());

        let step1_out = client.step(None).unwrap();
        assert!(!step1_out.is_complete);
        let step1_buf = step1_out.buffer_to_send.unwrap();

        let step2_out = server.step(&step1_buf).unwrap();
        assert!(!step2_out.is_complete);
        let step2_buf = step2_out.buffer_to_send.unwrap();

        let step3_out = client.step(Some(&step2_buf)).unwrap();
        assert!(!step3_out.is_complete);
        let step3_buf = step3_out.buffer_to_send.unwrap();

        let step4_out = server.step(&step3_buf).unwrap();
        assert!(!step4_out.is_complete);
        let step4_buf = step4_out.buffer_to_send.unwrap();

        let step5_out = client.step(Some(&step4_buf)).unwrap();
        assert!(!step5_out.is_complete);
        let step5_buf = step5_out.buffer_to_send.unwrap();

        let step6_out = server.step(&step5_buf).unwrap();
        assert!(step6_out.is_complete);
        assert!(server.is_established());
        let step6_buf = step6_out.buffer_to_send.unwrap();

        let client_final = client.step(Some(&step6_buf)).unwrap();
        assert!(client_final.is_complete);
        assert!(client.is_established());
        assert!(client_final.buffer_to_send.is_none());

        let client_key = client.session_key().unwrap();
        let server_key = server.session_key().unwrap();
        assert_eq!(client_key, server_key);
        assert_ne!(&*client_key, &[0u8; 32]);
        assert_eq!(
            client.session_key_ref().unwrap(),
            server.session_key_ref().unwrap()
        );

        let mut client_cipher = client.create_cipher_state().unwrap();
        let mut server_cipher = server.create_cipher_state().unwrap();
        assert_eq!(server_cipher.enc_key(), &*client_key);

        let plaintext = b"Radmin VPN Phase 2 Control Test Message";
        let encrypted = client_cipher.encrypt(plaintext).unwrap();
        let decrypted = server_cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn attacker_without_password_is_rejected_at_proof_verification() {
        let username = "alice";
        let n = get_srp_prime_n().unwrap();
        let n_bytes = n.to_vec();
        let a_forged = pad_bignum_bytes(
            &BigNum::from_u32(1).unwrap().to_vec(),
            RADMIN_SRP1536_MODULUS_LEN,
        );

        let mut server =
            ControlServerSession::new(username.into(), "real-password".into()).unwrap();
        let mut attacker = ControlClientNegotiator::new(username.into(), "guess".into());
        let s1 = attacker
            .step(None)
            .expect("etapa 1 do atacante")
            .buffer_to_send
            .unwrap();
        let s2 = server.step(&s1).expect("etapa 2").buffer_to_send.unwrap();
        let salt = find_item(&decode_items(&s2).unwrap(), TAG_SALT)
            .unwrap()
            .to_vec();

        let mut s3 = encode_item(TAG_STEP, &3u32.to_le_bytes()).unwrap();
        s3.extend(encode_item(TAG_PUBLIC_EPHEMERAL, &a_forged).unwrap());
        let s4 = server
            .step(&s3)
            .expect("etapa 3: A = 1 em 192 bytes está em (0, N) e deve ser aceito")
            .buffer_to_send
            .unwrap();
        let b = find_item(&decode_items(&s4).unwrap(), TAG_PUBLIC_EPHEMERAL)
            .unwrap()
            .to_vec();

        let s_forged = a_forged.clone();
        let k_forged = compute_srp_kdf(&s_forged);
        let m1 = compute_srp_m1(
            &n_bytes,
            RADMIN_SRP_GENERATOR,
            username,
            &salt,
            &a_forged,
            &b,
            &k_forged,
        );
        let mut s5 = encode_item(TAG_STEP, &5u32.to_le_bytes()).unwrap();
        s5.extend(encode_item(TAG_PROOF, &m1).unwrap());

        assert!(
            matches!(
                server.step(&s5),
                Err(ControlHandshakeError::ProofVerificationFailed)
            ),
            "etapa 5: prova forjada com S = 1 deve falhar em ProofVerificationFailed"
        );
    }

    #[test]
    fn honest_proof_is_accepted_on_same_server_path() {
        let mut client = ControlClientNegotiator::new("alice".into(), "real-password".into());
        let mut server = ControlServerSession::new("alice".into(), "real-password".into()).unwrap();
        let s1 = client.step(None).expect("etapa 1").buffer_to_send.unwrap();
        let s2 = server.step(&s1).expect("etapa 2").buffer_to_send.unwrap();
        let s3 = client
            .step(Some(&s2))
            .expect("etapa 3")
            .buffer_to_send
            .unwrap();
        let s4 = server.step(&s3).expect("etapa 4").buffer_to_send.unwrap();
        let s5 = client
            .step(Some(&s4))
            .expect("etapa 5 do cliente honesto")
            .buffer_to_send
            .unwrap();
        assert!(
            server.step(&s5).is_ok(),
            "controle: prova honesta deve ser aceita"
        );
    }

    #[test]
    fn test_srp_handshake_wrong_password_fails() {
        let username = "radmin_operator";
        let right_password = "CorrectPassword123";
        let wrong_password = "IncorrectPassword999";

        let mut client =
            ControlClientNegotiator::new(username.to_string(), wrong_password.to_string());
        let mut server =
            ControlServerSession::new(username.to_string(), right_password.to_string()).unwrap();

        let step1 = client.step(None).unwrap().buffer_to_send.unwrap();
        let step2 = server.step(&step1).unwrap().buffer_to_send.unwrap();
        let step3 = client.step(Some(&step2)).unwrap().buffer_to_send.unwrap();
        let step4 = server.step(&step3).unwrap().buffer_to_send.unwrap();
        let step5 = client.step(Some(&step4)).unwrap().buffer_to_send.unwrap();

        let err = server.step(&step5);
        assert_eq!(err, Err(ControlHandshakeError::ProofVerificationFailed));
        assert!(!server.is_established());
    }

    #[test]
    fn test_srp_handshake_tampered_m2_fails() {
        let username = "alice";
        let password = "password";

        let mut client = ControlClientNegotiator::new(username.to_string(), password.to_string());
        let mut server =
            ControlServerSession::new(username.to_string(), password.to_string()).unwrap();

        let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
        let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
        let s3 = client.step(Some(&s2)).unwrap().buffer_to_send.unwrap();
        let s4 = server.step(&s3).unwrap().buffer_to_send.unwrap();
        let s5 = client.step(Some(&s4)).unwrap().buffer_to_send.unwrap();
        let mut s6 = server.step(&s5).unwrap().buffer_to_send.unwrap();

        let last_idx = s6.len() - 1;
        s6[last_idx] ^= 0xFF;

        let err = client.step(Some(&s6));
        assert_eq!(err, Err(ControlHandshakeError::ProofVerificationFailed));
        assert!(!client.is_established());
    }

    #[test]
    fn test_srp_handshake_unexpected_step() {
        let mut client = ControlClientNegotiator::new("user".into(), "pass".into());
        let _ = client.step(None).unwrap();

        let bad_step = encode_item(TAG_STEP, &5u32.to_le_bytes()).unwrap();
        let err = client.step(Some(&bad_step));
        assert!(matches!(
            err,
            Err(ControlHandshakeError::UnexpectedStep {
                expected: 2,
                got: 5
            })
        ));
    }

    #[test]
    fn test_random_srp_exponent_bounds_and_bit_length() {
        let prime_n = get_srp_prime_n().unwrap();
        let one = BigNum::from_u32(1).unwrap();
        let mut n_minus_1 = BigNum::new().unwrap();
        n_minus_1.checked_sub(&prime_n, &one).unwrap();

        let mut previous_samples = Vec::new();

        for _ in 0..10 {
            let exp = random_srp_exponent(&prime_n).unwrap();
            assert!(exp > one);
            assert!(exp < n_minus_1);
            assert!(exp.num_bits() >= 1500);

            let exp_bytes = exp.to_vec();
            assert!(
                !previous_samples.contains(&exp_bytes),
                "colisão detectada em expoentes aleatórios gerados"
            );
            previous_samples.push(exp_bytes);
        }
    }

    #[test]
    fn test_validate_srp_public_value_strict_checks() {
        let prime_n = get_srp_prime_n().unwrap();

        let g_bn = BigNum::from_u32(5).unwrap();
        let a_secret = random_srp_exponent(&prime_n).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut a_public = BigNum::new().unwrap();
        a_public
            .mod_exp(&g_bn, &a_secret, &prime_n, &mut ctx)
            .unwrap();
        let valid_bytes = pad_bignum_bytes(&a_public.to_vec(), RADMIN_SRP1536_MODULUS_LEN);
        assert_eq!(valid_bytes.len(), 192);
        assert!(validate_srp_public_value(&valid_bytes, &prime_n).is_ok());

        assert_eq!(
            validate_srp_public_value(&valid_bytes[..191], &prime_n),
            Err(ControlHandshakeError::InvalidPublicEphemeral)
        );
        let mut oversized = valid_bytes.clone();
        oversized.push(0x00);
        assert_eq!(
            validate_srp_public_value(&oversized, &prime_n),
            Err(ControlHandshakeError::InvalidPublicEphemeral)
        );
        assert_eq!(
            validate_srp_public_value(&[], &prime_n),
            Err(ControlHandshakeError::InvalidPublicEphemeral)
        );

        let zero_bytes = vec![0u8; 192];
        assert_eq!(
            validate_srp_public_value(&zero_bytes, &prime_n),
            Err(ControlHandshakeError::InvalidPublicEphemeral)
        );

        let n_bytes = pad_bignum_bytes(&prime_n.to_vec(), RADMIN_SRP1536_MODULUS_LEN);
        assert_eq!(
            validate_srp_public_value(&n_bytes, &prime_n),
            Err(ControlHandshakeError::InvalidPublicEphemeral)
        );

        let one = BigNum::from_u32(1).unwrap();
        let mut n_plus_one = BigNum::new().unwrap();
        n_plus_one.checked_add(&prime_n, &one).unwrap();
        let n_plus_one_bytes = pad_bignum_bytes(&n_plus_one.to_vec(), RADMIN_SRP1536_MODULUS_LEN);
        assert_eq!(
            validate_srp_public_value(&n_plus_one_bytes, &prime_n),
            Err(ControlHandshakeError::InvalidPublicEphemeral)
        );
    }

    #[test]
    fn test_srp_handshake_bad_username_fails_closed() {
        let right_username = "alice";
        let wrong_username = "bob";
        let password = "password";

        let mut client =
            ControlClientNegotiator::new(wrong_username.to_string(), password.to_string());
        let mut server =
            ControlServerSession::new(right_username.to_string(), password.to_string()).unwrap();

        let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
        let err = server.step(&s1);
        assert_eq!(err, Err(ControlHandshakeError::ProofVerificationFailed));
        assert!(!server.is_established());

        let retry_err = server.step(&s1);
        assert!(matches!(
            retry_err,
            Err(ControlHandshakeError::InvalidState(_))
        ));
    }

    #[test]
    fn test_srp_handshake_tampered_m1_fails_closed() {
        let username = "alice";
        let password = "password";

        let mut client = ControlClientNegotiator::new(username.to_string(), password.to_string());
        let mut server =
            ControlServerSession::new(username.to_string(), password.to_string()).unwrap();

        let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
        let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
        let s3 = client.step(Some(&s2)).unwrap().buffer_to_send.unwrap();
        let s4 = server.step(&s3).unwrap().buffer_to_send.unwrap();
        let mut s5 = client.step(Some(&s4)).unwrap().buffer_to_send.unwrap();

        let last_idx = s5.len() - 1;
        s5[last_idx] ^= 0xAA;

        let err = server.step(&s5);
        assert_eq!(err, Err(ControlHandshakeError::ProofVerificationFailed));
        assert!(!server.is_established());

        let retry_err = server.step(&s5);
        assert!(matches!(
            retry_err,
            Err(ControlHandshakeError::InvalidState(_))
        ));
    }

    #[test]
    fn test_srp_handshake_invalid_client_a_rejected_by_server() {
        let username = "alice";
        let password = "password";

        let mut client = ControlClientNegotiator::new(username.to_string(), password.to_string());
        let mut server =
            ControlServerSession::new(username.to_string(), password.to_string()).unwrap();

        let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
        let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
        let _s3 = client.step(Some(&s2)).unwrap();

        let item_step3 = encode_item(TAG_STEP, &3u32.to_le_bytes()).unwrap();
        let item_bad_a = encode_item(TAG_PUBLIC_EPHEMERAL, &[0u8; 192]).unwrap();
        let mut malformed_s3 = item_step3;
        malformed_s3.extend_from_slice(&item_bad_a);

        let err = server.step(&malformed_s3);
        assert_eq!(err, Err(ControlHandshakeError::InvalidPublicEphemeral));
        assert!(!server.is_established());

        assert!(matches!(
            server.step(&malformed_s3),
            Err(ControlHandshakeError::InvalidState(_))
        ));
    }

    #[test]
    fn test_srp_handshake_invalid_server_b_rejected_by_client() {
        let username = "alice";
        let password = "password";

        let mut client = ControlClientNegotiator::new(username.to_string(), password.to_string());

        let _s1 = client.step(None).unwrap();

        let prime_n = get_srp_prime_n().unwrap();
        let item_step2 = encode_item(TAG_STEP, &2u32.to_le_bytes()).unwrap();
        let item_salt = encode_item(TAG_SALT, &[0x11; 16]).unwrap();
        let item_n = encode_item(TAG_MODULUS, &prime_n.to_vec()).unwrap();
        let item_g = encode_item(TAG_GENERATOR, &[RADMIN_SRP_GENERATOR]).unwrap();

        let mut s2 = Vec::new();
        s2.extend_from_slice(&item_step2);
        s2.extend_from_slice(&item_salt);
        s2.extend_from_slice(&item_n);
        s2.extend_from_slice(&item_g);

        let _s3 = client.step(Some(&s2)).unwrap();

        let item_step4 = encode_item(TAG_STEP, &4u32.to_le_bytes()).unwrap();
        let item_bad_b = encode_item(TAG_PUBLIC_EPHEMERAL, &[0x44; 100]).unwrap();
        let mut malformed_s4 = item_step4;
        malformed_s4.extend_from_slice(&item_bad_b);

        let err = client.step(Some(&malformed_s4));
        assert_eq!(err, Err(ControlHandshakeError::InvalidPublicEphemeral));
        assert!(!client.is_established());

        assert!(matches!(
            client.step(Some(&malformed_s4)),
            Err(ControlHandshakeError::InvalidState(_))
        ));
    }

    #[test]
    fn test_srp_handshake_divergent_group_parameters_rejected() {
        let username = "alice";
        let password = "password";

        let prime_n = get_srp_prime_n().unwrap();
        let valid_n = pad_bignum_bytes(&prime_n.to_vec(), RADMIN_SRP1536_MODULUS_LEN);
        let item_step2 = encode_item(TAG_STEP, &2u32.to_le_bytes()).unwrap();
        let item_salt = encode_item(TAG_SALT, &[0x11; 16]).unwrap();

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let _s1 = client.step(None).unwrap();
            let item_n = encode_item(TAG_MODULUS, &valid_n).unwrap();
            let item_bad_g = encode_item(TAG_GENERATOR, &[2u8]).unwrap();

            let mut s2 = Vec::new();
            s2.extend_from_slice(&item_step2);
            s2.extend_from_slice(&item_salt);
            s2.extend_from_slice(&item_n);
            s2.extend_from_slice(&item_bad_g);

            let err = client.step(Some(&s2));
            assert_eq!(err, Err(ControlHandshakeError::InvalidGroupParameters));
            assert!(!client.is_established());
            assert!(matches!(
                client.step(Some(&s2)),
                Err(ControlHandshakeError::InvalidState(_))
            ));
        }

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let _s1 = client.step(None).unwrap();
            let item_n = encode_item(TAG_MODULUS, &valid_n).unwrap();
            let item_bad_g = encode_item(TAG_GENERATOR, &[5u8, 0u8]).unwrap();

            let mut s2 = Vec::new();
            s2.extend_from_slice(&item_step2);
            s2.extend_from_slice(&item_salt);
            s2.extend_from_slice(&item_n);
            s2.extend_from_slice(&item_bad_g);

            let err = client.step(Some(&s2));
            assert_eq!(err, Err(ControlHandshakeError::InvalidGroupParameters));
            assert!(!client.is_established());
        }

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let _s1 = client.step(None).unwrap();
            let item_n = encode_item(TAG_MODULUS, &valid_n).unwrap();
            let item_bad_g = encode_item(TAG_GENERATOR, &[]).unwrap();

            let mut s2 = Vec::new();
            s2.extend_from_slice(&item_step2);
            s2.extend_from_slice(&item_salt);
            s2.extend_from_slice(&item_n);
            s2.extend_from_slice(&item_bad_g);

            let err = client.step(Some(&s2));
            assert_eq!(err, Err(ControlHandshakeError::InvalidGroupParameters));
            assert!(!client.is_established());
        }

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let _s1 = client.step(None).unwrap();
            let item_bad_n = encode_item(TAG_MODULUS, &valid_n[..191]).unwrap();
            let item_g = encode_item(TAG_GENERATOR, &[RADMIN_SRP_GENERATOR]).unwrap();

            let mut s2 = Vec::new();
            s2.extend_from_slice(&item_step2);
            s2.extend_from_slice(&item_salt);
            s2.extend_from_slice(&item_bad_n);
            s2.extend_from_slice(&item_g);

            let err = client.step(Some(&s2));
            assert_eq!(err, Err(ControlHandshakeError::InvalidGroupParameters));
            assert!(!client.is_established());
        }

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let _s1 = client.step(None).unwrap();
            let mut bad_n = valid_n.clone();
            bad_n.push(0x00);
            let item_bad_n = encode_item(TAG_MODULUS, &bad_n).unwrap();
            let item_g = encode_item(TAG_GENERATOR, &[RADMIN_SRP_GENERATOR]).unwrap();

            let mut s2 = Vec::new();
            s2.extend_from_slice(&item_step2);
            s2.extend_from_slice(&item_salt);
            s2.extend_from_slice(&item_bad_n);
            s2.extend_from_slice(&item_g);

            let err = client.step(Some(&s2));
            assert_eq!(err, Err(ControlHandshakeError::InvalidGroupParameters));
            assert!(!client.is_established());
        }

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let _s1 = client.step(None).unwrap();
            let mut bad_n = valid_n;
            bad_n[0] ^= 0x01;
            let item_bad_n = encode_item(TAG_MODULUS, &bad_n).unwrap();
            let item_g = encode_item(TAG_GENERATOR, &[RADMIN_SRP_GENERATOR]).unwrap();

            let mut s2 = Vec::new();
            s2.extend_from_slice(&item_step2);
            s2.extend_from_slice(&item_salt);
            s2.extend_from_slice(&item_bad_n);
            s2.extend_from_slice(&item_g);

            let err = client.step(Some(&s2));
            assert_eq!(err, Err(ControlHandshakeError::InvalidGroupParameters));
            assert!(!client.is_established());
        }
    }

    #[test]
    fn test_control_session_explicit_clear() {
        let username = "alice";
        let password = "SecretPassword123";

        let mut client = ControlClientNegotiator::new(username.to_string(), password.to_string());
        let mut server =
            ControlServerSession::new(username.to_string(), password.to_string()).unwrap();

        let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
        let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
        let s3 = client.step(Some(&s2)).unwrap().buffer_to_send.unwrap();
        let s4 = server.step(&s3).unwrap().buffer_to_send.unwrap();
        let s5 = client.step(Some(&s4)).unwrap().buffer_to_send.unwrap();
        let s6 = server.step(&s5).unwrap().buffer_to_send.unwrap();
        let _ = client.step(Some(&s6)).unwrap();

        assert!(client.is_established());
        assert!(server.is_established());

        assert_ne!(&*client.session_key().unwrap(), &[0u8; 32]);
        assert_ne!(&*server.session_key().unwrap(), &[0u8; 32]);
        assert_eq!(
            client.session_key_ref().unwrap(),
            server.session_key_ref().unwrap()
        );

        client.clear();
        server.clear();

        if let ControlClientState::Established {
            session_key,
            k_full,
        } = client.state()
        {
            assert_eq!(**session_key, [0u8; 32]);
            assert_eq!(**k_full, [0u8; 40]);
        } else {
            panic!("client state should remain Established after clear");
        }

        if let ControlServerState::Established {
            session_key,
            k_full,
        } = server.state()
        {
            assert_eq!(**session_key, [0u8; 32]);
            assert_eq!(**k_full, [0u8; 40]);
        } else {
            panic!("server state should remain Established after clear");
        }
    }

    #[test]
    fn test_secret_bignum_explicit_clear() {
        let raw = [0x5Au8; 32];
        let mut secret_bn = SecretBigNum::from_slice(&raw).unwrap();
        assert_eq!(secret_bn.num_bits(), 255);

        secret_bn.clear();
        assert_eq!(secret_bn.num_bits(), 0);
        assert!(secret_bn.to_vec().is_empty() || secret_bn.to_vec() == vec![0]);
    }

    #[test]
    fn test_secret_bignum_drop_executes_clear() {
        let raw = [0x5Au8; 32];
        let initial_drops = SecretBigNum::test_drop_count();

        {
            let secret_bn = SecretBigNum::from_slice(&raw).unwrap();
            assert_eq!(secret_bn.num_bits(), 255);
        }

        let final_drops = SecretBigNum::test_drop_count();
        assert_eq!(final_drops, initial_drops + 1);
    }

    #[test]
    fn test_control_sessions_raii_drop() {
        let username = "drop_test_user";
        let password = "DropTestPassword123!";

        {
            let _client = ControlClientNegotiator::new(username.into(), password.into());
            let _server = ControlServerSession::new(username.into(), password.into()).unwrap();
        }

        {
            let mut client = ControlClientNegotiator::new(username.into(), password.into());
            let mut server = ControlServerSession::new(username.into(), password.into()).unwrap();

            let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
            let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
            let _s3 = client.step(Some(&s2)).unwrap();
        }

        {
            let mut client = ControlClientNegotiator::new(username.into(), password.into());
            let mut server = ControlServerSession::new(username.into(), password.into()).unwrap();

            let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
            let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
            let s3 = client.step(Some(&s2)).unwrap().buffer_to_send.unwrap();
            let s4 = server.step(&s3).unwrap().buffer_to_send.unwrap();
            let s5 = client.step(Some(&s4)).unwrap().buffer_to_send.unwrap();
            let s6 = server.step(&s5).unwrap().buffer_to_send.unwrap();
            let _ = client.step(Some(&s6)).unwrap();

            assert!(client.is_established());
            assert!(server.is_established());
        }
    }

    #[test]
    fn test_control_client_transition_failure_zeroizes_ephemeral_secrets() {
        let username = "bob";
        let password = "SecretPassword456";

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let _s1 = client.step(None).unwrap();
            let bad_step2 = encode_item(TAG_STEP, &2u32.to_le_bytes()).unwrap();
            let res = client.step(Some(&bad_step2));
            assert!(res.is_err());
            assert!(matches!(client.state(), ControlClientState::Failed(_)));
        }

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let s1 = client.step(None).unwrap().buffer_to_send.unwrap();

            let mut server =
                ControlServerSession::new(username.to_string(), password.to_string()).unwrap();
            let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
            let _s3 = client.step(Some(&s2)).unwrap();

            assert!(matches!(
                client.state(),
                ControlClientState::State4WaitingServerEphemeral { .. }
            ));

            let item_step4 = encode_item(TAG_STEP, &4u32.to_le_bytes()).unwrap();
            let item_bad_b = encode_item(TAG_PUBLIC_EPHEMERAL, &[0u8; 192]).unwrap();
            let mut bad_s4 = Vec::new();
            bad_s4.extend_from_slice(&item_step4);
            bad_s4.extend_from_slice(&item_bad_b);

            let res = client.step(Some(&bad_s4));
            assert_eq!(res, Err(ControlHandshakeError::InvalidPublicEphemeral));
            assert!(matches!(client.state(), ControlClientState::Failed(_)));
        }

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let mut server =
                ControlServerSession::new(username.to_string(), password.to_string()).unwrap();

            let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
            let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
            let s3 = client.step(Some(&s2)).unwrap().buffer_to_send.unwrap();
            let s4 = server.step(&s3).unwrap().buffer_to_send.unwrap();
            let _s5 = client.step(Some(&s4)).unwrap();

            assert!(matches!(
                client.state(),
                ControlClientState::State6WaitingServerProof { .. }
            ));

            let item_step6 = encode_item(TAG_STEP, &6u32.to_le_bytes()).unwrap();
            let item_bad_m2 = encode_item(TAG_PROOF, &[0xDE; 20]).unwrap();
            let mut bad_s6 = Vec::new();
            bad_s6.extend_from_slice(&item_step6);
            bad_s6.extend_from_slice(&item_bad_m2);

            let res = client.step(Some(&bad_s6));
            assert_eq!(res, Err(ControlHandshakeError::ProofVerificationFailed));
            assert!(matches!(client.state(), ControlClientState::Failed(_)));
        }
    }

    #[test]
    fn test_control_server_transition_failure_zeroizes_ephemeral_secrets() {
        let username = "charlie";
        let password = "SecretPassword789";

        {
            let mut server =
                ControlServerSession::new(username.to_string(), password.to_string()).unwrap();
            let bad_user_bytes = encode_identity("wrong_user");
            let item_step1 = encode_item(TAG_STEP, &1u32.to_le_bytes()).unwrap();
            let item_id = encode_item(TAG_IDENTITY, &bad_user_bytes).unwrap();
            let mut bad_s1 = Vec::new();
            bad_s1.extend_from_slice(&item_step1);
            bad_s1.extend_from_slice(&item_id);

            let res = server.step(&bad_s1);
            assert_eq!(res, Err(ControlHandshakeError::ProofVerificationFailed));
            assert!(matches!(server.state(), ControlServerState::Failed(_)));
        }

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let mut server =
                ControlServerSession::new(username.to_string(), password.to_string()).unwrap();

            let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
            let _s2 = server.step(&s1).unwrap();

            assert!(matches!(
                server.state(),
                ControlServerState::State3WaitingClientEphemeral { .. }
            ));

            let item_step3 = encode_item(TAG_STEP, &3u32.to_le_bytes()).unwrap();
            let item_bad_a = encode_item(TAG_PUBLIC_EPHEMERAL, &[0u8; 192]).unwrap();
            let mut bad_s3 = Vec::new();
            bad_s3.extend_from_slice(&item_step3);
            bad_s3.extend_from_slice(&item_bad_a);

            let res = server.step(&bad_s3);
            assert_eq!(res, Err(ControlHandshakeError::InvalidPublicEphemeral));
            assert!(matches!(server.state(), ControlServerState::Failed(_)));
        }

        {
            let mut client =
                ControlClientNegotiator::new(username.to_string(), password.to_string());
            let mut server =
                ControlServerSession::new(username.to_string(), password.to_string()).unwrap();

            let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
            let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
            let s3 = client.step(Some(&s2)).unwrap().buffer_to_send.unwrap();
            let _s4 = server.step(&s3).unwrap();

            assert!(matches!(
                server.state(),
                ControlServerState::State5WaitingClientProof { .. }
            ));

            let item_step5 = encode_item(TAG_STEP, &5u32.to_le_bytes()).unwrap();
            let item_bad_m1 = encode_item(TAG_PROOF, &[0xAA; 20]).unwrap();
            let mut bad_s5 = Vec::new();
            bad_s5.extend_from_slice(&item_step5);
            bad_s5.extend_from_slice(&item_bad_m1);

            let res = server.step(&bad_s5);
            assert_eq!(res, Err(ControlHandshakeError::ProofVerificationFailed));
            assert!(matches!(server.state(), ControlServerState::Failed(_)));
        }
    }

    #[test]
    fn test_control_handshake_debug_redacted() {
        let username = "debug_user";
        let password = "SuperSecretUnexposedPassword999!";

        let mut client = ControlClientNegotiator::new(username.to_string(), password.to_string());
        let mut server =
            ControlServerSession::new(username.to_string(), password.to_string()).unwrap();

        let client_dbg = format!("{:?}", client);
        assert!(!client_dbg.contains(password));
        assert!(client_dbg.contains("[REDACTED]"));

        let server_dbg = format!("{:?}", server);
        assert!(!server_dbg.contains(password));
        assert!(server_dbg.contains("[REDACTED]"));

        let s1 = client.step(None).unwrap().buffer_to_send.unwrap();
        let s2 = server.step(&s1).unwrap().buffer_to_send.unwrap();
        let _s3 = client.step(Some(&s2)).unwrap();

        let client_state_dbg = format!("{:?}", client.state());
        assert!(client_state_dbg.contains("[REDACTED]"));

        let server_state_dbg = format!("{:?}", server.state());
        assert!(server_state_dbg.contains("[REDACTED]"));
    }

    #[test]
    fn test_failed_session_cannot_be_reused() {
        let mut client = ControlClientNegotiator::new("alice".into(), "pass".into());
        let err = client.step(Some(&[1, 2, 3]));
        assert!(err.is_err());
        assert!(!client.is_established());

        let retry1 = client.step(None);
        assert!(matches!(
            retry1,
            Err(ControlHandshakeError::InvalidState(_))
        ));
        let retry2 = client.step(Some(&[1, 2, 3]));
        assert!(matches!(
            retry2,
            Err(ControlHandshakeError::InvalidState(_))
        ));
    }
}
