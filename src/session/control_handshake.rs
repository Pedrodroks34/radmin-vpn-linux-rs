//! Handshake da Conexão de Controle `SHelper_*` (SRP-6a, porta 17301).
//!
//! Evidências binárias verificadas por desmontagem estática:
//! - `shelper.dll!0x1006ab90` (`SHelper_CreateClient` -> `0x10067a30`):
//!   Inicializa a estrutura do cliente SRP-6a (`0x21d4` bytes), carrega o validador
//!   de grupo em `0x100699e0` e configura o callback para verificação de $N$ e $g$.
//! - `shelper.dll!0x1006ad20` (`SHelper_CreateServer` -> `0x10067c00`):
//!   Inicializa a estrutura do servidor SRP-6a.
//! - `shelper.dll!0x1006b1d0` (`SHelper_GetNetworkProtocolVersion`):
//!   Retorna a versão de protocolo constante `3`.
//! - `shelper.dll!0x1006ab80` (`SHelper_CheckNetworkProtocolVersion`):
//!   Valida `param_1 == 3`.
//! - `shelper.dll!0x1006b1e0` (`SHelper_GetNextBuffer` -> `0x100670d0`):
//!   Despacha para `0x10066680` (Cliente) ou executa os estados do Servidor (`0x100670d0`).
//! - `shelper.dll!0x10066680` (Máquina de Estados do Cliente):
//!   - **Caso 0**: Emite Item `0x10000000` (step = 1) + Item `0x20000000` (username UTF-16 byte-swapped).
//!   - **Caso 2**: Recebe Item `0x10000000` (step = 2) + Item `0x30000000` (salt) +
//!     Item `0x40000000` ($N$) + Item `0x50000000` ($g$). Gera $a$, calcula $A = g^a \bmod N$,
//!     emite Item `0x10000000` (step = 3) + Item `0x60000000` ($A$).
//!   - **Caso 4**: Recebe Item `0x10000000` (step = 4) + Item `0x60000000` ($B$).
//!     Calcula $u = \text{SHA1}(\text{PAD}(A) \ || \ \text{PAD}(B))$, $S$, $K_{\text{full}}$ (KDF),
//!     e $M_1$. Emite Item `0x10000000` (step = 5) + Item `0x70000000` ($M_1$).
//!   - **Caso 6**: Recebe Item `0x10000000` (step = 6) + Item `0x70000000` ($M_2$).
//!     Verifica $M_2 == \text{SHA1}(A \ || \ M_1 \ || \ K_{\text{full}})$. Se válido, marca
//!     `is_established = true` e finaliza o handshake.
//! - `shelper.dll!0x1006b010` (`SHelper_GetKey`):
//!   Retorna a chave derivada da sessão ($K_{\text{full}}$ de 40 bytes).
//! - `shelper.dll!0x10061790` (KDF):
//!   Gera 40 bytes via SHA-1 iterativo sobre $S \ || \ \text{counter}_{\text{be32}}$.
//! - `RvROLClient.dll!0x1003dd40` e `0x100df250`:
//!   Instala os primeiros 32 bytes ($0x20$) da chave no `SHelper_CChannel` para criptografia
//!   AES-256-CBC subsequente.

use crate::crypto::famatech::{FamatechCipherState, AES_256_KEY_SIZE};
use openssl::bn::{BigNum, BigNumContext};
use openssl::rand::rand_bytes;
use openssl::sha::sha1;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Versão do protocolo de rede do SHelper (`shelper.dll!0x1006b1d0` -> `return 3`).
pub const SHELPER_PROTOCOL_VERSION: u32 = 3;

/// Tamanho em bytes do primo modular SRP-1536 (192 bytes = 1536 bits).
pub const RADMIN_SRP1536_MODULUS_LEN: usize = 192;

/// Gerador SRP fixo ($g = 5$, `shelper.dll!0x100ac279`).
pub const RADMIN_SRP_GENERATOR: u8 = 5;

/// Multiplicador SRP ($k = 3$, `shelper.dll!0x100607d0`).
pub const RADMIN_SRP_K: u32 = 3;

/// Tamanho do digest SHA-1 (20 bytes).
pub const RADMIN_SRP_DIGEST_LEN: usize = 20;

/// Tamanho da chave expandida derivada da KDF (`shelper.dll!0x10061790` -> 40 bytes = 0x28).
pub const RADMIN_SRP_KDF_KEY_LEN: usize = 40;

/// Tamanho da chave de sessão para AES-256-CBC (32 bytes).
pub const CONTROL_SESSION_KEY_SIZE: usize = AES_256_KEY_SIZE;

// ---------------------------------------------------------------------------
// Identificadores de Tag TLV (shelper.dll!0x100626e0 / 0x10062900)
// ---------------------------------------------------------------------------

/// Tag de identificação do passo / estado do protocolo (4 bytes, `u32` little-endian).
pub const TAG_STEP: u32 = 0x10000000;

/// Tag de identidade do cliente (string UTF-16 byte-swapped).
pub const TAG_IDENTITY: u32 = 0x20000000;

/// Tag de salt do usuário ($s$).
pub const TAG_SALT: u32 = 0x30000000;

/// Tag do módulo primo ($N$, 192 bytes big-endian).
pub const TAG_MODULUS: u32 = 0x40000000;

/// Tag do gerador ($g = 5$).
pub const TAG_GENERATOR: u32 = 0x50000000;

/// Tag da chave efêmera pública ($A$ do cliente ou $B$ do servidor, 192 bytes big-endian).
pub const TAG_PUBLIC_EPHEMERAL: u32 = 0x60000000;

/// Tag da prova criptográfica de posse de chave ($M_1$ do cliente ou $M_2$ do servidor, 20 bytes SHA-1).
pub const TAG_PROOF: u32 = 0x70000000;

/// Módulo primo de 1536 bits hardcoded em `shelper.dll!0x100ac280`.
pub const RADMIN_SRP1536_PRIME_HEX: &str = "\
e634471e75f2d76a0a3f5e252c5a6efb48edad645d31d9ecbc400416e14f5c6c\
2ed378602d6eb8e9478b99e6474932393538b4be7177e0e05d3aaed17b5ae87a\
a20f3dad37af019518f45b6dde76b2bfdfb140f379cc15383b304b7975b90796\
7553cd6fdaf08d68832b603120430a501067d21beb2ce2275a20036a2dc80f1c\
9d3ab9221afd5baceda5c2a31077c54fc6f274aaeba17ddd0b5c68f4f8e751a8\
90a58648147a82e6f4f532ccdc939a12942799a713500e17dd4f6ff216cd54c7";

// ---------------------------------------------------------------------------
// Erros do Handshake de Controle
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Item TLV (Framing interno: shelper.dll!0x100626e0 e 0x10062900)
// ---------------------------------------------------------------------------

/// Estrutura de um item TLV no protocolo de handshake do Radmin.
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

/// Codifica um item TLV individual com o cabeçalho de 4 bytes em network byte order (big-endian).
///
/// Fórmula binária oficial (`shelper.dll!0x100626e0`):
/// `header = (tag & 0xF8000000) | (payload.len() & 0x07FFFFFF)`
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

/// Decodifica uma sequência de itens TLV de um buffer de bytes (`shelper.dll!0x10062900`).
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

/// Localiza o primeiro item com a tag especificada na lista de itens decodificados.
pub fn find_item(items: &[ControlItem], tag: u32) -> Option<&[u8]> {
    items
        .iter()
        .find(|item| item.tag == tag)
        .map(|item| item.payload.as_slice())
}

/// Codifica a identidade do cliente em UTF-16 com inversão de endianness (`0x10066680` Caso 0).
pub fn encode_identity(username: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(username.len() * 2);
    for c in username.encode_utf16() {
        out.push((c >> 8) as u8);
        out.push((c & 0xFF) as u8);
    }
    out
}

/// Decodifica a identidade do cliente a partir do buffer UTF-16BE.
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

// ---------------------------------------------------------------------------
// Operações Criptográficas do SRP-6a (Thomas J. Wu)
// ---------------------------------------------------------------------------

/// Retorna o BigNum correspondente ao módulo primo fixo $N$ de 1536 bits.
pub fn get_srp_prime_n() -> Result<BigNum, ControlHandshakeError> {
    BigNum::from_hex_str(RADMIN_SRP1536_PRIME_HEX)
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao carregar primo N: {e}")))
}

/// Calcula a senha privada $x$ (`shelper.dll!0x10060340`):
/// $$h_1 = \text{SHA1}(\text{username} \ || \ \text{":"} \ || \ \text{password})$$
/// $$x = \text{SHA1}(\text{salt} \ || \ h_1)$$
pub fn compute_srp_x(
    username: &str,
    password: &str,
    salt: &[u8],
) -> Result<BigNum, ControlHandshakeError> {
    let mut cred_buf = Vec::with_capacity(username.len() + 1 + password.len());
    cred_buf.extend_from_slice(username.as_bytes());
    cred_buf.push(b':');
    cred_buf.extend_from_slice(password.as_bytes());
    let h1 = sha1(&cred_buf);

    let mut x_buf = Vec::with_capacity(salt.len() + h1.len());
    x_buf.extend_from_slice(salt);
    x_buf.extend_from_slice(&h1);
    let x_bytes = sha1(&x_buf);

    BigNum::from_slice(&x_bytes)
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em BN para x: {e}")))
}

/// Preenche um buffer com zeros à esquerda até atingir o comprimento especificado.
pub fn pad_bignum_bytes(bytes: &[u8], target_len: usize) -> Vec<u8> {
    if bytes.len() >= target_len {
        bytes.to_vec()
    } else {
        let mut padded = vec![0u8; target_len - bytes.len()];
        padded.extend_from_slice(bytes);
        padded
    }
}

/// Gera um expoente privado efêmero SRP ($a$ ou $b$) criptograficamente seguro:
/// - Utiliza CSPRNG (`openssl::rand::rand_bytes`) gerando 192 bytes (1536 bits) de entropia.
/// - Garante que o expoente pertença estritamente ao intervalo válido $1 < exp < N - 1$
///   (isto é, $2 \le exp \le N - 2$) e não seja trivial ($0$ ou $1$).
/// - Implementa amostragem com repetição/rejeição (rejection sampling) caso gere valor fora do domínio aceitável.
pub fn random_srp_exponent(prime_n: &BigNum) -> Result<BigNum, ControlHandshakeError> {
    let one = BigNum::from_u32(1)
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao criar BN 1: {e}")))?;
    let mut n_minus_1 = BigNum::new().map_err(|e| {
        ControlHandshakeError::CryptoError(format!("falha ao criar BN n_minus_1: {e}"))
    })?;
    n_minus_1
        .checked_sub(prime_n, &one)
        .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao calcular N - 1: {e}")))?;

    for _ in 0..128 {
        let mut buf = [0u8; RADMIN_SRP1536_MODULUS_LEN];
        rand_bytes(&mut buf).map_err(|e| {
            ControlHandshakeError::CryptoError(format!("falha no CSPRNG ao gerar expoente: {e}"))
        })?;

        let candidate = BigNum::from_slice(&buf).map_err(|e| {
            ControlHandshakeError::CryptoError(format!("falha ao carregar BN candidato: {e}"))
        })?;

        // Garante 1 < candidate < N - 1
        if candidate > one && candidate < n_minus_1 {
            return Ok(candidate);
        }
    }

    Err(ControlHandshakeError::CryptoError(
        "limite de tentativas excedido ao gerar expoente SRP".to_string(),
    ))
}

/// Valida rigorosamente uma chave pública efêmera SRP ($A$ ou $B$) conforme RFC 5054 / Thomas Wu
/// e desmontagem de `shelper.dll!0x10060510`:
/// - Exige representação canônica com exatamente 192 bytes (`RADMIN_SRP1536_MODULUS_LEN`).
/// - O valor deve ser estritamente não nulo ($val \ne 0$) e menor que o módulo primo ($val < N$).
/// - Valida formalmente que $val \pmod N \ne 0$ utilizando `nnmod` com receptor e operandos corretos.
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

    // Rejeita val == 0
    if val.num_bits() == 0 {
        warn!("validate_srp_public_value: valor público é zero");
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    // Rejeita val >= N
    if &val >= prime_n {
        warn!("validate_srp_public_value: valor público fora do domínio (val >= N)");
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    // Validação formal val mod N != 0 usando nnmod com receptor correto
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

/// Calcula o scrambler aleatório $u$ (`shelper.dll!0x10060810`):
/// $$u = \text{SHA1}(\text{PAD}(A) \ || \ \text{PAD}(B))$$
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

/// Função de Derivação de Chave (KDF) de 40 bytes (`shelper.dll!0x10061790`):
/// $$K_0 = \text{SHA1}(S \ || \ \text{0x00000000}_{\text{be}})$$
/// $$K_1 = \text{SHA1}(S \ || \ \text{0x00000001}_{\text{be}})$$
pub fn compute_srp_kdf(s_bytes: &[u8]) -> [u8; RADMIN_SRP_KDF_KEY_LEN] {
    let mut out = [0u8; RADMIN_SRP_KDF_KEY_LEN];

    let mut buf0 = Vec::with_capacity(s_bytes.len() + 4);
    buf0.extend_from_slice(s_bytes);
    buf0.extend_from_slice(&0u32.to_be_bytes());
    let k0 = sha1(&buf0);

    let mut buf1 = Vec::with_capacity(s_bytes.len() + 4);
    buf1.extend_from_slice(s_bytes);
    buf1.extend_from_slice(&1u32.to_be_bytes());
    let k1 = sha1(&buf1);

    out[..20].copy_from_slice(&k0);
    out[20..40].copy_from_slice(&k1);
    out
}

/// Calcula a prova de cliente $M_1$ (`shelper.dll!0x100601b0` e `0x10060510`):
/// $$M_1 = \text{SHA1}((\text{SHA1}(N) \oplus \text{SHA1}(g)) \ || \ \text{SHA1}(\text{username}) \ || \ \text{salt} \ || \ A \ || \ B \ || \ K_{\text{full}})$$
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

    let mut buf = Vec::new();
    buf.extend_from_slice(&h_xor);
    buf.extend_from_slice(&h_i);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(a_bytes);
    buf.extend_from_slice(b_bytes);
    buf.extend_from_slice(k_full);

    sha1(&buf)
}

/// Calcula a prova do servidor $M_2$ (`shelper.dll!0x10060900`):
/// $$M_2 = \text{SHA1}(A \ || \ M_1 \ || \ K_{\text{full}})$$
pub fn compute_srp_m2(
    a_bytes: &[u8],
    m1: &[u8; RADMIN_SRP_DIGEST_LEN],
    k_full: &[u8; RADMIN_SRP_KDF_KEY_LEN],
) -> [u8; RADMIN_SRP_DIGEST_LEN] {
    let mut buf = Vec::with_capacity(a_bytes.len() + m1.len() + k_full.len());
    buf.extend_from_slice(a_bytes);
    buf.extend_from_slice(m1);
    buf.extend_from_slice(k_full);
    sha1(&buf)
}

// ---------------------------------------------------------------------------
// Máquina de Estados do Handshake de Controle do Cliente
// ---------------------------------------------------------------------------

/// Resultado da execução de uma etapa do handshake de controle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlStepOutput {
    /// Buffer de dados a ser transmitido para o par (se houver).
    pub buffer_to_send: Option<Vec<u8>>,
    /// Indicador se o handshake foi concluído com sucesso e a chave está pronta.
    pub is_complete: bool,
}

/// Estados internos do cliente de controle (`shelper.dll!0x10066680`).
#[derive(Debug)]
pub enum ControlClientState {
    /// Estado 0 inicial: pronto para emitir Step 1 (username).
    State0Initial,
    /// Estado 2: enviou Step 1, aguardando parâmetros do servidor (Step 2: salt, N, g).
    State2WaitingServerParams,
    /// Estado 4: enviou Step 3 (A), aguardando chave efêmera do servidor (Step 4: B).
    State4WaitingServerEphemeral {
        a_secret: BigNum,
        a_public_bytes: Vec<u8>,
        salt: Vec<u8>,
        x_secret: BigNum,
    },
    /// Estado 6: enviou Step 5 (M1), aguardando prova do servidor (Step 6: M2).
    State6WaitingServerProof {
        a_public_bytes: Vec<u8>,
        m1_proof: [u8; RADMIN_SRP_DIGEST_LEN],
        k_full: [u8; RADMIN_SRP_KDF_KEY_LEN],
    },
    /// Handshake estabelecido com sucesso.
    Established {
        session_key: [u8; CONTROL_SESSION_KEY_SIZE],
        k_full: [u8; RADMIN_SRP_KDF_KEY_LEN],
    },
    /// Handshake falhou com erro irrecuperável.
    Failed(String),
}

/// Negociador do handshake de controle do cliente (Família `SHelper_*`).
pub struct ControlClientNegotiator {
    username: String,
    password: String,
    state: ControlClientState,
    version_exchanged: bool,
}

impl ControlClientNegotiator {
    /// Inicializa um novo cliente de handshake de controle com as credenciais especificadas.
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            state: ControlClientState::State0Initial,
            version_exchanged: false,
        }
    }

    /// Retorna `true` se a validação inicial de versão de protocolo (`version = 3`) já ocorreu.
    pub fn is_version_exchanged(&self) -> bool {
        self.version_exchanged
    }

    /// Gera o pacote de versão inicial a ser transmitido ao servidor: `03 00 00 00`.
    pub fn create_version_packet() -> [u8; 4] {
        SHELPER_PROTOCOL_VERSION.to_le_bytes()
    }

    /// Valida o pacote de versão retornado pelo servidor (`0x1006ab80`).
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

    /// Retorna `true` se o handshake foi concluído com sucesso e a chave de sessão está pronta.
    pub fn is_established(&self) -> bool {
        matches!(self.state, ControlClientState::Established { .. })
    }

    /// Retorna a chave de sessão derivada de 32 bytes (`0x20`) para AES-256-CBC, se estabelecido.
    pub fn session_key(&self) -> Option<[u8; CONTROL_SESSION_KEY_SIZE]> {
        match &self.state {
            ControlClientState::Established { session_key, .. } => Some(*session_key),
            _ => None,
        }
    }

    /// Cria e retorna o estado de cifra `FamatechCipherState` inicializado com a chave de sessão.
    pub fn create_cipher_state(&self) -> Result<FamatechCipherState, ControlHandshakeError> {
        let key = self.session_key().ok_or_else(|| {
            ControlHandshakeError::InvalidState(
                "tentativa de obter cipher state antes do handshake concluído".into(),
            )
        })?;
        Ok(FamatechCipherState::new(key))
    }

    /// Executa uma transição de estado da máquina de estados do cliente.
    ///
    /// - No estado inicial (`State0Initial`), `in_buf` deve ser `None`. Retorna o buffer do Step 1.
    /// - Nos estados subsequentes, `in_buf` contém os bytes do frame de controle recebido do servidor.
    /// - Em caso de qualquer erro, transiciona imediatamente e permanentemente para `ControlClientState::Failed`,
    ///   garantindo encerramento em modo seguro (fail-closed) sem possibilidade de reutilização.
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

                // Caso 0: Emite Step 1 + Username UTF-16BE
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

                // 1. Validar Step 2
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

                // 2. Extrair Salt (Tag 0x30)
                let salt = find_item(&items, TAG_SALT)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_SALT })?
                    .to_vec();

                // 3. Validar Parâmetros N e g (Tags 0x40 e 0x50)
                let n_bytes = find_item(&items, TAG_MODULUS)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_MODULUS })?;
                let g_bytes = find_item(&items, TAG_GENERATOR)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_GENERATOR })?;

                let expected_n = get_srp_prime_n()?;
                let received_n = BigNum::from_slice(n_bytes).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("módulo N inválido: {e}"))
                })?;

                if received_n != expected_n {
                    warn!("ControlClient: módulo N recebido diverge do hardcoded oficial");
                    return Err(ControlHandshakeError::InvalidGroupParameters);
                }

                if g_bytes.is_empty() || g_bytes[0] != RADMIN_SRP_GENERATOR {
                    warn!(
                        got = ?g_bytes,
                        expected = RADMIN_SRP_GENERATOR,
                        "ControlClient: gerador g diverge do oficial"
                    );
                    return Err(ControlHandshakeError::InvalidGroupParameters);
                }

                // 4. Calcular x e gerar a secreto, calculando A = g^a mod N
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

                // 5. Emitir Step 3 + A
                let item_step3 = encode_item(TAG_STEP, &3u32.to_le_bytes())?;
                let item_a = encode_item(TAG_PUBLIC_EPHEMERAL, &a_public_vec)?;

                let mut out_buf = Vec::with_capacity(item_step3.len() + item_a.len());
                out_buf.extend_from_slice(&item_step3);
                out_buf.extend_from_slice(&item_a);

                self.state = ControlClientState::State4WaitingServerEphemeral {
                    a_secret,
                    a_public_bytes: a_public_vec,
                    salt,
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

                // 1. Validar Step 4
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

                // 2. Extrair e validar B (Tag 0x60)
                let b_bytes = find_item(&items, TAG_PUBLIC_EPHEMERAL).ok_or(
                    ControlHandshakeError::MissingRequiredTag {
                        tag: TAG_PUBLIC_EPHEMERAL,
                    },
                )?;

                let prime_n = get_srp_prime_n()?;
                let mut ctx = BigNumContext::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN ctx: {e}"))
                })?;

                // Validação rigorosa de segurança de B (0x10060510 e RFC 5054):
                // Comprimento canônico de 192 bytes, 1 <= B < N, B mod N != 0
                let b_public = validate_srp_public_value(b_bytes, &prime_n)?;

                // 3. Calcular u = SHA1(PAD(A) || PAD(B))
                let (u_bn, _u_bytes) = compute_srp_u(&a_public_bytes, b_bytes)?;

                // 4. Calcular base: (B - k * v) mod N
                // onde v = g^x mod N
                let g_bn = BigNum::from_u32(RADMIN_SRP_GENERATOR as u32).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN g: {e}"))
                })?;
                let mut v = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN v: {e}"))
                })?;
                v.mod_exp(&g_bn, &x_secret, &prime_n, &mut ctx)
                    .map_err(|e| {
                        ControlHandshakeError::CryptoError(format!("falha em mod_exp v: {e}"))
                    })?;

                let k_bn = BigNum::from_u32(RADMIN_SRP_K).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN k: {e}"))
                })?;
                let mut kv = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN kv: {e}"))
                })?;
                kv.mod_mul(&k_bn, &v, &prime_n, &mut ctx).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em mod_mul kv: {e}"))
                })?;

                // base = (B + N - (kv mod N)) mod N
                let mut base = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN base: {e}"))
                })?;
                base.mod_sub(&b_public, &kv, &prime_n, &mut ctx)
                    .map_err(|e| {
                        ControlHandshakeError::CryptoError(format!("falha em mod_sub base: {e}"))
                    })?;
                if base.num_bits() == 0 {
                    warn!("ControlClient: base (B - k*v) mod N == 0 (abortando handshake)");
                    return Err(ControlHandshakeError::InvalidPublicEphemeral);
                }

                // 5. Calcular expoente: (a + u * x)
                let mut ux = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN ux: {e}"))
                })?;
                ux.checked_mul(&u_bn, &x_secret, &mut ctx).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em mul: {e}"))
                })?;

                let mut exp = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN exp: {e}"))
                })?;
                exp.checked_add(&a_secret, &ux).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em add: {e}"))
                })?;

                // 6. Calcular segredo pré-mestre S = base ^ exp mod N
                let mut s = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN S: {e}"))
                })?;
                s.mod_exp(&base, &exp, &prime_n, &mut ctx).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em mod_exp S: {e}"))
                })?;

                let s_bytes = pad_bignum_bytes(&s.to_vec(), RADMIN_SRP1536_MODULUS_LEN);

                // 7. Derivar chave de 40 bytes via KDF (0x10061790)
                let k_full = compute_srp_kdf(&s_bytes);

                // 8. Calcular prova do cliente M1
                let n_vec = prime_n.to_vec();
                let m1 = compute_srp_m1(
                    &n_vec,
                    RADMIN_SRP_GENERATOR,
                    &self.username,
                    &salt,
                    &a_public_bytes,
                    b_bytes,
                    &k_full,
                );

                // 9. Emitir Step 5 + M1
                let item_step5 = encode_item(TAG_STEP, &5u32.to_le_bytes())?;
                let item_m1 = encode_item(TAG_PROOF, &m1)?;

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

                // 1. Validar Step 6
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

                // 2. Extrair e verificar M2 (Tag 0x70)
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

                // 3. Extrair chave de 32 bytes para AES-256 (0x100df250)
                let mut session_key = [0u8; CONTROL_SESSION_KEY_SIZE];
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

// ---------------------------------------------------------------------------
// Sessão de Handshake de Controle do Servidor (shelper.dll!0x100670d0)
// ---------------------------------------------------------------------------

/// Estados internos do servidor de controle.
#[derive(Debug)]
pub enum ControlServerState {
    /// Estado 1: aguardando identidade do cliente (Step 1).
    State1WaitingClientIdentity,
    /// Estado 3: enviou parâmetros, aguardando efêmera do cliente (Step 3: A).
    State3WaitingClientEphemeral {
        username: String,
        salt: Vec<u8>,
        verifier: BigNum,
        b_secret: BigNum,
        b_public_bytes: Vec<u8>,
    },
    /// Estado 5: enviou B, aguardando prova do cliente (Step 5: M1).
    State5WaitingClientProof {
        a_public_bytes: Vec<u8>,
        m1_expected: [u8; RADMIN_SRP_DIGEST_LEN],
        m2_proof: [u8; RADMIN_SRP_DIGEST_LEN],
        k_full: [u8; RADMIN_SRP_KDF_KEY_LEN],
    },
    /// Estabelecido com sucesso.
    Established {
        session_key: [u8; CONTROL_SESSION_KEY_SIZE],
        k_full: [u8; RADMIN_SRP_KDF_KEY_LEN],
    },
    /// Falhou.
    Failed(String),
}

/// Implementação do lado servidor do handshake de controle (usado para testes e emulação).
pub struct ControlServerSession {
    username: String,
    password: String,
    salt: Vec<u8>,
    state: ControlServerState,
}

impl ControlServerSession {
    /// Cria uma nova sessão de servidor com credenciais fixas e salt gerado.
    pub fn new(username: String, password: String) -> Result<Self, ControlHandshakeError> {
        let mut salt = [0u8; 16];
        rand_bytes(&mut salt)
            .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao gerar salt: {e}")))?;

        Ok(Self {
            username,
            password,
            salt: salt.to_vec(),
            state: ControlServerState::State1WaitingClientIdentity,
        })
    }

    /// Cria uma nova sessão com salt especificado (para testes determinísticos).
    pub fn with_salt(username: String, password: String, salt: Vec<u8>) -> Self {
        Self {
            username,
            password,
            salt,
            state: ControlServerState::State1WaitingClientIdentity,
        }
    }

    /// Retorna a chave de sessão de 32 bytes se o handshake estiver concluído.
    pub fn session_key(&self) -> Option<[u8; CONTROL_SESSION_KEY_SIZE]> {
        match &self.state {
            ControlServerState::Established { session_key, .. } => Some(*session_key),
            _ => None,
        }
    }

    /// Retorna `true` se o handshake foi concluído com sucesso.
    pub fn is_established(&self) -> bool {
        matches!(self.state, ControlServerState::Established { .. })
    }

    /// Executa um passo da máquina de estados do servidor.
    ///
    /// - Em caso de qualquer erro, transiciona imediatamente e permanentemente para `ControlServerState::Failed`,
    ///   garantindo encerramento em modo seguro (fail-closed) sem possibilidade de reutilização.
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

                // 1. Validar Step 1
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

                // 2. Extrair Identidade (Tag 0x20) e validar
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

                // 3. Calcular verifier v = g^x mod N
                let prime_n = get_srp_prime_n()?;
                let mut ctx = BigNumContext::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN ctx: {e}"))
                })?;

                let x = compute_srp_x(&self.username, &self.password, &self.salt)?;
                let g_bn = BigNum::from_u32(RADMIN_SRP_GENERATOR as u32).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN g: {e}"))
                })?;

                let mut v = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN v: {e}"))
                })?;
                v.mod_exp(&g_bn, &x, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em v: {e}")))?;

                // 4. Emitir Step 2 + Salt + N + g
                let item_step2 = encode_item(TAG_STEP, &2u32.to_le_bytes())?;
                let item_salt = encode_item(TAG_SALT, &self.salt)?;
                let item_n = encode_item(TAG_MODULUS, &prime_n.to_vec())?;
                let item_g = encode_item(TAG_GENERATOR, &[RADMIN_SRP_GENERATOR])?;

                let mut out_buf = Vec::new();
                out_buf.extend_from_slice(&item_step2);
                out_buf.extend_from_slice(&item_salt);
                out_buf.extend_from_slice(&item_n);
                out_buf.extend_from_slice(&item_g);

                // Gerar b secreto para a próxima etapa via CSPRNG dedicado
                let b_secret = random_srp_exponent(&prime_n)?;

                // Calcular B = (k*v + g^b) mod N
                let k_bn = BigNum::from_u32(RADMIN_SRP_K).map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN k: {e}"))
                })?;
                let mut kv = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN kv: {e}"))
                })?;
                kv.mod_mul(&k_bn, &v, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em kv: {e}")))?;

                let mut gb = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN gb: {e}"))
                })?;
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
                    salt: self.salt.clone(),
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

                // 1. Validar Step 3
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

                // 2. Extrair A (Tag 0x60)
                let a_bytes = find_item(&items, TAG_PUBLIC_EPHEMERAL).ok_or(
                    ControlHandshakeError::MissingRequiredTag {
                        tag: TAG_PUBLIC_EPHEMERAL,
                    },
                )?;

                let prime_n = get_srp_prime_n()?;
                let mut ctx = BigNumContext::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN ctx: {e}"))
                })?;

                // Validação rigorosa de segurança de A (0x10060510 e RFC 5054):
                // Comprimento canônico de 192 bytes, 1 <= A < N, A mod N != 0
                let a_public = validate_srp_public_value(a_bytes, &prime_n)?;

                // 3. u = SHA1(PAD(A) || PAD(B))
                let (u_bn, _) = compute_srp_u(a_bytes, &b_public_bytes)?;

                // 4. Calcular S = (A * v^u)^b mod N
                let mut vu = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN vu: {e}"))
                })?;
                vu.mod_exp(&verifier, &u_bn, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em vu: {e}")))?;

                let mut avu = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN avu: {e}"))
                })?;
                avu.mod_mul(&a_public, &vu, &prime_n, &mut ctx)
                    .map_err(|e| {
                        ControlHandshakeError::CryptoError(format!("falha em avu: {e}"))
                    })?;
                if avu.num_bits() == 0 {
                    warn!("ControlServer: (A * v^u) mod N == 0 (abortando handshake)");
                    return Err(ControlHandshakeError::InvalidPublicEphemeral);
                }

                let mut s = BigNum::new().map_err(|e| {
                    ControlHandshakeError::CryptoError(format!("falha em BN S: {e}"))
                })?;
                s.mod_exp(&avu, &b_secret, &prime_n, &mut ctx)
                    .map_err(|e| ControlHandshakeError::CryptoError(format!("falha em S: {e}")))?;

                let s_bytes = pad_bignum_bytes(&s.to_vec(), RADMIN_SRP1536_MODULUS_LEN);
                let k_full = compute_srp_kdf(&s_bytes);

                let n_vec = prime_n.to_vec();
                let m1_expected = compute_srp_m1(
                    &n_vec,
                    RADMIN_SRP_GENERATOR,
                    &username,
                    &salt,
                    a_bytes,
                    &b_public_bytes,
                    &k_full,
                );

                let m2 = compute_srp_m2(a_bytes, &m1_expected, &k_full);

                // 5. Emitir Step 4 + B
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

                // 1. Validar Step 5
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

                // 2. Validar M1 (Tag 0x70)
                let m1_received = find_item(&items, TAG_PROOF)
                    .ok_or(ControlHandshakeError::MissingRequiredTag { tag: TAG_PROOF })?;
                if m1_received != m1_expected {
                    warn!("ControlServer: prova M1 do cliente inválida");
                    return Err(ControlHandshakeError::ProofVerificationFailed);
                }

                // 3. Emitir Step 6 + M2
                let item_step6 = encode_item(TAG_STEP, &6u32.to_le_bytes())?;
                let item_m2 = encode_item(TAG_PROOF, &m2_proof)?;

                let mut out_buf = Vec::new();
                out_buf.extend_from_slice(&item_step6);
                out_buf.extend_from_slice(&item_m2);

                let mut session_key = [0u8; CONTROL_SESSION_KEY_SIZE];
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
        // 4 bytes header: Tag 0x10000000 | len 4 -> 0x10000004
        assert_eq!(&encoded1[..4], &[0x10, 0x00, 0x00, 0x04]);
        assert_eq!(&encoded1[4..], &payload1);

        let payload2 = vec![0xAB; 192];
        let encoded2 = encode_item(TAG_PUBLIC_EPHEMERAL, &payload2).unwrap();
        // Tag 0x60000000 | len 192 (0xc0) -> 0x600000C0
        assert_eq!(&encoded2[..4], &[0x60, 0x00, 0x00, 0xC0]);
        assert_eq!(&encoded2[4..], payload2.as_slice());

        // Concatena e decodifica ambos
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
        // Os blocos 0 e 1 devem ser diferentes devido ao contador
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

        // Step 1: Cliente emite Identidade
        let step1_out = client.step(None).unwrap();
        assert!(!step1_out.is_complete);
        let step1_buf = step1_out.buffer_to_send.unwrap();

        // Step 2: Servidor recebe Identidade e emite Salt, N, g
        let step2_out = server.step(&step1_buf).unwrap();
        assert!(!step2_out.is_complete);
        let step2_buf = step2_out.buffer_to_send.unwrap();

        // Step 3: Cliente recebe Salt, N, g e emite A
        let step3_out = client.step(Some(&step2_buf)).unwrap();
        assert!(!step3_out.is_complete);
        let step3_buf = step3_out.buffer_to_send.unwrap();

        // Step 4: Servidor recebe A e emite B
        let step4_out = server.step(&step3_buf).unwrap();
        assert!(!step4_out.is_complete);
        let step4_buf = step4_out.buffer_to_send.unwrap();

        // Step 5: Cliente recebe B e emite M1
        let step5_out = client.step(Some(&step4_buf)).unwrap();
        assert!(!step5_out.is_complete);
        let step5_buf = step5_out.buffer_to_send.unwrap();

        // Step 6: Servidor recebe M1, valida e emite M2 (completo!)
        let step6_out = server.step(&step5_buf).unwrap();
        assert!(step6_out.is_complete);
        assert!(server.is_established());
        let step6_buf = step6_out.buffer_to_send.unwrap();

        // Cliente recebe M2 e valida (completo!)
        let client_final = client.step(Some(&step6_buf)).unwrap();
        assert!(client_final.is_complete);
        assert!(client.is_established());
        assert!(client_final.buffer_to_send.is_none());

        // Validação definitiva: Ambas as partes devem concordar na chave de 32 bytes!
        let client_key = client.session_key().unwrap();
        let server_key = server.session_key().unwrap();
        assert_eq!(client_key, server_key);
        assert_ne!(client_key, [0u8; 32]);

        // Cifra Famatech pode ser criada com a chave derivada
        let mut cipher = client.create_cipher_state().unwrap();
        let plaintext = b"Radmin VPN Phase 2 Control Test Message";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
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

        // Step 1
        let step1 = client.step(None).unwrap().buffer_to_send.unwrap();
        // Step 2
        let step2 = server.step(&step1).unwrap().buffer_to_send.unwrap();
        // Step 3
        let step3 = client.step(Some(&step2)).unwrap().buffer_to_send.unwrap();
        // Step 4
        let step4 = server.step(&step3).unwrap().buffer_to_send.unwrap();
        // Step 5 (Cliente calcula M1 com senha errada)
        let step5 = client.step(Some(&step4)).unwrap().buffer_to_send.unwrap();

        // Servidor rejeita M1 incorreto
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

        // Adultera o byte da prova M2
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

        // Em vez do Step 2, envia Step 5
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
    fn test_random_srp_exponent_bounds_and_entropy() {
        let prime_n = get_srp_prime_n().unwrap();
        let one = BigNum::from_u32(1).unwrap();
        let mut n_minus_1 = BigNum::new().unwrap();
        n_minus_1.checked_sub(&prime_n, &one).unwrap();

        for _ in 0..10 {
            let exp = random_srp_exponent(&prime_n).unwrap();
            assert!(exp > one);
            assert!(exp < n_minus_1);
            // Entropia substancial: pelo menos 1500 bits
            assert!(exp.num_bits() >= 1500);
        }
    }

    #[test]
    fn test_validate_srp_public_value_strict_checks() {
        let prime_n = get_srp_prime_n().unwrap();

        // 1. Chave canônica válida (1 < A < N, 192 bytes)
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

        // 2. Tamanhos incorretos (não canônicos)
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

        // 3. Valor Zero (0 mod N == 0)
        let zero_bytes = vec![0u8; 192];
        assert_eq!(
            validate_srp_public_value(&zero_bytes, &prime_n),
            Err(ControlHandshakeError::InvalidPublicEphemeral)
        );

        // 4. Valor exatamente igual a N (N mod N == 0)
        let n_bytes = pad_bignum_bytes(&prime_n.to_vec(), RADMIN_SRP1536_MODULUS_LEN);
        assert_eq!(
            validate_srp_public_value(&n_bytes, &prime_n),
            Err(ControlHandshakeError::InvalidPublicEphemeral)
        );

        // 5. Valor maior que N (N + 1)
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

        // Servidor em estado de falha deve rejeitar passos adicionais (fail-closed)
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

        // Adultera a prova M1 no Step 5
        let last_idx = s5.len() - 1;
        s5[last_idx] ^= 0xAA;

        let err = server.step(&s5);
        assert_eq!(err, Err(ControlHandshakeError::ProofVerificationFailed));
        assert!(!server.is_established());

        // Servidor fail-closed
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

        // Monta Step 3 malicioso com A = 0
        let item_step3 = encode_item(TAG_STEP, &3u32.to_le_bytes()).unwrap();
        let item_bad_a = encode_item(TAG_PUBLIC_EPHEMERAL, &[0u8; 192]).unwrap();
        let mut malformed_s3 = item_step3;
        malformed_s3.extend_from_slice(&item_bad_a);

        let err = server.step(&malformed_s3);
        assert_eq!(err, Err(ControlHandshakeError::InvalidPublicEphemeral));
        assert!(!server.is_established());

        // Fail-closed
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

        // Servidor envia Step 4 com B inválido (tamanho truncado de 100 bytes)
        let item_step4 = encode_item(TAG_STEP, &4u32.to_le_bytes()).unwrap();
        let item_bad_b = encode_item(TAG_PUBLIC_EPHEMERAL, &[0x44; 100]).unwrap();
        let mut malformed_s4 = item_step4;
        malformed_s4.extend_from_slice(&item_bad_b);

        let err = client.step(Some(&malformed_s4));
        assert_eq!(err, Err(ControlHandshakeError::InvalidPublicEphemeral));
        assert!(!client.is_established());

        // Fail-closed
        assert!(matches!(
            client.step(Some(&malformed_s4)),
            Err(ControlHandshakeError::InvalidState(_))
        ));
    }

    #[test]
    fn test_srp_handshake_divergent_group_parameters_rejected() {
        let username = "alice";
        let password = "password";

        let mut client = ControlClientNegotiator::new(username.to_string(), password.to_string());
        let _s1 = client.step(None).unwrap();

        let prime_n = get_srp_prime_n().unwrap();
        let item_step2 = encode_item(TAG_STEP, &2u32.to_le_bytes()).unwrap();
        let item_salt = encode_item(TAG_SALT, &[0x11; 16]).unwrap();
        let item_n = encode_item(TAG_MODULUS, &prime_n.to_vec()).unwrap();
        // Gerador g incorreto: 2 em vez de 5
        let item_bad_g = encode_item(TAG_GENERATOR, &[2u8]).unwrap();

        let mut s2_bad = Vec::new();
        s2_bad.extend_from_slice(&item_step2);
        s2_bad.extend_from_slice(&item_salt);
        s2_bad.extend_from_slice(&item_n);
        s2_bad.extend_from_slice(&item_bad_g);

        let err = client.step(Some(&s2_bad));
        assert_eq!(err, Err(ControlHandshakeError::InvalidGroupParameters));
        assert!(!client.is_established());

        // Fail-closed
        assert!(matches!(
            client.step(Some(&s2_bad)),
            Err(ControlHandshakeError::InvalidState(_))
        ));
    }

    #[test]
    fn test_failed_session_cannot_be_reused() {
        let mut client = ControlClientNegotiator::new("alice".into(), "pass".into());
        // Força falha passando entrada no Step 0
        let err = client.step(Some(&[1, 2, 3]));
        assert!(err.is_err());
        assert!(!client.is_established());

        // Tentativa de executar step novamente deve falhar imediatamente
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
