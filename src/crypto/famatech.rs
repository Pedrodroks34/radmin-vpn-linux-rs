//! Canal criptográfico proprietário Famatech (`SHelper_CChannel_*` em `shelper.dll`).
//!
//! Evidências binárias verificadas por desmontagem estática de `shelper.dll` e `RvROLClient.dll`:
//! - `shelper.dll!0x10062ca9` (`CChannel_Init`): inicializa a estrutura de `0x20c` bytes,
//!   zerando `enc_iv` (`+0x1ec`, 16 bytes) e `dec_iv` (`+0x1fc`, 16 bytes) com `[0u8; 16]`.
//! - `shelper.dll!0x10062c80` (`CChannel_Clear`): limpa integralmente os `0x20c` bytes (`memset 0`).
//! - `shelper.dll!0x10062e00` (`CChannel_SetKeyEnc`): exige `key_len == 0x20` (32 bytes) e
//!   configura chave de cifragem AES-256 (`0x100` bits) via `AES_set_encrypt_key`.
//! - `shelper.dll!0x10062d60` (`CChannel_SetKeyDec`): exige `key_len == 0x20` (32 bytes) e
//!   configura chave de decifragem AES-256 (`0x100` bits) via `AES_set_decrypt_key`.
//! - `RvROLClient.dll!0x100df250` (`CChannelWrapper::Create`), `0x100df470` (`SetKey`),
//!   `0x1003de29..0x1003de50` e `0x10096f0d..0x10096f21`: recebe o buffer de chave da sessão
//!   (64 bytes em `SHelper_RSession_GetKey`), valida `len >= 0x20` e passa os primeiros 32 bytes
//!   (`&key_buf[0..32]`) tanto para `key_enc` quanto para `key_dec`.
//! - `shelper.dll!0x10069c20` (`pad_and_sign`):
//!   - `total_len = (payload_len + 24) & !15` (`pad_len = total_len - payload_len` em `9..=24`).
//!   - Preenche `buf[payload_len .. total_len - 9]` com `0xCC` (`0x10069c77`).
//!   - Grava `pad_len as u8` em `buf[total_len - 1]` (`0x10069c84`).
//!   - Zera os 8 bytes `buf[total_len - 9 .. total_len - 1]` (`0x10069c88..0x10069c8f`).
//!   - Chama `shelper.dll!0x1006a0c0` sobre `buf[0 .. total_len - 9]` (soma aditiva de palavras
//!     64-bit little-endian com zero-fill na cauda `< 8` bytes) e grava a soma temporariamente em
//!     `buf[total_len - 9 .. total_len - 1]` (`0x10069ca2..0x10069ca6`).
//!   - Em seguida (`0x10069cb2`), chama `shelper.dll!0x100638f0` passando esses 8 bytes da soma,
//!     calcula o MD5 de 16 bytes e dobra-o em 8 bytes (`digest[i].wrapping_add(digest[i + 8])`),
//!     sobrescrevendo `buf[total_len - 9 .. total_len - 1]` (`0x10069cbd..0x10069cc5`).
//!   - Nota forense: o relatório `reverse-engineering/round-02/02-cryptography.md` interrompeu a
//!     leitura em `0x10069ca6` e afirmou incorretamente que o trailer seria a soma bruta de 64 bits;
//!     a desmontagem completa de `0x10069ca2..0x10069cc5` e do verificador `0x10069f90`
//!     (`0x1006a026..0x1006a06c`) comprova que o trailer no fio é o MD5 dobrado de 8 bytes.
//! - `shelper.dll!0x10069f90` (`verify_and_unpad`):
//!   - Exige `pad_len >= 9` (`0x1006a007: cmp ebx, 0x9; jb`) e `pad_len < total_len`
//!     (`0x1006a00e: cmp ebx, esi; jae`, garantindo pelo menos 1 byte de payload).
//!   - Verifica o trailer via `0x1006a0c0` + `0x100638f0` e valida todos os bytes `0xCC`.
//! - `shelper.dll!0x10063000` (`CChannel_Encrypt`) e `0x100630f0` (`CChannel_Decrypt`):
//!   - Opera AES-256-CBC contínuo por direção: `AES_cbc_encrypt` atualiza `enc_iv` (`+0x1ec`) e
//!     `dec_iv` (`+0x1fc`) in-place com os últimos 16 bytes do ciphertext processado.

use openssl::hash::{hash, MessageDigest};
use openssl::symm::{Cipher, Crypter, Mode};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const BLOCK_SIZE: usize = 16;
pub const AES_256_KEY_SIZE: usize = 32;
pub const RSESSION_KEY_BUFFER_SIZE: usize = 64;
pub const TRAILER_SIZE: usize = 9;
pub const MIN_PAD_LEN: usize = 9;
pub const MAX_PAD_LEN: usize = 24;
pub const PAD_BYTE: u8 = 0xCC;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("payload vazio não permitido")]
    EmptyPayload,
    #[error("tamanho de chave inválido: {size} bytes (esperado {expected} bytes)")]
    InvalidKeyLength { expected: usize, size: usize },
    #[error("tamanho de ciphertext inválido: {size} (deve ser múltiplo de 16 e >= 16)")]
    InvalidCiphertextSize { size: usize },
    #[error("tamanho de padding inválido: {pad_len} (deve estar entre 9 e 24 e ser menor que o bloco total)")]
    InvalidPaddingLength { pad_len: usize },
    #[error(
        "byte de padding corrompido na posição {offset}: esperado 0xCC, encontrado 0x{found:02x}"
    )]
    CorruptedPaddingByte { offset: usize, found: u8 },
    #[error("trailer corrompido: hash MD5 dobrado não confere")]
    TrailerMismatch,
    #[error("falha na operação OpenSSL: {0}")]
    OpenSslError(String),
}

/// Calcula o checksum aditivo little-endian de 64 bits (`shelper.dll!0x1006a0c0`).
/// Percorre palavras de 64 bits em little-endian. Se restar cauda (`< 8` bytes),
/// copia para um buffer temporário de 8 bytes preenchido com zeros à direita e soma.
pub fn famatech_checksum_64(data: &[u8]) -> u64 {
    let mut sum: u64 = 0;
    let (chunks, remainder) = data.as_chunks::<8>();

    for chunk in chunks {
        let word = u64::from_le_bytes(*chunk);
        sum = sum.wrapping_add(word);
    }

    if !remainder.is_empty() {
        let mut tail = [0u8; 8];
        tail[..remainder.len()].copy_from_slice(remainder);
        let word = u64::from_le_bytes(tail);
        sum = sum.wrapping_add(word);
    }

    sum
}

/// Calcula o MD5 do checksum de 64 bits (8 bytes LE) e dobra os 16 bytes em 8 bytes
/// (`shelper.dll!0x100638f0`): `digest[i] = digest[i].wrapping_add(digest[i + 8])` para `i in 0..8`.
pub fn famatech_fold_md5(sum_64: u64) -> [u8; 8] {
    let sum_bytes = sum_64.to_le_bytes();
    let digest = hash(MessageDigest::md5(), &sum_bytes).expect("cálculo de MD5 falhou");

    let mut folded = [0u8; 8];
    for i in 0..8 {
        folded[i] = digest[i].wrapping_add(digest[i + 8]);
    }
    folded
}

/// Aplica o padding proprietário Famatech e anexa o trailer de integridade (`shelper.dll!0x10069c20`).
///
/// Layout:
/// - `total_len = ((payload_len + 24) / 16) * 16`
/// - `pad_len = total_len - payload_len` (`9 <= pad_len <= 24`)
/// - `payload` copiado em `0..payload_len`
/// - bytes `0xCC` em `payload_len..(total_len - 9)`
/// - 8 bytes MD5 dobrado em `(total_len - 9)..(total_len - 1)`
/// - 1 byte `pad_len` em `total_len - 1`
pub fn famatech_pad_and_sign(payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if payload.is_empty() {
        return Err(CryptoError::EmptyPayload);
    }

    let payload_len = payload.len();
    let total_len = ((payload_len + 24) / BLOCK_SIZE) * BLOCK_SIZE;
    let pad_len = total_len - payload_len;

    debug_assert!((MIN_PAD_LEN..=MAX_PAD_LEN).contains(&pad_len));

    let mut buf = vec![0u8; total_len];
    buf[..payload_len].copy_from_slice(payload);

    // Preenche com 0xCC do fim do payload até total_len - 9
    let cc_end = total_len - TRAILER_SIZE;
    for b in &mut buf[payload_len..cc_end] {
        *b = PAD_BYTE;
    }

    // Calcula checksum sobre os primeiros total_len - 9 bytes (0x1006a0c0 + 0x100638f0)
    let sum_64 = famatech_checksum_64(&buf[..cc_end]);
    let folded_mac = famatech_fold_md5(sum_64);

    // Grava trailer: 8 bytes MAC + 1 byte pad_len
    buf[cc_end..total_len - 1].copy_from_slice(&folded_mac);
    buf[total_len - 1] = pad_len as u8;

    Ok(buf)
}

/// Verifica a integridade, remove o trailer e descarta o padding (`shelper.dll!0x10069f90`).
pub fn famatech_verify_and_unpad(buf: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if buf.len() < BLOCK_SIZE || !buf.len().is_multiple_of(BLOCK_SIZE) {
        return Err(CryptoError::InvalidCiphertextSize { size: buf.len() });
    }

    let total_len = buf.len();
    let pad_len = buf[total_len - 1] as usize;

    // Em shelper.dll!0x1006a007..0x1006a010:
    // cmp ebx, 0x9; jb 0x1006a0aa
    // cmp ebx, esi; jae 0x1006a0aa (rejeita pad_len >= total_len, exigindo >= 1 byte de payload)
    if !(MIN_PAD_LEN..=MAX_PAD_LEN).contains(&pad_len) || pad_len >= total_len {
        return Err(CryptoError::InvalidPaddingLength { pad_len });
    }

    let payload_len = total_len - pad_len;
    let cc_end = total_len - TRAILER_SIZE;

    // Verifica trailer de integridade (0x1006a026..0x1006a06c) e bytes 0xCC (0x1006a076..0x1006a080)
    for (i, &b) in buf[payload_len..cc_end].iter().enumerate() {
        if b != PAD_BYTE {
            return Err(CryptoError::CorruptedPaddingByte {
                offset: payload_len + i,
                found: b,
            });
        }
    }

    let sum_64 = famatech_checksum_64(&buf[..cc_end]);
    let expected_mac = famatech_fold_md5(sum_64);
    let received_mac = &buf[cc_end..total_len - 1];

    if received_mac != expected_mac {
        return Err(CryptoError::TrailerMismatch);
    }

    Ok(buf[..payload_len].to_vec())
}

/// Estado do canal criptográfico AES-256-CBC contínuo da Famatech (`SHelper_CChannel`).
///
/// Reproduz a estrutura inicializada em `shelper.dll!0x10062ca9`:
/// - `enc_key`: chave de cifragem AES-256 (32 bytes, configurada via `0x10062e00`)
/// - `dec_key`: chave de decifragem AES-256 (32 bytes, configurada via `0x10062d60`)
/// - `enc_iv`: IV de envio de 16 bytes (`+0x1ec`, inicializado com zeros)
/// - `dec_iv`: IV de recepção de 16 bytes (`+0x1fc`, inicializado com zeros)
pub struct FamatechCipherState {
    enc_key: [u8; AES_256_KEY_SIZE],
    dec_key: [u8; AES_256_KEY_SIZE],
    enc_iv: [u8; BLOCK_SIZE],
    dec_iv: [u8; BLOCK_SIZE],
}

impl std::fmt::Debug for FamatechCipherState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FamatechCipherState")
            .field("enc_key", &"[REDACTED]")
            .field("dec_key", &"[REDACTED]")
            .field("enc_iv", &"[REDACTED]")
            .field("dec_iv", &"[REDACTED]")
            .finish()
    }
}

impl FamatechCipherState {
    /// Inicializa o canal com a mesma chave de 32 bytes para cifragem e decifragem e IVs zerados
    /// (`RvROLClient.dll!0x100df250` / `shelper.dll!0x10062ca9`).
    pub fn new(key: [u8; AES_256_KEY_SIZE]) -> Self {
        Self {
            enc_key: key,
            dec_key: key,
            enc_iv: [0u8; BLOCK_SIZE],
            dec_iv: [0u8; BLOCK_SIZE],
        }
    }

    /// Inicializa o canal com chaves de 32 bytes explícitas para envio e recepção
    /// (`shelper.dll!0x1006a8b0` `SHelper_CChannel_CreateClient` / `0x1006a990` `CreateServer`).
    pub fn with_separate_keys(
        enc_key: [u8; AES_256_KEY_SIZE],
        dec_key: [u8; AES_256_KEY_SIZE],
    ) -> Self {
        Self {
            enc_key,
            dec_key,
            enc_iv: [0u8; BLOCK_SIZE],
            dec_iv: [0u8; BLOCK_SIZE],
        }
    }

    /// Inicializa o canal a partir do buffer de 64 bytes retornado por `SHelper_RSession_GetKey`
    /// (`shelper.dll!0x1006ba80` -> `0x1006a270`), conforme comprovado em
    /// `RvROLClient.dll!0x10096f0d..0x10096f21`, `0x100df250` e `0x100df470`:
    /// os primeiros 32 bytes (`0..32`) são instalados como `key_enc` e `key_dec`.
    pub fn from_rsession_key(key_material: &[u8; RSESSION_KEY_BUFFER_SIZE]) -> Self {
        let mut key = [0u8; AES_256_KEY_SIZE];
        key.copy_from_slice(&key_material[..AES_256_KEY_SIZE]);
        Self::new(key)
    }

    /// Atualiza a chave de cifragem (`shelper.dll!0x10062e00` `CChannel_SetKeyEnc`),
    /// exigindo exatamente 32 bytes (`0x20`).
    pub fn set_key_enc(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        if key.len() != AES_256_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: AES_256_KEY_SIZE,
                size: key.len(),
            });
        }
        self.enc_key.copy_from_slice(key);
        Ok(())
    }

    /// Atualiza a chave de decifragem (`shelper.dll!0x10062d60` `CChannel_SetKeyDec`),
    /// exigindo exatamente 32 bytes (`0x20`).
    pub fn set_key_dec(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        if key.len() != AES_256_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: AES_256_KEY_SIZE,
                size: key.len(),
            });
        }
        self.dec_key.copy_from_slice(key);
        Ok(())
    }

    /// Atualiza ambas as chaves a partir de um buffer de sessão (`RvROLClient.dll!0x100df470`),
    /// exigindo pelo menos 32 bytes (`cmp len, 0x20; jb`) e utilizando `&key_buf[0..32]`.
    pub fn set_key_from_session_buffer(&mut self, key_buf: &[u8]) -> Result<(), CryptoError> {
        if key_buf.len() < AES_256_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: AES_256_KEY_SIZE,
                size: key_buf.len(),
            });
        }
        let slice = &key_buf[..AES_256_KEY_SIZE];
        self.set_key_enc(slice)?;
        self.set_key_dec(slice)?;
        Ok(())
    }

    /// Limpa chaves e IVs em memória (`shelper.dll!0x10062c80` `CChannel_Clear`).
    pub fn clear(&mut self) {
        self.enc_key.zeroize();
        self.dec_key.zeroize();
        self.enc_iv.zeroize();
        self.dec_iv.zeroize();
    }

    pub fn key(&self) -> &[u8; AES_256_KEY_SIZE] {
        &self.enc_key
    }

    pub fn enc_key(&self) -> &[u8; AES_256_KEY_SIZE] {
        &self.enc_key
    }

    pub fn dec_key(&self) -> &[u8; AES_256_KEY_SIZE] {
        &self.dec_key
    }

    pub fn enc_iv(&self) -> &[u8; BLOCK_SIZE] {
        &self.enc_iv
    }

    pub fn dec_iv(&self) -> &[u8; BLOCK_SIZE] {
        &self.dec_iv
    }

    /// Cifra um payload usando o protocolo Famatech (`shelper.dll!0x10063000`):
    /// 1. Adiciona padding `0xCC` e trailer de integridade (`0x10069c20`)
    /// 2. Cifra o bloco resultante usando AES-256-CBC com o `enc_iv` atual
    /// 3. Atualiza `enc_iv` com o último bloco de 16 bytes do ciphertext gerado
    pub fn encrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let padded = Zeroizing::new(famatech_pad_and_sign(payload)?);
        debug_assert_eq!(padded.len() % BLOCK_SIZE, 0);

        let mut crypter = Crypter::new(
            Cipher::aes_256_cbc(),
            Mode::Encrypt,
            &self.enc_key,
            Some(&self.enc_iv),
        )
        .map_err(|e| CryptoError::OpenSslError(e.to_string()))?;

        crypter.pad(false);

        let mut ciphertext = vec![0u8; padded.len() + BLOCK_SIZE];
        let mut count = crypter
            .update(&padded, &mut ciphertext)
            .map_err(|e| CryptoError::OpenSslError(e.to_string()))?;
        count += crypter
            .finalize(&mut ciphertext[count..])
            .map_err(|e| CryptoError::OpenSslError(e.to_string()))?;
        ciphertext.truncate(count);

        if ciphertext.len() < BLOCK_SIZE {
            return Err(CryptoError::InvalidCiphertextSize {
                size: ciphertext.len(),
            });
        }

        // Atualiza IV de envio com o último bloco de ciphertext (AES_cbc_encrypt in-place ivec)
        let last_block_start = ciphertext.len() - BLOCK_SIZE;
        self.enc_iv.copy_from_slice(&ciphertext[last_block_start..]);

        Ok(ciphertext)
    }

    /// Decifra um pacote usando o protocolo Famatech (`shelper.dll!0x100630f0`):
    /// 1. Valida tamanho múltiplo de 16 e `>= 16` (`0x10063110..0x1006311f`)
    /// 2. Decifra usando AES-256-CBC com o `dec_iv` atual
    /// 3. Atualiza `dec_iv` com o último bloco de 16 bytes do ciphertext recebido
    /// 4. Valida padding `0xCC`, verifica integridade do trailer e retorna payload original (`0x10069f90`)
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < BLOCK_SIZE || !ciphertext.len().is_multiple_of(BLOCK_SIZE) {
            return Err(CryptoError::InvalidCiphertextSize {
                size: ciphertext.len(),
            });
        }

        let mut crypter = Crypter::new(
            Cipher::aes_256_cbc(),
            Mode::Decrypt,
            &self.dec_key,
            Some(&self.dec_iv),
        )
        .map_err(|e| CryptoError::OpenSslError(e.to_string()))?;

        crypter.pad(false);

        let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len() + BLOCK_SIZE]);
        let mut count = crypter
            .update(ciphertext, &mut plaintext)
            .map_err(|e| CryptoError::OpenSslError(e.to_string()))?;
        count += crypter
            .finalize(&mut plaintext[count..])
            .map_err(|e| CryptoError::OpenSslError(e.to_string()))?;
        plaintext.truncate(count);

        // Atualiza IV de recepção com o último bloco do ciphertext antes de 0x10069f90
        let last_block_start = ciphertext.len() - BLOCK_SIZE;
        self.dec_iv.copy_from_slice(&ciphertext[last_block_start..]);

        // Valida e desempacota (0x10069f90). Plaintext é zeroizado automaticamente via Drop do Zeroizing
        // mesmo em caso de erro no trailer ou na remoção do padding.
        famatech_verify_and_unpad(&plaintext)
    }
}

impl Drop for FamatechCipherState {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_payload_rejection() {
        assert_eq!(famatech_pad_and_sign(&[]), Err(CryptoError::EmptyPayload));
    }

    #[test]
    fn test_padding_bounds_and_alignment() {
        for len in 1..=128 {
            let data = vec![0x42; len];
            let padded = famatech_pad_and_sign(&data).expect("padding deve ter sucesso");
            assert_eq!(padded.len() % 16, 0);
            let pad_len = padded[padded.len() - 1] as usize;
            assert!((9..=24).contains(&pad_len));
            assert_eq!(padded.len() - pad_len, len);

            let unpadded = famatech_verify_and_unpad(&padded).expect("unpad deve ter sucesso");
            assert_eq!(unpadded, data);
        }
    }

    #[test]
    fn test_checksum_64_endianness() {
        // Teste simples para confirmar endianness LE
        let data = [1u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(famatech_checksum_64(&data), 1);

        let data2 = [0u8, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(famatech_checksum_64(&data2), 256);
    }

    #[test]
    fn test_corrupted_padding_byte() {
        let data = b"Hello, Radmin VPN!";
        let mut padded = famatech_pad_and_sign(data).unwrap();
        // Altera um byte do padding 0xCC
        let total_len = padded.len();
        let pad_len = padded[total_len - 1] as usize;
        let payload_len = total_len - pad_len;
        if pad_len > 9 {
            padded[payload_len] = 0xAA;
            let res = famatech_verify_and_unpad(&padded);
            assert!(matches!(res, Err(CryptoError::CorruptedPaddingByte { .. })));
        }
    }

    #[test]
    fn test_corrupted_trailer_mac() {
        let data = b"Payload for trailer corruption test";
        let mut padded = famatech_pad_and_sign(data).unwrap();
        let total_len = padded.len();
        // Corrompe um byte do MAC (posições total_len - 9 até total_len - 2)
        padded[total_len - 5] ^= 0xFF;
        assert_eq!(
            famatech_verify_and_unpad(&padded),
            Err(CryptoError::TrailerMismatch)
        );
    }

    #[test]
    fn test_corrupted_pad_len_byte() {
        let data = b"Test pad len";
        let mut padded = famatech_pad_and_sign(data).unwrap();
        let total_len = padded.len();
        padded[total_len - 1] = 5; // < 9 é inválido
        assert_eq!(
            famatech_verify_and_unpad(&padded),
            Err(CryptoError::InvalidPaddingLength { pad_len: 5 })
        );

        padded[total_len - 1] = 30; // > 24 é inválido
        assert_eq!(
            famatech_verify_and_unpad(&padded),
            Err(CryptoError::InvalidPaddingLength { pad_len: 30 })
        );
    }

    #[test]
    fn test_cipher_state_roundtrip_various_lengths() {
        let key = [0x55u8; 32];
        let mut enc = FamatechCipherState::new(key);
        let mut dec = FamatechCipherState::new(key);

        let test_sizes = [1, 4, 7, 8, 15, 16, 23, 24, 31, 32, 100, 288, 1400];
        for (i, &size) in test_sizes.iter().enumerate() {
            let payload: Vec<u8> = (0..size).map(|b| (b + i) as u8).collect();
            let ciphertext = enc.encrypt(&payload).expect("cifragem falhou");
            assert_eq!(ciphertext.len() % 16, 0);

            let decrypted = dec.decrypt(&ciphertext).expect("decifragem falhou");
            assert_eq!(decrypted, payload, "falha para tamanho {}", size);
        }
    }

    #[test]
    fn test_continuous_cbc_iv_chaining() {
        let key = [0x77u8; 32];
        let mut enc = FamatechCipherState::new(key);
        let mut dec = FamatechCipherState::new(key);

        // Envia múltiplos pacotes consecutivos e garante que a cadeia de IV funciona
        for i in 0..10 {
            let msg = format!("Mensagem sequencial número {}", i).into_bytes();
            let ct = enc.encrypt(&msg).unwrap();
            let pt = dec.decrypt(&ct).unwrap();
            assert_eq!(pt, msg);
        }

        // Se descriptografarmos fora de ordem com o mesmo decryptor, deve falhar
        let msg_a = b"Primeiro pacote".to_vec();
        let msg_b = b"Segundo pacote".to_vec();
        let _ = enc.encrypt(&msg_a).unwrap();
        let ct_b = enc.encrypt(&msg_b).unwrap();

        // Tentar decifrar ct_b antes de ct_a
        let err = dec.decrypt(&ct_b);
        assert!(
            err.is_err(),
            "decifrar fora da ordem CBC deve falhar no trailer/padding"
        );
    }

    #[test]
    fn test_payload_ending_in_0xcc() {
        // Caso de borda crítico: se o payload terminar naturalmente com bytes 0xCC,
        // o algoritmo deve usar pad_len para saber exatamente onde o payload termina!
        let mut payload = vec![0x11, 0x22, 0x33];
        payload.extend_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC]);

        let key = [0xAAu8; 32];
        let mut enc = FamatechCipherState::new(key);
        let mut dec = FamatechCipherState::new(key);

        let ct = enc.encrypt(&payload).unwrap();
        let pt = dec.decrypt(&ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn test_reject_pad_len_equal_to_total_len_0x1006a00e() {
        // Em shelper.dll!0x1006a00e: cmp ebx, esi; jae 0x1006a0aa
        // Se total_len == 16 e pad_len == 16 (0 bytes de payload), deve ser rejeitado.
        let mut fake_block = [PAD_BYTE; 16];
        let sum = famatech_checksum_64(&fake_block[..7]);
        let mac = famatech_fold_md5(sum);
        fake_block[7..15].copy_from_slice(&mac);
        fake_block[15] = 16;

        assert_eq!(
            famatech_verify_and_unpad(&fake_block),
            Err(CryptoError::InvalidPaddingLength { pad_len: 16 })
        );
    }

    #[test]
    fn test_reject_invalid_ciphertext_sizes() {
        let mut dec = FamatechCipherState::new([0x11u8; 32]);
        for bad_size in [0usize, 1, 4, 8, 15, 17, 24, 31, 33, 47] {
            let buf = vec![0u8; bad_size];
            assert_eq!(
                dec.decrypt(&buf),
                Err(CryptoError::InvalidCiphertextSize { size: bad_size })
            );
            assert_eq!(
                famatech_verify_and_unpad(&buf),
                Err(CryptoError::InvalidCiphertextSize { size: bad_size })
            );
        }
    }

    #[test]
    fn test_rsession_64_byte_key_installation_and_clear() {
        // RvROLClient.dll!0x100df250 / 0x10096f0d: usa os primeiros 32 bytes do buffer de 64 bytes
        let mut rsession_key = [0u8; 64];
        for (i, b) in rsession_key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(7);
        }

        let mut client_cipher = FamatechCipherState::from_rsession_key(&rsession_key);
        let expected_key: [u8; 32] = rsession_key[..32].try_into().unwrap();
        assert_eq!(client_cipher.enc_key(), &expected_key);
        assert_eq!(client_cipher.dec_key(), &expected_key);
        assert_eq!(client_cipher.enc_iv(), &[0u8; 16]);
        assert_eq!(client_cipher.dec_iv(), &[0u8; 16]);

        let mut server_cipher = FamatechCipherState::new([0u8; 32]);
        assert_eq!(
            server_cipher.set_key_from_session_buffer(&rsession_key[..4]),
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                size: 4
            })
        );
        server_cipher
            .set_key_from_session_buffer(&rsession_key)
            .unwrap();

        let ct = client_cipher.encrypt(b"RSession CChannel payload").unwrap();
        let pt = server_cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, b"RSession CChannel payload");

        client_cipher.clear();
        assert_eq!(client_cipher.enc_key(), &[0u8; 32]);
        assert_eq!(client_cipher.dec_key(), &[0u8; 32]);
        assert_eq!(client_cipher.enc_iv(), &[0u8; 16]);
        assert_eq!(client_cipher.dec_iv(), &[0u8; 16]);
    }

    #[test]
    fn test_bidirectional_independent_iv_continuity() {
        let key = [0x99u8; 32];
        let mut peer_a = FamatechCipherState::new(key);
        let mut peer_b = FamatechCipherState::new(key);

        // A envia 2 pacotes seguidos antes de B responder
        let ct_a1 = peer_a.encrypt(b"A -> B packet 1").unwrap();
        let ct_a2 = peer_a.encrypt(b"A -> B packet 2").unwrap();

        // O envio de A não deve alterar o dec_iv de A
        assert_eq!(peer_a.dec_iv(), &[0u8; 16]);
        assert_ne!(peer_a.enc_iv(), &[0u8; 16]);

        // B envia 1 pacote antes de decifrar os pacotes de A
        let ct_b1 = peer_b.encrypt(b"B -> A packet 1").unwrap();
        assert_eq!(peer_b.dec_iv(), &[0u8; 16]);

        // Agora B decifra ct_a1 e ct_a2 em ordem
        assert_eq!(peer_b.decrypt(&ct_a1).unwrap(), b"A -> B packet 1");
        assert_eq!(peer_b.decrypt(&ct_a2).unwrap(), b"A -> B packet 2");
        assert_eq!(peer_b.dec_iv(), peer_a.enc_iv());

        // E A decifra ct_b1
        assert_eq!(peer_a.decrypt(&ct_b1).unwrap(), b"B -> A packet 1");
        assert_eq!(peer_a.dec_iv(), peer_b.enc_iv());
    }
}

#[cfg(test)]
mod state_regression {
    use super::*;

    #[test]
    fn corrupted_middle_block_keeps_receive_chain_in_sync() {
        let key = [0x42u8; 32];
        let mut sender = FamatechCipherState::new(key);
        let mut receiver = FamatechCipherState::new(key);

        let first = sender.encrypt(&[0xa0u8; 60]).unwrap();
        let second = sender.encrypt(&[0xb0u8; 60]).unwrap();

        let mut damaged = first.clone();
        damaged[BLOCK_SIZE] ^= 0xff;
        assert!(receiver.decrypt(&damaged).is_err());

        assert_eq!(receiver.decrypt(&second).unwrap(), vec![0xb0u8; 60]);
    }

    #[test]
    fn corrupted_last_block_desynchronizes_next_packet() {
        let key = [0x42u8; 32];
        let mut sender = FamatechCipherState::new(key);
        let mut receiver = FamatechCipherState::new(key);

        let first = sender.encrypt(&[0xa0u8; 60]).unwrap();
        let second = sender.encrypt(&[0xb0u8; 60]).unwrap();

        let mut damaged = first.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 0xff;
        assert!(receiver.decrypt(&damaged).is_err());

        assert!(receiver.decrypt(&second).is_err());
    }

    #[test]
    fn cipher_state_clear_and_drop_zeroizes_sensitive_material() {
        let key = [0x5au8; 32];
        let mut state = FamatechCipherState::new(key);
        let _ = state.encrypt(b"secret payload test").unwrap();
        assert_ne!(state.enc_iv(), &[0u8; 16]);

        state.clear();
        assert_eq!(state.enc_key(), &[0u8; 32]);
        assert_eq!(state.dec_key(), &[0u8; 32]);
        assert_eq!(state.enc_iv(), &[0u8; 16]);
        assert_eq!(state.dec_iv(), &[0u8; 16]);
    }

    #[test]
    fn test_cipher_state_debug_redacted() {
        let key = [0x77u8; 32];
        let state = FamatechCipherState::new(key);
        let debug_str = format!("{state:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("0x77"));
        assert!(!debug_str.contains("119")); // 0x77 in decimal
    }
}
