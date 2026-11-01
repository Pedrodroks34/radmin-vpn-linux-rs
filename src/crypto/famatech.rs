use openssl::hash::{hash, MessageDigest};
use openssl::symm::{Cipher, Crypter, Mode};
use thiserror::Error;

pub const BLOCK_SIZE: usize = 16;
pub const TRAILER_SIZE: usize = 9;
pub const MIN_PAD_LEN: usize = 9;
pub const MAX_PAD_LEN: usize = 24;
pub const PAD_BYTE: u8 = 0xCC;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("payload vazio não permitido")]
    EmptyPayload,
    #[error("tamanho de ciphertext inválido: {size} (deve ser múltiplo de 16 e >= 16)")]
    InvalidCiphertextSize { size: usize },
    #[error("tamanho de padding inválido: {pad_len} (deve estar entre 9 e 24)")]
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

/// Calcula o checksum aditivo little-endian de 64 bits (FUN_1006a0c0).
/// Percorre palavras de 64 bits em little-endian. Se restar cauda (< 8 bytes),
/// preenche com zeros à direita até 8 bytes e soma.
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn famatech_checksum_64(data: &[u8]) -> u64 {
    let mut sum: u64 = 0;
    let chunks = data.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
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

/// Calcula o MD5 do checksum de 64 bits (8 bytes LE) e dobra os 16 bytes em 8 bytes (FUN_100638f0):
/// digest[i] += digest[i + 8] para i in 0..8.
pub fn famatech_fold_md5(sum_64: u64) -> [u8; 8] {
    let sum_bytes = sum_64.to_le_bytes();
    let digest = hash(MessageDigest::md5(), &sum_bytes).expect("cálculo de MD5 falhou");

    let mut folded = [0u8; 8];
    for i in 0..8 {
        folded[i] = digest[i].wrapping_add(digest[i + 8]);
    }
    folded
}

/// Aplica o padding proprietário Famatech e anexa o trailer de integridade (FUN_10069c20).
///
/// Layout:
/// - total_len = ((payload_len + 24) / 16) * 16
/// - pad_len = total_len - payload_len (9 <= pad_len <= 24)
/// - payload copiado em 0..payload_len
/// - bytes 0xCC em payload_len..(total_len - 9)
/// - 8 bytes MD5 dobrado em (total_len - 9)..(total_len - 1)
/// - 1 byte pad_len em (total_len - 1)
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

    // Calcula checksum sobre os primeiros total_len - 9 bytes
    let sum_64 = famatech_checksum_64(&buf[..cc_end]);
    let folded_mac = famatech_fold_md5(sum_64);

    // Grava trailer: 8 bytes MAC + 1 byte pad_len
    buf[cc_end..total_len - 1].copy_from_slice(&folded_mac);
    buf[total_len - 1] = pad_len as u8;

    Ok(buf)
}

/// Verifica a integridade, remove o trailer e descarta o padding (FUN_10069f90).
pub fn famatech_verify_and_unpad(buf: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if buf.len() < BLOCK_SIZE || !buf.len().is_multiple_of(BLOCK_SIZE) {
        return Err(CryptoError::InvalidCiphertextSize { size: buf.len() });
    }

    let total_len = buf.len();
    let pad_len = buf[total_len - 1] as usize;

    if !(MIN_PAD_LEN..=MAX_PAD_LEN).contains(&pad_len) || pad_len > total_len {
        return Err(CryptoError::InvalidPaddingLength { pad_len });
    }

    let payload_len = total_len - pad_len;
    let cc_end = total_len - TRAILER_SIZE;

    // Valida bytes 0xCC
    for (i, &b) in buf[payload_len..cc_end].iter().enumerate() {
        if b != PAD_BYTE {
            return Err(CryptoError::CorruptedPaddingByte {
                offset: payload_len + i,
                found: b,
            });
        }
    }

    // Verifica trailer de integridade
    let sum_64 = famatech_checksum_64(&buf[..cc_end]);
    let expected_mac = famatech_fold_md5(sum_64);
    let received_mac = &buf[cc_end..total_len - 1];

    if received_mac != expected_mac {
        return Err(CryptoError::TrailerMismatch);
    }

    Ok(buf[..payload_len].to_vec())
}

/// Estado do canal criptográfico AES-256-CBC contínuo da Famatech.
///
/// Mantém a chave de 256 bits e o vetor de inicialização (IV) de 128 bits.
/// O IV inicial é 16 bytes zero. Cada pacote cifrado/decifrado atualiza o IV
/// com os últimos 16 bytes do ciphertext.
#[derive(Debug, Clone)]
pub struct FamatechCipherState {
    key: [u8; 32],
    enc_iv: [u8; 16],
    dec_iv: [u8; 16],
}

impl FamatechCipherState {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            enc_iv: [0u8; 16],
            dec_iv: [0u8; 16],
        }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn enc_iv(&self) -> &[u8; 16] {
        &self.enc_iv
    }

    pub fn dec_iv(&self) -> &[u8; 16] {
        &self.dec_iv
    }

    /// Cifra um payload usando o protocolo Famatech:
    /// 1. Adiciona padding 0xCC e trailer de integridade
    /// 2. Cifra o bloco resultante usando AES-256-CBC com o enc_iv atual
    /// 3. Atualiza enc_iv com o último bloco de 16 bytes do ciphertext gerado
    pub fn encrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let padded = famatech_pad_and_sign(payload)?;
        debug_assert_eq!(padded.len() % BLOCK_SIZE, 0);

        let mut crypter = Crypter::new(
            Cipher::aes_256_cbc(),
            Mode::Encrypt,
            &self.key,
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

        // Atualiza IV de envio com o último bloco de ciphertext
        let last_block_start = ciphertext.len() - BLOCK_SIZE;
        self.enc_iv.copy_from_slice(&ciphertext[last_block_start..]);

        Ok(ciphertext)
    }

    /// Decifra um pacote usando o protocolo Famatech:
    /// 1. Valida tamanho múltiplo de 16
    /// 2. Decifra usando AES-256-CBC com o dec_iv atual
    /// 3. Atualiza dec_iv com o último bloco de 16 bytes do ciphertext recebido
    /// 4. Valida padding 0xCC, verifica integridade do trailer e retorna payload original
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < BLOCK_SIZE || !ciphertext.len().is_multiple_of(BLOCK_SIZE) {
            return Err(CryptoError::InvalidCiphertextSize {
                size: ciphertext.len(),
            });
        }

        let mut crypter = Crypter::new(
            Cipher::aes_256_cbc(),
            Mode::Decrypt,
            &self.key,
            Some(&self.dec_iv),
        )
        .map_err(|e| CryptoError::OpenSslError(e.to_string()))?;

        crypter.pad(false);

        let mut plaintext = vec![0u8; ciphertext.len() + BLOCK_SIZE];
        let mut count = crypter
            .update(ciphertext, &mut plaintext)
            .map_err(|e| CryptoError::OpenSslError(e.to_string()))?;
        count += crypter
            .finalize(&mut plaintext[count..])
            .map_err(|e| CryptoError::OpenSslError(e.to_string()))?;
        plaintext.truncate(count);

        // Atualiza IV de recepção com o último bloco do ciphertext
        let last_block_start = ciphertext.len() - BLOCK_SIZE;
        self.dec_iv.copy_from_slice(&ciphertext[last_block_start..]);

        // Valida e desempacota
        famatech_verify_and_unpad(&plaintext)
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
}
