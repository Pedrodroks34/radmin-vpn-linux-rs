//! # Módulo `protocol::framing` — Parser de framing TCP do Radmin VPN
//!
//! Implementa o protocolo de framing observado na captura de tráfego real
//! (pcap files em `/tmp/radmin_vm2.pcap` e `/tmp/radmin_17301.pcap`).
//!
//! ## Formato do frame (CONFIRMADO via captura de tráfego)
//!
//! Cada frame consiste em:
//!   - 4 bytes: tamanho do payload, big-endian (uint32_t), NÃO inclui os 4 bytes do cabeçalho
//!   - N bytes: payload (dados criptografados/opacos — estrutura interna desconhecida)
//!
//! Exemplo: `00 00 00 20` + 32 bytes de payload = 36 bytes totais no TCP.
//!
//! ## Grau de confiança
//!
//! - Formato do cabeçalho (4 bytes BE + tamanho): **Confirmado** (vários exemplos nos PCAPs)
//! - Endianness big-endian: **Confirmado** (00 00 00 20 = 32)
//! - Tamanho exclui o próprio cabeçalho: **Confirmado** (verificado em múltiplos frames)
//! - Conteúdo do payload: **Desconhecido** (requer decompilação ou mais capturas direcionadas)
//! - Identificador de tipo de mensagem: **Desconhecido**

use bytes::BufMut;

/// Tamanho do cabeçalho de framing em bytes.
pub const FRAME_HEADER_SIZE: usize = 4;

/// Tamanho máximo permitido para um único payload (proteção contra alocação excessiva).
/// O maior frame observado nos PCAPs foi 3396 bytes totais (3392 de payload).
/// Usamos 65535 como limite razoável para frames futuros.
pub const MAX_PAYLOAD_SIZE: usize = 65535;

/// Um frame TCP do Radmin VPN, pronto para ser enviado ou recém-recebido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedPacket {
    pub payload: Vec<u8>,
}

impl FramedPacket {
    /// Cria um novo frame com o payload fornecido.
    /// Retorna erro se o payload for vazio ou exceder MAX_PAYLOAD_SIZE.
    pub fn new(payload: Vec<u8>) -> Result<Self, FramingError> {
        if payload.is_empty() {
            return Err(FramingError::ZeroPayload);
        }
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(FramingError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }
        Ok(Self { payload })
    }

    /// Serializa o frame para bytes prontos para envio via TCP.
    /// Formato: [u32 BE tamanho][payload...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());
        buf.put_u32(self.payload.len() as u32);
        buf.extend_from_slice(&self.payload);
        buf
    }
}

/// Erros do parser de framing.
#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("buffer insuficiente: são necessários {needed} bytes, apenas {available} disponíveis")]
    InsufficientBuffer { needed: usize, available: usize },
    #[error("tamanho do payload excede o limite: {size} > {max} bytes")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("tamanho de payload inválido: zero")]
    ZeroPayload,
    #[error("frame truncado: EOF no cabeçalho ({available} de {needed} bytes)")]
    TruncatedHeader { needed: usize, available: usize },
    #[error("frame truncado: EOF no payload ({available} de {needed} bytes)")]
    TruncatedPayload { needed: usize, available: usize },
}

/// Parser de fluxo de bytes TCP para extrair frames individuais.
///
/// O TCP é um fluxo de bytes sem delimitação de mensagens. Este parser
/// acumula bytes recebidos e extrai frames completos quando disponíveis,
/// lidando com:
///   - Fragmentação: um frame pode chegar em múltiplas leituras TCP
///   - Agregação: múltiplos frames podem chegar em uma única leitura TCP
pub struct FrameParser {
    buffer: Vec<u8>,
}

impl FrameParser {
    /// Cria um novo parser vazio.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    /// Alimenta bytes brutos recebidos do socket TCP no parser.
    ///
    /// Retorna todos os frames completos que puderam ser extraídos.
    /// Bytes insuficientes para um frame completo permanecem no buffer
    /// para a próxima chamada.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<FramedPacket>, FramingError> {
        self.buffer.extend_from_slice(data);
        self.extract_frames()
    }

    /// Extrai todos os frames completos atualmente disponíveis no buffer.
    fn extract_frames(&mut self) -> Result<Vec<FramedPacket>, FramingError> {
        let mut frames = Vec::new();

        loop {
            // Precisamos de pelo menos 4 bytes para ler o tamanho
            if self.buffer.len() < FRAME_HEADER_SIZE {
                break;
            }

            // Lê o tamanho do payload (big-endian)
            let payload_size = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) as usize;

            // Valida o tamanho
            if payload_size == 0 {
                return Err(FramingError::ZeroPayload);
            }
            if payload_size > MAX_PAYLOAD_SIZE {
                return Err(FramingError::PayloadTooLarge {
                    size: payload_size,
                    max: MAX_PAYLOAD_SIZE,
                });
            }

            let total_frame_size = FRAME_HEADER_SIZE + payload_size;

            // Verifica se temos o frame completo no buffer
            if self.buffer.len() < total_frame_size {
                break; // Aguarda mais dados
            }

            // Extrai o payload
            let payload = self.buffer[FRAME_HEADER_SIZE..total_frame_size].to_vec();

            // Remove o frame processado do buffer
            self.buffer.drain(..total_frame_size);

            frames.push(FramedPacket::new(payload)?);
        }

        Ok(frames)
    }

    /// Retorna o número de bytes atualmente armazenados no buffer, aguardando
    /// mais dados para completar um frame.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Limpa o buffer interno. Útil em caso de erro de protocolo ou
    /// desconexão.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Verifica se o buffer contém dados incompletos de um frame
    /// (cabeçalho parcial ou payload incompleto).
    /// Retorna true se há bytes no buffer que não formam um frame completo.
    pub fn has_pending_data(&self) -> bool {
        if self.buffer.is_empty() {
            return false;
        }
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return true; // cabeçalho incompleto
        }
        // Lê o tamanho declarado
        let payload_size = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;
        // Se o tamanho é inválido (zero ou acima do limite), considera pendente
        if payload_size == 0 || payload_size > MAX_PAYLOAD_SIZE {
            return true;
        }
        // Se o payload não está completo, é pendente
        self.buffer.len() < (FRAME_HEADER_SIZE + payload_size)
    }

    /// Finaliza o parser ao receber EOF da conexão TCP.
    ///
    /// Retorna erro se houver dados incompletos no buffer.
    /// Retorna Ok(empty) se o buffer estiver vazio.
    pub fn finish(&mut self) -> Result<(), FramingError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return Err(FramingError::TruncatedHeader {
                needed: FRAME_HEADER_SIZE,
                available: self.buffer.len(),
            });
        }
        let payload_size = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;
        if payload_size == 0 || payload_size > MAX_PAYLOAD_SIZE {
            // Dados malformados - considera truncado
            return Err(FramingError::TruncatedPayload {
                needed: FRAME_HEADER_SIZE + payload_size,
                available: self.buffer.len(),
            });
        }
        Err(FramingError::TruncatedPayload {
            needed: FRAME_HEADER_SIZE + payload_size,
            available: self.buffer.len(),
        })
    }
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Frame real capturado: 00 00 00 20 + 32 bytes (keepalive/control)
    const FRAME_36: &[u8] = &[
        0x00, 0x00, 0x00, 0x20, // tamanho = 32
        0xd9, 0x39, 0x6b, 0x38, 0xe6, 0x5a, 0x30, 0xb6,
        0x65, 0xa8, 0xd9, 0x03, 0x43, 0xce, 0x5d, 0x02,
        0x42, 0x7b, 0x90, 0xf8, 0x0b, 0x21, 0xe2, 0x7b,
        0xff, 0x06, 0xe3, 0xe7, 0x83, 0xaf, 0xe6, 0x7f,
    ];

    #[test]
    fn serialize_and_parse_single_frame() {
        let payload = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03];
        let pkt = FramedPacket::new(payload.clone()).unwrap();
        let bytes = pkt.to_bytes();

        // Verifica o cabeçalho
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x08); // tamanho = 8

        // Verifica o payload
        assert_eq!(&bytes[4..12], &payload);

        // Faz o parse de volta
        let mut parser = FrameParser::new();
        let frames = parser.feed(&bytes).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, payload);
    }

    #[test]
    fn parse_real_captured_frame_36_bytes() {
        let mut parser = FrameParser::new();
        let frames = parser.feed(FRAME_36).unwrap();

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload.len(), 32);
        assert_eq!(frames[0].payload[0], 0xd9);
        assert_eq!(frames[0].payload[31], 0x7f);
        assert!(parser.buffered_len() == 0);
    }

    #[test]
    fn parse_multiple_frames_in_one_buffer() {
        let pkt1 = FramedPacket::new(vec![1, 2, 3]).unwrap();
        let pkt2 = FramedPacket::new(vec![4, 5]).unwrap();

        let mut buf = pkt1.to_bytes();
        buf.extend_from_slice(&pkt2.to_bytes());

        let mut parser = FrameParser::new();
        let frames = parser.feed(&buf).unwrap();

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload, vec![1, 2, 3]);
        assert_eq!(frames[1].payload, vec![4, 5]);
        assert!(parser.buffered_len() == 0);
    }

    #[test]
    fn parse_fragmented_frame_across_multiple_feeds() {
        let pkt = FramedPacket::new(vec![0xaa; 100]).unwrap();
        let bytes = pkt.to_bytes();

        // Envia apenas o cabeçalho + metade do payload
        let half = FRAME_HEADER_SIZE + 50;
        let mut parser = FrameParser::new();
        let frames = parser.feed(&bytes[..half]).unwrap();
        assert_eq!(frames.len(), 0);
        assert_eq!(parser.buffered_len(), half);

        // Envia o restante
        let frames = parser.feed(&bytes[half..]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload.len(), 100);
        assert!(parser.buffered_len() == 0);
    }

    #[test]
    fn reject_zero_payload() {
        let mut parser = FrameParser::new();
        let result = parser.feed(&[0x00, 0x00, 0x00, 0x00]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FramingError::ZeroPayload
        ));
    }

    #[test]
    fn reject_oversized_payload() {
        let mut parser = FrameParser::new();
        // Tamanho declarado = 70000, maior que MAX_PAYLOAD_SIZE
        let result = parser.feed(&[
            0x00, 0x01, 0x11, 0x70, // 70000 em big-endian
        ]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FramingError::PayloadTooLarge { .. }
        ));
    }

    #[test]
    fn to_bytes_round_trip() {
        let original = FramedPacket::new(vec![0x01, 0x02, 0x03, 0x04]).unwrap();
        let bytes = original.to_bytes();
        let reparsed = FramedPacket::new(bytes[FRAME_HEADER_SIZE..].to_vec()).unwrap();
        assert_eq!(original.payload, reparsed.payload);
    }

    #[test]
    fn eof_empty_buffer() {
        let mut parser = FrameParser::new();
        let result = parser.finish();
        assert!(result.is_ok());
        assert!(!parser.has_pending_data());
    }

    #[test]
    fn eof_incomplete_header() {
        let mut parser = FrameParser::new();
        // Alimenta apenas 2 bytes do cabeçalho
        parser.feed(&[0x00, 0x00]).unwrap();
        assert!(parser.has_pending_data());
        let result = parser.finish();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FramingError::TruncatedHeader { .. }
        ));
    }

    #[test]
    fn eof_incomplete_payload() {
        let mut parser = FrameParser::new();
        // Alimenta cabeçalho completo + parte do payload
        parser.feed(&[0x00, 0x00, 0x00, 0x10, 0xaa, 0xbb]).unwrap();
        assert!(parser.has_pending_data());
        let result = parser.finish();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FramingError::TruncatedPayload { .. }
        ));
    }

    #[test]
    fn eof_exact_frame_then_partial() {
        let mut parser = FrameParser::new();
        // Frame completo seguido de cabeçalho parcial
        let pkt = FramedPacket::new(vec![1, 2, 3]).unwrap();
        let mut data = pkt.to_bytes();
        data.extend_from_slice(&[0x00, 0x00]); // cabeçalho parcial
        let frames = parser.feed(&data).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, vec![1, 2, 3]);
        assert!(parser.has_pending_data());
        let result = parser.finish();
        assert!(result.is_err());
    }

    #[test]
    fn has_pending_data_empty() {
        let parser = FrameParser::new();
        assert!(!parser.has_pending_data());
    }

    #[test]
    fn has_pending_data_complete_frame() {
        let mut parser = FrameParser::new();
        let pkt = FramedPacket::new(vec![1, 2, 3]).unwrap();
        parser.feed(&pkt.to_bytes()).unwrap();
        assert!(!parser.has_pending_data());
    }
}
