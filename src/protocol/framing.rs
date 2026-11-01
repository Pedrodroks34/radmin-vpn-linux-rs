use bytes::BufMut;

pub const FRAME_HEADER_SIZE: usize = 4;

pub const MAX_PAYLOAD_SIZE: usize = 65535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedPacket {
    pub payload: Vec<u8>,
}

impl FramedPacket {

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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());
        buf.put_u32(self.payload.len() as u32);
        buf.extend_from_slice(&self.payload);
        buf
    }
}

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

pub struct FrameParser {
    buffer: Vec<u8>,
}

impl FrameParser {

    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<FramedPacket>, FramingError> {
        self.buffer.extend_from_slice(data);
        self.extract_frames()
    }

    fn extract_frames(&mut self) -> Result<Vec<FramedPacket>, FramingError> {
        let mut frames = Vec::new();

        loop {

            if self.buffer.len() < FRAME_HEADER_SIZE {
                break;
            }

            let payload_size = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) as usize;

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

            if self.buffer.len() < total_frame_size {
                break;
            }

            let payload = self.buffer[FRAME_HEADER_SIZE..total_frame_size].to_vec();

            self.buffer.drain(..total_frame_size);

            frames.push(FramedPacket::new(payload)?);
        }

        Ok(frames)
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn has_pending_data(&self) -> bool {
        if self.buffer.is_empty() {
            return false;
        }
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return true;
        }

        let payload_size = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;

        if payload_size == 0 || payload_size > MAX_PAYLOAD_SIZE {
            return true;
        }

        self.buffer.len() < (FRAME_HEADER_SIZE + payload_size)
    }

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

    const FRAME_36: &[u8] = &[
        0x00, 0x00, 0x00, 0x20,
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

        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x08);

        assert_eq!(&bytes[4..12], &payload);

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

        let half = FRAME_HEADER_SIZE + 50;
        let mut parser = FrameParser::new();
        let frames = parser.feed(&bytes[..half]).unwrap();
        assert_eq!(frames.len(), 0);
        assert_eq!(parser.buffered_len(), half);

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

        let result = parser.feed(&[
            0x00, 0x01, 0x11, 0x70,
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

        let pkt = FramedPacket::new(vec![1, 2, 3]).unwrap();
        let mut data = pkt.to_bytes();
        data.extend_from_slice(&[0x00, 0x00]);
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
