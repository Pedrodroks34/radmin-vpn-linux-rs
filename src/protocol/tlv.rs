use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const TLV_HEADER_SIZE: usize = 8;
pub const MAX_TLV_VALUE_SIZE: usize = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TlvTag(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvType {
    U32,
    U64,
    Buffer,
    Unknown(u8),
}

impl TlvTag {
    pub const TAG_SESSION_TOKEN: TlvTag = TlvTag(0x010001df);
    pub const TAG_PEER_STATUS: TlvTag = TlvTag(0x0100032b);
    pub const TAG_RSA_PUBLIC_KEY: TlvTag = TlvTag(0x090001ca);
    pub const TAG_HANDSHAKE_ID: TlvTag = TlvTag(0x01000302);
    pub const TAG_HANDSHAKE_COOKIE: TlvTag = TlvTag(0x02000303);
    pub const TAG_HANDSHAKE_CRYPTO: TlvTag = TlvTag(0x09000304);
    pub const TAG_TIMESTAMP: TlvTag = TlvTag(0x020001e1);
    pub const TAG_CLIENT_VERSION: TlvTag = TlvTag(0x010001d8);
    pub const TAG_NETWORK_ID: TlvTag = TlvTag(0x020001d5);

    pub fn new(tlv_type: u8, field_id: u32) -> Self {
        Self(((tlv_type as u32) << 24) | (field_id & 0x00FFFFFF))
    }

    pub fn tlv_type(&self) -> TlvType {
        match (self.0 >> 24) as u8 {
            0x01 => TlvType::U32,
            0x02 => TlvType::U64,
            0x09 => TlvType::Buffer,
            other => TlvType::Unknown(other),
        }
    }

    pub fn field_id(&self) -> u32 {
        self.0 & 0x00FFFFFF
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlvValue {
    U32(u32),
    U64(u64),
    Buffer(Vec<u8>),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlvRecord {
    pub tag: TlvTag,
    pub value: TlvValue,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TlvError {
    #[error("buffer insuficiente para cabeçalho TLV: necessário 8 bytes, disponível {0}")]
    IncompleteHeader(usize),
    #[error(
        "buffer insuficiente para valor TLV: necessário {needed} bytes, disponível {available}"
    )]
    IncompleteValue { needed: usize, available: usize },
    #[error("tamanho inválido para tipo U32: esperado 4 bytes, encontrado {0}")]
    InvalidU32Length(usize),
    #[error("tamanho inválido para tipo U64: esperado 8 bytes, encontrado {0}")]
    InvalidU64Length(usize),
    #[error("tamanho TLV ({0} bytes) excede o limite máximo permitido")]
    ValueTooLarge(usize),
}

impl TlvRecord {
    pub fn new_u32(tag: TlvTag, val: u32) -> Self {
        Self {
            tag,
            value: TlvValue::U32(val),
        }
    }

    pub fn new_u64(tag: TlvTag, val: u64) -> Self {
        Self {
            tag,
            value: TlvValue::U64(val),
        }
    }

    pub fn new_buffer(tag: TlvTag, val: Vec<u8>) -> Self {
        Self {
            tag,
            value: TlvValue::Buffer(val),
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self.value {
            TlvValue::U32(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self.value {
            TlvValue::U64(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.value {
            TlvValue::Buffer(b) => b.as_slice(),
            TlvValue::Raw(b) => b.as_slice(),
            _ => &[],
        }
    }

    pub fn encoded_len(&self) -> usize {
        TLV_HEADER_SIZE
            + match &self.value {
                TlvValue::U32(_) => 4,
                TlvValue::U64(_) => 8,
                TlvValue::Buffer(b) => b.len(),
                TlvValue::Raw(b) => b.len(),
            }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(self.encoded_len());
        match &self.value {
            TlvValue::U32(v) => {
                buf.put_u32(4);
                buf.put_u32(self.tag.0);
                buf.put_u32(*v);
            }
            TlvValue::U64(v) => {
                buf.put_u32(8);
                buf.put_u32(self.tag.0);
                buf.put_u64(*v);
            }
            TlvValue::Buffer(b) => {
                buf.put_u32(b.len() as u32);
                buf.put_u32(self.tag.0);
                buf.extend_from_slice(b);
            }
            TlvValue::Raw(b) => {
                buf.put_u32(b.len() as u32);
                buf.put_u32(self.tag.0);
                buf.extend_from_slice(b);
            }
        }
        buf.to_vec()
    }

    pub fn parse(input: &[u8]) -> Result<(Self, usize), TlvError> {
        if input.len() < TLV_HEADER_SIZE {
            return Err(TlvError::IncompleteHeader(input.len()));
        }

        let length = u32::from_be_bytes(input[0..4].try_into().unwrap()) as usize;
        let tag = TlvTag(u32::from_be_bytes(input[4..8].try_into().unwrap()));

        if length > MAX_TLV_VALUE_SIZE {
            return Err(TlvError::ValueTooLarge(length));
        }

        let total_size = TLV_HEADER_SIZE + length;
        if input.len() < total_size {
            return Err(TlvError::IncompleteValue {
                needed: total_size,
                available: input.len(),
            });
        }

        let val_bytes = &input[TLV_HEADER_SIZE..total_size];

        let value = match tag.tlv_type() {
            TlvType::U32 => {
                if length != 4 {
                    return Err(TlvError::InvalidU32Length(length));
                }
                TlvValue::U32(u32::from_be_bytes(val_bytes.try_into().unwrap()))
            }
            TlvType::U64 => {
                if length != 8 {
                    return Err(TlvError::InvalidU64Length(length));
                }
                TlvValue::U64(u64::from_be_bytes(val_bytes.try_into().unwrap()))
            }
            TlvType::Buffer => TlvValue::Buffer(val_bytes.to_vec()),
            TlvType::Unknown(_) => TlvValue::Raw(val_bytes.to_vec()),
        };

        Ok((Self { tag, value }, total_size))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlvMessage {
    pub records: Vec<TlvRecord>,
}

impl TlvMessage {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn add(&mut self, record: TlvRecord) {
        self.records.push(record);
    }

    pub fn add_u32(&mut self, tag: TlvTag, val: u32) {
        self.records.push(TlvRecord::new_u32(tag, val));
    }

    pub fn add_u64(&mut self, tag: TlvTag, val: u64) {
        self.records.push(TlvRecord::new_u64(tag, val));
    }

    pub fn add_buffer(&mut self, tag: TlvTag, val: Vec<u8>) {
        self.records.push(TlvRecord::new_buffer(tag, val));
    }

    pub fn get(&self, tag: TlvTag) -> Option<&TlvRecord> {
        self.records.iter().find(|r| r.tag == tag)
    }

    pub fn get_u32(&self, tag: TlvTag) -> Option<u32> {
        self.get(tag).and_then(|r| r.as_u32())
    }

    pub fn get_u64(&self, tag: TlvTag) -> Option<u64> {
        self.get(tag).and_then(|r| r.as_u64())
    }

    pub fn get_buffer(&self, tag: TlvTag) -> Option<&[u8]> {
        self.get(tag).map(|r| r.as_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let total_size: usize = self.records.iter().map(|r| r.encoded_len()).sum();
        let mut buf = Vec::with_capacity(total_size);
        for r in &self.records {
            buf.extend_from_slice(&r.to_bytes());
        }
        buf
    }

    pub fn parse(mut input: &[u8]) -> Result<Self, TlvError> {
        let mut records = Vec::new();
        while !input.is_empty() {
            let (rec, consumed) = TlvRecord::parse(input)?;
            records.push(rec);
            input = &input[consumed..];
        }
        Ok(Self { records })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_type_extraction() {
        assert_eq!(TlvTag::TAG_SESSION_TOKEN.tlv_type(), TlvType::U32);
        assert_eq!(TlvTag::TAG_SESSION_TOKEN.field_id(), 479);

        assert_eq!(TlvTag::TAG_PEER_STATUS.tlv_type(), TlvType::U32);
        assert_eq!(TlvTag::TAG_PEER_STATUS.field_id(), 811);

        assert_eq!(TlvTag::TAG_RSA_PUBLIC_KEY.tlv_type(), TlvType::Buffer);
        assert_eq!(TlvTag::TAG_RSA_PUBLIC_KEY.field_id(), 458);

        assert_eq!(TlvTag::TAG_TIMESTAMP.tlv_type(), TlvType::U64);
        assert_eq!(TlvTag::TAG_TIMESTAMP.field_id(), 481);

        let custom = TlvTag::new(0x05, 123);
        assert_eq!(custom.tlv_type(), TlvType::Unknown(0x05));
        assert_eq!(custom.field_id(), 123);
    }

    #[test]
    fn test_tlv_roundtrip_u32() {
        let rec = TlvRecord::new_u32(TlvTag::TAG_SESSION_TOKEN, 12345);
        let bytes = rec.to_bytes();
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[0..4], &4u32.to_be_bytes());
        assert_eq!(&bytes[4..8], &TlvTag::TAG_SESSION_TOKEN.0.to_be_bytes());
        assert_eq!(&bytes[8..12], &12345u32.to_be_bytes());

        let (parsed, consumed) = TlvRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, 12);
        assert_eq!(parsed, rec);
    }

    #[test]
    fn test_tlv_roundtrip_u64() {
        let rec = TlvRecord::new_u64(TlvTag::TAG_TIMESTAMP, 0x123456789ABCDEF0);
        let bytes = rec.to_bytes();
        assert_eq!(bytes.len(), 16);
        let (parsed, consumed) = TlvRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, 16);
        assert_eq!(parsed, rec);
    }

    #[test]
    fn test_tlv_roundtrip_buffer() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let rec = TlvRecord::new_buffer(TlvTag::TAG_RSA_PUBLIC_KEY, data.clone());
        let bytes = rec.to_bytes();
        assert_eq!(bytes.len(), 8 + 10);
        let (parsed, consumed) = TlvRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, 18);
        assert_eq!(parsed, rec);
        assert_eq!(parsed.as_bytes(), data.as_slice());
    }

    #[test]
    fn test_tlv_unknown_tag_preservation() {
        let custom_tag = TlvTag::new(0x88, 999);
        let custom_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let rec = TlvRecord {
            tag: custom_tag,
            value: TlvValue::Raw(custom_data.clone()),
        };
        let bytes = rec.to_bytes();
        let (parsed, consumed) = TlvRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, 8 + 4);
        assert_eq!(parsed.tag, custom_tag);
        assert_eq!(parsed.as_bytes(), custom_data.as_slice());
    }

    #[test]
    fn test_tlv_message_multi_record() {
        let mut msg = TlvMessage::new();
        msg.add_u32(TlvTag::TAG_SESSION_TOKEN, 1);
        msg.add_u32(TlvTag::TAG_PEER_STATUS, 2);
        msg.add_buffer(TlvTag::TAG_RSA_PUBLIC_KEY, vec![0xAB; 256]);

        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), 12 + 12 + (8 + 256));

        let parsed = TlvMessage::parse(&bytes).unwrap();
        assert_eq!(parsed.records.len(), 3);
        assert_eq!(parsed.get_u32(TlvTag::TAG_SESSION_TOKEN), Some(1));
        assert_eq!(parsed.get_u32(TlvTag::TAG_PEER_STATUS), Some(2));
        assert_eq!(
            parsed.get_buffer(TlvTag::TAG_RSA_PUBLIC_KEY).unwrap().len(),
            256
        );
    }

    #[test]
    fn test_tlv_errors() {
        // Incomplete header (< 8 bytes)
        assert!(matches!(
            TlvRecord::parse(&[0, 0, 0, 4]),
            Err(TlvError::IncompleteHeader(4))
        ));

        // Incomplete value (header says len=4, but only 2 bytes follow)
        let mut truncated = vec![0, 0, 0, 4, 1, 0, 1, 0xdf];
        truncated.extend_from_slice(&[0, 1]);
        assert!(matches!(
            TlvRecord::parse(&truncated),
            Err(TlvError::IncompleteValue {
                needed: 12,
                available: 10
            })
        ));

        // Inconsistent U32 length (header says len=5 for U32 type)
        let invalid_u32 = vec![0, 0, 0, 5, 1, 0, 1, 0xdf, 1, 2, 3, 4, 5];
        assert!(matches!(
            TlvRecord::parse(&invalid_u32),
            Err(TlvError::InvalidU32Length(5))
        ));
    }

    #[test]
    fn test_parse_real_captured_packet_686() {
        // Hexadecimal completo extraído diretamente de radmin_vm2.pcap, Pacote #686
        let pcap_hex = "0000012000000004010001df00000001000000040100032b0000000200000100090001ca705f461c05ec79e7a71b736ceacefb245c31906b29a6d686397b5efc8eaba571884ad7615dbf80ccefd5bdc26a33c22c2f77930a555dec9fd8398550f258edbb876e3832bae01d6db3e88095a91662c95b9e0c282e603682471a46a0c68c37f9204364b580468995edaea45d77bc591f3fd288b74162fd5d282bcf87dafbce10865f8afa57ef60abfd407d2c300435fb576960afc30b86fb4688e20dbc9f4f8bd30b130f9957ddd52603bdda9983ec8867caee864b055649df6532b7400b76bbf8f93789bbb4c785d07768db835241d990b8b40c2ec91d369faa0997e768183d75252b7a35937b63842631e860dafbb19036d38b67d5da90df92283ecc7add65";
        let raw_bytes = hex_to_bytes(pcap_hex);

        // 1. Validar framing externo
        assert_eq!(raw_bytes.len(), 292);
        let frame_len = u32::from_be_bytes(raw_bytes[0..4].try_into().unwrap()) as usize;
        assert_eq!(frame_len, 288);

        // 2. Extrair e validar mensagens TLV internas
        let inner_payload = &raw_bytes[4..4 + frame_len];
        let tlv_msg =
            TlvMessage::parse(inner_payload).expect("TLV parse de pacote #686 deve ter sucesso");

        assert_eq!(tlv_msg.records.len(), 3);

        // Campo 1: 0x010001df (TAG_SESSION_TOKEN) == 1
        assert_eq!(tlv_msg.get_u32(TlvTag::TAG_SESSION_TOKEN), Some(1));

        // Campo 2: 0x0100032b (TAG_PEER_STATUS) == 2
        assert_eq!(tlv_msg.get_u32(TlvTag::TAG_PEER_STATUS), Some(2));

        // Campo 3: 0x090001ca (TAG_RSA_PUBLIC_KEY), 256 bytes (RSA-2048)
        let rsa_pub = tlv_msg
            .get_buffer(TlvTag::TAG_RSA_PUBLIC_KEY)
            .expect("campo RSA deve existir");
        assert_eq!(rsa_pub.len(), 256);
        assert_eq!(&rsa_pub[0..4], &[0x70, 0x5f, 0x46, 0x1c]);
        assert_eq!(&rsa_pub[252..256], &[0xcc, 0x7a, 0xdd, 0x65]);

        // 3. Validar round-trip idêntico bit a bit
        let reserialized = tlv_msg.to_bytes();
        assert_eq!(reserialized.as_slice(), inner_payload);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
