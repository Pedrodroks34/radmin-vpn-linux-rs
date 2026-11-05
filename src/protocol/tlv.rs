use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const TLV_HEADER_SIZE: usize = 8;
pub const MAX_TLV_VALUE_SIZE: usize = 65527; // 65535 - TLV_HEADER_SIZE
pub const MAX_TLV_MESSAGE_SIZE: usize = 65535; // Alinhado com MAX_PAYLOAD_SIZE do FrameParser
pub const MAX_TLV_RECORDS_PER_MESSAGE: usize = 1024; // Prevenção de micro-record allocation bomb
pub const MAX_STRING_LEN: usize = 4096; // Teto defensivo para strings UTF-8

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TlvTag(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlvType {
    U32,        // 0x01 - UINT32 (4 bytes BE)
    U64,        // 0x02 - UINT64 (8 bytes BE)
    I32,        // 0x03 - INT32 (4 bytes BE, escalar primitivo com sinal)
    Bool,       // 0x04 - BOOL (1 ou 4 bytes no wire)
    Float,      // 0x05 - FLOAT (4 bytes IEEE 754, opaco)
    Double,     // 0x06 - DOUBLE (8 bytes IEEE 754, opaco)
    Compound,   // 0x08 - COMPOUND
    Buffer,     // 0x09 - BINARY / BLOB (preserva nome existente)
    DateTime,   // 0x0A - DATETIME
    StringUtf8, // 0x0B - STRING_UTF8 (sem terminação nula no wire)
    Object,     // 0x0C - OBJECT
    List,       // 0x0D - LIST / ARRAY
    Map,        // 0x0E - MAP / CONTAINER
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
            0x03 => TlvType::I32,
            0x04 => TlvType::Bool,
            0x05 => TlvType::Float,
            0x06 => TlvType::Double,
            0x08 => TlvType::Compound,
            0x09 => TlvType::Buffer,
            0x0A => TlvType::DateTime,
            0x0B => TlvType::StringUtf8,
            0x0C => TlvType::Object,
            0x0D => TlvType::List,
            0x0E => TlvType::Map,
            other => TlvType::Unknown(other),
        }
    }

    pub fn field_id(&self) -> u32 {
        self.0 & 0x00FFFFFF
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlvValue {
    U32(u32),
    U64(u64),
    I32(i32),
    Bool { value: bool, raw: Vec<u8> },
    Float([u8; 4]),
    Double([u8; 8]),
    Buffer(Vec<u8>),
    StringUtf8(String),
    Raw(Vec<u8>),
}

impl TlvValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            TlvValue::U32(_) => "U32",
            TlvValue::U64(_) => "U64",
            TlvValue::I32(_) => "I32",
            TlvValue::Bool { .. } => "Bool",
            TlvValue::Float(_) => "Float",
            TlvValue::Double(_) => "Double",
            TlvValue::Buffer(_) => "Buffer",
            TlvValue::StringUtf8(_) => "StringUtf8",
            TlvValue::Raw(_) => "Raw",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlvRecord {
    pub tag: TlvTag,
    pub value: TlvValue,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
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

    #[error("tamanho inválido para tipo I32: esperado 4 bytes, encontrado {0}")]
    InvalidI32Length(usize),

    #[error("tamanho inválido para tipo BOOL: esperado 1 ou 4 bytes, encontrado {0}")]
    InvalidBoolLength(usize),

    #[error("divergência entre valor lógico e representação binária do tipo BOOL")]
    BoolValueMismatch,

    #[error("tamanho inválido para tipo FLOAT: esperado 4 bytes, encontrado {0}")]
    InvalidFloatLength(usize),

    #[error("tamanho inválido para tipo DOUBLE: esperado 8 bytes, encontrado {0}")]
    InvalidDoubleLength(usize),

    #[error("string UTF-8 excede o limite máximo permitido ({max} bytes, encontrado {size})")]
    StringTooLarge { size: usize, max: usize },

    #[error("conteúdo de string inválido para UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    #[error("tamanho TLV ({0} bytes) excede o limite máximo permitido")]
    ValueTooLarge(usize),

    #[error("mensagem TLV excede o tamanho máximo permitido ({max} bytes, encontrado {size})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("quantidade de registros TLV excede o limite permitido ({0})")]
    TooManyRecords(usize),

    #[error("estouro aritmético no cálculo de tamanho da mensagem TLV")]
    SizeOverflow,

    #[error("tipo incompatível para tag TLV: esperado {expected:?}, encontrado {actual}")]
    TypeMismatch {
        expected: TlvType,
        actual: &'static str,
    },
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

    pub fn new_i32(tag: TlvTag, val: i32) -> Self {
        Self {
            tag,
            value: TlvValue::I32(val),
        }
    }

    pub fn new_bool_1(tag: TlvTag, val: bool) -> Self {
        Self {
            tag,
            value: TlvValue::Bool {
                value: val,
                raw: vec![if val { 1 } else { 0 }],
            },
        }
    }

    pub fn new_bool_4(tag: TlvTag, val: bool) -> Self {
        Self {
            tag,
            value: TlvValue::Bool {
                value: val,
                raw: if val {
                    vec![0, 0, 0, 1]
                } else {
                    vec![0, 0, 0, 0]
                },
            },
        }
    }

    pub fn new_bool_raw(tag: TlvTag, raw: Vec<u8>) -> Self {
        let value = match raw.len() {
            1 => raw[0] != 0,
            4 => u32::from_be_bytes(raw.as_slice().try_into().unwrap()) != 0,
            _ => false,
        };
        Self {
            tag,
            value: TlvValue::Bool { value, raw },
        }
    }

    pub fn new_buffer(tag: TlvTag, val: Vec<u8>) -> Self {
        Self {
            tag,
            value: TlvValue::Buffer(val),
        }
    }

    pub fn new_string(tag: TlvTag, val: String) -> Self {
        Self {
            tag,
            value: TlvValue::StringUtf8(val),
        }
    }

    pub fn new_float_opaque(tag: TlvTag, val: [u8; 4]) -> Self {
        Self {
            tag,
            value: TlvValue::Float(val),
        }
    }

    pub fn new_double_opaque(tag: TlvTag, val: [u8; 8]) -> Self {
        Self {
            tag,
            value: TlvValue::Double(val),
        }
    }

    pub fn new_raw(tag: TlvTag, val: Vec<u8>) -> Self {
        Self {
            tag,
            value: TlvValue::Raw(val),
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

    pub fn as_i32(&self) -> Option<i32> {
        match self.value {
            TlvValue::I32(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match &self.value {
            TlvValue::Bool { value, .. } => Some(*value),
            _ => None,
        }
    }

    pub fn bool_raw(&self) -> Option<&[u8]> {
        match &self.value {
            TlvValue::Bool { raw, .. } => Some(raw.as_slice()),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match &self.value {
            TlvValue::StringUtf8(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.value {
            TlvValue::Buffer(b) | TlvValue::Raw(b) => b.as_slice(),
            TlvValue::StringUtf8(s) => s.as_bytes(),
            TlvValue::Float(f) => f.as_slice(),
            TlvValue::Double(d) => d.as_slice(),
            TlvValue::Bool { raw, .. } => raw.as_slice(),
            _ => &[],
        }
    }

    pub fn encoded_len(&self) -> usize {
        TLV_HEADER_SIZE
            + match &self.value {
                TlvValue::U32(_) | TlvValue::I32(_) | TlvValue::Float(_) => 4,
                TlvValue::U64(_) | TlvValue::Double(_) => 8,
                TlvValue::Bool { raw, .. } => raw.len(),
                TlvValue::Buffer(b) | TlvValue::Raw(b) => b.len(),
                TlvValue::StringUtf8(s) => s.len(),
            }
    }

    pub fn validate(&self) -> Result<(), TlvError> {
        let expected_type = self.tag.tlv_type();
        let compatible = matches!(
            (&self.value, expected_type),
            (TlvValue::U32(_), TlvType::U32)
                | (TlvValue::U64(_), TlvType::U64)
                | (TlvValue::I32(_), TlvType::I32)
                | (TlvValue::Bool { .. }, TlvType::Bool)
                | (TlvValue::Float(_), TlvType::Float)
                | (TlvValue::Double(_), TlvType::Double)
                | (TlvValue::Buffer(_), TlvType::Buffer)
                | (TlvValue::StringUtf8(_), TlvType::StringUtf8)
                | (
                    TlvValue::Raw(_),
                    TlvType::Compound
                        | TlvType::DateTime
                        | TlvType::Object
                        | TlvType::List
                        | TlvType::Map
                        | TlvType::Unknown(_)
                )
        );

        if !compatible {
            return Err(TlvError::TypeMismatch {
                expected: expected_type,
                actual: self.value.type_name(),
            });
        }

        match &self.value {
            TlvValue::U32(_) | TlvValue::I32(_) | TlvValue::Float(_) => Ok(()),
            TlvValue::U64(_) | TlvValue::Double(_) => Ok(()),
            TlvValue::Bool { value, raw } => {
                if raw.len() != 1 && raw.len() != 4 {
                    return Err(TlvError::InvalidBoolLength(raw.len()));
                }
                let decoded = match raw.len() {
                    1 => raw[0] != 0,
                    4 => u32::from_be_bytes(raw.as_slice().try_into().unwrap()) != 0,
                    _ => unreachable!(),
                };
                if decoded != *value {
                    return Err(TlvError::BoolValueMismatch);
                }
                Ok(())
            }
            TlvValue::Buffer(b) | TlvValue::Raw(b) => {
                if b.len() > MAX_TLV_VALUE_SIZE {
                    return Err(TlvError::ValueTooLarge(b.len()));
                }
                Ok(())
            }
            TlvValue::StringUtf8(s) => {
                if s.len() > MAX_STRING_LEN {
                    return Err(TlvError::StringTooLarge {
                        size: s.len(),
                        max: MAX_STRING_LEN,
                    });
                }
                Ok(())
            }
        }
    }

    pub fn try_to_bytes(&self) -> Result<Vec<u8>, TlvError> {
        self.validate()?;
        let encoded_len = self.encoded_len();
        let mut buf = BytesMut::with_capacity(encoded_len);
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
            TlvValue::I32(v) => {
                buf.put_u32(4);
                buf.put_u32(self.tag.0);
                buf.put_i32(*v);
            }
            TlvValue::Bool { raw, .. } => {
                if raw.len() != 1 && raw.len() != 4 {
                    return Err(TlvError::InvalidBoolLength(raw.len()));
                }
                buf.put_u32(raw.len() as u32);
                buf.put_u32(self.tag.0);
                buf.extend_from_slice(raw);
            }
            TlvValue::Float(f) => {
                buf.put_u32(4);
                buf.put_u32(self.tag.0);
                buf.extend_from_slice(f);
            }
            TlvValue::Double(d) => {
                buf.put_u32(8);
                buf.put_u32(self.tag.0);
                buf.extend_from_slice(d);
            }
            TlvValue::Buffer(b) | TlvValue::Raw(b) => {
                buf.put_u32(b.len() as u32);
                buf.put_u32(self.tag.0);
                buf.extend_from_slice(b);
            }
            TlvValue::StringUtf8(s) => {
                buf.put_u32(s.len() as u32);
                buf.put_u32(self.tag.0);
                buf.extend_from_slice(s.as_bytes());
            }
        }
        Ok(buf.to_vec())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("falha ao serializar TlvRecord: restrições de formato ou tamanho violadas")
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

        let total_size = TLV_HEADER_SIZE
            .checked_add(length)
            .ok_or(TlvError::ValueTooLarge(length))?;

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
            TlvType::I32 => {
                if length != 4 {
                    return Err(TlvError::InvalidI32Length(length));
                }
                TlvValue::I32(i32::from_be_bytes(val_bytes.try_into().unwrap()))
            }
            TlvType::Bool => {
                let (b_val, raw_bytes) = match length {
                    1 => (val_bytes[0] != 0, val_bytes.to_vec()),
                    4 => (
                        u32::from_be_bytes(val_bytes.try_into().unwrap()) != 0,
                        val_bytes.to_vec(),
                    ),
                    other => return Err(TlvError::InvalidBoolLength(other)),
                };
                TlvValue::Bool {
                    value: b_val,
                    raw: raw_bytes,
                }
            }
            TlvType::Float => {
                if length != 4 {
                    return Err(TlvError::InvalidFloatLength(length));
                }
                TlvValue::Float(val_bytes.try_into().unwrap())
            }
            TlvType::Double => {
                if length != 8 {
                    return Err(TlvError::InvalidDoubleLength(length));
                }
                TlvValue::Double(val_bytes.try_into().unwrap())
            }
            TlvType::StringUtf8 => {
                if length > MAX_STRING_LEN {
                    return Err(TlvError::StringTooLarge {
                        size: length,
                        max: MAX_STRING_LEN,
                    });
                }
                let s = std::str::from_utf8(val_bytes)?;
                TlvValue::StringUtf8(s.to_string())
            }
            TlvType::Buffer => TlvValue::Buffer(val_bytes.to_vec()),
            _ => TlvValue::Raw(val_bytes.to_vec()),
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

    pub fn encoded_len(&self) -> usize {
        self.records
            .iter()
            .fold(0usize, |acc, r| acc.saturating_add(r.encoded_len()))
    }

    pub fn try_add(&mut self, record: TlvRecord) -> Result<(), TlvError> {
        if self.records.len() >= MAX_TLV_RECORDS_PER_MESSAGE {
            return Err(TlvError::TooManyRecords(self.records.len()));
        }
        record.validate()?;

        let mut current_size: usize = 0;
        for r in &self.records {
            current_size = current_size
                .checked_add(r.encoded_len())
                .ok_or(TlvError::SizeOverflow)?;
        }

        let record_len = record.encoded_len();
        let new_total = current_size
            .checked_add(record_len)
            .ok_or(TlvError::SizeOverflow)?;

        if new_total > MAX_TLV_MESSAGE_SIZE {
            return Err(TlvError::MessageTooLarge {
                size: new_total,
                max: MAX_TLV_MESSAGE_SIZE,
            });
        }

        self.records.push(record);
        Ok(())
    }

    pub fn add(&mut self, record: TlvRecord) {
        self.try_add(record)
            .expect("falha ao adicionar registro na mensagem TLV: limites de tamanho ou quantidade excedidos");
    }

    pub fn try_add_u32(&mut self, tag: TlvTag, val: u32) -> Result<(), TlvError> {
        self.try_add(TlvRecord::new_u32(tag, val))
    }

    pub fn try_add_u64(&mut self, tag: TlvTag, val: u64) -> Result<(), TlvError> {
        self.try_add(TlvRecord::new_u64(tag, val))
    }

    pub fn try_add_i32(&mut self, tag: TlvTag, val: i32) -> Result<(), TlvError> {
        self.try_add(TlvRecord::new_i32(tag, val))
    }

    pub fn try_add_bool_1(&mut self, tag: TlvTag, val: bool) -> Result<(), TlvError> {
        self.try_add(TlvRecord::new_bool_1(tag, val))
    }

    pub fn try_add_bool_4(&mut self, tag: TlvTag, val: bool) -> Result<(), TlvError> {
        self.try_add(TlvRecord::new_bool_4(tag, val))
    }

    pub fn try_add_bool_raw(&mut self, tag: TlvTag, raw: Vec<u8>) -> Result<(), TlvError> {
        self.try_add(TlvRecord::new_bool_raw(tag, raw))
    }

    pub fn try_add_buffer(&mut self, tag: TlvTag, val: Vec<u8>) -> Result<(), TlvError> {
        self.try_add(TlvRecord::new_buffer(tag, val))
    }

    pub fn try_add_string(&mut self, tag: TlvTag, val: String) -> Result<(), TlvError> {
        self.try_add(TlvRecord::new_string(tag, val))
    }

    pub fn add_u32(&mut self, tag: TlvTag, val: u32) {
        self.add(TlvRecord::new_u32(tag, val));
    }

    pub fn add_u64(&mut self, tag: TlvTag, val: u64) {
        self.add(TlvRecord::new_u64(tag, val));
    }

    pub fn add_i32(&mut self, tag: TlvTag, val: i32) {
        self.add(TlvRecord::new_i32(tag, val));
    }

    pub fn add_bool_1(&mut self, tag: TlvTag, val: bool) {
        self.add(TlvRecord::new_bool_1(tag, val));
    }

    pub fn add_bool_4(&mut self, tag: TlvTag, val: bool) {
        self.add(TlvRecord::new_bool_4(tag, val));
    }

    pub fn add_bool_raw(&mut self, tag: TlvTag, raw: Vec<u8>) {
        self.add(TlvRecord::new_bool_raw(tag, raw));
    }

    pub fn add_buffer(&mut self, tag: TlvTag, val: Vec<u8>) {
        self.add(TlvRecord::new_buffer(tag, val));
    }

    pub fn add_string(&mut self, tag: TlvTag, val: String) {
        self.add(TlvRecord::new_string(tag, val));
    }

    pub fn get(&self, tag: TlvTag) -> Option<&TlvRecord> {
        self.records.iter().find(|r| r.tag == tag)
    }

    pub fn get_all(&self, tag: TlvTag) -> Vec<&TlvRecord> {
        self.records.iter().filter(|r| r.tag == tag).collect()
    }

    pub fn get_u32(&self, tag: TlvTag) -> Option<u32> {
        self.get(tag).and_then(|r| r.as_u32())
    }

    pub fn get_u64(&self, tag: TlvTag) -> Option<u64> {
        self.get(tag).and_then(|r| r.as_u64())
    }

    pub fn get_i32(&self, tag: TlvTag) -> Option<i32> {
        self.get(tag).and_then(|r| r.as_i32())
    }

    pub fn get_bool(&self, tag: TlvTag) -> Option<bool> {
        self.get(tag).and_then(|r| r.as_bool())
    }

    pub fn get_bool_raw(&self, tag: TlvTag) -> Option<&[u8]> {
        self.get(tag).and_then(|r| r.bool_raw())
    }

    pub fn get_string(&self, tag: TlvTag) -> Option<&str> {
        self.get(tag).and_then(|r| r.as_string())
    }

    pub fn get_buffer(&self, tag: TlvTag) -> Option<&[u8]> {
        self.get(tag).map(|r| r.as_bytes())
    }

    pub fn try_to_bytes(&self) -> Result<Vec<u8>, TlvError> {
        if self.records.len() > MAX_TLV_RECORDS_PER_MESSAGE {
            return Err(TlvError::TooManyRecords(self.records.len()));
        }

        let mut total_size: usize = 0;
        for r in &self.records {
            r.validate()?;
            total_size = total_size
                .checked_add(r.encoded_len())
                .ok_or(TlvError::SizeOverflow)?;
        }

        if total_size > MAX_TLV_MESSAGE_SIZE {
            return Err(TlvError::MessageTooLarge {
                size: total_size,
                max: MAX_TLV_MESSAGE_SIZE,
            });
        }

        let mut buf = Vec::with_capacity(total_size);
        for r in &self.records {
            buf.extend_from_slice(&r.try_to_bytes()?);
        }
        Ok(buf)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("falha ao serializar TlvMessage: mensagem excede limites permitidos")
    }

    pub fn parse(mut input: &[u8]) -> Result<Self, TlvError> {
        if input.len() > MAX_TLV_MESSAGE_SIZE {
            return Err(TlvError::MessageTooLarge {
                size: input.len(),
                max: MAX_TLV_MESSAGE_SIZE,
            });
        }

        let mut records = Vec::new();
        while !input.is_empty() {
            if records.len() >= MAX_TLV_RECORDS_PER_MESSAGE {
                return Err(TlvError::TooManyRecords(records.len()));
            }
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

        assert_eq!(TlvTag::new(0x03, 100).tlv_type(), TlvType::I32);
        assert_eq!(TlvTag::new(0x04, 200).tlv_type(), TlvType::Bool);
        assert_eq!(TlvTag::new(0x05, 300).tlv_type(), TlvType::Float);
        assert_eq!(TlvTag::new(0x06, 400).tlv_type(), TlvType::Double);
        assert_eq!(TlvTag::new(0x08, 500).tlv_type(), TlvType::Compound);
        assert_eq!(TlvTag::new(0x0A, 600).tlv_type(), TlvType::DateTime);
        assert_eq!(TlvTag::new(0x0B, 700).tlv_type(), TlvType::StringUtf8);
        assert_eq!(TlvTag::new(0x0C, 800).tlv_type(), TlvType::Object);
        assert_eq!(TlvTag::new(0x0D, 900).tlv_type(), TlvType::List);
        assert_eq!(TlvTag::new(0x0E, 950).tlv_type(), TlvType::Map);

        let custom = TlvTag::new(0x77, 123);
        assert_eq!(custom.tlv_type(), TlvType::Unknown(0x77));
        assert_eq!(custom.field_id(), 123);
    }


    #[test]
    fn test_synthetic_parse_i32_endianness_and_signs() {
        let pos_bytes = [
            0x00, 0x00, 0x00, 0x04, // Length = 4
            0x03, 0x00, 0x00, 0x01, // Tag
            0x00, 0x00, 0x27, 0x10, // Value = 10000
        ];
        let (rec_pos, consumed) = TlvRecord::parse(&pos_bytes).unwrap();
        assert_eq!(consumed, 12);
        assert_eq!(rec_pos.as_i32(), Some(10000));

        let neg_bytes = [
            0x00, 0x00, 0x00, 0x04, // Length = 4
            0x03, 0x00, 0x00, 0x02, // Tag
            0xFF, 0xFF, 0xFE, 0x00, // Value = -512
        ];
        let (rec_neg, consumed_neg) = TlvRecord::parse(&neg_bytes).unwrap();
        assert_eq!(consumed_neg, 12);
        assert_eq!(rec_neg.as_i32(), Some(-512));
    }

    #[test]
    fn test_synthetic_parse_bool_1_and_4_bytes() {
        let bool1_true = [
            0x00, 0x00, 0x00, 0x01, // Length = 1
            0x04, 0x00, 0x01, 0xe7, // Tag (PROP_IS_ONLINE)
            0x01, // Value = true
        ];
        let (rec1, c1) = TlvRecord::parse(&bool1_true).unwrap();
        assert_eq!(c1, 9);
        assert_eq!(rec1.as_bool(), Some(true));
        assert_eq!(
            rec1.value,
            TlvValue::Bool {
                value: true,
                raw: vec![0x01],
            }
        );

        let bool1_false = [
            0x00, 0x00, 0x00, 0x01, // Length = 1
            0x04, 0x00, 0x01, 0xe7, // Tag
            0x00, // Value = false
        ];
        let (rec1_f, _) = TlvRecord::parse(&bool1_false).unwrap();
        assert_eq!(rec1_f.as_bool(), Some(false));
        assert_eq!(
            rec1_f.value,
            TlvValue::Bool {
                value: false,
                raw: vec![0x00],
            }
        );

        let bool4_true = [
            0x00, 0x00, 0x00, 0x04, // Length = 4
            0x04, 0x00, 0x01, 0xe7, // Tag
            0x00, 0x00, 0x00, 0x01, // Value = 1
        ];
        let (rec4, c4) = TlvRecord::parse(&bool4_true).unwrap();
        assert_eq!(c4, 12);
        assert_eq!(rec4.as_bool(), Some(true));
        assert_eq!(
            rec4.value,
            TlvValue::Bool {
                value: true,
                raw: vec![0, 0, 0, 1],
            }
        );

        let bool4_false = [
            0x00, 0x00, 0x00, 0x04, // Length = 4
            0x04, 0x00, 0x01, 0xe7, // Tag
            0x00, 0x00, 0x00, 0x00, // Value = 0
        ];
        let (rec4_f, _) = TlvRecord::parse(&bool4_false).unwrap();
        assert_eq!(rec4_f.as_bool(), Some(false));
        assert_eq!(
            rec4_f.value,
            TlvValue::Bool {
                value: false,
                raw: vec![0, 0, 0, 0],
            }
        );
    }

    #[test]
    fn test_bool_non_canonical_1_byte_roundtrip() {
        let tag = TlvTag::new(0x04, 20);

        let rec_can_t = TlvRecord::new_bool_1(tag, true);
        let bytes_can_t = rec_can_t.to_bytes();
        assert_eq!(bytes_can_t.len(), 9);
        assert_eq!(bytes_can_t[8], 0x01);
        let (parsed_can_t, c) = TlvRecord::parse(&bytes_can_t).unwrap();
        assert_eq!(c, 9);
        assert_eq!(parsed_can_t.as_bool(), Some(true));
        assert_eq!(
            parsed_can_t.value,
            TlvValue::Bool {
                value: true,
                raw: vec![0x01],
            }
        );
        assert_eq!(parsed_can_t.to_bytes(), bytes_can_t);

        let rec_can_f = TlvRecord::new_bool_1(tag, false);
        let bytes_can_f = rec_can_f.to_bytes();
        assert_eq!(bytes_can_f[8], 0x00);
        let (parsed_can_f, _) = TlvRecord::parse(&bytes_can_f).unwrap();
        assert_eq!(parsed_can_f.as_bool(), Some(false));
        assert_eq!(
            parsed_can_f.value,
            TlvValue::Bool {
                value: false,
                raw: vec![0x00],
            }
        );
        assert_eq!(parsed_can_f.to_bytes(), bytes_can_f);

        for non_canonical_byte in [0x02u8, 0x42, 0x7F, 0xFF] {
            let raw_wire = [
                0x00,
                0x00,
                0x00,
                0x01,
                0x04,
                0x00,
                0x00,
                0x14,
                non_canonical_byte,
            ];
            let (parsed, consumed) =
                TlvRecord::parse(&raw_wire).expect("parse non-canonical 1-byte bool");
            assert_eq!(consumed, 9);
            assert_eq!(parsed.as_bool(), Some(true));
            assert_eq!(
                parsed.value,
                TlvValue::Bool {
                    value: true,
                    raw: vec![non_canonical_byte],
                }
            );
            let re_serialized = parsed.to_bytes();
            assert_eq!(re_serialized, raw_wire);
            assert_eq!(re_serialized[8], non_canonical_byte);
        }
    }

    #[test]
    fn test_bool_non_canonical_4_bytes_roundtrip() {
        let tag = TlvTag::new(0x04, 21);

        let rec_can_t = TlvRecord::new_bool_4(tag, true);
        let bytes_can_t = rec_can_t.to_bytes();
        assert_eq!(bytes_can_t.len(), 12);
        assert_eq!(&bytes_can_t[8..12], &[0x00, 0x00, 0x00, 0x01]);
        let (parsed_can_t, c) = TlvRecord::parse(&bytes_can_t).unwrap();
        assert_eq!(c, 12);
        assert_eq!(parsed_can_t.as_bool(), Some(true));
        assert_eq!(
            parsed_can_t.value,
            TlvValue::Bool {
                value: true,
                raw: vec![0, 0, 0, 1],
            }
        );
        assert_eq!(parsed_can_t.to_bytes(), bytes_can_t);

        let rec_can_f = TlvRecord::new_bool_4(tag, false);
        let bytes_can_f = rec_can_f.to_bytes();
        assert_eq!(&bytes_can_f[8..12], &[0x00, 0x00, 0x00, 0x00]);
        let (parsed_can_f, _) = TlvRecord::parse(&bytes_can_f).unwrap();
        assert_eq!(parsed_can_f.as_bool(), Some(false));
        assert_eq!(
            parsed_can_f.value,
            TlvValue::Bool {
                value: false,
                raw: vec![0, 0, 0, 0],
            }
        );
        assert_eq!(parsed_can_f.to_bytes(), bytes_can_f);

        let non_canonical_samples = [
            [0x00u8, 0x00, 0x00, 0xFF],
            [0x00, 0x01, 0x00, 0x00],
            [0x12, 0x34, 0x56, 0x78],
            [0xFF, 0xFF, 0xFF, 0xFF],
        ];

        for sample in non_canonical_samples {
            let mut raw_wire = vec![0x00, 0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x15];
            raw_wire.extend_from_slice(&sample);

            let (parsed, consumed) =
                TlvRecord::parse(&raw_wire).expect("parse non-canonical 4-byte bool");
            assert_eq!(consumed, 12);
            assert_eq!(parsed.as_bool(), Some(true));
            assert_eq!(
                parsed.value,
                TlvValue::Bool {
                    value: true,
                    raw: sample.to_vec(),
                }
            );
            let re_serialized = parsed.to_bytes();
            assert_eq!(re_serialized, raw_wire);
            assert_eq!(&re_serialized[8..12], &sample);
        }
    }

    #[test]
    fn test_synthetic_parse_string_utf8() {
        let str_bytes = [
            0x00, 0x00, 0x00, 0x09, // Length = 9
            0x0B, 0x00, 0x01, 0xDC, // Tag
            b'R', b'a', b'd', b'm', b'i', b'n', b'N', b'e',
            b't', // Value UTF-8 sem terminador nulo
        ];
        let (rec, consumed) = TlvRecord::parse(&str_bytes).unwrap();
        assert_eq!(consumed, 17);
        assert_eq!(rec.as_string(), Some("RadminNet"));
        assert_eq!(rec.value, TlvValue::StringUtf8("RadminNet".to_string()));
    }

    #[test]
    fn test_synthetic_parse_float_and_double_opaque() {
        let float_bytes = [
            0x00, 0x00, 0x00, 0x04, 0x05, 0x00, 0x00, 0x10, 0x3F, 0x80, 0x00,
            0x00, // 1.0f em IEEE 754
        ];
        let (rec_f, c_f) = TlvRecord::parse(&float_bytes).unwrap();
        assert_eq!(c_f, 12);
        assert_eq!(rec_f.value, TlvValue::Float([0x3F, 0x80, 0x00, 0x00]));
        assert_eq!(rec_f.as_bytes(), &[0x3F, 0x80, 0x00, 0x00]);

        let double_bytes = [
            0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x20, 0x40, 0x09, 0x21, 0xFB, 0x54, 0x44,
            0x2D, 0x18, // ~pi em IEEE 754 double
        ];
        let (rec_d, c_d) = TlvRecord::parse(&double_bytes).unwrap();
        assert_eq!(c_d, 16);
        assert_eq!(
            rec_d.value,
            TlvValue::Double([0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18])
        );
        assert_eq!(
            rec_d.as_bytes(),
            &[0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18]
        );
    }

    #[test]
    fn test_synthetic_unknown_tag_preservation_raw() {
        let custom_bytes = [
            0x00, 0x00, 0x00, 0x03, 0x7F, 0x00, 0x01, 0x23, 0xAA, 0xBB, 0xCC,
        ];
        let (rec, consumed) = TlvRecord::parse(&custom_bytes).unwrap();
        assert_eq!(consumed, 11);
        assert_eq!(rec.tag, TlvTag(0x7F000123));
        assert_eq!(rec.tag.tlv_type(), TlvType::Unknown(0x7F));
        assert_eq!(rec.value, TlvValue::Raw(vec![0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn test_unknown_tag_type_preserves_raw_bytes() {
        let unknown_tag = TlvTag::new(0x7F, 99); // 0x7F não mapeado na taxonomia Famatech
        assert_eq!(unknown_tag.tlv_type(), TlvType::Unknown(0x7F));
        let payload = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let rec = TlvRecord::new_raw(unknown_tag, payload.clone());
        let bytes = rec.to_bytes();
        let (parsed, consumed) = TlvRecord::parse(&bytes).expect("parse unknown");
        assert_eq!(consumed, 12);
        assert_eq!(parsed.tag, unknown_tag);
        assert_eq!(parsed.as_bytes(), payload.as_slice());
        assert_eq!(parsed.value, TlvValue::Raw(payload));

        assert_eq!(parsed.to_bytes(), bytes);
    }


    #[test]
    fn test_parse_real_captured_packet_686() {
        let pcap_hex = "0000012000000004010001df00000001000000040100032b0000000200000100090001ca705f461c05ec79e7a71b736ceacefb245c31906b29a6d686397b5efc8eaba571884ad7615dbf80ccefd5bdc26a33c22c2f77930a555dec9fd8398550f258edbb876e3832bae01d6db3e88095a91662c95b9e0c282e603682471a46a0c68c37f9204364b580468995edaea45d77bc591f3fd288b74162fd5d282bcf87dafbce10865f8afa57ef60abfd407d2c300435fb576960afc30b86fb4688e20dbc9f4f8bd30b130f9957ddd52603bdda9983ec8867caee864b055649df6532b7400b76bbf8f93789bbb4c785d07768db835241d990b8b40c2ec91d369faa0997e768183d75252b7a35937b63842631e860dafbb19036d38b67d5da90df92283ecc7add65";
        let raw_bytes = hex_to_bytes(pcap_hex);

        assert_eq!(raw_bytes.len(), 292);
        let frame_len = u32::from_be_bytes(raw_bytes[0..4].try_into().unwrap()) as usize;
        assert_eq!(frame_len, 288);

        let inner_payload = &raw_bytes[4..4 + frame_len];
        let tlv_msg =
            TlvMessage::parse(inner_payload).expect("TLV parse de pacote #686 deve ter sucesso");

        assert_eq!(tlv_msg.records.len(), 3);

        assert_eq!(tlv_msg.get_u32(TlvTag::TAG_SESSION_TOKEN), Some(1));

        assert_eq!(tlv_msg.get_u32(TlvTag::TAG_PEER_STATUS), Some(2));

        let rsa_pub = tlv_msg
            .get_buffer(TlvTag::TAG_RSA_PUBLIC_KEY)
            .expect("campo RSA deve existir");
        assert_eq!(rsa_pub.len(), 256);
        assert_eq!(&rsa_pub[0..4], &[0x70, 0x5f, 0x46, 0x1c]);
        assert_eq!(&rsa_pub[252..256], &[0xcc, 0x7a, 0xdd, 0x65]);

        let reserialized = tlv_msg.to_bytes();
        assert_eq!(reserialized.as_slice(), inner_payload);
    }

    #[test]
    fn test_forensic_packet_5487_reply_radmin_vm_pcap() {
        let pcap_hex_reply = "0000000c00000004010001df00000002";
        let raw_bytes = hex_to_bytes(pcap_hex_reply);
        assert_eq!(raw_bytes.len(), 16);

        let tlv_payload = &raw_bytes[4..16];
        assert_eq!(
            tlv_payload,
            &[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x01, 0xdf, 0x00, 0x00, 0x00, 0x02]
        );

        let msg = TlvMessage::parse(tlv_payload).expect("parsing do payload TLV do pacote #5487");
        assert_eq!(msg.records.len(), 1);

        assert_eq!(msg.get_u32(TlvTag(0x010001df)), Some(2));
        assert_eq!(msg.try_to_bytes().unwrap().as_slice(), tlv_payload);
    }


    #[test]
    fn test_security_truncated_header_rejected() {
        for len in 0..8 {
            let buf = vec![0u8; len];
            assert!(matches!(
                TlvRecord::parse(&buf),
                Err(TlvError::IncompleteHeader(l)) if l == len
            ));
        }
    }

    #[test]
    fn test_security_truncated_value_rejected() {
        let mut buf = vec![0x00, 0x00, 0x00, 0x0A, 0x01, 0x00, 0x00, 0x01];
        buf.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            TlvRecord::parse(&buf),
            Err(TlvError::IncompleteValue {
                needed: 18,
                available: 12
            })
        );
    }

    #[test]
    fn test_security_scalar_length_mismatch_rejected() {
        let bad_u32 = [0, 0, 0, 3, 0x01, 0, 0, 1, 1, 2, 3];
        assert_eq!(
            TlvRecord::parse(&bad_u32),
            Err(TlvError::InvalidU32Length(3))
        );

        let bad_u64 = [0, 0, 0, 7, 0x02, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(
            TlvRecord::parse(&bad_u64),
            Err(TlvError::InvalidU64Length(7))
        );

        let bad_i32 = [0, 0, 0, 5, 0x03, 0, 0, 1, 1, 2, 3, 4, 5];
        assert_eq!(
            TlvRecord::parse(&bad_i32),
            Err(TlvError::InvalidI32Length(5))
        );

        let bad_bool_0 = [0, 0, 0, 0, 0x04, 0, 0, 1];
        assert_eq!(
            TlvRecord::parse(&bad_bool_0),
            Err(TlvError::InvalidBoolLength(0))
        );

        let bad_bool_2 = [0, 0, 0, 2, 0x04, 0, 0, 1, 0, 1];
        assert_eq!(
            TlvRecord::parse(&bad_bool_2),
            Err(TlvError::InvalidBoolLength(2))
        );

        let bad_float = [0, 0, 0, 3, 0x05, 0, 0, 1, 1, 2, 3];
        assert_eq!(
            TlvRecord::parse(&bad_float),
            Err(TlvError::InvalidFloatLength(3))
        );

        let bad_double = [0, 0, 0, 7, 0x06, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(
            TlvRecord::parse(&bad_double),
            Err(TlvError::InvalidDoubleLength(7))
        );
    }

    #[test]
    fn test_security_invalid_utf8_rejected() {
        let bad_utf8 = [
            0x00, 0x00, 0x00, 0x02, 0x0B, 0x00, 0x00, 0x01, 0xC3, 0x28, // Sequência truncada
        ];
        assert!(matches!(
            TlvRecord::parse(&bad_utf8),
            Err(TlvError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn test_security_string_length_limit_enforced() {
        let mut big_str_hdr = vec![0x00, 0x00, 0x10, 0x01, 0x0B, 0x00, 0x00, 0x01]; // len = 4097
        big_str_hdr.resize(8 + 4097, b'A');
        assert_eq!(
            TlvRecord::parse(&big_str_hdr),
            Err(TlvError::StringTooLarge {
                size: 4097,
                max: MAX_STRING_LEN
            })
        );
    }

    #[test]
    fn test_security_allocation_bomb_rejected_without_alloc() {
        let huge_hdr = [0x00, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01]; // len = 65536
        assert_eq!(
            TlvRecord::parse(&huge_hdr),
            Err(TlvError::ValueTooLarge(65536))
        );
    }

    #[test]
    fn test_security_message_size_limit_enforced() {
        let over_limit = vec![0u8; MAX_TLV_MESSAGE_SIZE + 1];
        assert_eq!(
            TlvMessage::parse(&over_limit),
            Err(TlvError::MessageTooLarge {
                size: MAX_TLV_MESSAGE_SIZE + 1,
                max: MAX_TLV_MESSAGE_SIZE
            })
        );
    }

    #[test]
    fn test_security_max_records_limit_enforced() {
        let single_rec = [0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 1]; // 12 bytes
        let mut msg_bytes = Vec::with_capacity(12 * 1025);
        for _ in 0..1025 {
            msg_bytes.extend_from_slice(&single_rec);
        }
        assert_eq!(
            TlvMessage::parse(&msg_bytes),
            Err(TlvError::TooManyRecords(1024))
        );
    }


    #[test]
    fn test_security_serialization_individual_record_limit_rejected() {
        let huge_buf = vec![0xAA; MAX_TLV_VALUE_SIZE + 1];
        let rec = TlvRecord::new_buffer(TlvTag::new(0x09, 1), huge_buf);
        assert_eq!(
            rec.try_to_bytes(),
            Err(TlvError::ValueTooLarge(MAX_TLV_VALUE_SIZE + 1))
        );
    }

    #[test]
    fn test_security_serialization_string_length_limit_rejected() {
        let long_str = "x".repeat(MAX_STRING_LEN + 1);
        let rec = TlvRecord::new_string(TlvTag::new(0x0B, 1), long_str.clone());
        assert_eq!(
            rec.try_to_bytes(),
            Err(TlvError::StringTooLarge {
                size: MAX_STRING_LEN + 1,
                max: MAX_STRING_LEN
            })
        );

        let mut msg = TlvMessage::new();
        assert_eq!(
            msg.try_add_string(TlvTag::new(0x0B, 1), long_str),
            Err(TlvError::StringTooLarge {
                size: MAX_STRING_LEN + 1,
                max: MAX_STRING_LEN
            })
        );
    }

    #[test]
    fn test_security_serialization_message_size_limit_rejected() {
        let mut msg = TlvMessage::new();
        let part1 = vec![0x11; 30000];
        let part2 = vec![0x22; 30000];
        let part3 = vec![0x33; 30000];

        msg.try_add(TlvRecord::new_buffer(TlvTag::new(0x09, 1), part1))
            .unwrap();
        msg.try_add(TlvRecord::new_buffer(TlvTag::new(0x09, 2), part2))
            .unwrap();

        assert_eq!(
            msg.try_add(TlvRecord::new_buffer(TlvTag::new(0x09, 3), part3.clone())),
            Err(TlvError::MessageTooLarge {
                size: 90024,
                max: MAX_TLV_MESSAGE_SIZE
            })
        );
        assert_eq!(msg.records.len(), 2);

        msg.records
            .push(TlvRecord::new_buffer(TlvTag::new(0x09, 3), part3));
        assert_eq!(
            msg.try_to_bytes(),
            Err(TlvError::MessageTooLarge {
                size: 90024,
                max: MAX_TLV_MESSAGE_SIZE
            })
        );
    }

    #[test]
    fn test_security_try_add_accumulated_size_limit() {
        let mut msg = TlvMessage::new();

        msg.try_add(TlvRecord::new_buffer(
            TlvTag::new(0x09, 1),
            vec![0xAA; 32000],
        ))
        .expect("registro 1 deve ser aceito");
        assert_eq!(msg.encoded_len(), 32008);
        assert_eq!(msg.records.len(), 1);

        msg.try_add(TlvRecord::new_buffer(
            TlvTag::new(0x09, 2),
            vec![0xBB; 32000],
        ))
        .expect("registro 2 deve ser aceito");
        assert_eq!(msg.encoded_len(), 64016);
        assert_eq!(msg.records.len(), 2);

        let err = msg
            .try_add(TlvRecord::new_buffer(
                TlvTag::new(0x09, 3),
                vec![0xCC; 2000],
            ))
            .expect_err("adição acima de 65.535 bytes deve ser rejeitada");

        assert_eq!(
            err,
            TlvError::MessageTooLarge {
                size: 66024,
                max: MAX_TLV_MESSAGE_SIZE,
            }
        );

        assert_eq!(msg.records.len(), 2);
        assert_eq!(msg.encoded_len(), 64016);

        let serialized = msg
            .try_to_bytes()
            .expect("mensagem válida deve serializar com sucesso");
        assert_eq!(serialized.len(), 64016);
    }

    #[test]
    #[should_panic(expected = "limites de tamanho ou quantidade excedidos")]
    fn test_security_legacy_add_panics_on_size_limit_overflow() {
        let mut msg = TlvMessage::new();
        msg.add_buffer(TlvTag::new(0x09, 1), vec![0xAA; 60000]);
        msg.add_buffer(TlvTag::new(0x09, 2), vec![0xBB; 10000]);
    }

    #[test]
    #[should_panic(expected = "limites de tamanho ou quantidade excedidos")]
    fn test_security_legacy_add_panics_on_record_count_overflow() {
        let mut msg = TlvMessage::new();
        for i in 0..1024 {
            msg.add_u32(TlvTag::new(0x01, i), i);
        }
        msg.add_u32(TlvTag::new(0x01, 1024), 1024);
    }

    #[test]
    fn test_security_serialization_max_records_limit_rejected() {
        let mut msg = TlvMessage::new();
        for i in 0..1024 {
            msg.try_add(TlvRecord::new_u32(TlvTag::new(0x01, i), i))
                .unwrap();
        }
        assert_eq!(
            msg.try_add(TlvRecord::new_u32(TlvTag::new(0x01, 1024), 1024)),
            Err(TlvError::TooManyRecords(1024))
        );

        msg.records
            .push(TlvRecord::new_u32(TlvTag::new(0x01, 1024), 1024));
        assert_eq!(msg.try_to_bytes(), Err(TlvError::TooManyRecords(1025)));
    }

    #[test]
    fn test_security_bool_invalid_wire_len_safe_rejection() {
        for invalid_len in [0usize, 2, 3, 5, 8, 16] {
            let rec = TlvRecord {
                tag: TlvTag::new(0x04, 1),
                value: TlvValue::Bool {
                    value: true,
                    raw: vec![0xFF; invalid_len],
                },
            };
            assert_eq!(
                rec.try_to_bytes(),
                Err(TlvError::InvalidBoolLength(invalid_len))
            );

            let mut msg = TlvMessage::new();
            assert_eq!(
                msg.try_add(rec.clone()),
                Err(TlvError::InvalidBoolLength(invalid_len))
            );

            msg.records.push(rec);
            assert_eq!(
                msg.try_to_bytes(),
                Err(TlvError::InvalidBoolLength(invalid_len))
            );
        }
    }

    #[test]
    fn test_security_bool_value_raw_mismatch_rejected() {
        let tag = TlvTag::new(0x04, 10);

        let rec1 = TlvRecord {
            tag,
            value: TlvValue::Bool {
                value: true,
                raw: vec![0x00],
            },
        };
        assert_eq!(rec1.validate(), Err(TlvError::BoolValueMismatch));
        assert_eq!(rec1.try_to_bytes(), Err(TlvError::BoolValueMismatch));
        let mut msg1 = TlvMessage::new();
        assert_eq!(msg1.try_add(rec1), Err(TlvError::BoolValueMismatch));

        let rec2 = TlvRecord {
            tag,
            value: TlvValue::Bool {
                value: false,
                raw: vec![0x01],
            },
        };
        assert_eq!(rec2.validate(), Err(TlvError::BoolValueMismatch));
        assert_eq!(rec2.try_to_bytes(), Err(TlvError::BoolValueMismatch));
        let mut msg2 = TlvMessage::new();
        assert_eq!(msg2.try_add(rec2), Err(TlvError::BoolValueMismatch));

        let rec3 = TlvRecord {
            tag,
            value: TlvValue::Bool {
                value: true,
                raw: vec![0x00, 0x00, 0x00, 0x00],
            },
        };
        assert_eq!(rec3.validate(), Err(TlvError::BoolValueMismatch));
        assert_eq!(rec3.try_to_bytes(), Err(TlvError::BoolValueMismatch));
        let mut msg3 = TlvMessage::new();
        assert_eq!(msg3.try_add(rec3), Err(TlvError::BoolValueMismatch));

        let rec4 = TlvRecord {
            tag,
            value: TlvValue::Bool {
                value: false,
                raw: vec![0x00, 0x00, 0x00, 0xFF],
            },
        };
        assert_eq!(rec4.validate(), Err(TlvError::BoolValueMismatch));
        assert_eq!(rec4.try_to_bytes(), Err(TlvError::BoolValueMismatch));
        let mut msg4 = TlvMessage::new();
        assert_eq!(msg4.try_add(rec4), Err(TlvError::BoolValueMismatch));

        let valid_non_can_1 = TlvRecord {
            tag,
            value: TlvValue::Bool {
                value: true,
                raw: vec![0x42],
            },
        };
        assert!(valid_non_can_1.validate().is_ok());
        let bytes1 = valid_non_can_1.try_to_bytes().expect("deve serializar");
        assert_eq!(bytes1[8], 0x42);
        let (parsed1, c1) = TlvRecord::parse(&bytes1).expect("parse");
        assert_eq!(c1, 9);
        assert_eq!(parsed1.as_bool(), Some(true));
        assert_eq!(parsed1.to_bytes(), bytes1);

        let valid_non_can_4 = TlvRecord {
            tag,
            value: TlvValue::Bool {
                value: true,
                raw: vec![0x00, 0x00, 0x00, 0xFF],
            },
        };
        assert!(valid_non_can_4.validate().is_ok());
        let bytes4 = valid_non_can_4.try_to_bytes().expect("deve serializar");
        assert_eq!(&bytes4[8..12], &[0x00, 0x00, 0x00, 0xFF]);
        let (parsed4, c4) = TlvRecord::parse(&bytes4).expect("parse");
        assert_eq!(c4, 12);
        assert_eq!(parsed4.as_bool(), Some(true));
        assert_eq!(parsed4.to_bytes(), bytes4);
    }

    #[test]
    fn test_legacy_to_bytes_compatibility() {
        let mut msg = TlvMessage::new();
        msg.add_u32(TlvTag::TAG_SESSION_TOKEN, 10);
        msg.add_u64(TlvTag::TAG_TIMESTAMP, 20);
        msg.add_buffer(TlvTag::TAG_RSA_PUBLIC_KEY, vec![0xDD; 64]);

        let legacy_bytes = msg.to_bytes();
        let safe_bytes = msg.try_to_bytes().expect("try_to_bytes deve ter sucesso");
        assert_eq!(legacy_bytes, safe_bytes);

        let parsed = TlvMessage::parse(&legacy_bytes).expect("parse");
        assert_eq!(parsed.get_u32(TlvTag::TAG_SESSION_TOKEN), Some(10));
        assert_eq!(parsed.get_u64(TlvTag::TAG_TIMESTAMP), Some(20));
        assert_eq!(
            parsed.get_buffer(TlvTag::TAG_RSA_PUBLIC_KEY),
            Some([0xDD; 64].as_slice())
        );
    }


    #[test]
    fn test_repeated_tags_get_all() {
        let mut msg = TlvMessage::new();
        let tag = TlvTag::new(0x02, 10); // ex: TAG_NODE_ID
        msg.add_u64(tag, 1001);
        msg.add_u64(tag, 1002);
        msg.add_u64(tag, 1003);

        assert_eq!(msg.get_u64(tag), Some(1001)); // get() retorna o primeiro
        let all = msg.get_all(tag);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].as_u64(), Some(1001));
        assert_eq!(all[1].as_u64(), Some(1002));
        assert_eq!(all[2].as_u64(), Some(1003));
    }

    #[test]
    fn test_symmetric_roundtrip_all_types() {
        let mut msg = TlvMessage::new();
        msg.add_u32(TlvTag::new(0x01, 1), 42);
        msg.add_u64(TlvTag::new(0x02, 2), 999999);
        msg.add_i32(TlvTag::new(0x03, 3), -12345);
        msg.add_bool_1(TlvTag::new(0x04, 4), true);
        msg.add_bool_4(TlvTag::new(0x04, 5), false);
        msg.add_string(TlvTag::new(0x0B, 6), "TestNet".to_string());
        msg.add_buffer(TlvTag::new(0x09, 7), vec![1, 2, 3, 4, 5]);

        let bytes = msg.to_bytes();
        let parsed = TlvMessage::parse(&bytes).expect("parse roundtrip");

        assert_eq!(parsed.get_u32(TlvTag::new(0x01, 1)), Some(42));
        assert_eq!(parsed.get_u64(TlvTag::new(0x02, 2)), Some(999999));
        assert_eq!(parsed.get_i32(TlvTag::new(0x03, 3)), Some(-12345));
        assert_eq!(parsed.get_bool(TlvTag::new(0x04, 4)), Some(true));
        assert_eq!(parsed.get_bool(TlvTag::new(0x04, 5)), Some(false));
        assert_eq!(parsed.get_string(TlvTag::new(0x0B, 6)), Some("TestNet"));
        assert_eq!(
            parsed.get_buffer(TlvTag::new(0x09, 7)),
            Some([1u8, 2, 3, 4, 5].as_slice())
        );

        assert_eq!(
            parsed.get(TlvTag::new(0x04, 4)).unwrap().value,
            TlvValue::Bool {
                value: true,
                raw: vec![1],
            }
        );
        assert_eq!(
            parsed.get(TlvTag::new(0x04, 5)).unwrap().value,
            TlvValue::Bool {
                value: false,
                raw: vec![0, 0, 0, 0],
            }
        );

        assert_eq!(parsed.to_bytes(), bytes);
    }


    #[test]
    fn test_security_type_mismatch_all_valid_combinations() {
        let valid_records = vec![
            TlvRecord::new_u32(TlvTag::new(0x01, 1), 42),
            TlvRecord::new_u64(TlvTag::new(0x02, 2), 123456789),
            TlvRecord::new_i32(TlvTag::new(0x03, 3), -99),
            TlvRecord::new_bool_1(TlvTag::new(0x04, 4), true),
            TlvRecord::new_float_opaque(TlvTag::new(0x05, 5), [0x3F, 0x80, 0x00, 0x00]),
            TlvRecord::new_double_opaque(
                TlvTag::new(0x06, 6),
                [0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18],
            ),
            TlvRecord::new_raw(TlvTag::new(0x08, 8), vec![0xCA, 0xFE]), // Compound
            TlvRecord::new_buffer(TlvTag::new(0x09, 9), vec![1, 2, 3]),
            TlvRecord::new_raw(TlvTag::new(0x0A, 10), vec![0x00; 8]), // DateTime
            TlvRecord::new_string(TlvTag::new(0x0B, 11), "valid_utf8".to_string()),
            TlvRecord::new_raw(TlvTag::new(0x0C, 12), vec![0x11, 0x22]), // Object
            TlvRecord::new_raw(TlvTag::new(0x0D, 13), vec![0x33, 0x44]), // List
            TlvRecord::new_raw(TlvTag::new(0x0E, 14), vec![0x55, 0x66]), // Map
            TlvRecord::new_raw(TlvTag::new(0x7F, 15), vec![0x77, 0x88]), // Unknown
        ];

        let mut msg = TlvMessage::new();
        for rec in valid_records {
            assert!(
                rec.validate().is_ok(),
                "validação falhou para {:?}",
                rec.tag
            );
            assert!(
                rec.try_to_bytes().is_ok(),
                "serialização falhou para {:?}",
                rec.tag
            );
            assert!(msg.try_add(rec).is_ok(), "try_add falhou para a mensagem");
        }
        assert!(msg.try_to_bytes().is_ok());
    }

    #[test]
    fn test_security_type_mismatch_invalid_primitive_cases() {
        let invalid_cases = vec![
            (
                TlvRecord {
                    tag: TlvTag::new(0x01, 1), // U32
                    value: TlvValue::U64(100),
                },
                TlvError::TypeMismatch {
                    expected: TlvType::U32,
                    actual: "U64",
                },
            ),
            (
                TlvRecord {
                    tag: TlvTag::new(0x02, 2), // U64
                    value: TlvValue::U32(100),
                },
                TlvError::TypeMismatch {
                    expected: TlvType::U64,
                    actual: "U32",
                },
            ),
            (
                TlvRecord {
                    tag: TlvTag::new(0x03, 3), // I32
                    value: TlvValue::U32(100),
                },
                TlvError::TypeMismatch {
                    expected: TlvType::I32,
                    actual: "U32",
                },
            ),
            (
                TlvRecord {
                    tag: TlvTag::new(0x04, 4), // Bool
                    value: TlvValue::Float([0; 4]),
                },
                TlvError::TypeMismatch {
                    expected: TlvType::Bool,
                    actual: "Float",
                },
            ),
            (
                TlvRecord {
                    tag: TlvTag::new(0x05, 5), // Float
                    value: TlvValue::Double([0; 8]),
                },
                TlvError::TypeMismatch {
                    expected: TlvType::Float,
                    actual: "Double",
                },
            ),
            (
                TlvRecord {
                    tag: TlvTag::new(0x06, 6), // Double
                    value: TlvValue::Float([0; 4]),
                },
                TlvError::TypeMismatch {
                    expected: TlvType::Double,
                    actual: "Float",
                },
            ),
            (
                TlvRecord {
                    tag: TlvTag::new(0x09, 9), // Buffer
                    value: TlvValue::StringUtf8("buffer_not_string".to_string()),
                },
                TlvError::TypeMismatch {
                    expected: TlvType::Buffer,
                    actual: "StringUtf8",
                },
            ),
            (
                TlvRecord {
                    tag: TlvTag::new(0x0B, 11), // StringUtf8
                    value: TlvValue::Buffer(vec![0xAA, 0xBB]),
                },
                TlvError::TypeMismatch {
                    expected: TlvType::StringUtf8,
                    actual: "Buffer",
                },
            ),
        ];

        for (rec, expected_err) in invalid_cases {
            assert_eq!(rec.validate(), Err(expected_err.clone()));
            assert_eq!(rec.try_to_bytes(), Err(expected_err.clone()));

            let mut msg = TlvMessage::new();
            assert_eq!(msg.try_add(rec.clone()), Err(expected_err.clone()));
            assert!(msg.records.is_empty());

            msg.records.push(rec);
            assert_eq!(msg.try_to_bytes(), Err(expected_err));
        }
    }

    #[test]
    fn test_security_type_mismatch_raw_rules() {
        let valid_raw_types = [
            (0x08, TlvType::Compound),
            (0x0A, TlvType::DateTime),
            (0x0C, TlvType::Object),
            (0x0D, TlvType::List),
            (0x0E, TlvType::Map),
            (0x7F, TlvType::Unknown(0x7F)),
        ];
        for (type_byte, _) in valid_raw_types {
            let rec = TlvRecord::new_raw(TlvTag::new(type_byte, 1), vec![0x12, 0x34]);
            assert!(rec.validate().is_ok());
            assert!(rec.try_to_bytes().is_ok());
        }

        let primitive_types = [
            (0x01, TlvType::U32),
            (0x02, TlvType::U64),
            (0x03, TlvType::I32),
            (0x04, TlvType::Bool),
            (0x05, TlvType::Float),
            (0x06, TlvType::Double),
            (0x09, TlvType::Buffer),
            (0x0B, TlvType::StringUtf8),
        ];

        for (type_byte, expected_tlv_type) in primitive_types {
            let rec = TlvRecord::new_raw(TlvTag::new(type_byte, 100), vec![0xDE, 0xAD]);
            let expected_err = TlvError::TypeMismatch {
                expected: expected_tlv_type,
                actual: "Raw",
            };
            assert_eq!(rec.validate(), Err(expected_err.clone()));
            assert_eq!(rec.try_to_bytes(), Err(expected_err.clone()));

            let mut msg = TlvMessage::new();
            assert_eq!(msg.try_add(rec.clone()), Err(expected_err.clone()));
            assert_eq!(msg.records.len(), 0);

            msg.records.push(rec);
            assert_eq!(msg.try_to_bytes(), Err(expected_err));
        }
    }

    #[test]
    fn test_security_type_mismatch_try_add_and_try_to_bytes_rejected() {
        let mismatched = TlvRecord::new_u32(TlvTag::new(0x09, 1), 42);
        let expected_err = TlvError::TypeMismatch {
            expected: TlvType::Buffer,
            actual: "U32",
        };

        assert_eq!(mismatched.try_to_bytes(), Err(expected_err.clone()));

        let mut msg = TlvMessage::new();
        assert_eq!(msg.try_add(mismatched.clone()), Err(expected_err.clone()));
        assert!(msg.records.is_empty(), "nenhum registro deve ser inserido");

        msg.records.push(mismatched);
        assert_eq!(msg.try_to_bytes(), Err(expected_err));
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
