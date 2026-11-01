pub mod control;
pub mod framing;
pub mod packets;
pub mod tlv;

pub use control::{ControlMessage, PeerStatus};

pub use framing::{FrameParser, FramedPacket, FramingError, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE};
pub use tlv::{TlvError, TlvMessage, TlvRecord, TlvTag, TlvType, TlvValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosMessageType {
    Register,
    Connect,
    ContinueConnect,
    JoinNetwork,
    ManageNetwork,
    LeaveNetwork,
    GetNodes,
    GetNodeRegionSupport,
    EnumPublicNetworks,
    ReportIpConflict,
    ReportRServerInfo,
    ReportSessionSummary,
    ReportLanguage,
    ChatCommand,
    NeedMasterAddress,
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub struct RosNodeAddress {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub node_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthSessionId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    JoiningNetwork,
    InNetwork,
    Failed,
}

#[derive(Debug, Clone)]
pub struct RosMessage {
    pub msg_type: RosMessageType,
    pub session_id: Option<AuthSessionId>,
    pub payload: Vec<u8>,
}

impl RosMessage {
    pub fn new(msg_type: RosMessageType) -> Self {
        Self {
            msg_type,
            session_id: None,
            payload: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ros_message_default_has_no_session() {
        let m = RosMessage::new(RosMessageType::Register);
        assert!(m.session_id.is_none());
        assert!(m.payload.is_empty());
    }
}
