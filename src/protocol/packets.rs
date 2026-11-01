use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbstractClnPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbstractConnectionPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectResultPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsAlivePacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinNetworkPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelJoinPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManageNetworkPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumPublicNetworksPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatGetNodesPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetNodeRegionSupportPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiLanguagePacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RServerInfoPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummaryPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnetInfoPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectEnetInfoPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartEnetPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpInfoPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpNatInfoPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPktCollectTcpNatInfo {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatPenStatusPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosConnectionPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCommandPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPktChatCommandReply {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPktPushInfo {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPktLicInfo {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictedIpAddressPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestTrsPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgAuthFailed {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgAuthFinished {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgBadServerPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgRosIgnored {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientVersionInfo {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketConnection {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyPacket {
    pub _raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnyPacket {
    AbstractCln(AbstractClnPacket),
    AbstractConnection(AbstractConnectionPacket),
    Generic(GenericPacket),
    Net(NetPacket),
    Login(LoginPacket),
    ConnectResult(ConnectResultPacket),
    Heartbeat(HeartbeatPacket),
    IsAlive(IsAlivePacket),
    JoinNetwork(JoinNetworkPacket),
    CancelJoin(CancelJoinPacket),
    ManageNetwork(ManageNetworkPacket),
    EnumPublicNetworks(EnumPublicNetworksPacket),
    ChatGetNodes(ChatGetNodesPacket),
    GetNodeRegionSupport(GetNodeRegionSupportPacket),
    GuiLanguage(GuiLanguagePacket),
    RServerInfo(RServerInfoPacket),
    SessionSummary(SessionSummaryPacket),
    EnetInfo(EnetInfoPacket),
    DirectEnetInfo(DirectEnetInfoPacket),
    StartEnet(StartEnetPacket),
    TcpInfo(TcpInfoPacket),
    TcpNatInfo(TcpNatInfoPacket),
    RosPktCollectTcpNatInfo(RosPktCollectTcpNatInfo),
    NatPenStatus(NatPenStatusPacket),
    Ros(RosPacket),
    RosConnection(RosConnectionPacket),
    ChatCommand(ChatCommandPacket),
    RosPktChatCommandReply(RosPktChatCommandReply),
    RosPktPushInfo(RosPktPushInfo),
    RosPktLicInfo(RosPktLicInfo),
    ConflictedIpAddress(ConflictedIpAddressPacket),
    Log(LogPacket),
    RequestTrs(RequestTrsPacket),
    MsgAuthFailed(MsgAuthFailed),
    MsgAuthFinished(MsgAuthFinished),
    MsgBadServer(MsgBadServerPacket),
    MsgRosIgnored(MsgRosIgnored),
    ClientVersionInfo(ClientVersionInfo),
    PacketConnection(PacketConnection),
    Reply(ReplyPacket),
    Unknown { type_name: String, raw: Vec<u8> },
}
