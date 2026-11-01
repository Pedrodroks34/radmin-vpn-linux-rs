//! # Tipos de pacote do protocolo Radmin VPN
//!
//! Todos os tipos abaixo foram extraídos do RTTI de `RvROLClient.dll`
//! (strings de mangling C++ `?AV*Packet@RolClient@@`) e de `RvControlSvc.exe`.
//!
//! ## Classificação da evidência
//!
//! - **Existência do tipo:** Confirmada (nomes de classes nos binários)
//! - **Estrutura binária (campos, ordem, tamanhos):** Desconhecida — requer REA dinâmica
//! - **Semântica de cada campo:** Desconhecida
//! - **Serialização/deserialização:** Desconhecida

use serde::{Deserialize, Serialize};

/// Pacote abstrato base do cliente (interface `VIClnPacket` / classe `CAbstractClnPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbstractClnPacket {
    /// Placeholder — campos desconhecidos
    pub _raw: Vec<u8>,
}

/// Pacote de conexão abstrato (`CAbstractConnectionPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbstractConnectionPacket {
    pub _raw: Vec<u8>,
}

/// Pacote genérico (`CGenericPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de rede (`CMsgNetPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de login (`CLoginPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginPacket {
    pub _raw: Vec<u8>,
}

/// Resultado de conexão (`CConnectResultPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectResultPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de heartbeat (`CHeartbeatPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatPacket {
    pub _raw: Vec<u8>,
}

/// Pacote "está vivo" (`CIsAlivePacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsAlivePacket {
    pub _raw: Vec<u8>,
}

/// Pacote de entrada em rede (`CJoinNetworkPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinNetworkPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de cancelar entrada (`CCancelJoinPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelJoinPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de gerenciar rede (`CManageNetworkPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManageNetworkPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de listar redes públicas (`CEnumPublicNetworksPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumPublicNetworksPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de obter nós (`CChatGetNodesPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatGetNodesPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de suporte de região (`CGetNodeRegionSupportPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetNodeRegionSupportPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de idioma da GUI (`CGuiLanguagePacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiLanguagePacket {
    pub _raw: Vec<u8>,
}

/// Pacote de informação do servidor (`CRServerInfoPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RServerInfoPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de resumo de sessão (`CSessionSummaryPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummaryPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de info de rede Enet (`CEnetInfoPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnetInfoPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de info de rede Enet direta (`CDirectEnetInfoPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectEnetInfoPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de iniciar Enet (`CStartEnetPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartEnetPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de info TCP (`CTcpInfoPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpInfoPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de info NAT TCP (`CTcpNatInfoPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpNatInfoPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de coletar info NAT TCP (`CRosPktCollectTcpNatInfo`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPktCollectTcpNatInfo {
    pub _raw: Vec<u8>,
}

/// Pacote de penetração de NAT (`CNatPenPackets`, `CNatPenStatusPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatPenStatusPacket {
    pub _raw: Vec<u8>,
}

/// Pacote ROS genérico (`CRosPacket`, interface `IRosPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de conexão ROS (`CRosConnectionPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosConnectionPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de comando de chat (`CChatCommandPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCommandPacket {
    pub _raw: Vec<u8>,
}

/// Resposta de comando de chat ROS (`CRosPktChatCommandReply`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPktChatCommandReply {
    pub _raw: Vec<u8>,
}

/// Pacote de push info (`CRosPktPushInfo`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPktPushInfo {
    pub _raw: Vec<u8>,
}

/// Pacote de info de licença (`CRosPktLicInfo`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosPktLicInfo {
    pub _raw: Vec<u8>,
}

/// Pacote de conflito de IP (`CConflictedIpAddressPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictedIpAddressPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de log (`CLogPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogPacket {
    pub _raw: Vec<u8>,
}

/// Pacote de requisição TRS (`CRequestTrsPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestTrsPacket {
    pub _raw: Vec<u8>,
}

/// Mensagem de autenticação falhou (`CMsgAuthFailed`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgAuthFailed {
    pub _raw: Vec<u8>,
}

/// Mensagem de autenticação finalizada (`CMsgAuthFinished`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgAuthFinished {
    pub _raw: Vec<u8>,
}

/// Mensagem servidor ruim (`CMsgBadServerPacket`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgBadServerPacket {
    pub _raw: Vec<u8>,
}

/// ROS ignorado (`CMsgRosIgnored`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgRosIgnored {
    pub _raw: Vec<u8>,
}

/// Pacote de versão do cliente (`CClientVersionInfo`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientVersionInfo {
    pub _raw: Vec<u8>,
}

/// Pacote de conexão de pacote (`CPacketConnection` no FamRT)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketConnection {
    pub _raw: Vec<u8>,
}

/// Pacote de resposta do serviço (`ReplyPacket@ControlSvc`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyPacket {
    pub _raw: Vec<u8>,
}

/// Enumera todos os tipos de pacote conhecidos (placeholders)
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
