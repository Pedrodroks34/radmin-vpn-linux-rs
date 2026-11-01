//! # Módulo `protocol` — Protocolo proprietário do Radmin VPN (ROS)
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - O cliente Windows utiliza um servidor de sinalização chamado **ROS** ("Radmin Online Server").
//! - A classe `VIRosProtocol` (RTTI visível em `RvROLClient.dll`) expõe a interface do protocolo ROS.
//! - `CRosAddress` e `CRosSessionId` são usados para endereçamento e sessão no ROS.
//! - Não há endereços IP de servidores Radmin hardcoded nos binários; são resolvidos via DNS/DoH.
//!   (String `https://%hs/dns-query` + lista de resolvers públicos: 1.1.1.1, 8.8.8.8, 9.9.9.9, etc.)
//!
//! **Fortemente provável:**
//! - `ROLClient_Register` registra o dispositivo junto ao servidor ROS.
//! - `ROLClient_Connect` / `ContinueConnect` estabelecem canais de sinalização.
//! - `ROLClient_GetNodes` / `EnumPublicNetworks` descobrem membros e redes públicas.
//!
//! **Desconhecido:**
//! - Estrutura binária exata dos pacotes ROS.
//! - Handshake de autenticação.
//! - Portas utilizadas.
//! - Heartbeat e keep-alive.
//
//! ## Tipos de pacote identificados via RTTI (RvROLClient.dll)
//!
//! Os seguintes tipos de pacote foram extraídos dos nomes de classes C++ nos binários.
//! Suas estruturas binárias são **desconhecidas** e estão em `protocol/packets.rs`
//! como placeholders:
//!
//! `CAbstractClnPacket`, `CAbstractConnectionPacket`, `CCancelJoinPacket`,
//! `CChatCommandPacket`, `CChatGetNodesPacket`, `CClientVersionInfo`,
//! `CConflictedIpAddressPacket`, `CConnectResultPacket`, `CDirectEnetInfoPacket`,
//! `CEnetInfoPacket`, `CEnumPublicNetworksPacket`, `CGenericPacket`,
//! `CGetNodeRegionSupportPacket`, `CGuiLanguagePacket`, `CHeartbeatPacket`,
//! `CIsAlivePacket`, `CJoinNetworkPacket`, `CLoginPacket`, `CLogPacket`,
//! `CManageNetworkPacket`, `CMsgAuthFailed`, `CMsgAuthFinished`,
//! `CMsgBadServerPacket`, `CMsgNetPacket`, `CMsgRosIgnored`, `CNatPenPackets`,
//! `CNatPenStatusPacket`, `CPacketConnection`, `CRequestTrsPacket`,
//! `CRosConnectionPacket`, `CRosPacket`, `CRosPktChatCommandReply`,
//! `CRosPktCollectTcpNatInfo`, `CRosPktLicInfo`, `CRosPktPushInfo`,
//! `CRServerInfoPacket`, `CSessionSummaryPacket`, `CStartEnetPacket`,
//! `CTcpInfoPacket`, `CTcpNatInfoPacket`, `VIClnPacket`, `IRosPacket`,
//! `ReplyPacket` (do ControlSvc).
//!
//! ## Planejamento de implementação
//!
//! Este módulo define os tipos de mensagem e estados de conexão do protocolo ROS.
//! Os detalhes de serialização/binário devem ser preenchidos após análise dinâmica.
pub mod packets;
pub mod framing;

/// Tipos de mensagem do protocolo ROS (inferidos das exportações de RvROLClient)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosMessageType {
    Register,           // ROLClient_Register
    Connect,            // ROLClient_Connect
    ContinueConnect,    // ROLClient_ContinueConnect
    JoinNetwork,        // ROLClient_JoinNetwork
    ManageNetwork,      // ROLClient_ManageNetwork / ManageNetwork2
    LeaveNetwork,       // ROLClient_LeaveNetwork (inferido)
    GetNodes,           // ROLClient_GetNodes
    GetNodeRegionSupport, // ROLClient_GetNodeRegionSupport
    EnumPublicNetworks, // ROLClient_EnumPublicNetworks
    ReportIpConflict,   // ROLClient_ReportIpConflict
    ReportRServerInfo,  // ROLClient_ReportRServerInfo
    ReportSessionSummary, // ROLClient_ReportSessionSummary
    ReportLanguage,     // ROLClient_ReportLanguage
    ChatCommand,        // ROLClient_ChatCommand
    NeedMasterAddress,  // ROLClient_NeedMasterAddress
    Unknown(u8),
}

/// Endereço de um nó na rede Radmin VPN (inferido de CRosAddress / CClientIpAddress)
#[derive(Debug, Clone)]
pub struct RosNodeAddress {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub node_id: u64,  // inferido de VCRid / CConnectionId
}

/// ID de sessão de autenticação (inferido de CAuthSessionId)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthSessionId(pub u64);

/// Estado da conexão ROS
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

/// Mensagem genérica do protocolo (estrutura placeholder — preencher após REA dinâmica)
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
