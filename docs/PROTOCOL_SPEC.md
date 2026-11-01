# Especificação do Protocolo Radmin VPN — Fase 2 (Reconstrução)

**Status:** ESPECIFICAÇÃO PARCIAL — baseada em análise estática de binários (REA)
+ captura de tráfego real (tshark, VM 192.168.122.77, interface virbr0).
Nenhuma decompilação foi realizada neste ambiente.

**Regra obrigatória:** Nenhum campo, offset, tamanho, endianness, identificador numérico,
função de serialização ou algoritmo criptográfico foi observado diretamente. Todos os
valores marcados como `desconhecido` devem permanecer assim até análise dinâmica
ou decompilação.

---

## 1. Visão Geral da Arquitetura de Protocolos

O Radmin VPN é composto por três camadas de protocolo distintas, identificadas nos binários:

```
┌─────────────────────────────────────────────────────────┐
│  RvRvpnGui.exe  (Qt/QML UI)                             │
└──────────────┬──────────────────────────────────────────┘
               │  named pipe: \\.\pipe\RadminVpnGuiChannel
               ▼
┌─────────────────────────────────────────────────────────┐
│  RvControlSvc.exe  (serviço Windows, motor FamRT/C++)   │
│  ├── Pacotes de controle (CPacket_*): handshake,        │
│  │   keepalive, shutdown, frame, switch, filter          │
│  ├── Imports WS2_32 (WSARecv), WININET                  │
│  └── Chama ROLClient_* (conectar, enviar, receber, etc) │
└──────────────┬──────────────────────────────────────────┘
               │  DeviceIoControl \\.\RVPNNETMP
               ▼
┌─────────────────────────────────────────────────────────┐
│  NetMP60.sys  (NDIS 6 miniport, \Device\RVPNNETMP)      │
│  ├── IOCTL start address                                │
│  ├── Current Address / Permanent Address (MAC)          │
│  └── Assinado por Microsoft Windows HC                  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  RvROLClient.dll  (biblioteca de cliente ROL)           │
│  ├── Pacotes ROS (CRosPkt_*): registro, login, join,    │
│  │   heartbeat, networks, NAT, etc.                      │
│  ├── Pacotes de sessão (CMsg_*, CSession_*): auth, IP,  │
│  │   Enet, shutdown, private session                     │
│  ├── Pacotes de dados cliente (C*Packet@RolClient):     │
│  │   login, join, manage, heartbeat, enet, etc.          │
│  ├── Estruturas: CCryptoChannel, CAuthSessionId,        │
│  │   VCUniqueConnectionId, VCRid, VCRosAddress,          │
│  │   VCRosSessionId, CEnetAbstractConnection,            │
│  │   TMBufferQueueWithCode (send/recv),                  │
│  │   CProxyAddressPool, CGenericAddressPool,             │
│  │   CDEnetAddresses, USPortPara, USNatPenPacket         │
│  └── 47 exportações ROLClient_*                         │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Camada de Controle — `RvControlSvc.exe`

### 2.1 Fluxo de Inicialização (inferido de imports)

O serviço Windows segue este fluxo (ordem inferida de imports, não observada em execução):

1. `StartServiceCtrlDispatcherW` / `RegisterServiceCtrlHandlerExW` / `SetServiceStatus`
   — registro como serviço Windows.
2. `CreateNamedPipeW` / `ConnectNamedPipe` / `DisconnectNamedPipe`
   — IPC com GUI via `\\.\pipe\RadminVpnGuiChannel`.
3. `ROLClient_InitConnector` / `ROLClient_Connect` / `ROLClient_ContinueConnect`
   — inicialização do conector ROL.
4. `ROLClient_ListenVpn` — escuta VPN.
5. `ROLClient_Send` / `ROLClient_Receive` / `ROLClient_WaitForSend` — transporte.
6. `CreateServiceW` / `DeleteService` / `ChangeServiceConfigW` — gestão de serviço.
7. `DeviceIoControl` — comunicação com `NetMP60.sys` (`\\.\RVPNNETMP`).
8. `FwpmFilterAdd0` / `FwpmSubLayerAdd0` (fwpuclnt) — regras de firewall WFP.
9. `CreateIpNetEntry` / `DeleteIpForwardEntry2` (IPHLPAPI) — rotas/IP.

**Evidência:** `inspect_pe_imports` (REA evidence IDs `ev_f0e6dd1...`, `ev_f2d0dc1...`)
**Grau de confiança:** Confirmado para imports; ordem de execução é inferência, não observação.

### 2.2 Pacotes de Controle (CPacket_*@ControlSvc)

Identificados via RTTI no `RvControlSvc.exe`. Nenhum campo, tamanho ou função de
serialização observado.

| Nome | Identificador | Tamanho | Campos | Tipos | Ordem | Endianness | Função Serialização | Função Desserialização | Evidência | Confiança |
|---|---|---|---|---|---|---|---|---|---|---|
| `CPacket_Handshake_Syn` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string `?AVCPacket_Handshake_Syn@ControlSvc@@` | Nome confirmado; resto desconhecido |
| `CPacket_Handshake_SynAck` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_Handshake_Ack` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_KeepAlive` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_KeepAliveAck` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_Shutdown` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_RadminPort` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_RegionSupport` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_ProductVersion` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_Frame` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_ConfirmSwitch` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_StartSwitch` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_FinalizeSwitch` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_PacketFilter` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_Invalid` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket_Unknown` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `CPacket@ControlSvc@@` (base) | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |
| `IPacket@ControlSvc@@` (interface) | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI string | Nome confirmado; resto desconhecido |

**Observação:** Os nomes `Syn/SynAck/Ack` sugerem handshake tipo TCP, mas isso é inferência de nome, não evidência de comportamento.

---

## 3. Camada de Sessão e Dados — `RvROLClient.dll`

### 3.1 Exportações da API ROLClient (confirmadas)

| Export | Endereço (RVA) | Ordinal | Papel inferido | Confiança |
|---|---|---|---|---|
| `ROLClient_InitDll` | 0x10041010 | 19 | Inicialização da DLL | Confirmado (export table) |
| `ROLClient_ShutdownDll` | 0x10042540 | 43 | Encerramento | Confirmado |
| `ROLClient_Register` | 0x100419d0 | 28 | Registro de dispositivo | Confirmado |
| `ROLClient_Connect` | 0x10040670 | 6 | Conexão | Confirmado |
| `ROLClient_ContinueConnect` | 0x10040760 | 7 | Continuação de conexão | Confirmado |
| `ROLClient_Listen` | 0x10041380 | 21 | Escuta | Confirmado |
| `ROLClient_ListenVpn` | 0x10041470 | 22 | Escuta VPN | Confirmado |
| `ROLClient_Send` | 0x10041e70 | 34 | Envio de dados | Confirmado |
| `ROLClient_Receive` | 0x100418b0 | 27 | Recepção de dados | Confirmado |
| `ROLClient_WaitForSend` | 0x100425f0 | 44 | Aguardar envio | Confirmado |
| `ROLClient_ShutdownChannel` | 0x100423c0 | 41 | Encerrar canal | Confirmado |
| `ROLClient_JoinNetwork` | 0x100412a0 | 20 | Entrar em rede | Confirmado |
| `ROLClient_CancelJoin` | 0x10040430 | 3 | Cancelar entrada | Confirmado |
| `ROLClient_ManageNetwork` | 0x10041710 | 25 | Gerenciar rede | Confirmado |
| `ROLClient_ManageNetwork2` | 0x10041650 | 24 | Gerenciar rede v2 | Confirmado |
| `ROLClient_LeaveNetwork` | (não exportado) | — | Sair de rede | Inferido (string no ControlSvc) |
| `ROLClient_GetNodes` | 0x10040de0 | 16 | Obter nós | Confirmado |
| `ROLClient_GetNodeRegionSupport` | 0x10040d20 | 15 | Suporte de região | Confirmado |
| `ROLClient_EnumPublicNetworks` | 0x100409a0 | 10 | Enumera redes públicas | Confirmado |
| `ROLClient_ChatCommand` | 0x100404e0 | 4 | Comando chat | Confirmado |
| `ROLClient_ReportIpConflict` | 0x10041b30 | 30 | Reportar conflito IP | Confirmado |
| `ROLClient_ReportLanguage` | 0x10041bf0 | 31 | Reportar idioma | Confirmado |
| `ROLClient_ReportRServerInfo` | 0x10041cd0 | 32 | Reportar info servidor | Confirmado |
| `ROLClient_ReportSessionSummary` | 0x10041db0 | 33 | Resumo de sessão | Confirmado |
| `ROLClient_NeedMasterAddress` | 0x100417f0 | 26 | Endereço mestre | Confirmado |
| `ROLClient_SetMaxPacketSize` | 0x10042090 | 37 | Tamanho máximo pacote | Confirmado |
| `ROLClient_SetCompression` | 0x10041fd0 | 36 | Compressão | Confirmado |
| `ROLClient_SetPriority` | 0x10042150 | 38 | Prioridade | Confirmado |
| `ROLClient_SetVirtualAddresses` | 0x10042300 | 40 | Endereços virtuais | Confirmado |
| `ROLClient_SetChannelCounters` | 0x10041f10 | 35 | Contadores de canal | Confirmado |
| `ROLClient_DisableEncryption` | 0x10040830 | 8 | Desabilitar criptografia | Confirmado |
| `ROLClient_EnableModuleEvents` | 0x100408f0 | 9 | Eventos de módulo | Confirmado |
| `ROLClient_AllocMemory` | 0x100403c0 | 2 | Alocar memória | Confirmado |
| `ROLClient_FreeMemory` | 0x10040c00 | 13 | Liberar memória | Confirmado |
| `ROLClient_GetUnsendDataSize` | 0x10040eb0 | 17 | Tamanho dados não enviados | Confirmado |
| `ROLClient_InitConnector` | 0x10040f50 | 18 | Inicializar conector | Confirmado |
| `ROLClient_ShutdownConnector` | 0x10042480 | 42 | Encerrar conector | Confirmado |
| `ROLClient_FreeConnector` | 0x10040b40 | 12 | Liberar conector | Confirmado |
| `ROLClient_RejectConnect` | 0x10041ab0 | 29 | Rejeitar conexão | Confirmado |
| `ROLClient_WaitModuleEvent` | 0x100426a0 | 45 | Aguardar evento módulo | Confirmado |
| `ROLClient_WaitROLEvent` | 0x10042770 | 46 | Aguardar evento RO | Confirmado |
| `ROLClient_WaitThreads` | 0x100427d0 | 47 | Aguardar threads | Confirmado |
| `ROLClient_GetChannelProductVersion` | 0x10040c60 | 14 | Versão produto canal | Confirmado |

**Evidência:** `inspect_native_exports` (REA) — export table completa capturada.

### 3.2 Pacotes ROS (CRosPkt_*@RolClient)

Identificados via RTTI. Comunicação com servidor ROS (Radmin Online Server).

| Nome | Identificador | Tamanho | Campos | Tipos | Ordem | Endianness | Serialização | Desserialização | Evidência | Confiança |
|---|---|---|---|---|---|---|---|---|---|---|
| `CRosPktAttachOk` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI `?AVCRosPktAttachOk@RolClient@@` | Nome confirmado |
| `CRosPktCancelRedirect` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktChatCommandReply` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktChatEvents` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktChatNodes` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktClosestMaster` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktCollectTcpNatInfo` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktConnectAck` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktConnectFailed` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktError` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktHeartbeat` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktInstallRadminShim` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktInvalid` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktIsAlive` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktJoinApproved` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktJoinNetwork` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktLicInfo` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktLicManagmentReply` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktLoginComplete` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktManageNetReply` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktMessage` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktNetworksChanges` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktNetworks` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktNewConnection` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktNodeRegionSupport` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktNoRServer` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktPostpone` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktPublicNetworks` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktPushDirectEnet` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktPushEnet` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktPushInfo` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktRedirect` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktRegistered` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktRosAddr` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktStartEnet` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktTRSData` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPktUnknown` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosConnectionPacket` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRosPacket` / `IRosPacket` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI (interface) | Nome confirmado |
| `VCRosAddress` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `VCRosSessionId` | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |

### 3.3 Pacotes de Sessão e Mensagem (CMsg_* / CSession_*@RolClient)

| Nome | Identificador | Tamanho | Campos | Evidência | Confiança |
|---|---|---|---|---|---|
| `CMsgAuthFailed` | desconhecido | desconhecido | desconhecido | RTTI `?AVCMsgAuthFailed@RolClient@@` | Nome confirmado |
| `CMsgAuthFinished` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgConnectFailed` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgConnecting` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgConnectorClosed` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgConnectorFailed` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgDEnetAddresses` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgEnetAddress` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgIpAddresses` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgSessionStart` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgSessionStop` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CMsgShutdown` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CPrivateSessionMsg` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CSessionErrorMsg` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CSessionMsg` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CSessionSummaryPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |

### 3.4 Pacotes de Dados do Cliente (C*Packet@RolClient)

| Nome | Identificador | Tamanho | Campos | Evidência | Confiança |
|---|---|---|---|---|---|
| `CAbstractClnPacket` / `VIClnPacket` | desconhecido | desconhecido | desconhecido | RTTI (interface `VIClnPacket`, classe `CAbstractClnPacket`) | Nome confirmado |
| `CAbstractConnectionPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CCancelJoinPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CChatCommandPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CChatGetNodesPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CClientVersionInfo` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CConflictedIpAddressPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CConnectResultPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CDirectEnetInfoPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CEnetInfoPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CEnumPublicNetworksPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CGenericPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CGetNodeRegionSupportPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CGuiLanguagePacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CHeartbeatPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CIsAlivePacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CJoinNetworkPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CLoginPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CLogPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CManageNetworkPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CNatPenPackets` / `CNatPenStatusPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CPacketConnection` (FamRT) | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `CRequestTrsPacket` | desconhecido | desconhecido | desconhecido | RTTI | Nome confirmado |
| `ReplyPacket` (ControlSvc) | desconhecido | desconhecido | desconhecido | RTTI `?AV?$TAutoPtr@VCReplyPacket@ControlSvc@@` | Nome confirmado |

### 3.5 Estruturas Internas (não necessariamente transmitidas na rede)

| Nome | Papel inferido | Evidência | Confiança |
|---|---|---|---|
| `CCryptoChannel` | Canal criptografado | RTTI `?AVCCryptoChannel@RolClient@@` | Nome confirmado; algoritmo desconhecido |
| `CCryptoChannelNotificator` | Notificador de canal crypto | RTTI | Nome confirmado |
| `CPrivateSessionMsg` | Mensagem de sessão privada | RTTI | Nome confirmado |
| `CAuthSessionId` | ID de sessão de autenticação | RTTI `VCAuthSessionId@rol@@` | Nome confirmado |
| `VCUniqueConnectionId` | ID único de conexão | RTTI `VCUniqueConnectionId@2@` | Nome confirmado |
| `VCRid` | ID de nó/recurso | RTTI `VCRid@rol@@` | Nome confirmado |
| `VCNetWorker` | Trabalhador de rede | RTTI | Nome confirmado |
| `VCConnector` | Conector | RTTI | Nome confirmado |
| `VCConnection` | Conexão | RTTI | Nome confirmado |
| `CConnectionPool` | Pool de conexões | RTTI | Nome confirmado |
| `CEnetAbstractConnection` | Conexão abstrata Enet | RTTI `CEnetAbstractConnection@ENETConnect@@` | Nome confirmado |
| `CEnetIocpConnection` | Conexão IOCP Enet | RTTI | Nome confirmado |
| `CEnetScheduler` | Agendador Enet | RTTI | Nome confirmado |
| `CEnetWrapper` | Wrapper Enet | RTTI | Nome confirmado |
| `CENETConnector` | Conector Enet | RTTI `RolClient::CENETConnector` | Nome confirmado |
| `CEnetChannelNotificator` | Notificador de canal Enet | RTTI | Nome confirmado |
| `TMBufferQueueWithCode` (send/recv) | Filas de buffer com código | RTTI `TMBufferQueueWithCode@W4ESendCode@...` / `W4ERecvCode@...` | Nome confirmado |
| `CProxyAddressPool` | Pool de endereços proxy | RTTI | Nome confirmado |
| `CGenericAddressPool` | Pool genérico de endereços | RTTI | Nome confirmado |
| `CProxyAddressChecker` | Verificador de endereço proxy | RTTI | Nome confirmado |
| `CDEnetAddresses` | Endereços DEnet | RTTI | Nome confirmado |
| `USPortPara` | Parâmetros de porta | RTTI | Nome confirmado |
| `USNatPenPacket` | Pacote de penetração NAT | RTTI | Nome confirmado |
| `USNatPenWave` | Onda de penetração NAT | RTTI | Nome confirmado |
| `USPenGroup` | Grupo de penetração | RTTI | Nome confirmado |
| `USOneAck` | ACK único | RTTI | Nome confirmado |
| `CPenWaveSenderReceiver` | Enviador/recebedor de onda | RTTI | Nome confirmado |

---

## 4. Camada Criptográfica — `CCryptoChannel`

### 4.1 O que foi confirmado

- Classe `CCryptoChannel@RolClient@@` existe (RTTI).
- `ROLClient_SetCompression` (export, 0x10041fd0) e `ROLClient_DisableEncryption` (export, 0x10040830) existem — compressão e criptografia são configuráveis.
- `FamCurl` com `?g_DefaultCaCertPem` (CA PEM embutida) — usado para HTTPS/DoH.
- `CPrivateSessionMsg` — mensagens de sessão privada (possivelmente criptografadas).

### 4.2 O que é desconhecido

| Item | Status |
|---|---|
| Algoritmo de criptografia (AES, ChaCha20, RSA, ECC, etc.) | Desconhecido |
| Derivação de chaves | Desconhecido |
| Troca de chaves | Desconhecido |
| Modo de operação (CBC, GCM, etc.) | Desconhecido |
| Tamanho de chave | Desconhecido |
| IV/nonce | Desconhecido |
| Autenticação de mensagem (HMAC, AEAD) | Desconhecido |
| Proteção contra replay | Desconhecido |
| Estrutura dos registros criptográficos | Desconhecido |
| Função de serialização/desserialização criptográfica | Desconhecido |

**Evidência:** Strings RTTI e export table apenas. Nenhuma string de algoritmo (AES/RSA/SHA) identificável nos binários.

---

## 5. Driver de Rede — `NetMP60.sys`

### 5.1 O que foi confirmado

- Driver NDIS 6 miniport (PE32+, x86-64).
- Device: `\Device\RVPNNETMP` / `\DosDevices\RVPNNETMP`.
- PDB path: `S:\RadminVPN.driver.1.1\x64\RadminVPNRelease\RvNetMP60.pdb` (build path interno).
- Strings: `Current Address`, `Permanent Address` (endereços MAC).
- `IOCTL/start address` — interface de controle via IOCTL.
- Assinado por `Microsoft Windows Hardware Compatibility Publisher`.
- Usa NDIS APIs: `NdisAllocateNetBufferAndNetBufferList`, `NdisMIndicateReceiveNetBufferLists`, `NdisMRegisterMiniportDriver`, `NdisMSendNetBufferListsComplete`, `NdisOpenConfigurationEx`, `NdisReadNetworkAddress`, etc.
- Driver versions: `NetMP60_1_0` e `NetMP60_1_1` (do `.inf`).

### 5.2 O que é desconhecido

| Item | Status |
|---|---|
| Formato do quadro Ethernet (EtherType, payload) | Desconhecido |
| IOCTL codes específicos | Desconhecidos |
| Estrutura de pacotes entre driver e serviço | Desconhecida |
| MTU da interface virtual | Desconhecido |
| Faixa de IP atribuída | Desconhecida |
| Se é encapsulamento L2 puro ou IP dentro do driver | Desconhecido |

**Evidência:** Strings do `.sys`, imports NDIS, `.inf` (NCF_VIRTUAL, IF_TYPE_ETHERNET_CSMACD).

---

## 6. NAT Traversal — `RvUESClient.dll` + `RvROLClient.dll`

### 6.1 Confirmed

- `UESC_GetTcpNatType` (export, 0x10005a10) — detecção de tipo de NAT TCP.
- `UESC_GetAddress` (export, 0x10005910) — obtenção de endereço.
- `UESC_Init` / `UESC_Shutdown` — inicialização/encerro.
- Strings de log: `TcpNatChecker[%1].Bind/Connect/Recv/Send/Delta/InvalidAddress/InvalidResponce/DirectAddress/GetTcpNatType`.
- `CPenSocket`, `USNatPenPacket`, `USNatPenWave`, `USPenGroup`, `USOneAck`, `CPenWaveSenderReceiver` — estruturas de hole punching.
- `USPortPara` — parâmetros de porta.
- Tipos de conexão observados no serviço: UDP/direct, UDP/nat, UDP/nat/random, UDP/teredo, TCP/direct, TCP/nat, TCP/teredo, Connections Relay.

### 6.2 Desconhecido

| Item | Status |
|---|---|
| Algoritmo de detecção de NAT | Desconhecido |
| Estrutura dos pacotes de penetração | Desconhecido |
| Servidores STUN/TURN/relay | Desconhecidos |
| Portas utilizadas | Desconhecidas |
| Comportamento frente a NAT simétrico | Desconhecido |

---

## 7. DNS / Descoberta de Servidores

### 7.1 Confirmado

- String `https://%hs/dns-query` — DNS-over-HTTPS.
- Resolvers públicos hardcoded em `RvROLClient.dll`: 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 208.67.222.222, 208.67.220.220, 1.0.0.2, 1.0.0.3, 1.1.1.2, 1.1.1.3, 9.9.9.9–13, 130.59.31.248, 130.59.31.251, 223.5.5.5, 223.6.6.6.
- Nenhum IP de servidor Radmin hardcoded encontrado.
- `ROLClient_GetNodeRegionSupport` — suporte de região de nós.

### 7.2 Desconhecido

| Item | Status |
|---|---|
| Hostname do servidor ROS | Desconhecido |
| Endpoint DoH exato (além do padrão `https://%hs/dns-query`) | Desconhecido |
| Formato da requisição DoH | Desconhecido |
| Endereços de servidores relay | Desconhecidos |

---

## 8. Identidade e Autenticação

### 8.1 Confirmado

- `ROLClient_Register` — registro de dispositivo.
- `CAuthSessionId` — ID de sessão de autenticação (RTTI).
- `ROLClient_ReportLanguage`, `ROLClient_ReportRServerInfo` — reportes pós-autenticação.
- Registro Windows: `HKLM\SOFTWARE\Famatech\RadminVPN\1.0`.
- `CLoginPacket`, `CMsgAuthFailed`, `CMsgAuthFinished` — pacotes de login/auth.

### 8.2 Desconhecido

| Item | Status |
|---|---|
| Formato do identificador de dispositivo | Desconhecido |
| Fluxo de handshake de autenticação | Desconhecido |
| Credenciais (senha, token, certificado) | Desconhecidas |
| Validação de membros / autorização de rede | Desconhecida |

---

## 9. Descobertas da Captura de Tráfego (Fase 2 — Análise Dinâmica)

### 9.1 Setup de captura

- Interface: `virbr0` (Libvirt Bridge)
- VM IP: `192.168.122.77`
- Filtro: `host 192.168.122.77`
- Arquivo 1: `/tmp/radmin_vm.pcap` (~21 MB, ~6360 pacotes)
- Arquivo 2: `/tmp/radmin_vm2.pcap` (~196 KB, ~69 frames TCP para porta 17301)
- Sub-extração porta 17301: `/tmp/radmin_17301.pcap` (~30 KB, 3 fluxos TCP distintos)

### 9.2 Servidores e portas identificados

| Servidor IP | Porta | Protocolo | Papel inferido |
|---|---|---|---|
| `148.113.190.78` | 17301 | TCP | Servidor de controle/sinalização Radmin |
| `198.244.203.247` | 17301 | TCP | Servidor de controle/sinalização (fallback?) |
| `45.162.230.182` | 17351 | TCP | Servidor alternativo |
| Vários (Akamai) | 443 | TCP | CDN/HTTPS (possível DoH ou tráfego de fundo Windows) |

**Observação:** Toda a comunicação principal identificada como tráfego Radmin usa a porta **17301** (TCP). Outros servidores na porta 443 via Akamai podem ser DoH, atualizações ou tráfego de fundo do Windows — não confirmado como Radmin.

### 9.3 Formato do protocolo na porta 17301 (CONFIRMADO via captura)

**Cabeçalho:** 4 bytes, big-endian, `uint32_t` = tamanho do payload (não inclui os 4 bytes do cabeçalho).

| Exemplo | Tamanho declarado | Payload | Total no TCP |
|---|---|---|---|
| `00 00 00 20` | 32 | 32 bytes | 36 bytes |
| `00 00 00 90` | 144 | 144 bytes | 148 bytes |
| `00 00 01 00` | 256 | 256 bytes | 260 bytes |
| `00 00 01 30` | 304 | 304 bytes | 308 bytes |
| `00 00 01 60` | 352 | 352 bytes | 356 bytes |
| `00 00 00 c0` | 192 | 192 bytes | 196 bytes |
| `00 00 02 c0` | 704 | 704 bytes | 708 bytes |
| `00 00 0d 40` | 3392 | 3392 bytes | 3396 bytes |

**Sequência observada no handshake inicial:**
1. `00 00 00 20` + 32 bytes (cliente → servidor)
2. `00 00 00 20` + 32 bytes (servidor → cliente)
3. `00 00 00 90` + 144 bytes (servidor → cliente)
4. `00 00 01 60` + 352 bytes (cliente → servidor)
5. `00 00 01 00` + 256 bytes (servidor → cliente)
6. `00 00 01 30` + 304 bytes (cliente → servidor)
7. `00 00 00 60` + 96 bytes (servidor → cliente)
8. `00 00 00 70` + 112 bytes (cliente → servidor)
9. `00 00 00 04 03 00 00 00` — pacote de controle (8 bytes total)
10. Pacotes maiores (192, 704, 1960, 3392 bytes) — dados de sessão

**Campos dentro do payload:** **Desconhecidos** — requer decompilação para identificar estrutura interna.

**Endianness:** Big-endian (confirmado via `00 00 00 20` = 32).

### 9.4 Validação do parser com dados reais do PCAP

**Método de extração:**
1. Extraídos payloads TCP de cada fluxo separadamente usando `tshark -Y tcp.stream==N -T fields -e tcp.payload`
2. Convertidos de hex para binário via `xxd -r -p`
3. Cada fluxo foi validado individualmente com um script Python que replica a lógica do FrameParser

**Resultados por fluxo:**

| Fluxo | Bytes totais | Frames | Bytes consumidos | Restantes | Truncado? |
|---|---|---|---|---|---|
| Stream 0 (56923→148.113.190.78) | 11260 | 19 | 11260 | 0 | Não |
| Stream 1 (49493→198.244.203.247) | 5920 | 18 | 5920 | 0 | Não |
| Stream 2 (49494→148.113.190.78) | 5644 | 17 | 5644 | 0 | Não |
| **Total** | **22824** | **54** | **22824** | **0** | **Não** |

**Tamanhos de payload observados nos 54 frames:**
32, 32, 144, 352, 256, 304, 96, 112, 144, 352, 256, 304, 96, 128, 3968, 384, 3392, 704, 128, 4, 4, 192, 192, 4, 32, 256, 224, 4, 32, 224, 48, 256, 224, 48, 208, 2576, 160, 432, 224, 48, 384, 384, 48, 208, 160, 240, 2576, 160, 432, 224, 288, 384, 384, 160

**Confirmação:** Todos os 54 frames foram extraídos com sucesso. Cada fluxo TCP foi separado e validado individualmente. Nenhum byte ficou sem consumir. Nenhum frame truncado foi encontrado. Os fluxos não foram misturados.

### 9.5 O que é desconhecido

| Item | Status |
|---|---|
| Estrutura interna do payload (campos, tipos, ordem) | Desconhecido |
| Identificador de tipo de pacote | Desconhecido |
| Algoritmo de criptografia do payload | Desconhecido |
| Handshake de autenticação (campos específicos) | Desconhecido |
| Faixa de IP virtual atribuída pelo servidor | Desconhecido |
| Se há separação entre canal de controle e dados | Desconhecido |

### 9.6 Descobertas da Captura 2 (ações: conectar, msg chat, desconectar, reconectar)

Arquivo: `/tmp/radmin_vm2.pcap` (~196 KB)

| Tempo | Origem → Destino | Porta | Tamanho | Inferência |
|---|---|---|---|---|
| ~25.9s | 192.168.122.77 → 148.113.190.78 | 17301 | 148 | Conexão inicial (porta 56923) |
| ~26-39s | bidirecional | 17301 | 144, 1440, 36, 100, 180, 116, 68 | Handshake + dados de sessão |
| ~39-67s | bidirecional | 17301 | 36-180 | Tráfego periódico (keepalive/mensagens) |
| ~98-99s | 192.168.122.77 → 148.113.190.78 | 17301 | 0, 8, 196, 36, 260, 228 | **Reconexão** (nova porta 49526) |
| ~99s | cliente → servidor | 17301 | 8 | `00 00 00 04 03 00 00 00` (pacote de controle/ACK) |
| ~99s | servidor → cliente | 17301 | 8 | `00 00 00 04 03 00 00 00` (resposta de controle) |

**Pacote de controle identificado:** `00 00 00 04 03 00 00 00` — cabeçalho (tamanho=4) + 4 bytes de payload (`03 00 00 00`). Pode ser keepalive ou ACK de confirmação.

**Reconexão:** Nova conexão TCP na porta 49526 → 17301, sugerindo que o cliente reconecta após desconexão.

---

## 10. Limitações da Análise Estática

1. **Nenhum descompilador disponível** (Ghidra/IDA/Hopper não configurados neste host).
2. **Nenhuma captura de tráfego** (Wireshark não executado — requer VM Windows isolada).
3. **Nenhuma execução observada** (não há depuração, emulação ou replay).
4. **Offsets de campos, tamanhos, endianness, identificadores numéricos** não foram observados.
5. **Funções de serialização/desserialização** não foram identificadas (não há strings como "serialize" nos binários — são funções C++ compiladas sem símbolos de depuração).
6. **Algoritmos criptográficos** não identificados.

---

## 11. Próximos Passos Obrigatórios (em ordem)

1. Executar cliente Windows em VM isolada com Wireshark para capturar tráfego real.
2. Decompilar `RvROLClient.dll` e `RvControlSvc.exe` (Ghidra/IDA/Kuna) para extrair:
   - Estruturas binárias dos pacotes (offsets, tamanhos, tipos).
   - Funções de serialização/desserialização.
   - Algoritmos criptográficos.
   - Endereços e portas dos servidores ROS/relay.
3. Preencher todas as células marcadas `desconhecido` nesta especificação.
4. Somente então substituir `_raw: Vec<u8>` pelas estruturas Rust reais em `src/protocol/packets.rs`.

---

## 12. Critério de Conclusão da Fase 2

A fase estará concluída quando houver documentação suficiente para implementar o protocolo de controle e transporte de dados **sem depender de suposições**. Até lá, nenhum campo de pacote pode ser considerado confirmado.

**Não declarar compatibilidade até conseguir demonstrá-la com testes reais contra o cliente oficial Windows.**

---

## Evidence IDs (REA)

| Operação | Alvo | Evidence ID |
|---|---|---|
| `inspect_pe_imports` | `RvControlSvc.exe` | `ev_f0e6dd1ce5b574f86d6d41fcda0677f6e5f591a7386caeb0bd8aa8a9029c0af2` |
| `inspect_pe_imports` | `RvRvpnGui.exe` | `ev_f2d0dc1c21103795e69dcf1948227d529a1a9eff6a236323a5dd8be5c628b01c` |
| `inspect_pe_imports` | `RvROLClient.dll` | `ev_c45aa4d9309c7ee6a62cde6b1c11275995903eb391c46594f58b0b1940cfe4a0` |
| `inspect_pe_imports` | `RvUESClient.dll` | `ev_8fa3bd5ac9b1c89d529e7c83dcb3532ceb7a3d401f25e053a54877e178cdb03` |
| `inspect_pe_imports` | `imrsdk.dll` | `ev_f2aa613865e78903cb5c2f31840e9cda57b8c07954454c03263c90f51200547a` |
| `inspect_native_exports` | `RvROLClient.dll` | 47 exports capturados |
| `inspect_native_exports` | `RvUESClient.dll` | 6 exports capturados |
| `inspect_native_exports` | `imrsdk.dll` | 22 exports capturados |
| `inspect_pe_certificates` | `RvControlSvc.exe` | Cadeia DigiCert → Famatech Corp. |
| `open_binary` | Instalador `Radmin_VPN_2.1.4951.1.exe` | SHA-256 `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7` |
