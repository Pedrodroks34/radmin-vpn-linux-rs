# Radmin VPN Protocol Specification: Phase 2 (Reconstruction)

**Status:** PARTIAL SPECIFICATION, based on static analysis of binaries (reverse engineering) and real traffic capture (tshark, VM 192.168.122.77, interface virbr0). No decompilation was performed in this environment. For later Ghidra findings, see `CONTROL_PROTOCOL.md`.

**Rule:** No field, offset, size, endianness, numeric identifier, serialization function, or cryptographic algorithm has been directly observed unless marked as confirmed. Every value marked "unknown" must stay that way until dynamic analysis or decompilation settles it.

---

## 1. Protocol architecture overview

Radmin VPN has three distinct protocol layers, identified in the binaries:

```
┌─────────────────────────────────────────────────────────┐
│  RvRvpnGui.exe  (Qt/QML UI)                             │
└──────────────┬──────────────────────────────────────────┘
               │  named pipe: \\.\pipe\RadminVpnGuiChannel
               ▼
┌─────────────────────────────────────────────────────────┐
│  RvControlSvc.exe  (Windows service, FamRT/C++ engine)  │
│  ├── Control packets (CPacket_*): handshake,            │
│  │   keep-alive, shutdown, frame, switch, filter        │
│  ├── WS2_32 imports (WSARecv), WININET                  │
│  └── Calls ROLClient_* (connect, send, receive, etc.)   │
└──────────────┬──────────────────────────────────────────┘
               │  DeviceIoControl \\.\RVPNNETMP
               ▼
┌─────────────────────────────────────────────────────────┐
│  NetMP60.sys  (NDIS 6 miniport, \Device\RVPNNETMP)      │
│  ├── IOCTL start address                                │
│  ├── Current Address / Permanent Address (MAC)          │
│  └── Signed by Microsoft Windows HC                     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  RvROLClient.dll  (ROL client library)                  │
│  ├── ROS packets (CRosPkt_*): register, login, join,    │
│  │   heartbeat, networks, NAT, etc.                     │
│  ├── Session packets (CMsg_*, CSession_*): auth, IP,    │
│  │   Enet, shutdown, private session                    │
│  ├── Client data packets (C*Packet@RolClient):          │
│  │   login, join, manage, heartbeat, enet, etc.         │
│  ├── Structures: CCryptoChannel, CAuthSessionId,        │
│  │   VCUniqueConnectionId, VCRid, VCRosAddress,         │
│  │   VCRosSessionId, CEnetAbstractConnection,           │
│  │   TMBufferQueueWithCode (send/recv),                 │
│  │   CProxyAddressPool, CGenericAddressPool,            │
│  │   CDEnetAddresses, USPortPara, USNatPenPacket        │
│  └── 47 ROLClient_* exports                             │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Control layer: `RvControlSvc.exe`

### 2.1 Initialization flow (inferred from imports)

The service likely follows this sequence. The order is inferred from imports and was not observed at runtime:

1. `StartServiceCtrlDispatcherW` / `RegisterServiceCtrlHandlerExW` / `SetServiceStatus`: registers as a Windows service.
2. `CreateNamedPipeW` / `ConnectNamedPipe` / `DisconnectNamedPipe`: IPC with the GUI through `\\.\pipe\RadminVpnGuiChannel`.
3. `ROLClient_InitConnector` / `ROLClient_Connect` / `ROLClient_ContinueConnect`: initializes the ROL connector.
4. `ROLClient_ListenVpn`: listens for VPN traffic.
5. `ROLClient_Send` / `ROLClient_Receive` / `ROLClient_WaitForSend`: transport.
6. `CreateServiceW` / `DeleteService` / `ChangeServiceConfigW`: service management.
7. `DeviceIoControl`: communication with `NetMP60.sys` (`\\.\RVPNNETMP`).
8. `FwpmFilterAdd0` / `FwpmSubLayerAdd0` (fwpuclnt): WFP firewall rules.
9. `CreateIpNetEntry` / `DeleteIpForwardEntry2` (IPHLPAPI): routes and IP addresses.

**Evidence:** `inspect_pe_imports` (REA evidence IDs `ev_f0e6dd1...`, `ev_f2d0dc1...`).
**Confidence:** Confirmed for imports. The execution order is an inference, not an observation.

### 2.2 Control packets (`CPacket_*@ControlSvc`)

Identified via RTTI in `RvControlSvc.exe`. No field, size, or serialization function has been observed for any of them.

| Name | RTTI evidence | Status |
|---|---|---|
| `CPacket_Handshake_Syn` | `?AVCPacket_Handshake_Syn@ControlSvc@@` | Name confirmed |
| `CPacket_Handshake_SynAck` | RTTI | Name confirmed |
| `CPacket_Handshake_Ack` | RTTI | Name confirmed |
| `CPacket_KeepAlive` | RTTI | Name confirmed |
| `CPacket_KeepAliveAck` | RTTI | Name confirmed |
| `CPacket_Shutdown` | RTTI | Name confirmed |
| `CPacket_RadminPort` | RTTI | Name confirmed |
| `CPacket_RegionSupport` | RTTI | Name confirmed |
| `CPacket_ProductVersion` | RTTI | Name confirmed |
| `CPacket_Frame` | RTTI | Name confirmed |
| `CPacket_ConfirmSwitch` | RTTI | Name confirmed |
| `CPacket_StartSwitch` | RTTI | Name confirmed |
| `CPacket_FinalizeSwitch` | RTTI | Name confirmed |
| `CPacket_PacketFilter` | RTTI | Name confirmed |
| `CPacket_Invalid` | RTTI | Name confirmed |
| `CPacket_Unknown` | RTTI | Name confirmed |
| `CPacket@ControlSvc@@` (base) | RTTI | Name confirmed |
| `IPacket@ControlSvc@@` (interface) | RTTI | Name confirmed |

**Note:** The names `Syn`, `SynAck`, and `Ack` suggest a TCP-like handshake. This is inferred from the names, not from observed behavior.

---

## 3. Session and data layer: `RvROLClient.dll`

### 3.1 Confirmed ROLClient API exports

| Export | RVA | Ordinal | Inferred role | Confidence |
|---|---|---|---|---|
| `ROLClient_InitDll` | 0x10041010 | 19 | DLL initialization | Confirmed (export table) |
| `ROLClient_ShutdownDll` | 0x10042540 | 43 | Shutdown | Confirmed |
| `ROLClient_Register` | 0x100419d0 | 28 | Device registration | Confirmed |
| `ROLClient_Connect` | 0x10040670 | 6 | Connection | Confirmed |
| `ROLClient_ContinueConnect` | 0x10040760 | 7 | Continue connection | Confirmed |
| `ROLClient_Listen` | 0x10041380 | 21 | Listen | Confirmed |
| `ROLClient_ListenVpn` | 0x10041470 | 22 | Listen for VPN | Confirmed |
| `ROLClient_Send` | 0x10041e70 | 34 | Send data | Confirmed |
| `ROLClient_Receive` | 0x100418b0 | 27 | Receive data | Confirmed |
| `ROLClient_WaitForSend` | 0x100425f0 | 44 | Wait for send | Confirmed |
| `ROLClient_ShutdownChannel` | 0x100423c0 | 41 | Close channel | Confirmed |
| `ROLClient_JoinNetwork` | 0x100412a0 | 20 | Join network | Confirmed |
| `ROLClient_CancelJoin` | 0x10040430 | 3 | Cancel join | Confirmed |
| `ROLClient_ManageNetwork` | 0x10041710 | 25 | Manage network | Confirmed |
| `ROLClient_ManageNetwork2` | 0x10041650 | 24 | Manage network (v2) | Confirmed |
| `ROLClient_LeaveNetwork` | (not exported) | none | Leave network | Inferred (string in ControlSvc) |
| `ROLClient_GetNodes` | 0x10040de0 | 16 | Get nodes | Confirmed |
| `ROLClient_GetNodeRegionSupport` | 0x10040d20 | 15 | Region support | Confirmed |
| `ROLClient_EnumPublicNetworks` | 0x100409a0 | 10 | Enumerate public networks | Confirmed |
| `ROLClient_ChatCommand` | 0x100404e0 | 4 | Chat command | Confirmed |
| `ROLClient_ReportIpConflict` | 0x10041b30 | 30 | Report IP conflict | Confirmed |
| `ROLClient_ReportLanguage` | 0x10041bf0 | 31 | Report language | Confirmed |
| `ROLClient_ReportRServerInfo` | 0x10041cd0 | 32 | Report server info | Confirmed |
| `ROLClient_ReportSessionSummary` | 0x10041db0 | 33 | Session summary | Confirmed |
| `ROLClient_NeedMasterAddress` | 0x100417f0 | 26 | Master address | Confirmed |
| `ROLClient_SetMaxPacketSize` | 0x10042090 | 37 | Max packet size | Confirmed |
| `ROLClient_SetCompression` | 0x10041fd0 | 36 | Compression | Confirmed |
| `ROLClient_SetPriority` | 0x10042150 | 38 | Priority | Confirmed |
| `ROLClient_SetVirtualAddresses` | 0x10042300 | 40 | Virtual addresses | Confirmed |
| `ROLClient_SetChannelCounters` | 0x10041f10 | 35 | Channel counters | Confirmed |
| `ROLClient_DisableEncryption` | 0x10040830 | 8 | Disable encryption | Confirmed |
| `ROLClient_EnableModuleEvents` | 0x100408f0 | 9 | Module events | Confirmed |
| `ROLClient_AllocMemory` | 0x100403c0 | 2 | Allocate memory | Confirmed |
| `ROLClient_FreeMemory` | 0x10040c00 | 13 | Free memory | Confirmed |
| `ROLClient_GetUnsendDataSize` | 0x10040eb0 | 17 | Unsent data size | Confirmed |
| `ROLClient_InitConnector` | 0x10040f50 | 18 | Initialize connector | Confirmed |
| `ROLClient_ShutdownConnector` | 0x10042480 | 42 | Shut down connector | Confirmed |
| `ROLClient_FreeConnector` | 0x10040b40 | 12 | Free connector | Confirmed |
| `ROLClient_RejectConnect` | 0x10041ab0 | 29 | Reject connection | Confirmed |
| `ROLClient_WaitModuleEvent` | 0x100426a0 | 45 | Wait for module event | Confirmed |
| `ROLClient_WaitROLEvent` | 0x10042770 | 46 | Wait for ROL event | Confirmed |
| `ROLClient_WaitThreads` | 0x100427d0 | 47 | Wait for threads | Confirmed |
| `ROLClient_GetChannelProductVersion` | 0x10040c60 | 14 | Channel product version | Confirmed |

**Evidence:** `inspect_native_exports` (REA). Full export table captured.

### 3.2 ROS packets (`CRosPkt_*@RolClient`)

Identified via RTTI. Used to communicate with the ROS server (Radmin Online Server). Names only; no structure is known.

- Attach and redirect: `CRosPktAttachOk`, `CRosPktCancelRedirect`, `CRosPktRedirect`, `CRosPktClosestMaster`, `CRosPktNoRServer`.
- Chat: `CRosPktChatCommandReply`, `CRosPktChatEvents`, `CRosPktChatNodes`, `CRosPktMessage`.
- Connection: `CRosPktConnectAck`, `CRosPktConnectFailed`, `CRosPktNewConnection`, `CRosPktPostpone`.
- Errors and invalid: `CRosPktError`, `CRosPktInvalid`, `CRosPktUnknown`.
- Liveness: `CRosPktHeartbeat`, `CRosPktIsAlive`.
- Network membership: `CRosPktJoinApproved`, `CRosPktJoinNetwork`, `CRosPktManageNetReply`, `CRosPktNetworks`, `CRosPktNetworksChanges`, `CRosPktPublicNetworks`, `CRosPktRegistered`, `CRosPktLoginComplete`.
- Licensing: `CRosPktLicInfo`, `CRosPktLicManagmentReply`.
- Enet and push: `CRosPktPushDirectEnet`, `CRosPktPushEnet`, `CRosPktPushInfo`, `CRosPktStartEnet`.
- Address and region: `CRosPktRosAddr`, `CRosPktNodeRegionSupport`.
- NAT and tunnels: `CRosPktCollectTcpNatInfo`, `CRosPktTRSData`, `CRosPktInstallRadminShim`.
- Base types: `CRosPacket`, `IRosPacket`, `CRosConnectionPacket`, `VCRosAddress`, `VCRosSessionId`.

### 3.3 Session and message packets (`CMsg_*` / `CSession_*@RolClient`)

Names only, confirmed by RTTI.

- Authentication: `CMsgAuthFailed`, `CMsgAuthFinished`.
- Connector: `CMsgConnectFailed`, `CMsgConnecting`, `CMsgConnectorClosed`, `CMsgConnectorFailed`.
- Addresses: `CMsgDEnetAddresses`, `CMsgEnetAddress`, `CMsgIpAddresses`.
- Session: `CMsgSessionStart`, `CMsgSessionStop`, `CMsgShutdown`, `CSessionMsg`, `CSessionErrorMsg`, `CSessionSummaryPacket`, `CPrivateSessionMsg`.

### 3.4 Client data packets (`C*Packet@RolClient`)

Names only, confirmed by RTTI.

- Base types: `CAbstractClnPacket` / `VIClnPacket`, `CAbstractConnectionPacket`, `CGenericPacket`.
- Join and manage: `CCancelJoinPacket`, `CJoinNetworkPacket`, `CManageNetworkPacket`, `CEnumPublicNetworksPacket`.
- Login and status: `CLoginPacket`, `CIsAlivePacket`, `CHeartbeatPacket`, `CLogPacket`, `CClientVersionInfo`, `CGuiLanguagePacket`.
- Chat: `CChatCommandPacket`, `CChatGetNodesPacket`.
- Enet and connection: `CConnectResultPacket`, `CDirectEnetInfoPacket`, `CEnetInfoPacket`, `CConflictedIpAddressPacket`, `CGetNodeRegionSupportPacket`.
- NAT and TRS: `CNatPenPackets`, `CNatPenStatusPacket`, `CRequestTrsPacket`.
- Service: `CPacketConnection` (FamRT), `ReplyPacket` (ControlSvc, RTTI `?AV?$TAutoPtr@VCReplyPacket@ControlSvc@@`).

### 3.5 Internal structures (not necessarily sent over the network)

| Name | Inferred role | Evidence | Status |
|---|---|---|---|
| `CCryptoChannel` | Encrypted channel | RTTI `?AVCCryptoChannel@RolClient@@` | Name confirmed; algorithm unknown here (see §4 and `CONTROL_PROTOCOL.md` §6) |
| `CCryptoChannelNotificator` | Crypto channel notifier | RTTI | Name confirmed |
| `CAuthSessionId` | Authentication session ID | RTTI `VCAuthSessionId@rol@@` | Name confirmed |
| `VCUniqueConnectionId` | Unique connection ID | RTTI `VCUniqueConnectionId@2@` | Name confirmed |
| `VCRid` | Node or resource ID | RTTI `VCRid@rol@@` | Name confirmed |
| `VCNetWorker` | Network worker | RTTI | Name confirmed |
| `VCConnector` | Connector | RTTI | Name confirmed |
| `VCConnection` | Connection | RTTI | Name confirmed |
| `CConnectionPool` | Connection pool | RTTI | Name confirmed |
| `CEnetAbstractConnection` | Abstract Enet connection | RTTI `CEnetAbstractConnection@ENETConnect@@` | Name confirmed |
| `CEnetIocpConnection` | IOCP Enet connection | RTTI | Name confirmed |
| `CEnetScheduler` | Enet scheduler | RTTI | Name confirmed |
| `CEnetWrapper` | Enet wrapper | RTTI | Name confirmed |
| `CENETConnector` | Enet connector | RTTI `RolClient::CENETConnector` | Name confirmed |
| `CEnetChannelNotificator` | Enet channel notifier | RTTI | Name confirmed |
| `TMBufferQueueWithCode` (send and receive) | Coded buffer queues | RTTI `TMBufferQueueWithCode@W4ESendCode@...` / `W4ERecvCode@...` | Name confirmed |
| `CProxyAddressPool` | Proxy address pool | RTTI | Name confirmed |
| `CGenericAddressPool` | Generic address pool | RTTI | Name confirmed |
| `CProxyAddressChecker` | Proxy address checker | RTTI | Name confirmed |
| `CDEnetAddresses` | DEnet addresses | RTTI | Name confirmed |
| `USPortPara` | Port parameters | RTTI | Name confirmed |
| `USNatPenPacket` | NAT penetration packet | RTTI | Name confirmed |
| `USNatPenWave` | NAT penetration wave | RTTI | Name confirmed |
| `USPenGroup` | Penetration group | RTTI | Name confirmed |
| `USOneAck` | Single ACK | RTTI | Name confirmed |
| `CPenWaveSenderReceiver` | Wave sender and receiver | RTTI | Name confirmed |

---

## 4. Cryptographic layer: `CCryptoChannel`

### 4.1 Confirmed at this stage

- Class `CCryptoChannel@RolClient@@` exists (RTTI).
- `ROLClient_SetCompression` (export, 0x10041fd0) and `ROLClient_DisableEncryption` (export, 0x10040830) exist, so compression and encryption are configurable.
- `FamCurl` with `?g_DefaultCaCertPem` (embedded CA PEM), used for HTTPS and DoH.
- `CPrivateSessionMsg`: private session messages, possibly encrypted.

### 4.2 Status of the algorithm

**To reconcile:** an earlier version of this section listed the algorithm as unknown. Later static analysis of `shelper.dll` (see `CONTROL_PROTOCOL.md` §6) identifies AES-256-CBC and RSA key exchange in the code. That evidence is static, from the code and RTTI, and has **not** been observed in traffic. Until the traffic is decrypted or the code paths are verified dynamically, treat the items below as unknown in this document.

| Item | Status here |
|---|---|
| Encryption algorithm | Unknown here. Static candidate in `CONTROL_PROTOCOL.md`. |
| Key derivation | Unknown |
| Key exchange | Unknown here. Static candidate in `CONTROL_PROTOCOL.md`. |
| Mode of operation | Unknown here. Static candidate in `CONTROL_PROTOCOL.md`. |
| Key size | Unknown here. Static candidate in `CONTROL_PROTOCOL.md`. |
| IV or nonce | Unknown |
| Message authentication (HMAC, AEAD) | Unknown |
| Replay protection | Unknown |
| Cryptographic record format | Unknown |
| Cryptographic serialization functions | Unknown |

**Evidence in this document:** RTTI strings and the export table. No identifiable algorithm string (AES, RSA, SHA) was found in these binaries at this stage.

---

## 5. Network driver: `NetMP60.sys`

### 5.1 Confirmed

- NDIS 6 miniport driver (PE32+, x86-64).
- Device: `\Device\RVPNNETMP` / `\DosDevices\RVPNNETMP`.
- PDB path: `S:\RadminVPN.driver.1.1\x64\RadminVPNRelease\RvNetMP60.pdb` (internal build path).
- Strings: `Current Address` and `Permanent Address` (MAC addresses).
- `IOCTL/start address`: control interface through IOCTL.
- Signed by `Microsoft Windows Hardware Compatibility Publisher`.
- Uses NDIS APIs such as `NdisAllocateNetBufferAndNetBufferList`, `NdisMIndicateReceiveNetBufferLists`, `NdisMRegisterMiniportDriver`, `NdisMSendNetBufferListsComplete`, `NdisOpenConfigurationEx`, and `NdisReadNetworkAddress`.
- Driver versions: `NetMP60_1_0` and `NetMP60_1_1` (from the `.inf`).

### 5.2 Unknown

- Ethernet frame format (EtherType, payload).
- Specific IOCTL codes.
- Packet structure between the driver and the service.
- MTU of the virtual interface.
- Assigned IP range.
- Whether it is pure L2 encapsulation or IP inside the driver.

**Evidence:** `.sys` strings, NDIS imports, and the `.inf` (`NCF_VIRTUAL`, `IF_TYPE_ETHERNET_CSMACD`).

---

## 6. NAT traversal: `RvUESClient.dll` and `RvROLClient.dll`

### 6.1 Confirmed

- `UESC_GetTcpNatType` (export, 0x10005a10): TCP NAT type detection.
- `UESC_GetAddress` (export, 0x10005910): address discovery.
- `UESC_Init` and `UESC_Shutdown`: initialization and shutdown.
- Log strings: `TcpNatChecker[%1].Bind/Connect/Recv/Send/Delta/InvalidAddress/InvalidResponce/DirectAddress/GetTcpNatType`.
- Hole punching structures: `CPenSocket`, `USNatPenPacket`, `USNatPenWave`, `USPenGroup`, `USOneAck`, `CPenWaveSenderReceiver`.
- `USPortPara`: port parameters.
- Connection types seen in the service: UDP/direct, UDP/nat, UDP/nat/random, UDP/teredo, TCP/direct, TCP/nat, TCP/teredo, Connections Relay.

### 6.2 Unknown

- NAT detection algorithm.
- Hole punching packet structure.
- STUN, TURN, or relay servers.
- Ports used.
- Behavior with symmetric NAT.

---

## 7. DNS and server discovery

### 7.1 Confirmed

- String `https://%hs/dns-query`: DNS over HTTPS.
- Public resolvers hardcoded in `RvROLClient.dll`: 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 208.67.222.222, 208.67.220.220, 1.0.0.2, 1.0.0.3, 1.1.1.2, 1.1.1.3, 9.9.9.9 through 9.9.9.13, 130.59.31.248, 130.59.31.251, 223.5.5.5, 223.6.6.6.
- No Radmin server IP is hardcoded.
- `ROLClient_GetNodeRegionSupport`: region support for nodes.

### 7.2 Unknown

- ROS server hostname.
- Exact DoH endpoint beyond the `https://%hs/dns-query` pattern.
- DoH request format.
- Relay server addresses.

---

## 8. Identity and authentication

### 8.1 Confirmed

- `ROLClient_Register`: device registration.
- `CAuthSessionId`: authentication session ID (RTTI).
- `ROLClient_ReportLanguage` and `ROLClient_ReportRServerInfo`: reports after authentication.
- Windows registry key: `HKLM\SOFTWARE\Famatech\RadminVPN\1.0`.
- `CLoginPacket`, `CMsgAuthFailed`, `CMsgAuthFinished`: login and authentication packets.

### 8.2 Unknown

- Device identifier format.
- Authentication handshake flow.
- Credentials (password, token, or certificate).
- Member validation and network authorization.

---

## 9. Traffic capture findings (phase 2, dynamic analysis)

### 9.1 Capture setup

- Interface: `virbr0` (libvirt bridge).
- VM IP: `192.168.122.77`.
- Filter: `host 192.168.122.77`.
- File 1: `/tmp/radmin_vm.pcap` (about 21 MB, about 6,360 packets).
- File 2: `/tmp/radmin_vm2.pcap` (about 196 KB, about 69 TCP frames to port 17301).
- Port 17301 extract: `/tmp/radmin_17301.pcap` (about 30 KB, 3 distinct TCP flows).

### 9.2 Servers and ports observed

| Server IP | Port | Protocol | Inferred role |
|---|---|---|---|
| `148.113.190.78` | 17301 | TCP | Radmin control and signaling server |
| `198.244.203.247` | 17301 | TCP | Control and signaling server (fallback?) |
| `45.162.230.182` | 17351 | TCP | Alternate server. **To reconcile:** `CONTROL_PROTOCOL.md` lists 17351 as peer-to-peer. |
| Several (Akamai) | 443 | TCP | CDN and HTTPS. Possibly DoH or background Windows traffic. Not confirmed as Radmin. |

**Note:** All main traffic identified as Radmin uses **TCP 17301**. Other servers on port 443 through Akamai may be DoH, updates, or background Windows traffic, which is not confirmed as Radmin.

### 9.3 Protocol format on port 17301 (confirmed by capture)

**Header:** 4 bytes, big-endian `uint32_t` containing the payload size. The header is not included in the size.

| Example header | Declared size | Payload | Total on TCP |
|---|---|---|---|
| `00 00 00 20` | 32 | 32 bytes | 36 bytes |
| `00 00 00 90` | 144 | 144 bytes | 148 bytes |
| `00 00 01 00` | 256 | 256 bytes | 260 bytes |
| `00 00 01 30` | 304 | 304 bytes | 308 bytes |
| `00 00 01 60` | 352 | 352 bytes | 356 bytes |
| `00 00 00 c0` | 192 | 192 bytes | 196 bytes |
| `00 00 02 c0` | 704 | 704 bytes | 708 bytes |
| `00 00 0d 40` | 3,392 | 3,392 bytes | 3,396 bytes |

**Initial handshake sequence observed:**

1. `00 00 00 20` + 32 bytes (client to server)
2. `00 00 00 20` + 32 bytes (server to client)
3. `00 00 00 90` + 144 bytes (server to client)
4. `00 00 01 60` + 352 bytes (client to server)
5. `00 00 01 00` + 256 bytes (server to client)
6. `00 00 01 30` + 304 bytes (client to server)
7. `00 00 00 60` + 96 bytes (server to client)
8. `00 00 00 70` + 112 bytes (client to server)
9. `00 00 00 04 03 00 00 00`: control packet (8 bytes total)
10. Larger packets (192, 704, 1,960, 3,392 bytes): session data

**Fields inside the payload:** **Unknown.** Decompilation is required to identify the internal structure.

**Endianness:** big-endian (confirmed by `00 00 00 20` = 32).

### 9.4 Parser validation with real PCAP data

**Method:**

1. Extract TCP payloads from each flow with `tshark -Y tcp.stream==N -T fields -e tcp.payload`.
2. Convert hex to binary with `xxd -r -p`.
3. Validate each flow with a Python script that replicates the `FrameParser` logic.

**Results per flow:**

| Flow | Total bytes | Frames | Bytes consumed | Remaining | Truncated? |
|---|---|---|---|---|---|
| Stream 0 (56923 to 148.113.190.78) | 11,260 | 19 | 11,260 | 0 | No |
| Stream 1 (49493 to 198.244.203.247) | 5,920 | 18 | 5,920 | 0 | No |
| Stream 2 (49494 to 148.113.190.78) | 5,644 | 17 | 5,644 | 0 | No |
| **Total** | **22,824** | **54** | **22,824** | **0** | **No** |

**Payload sizes observed across the 54 frames:**
32, 32, 144, 352, 256, 304, 96, 112, 144, 352, 256, 304, 96, 128, 3968, 384, 3392, 704, 128, 4, 4, 192, 192, 4, 32, 256, 224, 4, 32, 224, 48, 256, 224, 48, 208, 2576, 160, 432, 224, 48, 384, 384, 48, 208, 160, 240, 2576, 160, 432, 224, 288, 384, 384, 160

**Result:** All 54 frames were extracted. Each TCP flow was separated and validated on its own. No bytes were left unconsumed, no truncated frame was found, and the flows were not mixed.

### 9.5 Unknown

- Internal payload structure (fields, types, order).
- Packet type identifier.
- Payload encryption algorithm.
- Authentication handshake fields.
- Virtual IP range assigned by the server.
- Whether control and data channels are separate.

### 9.6 Findings from capture 2 (actions: connect, chat message, disconnect, reconnect)

File: `/tmp/radmin_vm2.pcap` (about 196 KB).

| Time | Direction | Port | Size | Inference |
|---|---|---|---|---|
| ~25.9 s | 192.168.122.77 to 148.113.190.78 | 17301 | 148 | Initial connection (source port 56923) |
| ~26 to 39 s | both | 17301 | 144, 1440, 36, 100, 180, 116, 68 | Handshake and session data |
| ~39 to 67 s | both | 17301 | 36 to 180 | Periodic traffic (keep-alive or messages) |
| ~98 to 99 s | 192.168.122.77 to 148.113.190.78 | 17301 | 0, 8, 196, 36, 260, 228 | **Reconnection** (new source port 49526) |
| ~99 s | client to server | 17301 | 8 | `00 00 00 04 03 00 00 00` (control or ACK) |
| ~99 s | server to client | 17301 | 8 | `00 00 00 04 03 00 00 00` (control response) |

**Control packet:** `00 00 00 04 03 00 00 00`: header (size 4) plus 4 payload bytes (`03 00 00 00`). It may be a keep-alive or an acknowledgment.

**Reconnection:** A new TCP connection from port 49526 to 17301, which suggests the client reconnects after a disconnect.

**To verify:** `REVERSE_ENGINEERING.md` says reconnection happened about 30 seconds after the first connection. The times in this table (about 25.9 s and about 98 s) give about 72 seconds between the first connection and the reconnection. Check these against the raw capture.

---

## 10. Limitations of static analysis

1. No decompiler (Ghidra, IDA, Hopper) was configured on this host.
2. No traffic capture was performed on a Windows VM. Wireshark ran only on the Linux host.
3. No execution was observed (no debugging, emulation, or replay).
4. Field offsets, sizes, endianness, and numeric identifiers have not been observed.
5. Serialization and deserialization functions were not identified. The binaries contain no strings such as "serialize", since these are compiled C++ functions without debug symbols.
6. Cryptographic algorithms were not identified at this stage. See `CONTROL_PROTOCOL.md` for later findings.

---

## 11. Required next steps (in order)

1. Run the Windows client in an isolated VM with Wireshark to capture real traffic.
2. Decompile `RvROLClient.dll` and `RvControlSvc.exe` (Ghidra, IDA, or Kuna) to extract:
   - Binary packet structures (offsets, sizes, types).
   - Serialization and deserialization functions.
   - Cryptographic algorithms.
   - Addresses and ports of the ROS and relay servers.
3. Fill in every cell marked "unknown" in this specification.
4. Only then replace `_raw: Vec<u8>` with real Rust structures in `src/protocol/packets.rs`.

---

## 12. Completion criteria for phase 2

Phase 2 is complete when there is enough documentation to implement the control and data transport protocols **without relying on assumptions**. Until then, no packet field may be considered confirmed.

**Do not declare compatibility until it has been demonstrated with real tests against the official Windows client.**

---

## Evidence IDs (REA)

| Operation | Target | Evidence ID |
|---|---|---|
| `inspect_pe_imports` | `RvControlSvc.exe` | `ev_f0e6dd1ce5b574f86d6d41fcda0677f6e5f591a7386caeb0bd8aa8a9029c0af2` |
| `inspect_pe_imports` | `RvRvpnGui.exe` | `ev_f2d0dc1c21103795e69dcf1948227d529a1a9eff6a236323a5dd8be5c628b01c` |
| `inspect_pe_imports` | `RvROLClient.dll` | `ev_c45aa4d9309c7ee6a62cde6b1c11275995903eb391c46594f58b0b1940cfe4a0` |
| `inspect_pe_imports` | `RvUESClient.dll` | `ev_8fa3bd5ac9b1c89d529e7c83dcb3532ceb7a3d401f25e053a54877e178cdb03` |
| `inspect_pe_imports` | `imrsdk.dll` | `ev_f2aa613865e78903cb5c2f31840e9cda57b8c07954454c03263c90f51200547a` |
| `inspect_native_exports` | `RvROLClient.dll` | 47 exports captured |
| `inspect_native_exports` | `RvUESClient.dll` | 6 exports captured |
| `inspect_native_exports` | `imrsdk.dll` | 22 exports captured |
| `inspect_pe_certificates` | `RvControlSvc.exe` | Certificate chain DigiCert to Famatech Corp. |
| `open_binary` | Installer `Radmin_VPN_2.1.4951.1.exe` | SHA-256 `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7` |
