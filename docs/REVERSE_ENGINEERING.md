# Reverse Engineering Report: Radmin VPN 2.1.4951.1

## Executive summary

The installer `Radmin_VPN_2.1.4951.1.exe` (54.3 MB, Inno Setup with a nested MSI) contains:

- `RvRvpnGui.exe`: GUI, Qt 5.15 / QML.
- `RvControlSvc.exe`: Windows service, FamRT/C++ engine with IOCP.
- `RvROLClient.dll`: ROL client (47 exports: connect, register, join network, send, receive, NAT, and others).
- `RvUESClient.dll`: NAT type detection.
- `NetMP60.sys`: virtual NDIS driver (`\\Device\\RVPNNETMP`, L2 Ethernet).
- Legacy Radmin Server 3 components (`Radmin.exe`, `rchatx.dll`, `voicex.dll`, and others).

## Architecture (confirmed by reverse engineering)

```
GUI (Qt) ── named pipe \\.\pipe\RadminVpnGuiChannel ──> Service RvControlSvc.exe
                                                        │
                          ├─ RvROLClient.dll ─────────► ROS (signaling server)
                          ├─ RvUESClient.dll ──────────► NAT type detection
                          ├─ WFP (fwpuclnt) ───────────► Firewall rules
                          ├─ IPHLPAPI ─────────────────► Routes and IP config
                          └─ DeviceIoControl ──────────► NetMP60.sys (virtual L2 adapter)
```

## Components and roles

See `README.md`.

## Packet types identified via RTTI (RvROLClient.dll)

The following packet types were extracted from the C++ class names in the binaries (strings like `?AV*Packet@RolClient@@`). Their binary structures are **unknown**.

| Packet | Inferred role |
|---|---|
| `CAbstractClnPacket` / `VIClnPacket` | Abstract client packet / interface |
| `CAbstractConnectionPacket` | Abstract connection packet |
| `CCancelJoinPacket` | Cancel joining a network |
| `CChatCommandPacket` | Chat command |
| `CChatGetNodesPacket` | Get nodes via chat |
| `CClientVersionInfo` | Client version information |
| `CConflictedIpAddressPacket` | IP conflict detection |
| `CConnectResultPacket` | Connection result |
| `CDirectEnetInfoPacket` | Direct Enet network info |
| `CEnetInfoPacket` | Enet network info |
| `CEnumPublicNetworksPacket` | Enumerate public networks |
| `CGenericPacket` | Generic packet |
| `CGetNodeRegionSupportPacket` | Node region support |
| `CGuiLanguagePacket` | GUI language |
| `CHeartbeatPacket` | Heartbeat / keep-alive |
| `CIsAlivePacket` | Liveness check |
| `CJoinNetworkPacket` | Join a virtual network |
| `CLoginPacket` | Login / authentication |
| `CLogPacket` | Log packet |
| `CManageNetworkPacket` | Manage a virtual network |
| `CMsgAuthFailed` | Authentication failed |
| `CMsgAuthFinished` | Authentication finished |
| `CMsgBadServerPacket` | Bad or invalid server |
| `CMsgNetPacket` | Network packet |
| `CMsgRosIgnored` | ROS message ignored |
| `CNatPenPackets` / `CNatPenStatusPacket` | NAT penetration packets |
| `CPacketConnection` (FamRT) | Packet connection |
| `CRequestTrsPacket` | TRS request |
| `CRosConnectionPacket` | ROS connection |
| `CRosPacket` / `IRosPacket` | ROS packet (interface) |
| `CRosPktChatCommandReply` | ROS chat command reply |
| `CRosPktCollectTcpNatInfo` | Collect TCP NAT info |
| `CRosPktLicInfo` | License info |
| `CRosPktPushInfo` | Info push (notification) |
| `CRServerInfoPacket` | R server info |
| `CSessionSummaryPacket` | Session summary |
| `CStartEnetPacket` | Start Enet |
| `CTcpInfoPacket` | TCP info |
| `CTcpNatInfoPacket` | TCP NAT info |
| `ReplyPacket` (ControlSvc) | Service reply packet |

Supporting classes identified: `CPenSocket`, `USNatPenPacket`, `USNatPenWave`, `USPenGroup`, `USPortPara`, `CAuthSessionId`, `CRosAddress`, `CRosSessionId`, `CCryptoChannel`, `VCRosSessionId`, `VCConnector`, `VCConnection`, `CConnectionPool`, `CEnetScheduler`, `CChatRegionSupportCache`, `CNodeMapEntry`, `CVNetWorker`, `CConContainer`, `NTcpConnect`, `NTrsConnect`, `ENETConnect`.

## Classification of findings

| Item | Status | Basis |
|---|---|---|
| Inno Setup + MSI installer | Confirmed | PE resources, strings |
| Windows service + named pipe | Confirmed | Imports and strings |
| Qt 5.15 / QML GUI | Confirmed | Qt5* imports |
| Virtual L2 NDIS driver | Confirmed | `.inf` and `.sys` strings |
| DNS-over-HTTPS and public resolvers | Confirmed | String `https://%hs/dns-query` and hardcoded IPs |
| ROS servers not hardcoded | Confirmed | No server IP found in the binaries |
| Encrypted channels and compression | Confirmed to exist | Exports `SetCompression`, `DisableEncryption` |
| NAT traversal (hole punching) | Confirmed to exist | Classes `CPenSocket`, `USNatPenPacket`, and others |
| ROS packet types | Confirmed by name | RTTI strings `?AV*Packet@RolClient@@` |
| Binary structure of packets | Unknown | Requires dynamic analysis |
| Encryption algorithms | Unknown here | No identifiable strings in this document. See `CONTROL_PROTOCOL.md` for later static findings. |
| Network ports | Unknown here | No fixed port found in this document. See `PROTOCOL_SPEC.md` for captured ports. |
| Authentication handshake | Unknown | Requires dynamic analysis |

## Traffic findings (Wireshark capture)

### Capture setup

- Interface: `virbr0` (libvirt bridge).
- VM IP: `192.168.122.77`.
- File 1: `/tmp/radmin_vm.pcap` (about 21 MB, about 6,360 packets).
- File 2: `/tmp/radmin_vm2.pcap` (about 196 KB, about 69 TCP frames to port 17301).
- Port 17301 extract: `/tmp/radmin_17301.pcap` (about 30 KB, 3 distinct TCP flows).

### Control port and server

- **TCP 17301**: confirmed as the Radmin control port.
- **Main server**: `148.113.190.78` (alternates: `198.244.203.247`, `45.162.230.182`).

### Frame format (confirmed by capture)

- **Header**: 4 bytes, big-endian `uint32_t` containing the payload size. The header is not included in the size.
- **Endianness**: big-endian (confirmed by `00 00 00 20` = 32).
- **Validation**: 54 frames extracted from 3 TCP flows, 22,824 bytes consumed, 0 bytes left over, no truncation.

### Parser validation

- Per-flow extraction: stream 0 (19 frames, 11,260 bytes), stream 1 (18 frames, 5,920 bytes), stream 2 (17 frames, 5,644 bytes).
- All flows fully consumed with no truncation.
- Parser implemented in `src/protocol/framing.rs` with 8 passing tests.
- Integration with `src/transport/mod.rs` completed with 5 integration tests.

### Control packet

- `00 00 00 04 03 00 00 00`: header (size 4) plus payload `03 00 00 00`.
- Meaning not confirmed (keep-alive, ACK, or handshake).

### Reconnection

- A new TCP connection is opened from a different source port after a disconnect.
- Reconnection was observed about 30 seconds after the first connection. To verify against the capture (see `PROTOCOL_SPEC.md` §9.6).

## Required next steps

1. Run the Windows client in an isolated VM with Wireshark to capture real traffic.
2. Decompile `RvROLClient.dll` and `RvControlSvc.exe` (Ghidra, IDA, or Kuna) to extract:
   - Binary packet structures (offsets, sizes, types).
   - Serialization and deserialization functions.
   - Cryptographic algorithms.
   - Addresses and ports of the ROS and relay servers.
3. Fill in every cell marked "unknown" in this specification.
4. Only then replace `_raw: Vec<u8>` with real Rust structures in `src/protocol/packets.rs`.

## Extraction directory

Binaries were extracted to `/tmp/opencode/radmin_ext/`, outside this repository.

## Limitations

- No decompiler (Ghidra, IDA, Hopper) was available on this host.
- No execution was observed (no debugging, emulation, or replay).
- Statements about exact packets, handshake, and encryption are inferences from symbols.
- No real packets from peers were captured, only the control server.
- The internal payload structure (fields, types, order) remains unknown.
