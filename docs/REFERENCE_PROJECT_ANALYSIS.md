# Reference Project Analysis: Radmin VPN for Linux (Wine)

**Target:** https://github.com/baptisterajaut/radmin-vpn-linux (cloned to `references/radmin-vpn-linux/`, git-ignored)

**License:** GPL-3.0

**Goal of this analysis:** extract reverse engineering findings from the external project and cross-check them against our static reverse engineering and captured traffic. The aim is to speed up building an independent Rust client without using Wine, Windows drivers, DLLs, or external hooks as dependencies.

**Scope note:** the findings in sections 2 and 3 describe the external project's own work. They are not verified by this repository's captures unless section 4 says so.

---

## 1. Architecture of the external project

The project runs the official Windows client (`RvControlSvc.exe` and `RvRvpnGui.exe`) under **Wine**, replacing incompatible components with native Linux implementations. The data flow is:

```
RvControlSvc.exe (Wine)
    ├─ DeviceIoControl \\.\RVPNNETMP (IOCTLs: VERSION, STATUS, CONNECT, SETUP, PEERMAC, ...)
    │     │
    │     ▼
    └─ rvpnnetmp.sys (PE shim driver, running under Wine)
            │ TLV-encoded frames over named pipes (FIFOs)
            │   Z:\tmp\rvpn_b2d         (bridge to driver)
            │   Z:\tmp\rvpn_d2b_high    (driver to bridge, high priority)
            │   Z:\tmp\rvpn_d2b_low     (driver to bridge, low priority)
            ▼
    tap_bridge (native Linux)
            │ [u16 len][frame] over FIFO / raw frame over TAP
            ▼
    TAP device (radminvpn0) ←─ virtual L2 network visible to Linux
```

Main components:

| Component | Type | Role |
|---|---|---|
| `rvpnnetmp.sys` | PE driver (mingw) | Emulates the NDIS miniport `NetMP60.sys`. Creates `\Device\RVPNNETMP`. Accepts IOCTLs from the service, queues frames in an IRP queue, routes by MAC, and sends and receives through FIFOs. |
| `tap_bridge` | native C binary | Reads and writes frames between the Linux TAP and the FIFOs. Two threads (incoming and outgoing). ARP snooping and gratuitous ARP. Minecraft multicast replication. JSON filters. |
| `adapter_hook.dll` | injected PE DLL | IAT hooks in `RvControlSvc.exe` and `RvROLClient.dll`: renames the adapter, no-op `RegSetKeySecurity`, `GetProcAddress` hook for `GetNameInfoW`, perflib stubs, `LoadLibrary` watcher for `RvROLClient.dll`. |
| `rvpn_launcher.exe` | PE injector | Creates `RvControlSvc.exe` suspended and injects `adapter_hook.dll` with `CreateRemoteThread` and `LoadLibraryA`. |
| `drvinst.exe` | PE stub | Replaces Famatech's NDIS driver installer, which would cause `abort()` under Wine. Returns 0. |
| `netsh.exe` / `netsh64.exe` | PE wrapper | Translates the Radmin `netsh interface ip` commands into `ip addr` and `ip link` on Linux, through a relay file. |
| `rvpn_dnsfix.so` | LD_PRELOAD (glibc) | Intercepts `getnameinfo` and `gethostbyaddr`. For private addresses, returns the numeric form immediately (avoids blocked PTR lookups). |
| `rvpn_reuseport.so` | LD_PRELOAD (wineserver) | Forces `SO_REUSEPORT` on every TCP socket created by the wineserver, allowing double `SO_REUSEADDR` on Windows (NAT traversal). |

---

## 2. Technical findings extracted from the external project

These findings are the reference project's own claims, taken from its comments and code. They are not verified in this repository.

### 2.1 Frame protocol (TLV)

Extracted from the comments and code of `rvpnnetmp.c`:

| Context | Format | Field 1 | Field 2 | Field 3 |
|---|---|---|---|---|
| Service read (driver to service) | TLV, mode 2 or higher | `u32 dest_mac_prefix` (host byte order, byte-swapped) | `u32 frame_len` | `frame_data` (minimum 60 bytes, zero-padded) |
| Service write (service to driver) | raw frame | Ethernet frame (14 bytes of header plus payload) | none | none |
| Bridge FIFO (driver and tap_bridge) | `[u16 len][frame]` | `u16 frame_len` (native byte order) | `frame_data` | none |

**Important detail of the read TLV:** `dest_mac_prefix` is the **first 4 bytes of the destination MAC** of the Ethernet frame, byte-swapped (`ntohl`). The service compares it with the MACs of peers registered through `IOCTL_RVPN_PEERMAC`. Without the byte swap, unicast frames match no peer and are silently dropped.

**Padding:** frames shorter than 60 bytes are zero-padded to 60 bytes (the Ethernet minimum).

### 2.2 IOCTLs identified

All derived from the reverse engineering of `RvNetMP60.sys` and the call sites in `RvControlSvc.exe`:

| IOCTL | Code | Input | Output | Inferred role |
|---|---|---|---|---|
| `IOCTL_RVPN_VERSION` | `0x0022C004` | 8 bytes (version and MAC) | 12 bytes | Version registration. If version is 4, returns `[status=0][MAC 6 bytes][pad 2]`. Otherwise `[status=1]`. |
| `IOCTL_RVPN_STATUS` | `0x00224018` | 0 | 4 bytes | Adapter status. Bit 0 means media present and active. The service checks `status != 0 && (status & 1)`. |
| `IOCTL_RVPN_CONNECT` | `0x00224020` | 0 | 1 byte | NDIS connection state. Returns `0x20` (`NdisMediaStateConnected`). If 0 bytes are written, `DeviceIoControl` fails and the service sees `CDeviceRemoved`. |
| `IOCTL_RVPN_SETLINK` | `0x00224010` | 0xB8B | 0xB8 | Statistics or link. Responds with a zeroed block of 0xB8 bytes. |
| `IOCTL_RVPN_SETUP` | `0x0022801C` | 4 bytes (mode) | 0 | Sets the TLV format mode. Mode 2 or higher enables `dest_mac_prefix` in the read TLV. |
| `IOCTL_RVPN_PEERMAC` | `0x00228014` | 6 bytes (MAC) | 0 | Registers which `FILE_OBJECT` (handle) answers for which peer MAC. Used by the RX thread to route unicast. |
| `IOCTL_RVPN_SETMAC` | `0x00228024` | variable | variable | Per-peer ownership ACK. Returns 1 byte. |

### 2.3 FIFOs (named pipes through Wine's `Z:` drive)

| Path | Direction | Purpose |
|---|---|---|
| `Z:\tmp\rvpn_b2d` | bridge to driver | Frames from the TAP arriving at the service (RX) |
| `Z:\tmp\rvpn_d2b_high` | driver to bridge | High priority: TCP, ICMP, unicast UDP, ARP |
| `Z:\tmp\rvpn_d2b_low` | driver to bridge | Low priority: broadcast, multicast, non-IP |
| `Z:\tmp\rvpn_d2b` | legacy | Single legacy pipe, not used by the new code |

### 2.4 MAC routing (PeerMAC)

The driver keeps a table of pairs `(FILE_OBJECT, MAC[6])`. It is dynamic: it starts with 16 slots and doubles up to 4,096. Unicast frames go to the `FILE_OBJECT` whose MAC matches the destination. Group frames (broadcast or multicast, where bit 0 of the first MAC byte is set) are delivered to **one IRP per distinct `FILE_OBJECT`**.

### 2.5 Priority detection (driver to bridge)

| Protocol | Priority |
|---|---|
| ARP (0x0806) | High |
| IPv4 TCP (6), ICMP (1) | High |
| IPv4 UDP unicast (17, bit 0 of the destination MAC clear) | High |
| IPv6 TCP (6), ICMPv6 (58) | High |
| IPv6 UDP unicast (17, bit 0 of the destination MAC clear) | High |
| Broadcast and multicast, non-IP | Low |

### 2.6 Uplink address detection

The project determines which interface is the "uplink" (the path to the Internet) in two ways:

1. `GetBestInterface(8.8.8.8)`: trusted only if the IfIndex appears in the adapter enumeration.
2. Fallback: the **only** adapter that is UP, has a `FirstGatewayAddress`, and has a routable IPv4 address (not loopback, not link-local 169.254/16, not CGNAT 100.64/10).

If the result is ambiguous (0 or more than 1 candidate), it returns 0 and does not filter, which is the safe behavior.

### 2.7 Interface filtering (`GetAdaptersAddresses` / `GetAdaptersInfo`)

The `adapter_hook.dll` intercepts both `IPHLPAPI` functions:

- Renames the TAP adapter to `Famatech Radmin VPN Ethernet Adapter` or `Radmin VPN`.
- Hides every adapter that is neither the TAP nor the default route, by zeroing `FirstUnicastAddress` (GAA) or `IpAddressList` (GAI).
- This stops the ROL connector from advertising the IPs of docker0, vmnet, or tailscale as NAT candidates.

### 2.8 Reverse DNS short-circuit (`rvpn_dnsfix.so`)

Intercepts `getnameinfo` and `gethostbyaddr` at the glibc level (LD_PRELOAD on the service). For private addresses (loopback 127/8, 10/8, 172.16/12, 192.168/16, APIPA 169.254/16, CGNAT 100.64/10), returns the numeric address and numeric port immediately, without querying DNS. Public addresses go to the real function.

The same is done for IPv6 (loopback, link-local, site-local, and ULA fc00::/7).

### 2.9 SO_REUSEPORT (`rvpn_reuseport.so`)

Intercepts `socket()` in the `wineserver` (LD_PRELOAD). For TCP sockets, forces `SO_REUSEPORT` before `bind()`. This lets Radmin 2.1 perform **TCP port-reuse NAT traversal**: bind a listener on `uplink:PORT`, advertise the mapping, then bind outgoing sockets to the same local port. Without it, the Linux kernel rejects the second bind with `EADDRINUSE`, which the wineserver relabels as `WSAEACCES`.

### 2.10 Perflib stubs

Wine is missing four `advapi32` exports:

- `PerfIncrementULongCounterValue`
- `PerfIncrementULongLongCounterValue`
- `PerfDecrementULongCounterValue`
- `PerfDecrementULongLongCounterValue`

Radmin 2.1 resolves seven exports in a cascade. If any of them fails, the counterset is not created, the per-peer counter object stays NULL, and the peer handshake is discarded, producing `error: 0x700000000`. The project answers with no-op stubs (`ERROR_SUCCESS`) through a `GetProcAddress` hook.

### 2.11 Minecraft multicast replication

`tap_bridge` detects IPv4 UDP packets to `224.0.2.60` (Minecraft LAN) and replicates them as broadcast to `26.255.255.255` and `255.255.255.255`, recalculating the IP checksum and zeroing the UDP checksum.

---

## 3. Binary structures identified

### 3.1 Internal driver structures (`rvpnnetmp.c`)

```c
// Device extension (per-instance driver state)
struct _DEVICE_EXTENSION {
    BOOLEAN Connected;
    UCHAR   MacAddress[6];
    LONG    IoctlCount;
    LONG    StatusCount;
    ULONG   SetupMode;       // set by IOCTL_RVPN_SETUP (0x22801c)
    HANDLE  FifoB2D;         // bridge to driver (RX)
    HANDLE  FifoD2B_High;    // driver to bridge, high priority
    HANDLE  FifoD2B_Low;     // driver to bridge, low priority
};

// Per-peer route table (MAC to FILE_OBJECT)
struct _PEER_ROUTE {
    PFILE_OBJECT fo;
    UCHAR mac[6];
};

// RX ring (fallback when no IRP is pending)
struct _RX_RING {
    volatile ULONG write_idx;
    volatile ULONG read_idx;
    struct { USHORT len; UCHAR data[1600]; } frames[16];
};
```

### 3.2 Ethernet frame format

Standard Ethernet II fields:

- Offset 0 to 5: destination MAC.
- Offset 6 to 11: source MAC.
- Offset 12 to 13: EtherType (big-endian): `0x0800` IPv4, `0x0806` ARP, `0x86DD` IPv6.
- Offset 14 onward: payload.

For IPv4:

- Offset 14 + 9 (byte 23 of the frame): IP protocol (1 ICMP, 6 TCP, 17 UDP).
- Offset 14 + 12 (byte 26 of the frame): source IP.
- Offset 14 + 16 (byte 30 of the frame): destination IP.

---

## 4. Cross-check with our reverse engineering

### 4.1 Independent confirmations (our static RE and captured traffic)

| Finding of the external project | Our evidence | Status |
|---|---|---|
| `\\Device\\RVPNNETMP` | Strings in `NetMP60_1_1_64.sys` | **Confirmed** |
| The driver is an NDIS 6 miniport, x86-64 | `file` and `.sys` strings | **Confirmed** |
| The service is `RvControlSvc.exe` | PE imports (`StartServiceCtrlDispatcherW`, and others) | **Confirmed** |
| The GUI connects through the named pipe `\\.\pipe\RadminVpnGuiChannel` | Service strings | **Confirmed** |
| Control port TCP **17301** | Wireshark capture (non-HTTP port with significant traffic) | **Confirmed** |
| Server `148.113.190.78:17301` | Wireshark capture | **Confirmed** |
| Frame header: 4-byte big-endian payload size | Wireshark capture (several examples) | **Confirmed** |
| Control packet `00 00 00 04 03 00 00 00` | Wireshark capture | **Confirmed (structure), meaning not confirmed** |
| Reconnection opens a new TCP connection (different source port) | Wireshark capture (port 49526 after 56923) | **Confirmed** |
| Driver signed by Microsoft WHQL | `inspect_pe_certificates` | **Confirmed** |
| Driver version `NetMP60_1_1` | `.inf` and `.sys` strings | **Confirmed** |
| DNS over HTTPS `https://%hs/dns-query` | `RvROLClient.dll` strings | **Confirmed** |
| Hardcoded public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9, and others) | `RvROLClient.dll` strings | **Confirmed** |

### 4.2 Findings of the external project that corroborate our RE

| Finding | External evidence | Our evidence | Status |
|---|---|---|---|
| The emulated NDIS driver replaces `NetMP60.sys` | Code of `rvpnnetmp.sys` | Strings of the original `.sys` | **Confirmed** |
| Ethernet frames travel over the virtual adapter | Code of `tap_bridge` and `rvpnnetmp.c` | Wireshark capture (we see TCP 17301, not Ethernet frames) | **Probable** |
| MAC routing for multiple peers | Driver code (`g_peer_routes`) | RTTI `VCUniqueConnectionId`, `VCConnection` | **Probable** |
| Frame priority (TCP and ICMP above broadcast) | Driver code (`classify_high_priority`) | Not observed directly | **Hypothesis** |
| Per-peer NAT traversal with SO_REUSEADDR and TCP port reuse | Code of `rvpn_reuseport.so` and docs | Strings `TcpNatChecker` and `Connections TCP/nat` in the service | **Probable** |
| Peer handshake fails without perflib counters | `wine-perflib.md` docs | RTTI `CAuthSessionId`, `CMsgAuth*` | **Probable** |

### 4.3 Architectural differences (our Rust client vs the external project)

| Aspect | External project | Our project (independent Rust) |
|---|---|---|
| Client execution | Wine plus the official Windows client | Native Rust code (no Wine) |
| Network driver | `rvpnnetmp.sys` (PE) emulated under Wine | Native Linux TUN/TAP |
| Service to driver channel | Named FIFOs plus Windows IOCTL | Not applicable (no Windows driver) |
| Driver to TAP channel | FIFOs plus `tap_bridge` | TUN/TAP directly from Rust |
| netsh translation | `netsh_wrapper.exe` | `netlink` / `rtnetlink` in Rust |
| Reverse DNS fix | `rvpn_dnsfix.so` (LD_PRELOAD on glibc) | Not needed (Rust controls its own DNS) |
| SO_REUSEPORT fix | `rvpn_reuseport.so` (LD_PRELOAD on wineserver) | Rust controls sockets directly |
| Perflib stubs | IAT hook on `advapi32` | Not applicable (we do not use `advapi32`) |
| Interface filtering | Hook on `GetAdaptersAddresses` / `GetAdaptersInfo` | Not needed (we control which IPs to advertise) |
| GUI | Windows client Qt (under Wine) | Rust CLI (optional TUI later) |

---

## 5. Reusable components (concepts, not code)

The external project's code is under **GPL-3.0**. We cannot copy C or C++ source into our Rust project without respecting the license and documenting provenance. We can, however, reuse documented concepts and structures:

| Concept | Source | Use in our Rust client |
|---|---|---|
| TLV framing: 4-byte length prefix | `rvpnnetmp.c`, `tlv_encode_frame` | Parser for TCP framing in our `transport` module |
| TLV with destination MAC prefix (4 bytes) | `rvpnnetmp.c` | Peer addressing structure |
| TCP and ICMP priority over broadcast | `classify_high_priority` | Priority queue in our transport |
| Unicast routing by MAC | `g_peer_routes` | Peer table keyed by virtual address |
| ARP snooping and gratuitous ARP | `tap_bridge.c` | Virtual address cache in our `network` module |
| Numeric reverse DNS for private addresses | `rvpn_dnsfix.c` | Not needed (Rust does not call glibc `getnameinfo` indirectly) |
| SO_REUSEPORT for NAT traversal | `rvpn_reuseport.c` | Rust sets `SO_REUSEADDR` and `SO_REUSEPORT` directly on sockets |
| Perflib counters for peer handshake | `wine-perflib.md` | Session and authentication structure to be found through dynamic RE |
| Minecraft multicast to broadcast | `replicate_mcast_to_bcast` | Not needed (limited scope) |

---

## 6. Limitations and incompatibilities

| Item | Detail |
|---|---|
| **GPL-3.0 license** | The C and C++ code of the external project cannot be copied into our Rust project without making it GPL-3.0 as well and documenting its origin. We use it only as a conceptual reference. |
| **Not a native client** | The external project runs the official Windows client under Wine. It contains no native network protocol code, only environment adaptation. |
| **Specific version** | Validated against Radmin VPN 2.1.4951.1 (the same version as our target). The reference project reports that 2.0.4899.9 also works. It reports that 1.4 is not supported. |
| **Does not reveal the packet protocol** | The external project never decoded the content of the TCP Ethernet frames between peers. It only carries them. The ROS control protocol and the data packets remain unknown. |
| **Does not reveal the authentication handshake** | The handshake between peers and with the ROS server remains unknown. |
| **Does not reveal the encryption algorithms** | `CCryptoChannel` has not been analyzed by either project. (The static analysis in `CONTROL_PROTOCOL.md` covers the code, but not from this reference project.) |

---

## 7. Relation to our specification (`docs/PROTOCOL_SPEC.md`)

### 7.1 What the external project confirms

| Our field | Previous status | New status | Basis |
|---|---|---|---|
| TCP port 17301 | Confirmed (capture) | **Confirmed** | The project uses the same port indirectly, through the Windows service |
| Server `148.113.190.78` | Confirmed (capture) | **Confirmed** | Same target |
| 4-byte big-endian header is the size | Confirmed (capture) | **Confirmed** | The driver's TLV uses `u32 frame_len`, though in a different context |
| `dest_mac_prefix` in TLV | Unknown | **Confirmed (concept)** | `rvpnnetmp.c`, lines 328 to 375 |
| 60-byte minimum frame | Unknown | **Confirmed** | `ETH_FRAME_MIN 60` in `rvpnnetmp.c` |

### 7.2 What remains unknown (both projects)

- Binary structure of the ROS packets (`CRosPkt*`, `CMsg*`, `CLoginPacket`, and others).
- Device-to-server authentication handshake.
- Encryption algorithms in `CCryptoChannel` (static candidates are in `CONTROL_PROTOCOL.md`).
- Format of the Ethernet frames between peers (what is inside the TLV payload).
- Virtual IP addressing (the 26.x.x.x range is not confirmed by either project).
- Peer-to-peer ports (NAT traversal uses port 17301 for control; data ports are unknown).

---

## 8. Next steps for an independent Rust implementation

Based on everything gathered so far, these are the recommended steps in order:

### Phase I: control protocol (high value, low cost)

1. **TCP framing parser** (`transport` module):
   - Read a big-endian `u32` as the payload size.
   - Read the full payload.
   - Handle fragmented frames (multiple TCP reads).
   - Handle multiple frames in one read.
   - Validate a maximum size (for example 65,535 bytes) to avoid excessive allocation.
   - Unit tests with real frames captured in the PCAPs.

2. **Payload analysis of the captured frames**:
   - Group frames by size (36, 68, 100, 116, 148, 180, 244, 260, 308, 356, 388, 708, 1,440, 1,960, 3,396 bytes).
   - Look for constant bytes (magic, message type, version).
   - Look for fields that change with the action (connect, chat message, disconnect, reconnect).

### Phase II: decompilation (to fill in what the traffic does not reveal)

3. **Open the Ghidra project** (`/tmp/opencode/ghidra_project/radmin_project.rep`) in the GUI:
   - Analyze `ROLClient_Connect`, `ROLClient_Send`, and `ROLClient_Receive`.
   - Analyze `CCryptoChannel` (structure and methods).
   - Analyze `CRosPktHeartbeat` and other ROS packet types.
   - Extract serialization and deserialization functions.

4. **More targeted traffic captures**:
   - One action at a time (only connect, only join network, only chat, only disconnect).
   - Correlate packet type with action.

### Phase III: Rust implementation (after enough evidence)

5. Replace `_raw: Vec<u8>` in `src/protocol/packets.rs` with real structures.
6. Implement the `session`, `identity`, `authentication`, and `crypto` modules.
7. Implement `tunnel` (native TUN/TAP).
8. Implement `daemon` (systemd service).

---

## 9. Conclusion

The reference project confirms our high-level architecture (a Windows service, a virtual network driver, and a TAP interface) and provides useful details about **low-level framing** (size-prefixed TLV, MAC routing, traffic prioritization). However, it does **not reveal the application protocol** (ROS, control packets, authentication, encryption). That remains the main unknown boundary of our work.

The shortest path to an independent Rust client is:

1. Implement the TCP framing parser now, based on the captures.
2. Make more targeted captures to identify message types.
3. Use the existing Ghidra project to decompile the serialization functions.
4. Only then implement the packet structures and session logic.

There is no shortcut: the control protocol and the cryptographic algorithms will only be known through analysis of the official binaries and real traffic.
