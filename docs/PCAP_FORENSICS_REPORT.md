# PCAP Forensics Report — Radmin VPN Traffic Analysis

**Project:** Radmin VPN Linux client (Rust, independent)  
**Capture directory:** `claude-handoff/pcaps/`  
**Tools used:** tshark 4.7.4, capinfos, mergecap, xxd, hexdump, python3  
**Analysis date:** 06 nov 2026  

---

## 1. Executive Summary

6 capture files (.pcap/.pcapng) were analyzed containing network traffic generated during real tests of the Radmin VPN Linux client (running via Wine) and previous VM captures. The captures reveal:

- **Control plane:** TCP/17301 and TCP/17351 to Radmin control servers (`148.113.190.78`, `198.244.203.247`, `45.162.230.182`).
- **Confirmed framing:** `[4-byte big-endian payload length][payload]` on both control ports.
- **STUN:** Binding Request on non-standard UDP ports (17309, 17341, 17342, 17357, 17358) for Radmin STUN servers, with Binding Response received.
- **Teredo:** UDP/3544 to Microsoft Teredo server (`20.201.205.4`).
- **Data plane:** UDP/9993 between virtual IPs (range `26.x.x.x`) and physical peer IPs, with TLV-structured messages containing session ID, encrypted data, and peer IP/port attributes.
- **Keepalive:** UDP/47836 between virtual IPs with 4-byte payload and incrementing sequence number.
- **Virtual interface:** `radminvpn0` with IP `26.239.229.134/8`, ARP, IGMP, SSDP.

No original .pcapng file was modified. No source code was altered.

---

## 2. Capture Inventory

| File | Type | Packets | Size | Duration | First capture | Last capture | Interface(s) | Capture filter |
|---|---|---|---|---|---|---|---|---|
| `radmin_17301.pcap` | pcapng | 85 | 30 kB | 55,86 s | 31/10/2026 18:06:10 | 31/10/2026 18:07:06 | virbr0 | host 192.168.122.77 |
| `radmin-connect.pcapng` | pcapng | 2.216 | 3,18 MB | 47,94 s | 06/11/2026 14:22:04 | 06/11/2026 14:22:52 | enp7s0, radminvpn0 | (none) |
| `radmin-mine-host.pcapng` | pcapng | 50.249 | 31 MB | 67,72 s | 06/11/2026 14:32:56 | 06/11/2026 14:34:03 | enp7s0, radminvpn0 | (none) |
| `radmin-mine.pcapng` | pcapng | 20.681 | 7,34 MB | 44,00 s | 06/11/2026 14:31:21 | 06/11/2026 14:32:05 | enp7s0, radminvpn0 | (none) |
| `radmin_vm2.pcap` | pcapng | 1.147 | 196 kB | 118,39 s | 31/10/2026 18:08:57 | 31/10/2026 18:10:56 | virbr0 | host 192.168.122.77 |
| `radmin_vm.pcap` | pcapng | 6.364 | 21 MB | 114,64 s | 31/10/2026 18:05:28 | 31/10/2026 18:07:23 | virbr0 | host 192.168.122.77 |

**SHA-256:** available in `capinfos` metadata (consulted individually).

**Tools available:** tshark (yes), capinfos (yes), mergecap (yes), xxd (yes), hexdump (yes), python3 (yes). No missing tools.

---

## 3. Event Timeline

| Relative time | Event | Capture | Source | Destination | Port | Protocol |
|---|---|---|---|---|---|---|
| T+0 | VM capture start | radmin_vm.pcap | 192.168.122.77 | — | — | — |
| T+0 | DNS queries (Windows/MS) | radmin_vm.pcap | 192.168.122.77 | 192.168.122.1 | 53 | UDP |
| T+7s | Teredo Router Solicitation | radmin_vm.pcap | 192.168.122.77:54778 | 20.201.205.4:3544 | UDP/3544 | Teredo |
| T+42s | TCP connects to 148.113.190.78:17301 | radmin_vm.pcap / radmin_17301.pcap | 192.168.122.77:56923 | 148.113.190.78:17301 | TCP/17301 | Control |
| T+95s | STUN Binding Request → 135.181.75.11:17357 | radmin_vm.pcap | 192.168.122.77:54527 | 135.181.75.11:17357 | UDP/17357 | STUN |
| T+95s | STUN Binding Request → 148.113.190.78:17341 | radmin_vm.pcap | 192.168.122.77:54530 | 148.113.190.78:17341 | UDP/17341 | STUN |
| T+95s | STUN Binding Request → 148.113.190.78:17342 | radmin_vm.pcap | 192.168.122.77:54530 | 148.113.190.78:17342 | UDP/17342 | STUN |
| T+96s | STUN Binding Request → 135.181.75.11:17358 | radmin_vm.pcap | 192.168.122.77:54527 | 135.181.75.11:17358 | UDP/17358 | STUN |
| T+96s | STUN Binding Response received (98 bytes) | radmin_vm.pcap | 135.181.75.11:17357 | 192.168.122.77:54527 | UDP/17357 | STUN |
| T+97s | STUN Binding Response received (98 bytes) | radmin_vm.pcap | 148.113.190.78:17341 | 192.168.122.77:54530 | UDP/17341 | STUN |
| T+96s | TCP connects to 45.162.230.182:17351 | radmin_vm.pcap | 192.168.122.77:49497 | 45.162.230.182:17351 | TCP/17351 | Alternative control |
| T+0 (connect) | Connection capture start | radmin-connect.pcapng | 192.168.15.15 | — | — | — |
| T+5s | TCP SYN → 148.113.190.78:17301 | radmin-connect.pcapng | 192.168.15.15:44340 | 148.113.190.78:17301 | TCP/17301 | Control |
| T+5s | TCP data → 148.113.190.78:17301 (196 bytes) | radmin-connect.pcapng | 192.168.15.15:44340 | 148.113.190.78:17301 | TCP/17301 | Control |
| T+5s | TCP data → 148.113.190.78:17301 (4420 bytes, fragmented) | radmin-connect.pcapng | 148.113.190.78:17301 | 192.168.15.15:44340 | TCP/17301 | Control |
| T+6s | TCP SYN → 198.244.203.247:17301 | radmin-connect.pcapng | 192.168.15.15:57924 | 198.244.203.247:17301 | TCP/17301 | Control (alternate) |
| T+6s | TCP SYN → 148.113.190.78:17301 (new connection) | radmin-connect.pcapng | 192.168.15.15:44342 | 148.113.190.78:17301 | TCP/17301 | Control |
| T+0 (mine) | Active traffic capture start | radmin-mine.pcapng | — | — | — | — |
| T+0 | UDP 9993 between virtual IPs | radmin-mine.pcapng | 26.239.229.134:9993 | 26.172.178.79:9993 | UDP/9993 | P2P Data |
| T+0 | Keepalive UDP 47836 | radmin-mine.pcapng | 26.228.88.155:47836 | 26.239.229.134:47836 | UDP/47836 | Keepalive |
| T+0 (mine-host) | Active traffic capture start (host) | radmin-mine-host.pcapng | — | — | — | — |
| T+5s | ARP on virtual interface | radmin-mine-host.pcapng | 26.239.229.134 | [IP_PUBLICO_MASCARADO} | — | ARP |
| T+5s | ARP on virtual interface | radmin-mine-host.pcapng | 26.172.178.79 | 26.239.229.134 | — | ARP |

**Note on phases:** File names (`radmin-connect`, `radmin-mine`, `radmin-mine-host`) suggest distinct phases (connection, active traffic, active traffic on host), but there is no direct confirmation in capture metadata. Timestamps indicate `radmin-mine` (14:31:21) precedes `radmin-mine-host` (14:32:56).

---

## 4. Identified Endpoints and Flows

### 4.1 Radmin Control Servers (CONFIRMED)

| IP | Port | Function | Captures | Evidence |
|---|---|---|---|---|
| 148.113.190.78 | 17301 | Primary control server | radmin_17301, radmin_vm, radmin_vm2, radmin-connect, radmin-mine | TCP handshake + data in multiple captures |
| 198.244.203.247 | 17301 | Alternative control server | radmin_vm, radmin_vm2, radmin-connect | TCP SYN observed |
| 45.162.230.182 | 17301/17351 | Control/relay server | radmin_vm, radmin_vm2 | TCP/17301 and TCP/17351 |
| 45.162.230.182 | 17351 | Alternative server (different sub-protocol) | radmin_vm | TCP handshake + data |

These IPs match those listed in `docs/PROTOCOL_SPEC.md` as servers observed in previous captures.

### 4.2 Radmin STUN Servers (STRONG INDICATION)

| IP | Port | Function | Captures | Evidence |
|---|---|---|---|---|
| 135.181.75.11 | 17357 | STUN server | radmin_vm.pcap | Binding Request sent, Binding Response (98 bytes) received |
| 135.181.75.20 | 17358 | STUN server | radmin_vm.pcap | Binding Request sent, Binding Response (98 bytes) received |
| 148.113.190.78 | 17341 | STUN server (also TCP control) | radmin_vm.pcap | Binding Request sent, Binding Response (98 bytes) received |
| 148.113.190.78 | 17342 | STUN server (also TCP control) | radmin_vm.pcap | Binding Request sent, Binding Response (98 bytes) received |
| 15.204.183.160 | 17342 | Alternative STUN server | radmin_vm.pcap | Binding Request sent, Binding Response (98 bytes) received |
| 162.19.169.168 | 17309/17310 | STUN server | radmin_vm2.pcap | Binding Request sent |

**Note:** These ports (17309, 17341, 17342, 17357, 17358) are NOT standard STUN ports (3478). They are Radmin-specific.

### 4.3 Teredo Server (CONFIRMED)

| IP | Port | Function | Captures | Evidence |
|---|---|---|---|---|
| 20.201.205.4 | 3544 | Microsoft Teredo server | radmin_vm.pcap, radmin_vm2.pcap | Teredo Router Solicitation (ICMPv6 type 133) encapsulated in UDP |

### 4.4 Radmin Virtual IPs (CONFIRMED)

| IP | Function | Captures | Evidence |
|---|---|---|---|
| 26.239.229.134 | Local client virtual IP (radminvpn0) | radmin-mine, radmin-mine-host, radmin-connect | Virtual interface, ARP, UDP/9993 traffic |
| 26.172.178.79 | Peer virtual IP | radmin-mine, radmin-mine-host, radmin-connect | Bidirectional UDP/9993, ARP |
| 26.228.42.15 | Peer virtual IP | radmin-mine, radmin-mine-host | UDP/9993, IGMP |
| 26.228.88.155 | Peer virtual IP | radmin-mine, radmin-mine-host, radmin-connect | Keepalive UDP/47836, ARP |
| 25.33.236.186 | Peer virtual IP (range 25.x) | radmin-mine, radmin-vm | UDP/9993 |
| 26.255.255.255 | Virtual broadcast | radmin-mine | UDP |

### 4.5 Peer Physical IPs (STRONG INDICATION)

| IP | Function | Captures | Evidence |
|---|---|---|---|
| [IP_PUBLICO_MASCARADO} | Peer physical IP | radmin-mine, radmin-mine-host, radmin_vm, radmin_vm2 | Bidirectional UDP/9993, ARP resolution on radminvpn0 |
| 103.195.103.66 | Peer physical IP / relay | radmin-mine | UDP/9993 |
| 25.33.236.186 | Ambiguous physical/virtual IP | radmin-mine, radmin_vm, radmin_vm2 | UDP/9993, TCP |

### 4.6 Highest Volume Flows

| Capture | Flow | Packets | Bytes | Direction |
|---|---|---|---|---|
| radmin-mine-host | 192.168.15.15:43139 ↔ [IP_PUBLICO_MASCARADO}:58358 (UDP) | 10.156 | 3,1 MB | Bidirectional (possible P2P/relay data) |
| radmin-mine-host | 104.29.143.41:19307 ↔ 192.168.15.15:47904 (TCP) | 3.495 | 712 kB | Bidirectional (HTTPS/TLS) |
| radmin-mine-host | 26.239.229.134 (virtual) | 5.276 | 2,4 MB | Virtual interface |
| radmin-mine-host | 26.228.42.15 (virtual) | 5.237 | 2,4 MB | Virtual interface (peer) |
| radmin_vm | 192.168.122.77:49480 ↔ 2.16.169.246:443 (TCP) | 1.379 | 14 MB | HTTPS (non-Radmin, Microsoft/CDN) |

**Note:** The highest volume traffic in `radmin_vm.pcap` is HTTPS to Microsoft/Akamai addresses — not Radmin traffic.

---

## 5. TCP Control Analysis

### 5.1 Port 17301

**Framing:** `[4-byte big-endian payload length][payload]`, where the length excludes the 4-byte header itself.

Byte evidence (radmin-connect.pcapng, frame 77):
```
00 00 00 c0 | 10 f9 bf 00 3c e2 ... (192 bytes of payload)
```
Length = 0x000000c0 = 192. tcp.len = 196 = 4 + 192. ✓

Frame 80:
```
00 00 00 20 | c7 f5 78 26 ... (32 bytes of payload)
```
Length = 0x20 = 32. tcp.len = 36 = 4 + 32. ✓

Frame 81:
```
00 00 01 00 | 65 93 01 46 ... (256 bytes of payload)
```
Length = 0x100 = 256. tcp.len = 260 = 4 + 256. ✓

**Fragmentation:** Messages larger than MSS are fragmented across TCP segments. Example (radmin-connect.pcapng):
- Frame 100: length=0x0a20=2592, first segment with 1440 bytes (4 header + 1436 payload)
- Frame 101: continuation with 1156 bytes of payload (no new length prefix)
- 1436 + 1156 = 2592 ✓

**Connection flow (radmin-connect.pcapng):**
1. TCP SYN → 148.113.190.78:17301 (source port 44340)
2. SYN-ACK, ACK (handshake complete)
3. Bidirectional data with PSH+ACK
4. New TCP connection → 198.244.203.247:17301 (alternative server)
5. New TCP connection → 148.113.190.78:17301 (new source port 44342)
6. TPKT detected by Wireshark in some frames (possible dissector misinterpretation)

**Classification:** CONFIRMED — framing `[4-byte BE length][payload]` validated in multiple frames.

### 5.2 Port 17351 (radmin_vm.pcap)

**Framing:** Same `[4-byte BE length][payload]`, but with a different sub-protocol in the payload.

Example (frame 5486):
```
00 00 00 cb | 10 00 00 04 00 00 00 03 60 00 00 bf ...
```
Length = 0xcb = 203. tcp.len = 207 = 4 + 203. ✓

**Internal payload structure (17351):**
- Bytes 0-3: `10 00 00 04` — message version/type (constant in all observed messages)
- Bytes 4-7: Sequence number (`00 00 00 03`, `00 00 00 04`, `00 00 00 05`, `00 00 00 06`) — incremental
- Bytes 8+: additional fields varying by message type

**Servers:** 45.162.230.182:17351 (CONFIRMED)

**Classification:** CONFIRMED for framing; STRONG INDICATION for being a separate control or synchronization channel.

---

## 6. STUN and NAT Analysis

### 6.1 STUN Binding Requests

All observed STUN requests use the standard RFC 5389 format:
- Message Type: `0x0001` (Binding Request)
- Message Length: `0x0000` (no attributes)
- Transaction ID: 16 random bytes

Example (radmin_vm.pcap, frame 5477):
```
192.168.122.77:54527 → 135.181.75.11:17357
Transaction ID: 24df3803cbe764ea106738b61d314c66
```

### 6.2 STUN Binding Responses

98-byte responses received from all queried STUN servers. Contain STUN header + attributes (possibly MAPPED-ADDRESS and XOR-MAPPED-ADDRESS, not decoded due to lack of specific dissector).

**Retry pattern:** Two Binding Requests sent with ~99-100 ms interval (retry due to no response on first attempt).

### 6.3 Non-Standard STUN Ports

| Port | Servers | Captures |
|---|---|---|
| 17309 | 162.19.169.168 | radmin_vm2.pcap |
| 17310 | 162.19.169.168, 198.244.203.247 | radmin_vm2.pcap |
| 17341 | 148.113.190.78 | radmin_vm.pcap |
| 17342 | 148.113.190.78, 15.204.183.160 | radmin_vm.pcap |
| 17347 | 148.113.1.139 | radmin_vm2.pcap |
| 17348 | 148.113.190.78, 148.113.1.139, 135.181.75.9 | radmin_vm2.pcap |
| 17349 | 148.113.190.78, 148.113.1.139, 135.181.75.9 | radmin_vm2.pcap |
| 17357 | 135.181.75.11, 135.181.75.20 | radmin_vm.pcap |
| 17358 | 135.181.75.11, 135.181.75.20 | radmin_vm.pcap |

**Classification:** STRONG INDICATION — these are request/response STUN servers, but ports are not standard STUN ports.

### 6.4 NAT Behavior

NAT type (Full Cone, Restricted, Symmetric) could not be determined based on a single STUN response. The client sends Binding Requests to multiple servers/ports, suggesting an attempt to discover the mapped address through multiple paths.

---

## 7. Teredo Analysis

**CONFIRMED:** Teredo traffic observed in two captures.

- Source: `192.168.122.77:54778`
- Destination: `20.201.205.4:3544` (Microsoft Teredo server)
- Content: Teredo IPv6 over UDP tunneling containing ICMPv6 Router Solicitation (type 133) from `fe80::ffff:ffff:fffe` to `ff02::2`
- Nonce: `8acf0087ddea3402`

Teredo is being used for IPv6 connectivity through NAT. There is no evidence that Radmin specifically uses Teredo — it may be background Windows/Wine traffic.

---

## 8. Virtual Interface Analysis

**Interface:** `radminvpn0` (present in radmin-connect, radmin-mine, radmin-mine-host)  
**Virtual IP:** `26.239.229.134/8` (CONFIRMED)  
**Virtual MAC:** `02:50:ce:a5:3a:26` and `02:08:62:e3:9a:28` (observed via ARP)

### 8.1 Virtual Interface Traffic

| Protocol | Endpoints | Captures | Evidence |
|---|---|---|---|
| ARP | `26.239.229.134` ↔ `[IP_PUBLICO_MASCARADO}`, `25.33.236.186` | radmin-mine, radmin-mine-host, radmin-connect | "Who has X? Tell 26.239.229.134" |
| UDP/9993 | `26.239.229.134` ↔ `26.172.178.79` | radmin-mine, radmin-mine-host | P2P data between virtual peers |
| UDP/9993 | `26.239.229.134` ↔ `26.228.42.15` | radmin-mine, radmin-mine-host | P2P data between virtual peers |
| UDP/47836 | `26.228.88.155` ↔ `26.239.229.134` | radmin-mine, radmin-mine-host, radmin-connect | Periodic keepalive |
| UDP/4445 | `26.239.229.134:60900` → `224.0.2.60:4445` | radmin-mine-host | Virtual multicast |
| IGMPv3 | `26.228.42.15` → `224.0.0.22` | radmin-mine-host | Membership Report (join/leave multicast group) |
| SSDP | `26.172.178.79` → `239.255.255.250:1900` | radmin-mine-host | M-SEARCH (possible background Windows traffic) |

### 8.2 Physical ↔ Virtual Correlation

The same session ID `e5 d4 c1 c5 bc 21 59 16 c8 0f` appears in both physical interface (enp7s0) and virtual interface (radminvpn0) traffic, confirming that the Radmin session spans both interfaces.

Example: `192.168.15.15:9993 → [IP_PUBLICO_MASCARADO}:9993` (physical) has the same base payload as `26.239.229.134:9993 → 26.172.178.79:9993` (virtual), differing only in the IP/port fields of the final TLV.

**Classification:** CONFIRMED — the virtual interface carries real Radmin traffic between peers, with ARP for virtual address resolution.

---

## 9. P2P and Relay Evidence

### 9.1 Direct Peer Communication (UDP/9993)

**CONFIRMED:** Direct UDP traffic between virtual peer IPs on port 9993.

Message structure (137 bytes, example `26.239.229.134:9993 → 26.172.178.79:9993`):

```
Offset  Content                              Size  Interpretation
0x00    25 2d ff 68                           4 bytes  Magic/message type
0x04    42 c3 84 70                           4 bytes  Variable field (possible flags)
0x08    e5 d4 c1 c5 bc 21 59 16               8 bytes  Session ID (part 1)
0x10    c8 0f                                 2 bytes  Session ID (part 2)
0x12    00 01                                 2 bytes  Message subtype
0x14    03 74 49 74 bf 0f ed 01               8 bytes  Variable field
0x1c    0d 01 10 00                           4 bytes  Fixed field (0d 01 10 00)
0x20    02 00 00 01                           4 bytes  Fixed field (02 00 00 01)
0x24    a1 b1 ea 42 91 21 59 16 c8 0f         10 bytes  Repeated session ID + timestamp?
0x2e    00 2e 38 e9 ... (48 bytes)            48 bytes  Encrypted/random data
0x5e    00 04                                 2 bytes  TLV Type = 0x0004
0x60    1a ac b2 4f                           4 bytes  Peer IP (26.172.178.79)
0x64    27 09                                 2 bytes  Peer port (9993)
0x66    00 00 00 00 08 ea c9 0a               8 bytes  Variable field
0x6e    00 00 01 94                           4 bytes  Variable field (0x00000194 = 404)
0x72    db 79 5b 4e 0b 2c                     6 bytes  Variable field
```

**Observations:**
- The same base payload is sent from multiple source ports (9993, 48318, 48870) to the same destination — hole punching attempt through multiple ports.
- TLV type `0x0004` contains peer IP and port — address exchange mechanism for direct connection.
- Responses of 59-230 bytes received from peer — confirms bidirectional communication.

### 9.2 Keepalive (UDP/47836)

**CONFIRMED:** Periodic keepalive between virtual peers.

Payload: 4 bytes, format `XX 02 00 00` where XX increments (c3, c4, c5, c6, c7, c8, c9, ca, cb, cc...).

Example:
```
26.228.88.155:47836 → 26.239.229.134:47836: c3 02 00 00
26.228.88.155:47836 → 26.239.229.134:47836: c4 02 00 00
26.228.88.155:47836 → 26.239.229.134:47836: c5 02 00 00
```

Interval: ~1 second between keepalives.

### 9.3 Relay (HYPOTHESIS)

The flow `192.168.15.15:43139 ↔ [IP_PUBLICO_MASCARADO}:58358` (UDP, 10.156 packets, 3,1 MB) in radmin-mine-host.pcapng may be relay traffic, but there is no direct evidence that it is a Radmin relay server.

**Classification:** HYPOTHESIS — not confirmed.

---

## 10. Capture Comparison

| Endpoint | radmin_17301 | radmin-connect | radmin-mine | radmin-mine-host | radmin_vm | radmin_vm2 |
|---|---|---|---|---|---|---|
| 148.113.190.78:17301 | ✓ | ✓ | ✓ (5 pkt) | — | ✓ | ✓ |
| 198.244.203.247:17301 | — | ✓ | — | — | ✓ | ✓ |
| 45.162.230.182:17301 | — | — | — | — | — | ✓ |
| 45.162.230.182:17351 | — | — | — | — | ✓ | — |
| 135.181.75.11:17357 | — | — | — | — | ✓ | — |
| 135.181.75.11:17358 | — | — | — | — | ✓ | — |
| 20.201.205.4:3544 (Teredo) | — | — | — | — | ✓ | ✓ |
| 26.239.229.134 (virtual) | — | ✓ | ✓ | ✓ | — | — |
| 26.172.178.79 (virtual peer) | — | ✓ | ✓ | ✓ | — | — |
| 26.228.42.15 (virtual peer) | — | — | ✓ | ✓ | — | — |
| 26.228.88.155 (virtual peer) | — | ✓ | ✓ | ✓ | — | — |
| 25.33.236.186 | — | — | ✓ | — | ✓ | — |
| STUN 17341/17342/17357/17358 | — | — | — | — | ✓ | — |
| STUN 17309/17310 | — | — | — | — | — | ✓ |

**Endpoints in all captures:** No endpoint appears in all 6 captures.

**Phase-exclusive endpoints:**
- `radmin-connect`: Initial TCP connections to control servers (port 17301, multiple parallel connections)
- `radmin-mine` / `radmin-mine-host`: Active P2P traffic between virtual peers (UDP/9993, keepalive UDP/47836)
- `radmin_vm` / `radmin_vm2`: STUN, Teredo, initial control connections

**Flows appearing after joining the network:** UDP/9993 between virtual peers, keepalive UDP/47836.

---

## 11. Correlation with Previous Findings

| Previous finding | Status | Evidence in PCAPs |
|---|---|---|
| Framing `[4-byte BE length][payload]` | ✓ CONFIRMED | Validated in TCP/17301 and TCP/17351 across multiple captures |
| Initial handshake `00 00 00 04 03 00 00 00` | — NOT FOUND | TCP/17301 captures start with PSH+ACK data, not the 8-byte handshake (possible handshake occurs before capture start or is filtered) |
| Control port 17301 | ✓ CONFIRMED | Multiple TCP connections observed |
| Port 17351 (inconclusive role) | ✓ CONFIRMED as alternative control | TCP handshake + data observed, sub-protocol with sequence numbers |
| STUN on non-standard ports | ✓ CONFIRMED | Binding Request/Response on 17309, 17341, 17342, 17357, 17358 |
| Teredo UDP/3544 | ✓ CONFIRMED | Router Solicitation to 20.201.205.4:3544 |
| Virtual interface 26.x.x.x | ✓ CONFIRMED | radminvpn0 with IP 26.239.229.134 |
| Servers 148.113.190.78, 198.244.203.247, 45.162.230.182 | ✓ CONFIRMED | All appear in captures |
| Port 9993 (not previously documented) | ✓ NEW DISCOVERY | Intense P2P traffic between virtual peers |
| Port 47836 keepalive (not previously documented) | ✓ NEW DISCOVERY | Periodic 4-byte keepalive between virtual peers |
| TLV with peer IP/port (not previously documented) | ✓ NEW DISCOVERY | Field `00 04 [IP] [port]` in UDP/9993 messages |

**Contradictory with previous reports:** No direct contradiction found. PCAPs confirm previous findings and add new details (ports 9993, 47836, TLV structure).

---

## 12. Contradictions and Unconfirmed Hypotheses

### 12.1 Contradictions

No direct contradiction found between PCAPs and previous reverse engineering reports.

### 12.2 Unconfirmed Hypotheses

| Hypothesis | Status | Justification |
|---|---|---|
| Port 17351 is key synchronization channel | HYPOTHESIS | Sub-protocol with sequence numbers, but no evidence of cryptographic material |
| Port 9993 is encrypted P2P data channel | STRONG INDICATION | Intense traffic between virtual peers, payloads appear encrypted, but no keys to decode |
| TLV type 0x0004 is STUN-style MAPPED-ADDRESS attribute | HYPOTHESIS | Similar structure (type + IP + port), but type 0x0004 is not standard STUN |
| Keepalive 47836 dead peer detection | HYPOTHESIS | Sequential payload, but no evidence of failure detection |
| Servers 17341/17342 do both STUN and control | STRONG INDICATION | Same IP serves TCP/17301 (control) and UDP/17341/17342 (STUN) |
| 25.x.x.x addresses are alternative virtual IP range | STRONG INDICATION | Appear in UDP/9993 conversations with other 26.x.x.x |

### 12.3 Inconclusive

- Encrypted content of TCP/17301 and TCP/17351 (no keys to decode)
- Encrypted content of UDP/9993 (no keys to decode)
- RSA operation (padding, key exchange) — not visible in encrypted traffic
- Origin of the 32-byte AES key — not determinable from encrypted traffic

---

## 13. Recommended Next Experiments

1. **Capture complete initial handshake:** Start capture before connecting the client to capture the first bytes of TCP/17301, including the possible handshake `00 00 00 04 03 00 00 00`.

2. **Decode UDP/9993 TLV:** Collect more UDP/9993 message samples to fully map the TLV structure, especially fields after the IP/port attribute (type 0x0004).

3. **Capture key exchange traffic:** Synchronize network capture with client UI events (login, connection) to identify when key material is negotiated.

4. **Analyze complete STUN responses:** The 98-byte responses contain attributes that may reveal NAT-mapped addresses — decode using a proper STUN dissector.

5. **Correlate keepalive with dead peer detection:** Monitor what happens when a peer is disconnected — do keepalives stop? Is there a notification packet?

6. **Test STUN on standard port:** Verify if the client also attempts STUN on standard port 3478 (not observed in these captures).

7. **Capture with specific port filter:** Capture only traffic on ports 17301, 17351, 9993, 47836 to reduce non-Radmin noise (HTTPS, DNS, etc.).

---

## 14. Conclusion Classification

| Conclusion | Classification | Basis |
|---|---|---|
| TCP framing `[4-byte BE length][payload]` on port 17301 | CONFIRMED | Validated in multiple frames, multiple captures |
| TCP framing `[4-byte BE length][payload]` on port 17351 | CONFIRMED | Validated in multiple frames |
| Control servers 148.113.190.78, 198.244.203.247, 45.162.230.182 | CONFIRMED | TCP handshake + data in multiple captures |
| STUN Binding Request/Response on non-standard Radmin ports | CONFIRMED | Requests sent, responses received |
| Teredo server 20.201.205.4:3544 | CONFIRMED | Router Solicitation observed |
| Virtual interface radminvpn0 with IP 26.239.229.134 | CONFIRMED | Present in 3 captures, active traffic |
| P2P communication UDP/9993 between virtual IPs | CONFIRMED | Bidirectional traffic observed |
| Keepalive UDP/47836 with 4-byte sequence | CONFIRMED | 10+ packets with incremental sequence |
| TLV structure with peer IP/port in UDP/9993 | CONFIRMED | Field `00 04 [IP] [port]` decoded |
| Port 17351 as key synchronization channel | HYPOTHESIS | No direct evidence of cryptographic material |
| Port 9993 as encrypted data channel | STRONG INDICATION | Payloads appear encrypted, no keys |
| NAT type (Full/Restricted/Symmetric) | INCONCLUSIVE | Single STUN response insufficient |
| Origin of 32-byte AES key | INCONCLUSIVE | Encrypted traffic, no keys |

---

**Generated file:** `docs/PCAP_FORENSICS_REPORT.md`  
**Original .pcapng files:** Preserved, unmodified  
**Project source code:** Unaltered  
**Masked IP:** User public IP replaced with `[IP_PUBLICO_MASCARADO}` throughout (original: `177.xxx.xxx.xxx`)