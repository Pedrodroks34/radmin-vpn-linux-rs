# PCAP Implementation Readiness — Radmin VPN Linux Client

**Project:** Radmin VPN Linux client (Rust, independent)  
**Basis:** Analysis of 6 PCAP/PCAPNG captures in `claude-handoff/pcaps/`  
**Date:** 06 nov 2026  
**Commit-base:** 9eecbfe  
**Language:** English  

---

## Readiness Matrix Summary

| # | Item | Readiness | Evidence Needed to Advance |
|---|---|---|---|
| 1 | Control framing | READY | — |
| 2 | Initial handshake | NOT READY | Capture handshake before any TCP connection |
| 3 | Authentication | NOT READY | Key material + authentication traffic |
| 4 | Cryptography | NOT READY | AES keys + algorithm + operation mode |
| 5 | STUN | PARTIALLY CHARACTERIZED | Ports and message format confirmed, but non-standard variant |
| 6 | NAT traversal | HYPOTHESIS | NAT type + successful hole punching |
| 7 | Peer discovery | PARTIALLY CHARACTERIZED | Discovery mechanism + complete TLV |
| 8 | UDP/9993 | PARTIALLY CHARACTERIZED | Complete structure + encrypted region |
| 9 | UDP/47836 | INCONCLUSIVE | Format confirmed but layout ambiguous |
| 10 | Relay | NOT READY | Relay server confirmation |
| 11 | Virtual interface | PARTIALLY CHARACTERIZED | ARP + IP 26.x.x.x confirmed, but encapsulation unknown |
| 12 | Packet encapsulation | NOT READY | Internal VPN packet format |

---

## Detailed Per-Item Analysis

### 1. Control Framing — READY

**PCAP Evidence:**
- TCP/17301: `[4-byte big-endian length][payload]` validated in 8 frames (frames 77, 80, 81, 82, 87, 88, 93, 94 of `radmin-connect.pcapng`)
- TCP/17351: Same framing validated in frames 5487, 5493, 5494, 5501 of `radmin_vm.pcap`
- Length field excludes the 4-byte header itself

**What can be implemented:**
- TCP framing parser for control
- Fragmented message reassembly (example: 2592 bytes across 2 TCP segments)

**What still needs:**
- None — framing fully characterized

---

### 2. Initial Handshake — NOT READY

**PCAP Evidence:**
- Handshake `00 00 00 04 03 00 00 00` mentioned in previous reports does NOT appear at the start of any captured TCP connection
- TCP/17301 captures begin with PSH+ACK data, not the 8-byte handshake
- Possible explanation: handshake occurs before capture start or is filtered

**Evidence needed:**
- Capture network BEFORE launching the Radmin client
- Capture first bytes of each TCP/17301 connection
- Verify whether handshake `00 00 00 04 03 00 00 00` is sent before or after TCP handshake

**Blocker:** Without handshake, control connection cannot be initiated.

---

### 3. Authentication — NOT READY

**PCAP Evidence:**
- All TCP/17301 and TCP/17351 traffic is encrypted
- No identifiable credentials, tokens, or authentication material in plaintext
- No evidence of SRP or other authentication protocol in captured traffic

**Evidence needed:**
- Capture traffic during client login (synchronized with UI events)
- Identify where username/password or key material is sent
- Verify whether authentication occurs inside encrypted channel or before

**Blocker:** Without understanding authentication, valid connection cannot be established.

---

### 4. Cryptography — NOT READY

**PCAP Evidence:**
- 48-byte encrypted region (0x2e–0x5d) in UDP/9993 Family A messages
- All TCP/17301 and TCP/17351 payload appears encrypted (high entropy)
- No nonce, IV, or key visible in any packet

**Evidence needed:**
- AES-256-CBC keys (32 bytes) used by CCryptoChannel
- IV used (fixed or variable)
- Operation mode (CBC confirmed in static analysis, but not verified in traffic)
- Padding scheme (0xcc fill + checksum + size indicator, per static analysis)

**Blocker:** Without keys, traffic cannot be encrypted/decrypted.

---

### 5. STUN — PARTIALLY CHARACTERIZED

**PCAP Evidence:**
- Binding Request (20 bytes) and Binding Response (56 bytes) observed on 9 ports
- Ports: 17309, 17310, 17341, 17342, 17347, 17348, 17349, 17357, 17358
- Non-standard variant: no magic cookie (0x2112A442), 16-byte transaction ID (not 12 as in RFC 5389)
- Automatic retry after ~100ms

**What can be implemented:**
- STUN Binding Request client on Radmin-specific ports
- Binding Response parsing to extract mapped address

**What still needs:**
- Decode STUN attributes in responses (MAPPED-ADDRESS, XOR-MAPPED-ADDRESS)
- Verify protocol variant compatibility with standard STUN libraries

---

### 6. NAT Traversal — HYPOTHESIS

**PCAP Evidence:**
- Hole punching attempt: same UDP/9993 message sent from ports 9993, 48318, 48870
- STUN Binding Request/Response on multiple servers
- No confirmation of successful hole punching (no verified request/response pairs)

**Evidence needed:**
- Determine NAT type (Full Cone, Restricted, Symmetric)
- Verify hole punching results in established bidirectional communication
- Capture traffic after successful hole punching

**Blocker:** Reliable NAT traversal cannot be implemented without knowing NAT type.

---

### 7. Peer Discovery — PARTIALLY CHARACTERIZED

**PCAP Evidence:**
- TLV 0x0004 contains peer IP + port (big-endian)
- 10-byte session identifier: `e5 d4 c1 c5 bc 21 59 16 c8 0f`
- No evidence of how peer list is obtained (discovery server? static list? broadcast?)

**Evidence needed:**
- Identify how peers are discovered (central server? static list? broadcast?)
- Fully specify TLV 0x0004 and other TLV types
- Verify whether other TLV types exist besides 0x0004

**Blocker:** Without discovery mechanism, client does not know which peers to contact.

---

### 8. UDP/9993 — PARTIALLY CHARACTERIZED

**PCAP Evidence:**
- 5 message families identified by size (28, 33, 99, 137, 247–641 bytes)
- Partially mapped structure for Family A (137 bytes)
- 48-byte encrypted region not decodable without keys
- TLV 0x0004 with peer IP/port confirmed

**Evidence needed:**
- Fully specify all fields of all families
- Identify encryption algorithm used in 48-byte region
- Determine whether nonce or IV exists in UDP/9993 messages
- Specify the 17 undocumented bytes at offset 0x78–0x8a of Family A

**Blocker:** Complete P2P communication cannot be implemented without understanding encryption and all fields.

---

### 9. UDP/47836 — INCONCLUSIVE

**PCAP Evidence:**
- 4-byte payload, format `XX YY 00 00` (sequential counter)
- Counter increments +1 per message
- Interval ~1 second between keepalives
- One direction only observed (26.228.88.155 → 26.239.229.134)

**Layout ambiguity:**
- `uint16 LE counter + 2 zero bytes` (counter from first 2 bytes, then `00 00`)
- `uint32 LE counter` (counter from all 4 bytes)

Both interpretations produce identical values because upper 16 bits are always zero. No evidence distinguishes them.

**What can be implemented:**
- Periodic keepalive with sequential counter
- Keepalive reception and validation

**What still needs:**
- Verify whether keepalive response is expected
- Determine timeout for dead peer detection

---

### 10. Relay — NOT READY

**PCAP Evidence:**
- High-volume flow (3.1 MB) between 192.168.15.15:43139 and [IP_PUBLICO_MASCARADO]:58358 (UDP)
- No evidence this is a Radmin relay server
- Could be traffic from another service or direct P2P with another peer

**Evidence needed:**
- Confirm whether a dedicated Radmin relay server exists
- Identify protocol used on relay channel
- Verify whether high-volume flow is Radmin or another service

**Blocker:** No evidence of relay in Radmin protocol from captures.

---

### 11. Virtual Interface — PARTIALLY CHARACTERIZED

**PCAP Evidence:**
- Interface `radminvpn0` with IP `26.239.229.134/8`
- ARP for virtual address resolution
- Locally administered MACs (prefix `02:`)
- IGMPv3, SSDP, MDNS as auxiliary traffic

**What can be implemented:**
- TUN/TAP interface with 26.x.x.x address
- ARP responses for virtual IPs
- Packet routing between virtual interface and UDP sockets

**What still needs:**
- Determine virtual interface driver (tun/tap vs other)
- Specify encapsulation format between virtual interface and physical network

**Blocker:** Without encapsulation format, working virtual interface cannot be implemented.

---

### 12. Packet Encapsulation — NOT READY

**PCAP Evidence:**
- No evidence of how virtual interface packets are encapsulated for physical transmission
- No direct packet-to-packet correlation between virtual interface Ethernet and physical UDP (beyond message-level UDP/9993)
- No evidence of additional header between virtual layer and UDP transport

**Evidence needed:**
- Capture virtual interface and physical interface simultaneously with packet-to-packet correlation
- Determine whether additional encapsulation exists (GRE, UDP-in-UDP, etc.)
- Verify whether virtual interface packet format matches UDP/9993

**Blocker:** Without understanding encapsulation, working virtual interface cannot be implemented.

---

## Implementation Priority Recommendations

### High Priority (blockers)

1. **Capture initial handshake** — Without handshake, no control connection
2. **Obtain encryption keys** — Without keys, no secure communication
3. **Understand encapsulation** — Without encapsulation, virtual interface cannot work

### Medium Priority (partials)

4. **Fully specify UDP/9993** — Including undocumented 17 bytes and encrypted region
5. **Identify peer discovery mechanism** — How peer list is obtained
6. **Determine NAT type** — For reliable NAT traversal implementation

### Low Priority (non-blockers)

7. **Implement UDP/47836 keepalive** — Simple, format confirmed
8. **Implement STUN client** — Format confirmed, ports known
9. **Implement virtual interface TUN/TAP** — IP format known

---

## Recommended Next Experiments

1. **Handshake capture:** Start network capture before launching Radmin client; capture first bytes of each TCP/17301 connection
2. **UI-synchronized capture:** Synchronize network capture with client login/connection events to identify authentication and key exchange
3. **STUN decoding:** Use appropriate STUN dissector to decode attributes in 56-byte responses
4. **Packet correlation:** Capture virtual and physical interfaces simultaneously, correlate packets by size and timestamp
5. **Real interoperability:** Test with official Windows client to validate protocol (observation only, no modification)

---

**Generated file:** `docs/PCAP_IMPLEMENTATION_READINESS.md`  
**Original .pcapng files:** Preserved, unmodified  
**Project source code:** Unaltered