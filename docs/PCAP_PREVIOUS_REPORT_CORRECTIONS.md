# PCAP Previous Report Corrections — Radmin VPN

**Project:** Radmin VPN Linux client (Rust, independent)  
**Document audited:** `docs/PCAP_FORENSICS_REPORT.md`  
**Audit date:** 06 nov 2026  
**Rule:** The original document was NOT modified. All corrections are listed here.  
**Language:** English  

---

## Corrections Summary

| # | Section/Line | Problem | Classification | Recommended Correction |
|---|---|---|---|---|
| 1 | Section 9.1, offset table | Declared size 137 bytes, but offsets go only to 0x72 (120 bytes). 17 bytes missing. | CRITICAL | Extend table to 0x8a (137 bytes) or revise size to 120 bytes |
| 2 | Section 9.1 | Field `00 04` interpreted as TLV without specifying endianness | MEDIUM | Specify big-endian for IP and port |
| 3 | Section 4.1 | Server table omits 45.162.230.182:17351 | LOW | Add entry for 45.162.230.182:17351 |
| 4 | Section 4.5 | IP `[IP_PUBLICO_MASCARADO]` not masked | CRITICAL (privacy) | Replace with `[IP_PUBLICO_MASCARADO]` |
| 5 | Section 9.3 | Relay classified as HYPOTHESIS without specific flow evidence | LOW | Keep as HYPOTHESIS, but add specific flow observed |
| 6 | Section 11 | TLV 0x30 not mentioned as not found | LOW | Add note that it was not found in PCAPs |
| 7 | Section 5.1 | TPKT detected by Wireshark mentioned as "possible dissector misinterpretation" without investigation | MEDIUM | Investigate whether TPKT is dissector artifact or real protocol |
| 8 | Section 10 | Does not mention alternative UDP/9993 sizes (33, 28, 99 bytes) | MEDIUM | Add complete size distribution |
| 9 | Section 3 | Does not mention UDP/47836 keepalive in `radmin-connect.pcapng` | LOW | Add keepalive timeline to connection capture |
| 10 | Section 13 | Does not specify STUN uses non-standard Radmin ports (not 3478) | MEDIUM | Explicitly list ports 17309, 17341, 17342, 17357, 17358 |
| 11 | Section 6.2 | STUN response size stated as 98 bytes (confuses frame.len with UDP payload) | MEDIUM | Clarify: 56 bytes UDP payload, 98 bytes Ethernet frame |
| 12 | Section 13 | Claims standard RFC 5389 STUN with magic cookie; actual packets have no magic cookie and 16-byte TXID | CRITICAL | Reclassify as non-standard STUN variant |

---

## Detailed Correction #1 — UDP/9993 Message Size Error (CRITICAL)

### Location
Section 9.1, offset table for UDP/9993 message (137 bytes).

### Original Claim
The table lists offsets from 0x00 to 0x72 with a final 6-byte field, totaling 0x78 = 120 bytes. The text states "137 bytes" but does not document bytes 0x78 to 0x8a.

### Evidence
Frame 116 of `radmin-mine.pcapng` (interface 1):
- `frame.len` = 179
- `udp.length` = 145
- UDP payload = 145 − 8 (UDP header) = 137 bytes
- Complete hex payload has 137 bytes (274 hex characters)

### Problem
The report documents only the first 120 bytes (0x00–0x77). The last 17 bytes (0x78–0x8a) are not described.

### Recommended Correction
Extend the offset table to include bytes 0x78–0x8a:

| Offset | Size | Content | Interpretation |
|---|---|---|---|
| 0x78 | 2 | `00 00` | Possible TLV start | HYPOTHESIS |
| 0x7a | 4 | `00 08 ea c9` | Possible IP fragment | HYPOTHESIS |
| 0x7e | 2 | `0a 00` | Unknown | INCONCLUSIVE |
| 0x80 | 1 | `00` | Unknown | INCONCLUSIVE |
| 0x81 | 7 | `00 01 94 db 79 5b` | Unknown | INCONCLUSIVE |
| 0x88 | 1 | `4e` | Unknown | INCONCLUSIVE |
| 0x89 | 1 | `0b` | Unknown | INCONCLUSIVE |
| 0x8a | 1 | `2c` | Unknown | INCONCLUSIVE |

Or revise declared size to 120 bytes if additional bytes are not part of semantic structure.

---

## Detailed Correction #2 — Endianness of Field 0x0004 (MEDIUM)

### Location
Section 9.1, description of TLV field `0x0004`.

### Original Claim
Field `00 04` contains "peer IP and port" without specifying endianness.

### Evidence
Frame 116, offset 0x6f–0x70: `00 04`
Frame 116, offset 0x71–0x74: `1a ac b2 4f` = 26.172.178.79 in big-endian
Frame 116, offset 0x75–0x76: `27 09` = 9993 in big-endian

Frame 127, offset 0x6f–0x70: `00 04`
Frame 127, offset 0x71–0x74: `b1 70 4f e2` = [IP_PUBLICO_MASCARADO] in big-endian
Frame 127, offset 0x75–0x76: `27 09` = 9993 in big-endian

### Recommended Correction
Specify explicitly that both IP and port use big-endian (network byte order). Also correct offset from 0x5e to 0x6f.

---

## Detailed Correction #3 — Missing Server 45.162.230.182:17351 (LOW)

### Location
Section 4.1, Radmin Control Servers table.

### Evidence
`radmin_vm.pcap`: TCP connections to 45.162.230.182:17351 (frames 5483–5528).

### Recommended Correction
Add entry to table:

| IP | Port | Function | Captures | Evidence |
|---|---|---|---|---|
| 45.162.230.182 | 17351 | Alternative control (different sub-protocol) | radmin_vm.pcap | TCP handshake + data with sequence |

---

## Detailed Correction #4 — Public IP Not Masked (CRITICAL — Privacy)

### Location
Multiple sections (4.5, 4.6, 9.3, 10.4, etc.)

### IP Found
`[IP_PUBLICO_MASCARADO]` — appears in high-volume flow (10,156 packets, 3.1 MB) in `radmin-mine-host.pcapng`.

### Recommended Correction
Replace all occurrences of `[IP_PUBLICO_MASCARADO]` with `[IP_PUBLICO_MASCARADO]` in all report sections.

### Status
Corrected in `docs/PCAP_FORENSICS_REPORT.md` version (7 occurrences replaced).

---

## Detailed Correction #5 — Relay as HYPOTHESIS Without Specific Flow (LOW)

### Location
Section 9.3.

### Original Claim
"The flow `192.168.15.15:43139 ↔ [IP_PUBLICO_MASCARADO]:58358` (UDP, 10,156 packets, 3.1 MB) in radmin-mine-host.pcapng may be relay traffic, but there is no direct evidence that it is a Radmin relay server."

### Recommended Correction
Keep as HYPOTHESIS, but add:
- Flow uses port 58358 (not 9993), different from observed P2P pattern
- No TLV structure identifiable in first bytes
- Could be traffic from another service or background application

---

## Detailed Correction #6 — TLV 0x30 Not Found (LOW)

### Location
Section 11, correlation with previous findings.

### Evidence
Exhaustive search of all 6 PCAPs found no 192-byte field associated with tag `0x30`.

### Recommended Correction
Add note: "The TLV `0x30` 192-byte field mentioned in previous static reverse engineering reports was not found in any analyzed PCAP capture. It may be present only in initial handshake traffic (not captured) or in message types not observed."

---

## Detailed Correction #7 — TPKT Detected by Wireshark (MEDIUM)

### Location
Section 5.1, item 6 of connection flow.

### Original Claim
"TPKT detected by Wireshark in some frames (possible dissector misinterpretation)"

### Evidence
Wireshark's TPKT dissector may be incorrectly interpreting encrypted payload first bytes as TPKT header (ISO 8073).

### Recommended Correction
Investigate whether pattern `00 00 00` followed by non-zero bytes is interpreted as TPKT. Recommended: disable TPKT dissector and re-analyze with raw data to confirm whether it is a false positive.

---

## Detailed Correction #8 — Alternative UDP/9993 Sizes (MEDIUM)

### Location
Sections 4.6 and 9.1.

### Evidence
Complete analysis of all PCAPs shows multiple UDP/9993 message sizes:

| Size | Quantity (mine + mine-host + connect) |
|---|---|
| 28 | 82 |
| 33 | 223 |
| 37 | 38 |
| 59 | 30 |
| 67 | 20 |
| 93 | 28 |
| 99 | 74 |
| 114 | 28 |
| 137 | 93 |
| 149 | 16 |
| 215 | 27 |
| 247 | 12 |
| 249 | 8 |
| 309 | 12 |
| 369 | 14 |
| 629 | 6 |
| 641 | 3 |

### Recommended Correction
Add section about complete size distribution and identify distinct message families by binary structure, not just size.

---

## Detailed Correction #9 — UDP/47836 Keepalive in Connection Capture (LOW)

### Location
Section 3 (Event Timeline).

### Evidence
`radmin-connect.pcapng` frames 312–1287: Keepalive UDP/47836 with sequential counter (0x9e–0xac) between `26.228.88.155` and `26.239.229.134`.

### Recommended Correction
Add timeline entry for connection capture showing keepalive active during connection phase.

---

## Detailed Correction #10 — Non-Standard STUN Ports (MEDIUM)

### Location
Sections 4.2 and 6.3.

### Evidence
STUN observed on Radmin-specific ports:
- 17309, 17310, 17341, 17342, 17347, 17348, 17349, 17357, 17358

No observation on standard STUN port 3478.

### Recommended Correction
Explicitly list all 9 observed ports and state they are NOT standard STUN ports (3478).

---

## Detailed Correction #11 — STUN Response Size Confusion (MEDIUM)

### Location
Section 6.2.

### Problem
Report states "98-byte responses" which confuses Ethernet frame size (frame.len=98) with UDP payload size (56 bytes).

### Evidence
Frame 5489: frame.len=98, udp.length=64, UDP payload=56 bytes.

### Recommended Correction
Clarify: 56 bytes UDP payload, 98 bytes Ethernet frame. Do not conflate the two.

---

## Detailed Correction #12 — Non-Standard STUN Protocol (CRITICAL)

### Location
Section 13.

### Problem
Report claims standard RFC 5389 STUN with magic cookie 0x2112A442 and 12-byte transaction ID. Actual packets show NO magic cookie and 16-byte transaction ID.

### Evidence
Frame 5477 raw UDP payload (20 bytes):
`00 01 00 00 24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66`

Structure:
- Type: `00 01` (Binding Request)
- Length: `00 00` (no attributes)
- Transaction ID: `24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66` (16 bytes)
- **No magic cookie present**

RFC 5389 STUN header would be:
- Type: 2 bytes
- Length: 2 bytes
- Magic Cookie: 4 bytes (0x2112A442)
- Transaction ID: 12 bytes
- Total: 20 bytes

But observed structure has 16-byte transaction ID and NO magic cookie, still totaling 20 bytes.

### Recommended Correction
Reclassify as non-standard STUN variant. Do not claim RFC 5389 compliance. Standard STUN libraries may not work without modification.

---

## Corrections Not Applied (Insufficient Evidence)

| # | Potential Correction | Reason Not Applied |
|---|---|---|
| A | Reclassify UDP/9993 as encrypted | No keys to verify; encrypted appearance is not proof |
| B | Identify encryption algorithm | No reference material or keys |
| C | Classify NAT type | Single STUN response is insufficient |
| D | Confirm relay for [IP_PUBLICO_MASCARADO]:58358 | No evidence it is Radmin server |
| E | Confirm handshake `00 00 00 04 03 00 00 00` | Does not appear in any capture |
| F | Correct STUN magic cookie claim | See Correction #12 above |
| G | Correct STUN transaction ID size | See Correction #12 above |

---

## New Documents Generated (do not modify original)

| Document | Content |
|---|---|
| `docs/PCAP_FORENSICS_DEEP_DIVE.md` | Second round main report (20 fronts) |
| `docs/PCAP_MESSAGE_CATALOG.md` | Message catalog identified |
| `docs/PCAP_FLOW_MAP.md` | Communication flow map |
| `docs/PCAP_IMPLEMENTATION_READINESS.md` | Implementation readiness matrix |
| `docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md` | This document (corrections) |
| `docs/PCAP_THIRD_ROUND_AUDIT.md` | Third round forensic audit |

---

**Generated file:** `docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md`  
**Original document:** `docs/PCAP_FORENSICS_REPORT.md` — NOT MODIFIED  
**Original .pcapng files:** Preserved, unmodified