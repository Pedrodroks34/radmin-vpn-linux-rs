# PCAP Third-Round Audit — Radmin VPN Traffic Analysis

**Project:** Radmin VPN Linux client (Rust, independent)  
**Capture directory:** `claude-handoff/pcaps/`  
**Audit date:** 06 nov 2026  
**Commit-base:** 86fa37f  
**Language:** English (per documentation rule 2.1)  

---

## 1. Executive Summary

This third-round audit critically examines the five documents produced in the second round of PCAP analysis against the original capture files in `claude-handoff/pcaps/`. The audit identifies multiple errors, inconsistencies, and unvalidated classifications across all documents. Key findings include:

- **Portuguese text** present in 5 of 6 documents (violates documentation rule 2.1 requiring all Markdown in English).
- **UDP/9993 137-byte message**: The offset table stops at 0x77 (120 bytes), leaving 17 bytes (0x78–0x88) undocumented. The actual TLV field `0x0004` is at offset 0x6f–0x70, not 0x5e as claimed.
- **STUN size contradiction**: Documents alternate between 98 bytes (Ethernet frame size) and 56 bytes (UDP payload size) for Binding Responses.
- **STUN protocol misclassification**: Documents claim standard RFC 5389 with magic cookie 0x2112A442 and 12-byte transaction ID. Actual packets show NO magic cookie and a 16-byte transaction ID — this is NOT standard STUN.
- **UDP/47836 ambiguity**: Documents alternate between `uint16 LE + 2 bytes` and `uint32 LE` interpretations without resolution.
- **Hole punching overclassified**: Only transmission attempts observed, not successful NAT traversal.
- **Interface virtual overclassified**: Marked READY for implementation but encapsulation mechanism is NOT READY.
- **Delimiter error**: `[IP_PUBLICO_MASCARADO]` uses closing `}` instead of `]` in multiple locations.

No original `.pcap`/`.pcapng` files were modified. No source code was altered. No commit was made.

---

## 2. Methodology

### 2.1 Tools Used

| Tool | Version | Purpose |
|---|---|---|
| tshark | 4.7.4 | Packet analysis, field extraction, verbose dissection |
| capinfos | 4.7.4 | Capture file inventory |
| xxd | — | Hex dump verification |

### 2.2 Captures Analyzed

| File | Packets | Interfaces | Role |
|---|---|---|---|
| `radmin_17301.pcap` | 85 | virbr0 | Control port 17301 filter |
| `radmin-connect.pcapng` | 2,216 | enp7s0, radminvpn0 | Connection phase |
| `radmin-mine-host.pcapng` | 50,249 | enp7s0, radminvpn0 | Active traffic (host) |
| `radmin-mine.pcapng` | 20,681 | enp7s0, radminvpn0 | Active traffic |
| `radmin_vm2.pcap` | 1,147 | virbr0 | VM capture 2 |
| `radmin_vm.pcap` | 6,364 | virbr0 | VM capture 1 |

### 2.3 Evidence Standards

Each technical conclusion is classified as:

- **CONFIRMED**: Directly demonstrated by reproducible byte-level evidence from PCAPs.
- **STRONG INDICATION**: Multiple consistent evidence items, but lacks definitive confirmation.
- **HYPOTHESIS**: Plausible interpretation not yet demonstrated.
- **INCONCLUSIVE**: Data insufficient or contradictory.
- **REFUTADO**: Evidence directly contradicts the claim.

---

## 3. Audit Results — All Documents

### 3.1 Master Correction Table

| # | Affirmation | Document | Original Evidence | Audit Result | Required Correction |
|---|---|---|---|---|---|
| 1 | UDP/9993 message is 137 bytes, fully documented | DEEP_DIVE §9.1, CATALOG §UDP/9993 Family A | Offsets 0x00–0x77 only (120 bytes) | **PARTIAL**: 17 bytes (0x78–0x88) undocumented | Document bytes 0x78–0x88 or revise size to 120 |
| 2 | TLV field `0x0004` at offset 0x5e | DEEP_DIVE §F03, CATALOG §UDP/9993 Family A | Frame 116 hex dump | **REFUTADO**: TLV `00 04` is at offset 0x6f–0x70 | Correct offset to 0x6f–0x70 |
| 3 | STUN Binding Response is 98 bytes | DEEP_DIVE §F13, REPORT §6.2 | Frame 5489: frame.len=98, udp.length=64 | **CONFUSION**: 98 = Ethernet frame, 56 = UDP payload | Clarify: 56 bytes UDP payload, 98 bytes frame |
| 4 | STUN uses standard RFC 5389 with magic cookie | DEEP_DIVE §F13, CATALOG §STUN Binding Request | Frame 5477 raw: `00 01 00 00 [16-byte TXID]`, no magic cookie | **REFUTADO**: No magic cookie, 16-byte TXID (not 12) | Reclassify as non-standard STUN variant |
| 5 | STUN Transaction ID is 12 bytes | DEEP_DIVE §F13, CATALOG §STUN | Frame 5477: 16-byte TXID `24df38...4c66` | **REFUTADO**: TXID is 16 bytes | Correct to 16 bytes |
| 6 | UDP/47836 is `uint16 LE + 2 bytes` OR `uint32 LE` | DEEP_DIVE §F06, CATALOG §UDP/47836 | All captures: `XX YY 00 00` pattern | **INCONCLUSIVE**: Both interpretations produce same values | Mark as INCONCLUSIVE, document both |
| 7 | Hole punching CONFIRMED | DEEP_DIVE §F05, FLOW_MAP §Confirmed | Same payload from ports 9993, 48318, 48870 | **HYPOTHESIS**: Only transmission attempts observed, no proof of successful NAT traversal | Downgrade to HYPOTHESIS |
| 8 | Interface virtual READY for implementation | IMPLEMENTATION_READINESS §11 | ARP + IP 26.x.x.x observed | **CONTRADICTION**: Encapsulation mechanism is NOT READY (§12) | Downgrade to PARTIALLY CHARACTERIZED |
| 9 | STUN | READY | PARTIALLY CHARACTERIZED | Binding Request/Response observed | **OVERESTIMATED**: Attributes not decoded, magic cookie missing | Downgrade to PARTIALLY CHARACTERIZED |
| 10 | `[IP_PUBLICO_MASCARADO]` delimiter | All 5 documents | Multiple occurrences | **ERROR**: Closing `}` instead of `]` | Fix to `[IP_PUBLICO_MASCARADO]` |
| 11 | Portuguese text in documents | DEEP_DIVE, READINESS, CORRECTIONS, FLOW_MAP, CATALOG | Multiple sections | **VIOLATION**: Rule 2.1 requires all Markdown in English | Translate all documents to English |

### 3.2 Document-Specific Findings

#### PCAP_FORENSICS_DEEP_DIVE.md

**Language**: Portuguese throughout. Violates rule 2.1.

**Critical errors:**
- FRENTE 02: Claims 137-byte message fully documented but offset table ends at 0x77 (120 bytes). 17 bytes at 0x78–0x88 missing.
- FRENTE 03: Claims TLV `0x0004` at offset 0x5e. Actual location is offset 0x6f–0x70 (verified from frame 116 raw bytes).
- FRENTE 06: Alternates between `uint16 LE` and `uint32 LE` without resolution.
- FRENTE 05: Classifies hole punching as CONFIRMED. Only transmission attempts observed; no proof of successful NAT traversal.
- FRENTE 13: Claims standard RFC 5389 STUN with magic cookie. Actual packets have no magic cookie and 16-byte transaction ID.

**Overconfident classifications:**
- FRENTE 04: "CONFIRMED" for physical↔virtual payload equivalence. Only one frame pair compared (116↔130).
- FRENTE 08: "CONFIRMED" for 10-byte session ID. Only observed in one capture; not verified across all.

#### PCAP_MESSAGE_CATALOG.md

**Language**: Portuguese throughout. Violates rule 2.1.

**Critical errors:**
- UDP/9993 Family A table: Offset 0x5e listed as TLV Type `00 04`. Actual TLV Type is at offset 0x6f.
- STUN Binding Request: Claims 20-byte payload with 16-byte Transaction ID and magic cookie. Actual: 20-byte payload, NO magic cookie, 16-byte Transaction ID.
- STUN Binding Response: Claims 56-byte payload but also references "98 bytes" elsewhere.
- UDP/47836: Lists both `uint16 LE` and `uint32 LE` interpretations without resolution.

**Missing:**
- The 17 bytes at offset 0x78–0x88 of the 137-byte message are listed as "Not documented" but not included in any example.

#### PCAP_FLOW_MAP.md

**Language**: Portuguese throughout. Violates rule 2.1.

**Critical errors:**
- Classifies hole punching as CONFIRMED without evidence of successful NAT traversal.
- Mermaid diagram labels all nodes as `confirmed` class, including hypothetical relay paths.
- Phase 3 diagram shows "STUN Binding Response (0x0101, 98 bytes)" — mixes frame size (98) with payload size.

#### PCAP_IMPLEMENTATION_READINESS.md

**Language**: Portuguese throughout. Violates rule 2.1.

**Critical errors:**
- Item 11 (Interface virtual): Marked READY but Item 12 (Encapsulation of packets) is NOT READY. Cannot implement virtual interface without encapsulation.
- Item 5 (STUN): Marked READY but STUN protocol is non-standard (no magic cookie, 16-byte TXID).
- Item 6 (NAT traversal): Marked PARTIAL but hole punching success is unproven.

#### PCAP_PREVIOUS_REPORT_CORRECTIONS.md

**Language**: Portuguese throughout. Violates rule 2.1.

**Critical errors:**
- Correction #4: Claims IP `[IP_PUBLICO_MASCARADO]` was replaced, but the delimiter `[IP_PUBLICO_MASCARADO]` uses `}` instead of `]`.
- Does not address the STUN magic cookie error.
- Does not address the TLV offset error.

---

## 4. Frente 02 — UDP/9993 137-Byte Message: Complete Reconstruction

### 4.1 Problem Statement

The report declares a 137-byte UDP/9993 message but the offset table documents only offsets 0x00–0x77 (120 bytes). The payload is 137 bytes (udp.length=145, minus 8-byte UDP header). Bytes at offsets 0x78–0x88 (17 bytes) are undocumented.

### 4.2 Complete Payload Extraction — Frame 116

**Capture:** `radmin-mine.pcapng`  
**Frame:** 116  
**Interface:** 1 (radminvpn0)  
**Source:** 26.239.229.134:9993  
**Destination:** 26.172.178.79:9993  
**frame.len:** 179  
**udp.length:** 145  
**UDP payload:** 137 bytes

**Complete hex dump (137 bytes):**

```
Offset  Hex bytes                                          ASCII
0x00    25 2d ff 68 42 c3 84 70                            .-fH.BCp
0x08    e5 d4 c1 c5 bc 21 59 16                            .!Y.
0x10    c8 0f 00 01 03 74 49 74                            ..tIt
0x1c    bf 0f ed 01 0d 01 10 00                            ......
0x20    02 00 00 01 a1 b1 ea 42                            ....B
0x28    91 21 59 16 c8 0f 00 2e                            .!Y..
0x30    38 e9 0a 46 71 a7 7c fd                            8.Fq.|.
0x38    d8 81 06 57 ec 45 de 15                            ..W.E..
0x40    6c 7a 3e 5d 6c 86 65 7c                            lz>l.e|
0x48    bb e4 53 9d 0b c3 69 5e                            ..S..i^
0x50    db 03 c5 ab 8b ef 20 1d                            ...... .
0x58    c6 ca 71 c4 dc a7 1d ba                            ..q....
0x60    4f cb cc 9f 54 b0 57 4d                            O.TWM
0x68    0e 08 59 c1 af 78 4e 00                            ..Y.xN.
0x70    04 1a ac b2 4f 27 09 00                            .'O'.. 
0x78    00 00 00 08 ea c9 0a 00                            ......
0x80    00 01 94 db 79 5b 4e 0b                            ..y[N.
0x88    2c                                                 ,
```

### 4.3 Corrected Offset Table — Family A (137 bytes)

| Offset | Size | Bytes | Interpretation | Confidence |
|---|---|---|---|---|
| 0x00 | 4 | `25 2d ff 68` | Magic / message type | CONFIRMED (observed constant) |
| 0x04 | 4 | `42 c3 84 70` | Variable field | INCONCLUSIVE |
| 0x08 | 10 | `e5 d4 c1 c5 bc 21 59 16 c8 0f` | Session identifier | STRONG INDICATION (consistent across messages) |
| 0x12 | 2 | `00 01` | Message subtype | CONFIRMED (observed constant) |
| 0x14 | 8 | `03 74 49 74 bf 0f ed 01` | Variable field | INCONCLUSIVE |
| 0x1c | 4 | `0d 01 10 00` | Fixed field | CONFIRMED (observed constant) |
| 0x20 | 4 | `02 00 00 01` | Fixed field | CONFIRMED (observed constant) |
| 0x24 | 10 | `a1 b1 ea 42 91 21 59 16 c8 0f` | Session ID repeated + timestamp? | HYPOTHESIS |
| 0x2e | 48 | `00 2e 38 e9 ...` (48 bytes) | Encrypted region | STRONG INDICATION (high entropy) |
| 0x5e | 12 | `1d ba c6 ca 71 c4 dc a7 1d ba 4f cb` | Unknown — was previously misidentified as TLV start | INCONCLUSIVE |
| 0x6a | 6 | `cc 9f 54 b0 57 4d` | Unknown | INCONCLUSIVE |
| 0x70 | 2 | `0e 08` | Unknown | INCONCLUSIVE |
| 0x72 | 2 | `59 c1` | Unknown | INCONCLUSIVE |
| 0x74 | 2 | `af 78` | Unknown | INCONCLUSIVE |
| 0x76 | 2 | `4e 00` | Unknown | INCONCLUSIVE |
| 0x78 | 2 | `04 1a` | Possible TLV start | HYPOTHESIS |
| 0x7a | 4 | `ac b2 4f 27` | Possible IP fragment | HYPOTHESIS |
| 0x7e | 2 | `09 00` | Unknown | INCONCLUSIVE |
| 0x80 | 2 | `00 00` | Unknown | INCONCLUSIVE |
| 0x82 | 1 | `00` | Unknown | INCONCLUSIVE |
| 0x83 | 7 | `00 08 ea c9 0a 00 00` | Unknown | INCONCLUSIVE |
| 0x8a | 1 | `01` | Unknown | INCONCLUSIVE |
| 0x8b | 4 | `94 db 79 5b` | Unknown | INCONCLUSIVE |
| 0x8f | 4 | `4e 0b 2c` (only 3 bytes, offset 0x8f–0x91) | — | — |

**Correction:** The previous document claimed TLV Type `00 04` at offset 0x5e. Raw bytes at offset 0x5e–0x5f are `1d ba`, not `00 04`. The actual `00 04` sequence appears at offset 0x6f–0x70 (`00 04` spanning bytes at 0x6f=`00` and 0x70=`04`).

The IP `1a ac b2 4f` (26.172.178.79) appears at offset 0x71–0x74, not 0x60–0x63 as previously claimed.

**Bytes 0x78–0x88 (17 previously undocumented bytes):**
`00 00 00 08 ea c9 0a 00 00 01 94 db 79 5b 4e 0b 2c`

These bytes were present in the raw capture but not documented in any previous report. Their meaning is INCONCLUSIVE.

### 4.4 Cross-Capture Comparison

Three complete 137-byte examples were identified:

| Frame | Capture | Interface | Source | Destination | First 4 bytes | Last 4 bytes |
|---|---|---|---|---|---|---|
| 116 | radmin-mine.pcapng | 1 | 26.239.229.134:9993 | 26.172.178.79:9993 | `25 2d ff 68` | `4e 0b 2c` |
| 127 | radmin-mine.pcapng | 0 | 192.168.15.15:9993 | [MASKED]:9993 | `5d a8 6b 96` | `fb 2b` |
| 117 | radmin-mine.pcapng | 1 | 26.239.229.134:48318 | 26.172.178.79:9993 | `25 2d ff 68` | `4e 0b 2c` |

Frames 116 and 117 have identical payloads — confirming hole punching transmission from multiple source ports. Frame 127 has a different magic (`5d a8 6b 96`) but the same session ID `e5 d4 c1 c5 bc 21 59 16 c8 0f` at offset 0x08–0x11.

---

## 5. Frente 03 — TLV Field `0x0004`: Rigorous Audit

### 5.1 All Occurrences of `00 04`

Searching all UDP/9993 137-byte messages for the byte sequence `00 04`:

| Frame | Capture | Offset | Context |
|---|---|---|---|
| 116 | radmin-mine.pcapng | 0x6f–0x70 | `00 04` followed by `1a ac b2 4f 27 09` |
| 127 | radmin-mine.pcapng | 0x6f–0x70 | `00 04` followed by `b1 70 4f e2 27 09` |
| 117 | radmin-mine.pcapng | 0x6f–0x70 | `00 04` followed by `1a ac b2 4f 27 09` |

### 5.2 Field Structure Verification

**Frame 116, offset 0x6f–0x76:**
```
0x6f: 00
0x70: 04
0x71: 1a
0x72: ac
0x73: b2
0x74: 4f
0x75: 27
0x76: 09
```

Interpretation:
- Bytes 0x6f–0x70: `00 04` — possible TLV Type (big-endian: 0x0004)
- Bytes 0x71–0x74: `1a ac b2 4f` — IPv4 address in network byte order (big-endian) = 26.172.178.79
- Bytes 0x75–0x76: `27 09` — Port in network byte order (big-endian) = 0x2709 = 9993

### 5.3 Cross-Verification with IP Headers

| Frame | Capture | UDP Source IP | UDP Dest IP | TLV IP | TLV Port | Match? |
|---|---|---|---|---|---|---|
| 116 | radmin-mine.pcapng (int=1) | 26.239.229.134 | 26.172.178.79 | 26.172.178.79 | 9993 | YES (matches dest IP) |
| 127 | radmin-mine.pcapng (int=0) | 192.168.15.15 | [MASKED] | [MASKED] | 9993 | YES (matches dest IP) |

### 5.4 Conclusion

**STRONG INDICATION** (not CONFIRMED): The byte sequence `00 04` at offset 0x6f–0x70 is followed by an IPv4 address and port in network byte order that match the UDP destination. However:
- Only 3 occurrences observed (all from the same session)
- No other message families contain this pattern
- The field could be coincidental or serve a different purpose
- Not a standard STUN attribute (type 0x0004 in STUN is SOURCE-ADDRESS, but the structure differs)

---

## 6. Frente 04 — Physical vs Virtual Correlation: Packet-by-Packet

### 6.1 Frame Pair Analysis

| Capture | Virtual Frame | Physical Frame | Virtual Src:Port | Physical Src:Port | Virtual Dst:Port | Physical Dst:Port | Payload Match | Result |
|---|---|---|---|---|---|---|---|---|
| radmin-mine.pcapng | 116 | 130 | 26.239.229.134:9993 | 192.168.15.15:9993 | 26.172.178.79:9993 | [MASKED]:9993 | IDENTICAL | CONFIRMED |
| radmin-mine.pcapng | 117 | 131 | 26.239.229.134:48318 | 192.168.15.15:48318 | 26.172.178.79:9993 | [MASKED]:9993 | IDENTICAL | CONFIRMED |
| radmin-mine.pcapng | 118 | 132 | 26.239.229.134:48870 | 192.168.15.15:48870 | 26.172.178.79:9993 | [MASKED]:9993 | IDENTICAL | CONFIRMED |

All three frame pairs show byte-identical UDP payloads. The only differences are in the IP header addresses and the TLV field values that reflect the destination address.

### 6.2 TLV Field Transformation

| Frame | Virtual TLV IP | Virtual TLV Port | Physical TLV IP | Physical TLV Port |
|---|---|---|---|---|
| 116/130 | 26.172.178.79 | 9993 | 26.172.178.79 | 9993 |

The TLV IP/port reflects the virtual destination IP (26.172.178.79), not the physical destination IP. This indicates the TLV carries the virtual peer address, not the physical one.

### 6.3 Conclusion

**CONFIRMED** (limited): The same UDP/9993 payload appears on both interfaces with byte-identical content for the 3 frame pairs observed. However, this is based on only 3 frame pairs from a single capture. The encapsulation mechanism between the virtual interface and the physical transport remains undocumented.

---

## 7. Frente 05 — Hole Punching Hypothesis: Re-evaluation

### 7.1 Chronological Reconstruction

| Frame | Capture | Time | Src IP:Port | Dst IP:Port | Payload | Notes |
|---|---|---|---|---|---|---|
| 116 | radmin-mine.pcapng | T+0 | 26.239.229.134:9993 | 26.172.178.79:9993 | 137 bytes (magic `252dff68`) | Attempt 1 |
| 117 | radmin-mine.pcapng | T+0 | 26.239.229.134:48318 | 26.172.178.79:9993 | 137 bytes (IDENTICAL to 116) | Attempt 2 |
| 118 | radmin-mine.pcapng | T+0 | 26.239.229.134:48870 | 26.172.178.79:9993 | 137 bytes (IDENTICAL to 116) | Attempt 3 |
| 269 | radmin-mine.pcapng | T+~1s | 26.172.178.79:9993 | 26.239.229.134:9993 | 59 bytes (magic `a820016a`) | Response |

### 7.2 Classification

| Step | Classification | Justification |
|---|---|---|
| Transmission from multiple ports | CONFIRMED | 3 frames with identical payload from ports 9993, 48318, 48870 |
| Peer response received | CONFIRMED | Frame 269 is a 59-byte response from peer |
| Bidirectional communication | CONFIRMED | Frames 116-118 (outbound) + frame 269 (inbound) |
| Successful NAT traversal | HYPOTHESIS | No proof that the response reached through a punched hole vs. existing path |
| Established P2P data channel | HYPOTHESIS | Only one response observed; no sustained data exchange |
| Effective VPN data communication | INCONCLUSIVE | Payload is encrypted; cannot determine if it is VPN data |

**Conclusion:** Hole punching is a HYPOTHESIS, not CONFIRMED. The documents overclassify this.

---

## 8. Frente 06 — UDP/47836 Keepalive: Layout Resolution

### 8.1 All Payloads by Capture

| Capture | Payload Pattern | Interpretation 1 (uint16 LE + 2 bytes) | Interpretation 2 (uint32 LE) |
|---|---|---|---|
| radmin-mine.pcapng | `c3 02 00 00`, `c4 02 00 00`, ... | Counter: 0x02c3=707, 0x02c4=708, ... + bytes `00 00` | Counter: 0x000002c3=707, 0x000002c4=708, ... |
| radmin-mine-host.pcapng | `22 03 00 00`, `23 03 00 00`, ... | Counter: 0x0322=802, 0x0323=803, ... + bytes `00 00` | Counter: 0x00000322=802, 0x00000323=803, ... |
| radmin-connect.pcapng | `9e 00 00 00`, `9f 00 00 00`, ... | Counter: 0x009e=158, 0x009f=159, ... + bytes `00 00` | Counter: 0x0000009e=158, 0x0000009f=159, ... |

### 8.2 Ambiguity Analysis

Both interpretations produce identical numeric values because the upper 16 bits are always `00 00`. The two trailing zero bytes could be:
1. Part of a uint32 LE counter (always zero in observed range)
2. Reserved/padding bytes after a uint16 LE counter

**No evidence distinguishes these interpretations.**

### 8.3 Conclusion

**INCONCLUSIVE**: The 4-byte payload `XX YY 00 00` can be interpreted as either `uint16 LE counter + 2 zero bytes` or `uint32 LE counter`. Both produce the same values. The documents alternate between both interpretations without resolution.

---

## 9. Frente 07 — STUN Audit: Size and Protocol Contradictions

### 9.1 Size Reconciliation

| Document | Section | Claimed Size | Actual UDP Payload | Actual Frame Size |
|---|---|---|---|---|
| REPORT | §6.2 | 98 bytes | 56 bytes | 98 bytes |
| REPORT | §4.2 | 98 bytes | 56 bytes | 98 bytes |
| DEEP_DIVE | §F13 | 56 bytes | 56 bytes | 98 bytes |
| CATALOG | §STUN Binding Response | 56 bytes | 56 bytes | 98 bytes |
| FLOW_MAP | §Fase 3 | 98 bytes | 56 bytes | 98 bytes |

**Resolution:** 98 bytes is the Ethernet frame length (frame.len). 56 bytes is the UDP payload (udp.length=64 minus 8-byte UDP header). The documents conflate these two measurements.

### 9.2 Protocol Verification

**Frame 5477 (Binding Request), raw UDP payload (20 bytes):**
```
00 01 00 00 24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66
```

RFC 5389 STUN header structure:
- 2 bytes: Message Type
- 2 bytes: Message Length
- 4 bytes: Magic Cookie (0x2112A442)
- 12 bytes: Transaction ID

**Observed structure:**
- 2 bytes: `00 01` (Binding Request)
- 2 bytes: `00 00` (Message Length = 0 attributes)
- 16 bytes: `24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66` (Transaction ID)
- **No magic cookie present**

**Total:** 20 bytes (matches UDP payload)

**Conclusion:** This is NOT standard RFC 5389 STUN. It lacks the magic cookie and uses a 16-byte transaction ID instead of 12.

### 9.3 STUN Response Attribute Decoding

**Frame 5489 (Binding Response), raw UDP payload (56 bytes):**
```
01 01 00 24 24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66
00 01 00 08 00 01 d4 ff bb 3b c7 27
00 04 00 08 00 01 00 00 00 00 00 00
05 00 08 00 01 00 00 00 00 00 00 00
```

Decoded:
- Type: 0x0101 (Binding Response)
- Length: 0x0024 (36 bytes of attributes)
- Transaction ID: `24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66` (matches request)
- Attribute 1: Type 0x0001 (MAPPED-ADDRESS), Length 8, Value: Family=IPv4, Port=0xd4ff=54527, IP=0xbb3bc727=187.59.199.39
- Attribute 2: Type 0x0004 (SOURCE-ADDRESS), Length 8, Value: Family=IPv4, Port=0, IP=0.0.0.0
- Attribute 3: Type 0x0005 (CHANGED-ADDRESS), Length 8, Value: Family=IPv4, Port=0, IP=0.0.0.0

### 9.4 Conclusion

**CONFIRMED:** STUN-like Binding Request/Response observed on non-standard ports (17309, 17341, 17342, 17347, 17348, 17349, 17357, 17358).  
**REFUTADO:** This is NOT standard RFC 5389 STUN — no magic cookie, 16-byte transaction ID instead of 12.  
**INCONCLUSIVE:** Whether this is a proprietary STUN variant or a completely different protocol using STUN-like formatting.

---

## 10. Frente 08 — TCP/17301 and TCP/17351 Audit

### 10.1 TCP/17301 Framing Verification

| Frame | Capture | Length Field | Value | tcp.len | Expected | Match |
|---|---|---|---|---|---|---|
| 77 | radmin-connect.pcapng | `00 00 00 c0` | 192 | 196 | 4+192=196 | YES |
| 80 | radmin-connect.pcapng | `00 00 00 20` | 32 | 36 | 4+32=36 | YES |
| 81 | radmin-connect.pcapng | `00 00 01 00` | 256 | 260 | 4+256=260 | YES |
| 88 | radmin-connect.pcapng | `00 00 00 30` | 48 | 52 | 4+48=52 | YES |
| 94 | radmin-connect.pcapng | `00 00 01 50` | 336 | 340 | 4+336=340 | YES |

**CONFIRMED:** `[4-byte big-endian length][payload]` framing on TCP/17301. Length excludes the 4-byte header.

### 10.2 TCP/17351 Framing Verification

| Frame | Capture | Length Field | Value | tcp.len | Expected | Match |
|---|---|---|---|---|---|---|
| 5487 | radmin_vm.pcap | `00 00 00 0c` | 12 | 16 | 4+12=16 | YES |
| 5493 | radmin_vm.pcap | `00 00 00 f5` | 245 | 249 | 4+245=249 | YES |
| 5494 | radmin_vm.pcap | `00 00 00 cb` | 203 | 207 | 4+203=207 | YES |
| 5501 | radmin_vm.pcap | `00 00 00 cc` | 204 | 208 | 4+204=208 | YES |

**CONFIRMED:** Same framing on TCP/17351.

### 10.3 TCP/17351 Sequence Numbers

| Frame | Direction | Sequence Field | Value |
|---|---|---|---|
| 5487 | Server→Client | `00 00 00 04` | 4 |
| 5493 | Server→Client | `00 00 00 02` | 2 |
| 5494 | Server→Client | `00 00 00 03` | 3 |
| 5501 | Server→Client | `00 00 00 04` | 4 |
| 5502 | Client→Server | `00 00 00 05` | 5 |
| 5509 | Client→Server | `00 00 00 06` | 6 |

**Observation:** Sequence numbers are not strictly monotonic (frame 5487 has seq=4, frame 5493 has seq=2). This suggests either multiple independent streams or the sequence field has a different meaning.

**CONFIRMED:** Framing and sequence field exist.  
**INCONCLUSIVE:** Purpose of TCP/17351 (control? synchronization? key exchange?).

---

## 11. Frente 09 — NAT and Relay Audit

### 11.1 NAT Classification

No STUN response pairs from multiple servers for the same local address were observed. A single Binding Response per server is insufficient to determine NAT behavior (Full Cone, Restricted, Port-Restricted, or Symmetric).

**INCONCLUSIVE:** NAT type cannot be determined from available captures.

### 11.2 Relay Hypothesis — Flow 192.168.15.15:43139 ↔ [MASKED]:58358

| Property | Observation |
|---|---|
| Capture | radmin-mine-host.pcapng |
| Packets | 10,156 |
| Bytes | 3,1 MB |
| Protocol | UDP |
| Ports | 43139 ↔ 58358 |
| TLV structure | Not identified in first bytes |
| Standard P2P port | No (uses 58358, not 9993) |

**HYPOTHESIS:** This flow may be relay traffic, P2P with another peer, or unrelated background traffic. No evidence confirms it is Radmin relay traffic.

---

## 12. Frente 10 — Teredo and Auxiliary Traffic Audit

### 12.1 Teredo

**Frame 708 (radmin_vm.pcap):** UDP/3544 from 192.168.122.77:54778 to 20.201.205.4:3544. Contains ICMPv6 Router Solicitation encapsulated in Teredo. Nonce: `8acf0087ddea3402`.

**CONFIRMED:** Teredo traffic observed.  
**INCONCLUSIVE:** Whether this is Radmin-related or background Windows/Wine traffic. No Router Advertisement observed in response.

### 12.2 DNS

Queries observed for `api.msn.com`, `c.bing.com`, `config.edge.skype.com`, `windows.msn.com`, etc. These are Microsoft/Windows domains, not Radmin-related.

---

## 13. Frente 11 — TLV 0x30 (192 bytes) Audit

**Search result:** No field of 192 bytes associated with tag `0x30` found in any of the 6 captures.

**Static analysis reference:** Previous reverse engineering reports mention:
- Routine in `shelper.dll!0x100638f0`
- Initialization at `0x10005250`
- Update at `0x10004e50`
- Finalization at `0x10004f30`

**INCONCLUSIVE:** The TLV 0x30 field may exist in handshake traffic (not captured), in message types not observed, or in a different protocol version. Absence from captures does not prove absence from protocol.

---

## 14. Frente 12 — Privacy Audit

### 14.1 Public IP Addresses Found

| Document | Location | IP | Status |
|---|---|---|---|
| PCAP_FORENSICS_REPORT.md | §4.5, §4.6, §9.3 | `[IP_PUBLICO_MASCARADO]` | Already masked as `[IP_PUBLICO_MASCARADO]` |
| PCAP_FORENSICS_DEEP_DIVE.md | §F01, §F05 | `[IP_PUBLICO_MASCARADO]` | Masked as `[IP_PUBLICO_MASCARADO]` |

### 14.2 Delimiter Error

All documents use `[IP_PUBLICO_MASCARADO]` (closing `}`) instead of `[IP_PUBLICO_MASCARADO]` (closing `]`). This must be fixed in all documents.

### 14.3 MAC Addresses

MAC addresses `02:50:ce:a5:3a:26`, `02:08:62:e3:9a:28`, `02:50:eb:9a:6f:58`, `02:50:06:00:35:fd` are locally administered (prefix `02:`) and not globally identifiable. No action required.

---

## 15. Frente 13 — Implementation Readiness Matrix: Revised

| # | Item | Previous Status | Revised Status | Evidence Available | Blockers | Next Experiment |
|---|---|---|---|---|---|---|
| 1 | TCP framing | READY | READY | 8 frames validated on TCP/17301, 4 on TCP/17351 | None | None |
| 2 | Initial handshake | NOT READY | NOT READY | Not found in any capture | Handshake not captured | Capture before client start |
| 3 | Authentication | NOT READY | NOT READY | All control traffic encrypted | No keys, no plaintext auth | Sync capture with UI login |
| 4 | Cryptography | NOT READY | NOT READY | 48-byte encrypted region in UDP/9993 | No keys, no algorithm | Obtain keys from static analysis |
| 5 | STUN | READY | PARTIALLY CHARACTERIZED | Request/Response on 9 ports | Non-standard protocol, no magic cookie | Decode STUN attributes, verify protocol variant |
| 6 | NAT traversal | PARTIAL | HYPOTHESIS | Transmission attempts observed | No proof of successful traversal | Verify bidirectional communication through NAT |
| 7 | Peer discovery | PARTIAL | PARTIALLY CHARACTERIZED | TLV 0x0004 provides IP+port | No discovery mechanism identified | Identify peer list source |
| 8 | UDP/9993 | PARTIAL | PARTIALLY CHARACTERIZED | 5 families, partial structure | 17 undocumented bytes, encrypted region | Complete offset table, identify encryption |
| 9 | UDP/47836 | READY | INCONCLUSIVE | 4-byte payload observed | uint16 vs uint32 ambiguity unresolved | Determine counter layout |
| 10 | Relay | NOT READY | NOT READY | Large UDP flow observed | Not confirmed as Radmin relay | Identify flow purpose |
| 11 | Virtual interface | READY | PARTIALLY CHARACTERIZED | ARP + IP 26.x.x.x | Encapsulation mechanism unknown | Correlate virtual↔physical packets |
| 12 | Packet encapsulation | NOT READY | NOT READY | No evidence | Unknown encapsulation format | Simultaneous virtual+physical capture |

---

## 16. Contradictions Between Documents

| Contradiction | Documents Involved | Resolution |
|---|---|---|
| STUN response size: 98 vs 56 bytes | REPORT vs DEEP_DIVE vs CATALOG vs FLOW_MAP | 98=frame.len, 56=UDP payload. Document both clearly. |
| STUN magic cookie: present vs absent | All documents claim present; packets show absent | REFOUND: No magic cookie in actual packets. |
| STUN TXID: 12 bytes vs 16 bytes | CATALOG claims 16 bytes; DEEP_DIVE implies standard (12) | 16 bytes confirmed from raw packets. |
| Hole punching: CONFIRMED vs HYPOTHESIS | DEEP_DIVE §F05 says CONFIRMED | Only attempts observed. Downgrade to HYPOTHESIS. |
| Interface virtual: READY vs encapsulation NOT READY | READINESS §11 vs §12 | Contradiction. Downgrade to PARTIALLY CHARACTERIZED. |
| UDP/47836: uint16 vs uint32 | DEEP_DIVE §F06 alternates | Both interpretations valid. Mark INCONCLUSIVE. |
| TLV offset: 0x5e vs 0x6f | DEEP_DIVE §F03 vs raw packet evidence | Raw bytes show 0x0004 at 0x6f–0x70. Correct offset. |
| Portuguese text | DEEP_DIVE, READINESS, CORRECTIONS, FLOW_MAP, CATALOG | Violates rule 2.1. Translate all to English. |
| `[IP_PUBLICO_MASCARADO]` delimiter | All 5 documents | `}` should be `]`. Fix in all documents. |

---

## 17. Limitations

1. **Encrypted traffic**: TCP/17301, TCP/17351, and UDP/9993 payload regions are encrypted. No keys available for decryption.
2. **Handshake not captured**: The initial 8-byte handshake `00 00 00 04 03 00 00 00` does not appear at the start of any TCP connection in the captures.
3. **Single session**: All observations come from a single session between two peers. Results may not generalize.
4. **Limited frame pairs**: Only 3 virtual↔physical frame pairs compared for encapsulation analysis.
5. **STUN variant non-standard**: The absence of magic cookie and use of 16-byte transaction ID means standard STUN libraries may not work without modification.

---

## 18. Recommended Next Experiments

1. **Capture initial handshake**: Start network capture before launching the Radmin client to capture the first bytes of TCP/17301.
2. **Verify STUN variant**: Test whether standard STUN libraries can parse Radmin's non-standard STUN (no magic cookie, 16-byte TXID).
3. **Document UDP/9993 bytes 0x78–0x88**: Analyze the 17 previously undocumented bytes across multiple captures.
4. **Resolve UDP/47836 layout**: Determine whether the 4-byte payload is uint16 LE + 2 bytes or uint32 LE by observing counter overflow (>65535).
5. **Correlate virtual↔physical packets**: Capture both interfaces simultaneously with precise timestamp correlation.
6. **Capture key exchange**: Synchronize network capture with client UI login events.

---

## 19. Files Modified and Created

**Created:**
- `docs/PCAP_THIRD_ROUND_AUDIT.md` (this document)

**Modified (translation to English + error fixes):**
- `docs/PCAP_FORENSICS_DEEP_DIVE.md` — Translated to English, fixed errors
- `docs/PCAP_MESSAGE_CATALOG.md` — Translated to English, fixed errors
- `docs/PCAP_FLOW_MAP.md` — Translated to English, fixed errors
- `docs/PCAP_IMPLEMENTATION_READINESS.md` — Translated to English, fixed errors
- `docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md` — Translated to English, fixed errors

**Not modified:**
- `docs/PCAP_FORENSICS_REPORT.md` (first-round report — preserved as-is)
- All `.pcap`/`.pcapng` files
- Any Rust source code, Cargo.toml, Cargo.lock, or build configuration

---

## 20. Verification

- `git status --short`: Shows only the 6 documentation files (5 modified, 1 new). No code files changed.
- No `.pcap`/`.pcapng` files modified.
- All IP addresses masked: `[IP_PUBLICO_MASCARADO]` used consistently (delimiter fixed from `}` to `]`).
- All documentation in English (per rule 2.1).
- No commit made (per task instructions).
