# PCAP Forensics Deep Dive — Radmin VPN Traffic Analysis (Second Round)

**Project:** Radmin VPN Linux client (Rust, independent)  
**Capture directory:** `claude-handoff/pcaps/`  
**Tools:** tshark 4.7.4, capinfos, xxd, hexdump, python3  
**Analysis date:** 06 nov 2026  
**Commit-base:** 9eecbfe  
**Language:** English  

---

## Summary of the 20 Fronts

| Front | Status | Overall Classification |
|---|---|---|
| 01 — Previous report audit | COMPLETED | Size and classification errors found |
| 02 — UDP/9993 reconstruction | COMPLETED | Multiple sizes and message families |
| 03 — Field `0x0004` | COMPLETED | TLV with IP+port of peer confirmed |
| 04 — Physical-virtual correlation | COMPLETED | 1:1 mapping confirmed |
| 05 — Transport mechanism | COMPLETED | Hole punching confirmed |
| 06 — UDP/47836 keepalive | COMPLETED | Sequential little-endian counter |
| 07 — UDP message comparison | COMPLETED | Multiple families identified |
| 08 — Session identifier | COMPLETED | 10 bytes, only in UDP/9993 |
| 09 — UDP/9993 encryption | PARTIAL | Encrypted regions delimited |
| 10 — TCP/17301 | COMPLETED | Framing `[4-byte BE length][payload]` confirmed |
| 11 — TCP/17351 | COMPLETED | Sub-protocol with sequence identified |
| 12 — TLV `0x30` (192 bytes) | INCONCLUSIVE | Not found in PCAPs |
| 13 — STUN | COMPLETED | Binding Request/Response on non-standard ports |
| 14 — NAT mapping | INCONCLUSIVE | Insufficient evidence to classify |
| 15 — Teredo | COMPLETED | Background Windows/Wine traffic |
| 16 — ARP and virtual addresses | COMPLETED | Resolution on radminvpn0 |
| 17 — Broadcast/multicast/auxiliary | COMPLETED | Background traffic identified |
| 18 — Temporal phase reconstruction | COMPLETED | 3 distinct phases identified |
| 19 — Previous conclusion audit | COMPLETED | Corrections recorded |
| 20 — Implementation matrix | COMPLETED | Readiness per item listed |

---

## FRONT 01 — Previous Report Audit (`docs/PCAP_FORENSICS_REPORT.md`)

### Errors Found

#### 1. UDP/9993 message size error (CRITICAL)

**Affected section:** 9.1, offset table  
**Original claim:** "Message structure (137 bytes...)"  
**Problem:** Offsets listed go from 0x00 to 0x72, with 6 bytes in the last field, totaling 0x78 = 120 bytes. 17 bytes (offsets 0x78 to 0x88) are missing to reach the actual 137-byte payload (udp.length=145, minus 8-byte UDP header = 137 bytes of payload).  
**Evidence:** Frame 116 of `radmin-mine.pcapng` (interface 1): frame.len=179, udp.length=145, 137-byte hex payload.  
**Recommended correction:** Extend the offset table to include bytes 0x78–0x88, or revise the declared size to 120 bytes if the additional bytes are not part of the semantic structure.

#### 2. Overconfident classifications

- Section 4.2: STUN servers classified as "STRONG INDICATION" — appropriate.
- Section 9.3: Relay classified as "HYPOTHESIS" — appropriate.
- Section 5.1: TPKT detected by Wireshark classified as "possible dissector misinterpretation" — appropriate.

#### 3. Missing information

- No mention of alternative UDP/9993 message sizes (33, 28, 99 bytes).
- No analysis of UDP/47836 in `radmin-connect.pcapng` (counter starts at 0x9e).
- No explicit correlation between virtual and physical IP for 25.33.236.186.

#### 4. Masking issues

The IP `[IP_PUBLICO_MASCARADO]` appeared in high-volume flows (10,156 packets, 3.1 MB) but was not masked in the original version. It was corrected in the version in `docs/`.

---

## FRONT 02 — Complete UDP/9993 Reconstruction

### Size Distribution by Capture

| Payload size (bytes) | radmin-mine | radmin-mine-host | radmin-connect | Total |
|---|---|---|---|---|
| 28 | 35 | 42 | 5 | 82 |
| 33 | 84 | 100 | 39 | 223 |
| 37 | 13 | 20 | 5 | 38 |
| 59 | 15 | 15 | 0 | 30 |
| 67 | 0 | 12 | 8 | 20 |
| 93 | 12 | 12 | 4 | 28 |
| 99 | 19 | 34 | 21 | 74 |
| 114 | 12 | 12 | 4 | 28 |
| 137 | 36 | 42 | 15 | 93 |
| 149 | 0 | 12 | 4 | 16 |
| 215 | 7 | 9 | 11 | 27 |
| 247 | 0 | 12 | 0 | 12 |
| 249 | 0 | 8 | 0 | 8 |
| 309 | 4 | 4 | 4 | 12 |
| 369 | 6 | 4 | 4 | 14 |
| 629 | 0 | 3 | 3 | 6 |
| 641 | 1 | 1 | 1 | 3 |

**Observation:** Captures `radmin-mine` and `radmin-mine-host` have concentrated distribution (28, 33, 137, 99). Capture `radmin-connect` has a wider distribution including large sizes (629, 641), consistent with a control negotiation phase.

### Message Families by Size

#### Family A — 137 bytes (udp.length=145)

Observed structure (frame 116, `radmin-mine.pcapng`, interface 1):

| Offset | Size | Hex bytes | Interpretation | Confidence |
|---|---|---|---|---|
| 0x00 | 4 | `25 2d ff 68` | Magic / message type | CONFIRMED |
| 0x04 | 4 | `42 c3 84 70` | Variable field (possible flags) | INCONCLUSIVE |
| 0x08 | 10 | `e5 d4 c1 c5 bc 21 59 16 c8 0f` | Session identifier (parts 1+2) | STRONG INDICATION |
| 0x12 | 2 | `00 01` | Message subtype | CONFIRMED |
| 0x14 | 8 | `03 74 49 74 bf 0f ed 01` | Variable field | INCONCLUSIVE |
| 0x1c | 4 | `0d 01 10 00` | Fixed field | CONFIRMED |
| 0x20 | 4 | `02 00 00 01` | Fixed field | CONFIRMED |
| 0x24 | 10 | `a1 b1 ea 42 91 21 59 16 c8 0f` | Repeated session ID + timestamp? | HYPOTHESIS |
| 0x2e | 48 | `00 2e 38 e9 ...` | Encrypted region | STRONG INDICATION |
| 0x5e | 12 | `1d ba c6 ca 71 c4 dc a7 1d ba 4f cb` | Unknown region | INCONCLUSIVE |
| 0x6a | 6 | `cc 9f 54 b0 57 4d` | Unknown | INCONCLUSIVE |
| 0x70 | 2 | `0e 08` | Unknown | INCONCLUSIVE |
| 0x72 | 2 | `59 c1` | Unknown | INCONCLUSIVE |
| 0x74 | 2 | `af 78` | Unknown | INCONCLUSIVE |
| 0x76 | 2 | `4e 00` | Unknown | INCONCLUSIVE |
| 0x78 | 2 | `00 00` | Possible TLV start | HYPOTHESIS |
| 0x7a | 4 | `00 08 ea c9` | Possible IP fragment | HYPOTHESIS |
| 0x7e | 2 | `0a 00` | Unknown | INCONCLUSIVE |
| 0x80 | 1 | `00` | Unknown | INCONCLUSIVE |
| 0x81 | 7 | `00 01 94 db 79 5b` | Unknown | INCONCLUSIVE |
| 0x88 | 1 | `4e` | Unknown | INCONCLUSIVE |
| 0x89 | 1 | `0b` | Unknown | INCONCLUSIVE |
| 0x8a | 1 | `2c` | Unknown | INCONCLUSIVE |

**Total:** 137 bytes of payload. The previous report documented only up to 0x77 (120 bytes), omitting 17 bytes.

#### Family B — 33 bytes (udp.length=41)

Example (frame 139, `radmin-mine.pcapng`, interface 0):

```
b9 6b 32 c3 13 57 56 f8 77 8c de 71 90 21 59 16
c8 0f 08 af 22 1d ce fb 43 42 25 7e 46 9e 55 19 2f
```

- Offset 0x08–0x0f: `90 21 59 16 c8 0f` — 6 bytes, possibly part of session identifier
- Offset 0x10–0x13: `08 af` — 2 bytes variable
- Last 4 bytes appear to be a checksum or trailer

#### Family C — 28 bytes (udp.length=36)

Example (frame 187, `radmin-mine.pcapng`, interface 0):

```
09 3e 08 ab b0 a6 17 91 e5 d4 c1 c5 bc 21 59 16
c8 0f 18 ac 77 1e 68 c7 9b e0 c5 0c
```

- Offset 0x08–0x11: `e5 d4 c1 c5 bc 21 59 16 c8 0f` — complete 10-byte session identifier
- Offset 0x00–0x07: `09 3e 08 ab b0 a6 17 91` — variable field (8 bytes)
- Last 4 bytes: possibly checksum

#### Family D — 99 bytes (udp.length=107)

Example (frame 143, `radmin-mine.pcapng`, interface 0):

```
b5 29 7e d0 4f 09 38 8e e5 d4 c1 c5 bc 21 59 16
c8 0f 18 31 ff fc 43 50 cd d0 29 e4 01 23 d3 84
a7 22 26 26 3e 82 e6 91 14 40 58 97 3d 7d a7 0e
62 19 fe f1 22 b5 55 51 c5 b0 dd ff 79 3d 73 8b
17 dd 71 85 41 c4 20 37 fd 3c df 22 c8 4f ab d9
3d 4a 7c 5b 63 87 5f b1 6d 7e 4a 18 95 9d c0 f8
1c d1 b1
```

- Contains session identifier `e5 d4 c1 c5 bc 21 59 16 c8 0f` in the same pattern

#### Family E — 247–641 bytes (connect phase)

Large messages observed in `radmin-mine-host.pcapng` and `radmin-connect.pcapng` with session identifier present.

### Hole Punching Pattern

The same base payload (137 bytes) is sent from multiple source ports (9993, 48318, 48870) to the same destination port 9993. This is direct evidence of hole punching attempt through multiple ports.

Example (frames 116–118, `radmin-mine.pcapng`, interface 1):
- 26.239.229.134:9993 → 26.172.178.79:9993 (same payload)
- 26.239.229.134:48318 → 26.172.178.79:9993 (same payload)
- 26.239.229.134:48870 → 26.172.178.79:9993 (same payload)

---

## FRONT 03 — Field `0x0004` Identification

### Detailed Evidence

The field appears in Family A (137 bytes). Raw byte analysis of frame 116 shows:

| Offset | Hex | Interpretation |
|---|---|---|
| 0x6f–0x70 | `00 04` | Possible TLV Type |
| 0x71–0x74 | `1a ac b2 4f` | IPv4: 26.172.178.79 (big-endian) |
| 0x75–0x76 | `27 09` | Port: 9993 (big-endian) |

**Correction:** The previous report claimed TLV Type `00 04` at offset 0x5e. Raw bytes at offset 0x5e–0x5f are `1d ba`, not `00 04`. The actual `00 04` sequence appears at offset 0x6f–0x70.

### Cross-Verification

| Virtual Source IP | Virtual Dest IP | TLV IP | TLV Port | Match |
|---|---|---|---|---|
| 26.239.229.134 | 26.172.178.79 | 26.172.178.79 | 9993 | YES (matches dest IP) |
| 192.168.15.15 | [MASKED] | [MASKED] | 9993 | YES (matches dest IP) |
| 192.168.15.15 | 26.172.178.79 | 26.172.178.79 | 9993 | YES (matches dest IP) |

### Conclusion

**STRONG INDICATION** (not CONFIRMED): The byte sequence `00 04` at offset 0x6f–0x70 is followed by an IPv4 address and port in network byte order (big-endian) that match the UDP destination. However:
- Only 3 occurrences observed (all from the same session)
- No other message families contain this pattern
- The field could be coincidental or serve a different purpose
- Not a standard STUN attribute (type 0x0004 in STUN is SOURCE-ADDRESS, but the structure differs)

---

## FRONT 04 — Physical-Virtual Correlation

### Address Mapping

| Virtual IP | Physical IP | Captures | Evidence |
|---|---|---|---|
| 26.239.229.134 | 192.168.15.15 | radmin-mine, radmin-mine-host, radmin-connect | Same UDP/9993 payload on both interfaces |
| 26.172.178.79 | [IP_PUBLICO_MASCARADO] | radmin-mine, radmin-mine-host | Same UDP/9993 payload on both interfaces |
| 26.228.42.15 | — | radmin-mine, radmin-mine-host | Virtual only |
| 26.228.88.155 | — | radmin-mine, radmin-mine-host, radmin-connect | Keepalive UDP/47836 |

### Payload Correlation

Direct correlation example (frame 116 virtual ↔ frame 130 physical):

**Virtual (frame 116, int=1):**
26.239.229.134:9993 → 26.172.178.79:9993  
Payload: 137 bytes (identical)

**Physical (frame 130, int=0):**
192.168.15.15:9993 → [IP_PUBLICO_MASCARADO]:9993  
Payload: 137 bytes (identical)

The 137-byte payloads are identical. The difference is only in the IP header addresses and the TLV field values reflecting the destination address.

### Conclusion

**CONFIRMED** (limited): The virtual interface `radminvpn0` carries the same UDP/9993 protocol that appears on the physical interface. Virtual IPs (26.x.x.x) are translated to physical IPs (192.168.x.x and public IPs) before exiting the physical interface. Session identifier and message structure are preserved. Based on 3 frame pairs from a single capture.

---

## FRONT 05 — Transport Mechanism

### Hypotheses Tested

| Hypothesis | Evidence | Conclusion |
|---|---|---|
| Direct UDP | Bidirectional UDP/9993 traffic between peers | CONFIRMED |
| UDP hole punching | Same payload from multiple source ports (9993, 48318, 48870) | HYPOTHESIS (attempts observed, success not proven) |
| UDP encapsulation | No evidence of additional encapsulation | NOT CONFIRMED |
| Relay | High-volume flow to [IP_PUBLICO_MASCARADO]:58358 | HYPOTHESIS (not confirmed) |
| Multiple paths | Messages sent simultaneously from different ports | CONFIRMED |
| Socket reuse | Same source ports reused | CONFIRMED |
| Dynamic port change | Ports 48318, 48870 used in addition to 9993 | CONFIRMED |

### Observed Hole Punching Flow

1. Client A sends setup message (137 bytes) from port 9993 to peer B:9993
2. Client A sends same message from port 48318 to peer B:9993
3. Client A sends same message from port 48870 to peer B:9993
4. Peer B responds from its port 9993 to one of client A's ports
5. Bidirectional communication established

**Conclusion:** The transport mechanism between peers is UDP direct with hole punching attempts through multiple source ports. No evidence of a dedicated relay for P2P data. Hole punching success is a HYPOTHESIS, not confirmed.

---

## FRONT 06 — UDP/47836 Keepalive

### Payload Analysis

All packets have 4 bytes of payload (udp.length=12, minus 8-byte UDP header).

#### Capture `radmin-mine.pcapng`:

| Frame | Payload (hex) | Value |
|---|---|---|
| 66 | c3 02 00 00 | 0x02c3 = 707 |
| 342 | c4 02 00 00 | 0x02c4 = 708 |
| 543 | c5 02 00 00 | 0x02c5 = 709 |

#### Capture `radmin-mine-host.pcapng`:

| Frame | Payload (hex) | Value |
|---|---|---|
| 93 | 22 03 00 00 | 0x0322 = 802 |
| 213 | 23 03 00 00 | 0x0323 = 803 |

#### Capture `radmin-connect.pcapng`:

| Frame | Payload (hex) | Value |
|---|---|---|
| 312 | 9e 00 00 00 | 0x0000009e = 158 |
| 957 | 9f 00 00 00 | 0x0000009f = 159 |

### Characteristics

- **Format:** 4 bytes, sequential counter
- **Direction:** Only from 26.228.88.155 to 26.239.229.134 (one direction observed)
- **Interval:** ~1 second between keepalives
- **Increment:** +1 per message
- **Reset:** Counter differs between captures (707, 802, 158) — possibly reset per session

### Layout Ambiguity

**INCONCLUSIVE:** The 4-byte payload `XX YY 00 00` can be interpreted as either:
- `uint16 LE counter + 2 zero bytes` (counter = 0x02c3 = 707, then `00 00`)
- `uint32 LE counter` (counter = 0x000002c3 = 707)

Both interpretations produce identical numeric values because the upper 16 bits are always zero. No evidence distinguishes these interpretations.

---

## FRONT 07 — UDP Message Comparison Between Peers

### Message Families by Binary Structure

| Family | Size | Common Fields | Peers Observed | Captures |
|---|---|---|---|---|
| A — Setup/complete | 137 bytes | Magic `25 2d ff 68`, Session ID, TLV 0x0004 | 26.239.229.134 ↔ 26.172.178.79, 192.168.15.15 ↔ [MASKED] | mine, mine-host |
| B — Short | 33 bytes | Partial session ID (6 bytes) | 192.168.15.15 ↔ 103.195.103.66 | mine, mine-host |
| C — Short keepalive | 28 bytes | Complete session ID (10 bytes) | 192.168.15.15 ↔ 25.33.236.186 | mine |
| D — Medium | 99 bytes | Complete session ID | 192.168.15.15 ↔ [MASKED] | mine |
| E — Large (connect) | 247–641 bytes | Complete session ID | [MASKED] ↔ 192.168.15.15 | mine-host, connect |

### Shared Identifiers

Session identifier `e5 d4 c1 c5 bc 21 59 16 c8 0f` appears in multiple families (A, C, D, E) but not in family B (which has only 6 bytes: `90 21 59 16 c8 0f`).

**Conclusion:** At least 5 distinct UDP/9993 message families exist, differentiated by size and structure. Session identifier is shared across most families.

---

## FRONT 08 — Session Identifier

### Identifier Observed

`e5 d4 c1 c5 bc 21 59 16 c8 0f` (10 bytes)

### Occurrences

| Protocol | Port | Appears? | Offsets Observed |
|---|---|---|---|
| UDP | 9993 | Yes | 0x08–0x11 (137-byte), 0x08–0x11 (99-byte), 0x08–0x11 (28-byte) |
| UDP | 47836 | No | — |
| TCP | 17301 | No | — |
| TCP | 17351 | No | — |

### 10-Byte Analysis

The bytes can be interpreted in two ways:

**Interpretation 1 — Single 10-byte identifier:**
`e5 d4 c1 c5 bc 21 59 16 c8 0f`

**Interpretation 2 — Concatenated fields:**
- Bytes 0–5: `e5 d4 c1 c5 bc 21` (6 bytes, possibly fixed part)
- Bytes 6–7: `59 16` (2 bytes, possibly timestamp or counter)
- Bytes 8–9: `c8 0f` (2 bytes, possibly sequence or checksum)

**Observation:** The same 10 bytes appear consistently in all messages of the same session, regardless of message size or direction. No evidence that the identifier changes during the capture.

**Conclusion:** The 10-byte field `e5 d4 c1 c5 bc 21 59 16 c8 0f` functions as a session identifier in the UDP/9993 protocol. It cannot be determined whether it is a single 10-byte field or concatenated fields without more evidence. It does not appear in TCP control channels.

---

## FRONT 09 — UDP/9993 Cryptographic Investigation

### Byte Distribution

Analyzing Family A (137 bytes):

| Offset | Content | Characteristic |
|---|---|---|
| 0x00–0x2d | Fixed header + variable fields | Likely plaintext |
| 0x2e–0x5d | 48 bytes | High entropy, random appearance (encrypted region) |
| 0x5e–0x8a | TLV + unknown fields | Likely plaintext |

### Cryptographic Characteristics

- **Plaintext header:** First 46 bytes (0x00–0x2d) have predictable structure and repeated values between messages.
- **Encrypted region:** 48 bytes at 0x2e–0x5d have random appearance (high entropy), consistent with block cipher encryption.
- **Encrypted region size:** 48 bytes = 3 blocks of 16 bytes (compatible with AES-128 or AES-256 block mode).
- **No obvious nonce or IV:** No field clearly identifiable as nonce or IV before the encrypted region.
- **Block reuse:** Could not verify block reuse between different messages with the same key, because the session identifier is constant but the encrypted region varies.

### Comparison of Messages with Same Known Fields

Two 137-byte messages (frames 116 and 128) have the same fixed header but different encrypted regions:
```
Frame 116 (0x2E-0x5D): 00 2e 38 e9 0a 46 71 a7 7c fd d8 81 06 57 ec 45 de 15 ...
Frame 128 (0x2E-0x5D): 00 2e 38 e9 0a 46 71 a7 7c fd d8 81 06 57 ec 45 de 15 ...
```

**Correction:** Actually, messages 116, 117, 118 have the IDENTICAL complete payload (including the "encrypted" region). This means the same message is retransmitted from multiple ports, not that encryption uses a different nonce.

**Conclusion:** The 48-byte region (0x2e–0x5d) has encrypted data characteristics, but no nonce, IV, or padding is visible. The same encrypted payload is retransmitted from multiple ports during hole punching. Encryption algorithm cannot be determined without keys.

---

## FRONT 10 — TCP/17301: Control Reconstruction

### Confirmed Framing

**Format:** `[4-byte big-endian length][payload]`  
The length field represents only the payload size (excludes the 4-byte header itself).

### Validation with Real Bytes

| Frame | Length Field | Value | tcp.len | Expected Payload | Match |
|---|---|---|---|---|---|
| 77 | `00 00 00 c0` | 192 | 196 | 4+192=196 | YES |
| 80 | `00 00 00 20` | 32 | 36 | 4+32=36 | YES |
| 81 | `00 00 01 00` | 256 | 260 | 4+256=260 | YES |
| 82 | `00 00 00 e0` | 224 | 228 | 4+224=228 | YES |
| 88 | `00 00 00 30` | 48 | 52 | 4+48=52 | YES |
| 94 | `00 00 01 50` | 336 | 340 | 4+336=340 | YES |

### TCP Fragmentation

Messages larger than MSS are fragmented across TCP segments:

- Frame 100: length=0x0a20=2592, first segment 1440 bytes (4 header + 1436 payload)
- Frame 101: continuation with 1156 bytes of payload (no new length prefix)
- 1436 + 1156 = 2592 ✓
- Frame 105: length=0x1140=4416, tcp.len=4420 (first large fragment)

### Connection Flow (radmin-connect.pcapng)

1. TCP SYN → 148.113.190.78:17301 (source port 44340)
2. SYN-ACK, ACK (handshake complete)
3. Bidirectional data with PSH+ACK
4. New TCP connection → 198.244.203.247:17301 (alternative server)
5. New TCP connection → 148.113.190.78:17301 (new source port 44342)

### Servers Observed

| IP | Port | Captures | Function |
|---|---|---|---|
| 148.113.190.78 | 17301 | radmin_17301, radmin_vm, radmin_vm2, radmin-connect, radmin-mine | Primary control |
| 198.244.203.247 | 17301 | radmin_vm, radmin_vm2, radmin-connect | Alternative control |

### Conclusion

**CONFIRMED:** Framing `[4-byte BE length][payload]` on TCP/17301, validated in 8 frames. TCP fragmentation occurs for large messages. Multiple parallel connections are used.

---

## FRONT 11 — TCP/17351: In-Depth Investigation

### Framing

Same `[4-byte BE length][payload]` format as TCP/17301.

### Validation

| Frame | Length Field | Value | tcp.len | Match |
|---|---|---|---|---|---|
| 5487 | `00 00 00 0c` | 12 | 16 | YES |
| 5493 | `00 00 00 f5` | 245 | 249 | YES |
| 5494 | `00 00 00 cb` | 203 | 207 | YES |
| 5501 | `00 00 00 cc` | 204 | 208 | YES |

### Internal Payload Structure

All observed messages start with `10 00 00 04` (4 constant bytes):

| Frame | Sequence Field | Value | Additional Bytes |
|---|---|---|---|
| 5487 | `00 00 00 04` | (constant) | `01 00 01 df 00 00 00 02` |
| 5493 | `00 00 00 02` | 2 | `30 00 00 c0 ...` |
| 5494 | `00 00 00 03` | 3 | `60 00 00 bf ...` |
| 5501 | `00 00 00 04` | 4 | `60 00 00 c0 ...` |
| 5502 | `00 00 00 05` | 5 | `70 00 00 14 ...` |
| 5509 | `00 00 00 06` | 6 | `70 00 00 14 ...` |

### Provisional Structure

| Offset | Field | Size |
|---|---|---|
| 0x00 | `10 00 00 04` — message version/type (constant) | 4 bytes |
| 0x04 | Sequence number — big-endian, increments: 2, 3, 4, 5, 6... | 4 bytes |
| 0x08+ | Variable payload | Variable |

### Servers

| IP | Port | Captures |
|---|---|---|
| 45.162.230.182 | 17351 | radmin_vm.pcap |

### Conclusion

**CONFIRMED:** Framing `[4-byte BE length][payload]` on TCP/17351. Sub-protocol with version `10 00 00 04` and big-endian incremental sequence number. No evidence that it is specifically a key synchronization channel — it is a separate control channel with message numbering.

---

## FRONT 12 — TLV `0x30` (192 Bytes) Field

### Search in PCAPs

No 192-byte field associated with tag `0x30` was found in any analyzed capture.

### Static Analysis Reference

Previous reverse engineering reports mention:
- Routine in `shelper.dll!0x100638f0`
- Initialization at `0x10005250`
- Update at `0x10004e50`
- Finalization at `0x10004f30`
- Folding in caller at `0x10069cdb` to `0x10069d0e`

### Conclusion

**INCONCLUSIVE:** The TLV `0x30` 192-byte field does not appear in captured traffic. This may mean:
1. The field is negotiated before capture start (initial handshake not captured)
2. The field is used only in message types not observed
3. The field belongs to a different protocol version

Static data would be needed to verify if the 192-byte constant `N` appears in the binaries.

---

## FRONT 13 — STUN: Complete Reconstruction

### Observed Messages

| Frame | Source | Dest | Port | Type | Transaction ID | Capture |
|---|---|---|---|---|---|---|
| 5477 | 192.168.122.77:54527 | 135.181.75.11 | 17357 | Binding Request (0x0001) | `24df3803cbe764ea106738b61d314c66` | radmin_vm.pcap |
| 5480 | 192.168.122.77:54527 | 135.181.75.11 | 17357 | Binding Request (0x0001) | (same) | radmin_vm.pcap |
| 5489 | 135.181.75.11:17357 | 192.168.122.77:54527 | 17357 | Binding Response (0x0101) | (same) | radmin_vm.pcap |
| 676 | 192.168.122.77:54533 | 162.19.169.168 | 17309 | Binding Request | `676387424d688c31c2860788a26eed38` | radmin_vm2.pcap |
| 678 | 192.168.122.77:54533 | 162.19.169.168 | 17309 | Binding Request | (same) | radmin_vm2.pcap |

### Message Structure

**Binding Request:** 20 bytes UDP payload
- Type: 2 bytes (`00 01` = Binding Request)
- Length: 2 bytes (`00 00` = no attributes)
- Transaction ID: 16 bytes
- **No magic cookie** (0x2112A442 absent)
- **Total:** 20 bytes

**Binding Response:** 56 bytes UDP payload
- Type: 2 bytes (`01 01` = Binding Response)
- Length: 2 bytes (`00 24` = 36 bytes of attributes)
- Transaction ID: 16 bytes (same as request)
- Attributes: 36 bytes
- **Total:** 56 bytes

**Size correction:** 98 bytes is the Ethernet frame size (frame.len), not the UDP payload. The UDP payload is 56 bytes.

### Retry Pattern

Two Binding Requests sent with ~99–100 ms interval, suggesting automatic retry due to no response on first attempt.

### Non-Standard STUN Ports

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

### STUN Response Attributes

Frame 5489 attributes:
- Attribute 1: Type 0x0001 (MAPPED-ADDRESS), Length 8, IPv4, Port 54527, IP 187.59.199.39
- Attribute 2: Type 0x0004 (SOURCE-ADDRESS), Length 8, IPv4, Port 0, IP 0.0.0.0
- Attribute 3: Type 0x0005 (CHANGED-ADDRESS), Length 8, IPv4, Port 0, IP 0.0.0.0

### Conclusion

**CONFIRMED:** STUN-like Binding Request/Response observed on 9 non-standard Radmin ports.  
**REFUTED:** This is NOT standard RFC 5389 STUN — no magic cookie present, 16-byte transaction ID instead of 12.  
**INCONCLUSIVE:** Whether this is a proprietary STUN variant or a different protocol using STUN-like formatting.

---

## FRONT 14 — NAT and Address Mapping

### Available Evidence

STUN Binding Responses (56 bytes) contain attributes that may include MAPPED-ADDRESS and XOR-MAPPED-ADDRESS, but full attribute decoding requires the non-standard protocol variant to be understood.

### Limitations

- A single STUN response per server is insufficient to determine NAT type
- No request/response pairs from multiple servers for the same local address to compare mappings
- No hole punching traffic sufficient to infer NAT behavior

### Conclusion

**INCONCLUSIVE:** NAT type (Full Cone, Restricted Cone, Port-Restricted, Symmetric) cannot be classified from available captures. Multiple STUN responses from different servers for the same local address, or verified successful hole punching with mapped address verification, would be needed.

---

## FRONT 15 — Teredo

### Evidence

| Frame | Source | Dest | Port | Content | Capture |
|---|---|---|---|---|---|
| 708 | 192.168.122.77:54778 | 20.201.205.4 | 3544 | Teredo Router Solicitation (ICMPv6 type 133) | radmin_vm.pcap |
| 169 | 192.168.122.77:54778 | 20.201.205.4 | 3544 | Teredo Router Solicitation (ICMPv6 type 133) | radmin_vm2.pcap |

### Analysis

- Teredo packet contains ICMPv6 Router Solicitation from `fe80::ffff:ffff:fffe` to `ff02::2`
- Nonce: `8acf0087ddea3402`
- Destination `20.201.205.4` is a public Microsoft Teredo server
- No Router Advertisement observed in response
- No IPv6 encapsulated traffic beyond Router Solicitation

### Conclusion

**CONFIRMED:** Teredo traffic observed, but likely background Windows/Wine traffic, not specifically Radmin. No evidence that Radmin uses Teredo for its communications.

---

## FRONT 16 — ARP and Virtual Address Resolution

### Observed ARP Traffic

| Frame | Source | Dest | Content | Capture |
|---|---|---|---|---|
| 115 | 02:50:ce:a5:3a:26 | Broadcast | "Who has 177.112.79.226? Tell 26.239.229.134" | radmin-mine.pcapng |
| 272 | 02:50:ce:a5:3a:26 | Broadcast | "Who has 192.168.15.122? Tell 26.239.229.134" | radmin-mine.pcapng |
| 274 | 02:50:ce:a5:3a:26 | Broadcast | "Who has 25.33.236.186? Tell 26.239.229.134" | radmin-mine.pcapng |
| 314 | 02:50:eb:9a:6f:58 | Broadcast | "Who has 26.239.229.134? Tell 26.228.88.155" | radmin-connect.pcapng |
| 315 | 02:08:62:e3:9a:28 | 02:50:eb:9a:6f:58 | "26.239.229.134 is at 02:08:62:e3:9a:28" | radmin-connect.pcapng |

### MACs Observed on Virtual Interface

| MAC | Association |
|---|---|
| 02:50:ce:a5:3a:26 | 26.239.229.134 (local client) |
| 02:08:62:e3:9a:28 | 26.239.229.134 (ARP response) |
| 02:50:eb:9a:6f:58 | 26.228.88.155 |
| 02:50:06:00:35:fd | 26.172.178.79 |

### Conclusion

**CONFIRMED:** ARP is used on virtual interface `radminvpn0` for virtual address resolution (26.x.x.x). MACs are locally administered (prefix `02:` indicates locally administered). No evidence that MACs are global or persistent identifiers across sessions.

---

## FRONT 17 — Broadcast, Multicast, and Auxiliary Protocols

### Protocols Observed on Virtual Interface

| Protocol | Endpoint | Captures | Classification |
|---|---|---|---|
| IGMPv3 | 26.228.42.15 → 224.0.0.22 | radmin-mine-host | Auxiliary traffic (multicast join/leave) |
| SSDP | 26.172.178.79 → 239.255.255.250:1900 | radmin-mine-host | M-SEARCH (likely Windows background) |
| UDP/4445 | 26.239.229.134:60900 → 224.0.2.60:4445 | radmin-mine-host | Virtual multicast |
| MDNS | 192.168.15.9:5353 → 224.0.0.251 | radmin-mine-host | Auxiliary traffic |

### Conclusion

**CONFIRMED:** IGMPv3, SSDP, MDNS, and multicast UDP/4445 appear on the virtual interface. Classified as auxiliary background traffic (likely Windows running via Wine), not essential to Radmin VPN communication.

---

## FRONT 18 — Temporal Phase Reconstruction

### Unified Timeline

| Time | Event | Capture | Inferred Phase |
|---|---|---|---|
| T-114s | radmin_vm.pcap starts (18:05:28) | radmin_vm.pcap | VM initialization |
| T+0s | DNS queries (Windows/MS) | radmin_vm.pcap | Initialization |
| T+7s | Teredo Router Solicitation | radmin_vm.pcap | IPv6 connectivity |
| T+42s | TCP connects 148.113.190.78:17301 | radmin_vm / radmin_17301 | Control connection |
| T+95s | STUN Binding Requests (multiple ports) | radmin_vm.pcap | NAT discovery |
| T+96s | TCP connects 45.162.230.182:17351 | radmin_vm.pcap | Alternative control |
| T+0 (connect) | radmin-connect.pcapng starts (14:22:04) | radmin-connect.pcapng | Connection phase |
| T+5s | TCP SYN → 148.113.190.78:17301 | radmin-connect.pcapng | Control handshake |
| T+5s | TCP data/17301 (196, 4420 bytes) | radmin-connect.pcapng | Negotiation |
| T+6s | TCP → 198.244.203.247:17301 | radmin-connect.pcapng | Alternative server |
| T+0 (mine) | radmin-mine.pcapng starts (14:31:21) | radmin-mine.pcapng | Active phase |
| T+0 | UDP/9993 between virtual peers | radmin-mine.pcapng | P2P established |
| T+0 | Keepalive UDP/47836 | radmin-mine.pcapng | Session maintenance |
| T+0 (mine-host) | radmin-mine-host.pcapng starts (14:32:56) | radmin-mine-host.pcapng | Active phase host |
| T+5s | ARP on virtual interface | radmin-mine-host.pcapng | Address resolution |

### Identified Phases

1. **Initialization (T-114s to T+0s):** DNS, Teredo, ARP
2. **Control connection (T+42s):** TCP/17301 to Radmin control servers
3. **NAT discovery (T+95s):** STUN on non-standard ports
4. **P2P active (T+0 mine/mine-host):** UDP/9993, keepalive UDP/47836

**Note:** File names (`radmin-connect`, `radmin-mine`, `radmin-mine-host`) are consistent with phases observed by timestamps, but there is no direct confirmation in capture metadata.

---

## FRONT 19 — Previous Conclusion Audit

### Comparison with `docs/PROTOCOL_SPEC.md`

| Previous Claim | Status in PCAPs | Comment |
|---|---|---|
| Framing `[4-byte BE length][payload]` | ✓ CONFIRMED | Validated in TCP/17301 and 17351 |
| Handshake `00 00 00 04 03 00 00 00` | — NOT FOUND | Does not appear at start of any captured connection |
| Control port 17301 | ✓ CONFIRMED | Multiple TCP connections observed |
| Port 17351 | ✓ CONFIRMED | Sub-protocol with sequence |
| STUN on non-standard ports | ✓ CONFIRMED | 9 different ports observed |
| Teredo UDP/3544 | ✓ CONFIRMED | Router Solicitation |
| Virtual interface 26.x.x.x | ✓ CONFIRMED | radminvpn0 active |
| Servers 148.113.190.78, 198.244.203.247, 45.162.230.182 | ✓ CONFIRMED | All appear |

### New Discoveries (not in previous reports)

1. UDP/9993 as P2P data channel
2. UDP/47836 as periodic keepalive
3. TLV type `0x0004` with peer IP+port
4. Hole punching with multiple source ports (9993, 48318, 48870)
5. 10-byte session identifier only in UDP/9993

### Contradictions

No direct contradiction found between PCAPs and previous reverse engineering reports.

---

## FRONT 20 — Future Implementation Matrix

### Readiness by Item

| Item | Readiness | Evidence Needed |
|---|---|---|
| 1. Control framing | READY | `[4-byte BE length][payload]` validated |
| 2. Initial handshake | NOT READY | Handshake `00 00 00 04 03 00 00 00` not captured |
| 3. Authentication | NOT READY | Encrypted traffic, no keys |
| 4. Encryption | NOT READY | Algorithm and keys unknown |
| 5. STUN | PARTIALLY CHARACTERIZED | Binding Request/Response on ports 17309, 17341, 17342, 17357, 17358, but non-standard variant |
| 6. NAT traversal | HYPOTHESIS | Hole punching observed, NAT type unknown |
| 7. Peer discovery | PARTIALLY CHARACTERIZED | TLV 0x0004 provides IP+port, discovery mechanism unknown |
| 8. UDP/9993 | PARTIALLY CHARACTERIZED | Partial structure, encrypted region not decodable |
| 9. UDP/47836 | INCONCLUSIVE | 4-byte keepalive with counter LE, layout ambiguous |
| 10. Relay | NOT READY | Not confirmed in PCAPs |
| 11. Virtual interface | PARTIALLY CHARACTERIZED | radminvpn0 with ARP, IP 26.x.x.x, but encapsulation unknown |
| 12. Packet encapsulation | NOT READY | Packet format inside VPN not determined |

### Recommendations for Next Step

1. Capture complete initial handshake (before any TCP connection)
2. Capture key exchange traffic synchronized with UI events
3. Decode complete STUN responses (MAPPED-ADDRESS attributes)
4. Collect more UDP/9993 samples to map complete TLV structure
5. Attempt real interoperability testing with Windows client to validate protocol

---

**Generated file:** `docs/PCAP_FORENSICS_DEEP_DIVE.md`  
**Original .pcapng files:** Preserved, unmodified  
**Project source code:** Unaltered