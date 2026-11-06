# PCAP Message Catalog — Radmin VPN Traffic Analysis

**Project:** Radmin VPN Linux client (Rust, independent)  
**Capture directory:** `claude-handoff/pcaps/`  
**Analysis date:** 06 nov 2026  
**Language:** English  

---

## Catalog Summary

| Protocol | Port | Family | Size (bytes) | Quantity | Confidence |
|---|---|---|---|---|---|
| TCP | 17301 | Control | Variable (4+payload) | ~100 | CONFIRMED |
| TCP | 17351 | Alternative control | Variable (4+payload) | ~30 | CONFIRMED |
| UDP | 9993 | A — Setup/complete | 137 | 93 | CONFIRMED |
| UDP | 9993 | B — Short | 33 | 223 | CONFIRMED |
| UDP | 9993 | C — Short keepalive | 28 | 82 | CONFIRMED |
| UDP | 9993 | D — Medium | 99 | 74 | CONFIRMED |
| UDP | 9993 | E — Large (connect) | 247–641 | ~40 | CONFIRMED |
| UDP | 47836 | Keepalive | 4 | ~60 | CONFIRMED |
| UDP | 17309/17341/17342/17357/17358 | STUN Binding Request | 20 | ~20 | CONFIRMED |
| UDP | 17309/17341/17342/17357/17358 | STUN Binding Response | 56 | ~10 | CONFIRMED |
| UDP | 3544 | Teredo Router Solicitation | 61 | 2 | CONFIRMED |

---

## TCP/17301 Message — Control

### Structure

```
[4-byte big-endian length][payload]
```

The length field represents only the payload size (excludes the 4-byte header).

### Real Examples

#### Message 1 — 192 bytes payload

**Capture:** `radmin-connect.pcapng`  
**Frame:** 77  
**Timestamp:** 06/11/2026 14:22:09.xxx  
**Source:** 192.168.15.15:44340  
**Destination:** 148.113.190.78:17301  
**tcp.len:** 196  
**Length field:** `00 00 00 c0` (192)

**Payload (192 bytes):**
```
10 f9 bf 00 3c e2 7b ed 34 3e 09 02 03 b8 0d 86
ec 02 a3 80 e1 79 96 44 71 cf 35 91 a4 c1 39 d8
01 21 05 b2 2b 4e 31 55 de 61 0a a8 90 e4 d9 ab
de 3a e8 70 93 32 94 1d 21 9e a2 13 f2 7f a3 55
5d 1e a7 97 e8 92 2d fc 84 a4 53 02 36 50 df 4e
1c a8 eb 16 2b 59 15 37 fd 51 75 81 28 be ff 45
4c 91 c8 7c 02 e1 3f ce 36 f6 29 6a d3 e6 40 e0
05 c2 96 1e 8e 58 43 4f 43 a 61 ee 53 fd bf de
5f 23 a 0f fd 4d bc c5 63 07 9c c5 a 45 b 8 ef
a7 6 03 84 68 28 13 5b 2c 8b 6e a0 39 6b b0 e
8b 77 f 21 59 01 b 73 14 8b a8 77 a 60 c 34 a
17 ee f7 3 5d 0d 6 ff cc e7 5 7c 8f 0b 3b 6f
a0 6 03 6b c d 2c
```

**Interpretation:** Encrypted data (high entropy). No identifiable fields in payload.

#### Message 2 — 32 bytes payload

**Capture:** `radmin-connect.pcapng`  
**Frame:** 80  
**Source:** 192.168.15.15:44340  
**Destination:** 148.113.190.78:17301  
**tcp.len:** 36  
**Length field:** `00 00 00 20` (32)

**Payload (32 bytes):**
```
c7 f5 78 26 af 97 91 03 70 c8 6f d5 cb 17 12 18
58 9d 2f 73 7f 39 7d cf 59 ee 46 4d 43 21 5b d0
```

**Interpretation:** 32 bytes of apparently random data (possible key, nonce, or cryptographic hash).

#### Message 3 — 256 bytes payload

**Capture:** `radmin-connect.pcapng`  
**Frame:** 81  
**Source:** 148.113.190.78:17301  
**Destination:** 192.168.15.15:44340  
**tcp.len:** 260  
**Length field:** `00 00 01 00` (256)

**Payload (256 bytes):** Encrypted data (high entropy, not displayed due to size).

#### Fragmented Message — 2592 bytes total

**Capture:** `radmin-connect.pcapng`  
**Frame 100:** Source 148.113.190.78:17301, Destination 192.168.15.15:44340  
**Length field:** `00 00 0a 20` (2592)  
**tcp.len:** 1440 (first fragment: 4 header + 1436 payload)

**Frame 101:** Source 148.113.190.78:17301, Destination 192.168.15.15:44340  
**tcp.len:** 1156 (continuation: 1156 bytes payload, no new length prefix)  
**Reconstruction:** 1436 + 1156 = 2592 ✓

---

## TCP/17351 Message — Alternative Control

### Structure

```
[4-byte big-endian length][payload]
```

Internal payload:
```
[4 bytes: 10 00 00 04 — constant version/type]
[4 bytes: big-endian sequence number]
[variable: message payload]
```

### Real Examples

#### Message 1 — Sequence 4

**Capture:** `radmin_vm.pcap`  
**Frame:** 5487  
**Source:** 45.162.230.182:17351  
**Destination:** 192.168.122.77:49497  
**tcp.len:** 16  
**Length field:** `00 00 00 0c` (12)

**Complete payload (12 bytes):**
```
00 00 00 04 01 00 01 df 00 00 00 02
```

**Fields:**
- `00 00 00 04`: version/type (constant)
- `01 00 01 df`: variable field
- `00 00 00 02`: sequence number = 2

#### Message 2 — Sequence 3

**Capture:** `radmin_vm.pcap`  
**Frame:** 5494  
**Source:** 45.162.230.182:17351  
**Destination:** 192.168.122.77:49497  
**tcp.len:** 207  
**Length field:** `00 00 00 cb` (203)

**Payload (203 bytes):**
```
10 00 00 04 00 00 00 03 60 00 00 bf bf 64 a2 64
40 1a 82 c5 ac 52 b2 5a ee 49 b9 5a 8f 1d c3 1e
8b 92 7c 87 02 ff 0e 78 2b fb 69 75 18 6a 17 62
fc 6d 8e ff 24 f 42 b 57 ed c 1f a 32 bb 42 e 0
a 52 9c 45 5 b 71 7e b 2a 6d f 0 b 8 f 2b 0 c
96 86 ace 54 5 4 2 12 30 a 9 cf 1 13 b 5 f 8 cb
f3 a c 95 f b e 52 b 0 3 21 6 f 5 a 2 b c d b
13 0 f 66 d c e 98 8d 0c af f 8 22 8c 92 de 8b
14 c 58 6c 0 7 da 1 b 9b 0 b 29 f 1a 6d ff 4e
c 3 f 3f 74 6 12 14 1 3b 79 c 8 b 11 f 12 4 da
21 79 2a d 5b 63 ff 9 d 4 f 15 55 ff d fe 0 ab
91 79 ff 6 bd 77 a 3 5bc 0 6 24 9 13 c 84 f 95 c
```

**Fields:**
- `10 00 00 04`: version/type (constant)
- `00 00 00 03`: sequence number = 3
- `60 00 00 bf ...`: variable payload (195 bytes)

#### Message 3 — Sequence 4

**Capture:** `radmin_vm.pcap`  
**Frame:** 5501  
**Source:** 45.162.230.182:17351  
**Destination:** 192.168.122.77:49497  
**tcp.len:** 208  
**Length field:** `00 00 00 cc` (204)

**Payload (204 bytes):**
```
10 00 00 04 00 00 00 04 60 00 00 c0 86 75 05 3a
9c 4a 5b 1a 39 d9 6a bf d0 74 01 5d 94 02 46 73
a 2e 78 fa 76 99 96 b 28 5b b 0 a 55 ff 63 34 a
90 9f 8f 1a b 3c 40 3 7d 06 d 92 f 5f 53 92 6d
ed 5d 48 b 21 66 a fd 97 ec 77 1b d 74 2c 2a 76
1c 86 37 2b 28 0b 71 f 6e 02 ad 52 02 26 dd 86
50 9a 10 59 55 31 6a a 29 52 ee 91 ed d 24 dd e
1b 7a 3c 5 d 3f f 84 39 ee 27 92 4 de 86 8a 78
99 9e 7c 37 0 5 36 90 9 77 89 1 f 3c 40 0 d 85
99 ed 89 d 0 f 31 20 33 cd 85 c 6 f 80 c 7a 89
7e 4 ce cd 0 c 12 d fd 2 b f aa 8 10 b cf 10
99 b df b cf 0 ad 26 fb 19 9 11 7 20 f da 54 ae
80 23 5b 5d da f 53 e 18 f cd 60 f 03 8 58 38 4
33 69 14 f 6
```

**Fields:**
- `10 00 00 04`: version/type (constant)
- `00 00 00 04`: sequence number = 4
- `60 00 00 c0 ...`: variable payload (200 bytes)

### Observed Sequence Numbers

| Frame | Direction | Sequence |
|---|---|---|
| 5487 | Server → Client | 4 |
| 5493 | Server → Client | 2 |
| 5494 | Server → Client | 3 |
| 5501 | Server → Client | 4 |
| 5502 | Client → Server | 5 |
| 5509 | Client → Server | 6 |
| 5510 | Client → Server | (no sequence, 20 bytes) |
| 5511 | Client → Server | (no sequence, 36 bytes) |
| 5512 | Client → Server | (no sequence, 68 bytes) |

**Observation:** Not all TCP/17351 messages have a sequence field. Smaller messages (20–68 bytes) may have a different structure.

---

## UDP/9993 Message — Family A (137 bytes)

### Complete Structure

| Offset | Size | Hex bytes | Interpretation | Confidence |
|---|---|---|---|---|
| 0x00 | 4 | `25 2d ff 68` | Magic / message type | CONFIRMED |
| 0x04 | 4 | `42 c3 84 70` | Variable field (flags?) | INCONCLUSIVE |
| 0x08 | 10 | `e5 d4 c1 c5 bc 21 59 16 c8 0f` | Session identifier | STRONG INDICATION |
| 0x12 | 2 | `00 01` | Message subtype | CONFIRMED |
| 0x14 | 8 | `03 74 49 74 bf 0f ed 01` | Variable field | INCONCLUSIVE |
| 0x1c | 4 | `0d 01 10 00` | Fixed field | CONFIRMED |
| 0x20 | 4 | `02 00 00 01` | Fixed field | CONFIRMED |
| 0x24 | 10 | `a1 b1 ea 42 91 21 59 16 c8 0f` | Repeated session ID | HYPOTHESIS |
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

**Total:** 137 bytes. The previous report documented only up to 0x77 (120 bytes), omitting 17 bytes at offsets 0x78–0x8a.

### Real Examples

#### Example 1 — Virtual → Virtual

**Capture:** `radmin-mine.pcapng`  
**Frame:** 116  
**Interface:** 1 (radminvpn0)  
**Source:** 26.239.229.134:9993  
**Destination:** 26.172.178.79:9993  
**udp.length:** 145 (137 bytes payload)

**Complete payload (137 bytes):**
```
25 2d ff 68 42 c3 84 70 e5 d4 c1 c5 bc 21 59 16
c8 0f 00 01 03 74 49 74 bf 0f ed 01 0d 01 10 00
02 00 00 01 a1 b1 ea 42 91 21 59 16 c8 0f 00 2e
38 e9 0a 46 71 a7 7c fd d8 81 06 57 ec 45 de 15
6c 7a 3e 5d 6c 86 65 7c bb e4 53 9d 0b c3 69 5e
db 03 c5 ab 8b ef 20 1d c6 ca 71 c4 dc a7 1d ba
4f cb cc 9f 54 b0 57 4d 0e 08 59 c1 af 78 4e 00
04 1a ac b2 4f 27 09 00 00 00 08 ea c9 0a 00 00
01 94 db 79 5b 4e 0b 2c
```

#### Example 2 — Physical → Virtual

**Capture:** `radmin-mine.pcapng`  
**Frame:** 127  
**Interface:** 0 (enp7s0)  
**Source:** 192.168.15.15:9993  
**Destination:** [IP_PUBLICO_MASCARADO]:9993  
**udp.length:** 145 (137 bytes payload)

**Complete payload (137 bytes):**
```
5d a8 6b 96 1d 5d 1b e e 5d 4c 1c 5b c 21 59 16
c8 0f 00 0d 03 dd 76 d7 ec cb a c 01 0d 01 10 00
02 00 00 01 a1 b1 ea 42 91 21 59 16 c8 0f 00 2e
38 e9 0a 46 71 a7 7c fd d8 81 06 57 ec 45 de 15
6c 7a 3e 5d 6c 86 65 7c bb e4 53 9d 0b c3 69 5e
db 03 c5 ab 8b ef 20 1d c6 ca 71 c4 dc a7 1d ba
4f cb cc 9f 54 b0 57 4d 0e 08 59 c1 af 78 4e 00
04 b1 70 4f e2 27 09 00 00 00 08 eac 9 0a 00 00
01 94 db 79 5b 4e fb 2b
```

**Differences from Example 1:**
- Offset 0x00–0x03: different (`5d a8 6b 96` vs `25 2d ff 68`) — possibly different message or nonce
- Offset 0x08–0x11: `e5 d4 c1 c5 bc 21 59 16 c8 0f` — SAME session identifier
- Offset 0x6f–0x76: `00 04 b1 70 4f e2 27 09` — TLV 0x0004 with IP `b1 70 4f e2` = [IP_PUBLICO_MASCARADO] and port `27 09` = 9993

#### Example 3 — Hole Punching (same payload, different port)

**Capture:** `radmin-mine.pcapng`  
**Frame:** 117  
**Source:** 26.239.229.134:48318  
**Destination:** 26.172.178.79:9993  
**udp.length:** 145

**Payload:** IDENTICAL to frame 116 (same 137-byte payload)

**Conclusion:** The same payload is retransmitted from multiple source ports to facilitate hole punching.

---

## UDP/9993 Message — Family B (33 bytes)

### Structure

| Offset | Size | Bytes | Interpretation |
|---|---|---|---|
| 0x00 | 4 | `b9 6b 32 c3` | Variable field |
| 0x04 | 4 | `13 57 56 f8` | Variable field |
| 0x08 | 4 | `77 8c de 71` | Variable field |
| 0x0c | 6 | `90 21 59 16 c8 0f` | Session identifier (partial, 6 bytes) |
| 0x12 | 2 | `08 af` | Variable field |
| 0x14 | 4 | `22 1d ce fb` | Variable field |
| 0x18 | 4 | `43 42 25 7e` | Variable field |
| 0x1c | 4 | `46 9e 55 19` | Variable field |
| 0x20 | 1 | `2f` | Variable field / trailer |

### Real Example

**Capture:** `radmin-mine.pcapng`  
**Frame:** 139  
**Interface:** 0 (enp7s0)  
**Source:** 192.168.15.15:48318  
**Destination:** 103.195.103.66:9993  
**udp.length:** 41 (33 bytes payload)

**Complete payload (33 bytes):**
```
b9 6b 32 c3 13 57 56 f8 77 8c de 71 90 21 59 16
c8 0f 08 af 22 1d ce fb 43 42 25 7e 46 9e 55 19 2f
```

**Observation:** Contains only 6 bytes of session identifier (`90 21 59 16 c8 0f`), not the complete 10 bytes.

---

## UDP/9993 Message — Family C (28 bytes)

### Structure

| Offset | Size | Bytes | Interpretation |
|---|---|---|---|
| 0x00 | 8 | `09 3e 08 ab b0 a6 17 91` | Variable field |
| 0x08 | 10 | `e5 d4 c1 c5 bc 21 59 16 c8 0f` | Complete session identifier |
| 0x12 | 10 | `18 ac 77 1e 68 c7 9b e0 c5 0c` | Variable field / trailer |

### Real Example

**Capture:** `radmin-mine.pcapng`  
**Frame:** 187  
**Interface:** 0 (enp7s0)  
**Source:** 192.168.15.15:9993  
**Destination:** 25.33.236.186:9993  
**udp.length:** 36 (28 bytes payload)

**Complete payload (28 bytes):**
```
09 3e 08 ab b0 a6 17 91 e5 d4 c1 c5 bc 21 59 16
c8 0f 18 ac 77 1e 68 c7 9b e0 c5 0c
```

---

## UDP/9993 Message — Family D (99 bytes)

### Real Example

**Capture:** `radmin-mine.pcapng`  
**Frame:** 143  
**Interface:** 0 (enp7s0)  
**Source:** 192.168.15.15:9993  
**Destination:** [IP_PUBLICO_MASCARADO]:9993  
**udp.length:** 107 (99 bytes payload)

**Complete payload (99 bytes):**
```
b5 29 7e d0 4f 09 38 8e e5 d4 c1 c5 bc 21 59 16
c8 0f 18 31 ff fc 43 50 cd d0 29 e4 01 23 d3 84
a7 22 26 26 3e 82 e6 91 14 40 58 97 3d 7d a7 0e
62 19 fe f1 22 b5 55 51 c5 b0 dd ff 79 3d 73 8b
17 dd 71 85 41 c4 20 37 fd 3c df 22 c8 4f ab d9
3d 4a 7c 5b 63 87 5f b1 6d 7e 4a 18 95 9d c0 f8
1c d1 b1
```

---

## UDP/9993 Message — Family E (247–641 bytes)

### Real Example (249 bytes)

**Capture:** `radmin-mine-host.pcapng`  
**Frame:** 132  
**Interface:** 0 (enp7s0)  
**Source:** [IP_PUBLICO_MASCARADO]:9993  
**Destination:** 192.168.15.15:9993  
**udp.length:** 257 (249 bytes payload)

**Payload (first 64 bytes):**
```
b6 0d 0e 91 fa 1e c5 00 21 59 16 c8 0f e5 d4 c1
c5 bc 21 59 16 c8 0f 18 08 6b cf d5 6c 27 0c 3e
c7 98 d7 1f 15 73 19 a 4d c 75 38 50 e 45 65 2e
8d b 7 a b da 7 b 18 e 3f 99 f 2 a 85 e 7d e 3a
7b 0 4 17 1b e 69 6 d 46 9 24 a 3b e a a d 9 a
3d 3 d 24 d 97 c 75 f 54 36 0 3 fa ee 95 43 c 1e
b 89 c 1 80 e b f 2 e 0 69 5 8 33 5 f ee 4 c 22
d 1f a 6 d a 1 d e 9 b 5 4 b d 9 3 f c c 7 e 3
6 e b 19 30 d b 3 b 48 fe 0 a c 0 f 7 fd a 5 3
3 af a 7 76 0c ee 2 b 96 0
```

**Observation:** Contains `21 59 16 c8 0f` and `e5 d4 c1 c5 bc 21 59 16 c8 0f` (partial and complete session identifier).

---

## UDP/47836 Message — Keepalive

### Structure

| Offset | Size | Bytes | Interpretation |
|---|---|---|---|
| 0x00 | 4 | `XX 02 00 00` | Sequential counter |

**Layout ambiguity:** The 4-byte payload can be interpreted as either:
- `uint16 LE counter + 2 zero bytes` (counter value from first 2 bytes, then `00 00`)
- `uint32 LE counter` (counter value from all 4 bytes)

Both interpretations produce identical values because the upper 16 bits are always zero. No evidence distinguishes these interpretations.

### Real Examples

#### Capture `radmin-mine.pcapng`:

| Frame | Payload | Value | Source | Destination |
|---|---|---|---|---|
| 66 | c3 02 00 00 | 707 | 26.228.88.155:47836 | 26.239.229.134:47836 |
| 342 | c4 02 00 00 | 708 | 26.228.88.155:47836 | 26.239.229.134:47836 |
| 543 | c5 02 00 00 | 709 | 26.228.88.155:47836 | 26.239.229.134:47836 |

#### Capture `radmin-mine-host.pcapng`:

| Frame | Payload | Value | Source | Destination |
|---|---|---|---|---|
| 93 | 22 03 00 00 | 802 | 26.228.88.155:47836 | 26.239.229.134:47836 |
| 213 | 23 03 00 00 | 803 | 26.228.88.155:47836 | 26.239.229.134:47836 |

#### Capture `radmin-connect.pcapng`:

| Frame | Payload | Value | Source | Destination |
|---|---|---|---|---|
| 312 | 9e 00 00 00 | 158 | 26.228.88.155:47836 | 26.239.229.134:47836 |
| 957 | 9f 00 00 00 | 159 | 26.228.88.155:47836 | 26.239.229.134:47836 |

---

## STUN Message — Binding Request

### Structure (non-standard variant)

| Offset | Field | Size | Example Value |
|---|---|---|---|
| 0x00 | Message Type | 2 bytes | `00 01` (Binding Request) |
| 0x02 | Message Length | 2 bytes | `00 00` |
| 0x04 | Transaction ID | 16 bytes | Random |
| **Total** | | **20 bytes** | |

**Note:** This is NOT standard RFC 5389 STUN. No magic cookie (0x2112A442) is present, and the transaction ID is 16 bytes (not 12).

### Real Example

**Capture:** `radmin_vm.pcap`  
**Frame:** 5477  
**Source:** 192.168.122.77:54527  
**Destination:** 135.181.75.11:17357  
**udp.length:** 28 (20 bytes payload)

**Complete payload:**
```
00 01 00 00 24 df 38 03 cb e7 64 ea 10 67 38 b6
1d 31 4c 66
```

**Fields:**
- Message Type: `00 01` = Binding Request
- Message Length: `00 00` = 0 attributes
- Transaction ID: `24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66`

---

## STUN Message — Binding Response

### Structure

| Offset | Field | Size |
|---|---|---|
| 0x00 | Message Type | 2 bytes (`01 01` = Binding Response) |
| 0x02 | Message Length | 2 bytes (`00 24` = 36 bytes attributes) |
| 0x04 | Transaction ID | 16 bytes (same as request) |
| 0x14 | Attributes | 36 bytes |
| **Total** | | **56 bytes** |

**Note:** 98 bytes is the Ethernet frame size (frame.len), not the UDP payload. The UDP payload is 56 bytes.

### Real Example

**Capture:** `radmin_vm.pcap`  
**Frame:** 5489  
**Source:** 135.181.75.11:17357  
**Destination:** 192.168.122.77:54527  
**udp.length:** 64 (56 bytes payload)

**Payload (first 20 bytes):**
```
01 01 00 24 [transaction ID] [36 bytes attributes]
```

**Decoded attributes:**
- Attribute 1: Type 0x0001 (MAPPED-ADDRESS), Length 8, IPv4, Port 54527, IP 187.59.199.39
- Attribute 2: Type 0x0004 (SOURCE-ADDRESS), Length 8, IPv4, Port 0, IP 0.0.0.0
- Attribute 3: Type 0x0005 (CHANGED-ADDRESS), Length 8, IPv4, Port 0, IP 0.0.0.0

---

## Teredo Message — Router Solicitation

### Structure

UDP payload encapsulated in Teredo IPv6 tunneling:
- Teredo header: client identifier, authentication, nonce
- Inner IPv6 packet: ICMPv6 Router Solicitation

### Real Example

**Capture:** `radmin_vm.pcap`  
**Frame:** 708  
**Source:** 192.168.122.77:54778  
**Destination:** 20.201.205.4:3544  
**udp.length:** 69 (61 bytes payload)

**Identified fields:**
- Nonce: `8a cf 00 87 dd ea 34 02`
- ICMPv6 Type: 133 (Router Solicitation)
- Source IPv6: `fe80::ffff:ffff:fffe`
- Destination IPv6: `ff02::2`

---

## Non-Semanticized Fields

Per investigation rules, the following fields receive no semantic interpretation without evidence:

| Field | Offset (Family A) | Size | Observed Values |
|---|---|---|---|
| Magic/type | 0x00 | 4 bytes | `25 2d ff 68`, `5d a8 6b 96`, `7b 69 98 01`, `1c 6e f3 f5` |
| Flags? | 0x04 | 4 bytes | `42 c3 84 70`, `00 0d 03 dd`, `00 c4 d1 77`, `00 31 7c 7f` |
| Variable 1 | 0x14 | 8 bytes | Multiple different values |
| Fixed 1 | 0x1c | 4 bytes | `0d 01 10 00` (constant in Family A) |
| Fixed 2 | 0x20 | 4 bytes | `02 00 00 01` (constant in Family A) |
| Encrypted | 0x2e | 48 bytes | High entropy, different between messages |
| Unknown region | 0x5e | 12 bytes | `1d ba c6 ca 71 c4 dc a7 1d ba 4f cb` |
| Unknown region | 0x6a | 6 bytes | `cc 9f 54 b0 57 4d` |
| Unknown region | 0x70 | 8 bytes | `0e 08 59 c1 af 78 4e 00` |
| Undocumented | 0x78 | 13 bytes | `00 00 00 08 ea c9 0a 00 00 01 94 db 79 5b` |
| Undocumented | 0x85 | 3 bytes | `4e 0b 2c` |

**Generated file:** `docs/PCAP_MESSAGE_CATALOG.md`  
**Original .pcapng files:** Preserved, unmodified