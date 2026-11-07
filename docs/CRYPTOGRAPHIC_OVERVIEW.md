# Cryptographic Overview — Radmin VPN Protocol Architecture

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Commit-base:** df8ce07  
**Language:** English  
**Status:** Investigation phase — evidence-backed, hypotheses clearly marked  

---

## 1. Scope and Methodology

This document synthesizes findings from static binary analysis of `shelper.dll`, `RvROLClient.dll`, `RvControlSvc.exe`, `RvRvpnGui.exe` (Ghidra headless + REA evidence) and PCAP traffic analysis (`radmin_17301.pcap`, `radmin_vm.pcap`, `radmin_vm2.pcap`, `radmin-connect.pcapng`, `radmin-mine.pcapng`, `radmin-mine-host.pcapng`). It is compared against the current Rust implementation in `src/`.

Confidence classification used throughout:

| Classification | Meaning |
|---|---|
| CONFIRMED | Directly demonstrated by instruction-level analysis, verified data flow, or reproducible behavior |
| STRONG INDICATION | Multiple consistent observations, missing one decisive verification |
| HYPOTHESIS | Plausible interpretation requiring verification |
| UNKNOWN | Insufficient evidence |
| REFUTED | Evidence directly contradicts the claim |

**No hypothesis is presented as a confirmed fact.** Where binary analysis could not be completed (dynamic execution blocked, tool budget exhausted), the gap is explicitly documented.

---

## 2. High-Level Architecture

The Radmin VPN protocol has three layers, confirmed by PCAP traffic and binary RTTI:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Control (TCP/17301)                               │
│  ├── SRP-6a mutual authentication + key agreement           │
│  ├── TLV-framed control messages                            │
│  └── AES-256-CBC encrypted channel (Famatech trailer)       │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Session / RSession (TCP/17351 or shared channel)  │
│  ├── RSA-PKCS#1 v1.5 key transport (client→server)          │
│  ├── 64-byte session key material                           │
│  ├── AES-256-CBC encrypted data channel                     │
│  └── Famatech trailer (checksum + folded MD5 + pad byte)    │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Peer / Data (UDP/9993, keepalive UDP/47836)       │
│  ├── Hole-punching discovery                                │
│  ├── AES-256-CBC encrypted peer data                        │
│  └── Famatech trailer                                       │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 Layer 1 — Control Channel (CONFIRMED structure)

- **Transport:** TCP, 4-byte big-endian length prefix `[len][payload]`, confirmed in PCAP frames 77, 80, 81, 82, 87, 88, 93, 94 of `radmin-connect.pcapng`.
- **Version negotiation:** 8-byte frame `00 00 00 04 03 00 00 00` (length=4, version=3), confirmed across all PCAP captures.
- **Authentication:** SRP-6a (1536-bit group, g=5), 6-step TLV exchange, confirmed via `shelper.dll` method tables `"SRP-6a client (tjw)"` / `"SRP-6a server (tjw)"` at `0x100ad75c`/`0x100ad7b4`.
- **Session key:** 40-byte KDF output (SHA-1 over S‖counter), first 32 bytes = AES-256 key.
- **Frame encryption:** AES-256-CBC with Famatech proprietary trailer (additive 64-bit checksum → MD5 → 8-byte fold + pad byte).

### 2.2 Layer 2 — Session / RSession Channel (CONFIRMED structure, split unverified)

- **Transport:** TCP (port 17351 observed in PCAP for coordination; shared channel for data).
- **Key establishment:** Client generates 64 random bytes, encrypts with server's RSA-2048 public key (PKCS#1 v1.5), server decrypts with private key. Confirmed in `shelper.dll` `SHelper_CChannel_CreateClient`/`CreateServer` and `RSession_CreateClient`/`CreateServer`.
- **Session key:** First 32 bytes of the 64-byte secret used as AES-256 key (split into enc/dec **UNVERIFIED** — see Investigation C, §8, hypothesis E12).
- **Frame encryption:** AES-256-CBC with Famatech trailer, same as Layer 1.

### 2.3 Layer 3 — Peer Data Channel (CONFIRMED structure, crypto unverified)

- **Transport:** UDP/9993 between virtual IPs (26.x.x.x), hole-punching from multiple source ports (9993, 48318, 488870).
- **Keepalive:** UDP/47836, 4-byte sequential counter (`XX 02 00 00`, little-endian).
- **Encryption:** AES-256-CBC with Famatech trailer (CONFIRMED structure in PCAP payloads; key derivation UNVERIFIED).
- **TLV field 0x0004:** Contains peer IPv4 (big-endian) + port (big-endian), CONFIRMED in PCAP frame 116 offset 0x6f–0x76.

---

## 3. Cryptographic Primitives Inventory

| Primitive | Algorithm | Mode/Params | Source | Confidence |
|---|---|---|---|---|
| Symmetric cipher | AES-256 | CBC | `shelper.dll` AESCryptor vtable `0x100832a0` slots +0x18/+0x1c | CONFIRMED |
| Block size | 16 bytes | — | `AESCryptor::GetBlockSize` returns 0x10 | CONFIRMED |
| Key size | 32 bytes | AES-256 | `SetKeyEnc`/`SetKeyDec` reject ≠32 bytes | CONFIRMED |
| IV | 16 bytes | Persistent (copied from last ciphertext block) | AESCryptor object layout `+0x1ec`/`+0x1fc` | CONFIRMED |
| Padding | 0xCC fill | + 8-byte checksum + 1-byte size (9 bytes overhead) | `FUN_10069c20` | CONFIRMED |
| Checksum | Additive 64-bit | LE word-additive, `mod 2^64` | `FUN_1006a0c0` | CONFIRMED |
| Digest | MD5 | RFC 1321, 92-byte context | `0x10005250`/`0x10004e50`/`0x10004f30` | CONFIRMED |
| Digest fold | Byte-wise add | `fold[i] = digest[i] + digest[8+i] mod 256` | `0x10069ce0–0x10069d15` | CONFIRMED |
| Trailer | 9 bytes | 8-byte folded MAC + 1-byte pad length | `0x10069d18–0x10069d3a` | CONFIRMED |
| Key exchange (RSession) | RSA-2048 | PKCS#1 v1.5 | `FUN_10065ec0` (pad=1) | CONFIRMED |
| Key exchange (control) | SRP-6a | N=1536-bit, g=5, k=H(N‖PAD(g))† | `shelper.dll` vtables | CONFIRMED (k=H() STRONG INDICATION) |
| Hash | SHA-1 | 20-byte output | `0x10028810`/`0x285f0`/`0x286d0` | CONFIRMED |
| KDF | SHA-1 | `SHA1(S‖BE32(0)) ‖ SHA1(S‖BE32(1))` = 40 bytes | `0x10061790` | CONFIRMED |

† `k = H(N‖PAD(g))` is STRONG INDICATION (SRP-6a class); legacy class uses `k = 3` (UNVERIFIED which class is instantiated).

---

## 4. Key Material Flow

```
Client (RSession)                              Server (RSession)
───────────────────                            ─────────────────
1. Generate 64 random bytes                    │
   (CSPRNG, RAND_bytes)                       │
2. Build 76-byte plaintext:                  │
   [12-byte header (3×u32 LE client_params)] │
   [64-byte key material]                     │
3. RSA-PKCS#1 v1.5 encrypt with              │
   server's 2048-bit public key               │
   ─────────────────────────────────────→   │
                                             │ 4. RSA private decrypt
                                             │    → 76-byte plaintext
                                             │ 5. Store 64 bytes at +0x30
                                             │    key_len=+0x28=0x40
                                             │
                                             │ 6. Emit 4-byte server token
                                             │    (LE u32)
   7. Receive 4-byte token                    ←─────────────────
   8. Session established                     │
   9. AES-256 key = key_material[0..32]       │   AES-256 key = key_material[0..32]†
                                              │   († split into enc/dec UNVERIFIED)
```

---

## 5. Trust Boundaries and Assumptions

1. **SRP-6a vs RSession independence (STRONG INDICATION):** The two mechanisms share the TCP carrier but have disjoint state, disjoint function sets, and no intra-module mixing in `shelper.dll`. Whether `RvROLClient.dll`/`RvControlSvc.exe` combines their outputs is UNKNOWN (call sites not traced due to tool budget exhaustion).

2. **No forward secrecy (CONFIRMED):** RSession key is client-chosen and transported under the server's static RSA public key. Compromise of the server's private key decrypts all past sessions.

3. **No encrypt-then-MAC (CONFIRMED):** The 8-byte folded MD5 is an unkeyed checksum computed over plaintext. An active attacker can forge valid trailers for chosen plaintexts. Authentication rests solely on the SRP-6a/RSA handshake, not on per-packet MACs.

4. **Persistent IVs (CONFIRMED):** AES-CBC IVs are stored in the cipher state object and updated from the last ciphertext block. There is no per-frame IV derivation or reset. Lost/reordered frames break decryption.

---

## 6. Related Documents

| Document | Content |
|---|---|
| `CRYPTO_MD5_ANALYSIS.md` | MD5 implementation, digest folding, 8-byte input, consumer trace |
| `CRYPTO_SRP_ANALYSIS.md` | SRP-6a parameters, handshake state machine, mathematical operations, Rust comparison |
| `CRYPTO_RSESSION_ANALYSIS.md` | RSession state machine, key establishment, key → CChannel chain |
| `CRYPTO_RSA_ANALYSIS.md` | RSA key sizes, formats, padding mode, call chains (pending Investigation D) |
| `CRYPTO_SYMMETRIC_ENCRYPTION.md` | AES-256-CBC, IV handling, packet protection (pending Investigation E) |
| `CRYPTO_RUST_GAP_ANALYSIS.md` | Original-vs-Rust discrepancy matrix (Investigation G) |
| `CRYPTO_UNRESOLVED_QUESTIONS.md` | Open questions and required next steps |

---

**Generated file:** `docs/CRYPTOGRAPHIC_OVERVIEW.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered