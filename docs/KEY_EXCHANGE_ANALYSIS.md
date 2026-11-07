# Key Exchange Analysis — RvROLClient.dll → shelper.dll → CChannel

**Project:** Radmin VPN Linux client (Rust, independent)
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs
**Binaries analyzed:** `RvROLClient.dll` (sha256: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`), `shelper.dll` (sha256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`), `RvRvpnGui.exe`, pcap `radmin_17301.pcap`
**Language:** English
**Status:** Investigation phase — Phase 1 Wave 3 synthesis (Task 3.2), consolidating the Wave 1 static-investigation register (Tasks 1.1, 1.2, 1.3, 2.1; Task 3.1 consolidation approved by reviewer)

---

## 1. Scope and Provenance Policy

This document traces the key-exchange architecture across `RvROLClient.dll`, `shelper.dll`, and the CChannel AES consumers, and reconciles it with the wire evidence from the TCP/17301 capture.

**Status values used in this document:**

| Value | Meaning |
|---|---|
| CONFIRMED | Observed directly in the Wave 1 register (with the producing task cited) |
| INFERRED | Logical conclusion from confirmed evidence; the intermediate step was not observed |
| UNVERIFIED | Rests only on prior traces/earlier sessions and was NOT re-verified in Wave 1 — provenance always cited |
| UNKNOWN | No evidence exists; open gap |

**Wave 1 inputs (register of Task 3.1, reviewer-approved):**

- Task 1.1 — Named pipe (RvRvpnGui.exe): `\\.\pipe\RadminVpnGuiChannel`, no crypto on the pipe
- Task 1.2 — CChannel surface of `RvROLClient.dll` (47 exports, resolver table)
- Task 1.3 — `shelper.dll` (partial pass terminated by circuit breaker)
- Task 2.1 — PCAP forensics (`radmin_17301.pcap`, 85 frames)

Where a Wave 1 finding contradicts a prior deep-audit document, both positions are stated and the item is listed as a contradiction in §8 (C1–C5).

---

## 2. Architecture Summary

Three independent key mechanisms exist, plus one explicitly crypto-free boundary:

| # | Mechanism | Module | Output | Confidence |
|---|---|---|---|---|
| K1 | SRP-6a control-channel authentication (TCP/17301) | `shelper.dll` (SHelper family) | 40-byte KDF output, first 32 bytes used | INFERRED (prior-trace) |
| K2 | RSession RSA key transport (client→server) | `shelper.dll` (RSession family) | 64-byte random secret | CONFIRMED |
| K3 | CChannel AES consumers (AESCryptor) | `shelper.dll` (CChannel family) | Encrypts/decrypts frame payloads | CONFIRMED |
| — | Named pipe `\\.\pipe\RadminVpnGuiChannel` (GUI↔service) | `RvRvpnGui.exe` | No ROLClient/crypto calls on the pipe | CONFIRMED |

**Named-pipe boundary (CONFIRMED, Task 1.1):** the GUI pipe traffic uses plain named-pipe I/O (`ReadFile` @ `FUN_00530150`, `WriteFile` @ `FUN_005301d0`, `TransactNamedPipe` @ `FUN_00561980` sends a 0x2c 44-byte request) and contains **no** `ROLClient` imports and no crypto calls. Imports present: `CreateFileW`, `WaitNamedPipeW`, `WriteFile`, `ReadFile`, `TransactNamedPipe` (notably absent: `CreateNamedPipeW`, `PeekNamedPipe`, `ConnectNamedPipe`, `ReadFileEx`, `WriteFileEx`). The pipe is an unencrypted brokerage channel; the RSA/SRP/AES path lives deeper in the service stack. Pipe subscriber dispatch `FUN_004e2ac0(0, 0x3f6)` performs no I/O and no crypto.

---

## 3. Call Graph (deliverable a)

### 3.1 Layer 0 — Static linkage, import phase (CONFIRMED, Task 1.2)

`RvROLClient.dll` imports exactly **one** function from `shelper.dll`:

```
RvROLClient.dll IAT @ 0x1011121c  →  SHelper_Init (hint/ordinal 22)
```

Provenance: import-table inspection (Task 1.2, CONFIRMED); cross-referenced by `CRYPTO_MD5_ANALYSIS.md` (`SHelper_Init`, ordinal 0x16).

### 3.2 Layer 1 — Dynamic resolution (CONFIRMED, Task 1.2)

```
InitDll (0x10041010)
  → global object @ 0x10187030
      vtable = 0x10115d6c
      vtable[1] = FUN_1003fbd0        (38× GetProcAddress against shelper.dll)
          ↳ stores resolved pointers into the global object's API table, slots +0x58 .. +0xec
```

Correction carried forward (Task 1.2): addresses `0x1003fd48` / `0x1003fd56` inside `FUN_1003fbd0` are **name pushes** feeding `GetProcAddress`, **not indirect calls** (prior "call" claim corrected).

### 3.3 Layer 2 — Resolver slot map (CONFIRMED slot names+offsets; task cites Task 1.2 + `CRYPTO_RSESSION_ANALYSIS.md` §8.3)

| API-table slot (RvROLClient.dll) | Resolved shelper export | shelper implementation | Wave 1 status |
|---|---|---|---|
| `SHelper_Init` +0x58 | `SHelper_Init` | static import | CONFIRMED |
| +0x98 | `SHelper_RSession_CreateClient` | `0x1006b860` (ord 31) | CONFIRMED (Task 1.3) |
| +0x9c..+0xa0 | `SHelper_RSession_CreateServer`/`_Delete` | `0x1006b8f0` (ord 32) / `0x1006b9e0` (ord 33) | CONFIRMED (Task 1.3) |
| +0xa4 | `SHelper_RSession_GetNextBuffer` | `0x1006b1e0` | UNVERIFIED (prior trace) |
| +0xb0 | `SHelper_RSession_GetKey`/`SHelper_GetKey` | `0x1006b010` | UNVERIFIED (prior trace) |
| +0xb4 | `SHelper_CChannel_CreateClient` | `0x1006a8b0` (inner `FUN_1006a630`) | UNVERIFIED (prior trace) |
| **+0xc0** | **`CChannel_SetKeyEnc`** | **`0x1006ab00`** | slot CONFIRMED; implementation UNVERIFIED (prior trace) |
| **+0xc4** | **`CChannel_SetKeyDec`** | **`0x1006aac0`** | slot CONFIRMED; implementation UNVERIFIED (prior trace) |
| +0xc8 | `CChannel_EncryptBuffer` | AESCryptor path | slot name CONFIRMED; call sites UNKNOWN |
| +0xcc | `CChannel_DecryptBuffer` | AESCryptor path | slot name CONFIRMED; call sites UNKNOWN |
| **+0xd0** | **`RSAHelper_CreateWithPublicKey`** | **address mapping UNKNOWN (circuit breaker, Task 1.3)** | name string CONFIRMED |
| **+0xd4** | **`RSAHelper_CreateWithPrivateKey`** | **address mapping UNKNOWN (circuit breaker, Task 1.3)** | name string CONFIRMED |
| +0xd8..+0xe8 | remaining `RSAHelper_*` slots | mapping UNKNOWN | UNKNOWN |

Name-string anchors in `shelper.dll` `.rdata` (CONFIRMED, Task 1.3): `RSAHelper_CreateWithPrivateKey` @ `0x100ab048`, `RSAHelper_CreateWithPublicKey` @ `0x100ab06f`.

### 3.4 Composite call graph

Legend: `→` CONFIRMED edge · `⇒` INFERRED edge · `⋅⋅>` UNKNOWN edge (not located)

```
RvRvpnGui.exe (GUI)
 └→ named pipe \.\pipe\RadminVpnGuiChannel       [CONFIRMED, no crypto]

RvROLClient.dll
 ├→ (static import)    shelper!SHelper_Init                    IAT 0x1011121c
 ├→ InitDll 0x10041010 → global obj 0x10187030 (vtable 0x10115d6c)
 ├→ vtable[1] = FUN_1003fbd0 → 38× GetProcAddress(shelper.dll)
 │     → API table slots +0x58..+0xec                       [§3.3]
 ├⇒ RNG: ADVAPI32 CryptGenRandom, 4 bytes per call          [CONFIRMED, Task 1.2]
 ⋅⋅> call sites: CChannel_CreateClient / SetKeyEnc / SetKeyDec  [UNKNOWN, §8]

shelper.dll (Base = 1, 38 exports)
 ├→ SRP-6a family  (SHelper_CreateClient 0x1006ab90 · CreateServer 0x1006ad20
 │                  GetNextBuffer 0x1006b1e0 · GetKey 0x1006b010)   [prior trace]
 │    ├⇒ SHelper_GetKey 0x1006b010 → FUN_10067000 → blob at obj+0x44/+0x4c
 │    └→ KDF 0x10061790 → 40-byte master key (SRP path)             [prior trace]
 ├→ RSession family (CreateClient 0x1006b860 · CreateServer 0x1006b8f0 ·
 │                  Delete 0x1006b9e0)                               [CONFIRMED]
 │    ├→ FUN_10069bc0 ctor (malloc 0x34)
 │    ├→ FUN_1006a690 client init / FUN_1006a700 server init
 │    ├→ FUN_10065f50 (RSA_new) → FUN_10066170 (n,e) / FUN_10065f70 (full set)
 │    ├→ FUN_1006a2b0 state machine
 │    │    ├→ FUN_10063530 (rand 0x40) → FUN_10005410 (RAND_METHOD.bytes)
 │    │    ├→ FUN_10065ec0 → 0x100092a0 (RSA_size) → 0x100092c0 (RSA_public_encrypt)
 │    │    └→ FUN_10065db0 (RSA_private_decrypt)
 │    └⇒ 64-byte secret stored at obj+0x30 (len +0x28 = 0x40)
 ├→ CChannel family (CreateClient 0x1006a8b0/FUN_1006a630 · SetKeyEnc 0x1006ab00 ·
 │                  SetKeyDec 0x1006aac0)                            [prior trace]
 │    └→ AESCryptor (vftable 0x100832a0, ctor FUN_10062b60, obj 0x20c bytes)
 │         ├→ +0x18 → 0x10062fb0 (AES_set_encrypt_key, bits = len*8 = 256)
 │         ├→ +0x1c → 0x10062f30 (AES_set_decrypt_key, bits = 256)
 │         ├→ +0x20 → 0x10062e90 (block size = 0x10)
 │         ├→ 0x10003b30 (AES-CBC transform)
 │         ├→ IVs: enc @+0x1ec, dec @+0x1fc (persistent, zero-initialized)
 │         └→ trailer: FUN_10069c20 (pad+sign) / FUN_10069f90 (verify+unpad)
 │              ├→ 0x1006a0c0 (64-bit additive checksum)
 │              ├→ FUN_100638f0 → MD5 0x10005250/0x10004e50/0x10004f30 → fold 0x10069ce0
 │              └→ pad byte 0xCC, pad len ∈ [9, 24]
 └→ jumptable thunk FUN_100092e0 (jumptable NOT recovered)           [UNKNOWN]
```

**The two gaps that break this graph** (both UNKNOWN, §8):

1. No call site in `RvROLClient.dll` was located for `CChannel_CreateClient` / `SetKeyEnc` / `SetKeyDec` (register Task 1.2: "exact call sites UNKNOWN"; `CRYPTO_RSESSION_ANALYSIS.md` §8.2 found no `call/jmp [reg+disp8]` sites at +0xb0/+0xb4/+0xc0/+0xc4 and dispatches the consumer to `RvControlSvc.exe`).
2. The shelper-side internal addresses of the `RSAHelper_*` exports were not mapped (Task 1.3 circuit breaker).

---

## 4. 32-Byte AES Key Flow (deliverable b)

### 4.1 Control channel — SRP-6a path (prior-trace, UNVERIFIED in Wave 1)

```
SRP-6a (PAD class, obj+4=3, descriptor 0x100ad75c client / 0x100ad7b4 server)
  → S = (B − k·g^x)^(a + u·x) mod N            core 0x10060510: NEVER DISASSEMBLED
  → KDF 0x10061790: 40 bytes (SHA-1(S ‖ BE32(0)) ‖ SHA-1(S ‖ BE32(1)))   [prior trace]
  → session key = first 32 bytes of the 40-byte KDF output              [prior trace]
  ⇒ SHelper_GetKey 0x1006b010 → FUN_10067000 → blob at obj+0x44 (len +0x4c)
        → RSession_analysis prior chain: 0x10069f50 splits (ptr, len)
  ⇒ RvROLClient prior trace: 0x1003dd40 → min(len, 0x20) → 0x100df250
        installs 32 bytes at this+0x20/+0x24
  ⋅⋅> CChannel_SetKeyEnc/SetKeyDec call site                            [UNKNOWN]
```

Whole-chain status: the SRP internals through `SHelper_GetKey` rest on **prior traces** (`CRYPTO_CONTROL_KEY_LIFECYCLE.md` §4 marks the chain "NOT ADVANCED" / UNVERIFIED today; `PHASE_2_IMPLEMENTATION_REPORT.md` cites `0x1003dd40`/`0x100df250`). Wave 1 did not re-verify any step. Hand-off entropy: server step `b` uses 1536-bit random exponent (prior trace); `RAND_bytes(192)`-with-`BN_add_word(1536)` shape is prior-trace.

### 4.2 RSession channel — RSA key-transport path (CONFIRMED, Task 1.3 + Investigations B/D)

```
1. Client side (FUN_1006a2b0, role 0, state 0):                    CONFIRMED
     RAND_bytes(64) via FUN_10063530 → FUN_10005410 (OpenSSL RAND_METHOD.bytes)
     build 76-byte plaintext = LE32(h0) ‖ LE32(h1) ‖ LE32(h2) ‖ key[64]
     FUN_10065ec0(this, &pt, 0x4c, &outbuf)   → RSA_public_encrypt → 256-byte block
2. Wire: 256-byte ciphertext transmitted on TCP/17301 stream       CONFIRMED (frames opaque)
3. Server side (FUN_1006a2b0, role 1, state 1):                    CONFIRMED
     FUN_10065db0 (RSA_private_decrypt), require plaintext len == 0x4c
     copy plaintext[12..76] (64 bytes) → obj+0x30, len +0x28 = 0x40
     emit 4-byte server token (its own CreateServer arg0, NOT derived from key/hash)
4. Consumer hand-off: 64 bytes @ obj+0x30 …                        UNKNOWN (no consumer found)
5⇒ Reduction to two 32-byte CChannel keys:                          UNVERIFIED HYPOTHESIS
     primary hypothesis:  key_enc = secret[0..32], key_dec = secret[32..64]  (role-dependent ordering possible)
     secondary: hash/KDF derivation in consumer (no hash call exists on the RSession path)
```

Status provenance: steps 1–3 CONFIRMED at instruction level (Tasks 1.3/Investigation B). Step 4 UNKNOWN — Wave 1 register: "concrete 32-byte key derivation UNKNOWN"; `CRYPTO_RSESSION_ANALYSIS.md` E12 classifies the 64→32+32 split as **HYPOTHESIS / UNVERIFIED** and locates the likely consumer in `RvControlSvc.exe` (untraced). There is **no KDF** on either RSession path (complete callee set of `FUN_1006a2b0` verified: no MD5/SHA/HKDF/HMAC reachable).

**Critical divergence for the Rust port** (cross-reference `CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md` B9–B11/C15): current Rust `from_rsession_key()` uses `key_material[..32]` for **both** enc and dec — `CONFIRMED_MISMATCH` against the binary's two-key contract (`CChannel_CreateClient` requires exactly two 32-byte keys; `SetKeyEnc`/`SetKeyDec` enforce len = 0x20). The correct 64→32+32 split (or derivation) is the single most important key-exchange gap.

### 4.3 Origin of the 32-byte AES keys (CONFIRMED negative finding, Task 1.2)

`RvROLClient.dll`'s only random source is **ADVAPI32 `CryptGenRandom` producing 4 bytes per call** (CONFIRMED). A 32-byte AES key is never generated inside `RvROLClient.dll` (INFERRED: no 32-byte random generation exists there; every crypto primitive is imported from `shelper.dll` via the resolver). Corollary: the 32-byte keys must originate in `shelper.dll` (K2 output for RSession sessions, or the K1 SRP output for control-channel sessions) and reach the AESCryptor **through unlocated call sites** — this is exactly gap §8/U1.

---

## 5. RSA Operations (deliverable c)

### 5.1 Identified RSA operations with addresses

| Operation | Address (shelper.dll unless noted) | Wave 1 status |
|---|---|---|
| `RSAHelper_CreateWithPublicKey` slots | RvROLClient API table slot **+0xd0** | slot name CONFIRMED (Task 1.2) |
| `RSAHelper_CreateWithPrivateKey` slots | RvROLClient API table slot **+0xd4** | slot name CONFIRMED (Task 1.2) |
| shelper implementation addresses of `RSAHelper_*` exports | — | **UNKNOWN** (Task 1.3 circuit breaker) |
| `RSA_new` | `0x10065f50` | CONFIRMED |
| Key import, client: `n` @ rsa+0x10, `e` @ rsa+0x14 via BN_bin2bn | `0x10066170` | CONFIRMED |
| Key import, server: full private set `n,e,d,p,q,dmp1,dmq1,iqmp` @ rsa+0x10..+0x2c | `0x10065f70` | CONFIRMED |
| `BN_bin2bn` (raw big-endian; no DER/PEM) | `0x10008a40` | CONFIRMED |
| `RSA_size` (`rsa+0x10` = n) → 0x100 (256 B) | `0x100092a0` | CONFIRMED |
| `RSA_public_encrypt` via `RSA_METHOD.rsa_pub_enc` (meth+4) | `0x100092c0` | CONFIRMED |
| `RSA_public_encrypt` wrapper (flen=0x4c, pad=1) | `FUN_10065ec0` | CONFIRMED |
| Padding-mode constant `PUSH 0x1` @ | **`0x10065f05`** | constant CONFIRMED; **interpretation UNVERIFIED** (§5.2) |
| `RSA_private_decrypt` wrapper | `FUN_10065db0` | CONFIRMED |
| RSession client state machine | `FUN_1006a2b0` role 0 | CONFIRMED |
| RSession server state machine | `FUN_1006a2b0` role 1 | CONFIRMED |

Fields `+0x28` / `+0x30` inside `FUN_1006a690` / `FUN_1006a700` were not resolved in the Wave 1 `shelper.dll` pass (UNKNOWN, Task 1.3 circuit breaker). Note the jumptable thunk `FUN_100092e0` (Task 1.3) has a jumptable that was not recovered; do not confuse it with the RSA primitives list above.

### 5.2 RSA padding mode — contradiction C3

- **Position A (prior deep-audit traces):** `PUSH 0x1` = `RSA_PKCS1_PADDING` ⇒ PKCS#1 v1.5 block `00 02 FF…FF 00 || plaintext` for a 256-byte modulus with 76-byte plaintext (169 × `0xFF`) — cited in `CRYPTO_RSA_KEY_PROVENANCE.md` §2 and `CRYPTO_RSESSION_KEY_LIFECYCLE.md` §2.3 (both mark it CONFIRMED there). Additionally `rsaesOaep` string has zero xrefs and no `RSA_sign`/`RSA_verify` in any traced chain (absence claims, prior traces).
- **Position B (Wave 1, Task 1.3):** the padding mode at `0x10065f05` and the OAEP/MGF absence were **not re-verified** (circuit breaker); register classifies them UNKNOWN.
- **Resolution:** evidence weight currently favors PKCS#1 v1.5 (Position A), but per the register this stays **UNVERIFIED until `0x10065f05`'s surrounding context is re-disassembled**. Listed as contradiction C3 in §8. No OAEP/MGF code was found anywhere in Wave 1 either — absence of positive OAEP evidence is consistent with Position A.

### 5.3 RSA key sizes and formats (CONFIRMED)

| Parameter | Value | Evidence |
|---|---|---|
| Modulus | 2048 bits / 256 bytes | `RSA_size` → `0x100`; `RSESSION_RSA_BLOCK_SIZE = 256` |
| Ciphertext block | 256 bytes | 76-byte plaintext + PKCS#1 v1.5 + 2048-bit modulus |
| Plaintext | 76 bytes (`0x4c`): 12-byte header (3× LE u32) + 64-byte key material | `FUN_1006a2b0` |
| Key format | raw big-endian components via `BN_bin2bn` | `0x10008a40` |
| Public exponent value | imported from caller buffer; value in binary UNKNOWN (Rust assumes 0x010001 = 65537) | buffer source UNKNOWN |

### 5.4 RSA provenance gaps (UNKNOWN)

Client public key `(n, e)` and server private-component buffers (8 pairs) to `SHelper_RSession_CreateClient`(0x1006b860) / `CreateServer`(0x1006b8f0) are **caller-supplied**. Which component (RvROLClient.dll? RvControlSvc.exe? config/certificate file?) supplies them, whether the key is static or rotated, and whether the client validates the server key are all UNKNOWN — details in `CRYPTO_RSA_KEY_PROVENANCE.md` §3–§7.

---

## 6. Cryptographic Parameters with Offsets (deliverable d)

### 6.1 SRP-6a group (control channel) — prior-trace provenance, matching Wave 1 register

| Parameter | Value | Offset (shelper.dll) | Status |
|---|---|---|---|
| Modulus N | 1536-bit (192 bytes, big-endian), starts `e634471e75f2d76a…`, ends `…216cd54c7` | `0x100ac280` (length 0xC0, pinned via memcmp at `0x100699e0`) | prior trace: CONFIRMED in `CRYPTO_SRP_ANALYSIS.md`; register treats as resting on prior traces (not re-verified in Wave 1) |
| Generator g | `0x05` (1 byte) | `0x100ac279` (descriptor `0x100ac358 → (0x100ac279, 1)`) | prior trace, same caveat |
| SHA-1 primitives (Tom Wu bundled `(tjw)`, NOT OpenSSL) | SHA1_Init / Update / Final | `0x10028810` / `0x100285f0` / `0x100286d0` | prior trace (`CRYPTO_CONTROL_KEY_LIFECYCLE.md` §6 uses the same triple in tables — re-verified there during deep audit) |
| Multiplier k | `k = SHA1(N ‖ PAD(g,192))` for SRP-6a class (legacy SRP-6 class encodes `k = 3`) | k-path `0x10060810`; S core `0x10060510` (never disassembled) | INFERRED/UNVERIFIED (formula); class selection CONFIRMED by prior trace |
| KDF | 40 bytes, iterative SHA-1 over `S ‖ counter_be32` | `0x10061790` | prior trace UNVERIFIED in Wave 1 (deep-audit doc `CRYPTO_RUST_GAP_ANALYSIS.md` marks CONFIRMED_MATCH vs Rust) |
| SRP class descriptors | `"SRP-6/6a client (tjw)"`, `"SRP-6/6a server (tjw)"`, PAD flag bit 0x2 | `.data 0x100ad730`–`0x100ad7d8`; name strings `.rdata 0x100a3de0`–`0x100a3e1f` | prior trace CONFIRMED + re-read in deep audit |
| BIGNUM object size | 0x14 bytes, layout +0x00 vt, +0x04 size, +0x08 data, +0x0c refcnt, +0x10 alloc | `0x1005f450`–`0x1005f4a1` | prior trace CONFIRMED |

Note: earlier phase-2 documents (`PHASE_2_IMPLEMENTATION_REPORT.md`) state `k = 3` as "proven"; the deep audit re-traced the init path and found `k = 3` only on the **legacy SRP-6** descriptor path (`0x100607d5: push 3`), with the deployed SRP-6a class computing `k` inline via SHA-1 (`0x10060810`). Wave 1 does not adjudicate; both paths are listed and the SRP-6a claim currently has stronger instruction-level evidence. No wire-level SRP frames were re-verified in Wave 1 (the capture is opaque from the first byte after framing, Task 2.1).

### 6.2 AES / CChannel parameters (CONFIRMED at shelper instruction level; consumer wiring UNKNOWN)

| Parameter | Value | Offset / address | Status |
|---|---|---|---|
| Cipher | AES-256-CBC | key slots `0x10062fb0` (enc) / `0x10062f30` (dec); CBC transform `0x10003b30` | CONFIRMED (prior session re-reads) |
| Key slots (vtable 0x100832a0) | +0x18 enc, +0x1c dec, +0x20 block size | returns 0x10 | CONFIRMED |
| Key length | exactly 32 bytes (`0x20`) enforced | `SetKeyEnc 0x1006ab00`, `SetKeyDec 0x1006aac0` | CONFIRMED (prior session) |
| AESCryptor object | 0x20c bytes, ctor `FUN_10062b60`, vftable `0x100832a0`; second vftable `0x100832c4` (TwoFishV2-shaped, no instantiation) | — | CONFIRMED / second vftable UNKNOWN (likely dead) |
| IVs | 16 bytes each, zero-initialized, persistent across frames, updated from last ciphertext block; independent per direction | enc IV `+0x1ec`, dec IV `+0x1fc` | CONFIRMED |
| Padding | pad byte `0xCC`; pad length ∈ [9, 24]; total = ((payload+8+block)/block)*block | encrypt `FUN_10069c20`, verify `FUN_10069f90` (gate `0x10069fe5`) | CONFIRMED |
| Trailer | 9 bytes: 8-byte folded MD5 + 1-byte pad length; decrypt-before-validation order confirmed | checksum `0x1006a0c0`; MD5 ctx `FUN_100638f0` → `0x10005250/0x10004e50/0x10004f30`; fold `0x10069ce0`–`0x10069d15` | CONFIRMED (not a MAC — unkeyed) |
| Wire corroboration | payload sizes ≡ 0 mod 16 in capture (only exception: the 4-byte control frame), consistent with 16-byte block CBC | frames f32/f35/f40/f44 of `radmin_17301.pcap` | CONFIRMED observation; semantics UNKNOWN |

### 6.3 RSA parameters

See §5.3: RSA-2048, raw BE components via `BN_bin2bn 0x10008a40`, plaintext 76 bytes, pad=1 constant @ `0x10065f05`, ciphertext 256 bytes.

### 6.4 RNG parameters

| Source | Output | Address | Status |
|---|---|---|---|
| `RvROLClient.dll` — ADVAPI32 `CryptAcquireContext`/`CryptGenRandom`/`CryptReleaseContext` | 4 bytes per call | inside RvROLClient.dll | CONFIRMED (Task 1.2) |
| `shelper.dll` — statically linked OpenSSL 1.0.1f `RAND_METHOD.bytes` | 64 bytes (`FUN_10063530` → `FUN_10005410`) on RSession path; 1536-bit/192-byte shaped draws on SRP path | dispatch `DAT_100b015c[1]` | CONFIRMED (RSession) / prior trace (SRP draw shape) |

---

## 7. CChannel ↔ AES Key Relationship (deliverable e)

**Contract (CONFIRMED at shelper level):** a CChannel object requires **two exactly-32-byte keys**:

- `CChannel_CreateClient` (`0x1006a8b0`, inner `FUN_1006a630`) — takes two 32-byte keys, allocates an AESCryptor (vftable `0x100832a0`).
- `CChannel_SetKeyEnc` (`0x1006ab00`) / `CChannel_SetKeyDec` (`0x1006aac0`) — both reject length ≠ `0x20` (32).
- RvROLClient API-table slots storing the resolved pointers: **+0xc0 (SetKeyEnc), +0xc4 (SetKeyDec), +0xc8 (EncryptBuffer), +0xcc (DecryptBuffer)** — pointers installed by `FUN_1003fbd0` (38× GetProcAddress).

**Key provenance into those slots (UNVERIFIED):**

| Channel | Key candidate source | Hand-off observed? |
|---|---|---|
| Control channel (TCP/17301) | first 32 bytes of the 40-byte SRP-6a KDF output, retrievable via `SHelper_GetKey 0x1006b010` blob (obj+0x44/+0x4c) | No — `GetKey`→`SetKeyEnc/SetKeyDec` call sites never located anywhere (RvROLClient or RvControlSvc) |
| RSession channel | 64-byte random secret (obj+0x30, len+0x28=0x40), RSA-transported | No — no `call/jmp [reg+0xb0..+0xc4]` sites in RvROLClient.dll (only unrelated scheduler code at `0x1000a3d0`); dispatch of `RSession_CreateClient/Server` unknown; consumer likely `RvControlSvc.exe` (STRONG INDICATION, untraced) |

**Implication:** the composition point `source → SetKeyEnc/SetKeyDec` lives outside `shelper.dll` (no intra-module xrefs exist for the seven RSession exports, CONFIRMED at Investigation E14) and was not found in `RvROLClient.dll` (Wave 1). Until `RvControlSvc.exe`'s resolver/call sites are traced, ANY 64→32+32 mapping or GetKey→AESC installation claim must be labeled UNVERIFIED/UNKNOWN. This is the core subject of contradictions C1 and C2 (§8).

---

## 8. Remaining Gaps (deliverable f)

### 8.1 Wave 1 UNKNOWN items (per task)

| # | Gap | Source task | Notes |
|---|---|---|---|
| U1 | Exact call sites of `CChannel_CreateClient`, `SetKeyEnc`, `SetKeyDec` in consumers | 1.2 | Blocks the whole key-install chain; trace `RvControlSvc.exe` resolver |
| U2 | Concrete 32-byte key derivation (64 → 32+32) | 1.2 / 1.3 | Split halves vs KDF; INFERRED hypothesis only |
| U3 | `RSAHelper_*` shelper function-address mapping; fields +0x28/+0x30 in `FUN_1006a690`/`FUN_1006a700` | 1.3 | Circuit breaker; requires fresh shelpers sweep |
| U4 | RSA padding mode @ `0x10065f05`; OAEP/MGF absence | 1.3 | See §5.2 / C3 |
| U5 | Wire message semantics of the GUI pipe (44-byte `TransactNamedPipe` request, 0x3f6 notification, serializer/receiver) | 1.1 | No crypto on pipe (CONFIRMED), but structure UNKNOWN; prior "12-byte envelope" claim NOT reproduced |
| U6 | `FUN_100092e0` jumptable | 1.3 | Not recovered |
| U7 | Key-exchange field layout/cipher/padding semantics on the wire; `03 00 00 00` frame; no plaintext→ciphertext transition observed (opaque from byte 1) | 2.1 | PCAP |
| U8 | "1960-byte packet" and `45.162.230.182:17351` NOT reproduced | 2.1 | C4 below |
| U9 | `radmin_vm2.pcap` inaccessible (root-owned, 0600) | 2.1 | B1 below |
| U10 | No ephemeral-key memory dump; no PDB for `RvROLClient.dll` | 3.1 | B2/B4 below |
| U11 | Wire message semantics overall (`B5` in the register — carried here as packet-field semantics, distinct from U7 channel framing) | 3.1 | blocks packet reconstruction |

### 8.2 Contradictions C1–C5 (register of Task 3.1)

| ID | Contradiction | Current best position (evidence cited above) |
|---|---|---|
| C1 | Key provenance: static-analysis claims of key flows vs. absence of located call sites (register: exists and stops) | Position "exists, consumer unlocated" — accept only chain edges with addresses; everything else UNKNOWN |
| C2 | Mechanism: RSA key transport vs SRP-6a | **INFERRED: both exist, on separate channels** — SRP-6a = control channel (K1), RSA = RSession (K2); `SHelper_GetKey` blob is disjoint from the RSession state machine (prior E13). Final composition point UNKNOWN (see §7) |
| C3 | RSA padding: OAEP vs PKCS#1 v1.5 | Prior traces favor PKCS#1 v1.5 (`PUSH 0x1` @ `0x10065f05`); Wave 1 could not re-verify — UNVERIFIED pending `0x10065f05` re-disassembly (§5.2) |
| C4 | Server `45.162.230.182:17351` / "1960-byte packet" in a prior claim | NOT reproduced in Wave 1, treat as unverified observation of unknown provenance |
| C5 | Documentation state drift (docs implying Phases 2–3 complete vs. actual plan Phase 1) | informational; this document is a Phase 1 Wave 3 artifact |

Also carried from the deep-audit (not in the C-list, but material to key exchange): the `k` multiplier discrepancy — legacy `k = 3` (phase-2 docs) vs `k = SHA1(N‖PAD(g))` (deep audit, SRP-6a class) — see §6.1 note; unresolved until `0x10060510` is disassembled.

### 8.3 Blockers B1–B5 (register of Task 3.1)

| ID | Blocker | Impact on key-exchange analysis |
|---|---|---|
| B1 | `radmin_vm2.pcap` inaccessible (root-owned 600) | second capture cannot corroborate 17351-claims (C4) |
| B2 | No ephemeral-key memory dump | post-handshake frames stay opaque; no offline confirmation of K1/K2 outputs |
| B3 | RSA padding unconfirmed | C3 open; affects plaintext-76 reconstruction predictions only, not sizes |
| B4 | No PDB for `RvROLClient.dll` | symbol-less wiring; call sites of U1 can only come from dynamic-analysis-style tracing of indirect calls |
| B5 | Wire message semantics unknown | even with keys recovered, frame fields need mapping |

### 8.4 Re-verification targets (exact addresses)

1. `objdump -d --start-address=0x10065ec0 --stop-address=0x10065f60 shelper.dll` — resolve RSA padding `PUSH 0x1` @ `0x10065f05` (C3/B3).
2. Locate `GetProcAddress`-slot call sites (`[reg+0xc0]`, `[reg+0xc4]`, `[reg+0xb0]`, `[reg+0xb4]`) in `RvROLClient.dll` **and** `RvControlSvc.exe` (U1/C1).
3. Disassemble `0x10060510` (S core) and `0x10061790` (KDF) to settle the k/S/KDF chain (C2, §6.1).
4. Map `RSAHelper_*` export addresses in `shelper.dll` from the name anchors `0x100ab048`/`0x100ab06f`, and resolve fields +0x28/+0x30 of `FUN_1006a690`/`FUN_1006a700` (U3).
5. Retry access to `radmin_vm2.pcap` (B1) if permissions allow.

---

## 9. Evidence Sources

Wave 1 register (Task 3.1, reviewer APPROVED): Task 1.1 (named pipe), Task 1.2 (CChannel surface of RvROLClient.dll), Task 1.3 (shelper.dll, circuit-broken), Task 2.1 (PCAP).

Cross-referenced existing documents:

- `docs/CRYPTO_CONTROL_KEY_LIFECYCLE.md` — SRP-6a chain, class descriptors, k/S/KDF
- `docs/CRYPTO_SRP_ANALYSIS.md` — N @ `0x100ac280`, g @ `0x100ac279`, hash primitives
- `docs/CRYPTO_RSESSION_ANALYSIS.md` — slot map +0x98..+0xec, E12 hypothesis, consumer dispatch
- `docs/CRYPTO_RSESSION_KEY_LIFECYCLE.md` — 76-byte plaintext, RSA call sites, no-KDF proof
- `docs/CRYPTO_AES_CONSUMER_TRACE.md` — AESCryptor vtable, IVs, pad/trailer
- `docs/CRYPTO_RSA_KEY_PROVENANCE.md` — RSA parameters, padding position A, provenance UNKNOWNs
- `docs/CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md` — binary-vs-Rust matrix (B9–B11, C15)
- `docs/PHASE_1_UNRESOLVED.md`, `docs/CRYPTO_MD5_ANALYSIS.md` — export family addresses

**Limitation:** all items marked UNVERIFIED rest only on the cited prior-trace documents and were not re-executed in Wave 1. Items marked UNKNOWN have no evidence trail at all — they are not inferred, guessed, or extrapolated.

---

**Generated file:** `docs/KEY_EXCHANGE_ANALYSIS.md`
**Original binaries and PCAPs:** Preserved, unmodified
**Rust source code:** Unaltered
