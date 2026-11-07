# Cryptographic Analysis — RSession Key Establishment

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Binaries analyzed:** `shelper.dll` (sha256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`), `RvROLClient.dll` (sha256: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`), `RvControlSvc.exe` (sha256: `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`)  
**Language:** English  
**Status:** Investigation phase — evidence-backed  

---

## 1. Scope

This document analyzes RSession cryptography in `shelper.dll` — the session key establishment mechanism that is **separate from** control-channel authentication (SRP-6a). It is part of Investigation C of the cryptographic deep audit.

All findings are from static disassembly (instruction-level). Dynamic execution was **not possible**; confidence rests on structural and constant-level identity.

---

## 2. RSession Function Inventory

### 2.1 Exported API (ordinals 31–37)

| Ordinal | Export | Address | Role |
|---|---|---|---|
| 31 | `SHelper_RSession_CreateClient` | `0x1006b860` | Thin wrapper → `FUN_10069bc0` + `FUN_1006a690` |
| 32 | `SHelper_RSession_CreateServer` | `0x1006b8f0` | 17 args (8 × (buf,len) RSA components + int) → `FUN_10069bc0` + `FUN_1006a700` |
| 33 | `SHelper_RSession_Delete` | `0x1006b9e0` | Zeroes `+0x28`/`+0x2c`, frees `+0x30`, frees RSA |
| 34 | `SHelper_RSession_GetClientDataOnServer` | `0x1006ba40` | Guarded read of `+0x14..+0x1c` |
| 35 | `SHelper_RSession_GetKey` | `0x1006ba80` | Guard `FUN_1006a270` then return `(+0x30, +0x28)` |
| 36 | `SHelper_RSession_GetNextBuffer` | `0x1006bb10` | Public entry to state-machine worker |
| 37 | `SHelper_RSession_GetServerDataOnClient` | `0x1006bbb0` | Guarded read of `+0x14` |

**CONFIRMED:** No `SHelper_*` export is referenced by any intra-module xref inside `shelper.dll` (Ghidra callers list empty for all seven). Composition therefore happens in consumer binaries (`RvROLClient.dll`, `RvControlSvc.exe`).

### 2.2 Internal Functions

| Function | Address | Role |
|---|---|---|
| `FUN_10069bc0` | `0x10069bc0` | Constructor; zeroes `+0x04..+0x24`, `+0x28`, `+0x2c`, `+0x30`; allocates RSA via `FUN_10065f50` |
| `FUN_1006a690` | `0x1006a690` | Client init (copies 12-byte header from 3 args, sets role `+0x20` = 0) |
| `FUN_1006a700` | `0x1006a700` | Server init (RSA private components, sets role `+0x20` = 1, state `+0x24` = 1) |
| `FUN_1006a2b0` | `0x1006a2b0` | State-machine worker (not an export) |
| `FUN_1006a270` | `0x1006a270` | `GetKey` guard |
| `FUN_1006a220` | `0x1006a220` | Client-data getter |
| `FUN_10065f50` / `FUN_10009290` / `FUN_10008fa0` | — | `RSA_new` path (source string `.\\crypto\\rsa\\rsa_lib.c` line `0x8b`) |
| `FUN_10066170` | `0x10066170` | Client RSA: sets `n`@`+0x10`, `e`@`+0x14` via `BN_bin2bn` (`FUN_10008a40`) |
| `FUN_10065f70` | `0x10065f70` | Server RSA: `n,e,d,p,q,dmp1,dmq1,iqmp` @ `+0x10..+0x2c` |
| `FUN_10065ec0` | `0x10065ec0` | RSA public encrypt (padding mode `PUSH 0x1` @ `0x10065f05`) |
| `FUN_10065db0` | `0x10065db0` | RSA private decrypt |
| `FUN_10063530` → `FUN_10005410` | — | RAND engine wrapper for 64 random bytes |
| `FUN_10069c20` / `FUN_1006a0c0` | — | Frame seal + 64-bit additive checksum |
| `FUN_100638f0` | `0x100638f0` | MD5 wrapper (Init/Update/Final) |
| `FUN_10069f90` | `0x10069f90` | Frame validator (recomputes trailer) |
| `FUN_10062b60` | `0x10062b60` | AESCryptor (CChannel) constructor, object size `0x20c` |
| `FUN_10003b30` | `0x10003b30` | AES-CBC transform |
| `FUN_1006c944` / `FUN_1006c980` | — | `malloc` / `memcpy` thunks |

---

## 3. RSession State Machine (CONFIRMED)

### 3.1 Structure Fields

| Offset | Type | Meaning | Confidence |
|---|---|---|---|
| `+0x00` | `RSA*` | RSA context | CONFIRMED |
| `+0x04` | `u32` | 12-byte header field 1 (client `CreateClient` arg) | CONFIRMED |
| `+0x08` | `u32` | 12-byte header field 2 | CONFIRMED |
| `+0x0c` | `u32` | 12-byte header field 3 | CONFIRMED |
| `+0x10` | `int` | Established flag (0/1); server = decrypted header[3] | CONFIRMED |
| `+0x14` | `u32` | Client: 4-byte value from server; server: decrypted header[0] | CONFIRMED |
| `+0x18` | `u32` | Decrypted header[1] (server only) | CONFIRMED |
| `+0x1c` | `u32` | Decrypted header[2] (server only) | CONFIRMED |
| `+0x20` | `int` | Role (0 = client, 1 = server) | CONFIRMED |
| `+0x24` | `int` | State (0..3) | CONFIRMED |
| `+0x28` | `u32` | Key length = `0x40` (64) | CONFIRMED |
| `+0x2c` | `u32` | Key capacity = `0x40` | CONFIRMED |
| `+0x30` | heap ptr | 64-byte symmetric key | CONFIRMED |

**REFUTED:** The task brief's "+0x28 = AES key size 32 bytes". The stored value is `0x40` = 64. If a 32-byte AES key is derived, it is derived downstream, not here.

`GetKey` in state INIT fails: `FUN_1006a270` requires `+0x10 != 0` **and** `+0x28 != 0` **and** `+0x30 != 0` — CONFIRMED.

### 3.2 Client State Machine (CONFIRMED)

Entry state `0 = INIT`:

1. **State 0 → 1:** Writes `+0x24 = 1` at `0x1006a517`, allocates a `0x4c` blob (12-byte header + 64 random bytes), RSA-encrypts it, emits it.
2. **State 1 → 2:** `INC [ESI+0x24]` at `0x1006a5eb` → state `2 = AWAIT_ACK`.
3. **State 2 → 3:** Accepts a blob of exactly 4 bytes: `+0x14 = LE32(blob)`, `+0x24 = 3`, `+0x10 = 1`, emits an empty blob with the "produced output" flag set.

### 3.3 Server State Machine (CONFIRMED)

Entry state `1 = AWAIT_KEY` (`CreateServer` sets state 1):

1. **State 1 → 2:** RSA-decrypts the `0x4c` blob, validates decrypted length, copies header bytes into `+0x14`, `+0x18`, `+0x1c` and the 64-byte key into heap buffer at `+0x30`, sets `+0x28 = +0x2c = 0x40`, then `INC [..+0x24]` → 2.
2. **State 2 → 3:** Emits a 4-byte reply taken from `*(this+0x04)`, then `INC` → 3, `+0x10 = 1`.

**Observation:** The client's 4-byte ACK value is opaque; the server never interprets it beyond length (STRONG INDICATION it is a cookie the client echoes; exact semantic UNKNOWN).

---

## 4. Key Establishment (CONFIRMED)

1. Client generates **64 random bytes** (`FUN_10063530` → `FUN_10005410`, OpenSSL RAND wrapper).
2. Wire blob = `0x4c` bytes = 12-byte cleartext header || 64-byte key material.
3. Whole `0x4c` blob is encapsulated with **RSA public-key encryption**, padding mode constant `1` (`PUSH 0x1` at `0x10065f05` inside `FUN_10065ec0`).
4. Server decrypts with `RSA_private_decrypt` (`FUN_10065db0`), validates length, stores the 64 bytes verbatim at `+0x30`.
5. **No DH, no ECDH, no SRP, no HKDF/PBKDF/KDF call exists anywhere in the RSession path** — the 64 bytes are used as-is (STRONG INDICATION that any splitting/derivation happens in the consumer).

**Threat-model consequence:** The session key is chosen entirely by the client and transported under the server's RSA public key. There is no server-side contribution and **no forward secrecy**. Compromise of the server's private key decrypts all past sessions. The 64-byte key is not authenticated beyond RSA-PKCS#1 v1.5 padding validity.

---

## 5. RSA Participation (CONFIRMED)

- **Ownership:** `RSession+0x00`.
- **Client:** Only `(n, e)` imported from two caller buffers via `BN_bin2bn` (`FUN_10066170`).
- **Server:** Full private set `(n,e,d,p,q,dmp1,dmq1,iqmp)` imported by `FUN_10065f70` from the 8 `(buf,len)` `CreateServer` arguments.
- **Padding:** **RSA_PKCS1_PADDING only**. No OAEP constant loaded on this path.
- **No RSA signing / no `md5WithRSA` invocation** reachable from RSession, despite the algorithm-name string being present elsewhere in the static OpenSSL.

---

## 6. MD5 / Digest Participation (CONFIRMED)

The prior round-02 document asserted "no MD5 anywhere". That is **wrong**.

**Digest path:**

- Seal: `FUN_10069c20` → `FUN_1006a0c0` computes a **64-bit additive checksum** over the region `0..(total-9)`, where `total = ((payload + 8 + block) / block) * block` and `block < 0x100`.
- `FUN_100638f0` → `MD5_Init` `0x10005250` (IV `0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`; 0x5c-byte context), `MD5_Update` `0x10004e50`, `MD5_Final` `0x10004f30` over the **8-byte checksum only** (not over the payload).
- 16-byte digest is folded to 8 bytes by byte-wise `out[i] += out[i+8]` (asm `0x10069ce0–0x10069d15`).
- Result written at `buf[total-9]`; last byte at `buf[total-1]` = pad length (range 9..24); pad bytes are `0xCC`.
- Validator `FUN_10069f90` recomputes the identical construction.

**Cryptographic assessment:** This is **not a MAC**. It is a non-keyed checksum-of-a-checksum, so it provides integrity against random corruption only, not against an active attacker. Authentication rests solely on AES-CBC with persistent IVs (below), which is malleable. There is no encrypt-then-MAC.

**CChannel frame crypto:** `FUN_10003b30` = AES-CBC; `AES_KEY` for encryption at `+0x4` with IV at `+0x1ec`, for decryption at `+0xf8` with IV at `+0x1fc` (AESCryptor object size `0x20c`). IVs are **persistent across frames** (no per-frame IV derivation) — CONFIRMED from object layout, since only two IV buffers exist and no per-call IV reset was observed.

---

## 7. Relationship to Control-Channel Authentication

- RSession performs **key transport only**. It has no password, no verifier, no SRP messages, no DH group parameters. **CONFIRMED** by exhaustive function inventory above.
- `SHelper_GetKey` (`0x1006b010` → `FUN_10067000`) is a **different** mechanism: it returns a blob at the SHelper object's `+0x44`/`+0x4c`, filled by the SHelper protocol state machine at `+0x21cc` from peer data (tags `0x10000000`..`0x70000000`). RSession never touches those fields and `FUN_10067000` is never called from `FUN_1006a2b0` or its callees.
- **STRONG INDICATION:** Control-channel authentication (SRP-6a) and RSession key establishment are **independent mechanisms that only share the TCP carrier**. Their outputs are not mixed inside `shelper.dll`.
- Caveat: Absence of intra-module xrefs cannot prove the consumer does not combine them; the combination point, if any, lives in `RvROLClient.dll` / `RvControlSvc.exe`.

---

## 8. Key → CChannel Installation Chain

### 8.1 Established Facts

- `SHelper_CChannel_CreateClient` (`0x1006a8b0`, internal `FUN_1006a630`) requires **two keys of exactly 32 bytes** and creates an AESCryptor (vftable `0x100832a0`).
- Key setters `SHelper_CChannel_SetKeyEnc` (`0x1006ab00`) and `SetKeyDec` (`0x1006aac0`) enforce length `0x20`.
- AES key schedule installed via vtable slots `+0x18` → `0x10062fb0` (`AES_set_encrypt_key`, bits = `len*8` = 256) and `+0x1c` → `0x10062f30` (`AES_set_decrypt_key`).
- RSession hands out **64 bytes** at `+0x30` with length `+0x28 = 0x40`.

### 8.2 Inference (HYPOTHESIS — UNVERIFIED)

A 64-byte RSession secret must be reduced to two 32-byte AES-256 keys.

- **Primary hypothesis:** `key_enc = secret[0..32]`, `key_dec = secret[32..64]`. Consistent with the "two exactly-32-byte keys" contract and with the absence of any hash/KDF in either module's RSession path; but the split is **not** observed, and the enc/dec ordering may be role-dependent (client enc = first half, server enc = second half).
- **Alternative:** A hash (e.g. MD5/SHA-1 truncation) derives the two keys in the consumer. Not supported by any observed call in shelper, and no such call exists on the RSession path, so this remains secondary.

**UNKNOWN / UNVERIFIED:** Neither `call/jmp [reg+0xb0]` nor `mov reg,[reg+0xb0]` call sites exist in `RvROLClient.dll` (only unrelated scheduler code at `0x1000a3d0`), so RSession consumption is very likely in `RvControlSvc.exe`. `RvControlSvc.exe` was opened but its `GetProcAddress` resolver could not be traced before tool budget exhaustion (200/200). **The 64 → 32+32 mapping must therefore be treated as unverified.**

### 8.3 Consumer-Side Dispatch Evidence

`RvROLClient.dll` `FUN_1003fbd0`: dynamic resolution stores pointers at object `+0x58..+0xec` — `RSession_CreateClient`→`+0x98`, `_GetNextBuffer`→`+0xa4`, `_GetServerDataOnClient`→`+0xa8`, `_GetClientDataOnServer`→`+0xac`, `_GetKey`→`+0xb0`, `CChannel_CreateClient`→`+0xb4`, `SetKeyEnc`→`+0xc0`, `SetKeyDec`→`+0xc4`, `RSAHelper_*`→`+0xd0..+0xe8`.

Both `RvROLClient.dll` and `RvControlSvc.exe` import **only** `SHelper_Init` from `Shelper.dll`; everything else is `GetProcAddress`-resolved — consistent with the required `SHelper_Init`-before-use contract and with vtable-style call indirection that defeated static xref analysis.

Also noted: a second vftable `0x100832c4` (TwoFishV2-shaped) exists in `.rdata`, but no instantiation site was found — **UNKNOWN**, likely dead or unused code path.

---

## 9. Evidence Table

| ID | Claim | Evidence | Class |
|---|---|---|---|
| E1 | Seven RSession exports, ordinals 31–37 | Export table, addresses per §2.1 | CONFIRMED |
| E2 | Client state 0 → 1 → 2 → 3 | `0x1006a517`, `0x1006a5eb`, state-2 branch | CONFIRMED |
| E3 | Server state 1 → 2 → 3 in one call | Server branch of `FUN_1006a2b0` | CONFIRMED |
| E4 | `+0x28` = 0x40 | `mov [esi+0x28], 0x40` in server store path | CONFIRMED |
| E5 | Key length 32 in `+0x28` | — | **REFUTED** |
| E6 | 64 random bytes, RSA-PKCS#1 v1.5 transport | `FUN_10063530`, `FUN_10065ec0` @ `0x10065f05` | CONFIRMED |
| E7 | RSA private components n..iqmp @ `+0x10..+0x2c` | `FUN_10065f70` | CONFIRMED |
| E8 | MD5 in frame trailer | `0x10069ce0`–`0x10069d15`, `FUN_100638f0`, `MD5_Init` `0x10005250` | CONFIRMED |
| E9 | "No MD5 anywhere" | Round-02 doc | **REFUTED** |
| E10 | AESCryptor vftable/offsets, AES-256-CBC, persistent IVs | `0x100832a0`, `FUN_10062b60`, `0x10062fb0`/`0x10062f30`, `FUN_10003b30` | CONFIRMED |
| E11 | CChannel requires two 32-byte keys | `SHelper_CChannel_CreateClient` `0x1006a8b0`, `0x1006ab00`/`0x1006aac0` | CONFIRMED |
| E12 | 64-byte secret split into two 32-byte AES keys | Inference only | **HYPOTHESIS / UNVERIFIED** |
| E13 | RSession independent of control-auth SRP-6a | Absent xrefs, disjoint state, separate `SHelper_GetKey` blob | STRONG INDICATION |
| E14 | No intra-module CChannel/RSession composition in shelper | Empty callers for all seven exports | CONFIRMED |
| E15 | `RvControlSvc.exe` is likely RSession consumer | No indirect call sites in `RvROLClient.dll`; `GetProcAddress` architecture | STRONG INDICATION (untraced) |

---

## 10. Unresolved Questions

1. **64 → two 32-byte AES keys:** Split vs. derivation, and enc/dec ordering per role. Needs `RvControlSvc.exe` resolver tracing + call-site identification. (Blocked by tool budget.)
2. **Client 4-byte ACK semantics:** Value is stored but never interpreted; whether it is a server-chosen cookie or an echo of `+0x04` is UNKNOWN.
3. **Server RSA key provenance:** Which component supplies the 8 component buffers to `CreateServer`, and whether they come from a certificate embedded in `RvROLClient.dll` — UNKNOWN.
4. **Header field semantics** (`+0x04..+0x0c`, `+0x14..+0x1c`): Treated as opaque dwords; no semantic binding found.
5. **TwoFishV2 vftable `0x100832c4`:** No instantiation found — dead code or unreached path.
6. **Persistent-IV consequence:** Whether the peer ever rekeys or resets IVs per frame was not observed; if truly persistent, the CBC chain is stateful and desynchronization-sensitive.

---

## 10. Corrections Required in Prior Documentation

`docs/reverse-engineering/round-02/02-cryptography.md` (or equivalent):

1. **(a)** Remove the "no MD5" claim — MD5 is present in the frame trailer.
2. **(b)** Do not report "+0x28 = AES key size 32" — the field is `0x40` (64).
3. **(c)** Correct the misdescribed indirect vtable calls as direct calls to `0x10003cb0` (if that was claimed).
4. **(d)** State that the CChannel trailer is an **unkeyed** checksum-of-checksum, **not a MAC**.

---

**Generated file:** `docs/CRYPTO_RSESSION_ANALYSIS.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered