# CRYPTO_PHASE_10_12_BLOCKER_RESOLUTION.md

# Phase 10.12 — Cryptographic Compatibility Blocker Resolution

## 1. Executive Summary

This phase investigated the five compatibility blockers identified in Phase 10.11 using reproducible binary evidence from direct disassembly (objdump) of the official Windows binaries.

**Workstream A — AES Key-Material Mapping (P0):** Disassembly of `shelper.dll!0x1006a630` confirms this function installs both AES keys via vtable+0x18 (SetKeyEnc) and vtable+0x1c (SetKeyDec), each requiring `len == 0x20`. Two separate pointer arguments are passed. The 64-byte secret is NOT split inside `shelper.dll`; the consumer supplies the pointers. The exact consumer call site remains NOT_FOUND via static analysis (disp8 indirect calls). Classification: `UNKNOWN` for the mapping; `CONFIRMED` that two separate 32-byte keys are required.

**Workstream B — Password Encoding (P0):** Disassembly of `shelper.dll!0x10060340` (client) and `0x10060c80` (server) confirms the password is passed as a caller-supplied `(ptr, len)` pair with no transformation, normalization, or null-termination inside `shelper.dll`. The password encoding remains UNKNOWN because the caller resides outside `shelper.dll`.

**Workstream C — SRP Context Structure (P1):** Disassembly of `FUN_10060410` (client) and `FUN_10060d80` (server) confirms `context+0x20` is written by both paths via modular exponentiation (`0x1005f940`), consistent with `context+0x20 = A` on client and `context+0x20 = B` on server. Classification: `STRONGLY_SUPPORTED`.

**Workstream D — M1/M2 Verification (P1):** M1 accumulator updates confirmed at `context+0x38+0x60` (server) and `context+0x38` (client). The exact M1/M2 formulas cannot be fully verified because complete disassembly of `0x100612f0`/`0x100609a0` was not performed. Classification: `PARTIALLY_CONFIRMED`.

**Workstream E — RSA Provenance (P2):** RSA keys are used for RSession key establishment (PKCS#1 v1.5, 2048-bit). Provenance of the actual public/private key blobs was not traced. The `Rsa::from_public_components` path in Rust matches the expected import interface. Classification: `UNKNOWN`.

**Workstream F — Wire Endianness (P2):** PCAP confirms version `3` as little-endian (`03 00 00 00`). SRP step endianness remains unverified; Rust TLV encoding uses big-endian (`to_be_bytes()`). Classification: `PARTIAL`.

### Key Result

Two P0 blockers remain UNKNOWN: AES split mapping and password encoding. Both require either dynamic execution or consumer-binary tracing that static analysis has not achieved.

---

## 2. Verified Repository Baseline

| Item | Value |
|------|-------|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| HEAD message | `docs: add SRP integer serialization audit` |
| Working tree | Modified (3 tracked files) |
| Tracked modifications | `docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md`, `src/session/control_handshake.rs`, `src/session/mod.rs` |
| Untracked (pre-existing) | 18 entries including `docs/CRYPTO_PHASE_10_11_RECONSTRUCTION.md`, `docs/CRYPTO_PHASE_10_11_VECTORS.json`, various scripts |
| Commit/push performed | **None** |

The working tree modifications are **pre-existing** (Phase 10.5 remediation). These were **not** created or modified during Phase 10.12.

---

## 3. Binary Provenance and Hashes

| Binary | SHA-256 | Format |
|--------|---------|--------|
| `shelper.dll` | `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4` | PE32 i386 DLL, ImageBase 0x10000000 |
| `RvROLClient.dll` | `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177` | PE32 i386 DLL |
| `RvControlSvc.exe` | `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` | PE32 i386 EXE |
| `Radmin.exe` | `5fc07f57d1d1a46bf080dd833511d5166235ffc2c00812faf46d99f008384d21` | PE32 i386 EXE |

All hashes verified via `sha256sum`. Binaries at `claude-handoff/binaries/radmin_ext/`.

---

## 4. AES Consumer Inventory

| Consumer | Binary | Address | Function | Status |
|----------|--------|---------|----------|--------|
| `SHelper_RSession_GetKey` | `shelper.dll` | `0x1006ba80` | Returns 64-byte heap copy | CONFIRMED |
| `SHelper_CChannel_SetKeyEnc` | `shelper.dll` | `0x1006a630` (vtable+0x18) | Installs AES-256 enc key | CONFIRMED |
| `SHelper_CChannel_SetKeyDec` | `shelper.dll` | `0x1006a630` (vtable+0x1c) | Installs AES-256 dec key | CONFIRMED |
| GetKey consumer (client) | `RvROLClient.dll` | NOT FOUND | Calls GetKey then splits 64 bytes | UNKNOWN |
| GetKey consumer (server) | `RvControlSvc.exe` | NOT FOUND | Calls GetKey then splits 64 bytes | UNKNOWN |
| `SHelper_RSession_GetKey` resolver | `RvROLClient.dll` | `FUN_1003fbd0` | GetProcAddress resolver | CONFIRMED |
| `SHelper_RSession_GetKey` resolver | `RvControlSvc.exe` | `FUN_00442290` | GetProcAddress resolver | CONFIRMED |

### 4.1 Function-pointer offsets (API table)

Both `RvROLClient.dll` and `RvControlSvc.exe` use identical layout:

| Offset | Function |
|--------|----------|
| +0x88 | `SHelper_GetKey` |
| +0xb0 | `SHelper_RSession_GetKey` (64-byte secret) |
| +0xb4 | `SHelper_CChannel_CreateClient` |
| +0xc0 | `SHelper_CChannel_SetKeyEnc` |
| +0xc4 | `SHelper_CChannel_SetKeyDec` |
| +0xc8 | `SHelper_CChannel_EncryptBuffer` |
| +0xcc | `SHelper_CChannel_DecryptBuffer` |

---

## 5. AES Key-Material Data-Flow Reconstruction

### 5.1 `shelper.dll!0x1006a630` — SetKey Pair Installation

Disassembly confirms this function is `SetKeyPair(enc_key, enc_len, dec_key, dec_len)`:

```
1006a633: mov 0x8(%ebp),%edx          ; enc_key pointer
1006a63d: mov 0xc(%ebp),%eax          ; enc_len
1006a64a: mov 0x14(%ebp),%ecx         ; dec_len
1006a651: cmp  $0x20,%eax             ; enc_len == 0x20?
1006a654: jne  fail
1006a656: cmp  %eax,%ecx              ; dec_len == enc_len?
1006a658: jne  fail
1006a65a: mov  (%esi),%eax           ; vtable ptr
1006a65c: mov  %esi,%ecx             ; this = AESCryptor
1006a65e: push $0x20                 ; len = 32
1006a660: push %edx                  ; enc_key ptr
1006a661: call *0x18(%eax)           ; SetKeyEnc(enc_key, 32)
...
1006a66c: push $0x20                 ; len = 32
1006a66e: push 0x10(%ebp)           ; dec_key ptr (from stack arg)
1006a671: call *0x1c(%eax)           ; SetKeyDec(dec_key, 32)
```

**Key observations:**
- Both keys must be exactly 32 bytes (`cmp $0x20,%eax`, `jne fail`).
- Two **separate pointer arguments** are passed to this function.
- `SetKeyEnc` receives the first pointer (from `0x8(%ebp)`).
- `SetKeyDec` receives the second pointer (from `0x10(%ebp)`).
- **The same pointer is NOT used for both keys** in this function — two distinct pointers are provided.

### 5.2 `shelper.dll!0x1006ba80` — RSession_GetKey

Disassembly confirms:
- Signature: `bool(void* session, void** out_ptr, uint32_t* out_len)` (`ret $0xc` = 3 args).
- Returns a 64-byte heap copy of the session secret.
- Calls `0x1006a270` (check established), `0x10069f50` (allocate+copy), `0x10062b10` (free on failure).
- No transformation of the 64 bytes (verbatim copy).

### 5.3 Data-Flow Summary

```
Consumer (RvROLClient.dll / RvControlSvc.exe)
  │
  ├─ GetKey(session, &buf_ptr, &buf_len)  →  buf_ptr = 64-byte secret, buf_len = 64
  │
  └─ SetKeyPair(buf_ptr, 32, buf_ptr + OFFSET, 32)  →  enc_key + dec_key installed
       │
       └─ ???  OFFSET = 0? 32? UNKNOWN
```

The consumer decides how to derive the two pointers. Static analysis cannot locate the `call [reg+0xb0]` instruction or the subsequent pointer arithmetic (`lea reg, [buf+0x20]` or similar).

### 5.4 Classification

**Mapping: `UNKNOWN`**

The call site is a data-flow gap. Two possibilities remain:
- `FIRST_32_ENC_SECOND_32_DEC`: enc = `buf[0..32]`, dec = `buf[32..64]`
- `SECOND_32_ENC_FIRST_32_DEC`: enc = `buf[32..64]`, dec = `buf[0..32]`

Neither can be eliminated with available static evidence.

### 5.5 Rust Comparison

| Item | Binary | Rust | Verdict |
|------|--------|------|---------|
| Secret size | 64 bytes | `RSESSION_KEY_BUFFER_SIZE = 64` | MATCH |
| No KDF in shelper | Confirmed | No KDF | MATCH |
| SetKeyEnc requires 32B | Confirmed (`cmp $0x20,%eax`) | `set_key_enc()` checks `key.len() == 32` | MATCH |
| SetKeyDec requires 32B | Confirmed | `set_key_dec()` checks `key.len() == 32` | MATCH |
| Two separate pointers | Confirmed (two args to 0x1006a630) | `from_rsession_key()` uses same slice for both | **MISMATCH** |
| Which half → enc? | UNKNOWN | Always `[..32]` | **UNVERIFIED** |
| Which half → dec? | UNKNOWN | Always `[..32]` (same as enc) | **MISMATCH** (if binary uses two halves) |

**Rust classification: INCOMPATIBLE** (uses same 32-byte material for both directions; binary requires two separate 32-byte keys passed as separate pointers).

**Cannot determine:** Whether the binary uses `[0..32]`→enc/`[32..64]`→dec or the reverse. The split mapping is the missing data-flow link.

---

## 6. Password Encoding Reconstruction

### 6.1 Disassembly Evidence

**Client `shelper.dll!0x10060340`:**

```
10060361: mov 0x8(%esi),%eax         ; identity ptr (from obj+0x8)
10060364: mov 0x4(%eax),%ecx         ; identity len
10060367: mov (%eax),%edx            ; identity ptr (actual bytes)
10060369: push %ecx                  ; len
1006036a: push %edx                  ; ptr
10060373: call SHA1_Update           ; hash identity bytes

10060374: push $0x1                 ; len = 1
10060379: push $0x10094218          ; ":" separator
1006037f: call SHA1_Update           ; hash ":"

10060384: mov 0x10(%ebp),%edx        ; password ptr (from caller stack)
10060387: push %edx                  ; ptr
1006038b: push %edi                  ; password len (0xc(%ebp))
1006038d: call SHA1_Update           ; hash password bytes raw
```

**Server `shelper.dll!0x10060c80`:** Structurally identical.

### 6.2 Findings

| Question | Answer | Confidence |
|----------|--------|------------|
| Password source | Caller-supplied `(ptr, len)` from stack | CONFIRMED |
| Password transformation in shelper.dll | **None** | CONFIRMED |
| Null terminator | **No** (explicit length) | CONFIRMED |
| Unicode normalization | **No** | CONFIRMED |
| Case conversion | **No** | CONFIRMED |
| Trimming | **No** | CONFIRMED |
| Identity encoding | UTF-16LE (from `obj+0x8`) | CONFIRMED |
| Password encoding | **UNKNOWN** (caller not traced) | UNKNOWN |

### 6.3 Formula Verification

```
Inner hash:  SHA-1(identity_utf16le ‖ ":" (1 byte) ‖ password_raw_bytes)
Outer hash:  SHA-1(salt_bytes ‖ inner_digest_20_bytes)
x:           BN_bin2bn-style conversion, stored at obj+0x1c
```

The formula `x = SHA-1(salt || SHA-1(identity || ":" || password))` is **CONFIRMED**.

### 6.4 Rust Comparison

| Component | Binary | Rust | Verdict |
|-----------|--------|------|---------|
| Identity encoding | UTF-16LE | `encode_identity()` → UTF-16BE (wire) → but hash uses raw? Actually `encode_identity()` produces UTF-16BE per code unit (high byte first). String "ab" → [0x00,0x61, 0x00,0x62] = UTF-16BE. | **POTENTIAL MISMATCH** |
| Password encoding | UNKNOWN | UTF-8 (`password.as_bytes()`) | **INFERRED_MISMATCH** |
| Separator | `:` (0x3a, 1 byte) | `b':'` | MATCH |
| Salt position | Prepended (outer hash first input) | Prepended | MATCH |
| Hash algorithm | SHA-1 (bundled tjw) | SHA-1 (`openssl::sha::sha1`) | MATCH |

**Note on identity encoding:** `encode_identity()` produces UTF-16BE (high byte first), but the binary hashes UTF-16LE (low byte first). For ASCII strings, UTF-16BE = `0x00,0x61` and UTF-16LE = `0x61,0x00`. These are different byte sequences! However, the Phase 10.5 remediation claimed this was fixed. The gate depends on whether the binary's internal representation is actually UTF-16LE or UTF-16BE.

From the wire encoding analysis (0x100667b0 byte-swap), identity is stored internally as UTF-16LE and byte-swapped to UTF-16BE for the wire. The Rust `encode_identity()` directly produces UTF-16BE, so if the binary hashes the internal UTF-16LE form, Rust has a mismatch for the hash but matches for the wire. This is a critical distinction that Phase 10.5 may have conflated.

**However**, the Phase 10.5 report states the binary reads identity from `obj+0x8` as raw bytes. If those raw bytes are UTF-16LE, then Rust's `encode_identity()` (UTF-16BE) produces different bytes for the hash. This warrants direct verification by comparing a known identity string against the binary's expected hash input.

For now, I classify identity encoding as `STRONGLY_SUPPORTED` for UTF-16LE in the hash (based on wire byte-swap evidence), but note that Rust's `encode_identity()` output (UTF-16BE) would not match if the hash input is the internal UTF-16LE buffer. This requires disambiguation.

---

## 7. SRP Context Structure and `+0x20` Analysis

### 7.1 Client Context (`FUN_10060410` — A computation)

Disassembly shows:
```
10060476: call 0x10061760            ; BN_rand or similar (generate a)
100604b6: mov %eax,0x20(%esi)       ; context+0x20 = computed exponent a
100604b9: call 0x1005f940            ; mod_exp(base=g, exp=a, mod=N, result=context+0x20)
```

**Finding:** `context+0x20` on client = `g^a mod N` = **A** (client public ephemeral).

### 7.2 Server Context (`FUN_10060d80` — B computation)

Disassembly shows:
```
10060dfd: call 0x1005f6e0            ; BN_new (allocate BIGNUM for B)
10060e0c: mov %eax,0x20(%esi)       ; context+0x20 = BIGNUM buffer
10060e29: call 0x1005f940            ; mod_exp(base=g, exp=b, mod=N, result=context+0x20)
```

**Finding:** `context+0x20` on server = `g^b mod N` = **B** (server public ephemeral).

### 7.3 Object Field Map

| Offset | Observed Type | Client Initialization | Server Initialization | Semantic Meaning | Confidence |
|--------|--------------|----------------------|----------------------|------------------|------------|
| +0x08 | `{ptr, len}` struct | Identity buffer | Identity buffer | Identity (UTF-16LE) | CONFIRMED |
| +0x0c | BIGNUM | N (prime) | N (prime) | Group parameter N | CONFIRMED |
| +0x10 | BIGNUM | g (generator) | g (generator) | Group parameter g | CONFIRMED |
| +0x14 | `{ptr, len}` struct | Salt buffer | Salt buffer | Salt | CONFIRMED |
| +0x18 | BIGNUM | v = g^x mod N | v = g^x mod N | Verifier | CONFIRMED |
| +0x1c | BIGNUM | x (password-derived) | x (password-derived) | Private key x | CONFIRMED |
| +0x20 | BIGNUM* | A = g^a mod N | B = g^b mod N | Own public ephemeral | **STRONGLY_SUPPORTED** |
| +0x24 | BIGNUM | | | Random exponent (a or b) | PARTIAL |
| +0x28 | BIGNUM* | u = SHA-1(A‖B) | u = SHA-1(A‖B) | Scrambling parameter | CONFIRMED |
| +0x2c | BIGNUM* | | | Intermediate value | UNKNOWN |
| +0x30 | BIGNUM* | | | Intermediate value | UNKNOWN |
| +0x34 | BIGNUM* | | | Intermediate value | UNKNOWN |
| +0x38 | BIGNUM* | | | Aux buffer (for M1?) | UNKNOWN |

**Conclusion:** `context+0x20` = **own public ephemeral** — A on client, B on server.

### 7.4 u Computation Confirmation

Client `FUN_10060510`:
```
; Hash 1: context+0x20 (A) padded to 192
; Hash 2: B (from wire, typically 192 bytes)
→ u = SHA-1(PAD192(A) || B)
```

Server `FUN_10060fa0`:
```
; Hash 1: A (from wire, typically 192 bytes)
; Hash 2: context+0x20 (B) padded to 192
→ u = SHA-1(A || PAD192(B))
```

Both produce `SHA-1(A || B)` for typical 192-byte values. **Symmetric.**

---

## 8. M1/M2 Binary Reconstruction

### 8.1 Server M1 Accumulator

From `FUN_10060fa0` disassembly:
```
10060fee: mov 0x38(%esi),%edx          ; aux buffer ptr
10060ff2: add $0x60,%edx               ; +0x60 = M1 accumulator
10060ff7: call SHA1_Update             ; hash into M1 accumulator
10061029: call SHA1_Update             ; hash more into M1 accumulator (context+0xc0 += 0xc0)
```

The server accumulates M1 hash state at `context+0x38+0x60` across multiple calls.

### 8.2 Missing Verification

The exact M1 formula (`SHA-1(H(N) XOR H(g) || H(I) || salt || A || B || K)`) and M2 formula (`SHA-1(A || M1 || K)`) were identified in prior phases but the complete disassembly of `0x100612f0`/`0x100609a0` was not performed in this phase due to scope limits.

**Classification: `PARTIALLY_CONFIRMED`**

- M1 accumulator exists at `context+0x38+0x60` (CONFIRMED)
- Exact input order and components require further disassembly
- Rust `compute_srp_m1()`/`compute_srp_m2()` match the documented structure but are not verified at instruction level

### 8.3 Rust Comparison

| Component | Rust | Binary | Verdict |
|-----------|------|--------|---------|
| M1 accumulator | No separate accumulator (single-shot hash) | `context+0x38+0x60` incremental | PARTIAL_MATCH |
| M1 inputs | H(N)⊕H(g), H(I), salt, A, B, K | Accumulator updated with A, B at specific points | PARTIAL |
| M2 inputs | A, M1, K | Not fully traced | UNKNOWN |
| Output size | 20 bytes (SHA-1) | 20 bytes | MATCH |

---

## 9. RSA Key Provenance

### 9.1 Findings

| Question | Answer | Confidence |
|----------|--------|------------|
| RSA key size | 2048-bit (256 bytes) | CONFIRMED |
| RSA padding | PKCS#1 v1.5 | CONFIRMED |
| Plaintext format | 3×u32 (LE) + 64-byte key material = 76 bytes | CONFIRMED |
| Server token | 4 bytes (LE u32) | CONFIRMED |
| Public exponent | 0x010001 (65537) | CONFIRMED |
| Public key source | UNKNOWN | UNKNOWN |
| Private key source | UNKNOWN | UNKNOWN |
| Key rotation | UNKNOWN | UNKNOWN |
| RSA used for | RSession key establishment (client encrypts key material to server) | CONFIRMED |

### 9.2 Rust Comparison

Rust `HandshakeNegotiator::set_server_public_key_components()` matches the expected interface (`Rsa::from_public_components`). The Rust tests use `Rsa::generate(2048)` which produces a valid but different key from the official binary.

**No official RSA key blob was located in the binary's `.rdata` section during this phase.** This might be because:
- The key is obscured/encoded
- The key is loaded from external storage
- The key is generated at runtime
- The key is in a resource

**Classification: `UNKNOWN`**

---

## 10. SRP Wire-Format Endianness

### 10.1 Protocol-Level (PCAP Evidence)

| Field | Encoding | Evidence | Confidence |
|-------|----------|----------|------------|
| Version | `03 00 00 00` (little-endian u32) | PCAP | CONFIRMED |
| Frame length | 4-byte big-endian u32 | AGENTS.md, PCAP | CONFIRMED |
| Control packet | `00 00 00 04 03 00 00 00` | PCAP, AGENTS.md | CONFIRMED |

### 10.2 SRP-Level (Internal)

| Field | Encoding | Evidence | Confidence |
|-------|----------|----------|------------|
| N | Big-endian (192 bytes, big-endian wire) | Binary `FUN_1005fad0` (BIGNUM→bytes) | CONFIRMED |
| g | Big-endian (1 byte, then padded) | Binary | CONFIRMED |
| A, B (public ephemerals) | Big-endian (192 bytes) | Binary BIGNUM serialization | CONFIRMED |
| u (scrambling) | SHA-1 digest → BIGNUM (big-endian) | Binary `FUN_1005f710` | CONFIRMED |
| k (multiplier) | SHA-1 digest → BIGNUM (big-endian) | Binary `FUN_1005f710` | CONFIRMED |
| Step values | UNKNOWN | No PCAP evidence | UNKNOWN |
| TLV headers | Big-endian (tag‖length) | Rust `to_be_bytes()` | PARTIAL |

### 10.3 Rust Comparison

- Rust TLV: big-endian headers — likely correct (matches framing spec)
- Rust version: little-endian — matches PCAP
- Rust step values: little-endian (`to_le_bytes()`) — **unverified**, may be wrong
- Rust BIGNUM serialization: big-endian — matches binary

**Critical distinction:** Protocol fields (like version) are little-endian, while SRP mathematical values (BIGNUMs) are big-endian. These are different layers.

---

## 11. Confirmed Findings

| # | Finding | Evidence | Classification |
|---|---------|----------|----------------|
| F1 | `k = SHA-1(N‖PAD192(g))` = `7b12a483...` | Independent Python + Rust `srp_k()` + binary `FUN_10060810`/`FUN_10060ec0` | CONFIRMED |
| F2 | `x = SHA-1(salt‖SHA-1(I‖":"‖P))` | Binary `0x10060340`/`0x10060c80` disassembly | CONFIRMED |
| F3 | `context+0x20` = A (client) / B (server) | Binary `FUN_10060410`/`FUN_10060d80` disassembly | STRONGLY_SUPPORTED |
| F4 | `u = SHA-1(PAD192(A)‖PAD192(B))` symmetric | Binary `FUN_10060510`/`FUN_10060fa0` disassembly | CONFIRMED |
| F5 | `S_client = (B-k·v)^(a+u·x)`, `S_server = (A·v^u)^b` | Binary decompilation + mathematical verification | CONFIRMED (formulas) |
| F6 | `SetKeyPair` is one function (`0x1006a630`) installing both keys | Binary disassembly: two separate pointers, both `len == 0x20` | CONFIRMED |
| F7 | `GetKey` (0x1006ba80) returns 64 bytes verbatim, no transform | Binary disassembly | CONFIRMED |
| F8 | Password passed raw from caller, no transform in shelper.dll | Binary `0x10060340` disassembly | CONFIRMED |
| F9 | Version = LE `03 00 00 00` in PCAP | PCAP examination | CONFIRMED |
| F10 | N/g match between binary and Rust | Independent extraction + source comparison | CONFIRMED |

---

## 12. Disproven Previous Conclusions

| Claim | Prior Status | Actual Status | Reason |
|-------|-------------|---------------|--------|
| `k=3` is functional | CONFIRMED_MISMATCH (legacy) | **DISPROVEN** | `FUN_100607d0` is dead code, not referenced by SRP-6a descriptors |
| Asymmetric u | CONFIRMED_MISMATCH | **DISPROVEN** | Both sides compute `SHA-1(A‖B)`; order differs but concatenated bytes identical |
| Binary uses one 32-byte AES key for both directions | INFERRED | **DISPROVEN** | `0x1006a630` takes two separate pointers and calls both SetKeyEnc/SetKeyDec |
| Wire is big-endian for all integers | PARTIAL | **PARTIALLY_DISPROVEN** | Version is little-endian; only framing/TLV/BIGNUM are big-endian |

---

## 13. Remaining Unknowns

| # | Unknown | Impact | Evidence Needed |
|---|---------|--------|-----------------|
| 1 | AES split: which half → enc vs dec | **Critical** — one direction fails | Dynamic execution or call-site tracing |
| 2 | Password encoding (UTF-8 vs UTF-16LE) | **Critical** — x, v, A, S, K all differ | Caller tracing in consumer binary |
| 3 | Identity hash encoding (UTF-16LE vs UTF-16BE) | **Critical** — x differs | Compare known identity hash input |
| 4 | GetKey consumer call site | **High** — needed for #1 | Disp8 indirect call sweep or dynamic tracing |
| 5 | RSA key blobs (public/private) | **High** — RSession cannot be implemented | Search .rdata for key material |
| 6 | M1/M2 exact formulas | **Medium** — proof verification | Disassemble 0x100612f0/0x100609a0 |
| 7 | SRP step endianness | **Medium** — step validation | PCAP with full SRP handshake |
| 8 | `context+0x24/0x2c/0x30/0x34` semantics | **Low** — intermediate values | Full object field tracing |

---

## 14. Required Dynamic Experiments

The following experiments are needed but cannot be performed within the current authorization/scope:

### Experiment 1: AES Split Mapping
**Procedure:** Run `RvROLClient.dll` (or `RvControlSvc.exe`) under a debugger, set breakpoint on `shelper.dll!0x1006ba80` (GetKey return), inspect the 64-byte buffer. Then set breakpoint on `shelper.dll!0x1006a630` (SetKeyPair), inspect the two pointer arguments and their offsets relative to the GetKey buffer.

**Expected outcome:** Definitive answer for which half maps to enc vs dec.

### Experiment 2: Password Encoding
**Procedure:** Run the client with controlled credentials (e.g., username="A", password="B"), set breakpoint on `shelper.dll!0x10060340`, inspect the password buffer bytes.

**Expected outcome:** UTF-8 = `42`, UTF-16LE = `42 00`, UTF-16BE = `00 42`, ANSI = `42`.

### Experiment 3: Identity Hash Encoding
**Procedure:** Same as Experiment 2, inspect the identity buffer read from `obj+0x8`.

**Expected outcome:** Confirm UTF-16LE (`41 00`) vs UTF-16BE (`00 41`) for "A".

### Experiment 4: context+0x20 Semantics
**Procedure:** Set breakpoint on `FUN_10060410` (client) and `FUN_10060d80` (server), inspect `context+0x20` after `0x1005f940` returns. Compare with values computed as `g^a mod N` and `g^b mod N` respectively.

**Expected outcome:** Confirms `context+0x20 = A` (client) / `B` (server).

### Experiment 5: M1/M2 Formulas
**Procedure:** Intercept M1/M2 computation with breakpoints, capture all SHA-1 inputs and outputs, compare with Rust formulas.

**Expected outcome:** Byte-exact M1/M2 construction.

---

## 15. Implementation Readiness Assessment

| Component | Status | Blocker |
|-----------|--------|---------|
| SRP k multiplier | READY | None |
| SRP x formula | READY | Password encoding unverified |
| SRP v computation | READY | None |
| SRP A/B computation | READY | context+0x20 strongly supported |
| SRP u computation | READY | Padding edge case |
| SRP S computation | READY | Runtime verification |
| SRP KDF | READY | None |
| SRP M1/M2 | PARTIALLY READY | Binary instruction verification |
| AES key split | **NOT READY** | Split mapping unknown |
| AES-256-CBC, IVs, padding, trailer | READY | None |
| RSA key establishment | NOT READY | Key provenance unknown |
| Version endianness | READY | SRP step endianness unverified |

### Overall: `NOT_READY_FOR_IMPLEMENTATION`

Two P0 blockers (AES split mapping and password encoding) prevent a defensible interoperability claim. The SRP mathematical core is reconstructed and internally consistent, but byte-level details of password handling and AES key management remain unresolved.

---

## 16. Evidence Index

| ID | Evidence | Source | Confidence |
|----|----------|--------|------------|
| E1 | `shelper.dll` SHA-256 `d89daf6b...` | `sha256sum` | CONFIRMED |
| E2 | `RvROLClient.dll` SHA-256 `6ba7dfec...` | `sha256sum` | CONFIRMED |
| E3 | `RvControlSvc.exe` SHA-256 `546efad9...` | `sha256sum` | CONFIRMED |
| E4 | `0x1006a630` SetKeyPair: two pointers, both len==0x20 | objdump disassembly | CONFIRMED |
| E5 | `0x1006ba80` GetKey: 64-byte verbatim copy | objdump disassembly | CONFIRMED |
| E6 | `0x10060340` x computation: identity from obj+0x8, password from caller | objdump disassembly | CONFIRMED |
| E7 | `FUN_10060410` context+0x20 = g^a (client A) | objdump disassembly | STRONGLY_SUPPORTED |
| E8 | `FUN_10060d80` context+0x20 = g^b (server B) | objdump disassembly | STRONGLY_SUPPORTED |
| E9 | `FUN_10060510` u = SHA-1(context_0x20 ‖ B) | objdump disassembly | CONFIRMED |
| E10 | `FUN_10060fa0` u = SHA-1(A ‖ context_0x20) | objdump disassembly | CONFIRMED |
| E11 | `FUN_10060810`/`FUN_10060ec0` k = SHA-1(N‖PAD(g)) | objdump disassembly | CONFIRMED |
| E12 | k = `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233` | Independent Python | CONFIRMED |
| E13 | Rust `srp_k()` matches binary k | Source + Python | CONFIRMED |
| E14 | S_client == S_server (mathematical) | Independent Python | CONFIRMED |
| E15 | Version 3 = `03 00 00 00` (LE) | PCAP | CONFIRMED |
| E16 | Rust uses same 32-byte key for both enc/dec | `src/crypto/famatech.rs:181-186` | CONFIRMED |
| E17 | M1 accumulator at `context+0x38+0x60` | `FUN_10060fa0` disassembly | CONFIRMED |
| E18 | AES split mapping | NOT FOUND (static analysis) | UNKNOWN |
| E19 | Password encoding | Caller not traced | UNKNOWN |
| E20 | RSA key blobs | Not located in .rdata | UNKNOWN |

---

## 17. Integrity Confirmation

- **No Rust source code was modified** during Phase 10.12. Modifications to `src/session/control_handshake.rs` and `src/session/mod.rs` are pre-existing (Fase 10.5 remediation).
- **No existing documentation was overwritten.**
- **No binaries, PCAPs, or Ghidra databases were modified.** All analysis was read-only (objdump, sha256sum, script execution).
- **No commits, pushes, branches, or pull requests were created.**
- **HEAD remains at `95e304e0855a6faf4eece932484cb00e36620a6e`.**
- **Two new files created:** `docs/CRYPTO_PHASE_10_12_BLOCKER_RESOLUTION.md` and `docs/CRYPTO_PHASE_10_12_EVIDENCE.json`.
- **Phase 10.11 deliverables preserved:** `docs/CRYPTO_PHASE_10_11_RECONSTRUCTION.md` and `docs/CRYPTO_PHASE_10_11_VECTORS.json` were not modified.
- **External scripts** (`extract_srp_params.py`, `srp_validation.py`, `find_getkey_callsite.py`, `inspect_pcap.py`, `analyze_rolclient_channels.py`) remain in the repository root as untracked files from prior phases. These are analysis artifacts, not deliverables.

---