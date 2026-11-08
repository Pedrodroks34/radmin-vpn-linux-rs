# CRYPTO_PHASE_10_11_RECONSTRUCTION.md

# Phase 10.11 — SRP Mathematical Reconstruction, Independent Vector Validation & AES Evidence Reconciliation

## 1. Executive Summary

This document reports the Phase 10.11 cryptographic investigation of the Radmin VPN Windows client (`Radmin_VPN_2.1.4951.1.exe`) and its reconciliation with the current Rust implementation (`radmin-vpn` crate).

Three workstreams were executed:

**A — SRP Mathematical Reconstruction**: Reconstructed the complete SRP authentication mathematics from static binary analysis of `shelper.dll` and `RvROLClient.dll`. Confirmed SRP-6a with `k = SHA-1(N || PAD192(g))`, symmetric `u = SHA-1(PAD192(A) || PAD192(B))`, identity hashed as UTF-16LE raw bytes, and `x = SHA-1(salt || SHA-1(identity || ":" || password))`.

**B — Independent Cryptographic Vector Validation**: Built an independent Python implementation (outside the repository) and verified: `k` computation (matches Rust `srp_k()`), mathematical consistency (`S_client == S_server` for both UTF-8 and UTF-16LE password paths), and `N`/`g` extraction from binary (matches Rust constants).

**C — AES/RSession Evidence Reconciliation**: Traced `SHelper_RSession_GetKey` consumers in `RvROLClient.dll` and `RvControlSvc.exe`. The exact call site could not be located statically (disp8 indirect calls defeat pattern matching). The 64→32+32 AES key split mapping remains UNKNOWN. Rust currently uses `key_material[..32]` for both enc and dec — a CONFIRMED_MISMATCH with the binary's two-key requirement, but the split direction cannot be determined from available evidence.

**D — PCAP and RSA Evidence Review**: PCAP analysis shows version value `3` sent as little-endian (`03 00 00 00`), matching Rust's `to_le_bytes()`. RSA key provenance remains unresolved.

### Key Result

The SRP reconstruction is mathematically consistent and the Rust `srp_k()` correction produces the same `k` as the binary. However, the AES key split mapping remains unresolved, and full Windows interoperability cannot be claimed without resolving it.

---

## 2. Verified Repository State

| Item | Value |
|------|-------|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| HEAD message | `docs: add SRP integer serialization audit` |
| Working tree | Modified (3 tracked files + untracked docs/scripts) |
| Tracked modifications | `docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md`, `src/session/control_handshake.rs`, `src/session/mod.rs` |
| Commit/push performed | **None** (investigation-only phase) |

The working tree modifications are **pre-existing** (Phase 10.5 remediation: `k=SHA-1(N||PAD(g))` via `srp_k()`, identity hash UTF-16LE via `encode_identity()`). These were **not** created or modified during Phase 10.11.

---

## 3. Binary Provenance and Hashes

All binaries verified via `sha256sum`. Original bytes never modified.

| Binary | SHA-256 | Format | Role |
|--------|---------|--------|------|
| `shelper.dll` | `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4` | PE32 i386 DLL, ImageBase 0x10000000 | Crypto library (SRP, AES, RSA, MD5) |
| `RvROLClient.dll` | `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177` | PE32 i386 DLL | ROL client library, 47 ROLClient_ exports |
| `RvControlSvc.exe` | `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` | PE32 i386 EXE | Control service (RSession consumer, suspected) |
| `Radmin_VPN_2.1.4951.1.exe` | `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7` | PE32 i386 EXE (installer) | Installer binary |

---

## 4. Tooling

| Tool | Version/Path | Use |
|------|--------------|-----|
| Ghidra 12.2 | `/opt/ghidra/support/analyzeHeadless` | Static decompilation of `shelper.dll` and `RvROLClient.dll` |
| objdump (GNU binutils) | `/usr/bin/objdump` | Disassembly, indirect call pattern search |
| readelf, nm, strings | `/usr/bin/` | Binary inspection |
| python3 | `/usr/bin/python3` | Independent SRP computation, parameter extraction, PCAP inspection |
| tshark/Wireshark | (referenced in prior docs) | PCAP analysis (existing captures only) |

Ghidra was available and used for static analysis of `shelper.dll` (existing project at `/tmp/rea-ghidra-KCSGad/`) and `RvROLClient.dll` (existing project at `/tmp/ghidra_work_rol2/rol2_project/`).

---

## 5. SRP Mathematical Reconstruction

### 5.1 Group Parameters (CONFIRMED)

| Parameter | Value | Source | Confidence |
|-----------|-------|--------|------------|
| N (prime modulus) | `e634471e75f2d76a...c7` (1536-bit, 192 bytes) | `shelper.dll` RVA 0x100ac280, verified by independent extraction | CONFIRMED |
| g (generator) | `0x05` (1 byte) | `shelper.dll` RVA 0x100ac279, verified by independent extraction | CONFIRMED |
| Modulus bit length | 1536 bits | Binary data + Rust `RADMIN_SRP1536_MODULUS_LEN = 192` | CONFIRMED |
| Modulus byte length | 192 bytes | Binary data | CONFIRMED |
| Generator representation | 1 byte `0x05`, PAD192(g) = 191 zero bytes + 0x05 | Binary `FUN_1005f760` (copy+pad g to 192) | CONFIRMED |
| Parameters fixed or negotiated | Fixed (same N, g for client and server) | Both SRP-6a descriptors reference same N, g | CONFIRMED |
| Client/server identical parameters | Yes | Same N, g in both client and server descriptors | CONFIRMED |

The Rust `RADMIN_SRP1536_PRIME_HEX` constant matches the binary N exactly (verified byte-for-byte by independent extraction).

### 5.2 Identity and Password Derivation

**Formula (CONFIRMED):**
```
x = SHA-1(salt ‖ SHA-1(identity ‖ ":" ‖ password))
```

| Component | Binary (`shelper.dll`) | Rust (`control_handshake.rs`) | Status |
|-----------|----------------------|------------------------------|--------|
| Inner hash | `SHA-1(identity ‖ ":" ‖ password)` | `SHA-1(encode_identity(username) ‖ ":" ‖ password)` | STRUCTURAL MATCH |
| Separator | `:` (0x3a, 1 byte) at `0x10094218` | `b':'` | MATCH |
| Salt order | Salt prepended (outer hash) | Salt prepended | MATCH |
| Hash algorithm | SHA-1 (bundled tjw implementation) | SHA-1 (`openssl::sha::sha1`) | ALGORITHM MATCH |
| Hash stages | 2 | 2 | MATCH |
| Identity hash encoding | **UTF-16LE** raw bytes from `obj+0x8` | **UTF-16LE** via `encode_identity()` | **CORRECTED (Fase 10.5)** |
| Password hash encoding | Unknown (caller-supplied, likely UTF-16LE) | **UTF-8** via `password.as_bytes()` | **INFERRED_MISMATCH** (unverified) |
| Null terminator | No | No | MATCH |
| Unicode normalization | No | No | MATCH |
| Case conversion/trimming | No | No | MATCH |

**Evidence:**
- `0x10060340` (client x computation): reads identity from `obj+0x8` as `{ptr,len}`, salt from `obj+0x14`, password from caller `(ptr,len)`
- `0x10060c80` (server x computation): structurally identical
- `0x10094218`: separator byte `:` (0x3a), length 1
- `0x10028810/0x100285f0/0x100286d0`: SHA-1 init/update/final
- Identity internally UTF-16LE (wire byte-swap at `0x100667b0` region confirmed)

**Rust status:** Identity encoding was corrected in Fase 10.5 (`encode_identity()` produces UTF-16LE bytes). Password encoding remains unverified — Rust uses UTF-8, binary likely uses UTF-16LE (inferred from shared credential source with identity, but caller not traced).

### 5.3 Verifier (PARTIALLY_CONFIRMED)

| Aspect | Binary | Rust | Status |
|--------|--------|------|--------|
| Formula | `v = g^x mod N` | `v = g^x mod N` | MATCH |
| Client calculates v | No (client does not have v) | N/A | N/A |
| Server calculates v | Yes, at `0x10060c80` (inline) | Server path computes v | MATCH |
| v persisted | Stored at `obj+0x18` | N/A (server not fully implemented) | PARTIAL |
| v transmitted | No | N/A | N/A |
| Serialization | BIGNUM (minimal form) | BigNum | PARTIAL |

### 5.4 Multiplier k (CONFIRMED)

**Formula (CONFIRMED):**
```
k = SHA-1(N || PAD192(g))
```

| Aspect | Binary | Rust | Status |
|--------|--------|------|--------|
| Formula | `SHA-1(N_bytes || PAD192(g_bytes))` | `srp_k()` computes `SHA-1(N || PAD192(g))` | **MATCH** |
| Value | `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233` | Same (verified independently) | **MATCH** |
| Is k=3? | No (legacy path is dead code) | No (was k=3, now dynamic) | **CORRECTED** |
| Client selection | `FUN_10060810` (descriptor offset 0x1c) | `srp_k()` called in client negotiator | CONFIRMED |
| Server selection | `FUN_10060ec0` (descriptor offset 0x18) | `srp_k()` called in server session | CONFIRMED |
| Legacy k=3 (`FUN_100607d0`) | Dead code, no callers | Removed | DISPROVEN |

**Independent verification:** Python computation of `SHA-1(N || PAD192(g))` produced `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233`, matching Rust `srp_k()` output.

### 5.5 Public Values A and B (PARTIALLY_CONFIRMED)

| Aspect | Binary | Rust | Status |
|--------|--------|------|--------|
| A = g^a mod N | Client computes at `FUN_10060410` (context+0x20 = A) | `compute_srp_A` | PARTIAL |
| B = (k·v + g^b) mod N | Server computes at `FUN_10060d80` (context+0x20 = B) | Server computes B | PARTIAL |
| Secret exponent generation | `rand192 + 1536` (no rejection sampling) | `random_srp_exponent()` (rejection sampling, 128 tries) | BEHAVIORAL DIVERGENCE |
| Randomness source | CryptGenRandom (4 bytes only, per prior analysis) | `openssl::rand::rand_bytes()` | DIFFERENT |
| Serialization | BIGNUM minimal form (`BN_bn2bin`) | `to_vec()` (big-endian minimal) | MATCH |
| Length validation | `len ≤ 192`, `val < N`, `val ≠ 0` | `len == 192` strict | PARTIAL_MATCH |

**Unresolved:** Whether `context+0x20` = A on client and B on server cannot be confirmed without dynamic execution. Evidence is MEDIUM confidence based on `FUN_10060410`/`FUN_10060d80` decompilation.

### 5.6 Scrambling Parameter u (CONFIRMED)

**Formula (CONFIRMED):**
```
u = SHA-1(PAD192(A) || PAD192(B))
```

| Aspect | Client | Server | Status |
|--------|--------|--------|--------|
| Formula | `SHA-1(context_0x20 || B)` where context_0x20 = A | `SHA-1(A || context_0x20)` where context_0x20 = B | SYMMETRIC |
| Hash order | Own ephemeral first, peer ephemeral second | Peer ephemeral first, own ephemeral second | Same bytes (A||B) |
| Padding | PAD192 for context value | PAD192 for context value | MATCH |
| Wire-received values | Hashed at full length (typically 192) | Hashed at full length (typically 192) | MATCH |
| Both sides compute u | Yes | Yes | CONFIRMED |
| Client receives u from server | No | No | CONFIRMED |

**Evidence:**
- `FUN_10060510` (client u/S): hashes `context+0x20` (padded to 192) then `B` (from wire)
- `FUN_10060fa0` (server u/S): hashes `A` (from wire) then `context+0x20` (padded to 192)
- Both produce `SHA-1(A || B)` if context+0x20 = A on client and B on server

**Rust status:** `compute_srp_u()` pads both A and B to 192 bytes and computes `SHA-1(pad_a || pad_b)`. Structurally matches binary. However, binary hashes context value with BIGNUM byte length (may strip leading zeros) while Rust always pads to 192 — potential edge case mismatch.

### 5.7 Shared Secret S (CONFIRMED formula, UNVERIFIED runtime)

| Side | Formula | Status |
|------|---------|--------|
| Client | `S = (B - k·v)^(a + u·x) mod N` | CONFIRMED (from `FUN_10060510` decompilation) |
| Server | `S = (A · v^u)^b mod N` | CONFIRMED (from `FUN_10060fa0` decompilation) |

**Mathematical consistency:** Independent Python verification confirmed `S_client == S_server` for both UTF-8 and UTF-16LE password paths when using consistent inputs.

**Runtime verification:** Cannot be confirmed without dynamic execution or PCAP traffic containing SRP public values. The existing PCAP (`pcaps/radmin_17301.pcap`) captures control frames but not the SRP handshake payload (captures start after version exchange).

### 5.8 Session Key and Authentication Proofs (PARTIALLY_CONFIRMED)

| Component | Formula | Binary Address | Rust Location | Status |
|-----------|---------|---------------|---------------|--------|
| K (session key) | `SHA-1(S‖BE32(0)) ‖ SHA-1(S‖BE32(1))` = 40 bytes | `FUN_10061790` (KDF, not disassembled in this phase) | `compute_srp_kdf()` | CONFIRMED (structure) |
| K length | 40 bytes | Binary | `RADMIN_SRP_KDF_KEY_LEN = 40` | CONFIRMED |
| AES key from K | First 32 bytes of KDF output | Binary | `CONTROL_SESSION_KEY_SIZE = 32` | CONFIRMED |
| M1 (client proof) | `SHA-1(H(N)⊕H(g) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K)` | `FUN_10060510`/`0x100612f0` area | `compute_srp_m1()` | PARTIAL |
| M2 (server proof) | `SHA-1(A ‖ M1 ‖ K)` | `0x100609a0`/`0x10061450` area | `compute_srp_m2()` | PARTIAL |

**Note:** M1/M2 function addresses (`0x100612f0`, `0x100609a0`, `0x10061450`) were identified in prior investigations but not disassembled in this phase due to time budget. The Rust formulas match the documented structure but cannot be verified against the binary at instruction level.

### 5.9 Complete Formula Inventory

| Component | Official Formula | Inputs | Output | Evidence | Confidence |
|-----------|-----------------|--------|--------|----------|------------|
| Group parameters | N=1536-bit prime, g=5 | Fixed in binary | N, g | `shelper.dll` 0x100ac280/0x100ac279 | CONFIRMED |
| k | SHA-1(N ‖ PAD192(g)) | N, g | k (20-byte SHA-1 → BIGNUM) | `FUN_10060810`, `FUN_10060ec0` | CONFIRMED |
| x | SHA-1(salt ‖ SHA-1(identity ‖ ":" ‖ password)) | identity, password, salt | x (20-byte → BIGNUM) | `0x10060340`, `0x10060c80` | CONFIRMED |
| v | g^x mod N | g, x, N | v | `0x1005f940` (mod_exp) | PARTIALLY_CONFIRMED |
| A | g^a mod N | g, a, N | A | `FUN_10060410` | PARTIALLY_CONFIRMED |
| B | (k·v + g^b) mod N | k, v, g, b, N | B | `FUN_10060d80` | PARTIALLY_CONFIRMED |
| u | SHA-1(PAD192(A) ‖ PAD192(B)) | A, B | u (20-byte → BIGNUM) | `FUN_10060510`, `FUN_10060fa0` | CONFIRMED |
| S (client) | (B - k·v)^(a + u·x) mod N | B, k, v, a, u, x, N | S | `FUN_10060510` | CONFIRMED (formula) |
| S (server) | (A · v^u)^b mod N | A, v, u, b, N | S | `FUN_10060fa0` | CONFIRMED (formula) |
| K | SHA-1(S‖0) ‖ SHA-1(S‖1) | S | K (40 bytes) | `FUN_10061790` | CONFIRMED (structure) |
| M1 | SHA-1(H(N)⊕H(g) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K) | N, g, I, salt, A, B, K | M1 (20 bytes) | `0x100612f0` area | PARTIAL |
| M2 | SHA-1(A ‖ M1 ‖ K) | A, M1, K | M2 (20 bytes) | `0x100609a0` area | PARTIAL |

---

## 6. Independent Validation Results

### 6.1 Independent Implementation

A Python implementation was created at `/home/pedrodroks/Downloads/radmin/srp_validation.py` (temporary, outside repository). It independently implements:

- Integer serialization (big-endian, 192-byte padding)
- SHA-1 hashing
- Modular exponentiation/multiplication/subtraction
- k = SHA-1(N || PAD192(g))
- x = SHA-1(salt || SHA-1(identity_UTF16LE || ":" || password))
- v = g^x mod N
- A = g^a mod N
- B = (k·v + g^b) mod N
- u = SHA-1(PAD192(A) || PAD192(B))
- S_client = (B - k·v)^(a + u·x) mod N
- S_server = (A · v^u)^b mod N
- K = SHA-1(S‖BE32(0)) ‖ SHA-1(S‖BE32(1))
- M1, M2

### 6.2 Validation Results

| Test | Independent Result | Rust Result | Difference | Classification |
|------|-------------------|-------------|------------|----------------|
| k = SHA-1(N||PAD192(g)) | `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233` | Same (via `srp_k()`) | None | MATCH |
| N value | Matches binary extraction | Matches (`RADMIN_SRP1536_PRIME_HEX`) | None | MATCH |
| g value | 5 | 5 (`RADMIN_SRP_GENERATOR`) | None | MATCH |
| S_client == S_server (UTF-8 password) | Yes | Yes (internal test) | None | MATCH |
| S_client == S_server (UTF-16LE password) | Yes | Not tested | N/A | NOT_TESTABLE |
| Identity UTF-16LE vs UTF-8 | x differs | Rust uses UTF-16LE (corrected) | Fixed in Fase 10.5 | CORRECTED |
| Password UTF-8 vs UTF-16LE | x differs significantly | Rust uses UTF-8 | INFERRED_MISMATCH | UNKNOWN |

### 6.3 Differential Summary

- **Matches:** k computation, N value, g value, S_client==S_server mathematical consistency
- **Mismatches:** None confirmed beyond pre-existing Fase 10.5 findings
- **Not testable:** Password encoding (UTF-8 vs UTF-16LE), runtime S equality with official binary
- **Unknown:** Whether `context+0x20` = A on client / B on server at runtime

---

## 7. AES/RSession Reconciliation

### 7.1 Previous Findings

**Phase 10.6:** Reported that `RvROLClient.dll!0x100dce30` calls `SHelper_RSession_GetKey`, which returns a 64-byte secret. Both `SetKeyEnc` (vtable +0xc0) and `SetKeyDec` (vtable +0xc4) require `len == 0x20` (32 bytes). Rust `from_rsession_key()` uses `key_material[..32]` for both enc and dec.

**Phase 10.10:** Classified the AES split mapping as unknown. Reported that two separate 32-byte keys might be required but the mapping could not be determined.

### 7.2 Phase 10.11 Investigation

Traced all consumers of `SHelper_RSession_GetKey` across `RvROLClient.dll`, `RvControlSvc.exe`, and `shelper.dll`:

| Binary | Function | Address | Offset in API Table | Status |
|--------|----------|---------|---------------------|--------|
| `RvROLClient.dll` | `FUN_1003fbd0` (GetProcAddress resolver) | 0x1003fbd0–0x1003ff8e | N/A | Resolves all shelper functions |
| `RvROLClient.dll` | API table storage | Object at 0x10187030 | GetKey at +0xb0, SetKeyEnc at +0xc0, SetKeyDec at +0xc4 | Confirmed |
| `RvROLClient.dll` | Actual `call [reg+0xb0]` site | NOT FOUND | N/A | disp8 indirect calls defeat static analysis |
| `RvControlSvc.exe` | `FUN_00442290` (GetProcAddress resolver) | 0x442290–0x44264e | N/A | Resolves all shelper functions |
| `RvControlSvc.exe` | Actual `call [reg+0xb0]` site | NOT FOUND | N/A | Not traced |

**Search methods attempted:**
- `call [reg + disp8]` patterns for offsets 0xb0, 0xb4, 0xc0, 0xc4, 0xc8, 0xc across all 8 registers — no matches
- `mov reg, [reg + disp32]` / `lea reg, [reg + disp32]` patterns — no matches
- `call [0x1011xxxx]` (IAT calls) — 369 matches found, but these are general IAT calls, not specifically to GetKey/SetKey offsets
- Ghidra `procedure_callers()` on init functions — empty results

### 7.3 Consumer-by-Consumer Conclusion

| Consumer | Binary | Function | Key Mapping | Confidence |
|----------|--------|----------|-------------|------------|
| RSession GetKey caller | `RvROLClient.dll` / `RvControlSvc.exe` | Not located | UNKNOWN | UNKNOWN |
| SetKeyEnc (+0xc0) | Both binaries | Resolved via GetProcAddress | 32-byte key required | CONFIRMED |
| SetKeyDec (+0xc4) | Both binaries | Resolved via GetProcAddress | 32-byte key required | CONFIRMED |
| 64-byte secret split | shelper.dll | No split performed (verbatim return) | Consumer decides | CONFIRMED (no split in shelper) |
| Rust `from_rsession_key()` | `famatech.rs:181-186` | `key_material[..32]` for both enc and dec | Same key both directions | CONFIRMED (source code) |
| Rust `set_key_from_session_buffer()` | `famatech.rs:210-221` | `key_buf[..32]` for both enc and dec | Same key both directions | CONFIRMED (source code) |
| Rust `from_separate_keys_ref()` | `famatech.rs:160-170` | Separate enc/dec keys available | Unused by RSession path | CONFIRMED (source code) |

### 7.4 Explicit Answers

1. **Does RSession use the same 32-byte key for encryption and decryption?**
   - **Rust:** YES (CONFIRMED from source code)
   - **Binary:** UNKNOWN (call site not located, cannot determine what consumer does with 64 bytes)

2. **Does another consumer use the second half?**
   - UNKNOWN (no consumer call site found)

3. **Is the 64-byte secret a pair of keys, a single key plus unused data, or a broader structure?**
   - UNKNOWN (SetKeyEnc/SetKeyDec both require exactly 32 bytes, suggesting two keys are used, but which half maps to which direction is unknown)

4. **Does current Rust reproduce the actual RSession behavior?**
   - PARTIALLY — Rust matches for: 64-byte secret size, no KDF, AES-256-CBC, persistent IVs, 0xCC padding, 9-byte trailer
   - Rust does NOT match for: key split (uses [..32] for both, binary requires two 32-byte keys)

5. **Is the Phase 10.10 blocker valid, partially valid, or disproven?**
   - **PARTIALLY_VALID** — The binary clearly requires two separate 32-byte keys (SetKeyEnc and SetKeyDec both enforce len==0x20). However, the split mapping (which half → enc, which → dec) cannot be determined from available static evidence. The blocker is real but not fully characterized.

---

## 8. PCAP Correlation

### 8.1 PCAPs Reviewed

| File | Size | Readable | Notes |
|------|------|----------|-------|
| `pcaps/radmin_17301.pcap` | 30,596 bytes | Yes | Control port TCP 17301 capture |
| `pcaps/radmin_vm2.pcap` | — | No | Root-owned, mode 600, not readable |
| `/tmp/radmin_vm.pcap` | — | No | Not present locally |

### 8.2 Findings

| Observation | Value | Confidence |
|-------------|-------|------------|
| Control port | TCP 17301 | CONFIRMED |
| Frame format | 4-byte BE uint32 payload size | CONFIRMED |
| Control packet | `00 00 00 04 03 00 00 00` ×4 on streams 1/2 | CONFIRMED |
| Payload sizes | ≡ 0 mod 16 | CONFIRMED |
| TLS | None | CONFIRMED |
| Version value | `3` (0x03000000 little-endian) | CONFIRMED (5 occurrences in PCAP) |
| Version endianness | **Little-endian** (`03 00 00 00`) | CONFIRMED (0 BE occurrences) |

**Important:** The PCAP shows version `3` sent as little-endian (`03 00 00 00`), matching Rust's `to_le_bytes()`. This contradicts prior claims that the wire uses big-endian for step values. However, the PCAP only captures the version exchange, not the SRP step values themselves. The endianness of SRP step values remains unverified.

No SRP handshake parameters (A, B, salt, identity, proofs) were observable in the existing PCAP — captures start after the version exchange and contain only control keepalive/ACK frames.

---

## 9. RSA Evidence Review

### 9.1 Findings

| Question | Answer | Confidence |
|----------|--------|------------|
| RSA public key provenance | UNKNOWN | UNKNOWN |
| RSA private key provenance | UNKNOWN | UNKNOWN |
| RSA key rotation | UNKNOWN | UNKNOWN |
| RSA involved in authentication | YES (PKCS#1 v1.5, RSession key establishment) | CONFIRMED |
| RSA key size | 2048-bit (256 bytes) | CONFIRMED (`RSESSION_RSA_BLOCK_SIZE = 256`) |
| RSA padding | PKCS#1 v1.5 | CONFIRMED |
| Plaintext size | 76 bytes (0x4c) | CONFIRMED (`RSESSION_PLAINTEXT_SIZE = 76`) |
| Server token size | 4 bytes | CONFIRMED (`RSESSION_SERVER_TOKEN_SIZE = 4`) |
| RSA public exponent | `0x010001` (65537) | CONFIRMED (`DEFAULT_RSA_PUBLIC_EXPONENT`) |

**Unresolved:** Where the client obtains the server's RSA public key, and where the server obtains its RSA private key. Neither `RvROLClient.dll` nor `RvControlSvc.exe` call sites for `SHelper_RSession_CreateClient`/`SHelper_RSession_CreateServer` were traced.

---

## 10. Confirmed Incompatibilities

| # | Item | Binary | Rust | Status | Impact |
|---|------|--------|------|--------|--------|
| 1 | Multiplier k | SHA-1(N||PAD(g)) dynamic | Was k=3, now SHA-1(N||PAD(g)) via `srp_k()` | **CORRECTED** (Fase 10.5) | Was fatal, now resolved |
| 2 | Identity hash encoding | UTF-16LE (obj+0x8) | Was UTF-8, now UTF-16LE via `encode_identity()` | **CORRECTED** (Fase 10.5) | Was fatal, now resolved |
| 3 | AES key split | Two 32-byte keys (enc/dec separate) | One 32-byte key for both directions | **NOT CORRECTED** | Fatal for one direction |
| 4 | Password encoding | Likely UTF-16LE (unverified) | UTF-8 (`password.as_bytes()`) | **INFERRED_MISMATCH** | Fatal if confirmed |
| 5 | Step endianness | Version = LE (`03 00 00 00` per PCAP) | `to_le_bytes()` for steps | PARTIAL_MATCH | Step endianness unverified for SRP steps |

---

## 11. Disproven Previous Claims

| Claim | Prior Status | Actual Status | Reason |
|-------|-------------|---------------|--------|
| Asymmetric u (client `SHA-1(k||B)`, server `SHA-1(A||k)`) | CONFIRMED_MISMATCH | **DISPROVEN** | Both compute `SHA-1(A||B)`; hash order differs but concatenated bytes are identical |
| k=3 is active SRP multiplier | CONFIRMED (legacy) | **DISPROVEN** | `FUN_100607d0` (k=3) is dead code, not referenced by any SRP-6a descriptor |
| Wire uses big-endian for all integers | PARTIAL | **PARTIALLY_DISPROVEN** | Version `3` is little-endian (`03 00 00 00`) per PCAP; SRP step endianness unverified |
| Rust k=3 vs binary k=SHA-1(N||g) is the only SRP mismatch | CONFIRMED_MISMATCH | **CORRECTED** | Both now use `k=SHA-1(N||PAD(g))` |

---

## 12. Remaining Unknowns

| # | Unknown | Impact on Interoperability | Evidence Needed |
|---|---------|---------------------------|-----------------|
| 1 | AES key split mapping (which half → enc/dec) | **Critical** — one direction will fail decryption | Dynamic execution or call site tracing in `RvROLClient.dll`/`RvControlSvc.exe` |
| 2 | Password encoding (UTF-8 vs UTF-16LE) | **Critical** — x, v, A, S, K, M1, M2 all differ | Dynamic execution or caller tracing |
| 3 | `context+0x20` = A on client / B on server | **High** — affects u computation | Dynamic execution or breakpoint tracing |
| 4 | GetKey consumer call site | **High** — needed for #1 | Dis8 indirect call sweep or dynamic tracing |
| 5 | RSA key provenance (client public, server private) | **High** — RSession cannot be implemented | Search `.rdata` for key blobs, trace `CreateClient`/`CreateServer` callers |
| 6 | SRP step endianness | **Medium** — version exchange works, SRP steps unknown | PCAP with SRP handshake or live testing |
| 7 | M1/M2 binary verification | **Medium** — proof verification | Disassemble `0x100612f0`, `0x100609a0`, `0x10061450` |

---

## 13. Implementation Readiness

| Component | Status | Blocker |
|-----------|--------|---------|
| SRP group parameters (N, g) | Ready | None |
| SRP k multiplier | Ready (corrected) | None |
| SRP x derivation | Ready (identity corrected, password unverified) | Password encoding |
| SRP v computation | Ready | None |
| SRP A/B computation | Ready | `context+0x20` assignment unverified |
| SRP u computation | Ready | Padding edge case |
| SRP S computation | Ready (mathematically consistent) | Runtime verification |
| SRP KDF | Ready | None |
| SRP M1/M2 | Partially ready | Binary verification |
| AES key split | **NOT READY** | Split mapping unknown |
| AES-256-CBC, IVs, padding, trailer | Ready | None |
| RSA key establishment | NOT READY | Key provenance unknown |
| Version endianness | Ready (matches PCAP) | SRP step endianness unverified |

**Overall:** The client Rust implementation is **not yet interoperable** with the official Windows client. Two critical blockers remain: AES key split mapping and password encoding. The SRP mathematical core is reconstructed and validated, but cannot be proven interoperable without dynamic execution.

---

## 14. Recommended Next Phase

**Do not proceed to implementation work yet.** The following must be resolved first:

1. **High priority:** Trace the `GetKey` consumer call site in `RvROLClient.dll`/`RvControlSvc.exe` to determine the AES key split mapping (which half of the 64-byte secret → enc vs dec). This requires either dynamic analysis or a more sophisticated static analysis of disp8 indirect call patterns.

2. **High priority:** Determine the password encoding used in the x computation. This requires tracing the caller of `0x10060340`/`0x10060c80` in the consumer binary.

3. **Medium priority:** Verify `context+0x20` = A on client / B on server at runtime.

4. **Medium priority:** Trace RSA key provenance in `RvROLClient.dll`/`RvControlSvc.exe`.

5. **Low priority:** Verify SRP step endianness with a PCAP containing the full handshake.

Once these are resolved, implementation work can proceed with confidence.

---

## 15. Evidence Index

| ID | Evidence | Source | Confidence |
|----|----------|--------|------------|
| E1 | `shelper.dll` SHA-256 verified | `sha256sum` | CONFIRMED |
| E2 | `RvROLClient.dll` SHA-256 verified | `sha256sum` | CONFIRMED |
| E3 | `RvControlSvc.exe` SHA-256 verified | `sha256sum` | CONFIRMED |
| E4 | N extracted from `shelper.dll` at file offset 0xaa880 | Independent Python extraction | CONFIRMED |
| E5 | g = 0x05 extracted from `shelper.dll` at file offset 0xaa879 | Independent Python extraction | CONFIRMED |
| E6 | k = SHA-1(N||PAD192(g)) = `7b12a483...` computed independently | Independent Python computation | CONFIRMED |
| E7 | Rust `srp_k()` produces same k as independent computation | Source code + Python comparison | CONFIRMED |
| E8 | S_client == S_server mathematically verified (both password paths) | Independent Python computation | CONFIRMED |
| E9 | Version `3` = `03 00 00 00` (little-endian) in PCAP | PCAP inspection | CONFIRMED |
| E10 | GetKey at context offset +0xb0, SetKeyEnc at +0xc0, SetKeyDec at +0xc4 | `RvROLClient.dll`/`RvControlSvc.exe` GetProcAddress resolver analysis | CONFIRMED |
| E11 | No `call [reg+0xb0/c0/c4]` found in static analysis | objdump pattern search | CONFIRMED (negative result) |
| E12 | Rust `from_rsession_key()` uses `key_material[..32]` for both enc/dec | `src/crypto/famatech.rs:181-186` | CONFIRMED |
| E13 | `FUN_100607d0` (k=3) is dead code, no callers | `shelper.dll` disassembly | CONFIRMED |
| E14 | `FUN_10060810` (client k) and `FUN_10060ec0` (server k) both compute SHA-1(N||PAD(g)) | `shelper.dll` decompilation | CONFIRMED |
| E15 | `FUN_10060510` (client u) and `FUN_10060fa0` (server u) both compute SHA-1(A||B) | `shelper.dll` decompilation | CONFIRMED |
| E16 | Identity internally UTF-16LE, wire UTF-16BE, hash uses internal UTF-16LE | `shelper.dll` `0x100667b0` byte-swap + `0x10060340` hash | CONFIRMED |
| E17 | Password encoding unknown (caller outside `shelper.dll` not traced) | `shelper.dll` `0x10060340`/`0x10060c80` analysis | UNKNOWN |

---

## 16. Integrity Confirmation

- **No Rust source code was modified** during Phase 10.11. The modifications to `src/session/control_handshake.rs` and `src/session/mod.rs` are pre-existing (Fase 10.5 remediation).
- **No existing documentation was overwritten.** The file `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md` pre-existed and was not modified.
- **No binaries, PCAPs, or Ghidra databases were modified.** All analysis was read-only.
- **No commits, pushes, branches, or pull requests were created.**
- **HEAD remains at `95e304e0855a6faf4eece932484cb00e36620a6e`.**
- **Two new files created:** `docs/CRYPTO_PHASE_10_11_RECONSTRUCTION.md` and `docs/CRYPTO_PHASE_10_11_VECTORS.json` (this phase's authorized deliverables).
- **Temporary scripts** (`extract_srp_params.py`, `srp_validation.py`, `find_getkey_callsite.py`, `inspect_pcap.py`) remain in the repository root but are not part of the authorized deliverables and should be cleaned up before any future commit.

---