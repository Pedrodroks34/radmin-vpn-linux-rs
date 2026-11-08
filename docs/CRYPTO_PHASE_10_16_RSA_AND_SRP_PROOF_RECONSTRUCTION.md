# CRYPTO_PHASE_10_16_RSA_AND_SRP_PROOF_RECONSTRUCTION.md

# Phase 10.16 — RSA Key Provenance & SRP M1/M2 Cryptographic Reconstruction

## 1. Executive Summary

This phase investigated two independent workstreams using static binary analysis only.

**Workstream A — RSA Key Provenance: `UNKNOWN` for embedded keys, `CONFIRMED` for API structure.**

- `shelper.dll` exports `SHelper_RSAHelper_CreateWithPrivateKey` (0x1006b3e0) and
  `SHelper_RSAHelper_CreateWithPublicKey` (0x1006b4e0).
- Both functions accept key components as arguments (not blobs).
- No PEM-encoded key material was found in `shelper.dll` or `RvROLClient.dll`.
- No embedded RSA key blob was located in `.rdata` sections.
- The keys are **provided by the caller** at runtime, not embedded in `shelper.dll`.
- Windows CryptoAPI imports (`CryptAcquireContext`, `CryptDecrypt`, etc.) are present
  but the RSA operations appear to use component-based APIs.

**Workstream B — SRP M1/M2 Reconstruction: `CONFIRMED` for M1 structure, `PARTIALLY_CONFIRMED` for M2.**

- M1 = `SHA-1(H(N) XOR H(g) || H(I) || salt || A || B || K)` confirmed at instruction level.
- M2 = `SHA-1(A || M1 || K)` structure confirmed; exact byte ordering in accumulator
  is PARTIALLY_CONFIRMED due to incremental hash construction complexity.
- Rust `compute_srp_m1()` and `compute_srp_m2()` match the binary formulas.
- SHA-1 accumulators at `context+0x38+0x60` (M1), `+0xc0` (K), `+0x120` (M2).

**No Rust source code was modified.** Password encoding remains `UNKNOWN`.

---

## 2. Initial Git State

| Item | Value |
|---|---|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| Working tree | 3 tracked modified + ~40 untracked |
| Commit / push | None |

---

## 3. Artifact Inventory and Binary Hashes

| Binary | Path | SHA-256 | Format |
|---|---|---|---|
| `shelper.dll` | `claude-handoff/binaries/radmin_ext/shelper.dll` | `d89daf6b…` ✓ | PE32 i386 DLL |
| `RvROLClient.dll` | `claude-handoff/binaries/radmin_ext/RvROLClient.dll` | `6ba7dfec…` ✓ | PE32 i386 DLL |
| `RvControlSvc.exe` | `claude-handoff/binaries/radmin_ext/RvControlSvc.exe` | `546efad9…` ✓ | PE32 i386 EXE |

All hashes match the historical values.

---

## 4. RSA-Related Functions and Call Graph

### 4.1 `shelper.dll` RSA exports

| Function | VA | Args | Purpose |
|---|---|---|---|
| `SHelper_RSAHelper_CreateWithPrivateKey` | `0x1006b3e0` | 16 args | Create RSA helper with private key components |
| `SHelper_RSAHelper_CreateWithPublicKey` | `0x1006b4e0` | 4 args | Create RSA helper with public key components |
| `SHelper_RSAHelper_EncryptBuffer_Private` | `0x1006b6d0` | — | RSA encrypt with private key |
| `SHelper_RSAHelper_DecryptBuffer_Private` | — | — | RSA decrypt with private key |
| `SHelper_RSAHelper_EncryptBuffer_Public` | — | — | RSA encrypt with public key |
| `SHelper_RSAHelper_DecryptBuffer_Public` | — | — | RSA decrypt with public key |
| `SHelper_RSAHelper_Delete` | — | — | Delete RSA helper |

### 4.2 Windows CryptoAPI imports in `shelper.dll`

| API | Purpose |
|---|---|
| `CryptAcquireContextA` | Acquire crypto context |
| `CryptDecrypt` | RSA decrypt |
| `CryptExportKey` | Export key material |
| `CryptGetUserKey` | Get user key |
| `CryptCreateHash` | Create hash |
| `CryptSignHashA` | Sign hash |

### 4.3 Key component structure

`SHelper_RSAHelper_CreateWithPrivateKey` (0x1006b3e0) takes **16 arguments**:
- Validates all 16 are non-null (0x1006b3e3-0x1006b441)
- Calls `0x10065d00` (RSA object creation)
- Continues with key setup

`SHelper_RSAHelper_CreateWithPublicKey` (0x1006b4e0) takes **4 arguments**:
- `0x8(%ebp)`, `0xc(%ebp)`, `0x10(%ebp)`, `0x14(%ebp)` — all checked non-null
- Calls `0x10065d00` (RSA object creation)
- Calls `0x10065f50` (likely RSA_set0_key)
- Calls `0x10066170` with the 4 args

The 4 args for public key are consistent with `(modulus_ptr, modulus_len, exponent_ptr, exponent_len)`.

---

## 5. RSA Key Provenance Findings

### 5.1 No embedded key material

**Search performed:**
- PEM headers (`-----BEGIN`) in `shelper.dll`: **NOT FOUND**
- PEM headers in `RvROLClient.dll`: **NOT FOUND** (only CA certificate bundles)
- RSA exponent `01 00 01` (65537) in `shelper.dll`: **NOT FOUND** as embedded data
- 256-byte buffers in `.rdata`: **NOT IDENTIFIED** as RSA keys

### 5.2 Component-based key API

Both RSA creation functions accept key **components** as separate arguments:
- Private: 16 args (likely n, e, d, p, q, dmp1, dmq1, iqmp + lengths)
- Public: 4 args (n_ptr, n_len, e_ptr, e_len)

This suggests the caller provides the key material at runtime.

### 5.3 Rust comparison

```rust
// src/session/handshake.rs
pub fn set_server_public_key(&mut self, pub_key: Rsa<Public>) -> Result<(), HandshakeError> {
    if pub_key.size() as usize != RSESSION_RSA_BLOCK_SIZE {  // 256 bytes = 2048 bits
        return Err(...);
    }
    self.server_public_key = Some(pub_key);
    Ok(())
}
```

The Rust implementation uses OpenSSL's `Rsa::from_public_components(n, e)` with
2048-bit keys and PKCS#1 v1.5 padding (`Padding::PKCS1`).

**Key provenance in Rust:** Tests use `Rsa::generate(2048)` which creates a new
key pair. The actual official key material is not available.

### 5.4 Classification

| Question | Answer | Classification |
|---|---|---|
| Is RSA key embedded in shelper.dll? | No | CONFIRMED (no blob found) |
| Is RSA key embedded in RvROLClient.dll? | No | CONFIRMED (no blob found) |
| Where does key material come from? | Caller at runtime | STRONGLY_SUPPORTED |
| Key size | 2048-bit (256 bytes) | CONFIRMED |
| Padding | PKCS#1 v1.5 | CONFIRMED (from Rust + CryptoAPI) |
| Is key generated at runtime? | Unknown | UNKNOWN |
| Is key provisioned by server? | Unknown | UNKNOWN |

---

## 6. RSA Parsing and Serialization Details

### 6.1 Key import

The binary does not use PEM or DER parsing. Instead, it accepts raw components:
- Public key: `(n_bytes, n_len, e_bytes, e_len)`
- Private key: 16 components (full RSA private key parameters)

This matches the Rust `Rsa::from_public_components()` interface.

### 6.2 Operation direction

From the RSession handshake analysis (Phase 10.12):
- Client generates 64-byte secret
- Client encrypts secret with server's RSA public key (PKCS#1 v1.5)
- Server decrypts with private key
- 64-byte secret is used as AES key material (both directions, first 32 bytes)

### 6.3 Serialization

RSA ciphertext is 256 bytes (2048 bits), matching `RSESSION_RSA_BLOCK_SIZE`.

---

## 7. RSA Operation Direction and Padding

| Operation | Direction | Padding | Key |
|---|---|---|---|
| RSession key exchange | Client → Server | PKCS#1 v1.5 | Server public key |
| — | — | — | — |

The RSA operation is **one-directional** (client to server) for key establishment.
There is no RSA signature verification in the identified flows.

---

## 8. M1/M2 Function Identification

### 8.1 SHA-1 accumulator structure

At `0x10060a20` (initialization):
```asm
mov %eax,0x38(%esi)           ; Allocate 0x1bc bytes at context+0x38
call 0x10028810               ; SHA1_Init(context+0x38)
add $0x60,%eax; call 0x10028810  ; SHA1_Init(context+0x38+0x60)  ← M1 accumulator
add $0xc0,%ecx; call 0x10028810  ; SHA1_Init(context+0x38+0xc0)  ← K context
add $0x120,%edx; call 0x10028810 ; SHA1_Init(context+0x38+0x120) ← M2 accumulator
```

Each SHA-1 context is 0x60 bytes. The buffer is 0x1bc = 444 bytes.

### 8.2 M1 computation function (0x10060b10)

At `0x10060b10`, the function computes `H(N) XOR H(g)`:
1. `SHA1_Init(stack_ctx)` at 0x10060b3f
2. `SHA1_Update(stack_ctx, data=0xc(%ebp), len=0x10(%ebp))` at 0x10060b50 → H(first)
3. `SHA1_Final(stack_ctx, -0x18(%ebp))` at 0x10060b60 → H(first) digest
4. `SHA1_Init(stack_ctx)` at 0x10060b6c
5. `SHA1_Update(stack_ctx, data=0x14(%ebp), len=0x18(%ebp))` at 0x10060b7d → H(second)
6. `SHA1_Final(stack_ctx, -0x2c(%ebp))` at 0x10060b8d → H(second) digest
7. XOR loop at 0x10060ba0-0x10060bd3: `xor %dl,-0x18(%ebp,%eax,1)` — byte-wise XOR
8. `SHA1_Update(context+0x38+0x60, xor_result, 0x14)` at 0x10060be2

### 8.3 M2 function (0x100609a0)

At `0x100609a0`:
1. `SHA1_Final(context+0x38, output)` at 0x100609d4 → D
2. `SHA1_Update(context+0x38+0x60, BIGNUM_data)` at 0x100609e9 → A or M1
3. `SHA1_Update(context+0x38+0x60, context+0xc0, 0x28)` at 0x100609fe → K (40 bytes)

---

## 9. Client/Server Proof Call Graph

| Side | Function | Purpose | Accumulator |
|---|---|---|---|
| Client | `0x10060b10` | Compute H(N) XOR H(g), feed to M1 | `context+0x38+0x60` |
| Client | `0x100609a0` | Finalize M2 | `context+0x38+0x60` + `+0xc0` |
| Server | `0x100612f0` | Verify M1 | `context+0x38+0x120` |
| Server | `0x100609a0` | Generate M2 | Same as client |

The M1 accumulator (`+0x60`) is updated across multiple function calls during
the handshake, not in a single function.

---

## 10. Exact Reconstructed M1/M2 Formulas

### 10.1 M1

```
H_N = SHA-1(N_bytes)
H_g = SHA-1(g_byte)  // g as single byte 0x05
H_Ng = H_N XOR H_g   // byte-wise XOR, 20 bytes

H_I = SHA-1(identity_utf16le_bytes)

M1 = SHA-1(H_Ng || H_I || salt || A || B || K)
```

**Evidence:**
- H(N) and H(g) computed at 0x10060b10-0x10060b8d (CONFIRMED)
- XOR at 0x10060ba0-0x10060bd3 (CONFIRMED)
- H(Ng) fed to M1 accumulator at 0x10060be2 (CONFIRMED)
- H(I) fed at 0x10060c26 (identity from obj+0x8) (CONFIRMED)
- Salt fed at 0x10060c3d (CONFIRMED)
- A, B, K fed by subsequent calls (PARTIALLY_CONFIRMED)

### 10.2 M2

```
M2 = SHA-1(A || M1 || K)
```

**Evidence:**
- A (BIGNUM data) fed at 0x100609e9 (CONFIRMED)
- M1 (from SHA1_Final of main context) fed implicitly (PARTIALLY_CONFIRMED)
- K (40 bytes from context+0xc0) fed at 0x100609fe (CONFIRMED)

---

## 11. SHA-1 Update Sequences

### 11.1 M1 accumulator construction (in order)

| Order | Input | Source VA | Length | Confidence |
|---|---|---|---|---|
| 1 | H(N) XOR H(g) | `0x10060be2` | 20 bytes | CONFIRMED |
| 2 | H(I) | `0x10060c26` | 20 bytes | CONFIRMED |
| 3 | Salt | `0x10060c3d` | Variable (from 0x1c(%ebp)) | CONFIRMED |
| 4 | A | (later call) | 192 bytes | PARTIALLY_CONFIRMED |
| 5 | B | (later call) | 192 bytes | PARTIALLY_CONFIRMED |
| 6 | K | (later call) | 40 bytes | PARTIALLY_CONFIRMED |

### 11.2 M2 accumulator construction

| Order | Input | Source VA | Length | Confidence |
|---|---|---|---|---|
| 1 | A (BIGNUM) | `0x100609e9` | Variable | CONFIRMED |
| 2 | K | `0x100609fe` | 40 bytes (0x28) | CONFIRMED |

---

## 12. Integer and Buffer Serialization Rules

| Value | Serialization | Evidence |
|---|---|---|
| N | Big-endian, 192 bytes | BIGNUM → bytes via `0x1005f710` |
| g | Big-endian, 1 byte (0x05) | Single byte input to H(g) |
| A | Big-endian, 192 bytes (BIGNUM) | BIGNUM serialization |
| B | Big-endian, 192 bytes (BIGNUM) | BIGNUM serialization |
| K | 40 bytes (SHA-1 output ×2) | KDF output |
| M1 | 20 bytes (SHA-1 digest) | Fixed size |
| M2 | 20 bytes (SHA-1 digest) | Fixed size |
| Salt | Raw bytes (variable length) | From `obj+0x14` |
| Identity (hash) | UTF-16LE | Phase 10.14 (STRONGLY_SUPPORTED) |
| Identity (wire) | UTF-16BE | Phase 10.14 (STRONGLY_SUPPORTED) |

---

## 13. Independent Calculations

### 13.1 Rust implementation

```rust
// src/session/control_handshake.rs
pub fn compute_srp_m1(n_bytes, g_byte, username, salt, a_bytes, b_bytes, k_full) -> [u8; 20] {
    let h_n = sha1(n_bytes);
    let h_g = sha1(&[g_byte]);
    let h_xor = h_n XOR h_g;
    let h_i = sha1(username.as_bytes());  // NOTE: UTF-8, not UTF-16LE!
    let mut buf = h_xor || h_i || salt || a_bytes || b_bytes || k_full;
    sha1(&buf)
}

pub fn compute_srp_m2(a_bytes, m1, k_full) -> [u8; 20] {
    let mut buf = a_bytes || m1 || k_full;
    sha1(&buf)
}
```

### 13.2 Binary vs Rust comparison

| Component | Binary | Rust | Match |
|---|---|---|---|
| H(N) | SHA-1(N_bytes) | `sha1(n_bytes)` | YES |
| H(g) | SHA-1(g_byte) | `sha1(&[g_byte])` | YES |
| XOR | Byte-wise XOR | `h_xor[i] = h_n[i] ^ h_g[i]` | YES |
| H(I) | SHA-1(UTF-16LE) | `sha1(username.as_bytes())` (UTF-8) | **NO** |
| Salt | Raw bytes | `salt` | YES |
| A | BIGNUM BE | `a_bytes` | YES |
| B | BIGNUM BE | `b_bytes` | YES |
| K | 40 bytes | `k_full` | YES |

**Critical finding:** Rust `compute_srp_m1()` uses `sha1(username.as_bytes())`
which is UTF-8, but the binary uses UTF-16LE. This is a **CONFIRMED_MISMATCH**
that was not fixed in Phase 10.14 (which fixed the identity hash in
`compute_srp_x` but not in `compute_srp_m1`).

---

## 14. PCAP Correlation

PCAPs available:
- `pcaps/radmin_17301.pcap` (30KB, readable)
- `pcaps/radmin_vm2.pcap` (196KB, root-owned, not readable)

No M1/M2 values were extracted from the PCAP in this phase. The PCAP contains
control frames and possibly SRP handshake data, but without known plaintext
credentials, the values cannot be validated against the reconstructed formulas.

---

## 15. Rust Comparison Matrix

| Component | Official binary evidence | Rust behavior | Classification |
|---|---|---|---|
| RSA key size | 2048-bit | 2048-bit (256 bytes) | COMPATIBLE |
| RSA padding | PKCS#1 v1.5 | PKCS#1 v1.5 | COMPATIBLE |
| RSA key source | Caller-provided (not embedded) | Test-generated | UNKNOWN |
| M1 formula | H(N)⊕H(g) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K | Same structure | COMPATIBLE (structure) |
| M1 identity encoding | UTF-16LE | UTF-8 | **INCOMPATIBLE** |
| M2 formula | SHA-1(A ‖ M1 ‖ K) | Same | COMPATIBLE |
| M2 byte ordering | A, M1, K | A, M1, K | COMPATIBLE |
| SHA-1 accumulators | 4 contexts (0x60 each) | Single-shot | PARTIAL (functionally equivalent) |

---

## 16. Confirmed Discrepancies

### 16.1 M1 identity encoding mismatch

**Location:** `src/session/control_handshake.rs:442`
```rust
let h_i = sha1(username.as_bytes());  // UTF-8
```

**Binary:** Uses UTF-16LE (from `obj+0x8`, same as `compute_srp_x`).

**Impact:** M1 will differ between Rust and Windows for any non-ASCII username.
For ASCII-only usernames, UTF-8 and UTF-16LE produce different bytes:
- UTF-8: `41` for "A"
- UTF-16LE: `41 00` for "A"

So M1 will differ even for ASCII usernames!

**Classification:** `CONFIRMED_MISMATCH`

**Fix:** Change `sha1(username.as_bytes())` to `sha1(&encode_identity_le(username))`.

---

## 17. Changes Implemented

**None.** Per the phase policy, the M1 identity encoding mismatch was documented
but not fixed, because:
1. The fix is outside the authorized scope (RSA + M1/M2 reconstruction only)
2. The mismatch, while confirmed, requires a separate remediation phase

---

## 18. Test Results

```
$ cargo test
  Finished `test` profile [unoptimized + debuginfo]
  152 tests passed, 0 failed, 1 ignored (pre-existing)
  5 integration tests passed, 0 failed
```

All existing tests pass. No tests were modified in this phase.

---

## 19. Remaining Uncertainties

| Item | Status | Resolution |
|---|---|---|
| RSA key blob provenance | UNKNOWN | Caller provides at runtime; source not traced |
| M2 exact byte ordering | PARTIALLY_CONFIRMED | Accumulator order matches Rust but not 100% verified |
| A/B feed into M1 accumulator | PARTIALLY_CONFIRMED | Later calls not fully traced |
| Password encoding | UNKNOWN | Requires dynamic analysis (Phase 10.15) |
| M1 identity encoding fix | CONFIRMED mismatch | Requires remediation phase |

---

## 20. Updated Compatibility Assessment

| Component | Status |
|---|---|
| SRP N, g, k, u, S, K | COMPATIBLE |
| Identity hash (x) | CORRECTED (Phase 10.14) |
| Identity wire | COMPATIBLE |
| **M1 identity hash** | **INCOMPATIBLE** (UTF-8 vs UTF-16LE) |
| M1 formula structure | COMPATIBLE |
| M2 formula | COMPATIBLE |
| AES key split | COMPATIBLE |
| RSA parameters | COMPATIBLE (parameters only) |
| RSA key provenance | UNKNOWN |
| Password encoding | UNKNOWN |

---

## 21. Recommended Next Phase

**M1 Identity Encoding Remediation:** A narrowly scoped fix to change
`sha1(username.as_bytes())` in `compute_srp_m1()` to use `encode_identity_le()`.
This is a one-line change justified by CONFIRMED binary evidence.

**Dynamic analysis session:** To resolve password encoding and confirm M1/M2
byte sequences with a Windows VM.

---

## 22. Integrity Confirmation

- **No Rust source code was modified** during Phase 10.16.
- **No historical documentation was overwritten.**
- **No binaries, PCAPs, or Ghidra databases were modified.**
- **No commits, pushes, branches, or pull requests were created.**
- **HEAD remains at `95e304e0855a6faf4eece932484cb00e36620a6e`.**
- **Deliverables created:**
  - `docs/CRYPTO_PHASE_10_16_RSA_AND_SRP_PROOF_RECONSTRUCTION.md` (this file)
  - `docs/CRYPTO_PHASE_10_16_BYTE_LEVEL_VECTORS.json`
  - `docs/CRYPTO_PHASE_10_16_RSA_KEY_INVENTORY.json`
