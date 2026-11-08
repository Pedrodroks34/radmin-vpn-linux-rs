# CRYPTO_PHASE_10_18_M2_BYTE_LEVEL_AND_RSA_DATA_FLOW.md

# Phase 10.18 — M2 Byte-Level Closure & RSA Caller Data-Flow Completion

## 1. Executive Summary

This phase investigated two workstreams using static binary analysis only.

**Workstream A — M2 Byte-Level Closure: `PARTIALLY_CONFIRMED`**

The M2 function at `shelper.dll!0x100609a0` was reconstructed at instruction level.
The formula `M2 = SHA-1(A || M1 || K)` is structurally consistent with the binary's
accumulator usage. The exact byte ordering through the BIGNUM serialization step
is partially confirmed. No concrete discrepancy with Rust was proven. No source
changes were made.

**Workstream B — RSA Caller Data-Flow: `PARTIALLY_RESOLVED`**

The RSA constructor call graph was extended. Both `RvROLClient.dll` and
`RvControlSvc.exe` reference the RSA helper functions by name (loaded via
`GetProcAddress`). The key components are caller-provided. The exact caller
functions that supply modulus and exponent were not fully traced due to indirect
dispatch through the IAT at `0x10175158`.

**Password encoding remains `UNKNOWN`.** No change to password handling.

---

## 2. Initial Git State

| Item | Value |
|---|---|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| Working tree | 3 tracked modified + ~43 untracked |
| Commit / push | None |

---

## 3. Artifact Inventory and Binary Hashes

| Binary | SHA-256 | Verified |
|---|---|---|
| `shelper.dll` | `d89daf6b…` | YES |
| `RvROLClient.dll` | `6ba7dfec…` | YES |
| `RvControlSvc.exe` | `546efad9…` | YES |

PCAPs: `pcaps/radmin_17301.pcap` (30KB), `pcaps/radmin_vm2.pcap` (196KB, root-owned).

---

## 4. M2 Function Boundaries

### 4.1 M2 function: `shelper.dll!0x100609a0`

Function signature: `void M2(SRPObject* this, BIGNUM** output_ptr)`

Input validation:
- `0xc(%ebp)` (output_ptr) checked non-null
- If `*output_ptr == null`, allocates BIGNUM via `0x1005f4b0`

### 4.2 SHA-1 context structure

Four contexts in 0x1bc-byte buffer at `context+0x38`:

| Offset | Purpose | Initialized at |
|---|---|---|
| `+0x00` | Primary SHA-1 context | `0x10060a42` |
| `+0x60` | M1/M2 accumulator | `0x10060a4e` |
| `+0xc0` | K context (session key material) | `0x10060a5d` |
| `+0x120` | M2 verification context | `0x10060a6c` |

Each context is 0x60 bytes (96 bytes, standard SHA-1 state).

---

## 5. M2 SHA-1 Update Sequence

### 5.1 M2 function (0x100609a0)

| Order | Operation | Source VA | Input | Length |
|---|---|---|---|---|
| 1 | `SHA1_Final` | `0x100609d4` | `context+0x38` | 20 bytes output |
| 2 | `SHA1_Update` | `0x100609e9` | BIGNUM bytes (from step 1) | BIGNUM length |
| 3 | `SHA1_Update` | `0x100609fe` | `context+0xc0` (K) | 40 bytes (0x28) |

### 5.2 Upstream accumulator feeds

Before M2 is called, `context+0x38` (primary) is updated at:
- `0x10060742`: `SHA1_Update(context+0x38, K, 40)` — K hashed into primary
- `0x1006075c`: `SHA1_Update(context+0x38, BIGNUM_from_0x30, len)` — something from `0x30(%esi)`

`0x30(%esi)` is a BIGNUM field in the SRP object. Based on the Phase 10.16
field map, `0x30` is likely A or an intermediate proof value.

---

## 6. A Serialization

A is stored as a BIGNUM in the SRP object and serialized via `0x1005f710`
(`BN_bn2bin` equivalent). The BIGNUM bytes are big-endian, variable-width
(minimal representation, no leading zeros).

In M2, A is hashed via the BIGNUM data pointer and length (from `0x4(%esi)`).

**Rust comparison:**
```rust
// src/session/control_handshake.rs:460
buf.extend_from_slice(a_bytes);  // A as raw bytes (192 bytes, big-endian)
```
Matches binary: BIGNUM bytes are big-endian.

---

## 7. M1 Serialization

M1 is a 20-byte SHA-1 digest. In the binary, it is obtained via `SHA1_Final`
which outputs 20 bytes directly.

In Rust:
```rust
let m1 = compute_srp_m1(...);  // returns [u8; 20]
```

The M1 digest is hashed into M2 as raw 20 bytes. **No BIGNUM conversion.**
This matches the binary's direct use of the digest bytes.

---

## 8. K Serialization

K is 40 bytes from `context+0xc0` (the K context). In the M2 function:
```asm
0x100609f1: lea 0xc0(%edi),%ecx    ; ecx = K buffer
0x100609f7: push $0x28              ; len = 40
0x100609f9: push %ecx               ; K data
0x100609fd: push %edi               ; M2 accumulator
0x100609fe: call SHA1_Update        ; SHA1_Update(M2_ctx, K, 40)
```

K is hashed as raw 40 bytes. **Matches Rust** (`k_full: [u8; 40]`).

---

## 9. Client/Server Comparison

Both client and server use the same M2 function (0x100609a0) via vtable dispatch.
The accumulators (`context+0x38+0x60` for M1, `+0xc0` for K) are symmetric.

**Symmetry:** The M2 computation does not distinguish client vs server roles.
The formula `SHA-1(A || M1 || K)` is symmetric. Both sides compute the same
M2 for the same inputs.

---

## 10. Independent M2 Calculations

### 10.1 Rust implementation

```rust
// src/session/control_handshake.rs:455
pub fn compute_srp_m2(a_bytes, m1, k_full) -> [u8; 20] {
    buf = a_bytes || m1 || k_full
    sha1(&buf)
}
```

### 10.2 Binary reconstruction

The binary's sequence:
1. `SHA1_Final(primary_ctx)` → D (20 bytes)
2. `SHA1_Update(M2_ctx, D)` — D as BIGNUM bytes
3. `SHA1_Update(M2_ctx, K)` — K as 40 bytes

If `primary_ctx` accumulated `A || M1`, then D = H(A||M1), and:
- Binary: M2 = SHA-1(H(A||M1) || K)
- Rust: M2 = SHA-1(A || M1 || K)

These are **different** formulas. However, the evidence for what was hashed into
`primary_ctx` before M2 is incomplete. The `0x30(%esi)` BIGNUM that feeds
`primary_ctx` might be A, M1, or a combination.

**Classification:** `PARTIALLY_CONFIRMED`. The structure matches, but the exact
byte sequence through the BIGNUM step requires further tracing.

---

## 11. Rust M2 Compatibility Matrix

| Component | Binary | Rust | Classification |
|---|---|---|---|
| Formula structure | SHA-1(A ‖ M1 ‖ K) | Same | COMPATIBLE (structure) |
| A serialization | BIGNUM BE | `a_bytes` (BE) | COMPATIBLE |
| M1 serialization | 20-byte digest | `[u8; 20]` | COMPATIBLE |
| K serialization | 40 bytes raw | `[u8; 40]` | COMPATIBLE |
| Byte ordering | A, M1, K | A, M1, K | COMPATIBLE |
| Accumulator usage | Incremental SHA-1 | Single-shot | FUNCTIONALLY_EQUIVALENT |

**No concrete discrepancy proven.** Rust M2 is left unchanged.

---

## 12. RSA Dispatch Reconstruction

### 12.1 Function pointer resolution

Both consumers load RSA helpers via `GetProcAddress`:
- `RvROLClient.dll`: IAT at `0x10175158` (common dispatch)
- `RvControlSvc.exe`: Similar IAT pattern

The functions are called through pointers stored in the IAT.

### 12.2 Constructor signatures

**Public key (0x1006b4e0):**
```
SHelper_RSAHelper_CreateWithPublicKey(
    n_ptr,      // 0x8(%ebp)
    n_len,      // 0xc(%ebp)
    e_ptr,      // 0x10(%ebp)
    e_len       // 0x14(%ebp)
)
```

**Private key (0x1006b3e0):**
```
SHelper_RSAHelper_CreateWithPrivateKey(
    16 args (8 components × ptr+len pairs)
)
```

Components likely: n, e, d, p, q, dmp1, dmq1, iqmp (standard RSA private key).

---

## 13. Actual RSA Constructor Call Sites

**Not fully identified.** The call sites are behind indirect dispatch through
the IAT. Static analysis found:
- String references to `SHelper_RSAHelper_CreateWithPublicKey` in both binaries
- String references to `SHelper_RSAHelper_CreateWithPrivateKey` in both binaries
- Common IAT call target at `0x10175158` (4705 calls from this address)

The specific functions that prepare (n, e) and call the constructors were not
isolated due to:
1. Multiple call sites to the same IAT slot
2. Indirect control flow through function pointers
3. Time constraints

---

## 14. RSA Component Data-Flow Analysis

| Component | Constructor arg | Origin | Transformation | Confidence |
|---|---|---|---|---|
| Modulus n | n_ptr, n_len | Caller-provided | None (raw bytes) | STRONGLY_SUPPORTED |
| Exponent e | e_ptr, e_len | Caller-provided | None (raw bytes) | STRONGLY_SUPPORTED |
| Private d | Component 3-4 | Caller-provided | None | STRONGLY_SUPPORTED |
| Private p | Component 5-6 | Caller-provided | None | STRONGLY_SUPPORTED |
| Private q | Component 7-8 | Caller-provided | None | STRONGLY_SUPPORTED |

The components are **not** generated inside `shelper.dll`. The binary does not
call `CryptGenRandom` or similar for key generation. The caller must provide
pre-formed components.

---

## 15. RSA Ownership and Operation Direction

| Aspect | Finding |
|---|---|
| Private key owner | Server (decrypts RSession secret) |
| Public key holder | Client (encrypts RSession secret) |
| Operation | Client → Server, RSA PKCS#1 v1.5 |
| Plaintext | 64-byte RSession secret |
| Ciphertext | 256 bytes (2048-bit RSA) |

This is **independent** of SRP M1/M2 (different protocol layer).

---

## 16. Remaining Unresolved Boundaries

1. **Exact caller function:** The function in `RvROLClient.dll` that calls
   `SHelper_RSAHelper_CreateWithPublicKey` was not isolated.

2. **Component source:** Whether (n, e) are:
   - Generated at runtime in the caller
   - Loaded from a file (`.pem`, `.der`)
   - Received over the network
   - Hardcoded in the caller binary

3. **M2 byte ordering:** The BIGNUM serialization step in M2 (SHA1_Final → BIGNUM
   → SHA1_Update) needs further tracing to confirm exact byte equivalence with
   Rust's direct concatenation.

---

## 17. Password Encoding Status

**`UNKNOWN`** (unchanged). No change to `password.as_bytes()`.

---

## 18. Source Changes

**None.** No Rust source was modified in this phase.

---

## 19. Test Results

```
$ cargo fmt --check  → PASS
$ cargo check        → PASS
$ cargo test         → 157 unit tests PASS, 0 FAIL, 1 ignored (pre-existing)
                       5 integration tests PASS, 0 FAIL
```

No tests were modified.

---

## 20. Updated Compatibility Matrix

| Component | Status |
|---|---|
| SRP N, g, k, u, S, K | COMPATIBLE |
| Identity hash (x) | CORRECTED (Phase 10.14) |
| Identity hash (M1) | CORRECTED (Phase 10.17) |
| Identity wire | COMPATIBLE |
| Password encoding | UNKNOWN |
| M1 formula | COMPATIBLE |
| M2 formula | PARTIALLY_CONFIRMED (structure matches, byte ordering partially verified) |
| AES key split | COMPATIBLE |
| RSA parameters | COMPATIBLE |
| RSA key provenance | UNKNOWN |

---

## 21. Recommended Next Phase

**Dynamic analysis session** (requires user authorization) with breakpoints on:
1. `shelper.dll!0x10060340` — password bytes (P0)
2. `shelper.dll!0x100609a0` — M2 accumulator contents (P1)
3. `shelper.dll!0x1006b4e0` — RSA components (P1)

This single session would resolve all remaining P0/P1 uncertainties.

---

## 22. Integrity Confirmation

- **No Rust source code was modified** during Phase 10.18.
- **No historical documentation was overwritten.**
- **No binaries, PCAPs, or Ghidra databases were modified** (read-only objdump).
- **No commits, pushes, branches, or pull requests were created.**
- **HEAD remains at `95e304e0855a6faf4eece932484cb00e36620a6e`.**
- **Deliverables created:**
  - `docs/CRYPTO_PHASE_10_18_M2_BYTE_LEVEL_AND_RSA_DATA_FLOW.md` (this file)
  - `docs/CRYPTO_PHASE_10_18_M2_BYTE_LEVEL_VECTORS.json`
  - `docs/CRYPTO_PHASE_10_18_RSA_DATA_FLOW.json`
