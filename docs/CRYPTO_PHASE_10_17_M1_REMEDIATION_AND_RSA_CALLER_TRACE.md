# CRYPTO_PHASE_10_17_M1_REMEDIATION_AND_RSA_CALLER_TRACE.md

# Phase 10.17 — M1 Identity Encoding Remediation & RSA Caller-Side Provenance Tracing

## 1. Executive Summary

This phase executed two independent workstreams:

**Workstream A — M1 Identity Encoding Remediation: COMPLETED.** Fixed
`compute_srp_m1()` in `src/session/control_handshake.rs` (line 442) to use
`encode_identity_le()` (UTF-16LE) instead of `username.as_bytes()` (UTF-8).
The wire encoding (`encode_identity()`, UTF-16BE) is unchanged. Five regression
tests were added with independent byte-array expectations. All tests pass.

**Workstream B — RSA Caller-Side Provenance: PARTIALLY_RESOLVED.** Traced the
RSA constructor call graph through `shelper.dll` and `RvROLClient.dll`. The
key components are caller-provided at runtime (not embedded). The exact caller
location that supplies the modulus and exponent was not fully traced due to
time constraints, but the data flow is partially reconstructed.

**Password encoding remains `UNKNOWN`.** No change to password handling.

---

## 2. Initial Git State

| Item | Value |
|---|---|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| Working tree | 3 tracked modified + ~40 untracked |
| Commit / push | None |

---

## 3. Phase 10.16 Evidence Revalidation

Phase 10.16 reported:
- RSA-2048, PKCS#1 v1.5, component-based API, no embedded blobs
- M1 = `SHA-1(H(N) XOR H(g) || H(I) || salt || A || B || K)` with H(I) as SHA-1(UTF-16LE)
- M2 = `SHA-1(A || M1 || K)`
- Rust `compute_srp_m1()` used `sha1(username.as_bytes())` (UTF-8) — **mismatch**

These findings were revalidated against the current source:
- `src/session/control_handshake.rs:442` confirmed: `let h_i = sha1(username.as_bytes());`
- `encode_identity_le()` exists at line 169 (added Phase 10.14)
- Binary evidence at `shelper.dll!0x10060c26`: identity from `obj+0x8` hashed raw (UTF-16LE)

---

## 4. M1 Mismatch Confirmation

**Binary (shelper.dll!0x10060bf3-0x10060c26):**
```asm
0x10060bf3: mov 0x8(%esi),%eax        ; identity ptr (obj+0x8)
0x10060bf6: mov 0x4(%eax),%ecx        ; identity len
0x10060bf9: mov (%eax),%edx           ; identity data
0x10060bfb: push %ecx
0x10060bfc: push %edx
0x10060bfd: lea -0x8c(%ebp),%eax
0x10060c00: push %eax
0x10060c02: call 0x100285f0           ; SHA1_Update(identity_utf16le)
```

The identity buffer at `obj+0x8` is UTF-16LE (Phase 10.14: internal form,
byte-swapped only for wire).

**Rust (before fix):**
```rust
let h_i = sha1(username.as_bytes());  // UTF-8: "A" → [0x41]
```

**Rust (after fix):**
```rust
let h_i = sha1(&encode_identity_le(username));  // UTF-16LE: "A" → [0x41, 0x00]
```

---

## 5. Exact Rust Remediation

**File:** `src/session/control_handshake.rs`, line 442

**Before:**
```rust
let h_i = sha1(username.as_bytes());
```

**After:**
```rust
let h_i = sha1(&encode_identity_le(username));
```

**Scope:** One-line change. No other SRP functions modified. No password encoding change. No wire encoding change.

---

## 6. UTF-16LE Regression Vectors

| Username | UTF-16LE bytes | Source |
|---|---|---|
| `A` | `41 00` | `encode_identity_le("A")` |
| `José` | `4a 00 6f 00 73 00 e9 00` | `encode_identity_le("José")` |
| `😀` (U+1F600) | `3d d8 00 de` | `encode_identity_le("😀")` |
| `` (empty) | `` | `encode_identity_le("")` |

All verified by tests `test_m1_identity_ascii`, `test_m1_identity_accented`,
`test_m1_identity_non_bmp`, `test_m1_identity_empty`.

---

## 7. UTF-16BE Wire Regression Vectors

| Username | UTF-16BE bytes | Source |
|---|---|---|
| `A` | `00 41` | `encode_identity("A")` |
| `José` | `00 4a 00 6f 00 73 00 e9` | `encode_identity("José")` |
| `😀` | `d8 3d de 00` | `encode_identity("😀")` |

Verified by `test_m1_identity_wire_be_preserved`. Wire encoding unchanged.

---

## 8. Independent SHA-1 Calculations

Each M1 test independently computes the expected SHA-1 input sequence:
1. H(N) = SHA1(N_bytes)
2. H(g) = SHA1([0x05])
3. H(N) XOR H(g) byte-wise
4. H(I) = SHA1(UTF-16LE bytes, hardcoded)
5. Concatenate: H(Ng) || H(I) || salt || A || B || K
6. SHA1(concatenated) = expected M1

The test does NOT call `compute_srp_m1()` to generate the expected value — it
reconstructs the hash manually with hardcoded byte arrays.

---

## 9. RSA Constructor Call Graph

```
RvROLClient.dll / RvControlSvc.exe
    │
    ├─ SHelper_RSAHelper_CreateWithPublicKey (0x1006b4e0)
    │      Args: (n_ptr, n_len, e_ptr, e_len)
    │      │
    │      └─► RSA object creation (0x10065d00)
    │          └─► Key setup (0x10065f50, 0x10066170)
    │
    └─ SHelper_RSAHelper_CreateWithPrivateKey (0x1006b3e0)
           Args: 16 components (n, e, d, p, q, dmp1, dmq1, iqmp + lens)
           │
           └─► RSA object creation (0x10065d00)
               └─► Key setup (16 component validation)
```

The constructors are called via function pointers resolved by `GetProcAddress`
from `shelper.dll`. The exact caller addresses in `RvROLClient.dll` were not
fully traced due to indirect dispatch through the IAT at `0x10175158`.

---

## 10. RSA Component Provenance

| Component | Origin | Transformation | Confidence |
|---|---|---|---|
| Modulus (n) | Caller-provided | None (raw bytes) | STRONGLY_SUPPORTED |
| Exponent (e) | Caller-provided | None (raw bytes) | STRONGLY_SUPPORTED |
| Private components | Caller-provided | None | STRONGLY_SUPPORTED |

**Not embedded:** No PEM/DER blobs, no 256-byte key material in `.rdata`.

**Not generated in shelper.dll:** The functions accept pre-formed components;
generation, if it happens, occurs in the caller.

**Exact source:** UNKNOWN. The components could be:
- Generated at runtime in `RvROLClient.dll`/`RvControlSvc.exe`
- Loaded from a configuration file
- Received from a remote server
- Derived from a pre-shared secret

The trace stops at the caller boundary. Further tracing requires:
1. Disassembling the caller functions that prepare (n, e)
2. Determining if they call `CryptGenRandom` or similar
3. Checking if the key is hardcoded in the caller binary

---

## 11. RSA Ownership and Lifecycle

| Aspect | Finding |
|---|---|
| Key owner | Server (public key used by client to encrypt) |
| Operation direction | Client → Server (one-directional) |
| Private key holder | Server (decrypts RSession secret) |
| Public key holder | Client (encrypts RSession secret) |
| Key lifetime | Per-session or per-connection (not determined) |

The RSA key protects the RSession 64-byte secret. The same secret is then used
as AES key material (both directions, first 32 bytes, per Phase 10.13).

---

## 12. RSA Operation Direction

**Client → Server:** Client generates 64-byte secret, encrypts with server's
RSA public key (PKCS#1 v1.5), sends 256-byte ciphertext to server. Server
decrypts with private key, extracts 64-byte secret, installs as AES keys.

This is **independent** of SRP M1/M2 (different protocol layer).

---

## 13. Unresolved Static-Analysis Boundaries

1. **Exact caller of `SHelper_RSAHelper_CreateWithPublicKey`:** Indirect via
   function pointer table; the specific dispatch site in `RvROLClient.dll`
   was not identified.

2. **Modulus/exponent source:** Whether the key is:
   - Generated via `CryptGenRandom` in the caller
   - Loaded from a file (`.pem`, `.der`, `.key`)
   - Received over the network (server-provided)
   - Hardcoded in the caller binary

3. **Key rotation:** Whether the key changes per session or is long-lived.

---

## 14. Password Encoding Status

**`UNKNOWN`** (unchanged from Phase 10.15).

No change to `password.as_bytes()` in `compute_srp_x()`. The password remains
UTF-8 in Rust, pending dynamic analysis. This phase did not investigate the
password encoding (out of scope).

---

## 15. M2 Status

**`PARTIALLY_CONFIRMED`** (unchanged from Phase 10.16).

M2 = `SHA-1(A || M1 || K)` structure confirmed. Exact byte ordering in the
accumulator is partially verified. No discrepancy found. No change made.

---

## 16. Source Changes

### 16.1 `src/session/control_handshake.rs`

1. **Line 442:** Changed `sha1(username.as_bytes())` → `sha1(&encode_identity_le(username))`
2. **Added tests:** 5 new tests at end of test module:
   - `test_m1_identity_ascii`
   - `test_m1_identity_accented`
   - `test_m1_identity_non_bmp`
   - `test_m1_identity_empty`
   - `test_m1_identity_wire_be_preserved`

### 16.2 `src/session/mod.rs`

No changes in this phase (Phase 10.14 already exported `encode_identity_le`).

---

## 17. Tests

```
$ cargo fmt --check  → PASS (exit 0)
$ cargo check        → PASS
$ cargo test         → 157 unit tests PASS, 0 FAIL, 1 ignored (pre-existing)
                       5 integration tests PASS, 0 FAIL
```

New tests (5):
- `test_m1_identity_ascii` — "A" → [0x41, 0x00]
- `test_m1_identity_accented` — "José" → [0x4a,0x00,0x6f,0x00,0x73,0x00,0xe9,0x00]
- `test_m1_identity_non_bmp` — "😀" → [0x3d,0xd8,0x00,0xde]
- `test_m1_identity_empty` — "" → empty
- `test_m1_identity_wire_be_preserved` — wire BE unchanged

All tests use hardcoded byte arrays as expected values (not derived from the implementation).

---

## 18. Final Git State

| Item | Initial | Final |
|---|---|---|
| Branch | `main` | `main` |
| HEAD | `95e304e…` | `95e304e…` |
| Tracked modifications | 3 files | 3 files (incremental diff in `control_handshake.rs`) |
| Untracked files | ~40 entries | ~43 entries (+3 Phase 10.17 docs) |
| Commit / push | None | None |

---

## 19. Updated Compatibility Matrix

| Component | Evidence status | Rust status | Notes |
|---|---|---|---|
| SRP N and g | CONFIRMED | Compatible | No change |
| SRP k | CONFIRMED | Compatible | No change |
| SRP u | CONFIRMED | Compatible | No change |
| SRP identity hash (x) | STRONGLY_SUPPORTED | **Corrected** (Phase 10.14) | UTF-16LE |
| SRP identity hash (M1) | STRONGLY_SUPPORTED | **CORRECTED** (this phase) | UTF-16LE |
| Identity wire encoding | STRONGLY_SUPPORTED | Compatible | UTF-16BE, unchanged |
| Password encoding | UNKNOWN | Unknown (UTF-8) | Dynamic analysis required |
| SRP S and K | CONFIRMED | Compatible | No change |
| AES key split | RESOLVED_STRONGLY_SUPPORTED | Compatible | Same 32B both directions |
| M2 formula | PARTIALLY_CONFIRMED | Compatible | No change |
| RSA key provenance | UNKNOWN | Existing impl | Caller-provided, source untraced |
| RSA parameters | CONFIRMED | Compatible | 2048-bit PKCS#1 v1.5 |

---

## 20. Recommended Next Phase

**Dynamic analysis session** (requires user authorization):
1. Start Windows VM
2. Attach debugger to client process
3. Breakpoint on `shelper.dll!0x10060340` (password + identity)
4. Breakpoint on `0x1006b4e0` (RSA public key components)
5. Capture bytes and compare against hypotheses

This single session resolves:
- Password encoding (P0)
- Identity LE confirmation (P1)
- RSA key provenance (P1)

---

## 21. Integrity Confirmation

- **Source modified:** 1 line in `compute_srp_m1()` + 5 tests (authorized remediation)
- **No historical documentation overwritten**
- **No binaries, PCAPs, or Ghidra projects modified**
- **No commits, pushes, or branch operations**
- **HEAD unchanged at `95e304e0855a6faf4eece932484cb00e36620a6e`**
- **Deliverables created:**
  - `docs/CRYPTO_PHASE_10_17_M1_REMEDIATION_AND_RSA_CALLER_TRACE.md` (this file)
  - `docs/CRYPTO_PHASE_10_17_BYTE_LEVEL_VECTORS.json`
  - `docs/CRYPTO_PHASE_10_17_RSA_CALL_GRAPH.json`
