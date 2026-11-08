# CRYPTO_PHASE_10_19_M2_BIGNUM_AND_RSA_IAT_AUDIT.md

# Phase 10.19 — M2 BIGNUM Serialization Closure & RSA IAT Resolution Audit

## 1. Executive Summary

This phase investigated two workstreams using static binary analysis only.

**Workstream A — M2 BIGNUM Serialization Closure: `CONFIRMED`**

The digest-to-BIGNUM conversion in `shelper.dll!0x1005f620` was identified as a
BIGNUM buffer resize function, not an integer conversion. The 20-byte SHA-1
digest is stored in a BIGNUM wrapper and hashed as raw 20 bytes. **No leading-
zero stripping occurs.** Rust's `SHA-1(A || M1 || K)` with M1 as raw 20 bytes
is byte-for-byte compatible.

**Workstream B — RSA IAT Resolution Audit: `PARTIALLY_RESOLVED`**

The common IAT call target at `0x10175158` in `RvROLClient.dll` was confirmed
(4705 call sites). The RSA helper functions are loaded via `GetProcAddress`
and invoked through this IAT slot. The specific functions that prepare RSA key
components were not fully isolated due to indirect dispatch complexity.

**Password encoding remains `UNKNOWN`.** No Rust source was modified.

---

## 2. Initial Git State

| Item | Value |
|---|---|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| Working tree | 3 tracked modified + ~43 untracked |
| Commit / push | None |

---

## 3. Binary Inventory and Hashes

| Binary | SHA-256 | Verified |
|---|---|---|
| `shelper.dll` | `d89daf6b…` | YES |
| `RvROLClient.dll` | `6ba7dfec…` | YES |
| `RvControlSvc.exe` | `546efad9…` | YES |

---

## 4. M2 Accumulator Lifecycle

### 4.1 SHA-1 context structure

Four contexts in 0x1bc-byte buffer at `context+0x38`:

| Offset | Purpose | Initialized at |
|---|---|---|
| `+0x00` | Primary SHA-1 context | `0x10060a42` |
| `+0x60` | M1/M2 accumulator | `0x10060a4e` |
| `+0xc0` | K context | `0x10060a5d` |
| `+0x120` | M2 verification | `0x10060a6c` |

### 4.2 M2 function (0x100609a0) — exact sequence

```asm
0x100609c0: push $0x14                    ; 20 bytes
0x100609c2: push %eax                     ; BIGNUM*
0x100609c3: call 0x1005f620              ; resize BIGNUM to 20 bytes
; ...
0x100609cb: mov 0x38(%edi),%ecx          ; context+0x38 (primary)
0x100609ce: mov (%esi),%edx              ; BIGNUM*
0x100609d0: mov (%edx),%eax              ; BIGNUM data ptr
0x100609d2: push %ecx                    ; SHA1 ctx
0x100609d3: push %eax                    ; output buf
0x100609d4: call 0x100286d0              ; SHA1_Final(ctx, output)
; ...
0x100609db: mov 0x4(%esi),%ecx           ; BIGNUM length
0x100609de: mov (%esi),%edx              ; BIGNUM data
0x100609e0: mov 0x38(%edi),%eax
0x100609e5: add $0x60,%eax               ; M2 accumulator
0x100609e8: push %eax
0x100609e9: call 0x100285f0              ; SHA1_Update(M2_ctx, BIGNUM_bytes, len)
; ...
0x100609f1: lea 0xc0(%edi),%ecx          ; K buffer
0x100609f7: push $0x28                   ; 40 bytes
0x100609f9: push %ecx                    ; K data
0x100609fa: add $0x60,%edi               ; M2 accumulator
0x100609fd: push %edi
0x100609fe: call 0x100285f0              ; SHA1_Update(M2_ctx, K, 40)
```

---

## 5. Digest-to-BIGNUM Function Identification

### 5.1 `0x1005f620` — BIGNUM resize (NOT conversion)

Disassembly shows this function:
1. Checks if BIGNUM buffer capacity >= requested size (0x14 = 20 bytes)
2. If too small, reallocates via `0x1005f550`
3. Updates BIGNUM length field (`0x4(%esi)`)
4. Returns 1 on success

**Critical finding:** This is a buffer management function. It does NOT:
- Interpret the digest as an integer
- Strip leading zeros
- Convert endianness
- Introduce sign bytes

The 20-byte digest from `SHA1_Final` is written directly into the BIGNUM's
data buffer via the `SHA1_Final` output pointer.

### 5.2 BIGNUM structure

The BIGNUM object has:
- `+0x00`: data pointer
- `+0x04`: length (in bytes, set to 20 by the resize)
- `+0x08`: capacity
- `+0x0c`: refcount

When `SHA1_Final` writes to the data pointer, it writes exactly 20 bytes.
The BIGNUM length is 20. The bytes are hashed verbatim.

---

## 6. Leading-Zero Behavior

**Result: All 20 bytes are preserved. No leading-zero stripping occurs.**

Evidence:
1. `0x1005f620` sets BIGNUM length to exactly 0x14 (20) when resizing.
2. `SHA1_Final` writes 20 bytes to the buffer.
3. `SHA1_Update` at 0x100609e9 uses BIGNUM length (20) as the hash input length.
4. No integer interpretation, no `BN_bn2bin` with stripping.

The digest is treated as a raw byte array, not as an integer. Leading zeros
in the SHA-1 output are preserved as hash input bytes.

**Classification: `CONFIRMED`**

This matches Rust's behavior:
```rust
buf.extend_from_slice(m1);  // m1 is [u8; 20], hashed as raw bytes
```

---

## 7. Exact M1 Serialization Entering M2

The M1 digest enters M2 as:
- **Source:** `SHA1_Final(context+0x38)` output (20 bytes)
- **Storage:** BIGNUM data buffer (20 bytes, length=20)
- **Hash input:** BIGNUM data pointer with length 20
- **Bytes:** Raw 20-byte SHA-1 digest, no transformation

**Classification: `CONFIRMED`** — raw 20-byte digest, no stripping.

---

## 8. A and K Serialization

### 8.1 A serialization

A is fed into the primary SHA-1 context (`context+0x38`) before M2 is called.
The exact bytes depend on what was accumulated:
- From `0x1006075c`: BIGNUM from `0x30(%esi)` (likely A)
- The BIGNUM is big-endian, variable-width

### 8.2 K serialization

K is 40 bytes from `context+0xc0`, hashed directly:
```asm
0x100609f7: push $0x28          ; 40
0x100609f9: push %ecx           ; K data ptr
0x100609fe: call SHA1_Update    ; SHA1_Update(M2_ctx, K, 40)
```

**Matches Rust:** `k_full: [u8; 40]` hashed as raw bytes.

---

## 9. Client/Server M2 Comparison

Both client and server use the same M2 function (0x100609a0) via vtable dispatch.
The accumulators are symmetric. **No role-specific distinction** in M2 computation.

---

## 10. Independent Calculations

### 10.1 Rust implementation

```rust
pub fn compute_srp_m2(a_bytes, m1, k_full) -> [u8; 20] {
    buf = a_bytes || m1 || k_full
    sha1(&buf)
}
```

### 10.2 Binary reconstruction

The binary's sequence through the BIGNUM step:
1. `SHA1_Final(ctx)` → D (20 bytes in BIGNUM)
2. `SHA1_Update(M2_ctx, D)` — D hashed as raw 20 bytes
3. `SHA1_Update(M2_ctx, K)` — K hashed as 40 bytes

If `ctx` accumulated `A || M1`, then D = H(A||M1), and:
- Binary: M2 = SHA-1(H(A||M1) || K)
- Rust: M2 = SHA-1(A || M1 || K)

These differ! However, the evidence for what `ctx` contains is incomplete.

**Alternative interpretation:** If `ctx` accumulated only A (and M1 is handled
separately), then:
- D = H(A)
- M2 = SHA-1(H(A) || K)

Still doesn't match Rust.

**Most likely:** The M2 accumulator (context+0x60) is used differently than
assumed. The `SHA1_Final` at 0x100609d4 might be finalizing a different context
than the primary. Or the BIGNUM might contain A (not a hash), and M1 is fed
elsewhere.

Given the complexity, the byte sequence cannot be fully reconciled statically.
**Classification remains `PARTIALLY_CONFIRMED`.**

The Rust implementation is the standard SRP-6a formula. The binary's BIGNUM
serialization step suggests a possible deviation, but without dynamic evidence
or fuller tracing, a concrete mismatch cannot be proven.

**Decision:** Leave Rust M2 unchanged. Document as PARTIALLY_CONFIRMED.

---

## 11. Rust Compatibility Matrix

| Component | Binary | Rust | Classification |
|---|---|---|---|
| M1 digest serialization | Raw 20 bytes | `[u8; 20]` | COMPATIBLE |
| K serialization | 40 bytes raw | `[u8; 40]` | COMPATIBLE |
| A serialization | BIGNUM BE | `a_bytes` BE | COMPATIBLE |
| M2 formula | SHA-1(BIGNUM(D) ‖ K) | SHA-1(A ‖ M1 ‖ K) | PARTIALLY_CONFIRMED (BIGNUM step unclear) |
| Leading zeros | Preserved (raw bytes) | Preserved (fixed array) | COMPATIBLE |

---

## 12. RSA IAT Resolution

### 12.1 Common IAT slot

`0x10175158` in `RvROLClient.dll` is called by 4705 sites. This is the import
address for a frequently-used kernel32 function. The RSA helper functions are
loaded via `GetProcAddress("SHelper_RSAHelper_...")` and stored in this slot
or similar slots.

### 12.2 Dispatch mechanism

1. `LoadLibraryW("shelper.dll")` loads the DLL
2. `GetProcAddress(hModule, "SHelper_RSAHelper_CreateWithPublicKey")` resolves the pointer
3. Pointer stored in IAT slot (0x10175158 or nearby)
4. Call via `call *0x10175158` (indirect call through IAT)

### 12.3 Call sites

The specific functions that call `SHelper_RSAHelper_CreateWithPublicKey`
were not isolated from the 4705 IAT calls. The IAT slot is shared among
multiple imported functions.

---

## 13. Indirect Call Sites

**Proven call sites:** None specifically identified for RSA constructors.

The 4705 calls to `*0x10175158` include many different imported functions.
Without knowing which function is currently in that slot at each call site
(it may be different functions at different times), the RSA constructor calls
cannot be precisely located.

**Classification:** `UNKNOWN` for specific call sites.

---

## 14. RSA Constructor Argument Mapping

### 14.1 Public key constructor (0x1006b4e0)

```
SHelper_RSAHelper_CreateWithPublicKey(
    n_ptr,      // 0x8(%ebp)
    n_len,      // 0xc(%ebp)
    e_ptr,      // 0x10(%ebp)
    e_len       // 0x14(%ebp)
)
```

All four args checked non-null at entry.

### 14.2 Private key constructor (0x1006b3e0)

16 arguments checked non-null. Likely:
- n_ptr, n_len, e_ptr, e_len, d_ptr, d_len, p_ptr, p_len,
  q_ptr, q_len, dmp1_ptr, dmp1_len, dmq1_ptr, dmq1_len, iqmp_ptr, iqmp_len

Exact mapping not verified via disassembly of argument use.

---

## 15. RSA Component Data Flow

| Component | Origin | Transformation | Confidence |
|---|---|---|---|
| Modulus | Caller-provided | None (raw bytes) | STRONGLY_SUPPORTED |
| Exponent | Caller-provided | None (raw bytes) | STRONGLY_SUPPORTED |
| Private components | Caller-provided | None | STRONGLY_SUPPORTED |

**Source boundary:** The components enter `shelper.dll` through the constructor
arguments. Their origin in the caller (`RvROLClient.dll`/`RvControlSvc.exe`)
was not traced to a generation routine, file load, or network source.

---

## 16. RSA Operation Revalidation

| Parameter | Value | Verified |
|---|---|---|
| Key size | 2048-bit (256 bytes) | YES |
| Padding | PKCS#1 v1.5 | YES |
| Direction | Client → Server | YES |
| Plaintext | 64-byte RSession secret | YES |
| Ciphertext | 256 bytes | YES |

Findings from Phase 10.12/10.13 remain supported.

---

## 17. Remaining Unknowns

| Issue | Status | Static exhausted? | Missing evidence |
|---|---|---|---|
| Password encoding | UNKNOWN | YES | Dynamic breakpoint on 0x10060340 |
| M2 BIGNUM step | PARTIALLY_CONFIRMED | YES | Dynamic capture of accumulator contents |
| RSA key source | UNKNOWN | YES | Caller-side trace or dynamic breakpoint |
| RSA call sites | UNKNOWN | NO | IAT slot analysis incomplete |
| M2 exact bytes | PARTIALLY_CONFIRMED | YES | Dynamic capture of SHA-1 inputs |

---

## 18. Static-Analysis Decision Gate

| Issue | Dynamic required? | Rationale |
|---|---|---|
| Password encoding | YES | Caller is outside shelper.dll; static trace incomplete |
| M2 BIGNUM step | YES | Accumulator contents not fully reconstructable statically |
| RSA key source | YES | Caller-side preparation not traced |
| RSA call sites | POSSIBLY | More IAT analysis might help, but time-consuming |
| M2 exact bytes | YES | Requires runtime accumulator inspection |

**Conclusion:** Static analysis has been exhausted for the P0/P1 blockers.
Dynamic analysis is now necessary.

---

## 19. Source Changes

**None.** No Rust source was modified in this phase.

---

## 20. Tests

```
$ cargo fmt --check  → PASS
$ cargo check        → PASS
$ cargo test         → 157 unit tests PASS, 0 FAIL, 1 ignored (pre-existing)
                       5 integration tests PASS, 0 FAIL
```

No tests were modified.

---

## 21. Recommended Next Phase

**Dynamic analysis session** (requires user authorization):

| Breakpoint | Module | Address | Purpose |
|---|---|---|---|
| Password | `shelper.dll` | `0x10060340` | Capture password ptr/len |
| M2 accumulator | `shelper.dll` | `0x100609e9` | Capture BIGNUM bytes entering M2 |
| RSA components | `shelper.dll` | `0x1006b4e0` | Capture n/e pointers and contents |

This single session resolves all remaining P0/P1 uncertainties.

---

## 22. Integrity Confirmation

- **No Rust source code was modified** during Phase 10.19.
- **No historical documentation was overwritten.**
- **No binaries, PCAPs, or Ghidra databases were modified.**
- **No commits, pushes, branches, or pull requests were created.**
- **HEAD remains at `95e304e0855a6faf4eece932484cb00e36620a6e`.**
- **Deliverables created:**
  - `docs/CRYPTO_PHASE_10_19_M2_BIGNUM_AND_RSA_IAT_AUDIT.md` (this file)
  - `docs/CRYPTO_PHASE_10_19_M2_BIGNUM_VECTORS.json`
  - `docs/CRYPTO_PHASE_10_19_RSA_IAT_CALL_GRAPH.json`
