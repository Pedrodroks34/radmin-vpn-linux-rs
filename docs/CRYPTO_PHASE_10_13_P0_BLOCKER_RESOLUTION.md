# CRYPTO_PHASE_10_13_P0_BLOCKER_RESOLUTION.md

# Phase 10.13 — P0 Cryptographic Blocker Resolution

## 1. Executive Summary

This phase resolves the three P0 blockers from the consolidated Phase 10.3–10.5
investigation using byte-level binary evidence.

| Blocker | Result | Classification |
|---|---|---|
| AES split mapping | `SAME_32_BYTE_MATERIAL_BOTH_DIRECTIONS` — both AES contexts receive the first 32 bytes of the 64-byte secret | `RESOLVED_STRONGLY_SUPPORTED` |
| Password encoding | Caller outside `shelper.dll`; encoding not determinable statically | `REQUIRES_DYNAMIC_ANALYSIS` |
| Identity hash input | Hash consumes the internal `obj+0x8` buffer (UTF-16LE), **not** the wire UTF-16BE form | `RESOLVED_STRONGLY_SUPPORTED` |

**Key discovery:** Rust's `from_rsession_key` (using `key_material[..32]` for both
directions) is **COMPATIBLE** with the official binary. Previous reports classified this
as a CONFIRMED_MISMATCH, but direct disassembly now proves both AES contexts receive the
same first 32 bytes in at least two independent code paths.

**Key discovery (identity):** The SRP hash and the wire serialization use **different
encodings** of the identity (hash = internal buffer, wire = byte-swapped copy). Rust
`encode_identity()` produces UTF-16BE and feeds it to **both** `compute_srp_x()` (hash)
and wire serialization. This means Rust is correct for the wire but **wrong for the hash**
(if the internal buffer is UTF-16LE, as strongly supported by Windows native format).

Overall readiness: **`PARTIALLY_READY`** — AES and identity resolved (strongly supported),
password remains unresolved.

---

## 2. Repository and Git State

| Item | Value |
|------|-------|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| Working tree | 3 tracked modified (Phase 10.5) + untracked (prior phases + consolidated docs) |
| Binaries | SHA-256 verified: `shelper.dll` `d89daf6b…`, `RvROLClient.dll` `6ba7dfec…`, `RvControlSvc.exe` `546efad9…` |
| Commit/push | None |

---

## 3. AES Caller and Directional Key Mapping

### 3.1 The GetKey → SetKeyPair flow

Two independent call paths were traced through `RvROLClient.dll`:

**Path A (via `0x100dce30` → `0x10096f21`):**

```
0x10096e07: lea -0x24(%ebp),%ecx         ; &local_buf (struct: {ptr, len, ...})
0x10096e0a: movlpd %xmm0,-0x24(%ebp)     ; zero 8 bytes
0x10096e0f: call 0x100a9960               ; initialize buffer struct
0x10096e14: lea -0x24(%ebp),%eax          ; &local_buf
0x10096e19: push %eax                      ; push &local_buf
0x10096e1a: call 0x100dce30                ; GetKey wrapper (this, &buf)

; Inside 0x100dce30:
0x100dce84: push 0xb8(%esi)                ; session object
0x100dce8a: mov 0x74(%esi),%eax            ; func ptr at API table +0x74
0x100dce8d: call *%eax                      ; GetKey(session, **out_ptr, *out_len)

; After return (back at 0x10096f03):
0x10096f03: lea -0x24(%ebp),%ecx          ; &local_buf
0x10096f08: call 0x100a9cd0                ; %eax = buf[4] (length)
0x10096f0d: push %eax                      ; push len2
0x10096f0e: push -0x24(%ebp)               ; push buf_ptr
0x10096f11: lea -0x24(%ebp),%ecx          ; &local_buf (again)
0x10096f14: call 0x100a9cd0                ; %eax = buf[4] (same length)
0x10096f19: push %eax                      ; push len1 (same value)
0x10096f1a: push -0x24(%ebp)               ; push buf_ptr (SAME POINTER)
0x10096f1f: push $0x0                      ; push 0
0x10096f21: call 0x100df250                ; SetKeyPair wrapper
```

**Path B (via `0x1003de1a` → `0x100df250`):**

```asm
0x1003de1a: mov -0x18(%ebp),%edi         ; %edi = buf_ptr
0x1003de21: lea -0x18(%ebp),%ecx         ; &local_buf
0x1003de24: call 0x100a9cd0              ; %eax = buf length
0x1003de29: mov $0x20,%edx               ; %edx = 0x20
0x1003de2e: cmp %edx,%eax                ; compare len vs 0x20
0x1003de30: cmovb %eax,%edx              ; %edx = min(len, 0x20)
0x1003de3b: push %edx                    ; push len (min)
0x1003de3c: push %edi                    ; push buf_ptr
0x1003de3d: push %edx                    ; push len (SAME)
0x1003de3e: push %edi                    ; push buf_ptr (SAME!)
0x1003de49: lea 0x180(%esi),%ecx         ; this
0x1003de4f: push %eax                    ; push extra arg
0x1003de50: call 0x100df250              ; SetKeyPair wrapper
```

### 3.2 `0x100df250` normalization

```asm
0x100df27e: cmpl $0x20,0x10(%ebp)      ; key1_len >= 0x20?
0x100df28b: cmpl $0x20,0x18(%ebp)      ; key2_len >= 0x20?
0x100df2c5: push $0x20                 ; normalize key2_len = 0x20
0x100df2c7: push %edi                  ; key2_ptr
0x100df2c8: push $0x20                 ; normalize key1_len = 0x20
0x100df2ca: push %ebx                  ; key1_ptr (== key2_ptr in both paths)
0x100df2d5: call *%eax                 ; SetKeyPair (shelper 0x1006a630)
```

### 3.3 Conclusion

| Path | key1_ptr (enc) | key2_ptr (dec) | key1_len | key2_len |
|---|---|---|---|---|
| A (0x10096f21) | `local_buf` | `local_buf` (same) | `buf[4]` | `buf[4]` (same) |
| B (0x1003de50) | `buf_ptr` | `buf_ptr` (same) | `min(len,0x20)` | `min(len,0x20)` (same) |

**Both independent paths pass the same buffer pointer with the same length for both
encryption and decryption.** The first 32 bytes of the GetKey buffer are used for
both directions. Bytes `[32..64]` are unused.

### 3.4 Rust comparison

```rust
// src/crypto/famatech.rs:181-186
pub fn from_rsession_key(key_material: &[u8; RSESSION_KEY_BUFFER_SIZE]) -> Self {
    let key_ref = key_material[..AES_256_KEY_SIZE].try_into().unwrap();
    Self::from_key_ref(key_ref)  // enc_key = dec_key = key_material[..32]
}
```

| Item | Binary | Rust | Match |
|---|---|---|---|
| Secret source | GetKey (64 bytes) | `key_material` (64 bytes) | YES |
| Key offset | `buf[0..32]` for both | `[..32]` for both | YES |
| Directional mapping | Same bytes both directions | Same bytes both directions | YES |
| Second half usage | Unused | Unused | YES |
| AES mode | AES-256-CBC | AES-256-CBC | YES |
| IV | Persistent per direction | Persistent per direction | YES |
| Padding | 0xCC + 9B trailer | 0xCC + 9B trailer | YES |

**Classification: `COMPATIBLE`**

Previous reports classified this as a mismatch, but the direct evidence now proves
otherwise. The "two separate keys" interpretation was based solely on `SetKeyPair`
taking two pointer arguments — but both pointers reference the **same data**.

### 3.5 Remaining uncertainty

Only `RvROLClient.dll` paths were traced. `RvControlSvc.exe` also resolves GetKey
(`FUN_00442290`) but its consumer was not traced. There is a possibility that the
control service uses a different mapping, but this is speculative without evidence.

Posterior probability that the observed paths are representative: HIGH.
Posterior probability that this is the only mapping: MEDIUM (untraced consumer exists).

**Classification: `RESOLVED_STRONGLY_SUPPORTED`**

---

## 4. Password Encoding and Provenance

### 4.1 Binary-side evidence

At `shelper.dll!0x10060340` (client) and `0x10060c80` (server):

```asm
0x10060384: mov 0x10(%ebp),%edx        ; password ptr (from caller stack)
0x10060387: push %edx
0x1006038b: push %edi                  ; password len (from 0xc(%ebp))
0x1006038d: call SHA1_Update           ; hash password raw bytes
```

The password is passed as a caller-supplied `(ptr, len)` with:
- No transformation inside `shelper.dll`
- No null terminator
- No normalization, case conversion, or trimming
- No length-with-terminator

### 4.2 Formula verification

```
Inner: SHA-1(identity_bytes ‖ 0x3a ‖ password_bytes)
Outer: SHA-1(salt_bytes ‖ inner_digest_20_bytes)
x = outer_digest → BIGNUM
```

The formula `x = SHA-1(salt || SHA-1(I || ":" || P))` is **CONFIRMED**.

### 4.3 Encoding investigation

The caller of `0x10060340`/`0x10060c80` exists outside `shelper.dll`. No direct
`call 0x10060340` exists anywhere in `shelper.dll` (confirmed by search). The caller
is in the consumer (likely `RvControlSvc.exe` or `RvROLClient.dll`).

Without knowing the caller's string representation, the password encoding is:

| Hypothesis | Likelihood | Basis |
|---|---|---|
| UTF-16LE | HIGH | Windows native string format; identity is also UTF-16-based |
| UTF-8 | MEDIUM | Rust default; some Windows code paths use UTF-8 |
| ANSI/code page | LOW | Less common in modern Windows crypto code |
| UTF-16BE | VERY LOW | Unnatural for Windows internal representation |

### 4.4 Rust comparison

```rust
// src/session/control_handshake.rs
cred_buf.extend_from_slice(&encode_identity(username));  // UTF-16BE
cred_buf.push(b':');
cred_buf.extend_from_slice(password.as_bytes());         // UTF-8
```

**Classification: `UNKNOWN`**

The Rust password encoding (UTF-8) is likely wrong if the Windows caller uses
UTF-16LE, but this cannot be confirmed statically.

**Classification: `REQUIRES_DYNAMIC_ANALYSIS`**

---

## 5. Identity Encoding Reconciliation

### 5.1 Three separate contexts

| Context | Buffer | Transformation | Encoding |
|---|---|---|---|
| SRP hash input | `obj+0x8` (read directly at `0x10060361`) | None (raw bytes) | **UTF-16LE** (internal) |
| Wire serialization | Copy from `+0x68`/`+0x70` fields, byte-swapped at `0x100667b0` | Byte-swap per u16 | **UTF-16BE** (after swap) |
| Rust `encode_identity()` | `username.encode_utf16()` → `(c>>8, c&0xFF)` | BE output | **UTF-16BE** |

### 5.2 Byte-swap evidence

At `0x100667b0` (wire serialization path):

```asm
0x1006679b: mov -0x24(%ebp),%edi       ; buffer ptr (from 0x10062800 fill)
0x100667b0: mov (%edi,%edx,2),%ax        ; load u16 (LE on x86)
0x100667b4: movzbl 0x1(%edi,%edx,2),%ecx ; high byte
0x100667b9: shl $0x8,%ax                 ; shift
0x100667bd: or %ax,%cx                   ; byte swap
0x100667c0: mov %cx,(%edi,%edx,2)        ; store swapped
; ... loop ...
0x100667cc: push $0x20000000             ; TAG_IDENTITY
0x100667d6: call 0x100626e0              ; serialize TLV
```

The swap converts each u16 from LE to BE (on x86, loading LE then byte-swapping gives BE).
This happens on a **copy** of the identity (from `0x10062800` fill at `0x10066789`),
not on `obj+0x8` itself. The original `obj+0x8` buffer is **not** modified.

### 5.3 Hash input evidence

At `0x10060361` (SRP x computation):

```asm
0x10060361: mov 0x8(%esi),%eax          ; identity struct ptr (obj+0x8)
0x10060364: mov 0x4(%eax),%ecx          ; length
0x10060367: mov (%eax),%edx             ; data ptr
0x10060369: push %ecx
0x1006036a: push %edx
0x1006036f: call SHA1_Update            ; hash raw bytes from obj+0x8
```

The hash reads `obj+0x8` **directly**, with no swap. The buffer at `obj+0x8` was set
during SRP object creation (CreateClient/CreateServer) and retains its internal form.

### 5.4 Deduction

For the swap to make sense (converting between LE and BE for the wire):
- If internal is LE: swap gives BE wire. Hash = LE. Wire = BE.
- If internal is BE: swap gives LE wire. Hash = BE. Wire = LE.

Windows native string format is UTF-16LE. The internal representation at `obj+0x8`
is set by Windows code (CreateClient/CreateServer). Therefore:

| Item | Encoding | Confidence |
|---|---|---|
| `obj+0x8` (internal) | UTF-16LE | STRONGLY_SUPPORTED |
| SRP hash input | UTF-16LE (raw obj+0x8) | STRONGLY_SUPPORTED |
| Wire identity | UTF-16BE (after swap) | STRONGLY_SUPPORTED |
| Rust `encode_identity()` | UTF-16BE | CONFIRMED (source code) |

**Rust uses UTF-16BE for both the hash and the wire.** The wire matches; the hash
does not (binary hashes LE, Rust hashes BE).

### 5.5 Rust comparison

| Operation | Windows bytes | Rust bytes | Match |
|---|---|---|---|
| Wire identity | UTF-16BE (after swap) | UTF-16BE (`encode_identity()`) | YES |
| SRP hash identity | UTF-16LE (raw `obj+0x8`) | UTF-16BE (`encode_identity()`) | **NO** |

**Classification: `RESOLVED_STRONGLY_SUPPORTED`**

Rust's `compute_srp_x()` feeds the wrong bytes to the hash. A targeted fix would
hash the UTF-16LE form (swap each pair of bytes from `encode_identity()` output).

**Note:** This does NOT mean `encode_identity()` should be changed. It is correct
for the wire. The hash needs the LE form, which is a different input. The fix
would be in `compute_srp_x()` to use an LE encoding for the hash input only.

---

## 6. Rust Byte-Level Comparison

### 6.1 Identity

Test identity: "José" (J=0x004A, o=0x006F, s=0x0073, é=0x00E9)

| Encoding | Bytes |
|---|---|
| UTF-8 | `4A 6F 73 C3 A9` |
| UTF-16LE | `4A 00 6F 00 73 00 E9 00` |
| UTF-16BE | `00 4A 00 6F 00 73 00 E9` |

- Binary hash input: `4A 00 6F 00 73 00 E9 00` (UTF-16LE)
- Rust hash input: `00 4A 00 6F 00 73 00 E9` (UTF-16BE via `encode_identity()`)
- Match: **NO**

### 6.2 Password

Test password: "päss" (p=0x0070, ä=0x00E4, s=0x0073, s=0x0073)

| Encoding | Bytes |
|---|---|
| UTF-8 | `70 C3 A4 73 73` |
| UTF-16LE | `70 00 E4 00 73 00 73 00` |
| UTF-16BE | `00 70 00 E4 00 73 00 73` |

- Binary password: UNKNOWN (depends on caller)
- Rust password: `70 C3 A4 73 73` (UTF-8)
- Match: **UNKNOWN**

### 6.3 AES

Test secret: `00 01 02 ... 3F` (64 bytes, each byte = its index)

| Item | Binary | Rust | Match |
|---|---|---|---|
| Enc key | `secret[0..32]` = `00..1F` | `key_material[..32]` = `00..1F` | YES |
| Dec key | `secret[0..32]` = `00..1F` | `key_material[..32]` = `00..1F` | YES |
| Bytes [32..64] | Unused | Unused | YES |

---

## 7. Independent Validation

A Python script was used to verify the byte-level encodings:

```python
# "José" identity
"José".encode("utf-8")       # b'J' + b'o' + b's' + b'\xc3\xa9' = 5 bytes
"José".encode("utf-16-le")   # b'J\x00o\x00s\x00\xe9\x00' = 8 bytes  
"José".encode("utf-16-be")   # b'\x00J\x00o\x00s\x00\xe9' = 8 bytes
```

All three produce visually distinct byte sequences. The Rust identity mismatch
is detectable with any non-ASCII test string.

---

## 8. Evidence Classification

| Finding | Classification | Evidence |
|---|---|---|
| Both AES keys = first 32 bytes | `RESOLVED_STRONGLY_SUPPORTED` | Two independent call paths, same pointer |
| Identity hash = UTF-16LE | `RESOLVED_STRONGLY_SUPPORTED` | Native Windows format + swap direction + `obj+0x8` direct read |
| Identity wire = UTF-16BE | `RESOLVED_STRONGLY_SUPPORTED` | Swap loop + Rust BE output match |
| Password encoding | `REQUIRES_DYNAMIC_ANALYSIS` | Caller outside `shelper.dll` |
| AES same-key in RvControlSvc.exe | `UNKNOWN` | Consumer not traced |

---

## 9. Remaining Uncertainties

1. **Password encoding** — the sole unresolved P0 blocker. Requires dynamic analysis.
2. **RvControlSvc.exe AES mapping** — the control service consumer was not traced.
   It might use a different mapping than `RvROLClient.dll`.
3. **Identity LE vs BE confirmation** — STRONGLY_SUPPORTED but not CONFIRMED.
   A single dynamic breakpoint on `0x10060340` would confirm.

---

## 10. Final Readiness Assessment

**`PARTIALLY_READY`**

- AES split: resolved (strongly supported). Rust is compatible.
- Identity hash encoding: resolved (strongly supported). Rust has a hash-input bug (BE vs LE).
- Password encoding: unresolved. Rust uses UTF-8; binary likely uses UTF-16LE.

**Blocker count:** 1 of 3 P0 blockers remains.

**Remediation readiness:** A targeted Rust fix for the identity hash encoding (use
UTF-16LE for `compute_srp_x` input while keeping UTF-16BE for wire) is justified by
strong evidence. The password encoding fix cannot be justified until resolved
dynamically.

---

## 11. Integrity Confirmation

- **No Rust source code was modified** during Phase 10.13.
- **No historical documentation was overwritten.**
- **No binaries, PCAPs, or Ghidra databases were modified.**
- **No commits, pushes, branches, or pull requests were created.**
- **HEAD remains at `95e304e0855a6faf4eece932484cb00e36620a6e`.**
- **Deliverables created:**
  - `docs/CRYPTO_PHASE_10_13_P0_BLOCKER_RESOLUTION.md` (this file)
  - `docs/CRYPTO_PHASE_10_13_BYTE_LEVEL_VECTORS.json`
  - `docs/CRYPTO_PHASE_10_13_DYNAMIC_ANALYSIS_PLAN.md`
