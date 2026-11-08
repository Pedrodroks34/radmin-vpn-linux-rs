# CRYPTO_PHASE_10_14_IDENTITY_REMEDIATION_AND_PASSWORD_INVESTIGATION.md

# Phase 10.14 — Identity Hash Remediation & Password Runtime Investigation

## 1. Executive Summary

This phase executed two independent workstreams:

**Workstream A — P0 Identity Hash Encoding Remediation: COMPLETED.** Added
`encode_identity_le()` (UTF-16LE) for the SRP hash input while preserving
`encode_identity()` (UTF-16BE) for the wire. `compute_srp_x()` now hashes the
UTF-16LE representation, matching the Windows internal `obj+0x8` buffer. The
wire path is unchanged. Wire regression tests continue to pass.

**Workstream B — P0 Password Encoding Runtime Investigation: NOT EXECUTED.**
No VM was started, no process was attached, and no live capture was performed.
Password encoding remains `UNKNOWN`. The dynamic-analysis procedure from Phase
10.13 was cross-checked against binary evidence and is ready for user
authorization.

Overall readiness: **`NOT_READY`** for official Windows interoperability testing.
The identity hash is corrected, AES is compatible, but password encoding blocks
a complete interoperability claim.

---

## 2. Initial and Final Git State

| Item | Initial | Final |
|---|---|---|
| Branch | `main` | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| Tracked modifications | 3 files (Fase 10.5) | 3 files (Fase 10.5 + Phase 10.14 identity) |
| Untracked files | ~35 entries | ~38 entries (+3 Phase 10.14 docs) |
| Commit / push | None | None |

---

## 3. Phase 10.13 Evidence Reviewed

The Phase 10.13 investigation established:

- `shelper.dll!0x10060361` reads identity from `obj+0x8` raw, no swap:
  `mov 0x8(%esi),%eax; mov 0x4(%eax),%ecx; mov (%eax),%edx; call SHA1_Update`.
- `shelper.dll!0x100667b0` byte-swaps a **copy** for wire serialization with
  `TAG_IDENTITY (0x20000000)`.
- Windows native string format is UTF-16LE, so the internal form is UTF-16LE.
- `encode_identity()` (Rust) produces UTF-16BE via `(c >> 8, c & 0xFF)`.

These findings were treated as STRONGLY_SUPPORTED and used as the basis for
remediation, per the phase authorization.

---

## 4. Rust Call-Site Matrix

All `encode_identity()` call sites were audited:

| Function / call site | File / line | Purpose | Required encoding | Current encoding | Action |
|---|---|---|---|---|---|
| `compute_srp_x()` | `control_handshake.rs:289` | SRP identity hash input | UTF-16LE | WAS UTF-16BE | **CHANGED to `encode_identity_le()`** |
| `State0Initial` wire | `control_handshake.rs:685` | Wire TLV identity | UTF-16BE | UTF-16BE | **UNCHANGED** |
| `test_identity_utf16_byte_swapping` | `control_handshake.rs:1557` | Roundtrip test | UTF-16BE (roundtrip) | UTF-16BE | UNCHANGED |
| `test_control_server_...` | `control_handshake.rs:2308` | Wire identity test | UTF-16BE | UTF-16BE | UNCHANGED |

**No other callers** of `encode_identity()` exist in the repository. The function
is not used by unrelated protocol paths (TLV, framing, transport).

---

## 5. Identity Encoding Diagnosis

**Problem:** `encode_identity()` produced UTF-16BE bytes and was reused for both
wire serialization and SRP hash input. The binary uses different encodings:
- Wire: UTF-16BE (byte-swapped copy)
- Hash: UTF-16LE (raw `obj+0x8`)

Rust was correct for the wire and wrong for the hash.

---

## 6. Exact Before/After Byte Vectors

### Before (Rust hash input = UTF-16BE)

| Identity | Bytes | Source |
|---|---|---|
| `A` | `00 41` | `encode_identity("A")` |
| `José` | `00 4a 00 6f 00 73 00 e9` | `encode_identity("José")` |
| `\u{1f600}` | `d8 3d de 00` | `encode_identity("😀")` |

### After (Rust hash input = UTF-16LE)

| Identity | Bytes | Source |
|---|---|---|
| `A` | `41 00` | `encode_identity_le("A")` |
| `José` | `4a 00 6f 00 73 00 e9 00` | `encode_identity_le("José")` |
| `\u{1f600}` | `3d d8 00 de` | `encode_identity_le("😀")` |

### Wire (unchanged, UTF-16BE)

| Identity | Bytes | Source |
|---|---|---|
| `A` | `00 41` | `encode_identity("A")` |
| `José` | `00 4a 00 6f 00 73 00 e9` | `encode_identity("José")` |
| `\u{1f600}` | `d8 3d de 00` | `encode_identity("😀")` |

---

## 7. Implementation Changes and Rationale

### 7.1 New helper: `encode_identity_le()`

Added to `src/session/control_handshake.rs` (after `encode_identity()`):

```rust
pub fn encode_identity_le(username: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(username.len() * 2);
    for c in username.encode_utf16() {
        out.push((c & 0xFF) as u8);
        out.push((c >> 8) as u8);
    }
    out
}
```

This produces UTF-16LE bytes: low byte first, high byte second.

### 7.2 Modified: `compute_srp_x()`

Line 289 changed from `encode_identity(username)` to `encode_identity_le(username)`.
The formula is otherwise unchanged:
`x = SHA-1(salt || SHA-1(identity_le || ":" || password))`.

### 7.3 Export

`encode_identity_le` is now exported in `src/session/mod.rs`.

### 7.4 What was NOT changed

- `encode_identity()` — still UTF-16BE, used for wire
- `decode_identity()` — still decodes UTF-16BE
- Password handling — still UTF-8 (`password.as_bytes()`), pending runtime evidence
- SRP formula, salt, k, u, S, K — untouched
- AES — untouched (Phase 10.13 resolved as COMPATIBLE)

### 7.5 AGENTS.md compliance

- No comments added (AGENTS.md prohibits `//`, `///`, `//!`, block comments)
- No new dependencies
- Error handling unchanged (helpers return `Vec<u8>`, infallible for valid `&str`)
- `rustfmt` compliant

---

## 8. Wire Serialization Regression Results

| Test | Result |
|---|---|
| `test_identity_utf16_byte_swapping` (roundtrip) | PASS |
| `test_control_server_transition_failure_zeroizes_ephemeral_secrets` (uses `encode_identity`) | PASS |
| `test_item_tlv_encode_decode` | PASS |
| `test_item_tlv_truncated` | PASS |
| All 5 integration tests | PASS |

The wire path is untouched and all existing tests pass.

---

## 9. SRP Hash Input Verification

Verification trace for `compute_srp_x("José", "test", salt)`:

1. `encode_identity_le("José")` → `[0x4a, 0x00, 0x6f, 0x00, 0x73, 0x00, 0xe9, 0x00]`
2. Append `":"` (0x3a) → `[0x4a, 0x00, 0x6f, 0x00, 0x73, 0x00, 0xe9, 0x00, 0x3a]`
3. Append `password.as_bytes()` → `test` as `[0x74, 0x65, 0x73, 0x74]`
4. SHA-1 → inner digest
5. SHA-1(salt ‖ inner) → x

The identity bytes now match the Windows internal representation (UTF-16LE).
The password bytes remain UTF-8 pending runtime verification.

---

## 10. Test Commands and Results

```
$ cargo fmt --check  → PASS (exit 0)
$ cargo check        → PASS (compiles cleanly)
$ cargo test         → 152 unit tests PASS, 0 FAIL, 1 ignored (pre-existing: requires /dev/net/tun)
                       5 integration tests PASS, 0 FAIL
```

New tests added (5):

| Test | Coverage |
|---|---|
| `test_identity_le_ascii` | "A" → LE `[0x41,0x00]`, BE `[0x00,0x41]` |
| `test_identity_le_accented` | "José" → LE and BE exact bytes |
| `test_identity_le_non_bmp_surrogate_pair` | "😀" (U+1F600) → LE `[3d,d8,00,de]`, BE `[d8,3d,de,00]` |
| `test_identity_le_empty` | "" → empty vec |
| `test_identity_le_differs_from_be_for_non_ascii` | LE ≠ BE for "José", same length |

Expected values are hardcoded byte arrays, not derived from the implementation.

---

## 11. Password Runtime Investigation Status

### 11.1 Plan status

The Phase 10.13 dynamic-analysis plan (`docs/CRYPTO_PHASE_10_13_DYNAMIC_ANALYSIS_PLAN.md`)
was reviewed. The proposed approach is sound:

- **Breakpoint:** `shelper.dll!0x10060340` (client x computation) and `0x10060c80` (server)
- **Registration:** Inspect `EDX` (password pointer) and `EDI` (password length) at the call site
- **Expected output:** Exact password bytes and length

Two additional breakpoints were identified in this phase:
- `shelper.dll!0x100df250` — SetKeyPair wrapper (AES confirmation)
- `shelper.dll!0x10060361` — identity struct pointer at hash consumption

### 11.2 Cross-check of proposed addresses

| Address | Phase 10.13 claim | Binary verification (this phase) | Status |
|---|---|---|---|
| `0x10060340` | Client x | Confirms: reads `obj+0x8`, separator `0x10094218`, password from caller `[ebp+16]` | VERIFIED |
| `0x10060c80` | Server x | Confirms: same structure | VERIFIED |
| `0x10060384` | Password ptr register | Confirms: `mov 0x10(%ebp),%edx` | VERIFIED |
| `0x10060355` | Password len register | Confirms: `mov 0xc(%ebp),%edi` | VERIFIED |

### 11.3 Required test inputs

The plan specifies testing with:
1. ASCII-only password (e.g., "p") — distinguishes by length (1 vs 2 bytes)
2. Non-ASCII password (e.g., "päss") — distinguishes UTF-8 multi-byte vs UTF-16LE/BE
3. BMP-outside character (e.g., "😀") — distinguishes surrogate pair behavior

### 11.4 Authorization boundary

**No VM was started. No process was attached. No live capture was performed.**

This remains an open requirement pending explicit user authorization to:
- Start the Windows VM (`win10`, KVM/virt-manager)
- Attach a debugger (x64dbg or WinDbg) to the client process
- Initiate a live SRP handshake with controlled credentials

### 11.5 Classification

Password encoding: **`UNKNOWN`** (unchanged from Phase 10.13).

---

## 12. Updated Compatibility Matrix

| Component | Evidence status | Rust status | Notes |
|---|---|---|---|
| SRP N and g | CONFIRMED | Compatible | No change |
| SRP k | CONFIRMED | Compatible | No change |
| SRP u | CONFIRMED | Compatible | No change |
| SRP identity hash encoding | STRONGLY_SUPPORTED (UTF-16LE) | **CORRECTED** (this phase) | `encode_identity_le()` added; `compute_srp_x()` now uses LE |
| Identity wire encoding | STRONGLY_SUPPORTED (UTF-16BE) | Compatible | `encode_identity()` unchanged (BE) |
| Password encoding | **UNKNOWN** | Unknown | Runtime evidence required; Rust still UTF-8 |
| SRP S and K | CONFIRMED | Compatible | No change |
| AES key split | RESOLVED (same 32B both directions) | Compatible | No change |
| M1/M2 | PARTIAL | Existing impl | No scope expansion |
| RSA key provenance | UNKNOWN | Existing impl | No scope expansion |

---

## 13. Updated Implementation-Readiness Assessment

**`NOT_READY`** for official Windows interoperability testing.

Rationale:
- Identity hash encoding: corrected with STRONGLY_SUPPORTED evidence.
- AES key mapping: resolved (Phase 10.13), Rust compatible.
- **Password encoding: UNKNOWN.** The password bytes fed to the SRP hash may
  differ between Rust (UTF-8) and the Windows client (likely UTF-16LE). This is
  a critical blocker: `x`, `v`, `A`, `S`, `K`, `M1`, `M2` all depend on it.
- RSA key provenance: UNKNOWN. No official key material available.

---

## 14. Remaining Blockers and Recommended Next Phase

| Blocker | Priority | Resolution path |
|---|---|---|
| Password encoding | P0 | Dynamic breakpoint on `0x10060340` (requires user authorization) |
| RSA key provenance | P1 | Search `.rdata` for key blobs; trace CreateClient/CreateServer callers |
| Identity LE confirmation | P1 | One dynamic breakpoint would upgrade STRONGLY_SUPPORTED → CONFIRMED |
| M1/M2 instruction-level verification | P2 | Full disassembly of `0x100612f0` / `0x100609a0` |

**Recommended next phase:** Authorization for the Windows VM dynamic session to
resolve the password encoding. This single session would also confirm the identity
LE encoding and the AES same-pointer mapping. Once the password bytes are known,
the remaining remediation is a one-line change in `compute_srp_x()`.

---

## 15. Git and Change Summary

### Pre-existing (not created by this phase)

- `src/session/control_handshake.rs` — Phase 10.5 remediation (k=SHA-1, srp_k export)
- `src/session/mod.rs` — Phase 10.5 remediation (srp_k export)
- `docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md` — Phase 10.5 audit
- ~35 untracked files (Phase 10.10–10.13 docs + analysis scripts)

### Modified by this phase

- `src/session/control_handshake.rs`:
  - Added `encode_identity_le()` helper (UTF-16LE)
  - Changed `compute_srp_x()` to use `encode_identity_le()` for hash input
  - Added 5 regression tests (`test_identity_le_*`)
- `src/session/mod.rs`:
  - Exported `encode_identity_le`

### Created by this phase

- `docs/CRYPTO_PHASE_10_14_IDENTITY_REMEDIATION_AND_PASSWORD_INVESTIGATION.md` (this file)
- `docs/CRYPTO_PHASE_10_14_BYTE_LEVEL_VECTORS.json`

### Integrity

- No commits, pushes, or branch operations
- No binaries, PCAPs, or Ghidra projects modified
- No historical documentation overwritten
- HEAD unchanged at `95e304e0855a6faf4eece932484cb00e36620a6e`
