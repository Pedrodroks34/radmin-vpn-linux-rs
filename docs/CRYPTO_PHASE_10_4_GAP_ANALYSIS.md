# CRYPTO_PHASE_10_4_GAP_ANALYSIS.md

## 1. Executive Summary

Cross-validation of Tasks 4.1 (SRP), 4.2 (AES Key Installation), and 4.3 (RSA Provenance) against the Rust implementation (src/session/control_handshake.rs, src/session/control.rs, src/crypto/famatech.rs) and against each other. Build (`cargo build`) succeeds; all 147 unit tests and 5 integration tests pass.

Key finding: multiple Task 4.1 claims are unsupported by instruction-level evidence. The asymmetric u computation claim (client SHA-1(k||B) vs server SHA-1(A||k)) rests on functions 0x10060510/0x10060fa0 that were NEVER disassembled. Rust uses symmetric SHA-1(A||B) for both sides. The integer serialization mismatch claim (Rust to_le_bytes vs big-endian wire) is a FALSE POSITIVE — Rust produces big-endian wire output via pad_bignum_bytes. A real interoperability blocker remains: the RSession 64-byte secret split mapping (which half → enc vs dec) is UNKNOWN from binary evidence, and Rust uses key_material[..32] for both enc and dec.

## 2. Confirmed Findings (with evidence references)

| Finding | Binary Evidence | Rust Source Evidence | Classification |
|---------|----------------|----------------------|----------------|
| SRP-6a client class (k=SHA-1(N||g)) | Client descriptor 0x100ad75c → FUN_10060810; xref chain CONFIRMED | control_handshake.rs:16 RADMIN_SRP_K=3 | INCOMPATIBLE |
| SRP-6a server class | Server descriptor 0x100ad7b4 → FUN_10060fa0 | N/A (Rust uses k=3 for both) | INCOMPATIBLE |
| KDF = SHA-1(S||BE32(0))||SHA-1(S||BE32(1)) = 40 bytes | FUN_10061790 @ shelper.dll | control_handshake.rs:384-400 | COMPATIBLE |
| Session key = first 32 KDF bytes | INFERRED (Task 4.1) | control_handshake.rs:981-982, 1463-1464 | COMPATIBLE |
| All 40 KDF bytes used (32 key + 8 proof) | Task 4.1 LIKELY | control_handshake.rs M1/M2 usage | COMPATIBLE |
| Identity wire UTF-16LE | Task 4.1 CONFIRMED | control_handshake.rs:146-153 encode_identity | COMPATIBLE (wire) |
| Identity hash UTF-8 | Task 4.1 UNKNOWN | control_handshake.rs:275 username.as_bytes() | INTERNAL INCONSISTENCY |
| Integer serialization big-endian wire | Task 4.1 CONFIRMED wire format | control_handshake.rs:288-296 pad_bignum_bytes | COMPATIBLE (Task 4.1 was FALSE POSITIVE) |
| RSA-2048 PKCS#1 v1.5 | FUN_10065ec0/0x10065db0; push $0x1 padding | handshake.rs RSA transport | COMPATIBLE |
| 76-byte plaintext (12-byte header || 64-byte key) | FUN_1006a2b0 client branch | handshake.rs RSA handshake | COMPATIBLE |
| No KDF on RSession path | Complete callee set of FUN_1006a2b0 | handshake.rs direct slice | COMPATIBLE |
| AES-256-CBC, persistent IVs, 0xCC padding, 9-byte trailer | FUN_10069c20/0x10069f90/0x10003b30 | famatech.rs AESCryptor | COMPATIBLE |
| RSA/SRP separation (disjoint primitive sets) | No intra-module xrefs in shelper.dll | Separate negotiators/cipher states | COMPATIBLE |
| RSession_GetKey ≠ control GetKey | 0x1006ba80 vs 0x1006b010 | Separate functions | CONFIRMED separate |

## 3. Inferred Findings

| Inference | Basis | Classification |
|-----------|-------|----------------|
| Session key = first 32 bytes (no transformation) | Rust confirms direct slice; binary doesn't explicitly prove | INFERRED (strong support) |
| Server k externally provided (object +0x20) | Task 4.3 CONFIRMED mechanism; value unknown | INFERRED |
| 64→32+32 split mapping | Binary requires two separate keys; mapping UNKNOWN | INFERRED (mechanism), UNKNOWN (mapping) |

## 4. Unknown Findings

| Unknown | Evidence Gap | Subsystem Affected |
|---------|--------------|-------------------|
| Binary server u computation | FUN_10060510/0x10060fa0 never disassembled | SRP |
| Password encoding in binary | Not traced in shelper.dll | SRP |
| Whether both SRP client/server descriptors instantiate in same session | Server descriptor existence ≠ usage proof | SRP |
| 64→32+32 split point and enc/dec assignment | Consumer call sites not located | AES Key Installation |
| Public exponent value | Imported from caller, not hardcoded | RSA |
| Server private key ultimate origin | Consumer binaries unavailable | RSA |
| Whether server k matches client SHA-1(N||g) | Requires RvROLClient.dll/RvControlSvc.exe tracing | SRP/RSA boundary |

## 5. Contradictions Between Reports

### C1 — Asymmetric u computation (BLOCKING)

**Task 4.1 claim:** Client u = SHA-1(k‖B), Server u = SHA-1(A‖k). Labeled CONFIRMED.

**Explorer verification:** Binary functions 0x10060510 (client S calc) and 0x10060fa0 (server S calc) were NEVER disassembled. CRYPTO_UNRESOLVED_QUESTIONS.md A-iii: "NOT DISASSEMBLED (budget expired)." KEY_EXCHANGE_ANALYSIS.md §6.1: "core 0x10060510: NEVER DISASSEMBLED."

**Rust source:** compute_srp_u (control_handshake.rs:367-382) computes SHA-1(A||B) identically for client (line 850) and server (line 1361) — SYMMETRIC. Internal tests pass (test_full_srp_handshake_success).

**Resolution:** The asymmetric u claim is UNSUPPORTED. It cannot be confirmed from instruction-level evidence. Task 4.1's "CRITICAL INCOMPATIBILITY" warning based on this claim is invalid. Rust's symmetric u is likely correct, but cannot be confirmed without disassembling the binary functions.

### C2 — Integer serialization (FALSE POSITIVE)

**Task 4.1 claim:** Rust uses to_le_bytes() (little-endian) for SRP integers — INCOMPATIBLE.

**Explorer verification:** FALSE POSITIVE. Rust pad_bignum_bytes (control_handshake.rs:288-296) produces big-endian wire serialization, matching the binary wire format.

**Resolution:** No contradiction. Task 4.1 mismatch verdict here is incorrect.

### C3 — Identity encoding internal inconsistency (Rust internal)

**Task 4.1 did not flag:** Wire identity UTF-16LE (encode_identity, control_handshake.rs:146-153) matches binary. But compute_srp_x hashes identity as UTF-8 (username.as_bytes(), line 275) — an internal Rust inconsistency.

**Impact:** If binary hashes UTF-16LE for both identity and password, Rust produces different x → cascading failure (v, A, S, K, M1, M2 all differ).

### C4 — RSession 64→32+32 AES key split (BLOCKING)

**Task 4.2:** Binary requires two separate 32-byte keys (SetKeyEnc/SetKeyDec enforce len==0x20). Split mapping UNKNOWN.

**Rust source:** from_rsession_key (famatech.rs:181-186) uses key_material[..32] for BOTH enc and dec. Bytes [32..64] unused.

**Resolution:** CONFIRMED_MISMATCH. Real interoperability blocker — Rust uses one key for both directions; binary expects two separate keys. Split mapping unknown from binary evidence.

### C5 — Session key byte usage

Task 4.1 marked "first 32 bytes" as INFERRED/LIKELY. Rust confirms direct first-32-bytes usage with no transformation. All 40 KDF bytes used (32 for key, 40 for M1/M2 proofs). This is a confirmation, not a contradiction.

## 6. Rust Implementation Mismatches (Field-by-Field Table)

| Item | Binary | Rust | Verdict | Evidence |
|------|--------|------|---------|----------|
| SRP class | SRP-6a client (k=SHA-1(N||g)) | k=3 (RADMIN_SRP_K) | INCOMPATIBLE | Task 4.1 §3, control_handshake.rs:16 |
| Multiplier k (server) | Externally provided (+0x20) | k=3 | INCOMPATIBLE | Task 4.1, control_handshake.rs:16 |
| u computation | Asymmetric claimed (UNVERIFIED) | Symmetric SHA-1(A||B) | UNKNOWN (binary unverified) | control_handshake.rs:367-382 |
| Identity wire | UTF-16LE | UTF-16LE | COMPATIBLE | Task 4.1 §7, control_handshake.rs:146-153 |
| Identity hash | UTF-16LE (likely) | UTF-8 | INTERNAL INCONSISTENCY | control_handshake.rs:275 |
| Password hash | UNKNOWN | UTF-8 | UNKNOWN | Task 4.1 §7, control_handshake.rs:275 |
| Integer serialization | Big-endian wire | Big-endian wire | COMPATIBLE | Task 4.1 §8 (FALSE POSITIVE), control_handshake.rs:288-296 |
| KDF | SHA-1(S||BE32(0))||SHA-1(S||BE32(1)) = 40B | Same formula | COMPATIBLE | Task 4.1 §10, control_handshake.rs:384-400 |
| Session key | First 32 bytes (likely) | First 32 bytes, no transform | COMPATIBLE | Task 4.1 §10, control_handshake.rs:981-982 |
| RSA modulus | 2048 bits | 2048 bits | COMPATIBLE | Task 4.3 §4, handshake.rs |
| RSA padding | PKCS#1 v1.5 | PKCS#1 v1.5 | COMPATIBLE | Task 4.3 §4, handshake.rs |
| RSA plaintext | 76 bytes (12 header || 64 key) | 76 bytes (12 header || 64 key) | COMPATIBLE | Task 4.2 §4, handshake.rs |
| RSession key → AES | Two separate 32-byte keys | key_material[..32] for both | CONFIRMED_MISMATCH | Task 4.2 §7-8, famatech.rs:181-186 |
| AES mode | AES-256-CBC | AES-256-CBC | COMPATIBLE | Task 4.2 §10, famatech.rs |
| IV handling | Persistent IVs | Persistent IVs | COMPATIBLE | Task 4.2 §9, famatech.rs |
| Padding | 0xCC | 0xCC | COMPATIBLE | Task 4.2 §10, famatech.rs |
| Trailer | 9-byte unkeyed (folded MD5 + pad len) | 9-byte unkeyed | COMPATIBLE | Task 4.2 §10, famatech.rs |
| No KDF on RSession path | No hash calls | No KDF | COMPATIBLE | Task 4.2 §12, handshake.rs |

## 7. False-Positive / Overconfident Claims Requiring Correction

| Claim | Original Verdict | Corrected Verdict | Reason |
|-------|-----------------|-------------------|--------|
| Asymmetric u computation | CONFIRMED (CRITICAL INCOMPATIBILITY) | UNKNOWN / UNSUPPORTED | Binary functions never disassembled |
| Integer serialization mismatch | INCOMPATIBLE | COMPATIBLE | Rust produces big-endian wire output |
| Task 4.1 "CRITICAL INCOMPATIBILITY" overall | BLOCKING | NOT BLOCKING (based on unverified C1) | Asymmetric u unverified |

## 8. Remaining Blockers to Interoperability

| Blocker | Severity | Evidence | Subsystem |
|---------|----------|----------|-----------|
| RSession 64→32+32 split mapping | CRITICAL | Two separate keys required in binary; Rust uses one key for both | AES Key Installation |
| Server u computation unverified | HIGH | Binary functions never disassembled | SRP |
| Password encoding in binary | HIGH | Not traced; consumer binaries unavailable | SRP |
| Whether both SRP client/server paths execute in same session | MEDIUM | Server descriptor existence ≠ usage proof | SRP |
| Public exponent value | MEDIUM | Imported from caller; not hardcoded | RSA |
| Server private key origin | MEDIUM | Consumer binaries unavailable | RSA |

## 9. Prioritized Next Investigations

1. **Disassemble FUN_10060510 and FUN_10060fa0** in shelper.dll to resolve C1 (asymmetric u). Highest priority — resolves whether Rust symmetric u is correct.
2. **Trace consumer call sites between GetKey and SetKeyEnc/SetKeyDec** in RvROLClient.dll/RvControlSvc.exe to resolve 64→32+32 split mapping (C4). Requires consumer binaries not available locally.
3. **Trace password processing** outside shelper.dll to resolve password encoding (C3).
4. **Determine if both SRP client and server descriptors instantiate in a live session** (C2).
5. **Confirm public exponent value** actually supplied by client in observed sessions.

---

**EVIDENCE_REFS** — All analysis based on:
- docs/CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md (Task 4.1, SME)
- docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md (Task 4.2, SME)
- docs/CRYPTO_RSA_KEY_PROVENANCE.md (Task 4.3, SME)
- src/session/control_handshake.rs (Rust source, read-only)
- src/session/handshake.rs (Rust source, read-only)
- src/crypto/famatech.rs (Rust source, read-only)
- Build: cargo build succeeds; 147 unit + 5 integration tests pass

**COMPLIANCE:** Task 4.4 cross-validation complete. All 5 mandatory review areas addressed: SRP revalidation (C1), password/identity (C3), KDF/session-key (C5), AES key installation (C4), RSA provenance (confirmed compatible). Reviewer challenged unsupported claims (C1, C2) and verified evidence supports conclusions.

STOP CONDITION: Task 4.4 complete. Do not dispatch Task 4.5 without explicit authorization.
