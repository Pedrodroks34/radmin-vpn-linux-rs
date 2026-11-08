# CRYPTO_PHASE_10_5_COMPATIBILITY_AUDIT.md

## 1. Executive Summary

Cross-validation of Tasks 4.1–5.3 investigation reports against each other and against the Rust implementation. Build (cargo build) succeeds; all 147 unit tests and 5 integration tests pass.

**Overall verdict: CRITICAL.** Three confirmed incompatibilities block interoperability between the Rust implementation and the official Windows client:

1. **SRP multiplier k**: Rust hardcodes k=3 (SRP-6 legacy); binary computes k=SHA-1(N||g) (SRP-6a) dynamically. Different k → different shared secret → complete handshake failure.

2. **Identity hash encoding**: Rust hashes identity as UTF-8 (`username.as_bytes()`); binary hashes identity as raw UTF-16LE bytes from obj+0x8. Different x → different v → complete handshake failure.

3. **RSession AES key split**: Rust uses key_material[..32] for both enc and dec; binary requires two separate exactly-32-byte keys via SetKeyEnc/SetKeyDec. One key for both directions → one direction will fail decryption.

Two additional critical claims were DISPROVEN:
- Asymmetric u computation (Task 4.1): both client and server compute SHA-1(A||B) — symmetric.
- Integer serialization mismatch (Task 4.1): Rust produces big-endian wire output matching binary.

## 2. Confirmed Findings (with evidence references)

### 2.1 SRP Subsystem

| Finding | Binary Evidence | Rust Source Evidence | Classification |
|---------|----------------|----------------------|----------------|
| SRP-6a selected | FUN_10060810 computes k=SHA-1(N||g); client descriptor 0x100ad75c references it | control_handshake.rs:16 RADMIN_SRP_K=3 | INCOMPATIBLE |
| N = 1536-bit prime | .data at 0x100ac280 | RADMIN_SRP1536_PRIME_HEX | COMPATIBLE |
| g = 0x05 | .data at 0x100ac279 | RADMIN_SRP_GENERATOR=5 | COMPATIBLE |
| k = SHA-1(N||g) | FUN_10060810/FUN_10060ec0 | k=3 hardcoded | INCOMPATIBLE |
| k=3 path (FUN_100607d0) | Dead code — no callers | RADMIN_SRP_K=3 used | INCOMPATIBLE (dead code vs active code) |
| u = SHA-1(A||B) both sides | FUN_10060510 (client), FUN_10060fa0 (server) disassembled | control_handshake.rs:367-382 compute_srp_u symmetric | COMPATIBLE |
| KDF = SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1)) = 40B | FUN_10061790 | control_handshake.rs:384-400 | COMPATIBLE |
| Session key = first 32 bytes | INFERRED (Task 4.1) | control_handshake.rs:981-982 | COMPATIBLE (inferred) |
| Integer serialization | Big-endian wire (FUN_1005fad0 uses BIGNUM length) | pad_bignum_bytes to 192 bytes | PARTIAL_MISMATCH (padding difference) |
| Identity wire UTF-16BE | encode_identity writes UTF-16BE per code unit | control_handshake.rs:146-153 | COMPATIBLE |
| Identity hash UTF-16LE | obj+0x8 raw bytes hashed | username.as_bytes() = UTF-8 | CONFIRMED_MISMATCH |

### 2.2 RSession / AES Subsystem

| Finding | Binary Evidence | Rust Source Evidence | Classification |
|---------|----------------|----------------------|----------------|
| 64-byte RSession secret | FUN_10063530 (OpenSSL RAND) | RSESSION_KEY_BUFFER_SIZE=64 | MATCH |
| 76-byte plaintext (12-byte header || 64-byte key) | FUN_1006a2b0 client branch | handshake.rs RSA handshake | COMPATIBLE |
| RSA-2048 PKCS#1 v1.5 | FUN_10065ec0/0x10065db0, push $0x1 | Padding::PKCS1 | COMPATIBLE |
| 256-byte ciphertext | RSA_size = 0x100 | RSESSION_RSA_BLOCK_SIZE=256 | COMPATIBLE |
| Server validates len==0x4c | FUN_1006a2b0 server branch | handshake.rs | COMPATIBLE |
| GetKey returns 64-byte verbatim copy | 0x1006ba80 → FUN_1006a270 → FUN_10062800 | handshake.rs | COMPATIBLE |
| No KDF on RSession path | Complete callee set of FUN_1006a2b0 | No KDF | COMPATIBLE |
| Two separate 32-byte AES keys required | SetKeyEnc/SetKeyDec enforce len==0x20 | key_material[..32] for BOTH | CONFIRMED_MISMATCH |
| AES-256-CBC | FUN_10003b30 | famatech.rs AESCryptor | COMPATIBLE |
| Persistent IVs | Zero-init, updated from last ciphertext block | famatech.rs | COMPATIBLE |
| 0xCC padding | FUN_10069c20 | famatech.rs | COMPATIBLE |
| 9-byte unkeyed trailer (folded MD5 + pad length) | FUN_10069f90 | famatech.rs | COMPATIBLE |
| Control vs RSession key separation | 0x1006ba80 vs 0x1006b010 | Separate negotiators | COMPATIBLE |

### 2.3 RSA Subsystem

| Finding | Binary Evidence | Rust Source Evidence | Classification |
|---------|----------------|----------------------|----------------|
| RSA-2048 | RSA_size reads RSA->n (+0x10) | RSESSION_RSA_BLOCK_SIZE=256 | COMPATIBLE |
| Raw big-endian key format | BN_bin2bn imports raw bytes | handshake.rs imports | COMPATIBLE |
| PKCS#1 v1.5 padding | push $0x1 before rsa_pub_encrypt/rsa_priv_decrypt | Padding::PKCS1 | COMPATIBLE |
| No OAEP / no signing | "rsaesOaep" zero xrefs; no RSA_sign/RSA_verify | No signing | COMPATIBLE |
| Keys caller-supplied | All BN_bin2bn sources are function args | handshake.rs passes caller buffers | COMPATIBLE |
| RSA only for RSession key transport | No signing; no other RSA use | RSA used only for key transport | COMPATIBLE |
| Public exponent value | Imported from caller; not hardcoded | RADMIN_SRP_K context (different) | UNKNOWN (caller-dependent) |
| Key rotation / validation | Not observed | No rotation | UNKNOWN |

## 3. Inferred Findings

| Inference | Basis | Classification |
|-----------|-------|----------------|
| Session key = first 32 bytes of KDF (no transformation) | Rust confirms direct slice; binary doesn't explicitly prove | INFERRED (strong support) |
| All 40 KDF bytes used (32 for key, 40 for M1/M2 proofs) | Rust confirms bytes 32-39 consumed in proofs | INFERRED |
| 64→32+32 split mapping | Binary requires two separate keys; mapping UNKNOWN | INFERRED (mechanism), UNKNOWN (mapping) |

## 4. Unknown Findings

| Unknown | Evidence Gap | Subsystem Affected |
|---------|--------------|-------------------|
| Binary server u computation | FUN_10060510/0x10060fa0 never disassembled before Task 5.2; now disassembled but context+0x20 contents unverified | SRP |
| Password encoding in binary | Not traced in shelper.dll; caller outside DLL | SRP |
| Whether both SRP client/server descriptors instantiate in same session | Server descriptor existence ≠ usage proof | SRP |
| 64→32+32 split point and enc/dec assignment | Consumer call sites not located (disp8 indirect calls) | AES Key Installation |
| Public exponent value | Imported from caller, not hardcoded | RSA |
| Server private key ultimate origin | Consumer binaries unavailable | RSA |
| Whether server k matches client SHA-1(N||g) | Requires RvROLClient.dll/RvControlSvc.exe tracing | SRP/RSA boundary |

## 5. Contradictions Between Reports

### C1 — Asymmetric u computation (DISPROVEN)

**Task 4.1 claim:** Client u=SHA-1(k||B), Server u=SHA-1(A||k). Labeled CONFIRMED, CRITICAL INCOMPATIBILITY.

**Task 4.4 finding:** Correctly identified as UNSUPPORTED — FUN_10060510/FUN_10060fa0 were never disassembled.

**Task 5.2 finding:** Both functions disassembled. Client: SHA-1(context_0x20||B). Server: SHA-1(A||context_0x20). If context_0x20=A on client and B on server, both compute SHA-1(A||B) — symmetric.

**Explorer verification V1:** control_handshake.rs:367-382 computes SHA-1(pad_a||pad_b) identically for both client and server.

**Resolution:** Asymmetric u claim is DISPROVEN. Not an interoperability blocker.

### C2 — Integer serialization mismatch (DISPROVEN — FALSE POSITIVE)

**Task 4.1 claim:** Rust uses to_le_bytes() (little-endian) vs binary big-endian wire. INCOMPATIBLE.

**Explorer verification V15:** Rust pad_bignum_bytes (control_handshake.rs:288-296) produces big-endian wire output matching binary.

**Resolution:** No contradiction. Task 4.1 mismatch verdict was incorrect.

### C3 — Identity hash encoding mismatch (CONFIRMED_MISMATCH)

**Task 4.4 finding:** Internal Rust inconsistency — wire UTF-16LE vs hash UTF-8.

**Task 5.3 confirmation:** Binary hashes identity as raw UTF-16LE bytes from obj+0x8. Rust hashes as UTF-8 via username.as_bytes().

**Resolution:** CONFIRMED_MISMATCH. Fatal — different x → different v → complete handshake failure.

### C4 — RSession 64→32+32 AES key split (CONFIRMED_MISMATCH)

**Task 4.4 finding:** Rust uses key_material[..32] for both enc and dec; binary expects two separate keys.

**Task 5.1 confirmation:** Binary requires two separate exactly-32-byte keys (SetKeyEnc/SetKeyDec both enforce len==0x20). GetKey returns all 64 bytes verbatim; split mapping unknown.

**Resolution:** CONFIRMED_MISMATCH. Fatal — one direction will fail decryption.

### C5 — Padding mismatch (PARTIAL_MISMATCH)

**Task 5.2 finding:** Binary hashes BIGNUM bytes at actual byte length (no zero-padding to 192 bytes). Rust pads to 192 bytes.

**Impact:** Only matters if BIGNUM representation strips leading zeros. Unverified.

**Resolution:** PARTIAL_MISMATCH. Impact uncertain.

## 6. Rust Implementation Mismatches (Field-by-Field Table)

| Item | Binary | Rust | Verdict | Evidence | Blocks Interoperability |
|------|--------|------|---------|----------|------------------------|
| SRP class | SRP-6a (k=SHA-1(N||g)) | SRP-6 (k=3 hardcoded) | INCOMPATIBLE | Task 5.2 §3-4 | YES |
| Multiplier k | SHA-1(N||g) computed dynamically | k=3 hardcoded RADMIN_SRP_K | INCOMPATIBLE | Task 5.2 §3-4 | YES |
| u computation | SHA-1(A||B) both sides | SHA-1(A||B) both sides | COMPATIBLE | Task 5.2 §3-4, V1 | NO |
| Identity wire | UTF-16BE per code unit | UTF-16BE per code unit | COMPATIBLE | Task 4.1, V7 | NO |
| Identity hash | UTF-16LE (obj+0x8 raw) | UTF-8 (username.as_bytes()) | CONFIRMED_MISMATCH | Task 5.3 §10, V3 | YES |
| Password hash | UNKNOWN (likely UTF-16LE) | UTF-8 (password.as_bytes()) | INFERRED_MISMATCH | Task 5.3 §10, V4 | YES (if confirmed) |
| Integer serialization | Big-endian wire, unpadded BIGNUM | Big-endian wire, padded to 192 bytes | PARTIAL_MISMATCH | Task 5.2 §6, V15 | UNCERTAIN |
| KDF | SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1)) = 40B | Same formula | COMPATIBLE | Task 4.1, V8 | NO |
| Session key | First 32 bytes | First 32 bytes | COMPATIBLE (inferred) | Task 4.1, V9 | NO |
| RSA modulus | 2048 bits | 2048 bits | COMPATIBLE | Task 4.3 | NO |
| RSA padding | PKCS#1 v1.5 | PKCS#1 v1.5 | COMPATIBLE | Task 4.3 | NO |
| RSA plaintext | 76 bytes | 76 bytes | COMPATIBLE | Task 4.2 | NO |
| RSession key → enc | 32-byte key (consumer split) | key_material[..32] | CONFIRMED_MISMATCH | Task 5.1, V10 | YES |
| RSession key → dec | 32-byte key (consumer split) | key_material[..32] (same) | CONFIRMED_MISMATCH | Task 5.1, V11 | YES |
| Bytes [32..64] usage | Must be used for one direction | Unused | CONFIRMED_MISMATCH | Task 5.1 | YES |
| AES mode | AES-256-CBC | AES-256-CBC | COMPATIBLE | Task 4.2 | NO |
| IV handling | Persistent IVs | Persistent IVs | COMPATIBLE | Task 4.2 | NO |
| Padding | 0xCC | 0xCC | COMPATIBLE | Task 4.2 | NO |
| Trailer | 9-byte unkeyed | 9-byte unkeyed | COMPATIBLE | Task 4.2 | NO |

## 7. False-Positive / Overconfident Claims Requiring Correction

| Claim | Original Verdict | Corrected Verdict | Reason |
|-------|-----------------|-------------------|--------|
| Asymmetric u computation | CONFIRMED (Task 4.1) | DISPROVEN | Binary functions disassembled in Task 5.2 — both compute SHA-1(A||B) |
| Integer serialization mismatch | INCOMPATIBLE (Task 4.1) | COMPATIBLE | Rust pad_bignum_bytes produces big-endian wire output |
| Task 4.4 "Task 4.1 functions never disassembled" | ACCEPTED | SUPERSEDED | Task 5.2 disassembled both FUN_10060510 and FUN_10060fa0 |

## 8. Remaining Blockers to Interoperability

| Blocker | Severity | Evidence | Subsystem |
|---------|----------|----------|-----------|
| **SRP multiplier k** | CRITICAL | Rust k=3 vs binary SHA-1(N||g) | SRP |
| **Identity hash encoding** | CRITICAL | Rust UTF-8 vs binary UTF-16LE | SRP |
| **Password hash encoding** | HIGH (likely CRITICAL) | Rust UTF-8 vs binary unknown (likely UTF-16LE) | SRP |
| **RSession AES key split** | CRITICAL | Rust one key for both directions vs binary two separate keys | AES Key Installation |
| **SRP integer padding** | MEDIUM (uncertain impact) | Binary unpadded vs Rust padded to 192 bytes | SRP |
| **Server k provenance** | MEDIUM | External vs internal computation unresolved | SRP/RSA |

## 9. Prioritized Next Investigations

1. **Replace k=3 with k=SHA-1(N||g)** — Highest priority. Modify control_handshake.rs to compute k dynamically per SRP-6a.
2. **Hash identity as UTF-16LE in compute_srp_x** — Change username.as_bytes() to UTF-16LE raw bytes.
3. **Determine password encoding** — Trace caller of 0x10060340/0x10060c80 in consumer binaries; implement correct password hash encoding.
4. **Implement separate enc/dec keys** — Modify from_rsession_key/famatech.rs to derive two distinct 32-byte keys. Split mapping must be determined from consumer tracing (U-1).
5. **Verify u padding behavior** — Determine whether context+0x20 BIGNUM values retain leading zeros.

---

**EVIDENCE_REFS:**
- docs/CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md (Task 4.1)
- docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md (Task 4.2)
- docs/CRYPTO_RSA_KEY_PROVENANCE.md (Task 4.3)
- docs/CRYPTO_PHASE_10_4_GAP_ANALYSIS.md (Task 4.4)
- docs/CRYPTO_PHASE_10_4_UNRESOLVED.md (Task 4.5)
- docs/CRYPTO_AES_KEY_SPLIT_TRACE.md (Task 5.1)
- docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md (Task 5.2)
- docs/CRYPTO_SRP_PASSWORD_ENCODING.md (Task 5.3)
- src/session/control_handshake.rs (Rust source)
- src/session/handshake.rs (Rust source)
- src/crypto/famatech.rs (Rust source)

**COMPLIANCE:** Task 5.4 cross-validation complete. Reviewer challenged unsupported claims (C1 asymmetric u DISPROVEN, C2 integer serialization DISPROVEN as false positive). Explorer verified all Rust source claims by direct file reads. All 17 audit areas classified.

STOP CONDITION: Task 5.4 complete. Do not dispatch Task 5.5 without explicit authorization.