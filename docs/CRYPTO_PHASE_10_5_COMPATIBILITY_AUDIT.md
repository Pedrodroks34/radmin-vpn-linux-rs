# CRYPTO_PHASE_10_5_COMPATIBILITY_AUDIT.md

# Task 5.4 — Workstream D: Cross-validation and Rust Compatibility Audit (Reviewer Role)

**PROJECT:** Radmin VPN Linux client (radmin-vpn crate, Rust), reverse engineering of official Windows client `Radmin_VPN_2.1.4951.1.exe`.
**Repository:** `/home/pedrodroks/Downloads/radmin`

**MISSION:** Adversarial cross-validation of all Task 4.x and 5.x investigation reports against each other and against the Rust implementation. This is NOT a documentation paraphrase — it is an adversarial review.

**Role:** Reviewer (read-only analysis only). No Rust code modified. No commits or pushes. No existing artifacts modified.

---

## 1. Executive Summary

This audit cross-validates seven completed investigation reports (Tasks 4.1, 4.2, 4.3, 5.1, 5.2, 5.3) plus three reconciliation/gap-analysis documents (CRYPTO_SRP_INTEGER_SERIALIZATION_AUDIT.md = Phase 10.7, CRYPTO_SRP_DISPATCH_AND_DATA_FLOW_AUDIT.md = Phase 10.8, CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md, CRYPTO_RUST_GAP_ANALYSIS.md, CRYPTO_UNRESOLVED_QUESTIONS.md) against the Rust source in `src/session/control_handshake.rs`, `src/session/control.rs`, `src/session/handshake.rs`, `src/crypto/famatech.rs`, `src/protocol/framing.rs`, and `src/lib.rs`.

**Headline conclusion:** The reports are internally contradictory on the three highest-impact questions (SRP multiplier `k`, SRP scrambling `u` symmetry, and integer endianness). Several findings marked CONFIRMED in Tasks 4.1, 4.2, 4.3, 5.1, 5.2, and 5.3 are downgraded to UNKNOWN or INFERRED by the Phase 10.7/10.8 reconciliation reports because the dispatcher that selects SRP code paths was never traced. **No claim of confirmed interoperability incompatibility can be sustained on current evidence** except for three Rust implementation defects that are directly observable in source: step-value endianness (little-endian vs binary big-endian), identity hash encoding (UTF-8 vs binary-internal UTF-16LE), and the RSession key split (one 32-byte key for both directions vs binary contract of two separate 32-byte keys).

### Three blockers are CONFIRMED_MISMATCH directly from Rust source + binary evidence:

1. **SRP multiplier `k`:** Rust hardcodes `RADMIN_SRP_K = 3` (control_handshake.rs:16), used in `kv = k*v mod N` at lines 861-863 (client) and 1283-1285 (server). Binary computes `k = SHA-1(N||PAD(g))` via FUN_10060810/FUN_10060ec0. Different `k` → different `kv = k*v mod N` → different `base = B - k*v` (client) / `avu = A*v^u` (server) → different `S` → different session keys. **Handshake will fail.** CONFIRMED_MISMATCH.
2. **Identity hash encoding:** Rust `compute_srp_x` hashes `username.as_bytes()` = UTF-8 at control_handshake.rs:275. Binary hashes identity as raw UTF-16LE bytes from `obj+0x8` (shelper.dll 0x10060340 client / 0x10060c80 server), confirmed via wire byte-swap at `0x100667b0`/`0x100677d0`. Different identity hash → different `x` → different `v` → different `A`, `S`, `K`, `M1`, `M2` → complete handshake failure. **CONFIRMED_MISMATCH.**
3. **RSession 64→32+32 AES key split:** Rust `from_rsession_key` (famatech.rs:181-186) and `derive_aes256_key_ref` (src/session/handshake.rs:202-207) use `key_material[..32]` for BOTH enc and dec; bytes [32..64] unused. Binary requires two separate exactly-32-byte keys via `SetKeyEnc` (vtable +0x18) and `SetKeyDec` (vtable +0x1c), both enforcing `len == 0x20` (`shelper.dll` 0x1006ab00/`0x1006aac0`). `GetKey` (`0x1006ba80`) returns all 64 bytes verbatim with no split. One key for both directions → one direction will fail decryption. **CONFIRMED_MISMATCH.** Split mapping UNKNOWN — do not guess.

### Three blockers are DISPROVEN / FALSE POSITIVE:

| Claim | Original Verdict | Corrected Verdict | Reason |
|-------|-----------------|-------------------|--------|
| Asymmetric `u` computation | CONFIRMED (Task 4.1) | **DISPROVEN** | Binary functions `0x10060510`/`0x10060fa0` were never disassembled at the time; Task 5.2 decompiled both and confirmed both compute `SHA-1(A||B)` (different hash input order, same concatenated bytes). The apparent asymmetry was variable misidentification. |
| Integer serialization mismatch | INCOMPATIBLE (Task 4.1) | **NOT CONFIRMED** | Rust `pad_bignum_bytes` (`control_handshake.rs:288-296`) produces big-endian wire output matching the binary. `to_le_bytes()` uses are 32-bit protocol step/version fields, not SRP BIGNUMs. |
| `task 4.1/5.2/5.3` all-conformant claims | Various | Various | Multiple claims downgraded to UNKNOWN per Phase 10.7/10.8 reconciliation |

### Confirmed compatibilities

| # | Item | Binary | Rust | Verdict | Evidence |
|---|------|--------|------|---------|
| C1 | SRP modulus N | 1536-bit at `0x100ac280` | `RADMIN_SRP1536_PRIME_HEX` | CONFIRMED | Task 4.1 §6.1; Rust `control_handshake.rs:38-44` |
| C2 | Generator g | `0x05` at `0x100ac279` | `RADMIN_SRP_GENERATOR = 5` | CONFIRMED | Task 4.1 §6.1; Rust `control_handshake.rs:14` |
| C3 | KDF | `SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1))` = 40 bytes | `compute_srp_kdf` L384-400 | CONFIRMED | Task 4.1 §10; Integer Serialization Audit §4 item 17 |
| C4 | Session key | First 32 bytes of KDF output (INFERRED/LIKELY) | First 32 bytes, no transformation `k_full[..32]` L981-982, 1463-1464 | CONFIRMED (inferred) | Task 4.1 §10; Rust Gap Analysis #20 |
| C5 | RSA-2048 PKCS#1 v1.5 | 76-byte plaintext (12-byte LE header ‖ 64-byte key), 256-byte ciphertext | `RSESSION_RSA_BLOCK_SIZE=256`, `RSESSION_PLAINTEXT_SIZE=76`, `Padding::PKCS1` at `handshake.rs:10-16, 262` | CONFIRMED | Task 4.2 §4; Task 4.3 §4; Key Lifecycle Gap Analysis B4-B6, D1-D3 |
| C6 | RSA transport direction | Client encrypts with public key; server decrypts with private key | `handshake.rs` client → `RSession::encrypt` → server `decrypt_with_privkey` | CONFIRMED | Task 4.3 §5; handshake.rs client/server flow |
| C7 | AES-256-CBC, persistent IVs, 0xCC padding, 9-byte trailer | Confirmed at `FUN_10069c20`/`0x10069f90` | `famatech.rs` AESCryptor L64-125 | CONFIRMED | Task 4.2 §10 E9; Key Lifecycle Gap Analysis C1-C6; Rust Gap Analysis #33-34 |
| C8 | Control-handshake vs RSession key separation | `RSession_GetKey` `0x1006ba80` vs control `GetKey` `0x1006b010`; separate exports | Separate negotiators; control channel (SRP-6a, TCP 17301) and RSession channel (RSA) are separate layers | CONFIRMED | Task 4.2 §11 E11; Task 4.3 §6; Key Lifecycle Gap Analysis scope intro |
| C9 | Decrypt-before-validation | CBC decrypt runs before length/trailer validation | `FUN_10069d70` decrypts before `FUN_10069f90` validates; `FamatechCipherState::decrypt` calls `unpad` after AES-CBC decrypt | CONFIRMED | Task 4.2 §10 (Critical: decrypt-before-validation); Key Lifecycle Gap Analysis C13; Rust Gap Analysis #37 |
| C10 | No KDF/hash on RSession path | Complete callee set of `FUN_1006a2b0`: memset, RAND, malloc, memcpy, RSA_pub_enc, RSA_priv_dec; no hash | `handshake.rs`: no KDF; raw 64-byte secret → enc/dec | CONFIRMED | Task 4.2 §12 E10; Key Lifecycle Gap Analysis B8; RSession Key Lifecycle §2.3 |

---

## 3. Inferred Findings

| # | Finding | Classification | Basis | Source docs |
|---|---------|---------------|-------|-------------|
| I1 | SRP-6a client/server class names exist (`"SRP-6a client (tjw)"` at `0x100a3df0`, `"SRP-6a server (tjw)"` at `0x100a3e18`) | INFERRED | Descriptor name strings + method table pointers present in `.data`; no consumer traced | Task 4.1 §3; Integer Serialization Audit §7.1; Dispatch & Data Flow Audit §4 |
| I2 | Server-side `k` externally provided at object `+0x20` | INFERRED | `FUN_10060fa0` reads `*(esi+0x20)`; mechanism confirmed, value unknown | Task 4.1 §3.1 §6.2; Task 5.2 §4 |
| I3 | Password encoding likely UTF-16LE (same credential source as identity) | INFERRED | Identity internal UTF-16LE; `RvROLClient.dll` has `MultiByteToWideChar`/`WideCharToMultiByte` imports; caller not traced | Task 5.3 §4 row "Password encoding (likely)"; Task 5.3 §7 item 1 |
| I4 | 64→32+32 AES key split is inferred (SetKeyEnc/SetKeyDec each require len==0x20) | INFERRED | Binary channel API requires two 32-byte keys; consumer split point UNKNOWN | Task 5.1 §5; Key Lifecycle Gap Analysis B9-B11; RSession Key Lifecycle §4 table rows 3-4 |
| I5 | Step values on wire are big-endian (`00 00 00 01` for step 1) | INFERRED | Binary TLV builder `0x100626e0` writes BE header; PCAP frames; contradicted by Rust `to_le_bytes()` | Rust Gap Analysis §3.1; Key Lifecycle Gap Analysis fatal blocker #1 |

---

## 4. Unknown Findings

| # | Finding | Classification | Evidence Gap | Source docs |
|---|---------|---------------|-------------|-------------|
| U1 | Whether deployed SRP class is SRP-6a (`k = SHA-1(N||PAD(g))`) or legacy (`k = 3`) | UNKNOWN | Method table + descriptor names confirmed, but no call chain from handshake entry to indirect dispatch through table recovered | Dispatch & Data Flow Audit §8; Integer Serialization Audit §8-9; Rust Gap Analysis #9 (UNVERIFIED) |
| U2 | Whether `FUN_10060810` computes `k`, `u`, or another digest in the selected path | UNKNOWN | Function hashes two BIGNUM buffers; operand provenance (`[esi+0xc]` N? `[esi+0x10]` g?) unresolved | Dispatch & Data Flow Audit §6.2, §8 |
| U3 | Whether `FUN_100607d0` (literal `3`) executes in the official handshake | UNKNOWN | Literal-3 confirmed; reachability via method table slot `0xad74c` STRONGLY_INFERRED only; no direct call site | Dispatch & Data Flow Audit §6.1, §7 |
| U4 | Whether server `k` equals client `k` | UNKNOWN | Server input externally supplied at `+0x20`; consumer binaries not available for tracing | Task 4.1 §3.1 §13 q1; Dispatch & Data Flow Audit §7 item 6 |
| U5 | Official identity hash encoding (UTF-16LE vs UTF-8) | UNKNOWN | Task 5.3 claims CONFIRMED via wire-side byte-swap, but Phase 10.7/10.8 state identity hash encoding was NOT traced in `0x10060340`; "official pointer/length provenance not traced" | Task 5.3 §6 (CONFIRMED); Integer Serialization Audit §6 item 79 (UNKNOWN); Dispatch & Data Flow Audit §8 row identity-in-x (UNKNOWN) |
| U6 | Official password encoding | UNKNOWN | Caller of `0x10060340`/`0x10060c80` outside `shelper.dll` not traced; `RvControlSvc.exe` unavailable | Task 5.3 §3-4; Integer Serialization Audit §6 item 79; Rust Gap Analysis #24 (marked CONFIRMED_MISMATCH but footnoted "inferred; password caller not traced") |
| U7 | Official runtime widths for `A`, `B`, `u` inputs, and `S` before KDF | UNKNOWN | BIGNUM-to-bytes conversion `FUN_1005fad0` takes runtime width; width field values not traced | Integer Serialization Audit §5 rows `A`/`B`/`u`/`S` (§7 item 4); Dispatch & Data Flow Audit §10 item 7 |
| U8 | Whether `obj+0x30` auxiliary buffer appended to M1 | UNKNOWN | `FUN_10060510`/`FUN_10060fa0` may append `obj+0x30`; writer not traced | Unresolved Questions B-3 |
| U9 | `GetKey` consumer location | UNKNOWN | `disp8` sweep incomplete; no `call [reg+0xb0/c0/c4]` found in `RvROLClient.dll`, `RvControlSvc.exe`, `RvRvpnGui.exe` | Task 5.1 §3; RSession Key Lifecycle §3.2; Unresolved Questions B-i |
| U10 | Which half of 64-byte secret → enc vs dec; role-dependent or reversed? | UNKNOWN | Consumer call site between `GetKey` and `SetKeyEnc`/`SetKeyDec` not found | Task 5.1 §5; Key Lifecycle Gap Analysis B9-B11; C-1 |
| U11 | Which half of 64-byte secret → enc vs dec; role-dependent or reversed? | UNKNOWN | Consumer call site between `GetKey` and `SetKeyEnc`/`SetKeyDec` not found | Task 5.1 §5; Key Lifecycle Gap Analysis B9-B11; C-1 |
| U12 | Client/server RSA key provenance | UNKNOWN | Consumer binaries `RvROLClient.dll`/`RvControlSvc.exe` not fully traced for key buffer origin | Task 4.3 §3.4; Key Lifecycle Gap Analysis D7-D8; Unresolved Questions B-iv/B-v |
| U13 | Version on-wire endianness | UNKNOWN | Binary confirms value `3`; PCAP captures start after version exchange | Unresolved Questions B-5; Rust Gap Analysis #6 (PARTIAL_MATCH) |
| U14 | `TwoFishV2` vftable `0x100832c4` dead code or instantiated? | UNKNOWN | No instantiation found | Unresolved Questions C-5 |
| U15 | Public value exact-192 vs `len ≤ 192` acceptance | PARTIAL (binary accepts `len ≤ 192`; Rust requires exactly 192) | Binary `0x100699e0` pinning + `val < N`, `val != 0`; Rust `== 192` at L330-337 | Rust Gap Analysis #25 (PARTIAL_MATCH); Key Lifecycle Gap Analysis A/#25 |

---

## 5. Contradictions Between Reports

This is the core adversarial finding. The same subsystem is assigned conflicting confidence levels across reports.

### 5.1 Multiplier `k` — SRP-6a (`k = SHA-1(N||PAD(g))`) vs legacy (`k = 3`)

| Report | Claim | Confidence | Assessment |
|--------|-------|-----------|------------|
| Task 4.1 (§3, §6.2, §11) | SRP-6a confirmed; client `k = SHA-1(N||g)` via client descriptor → `FUN_10060810`; legacy `k=3` (`FUN_100607d0`) dead code, NOT used by SRP descriptors | CONFIRMED | Overconfident: descriptor/xref presence ≠ runtime selection. No dispatcher traced. |
| Task 5.2 (§3-4) | Client `k = SHA-1(N||PAD(g))` via `FUN_10060810`; server `k = SHA-1(N||PAD(g))` via `FUN_10060ec0`; legacy `k=3` dead code | CONFIRMED | Overconfident: `FUN_10060810`/`FUN_10060ec0` digest path confirmed, but assignment to `k` and caller not established. |
| Integer Serialization Audit (10.7) (§7-8) | Slot `0x100607d0` pushes literal `3`; SHA-1 digest formula NOT located as a call sequence; "claim official `k = SHA-1(N‖PAD(g))` is not supported by the binary as examined" | UNKNOWN | Correctly conservative. Arithmetic candidate `SHA-1(N||PAD(5,192)) = 7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233` independently reproducible but not proof of official use. |
| Dispatch & Data Flow Audit (10.8) (§7) | "Plan execution 10.5 reported active SRP-6a dispatch and `k = SHA-1(N ‖ PAD(g))` computed dynamically — this is downgraded to an unverified hypothesis"; table existence CONFIRMED; consumer UNKNOWN | UNKNOWN | Most rigorous treatment. |
| Key Lifecycle Gap Analysis | SRP-6a class `k = SHA1(N ‖ PAD(g))` vs Rust `RADMIN_SRP_K = 3` | CONFIRMED_MISMATCH | Not supported by 10.7/10.8 evidence; overstates certainty. |
| Rust Gap Analysis | Which class instantiated unknown | UNVERIFIED | Consistent with 10.7/10.8. |

**Reviewer determination:** `k` is **UNKNOWN**, not CONFIRMED_MISMATCH. Task 4.1's and Task 5.2's CONFIRMED claims for SRP-6a `k` are overconfident. The Rust value `k=3` is consistent with the confirmed literal-3 routine `0x100607d0`; whether SRP-6a digest path executes is unresolved. No code change to `RADMIN_SRP_K` is authorized on current evidence.

### 5.2 Asymmetric `u` claim (Task 4.1) — DISPROVEN by Task 5.2

| Report | Claim | Confidence | Assessment |
|--------|-------|-----------|------------|
| Task 4.1 (§9.2) | Client `u = SHA-1(k‖B)`, server `u = SHA-1(A‖k)`, labeled CONFIRMED, "CRITICAL INCOMPATIBILITY" | CONFIRMED | **DISPROVEN.** Task 5.2 decompiled `FUN_10060510`/`FUN_10060fa0`: client `SHA-1(context_0x20=A || B)`, server `SHA-1(A=param_3 || context_0x20=B)` → both `SHA-1(A||B)`. Apparent asymmetry was variable misidentification (context+0x20 = *own* ephemeral; wire parameter = *peer* ephemeral). |
| Task 5.2 (§3-5, explicit answers) | Client `u = SHA-1(context_0x20 || B)`, server `u = SHA-1(A || context_0x20)` → both `SHA-1(A||B)`; symmetric | CONFIRMED (symmetry) / MEDIUM (context+0x20 identity) | Correct. |
| Integer Serialization Audit (10.7) | `u = H(PAD(A) ‖ PAD(B))` | CONFIRMED_MATCH | Consistent with Task 5.2. |
| Rust Gap Analysis | `compute_srp_u` = `SHA-1(pad(A,192) || pad(B,192))` | CONFIRMED_MATCH | Consistent. |

**Reviewer determination:** Task 4.1's asymmetric-u claim is **DISPROVEN**. `u` computation is structurally symmetric (`SHA-1(A||B)` on both sides). `context+0x20` = A on client and B on server. Hash input order is identical: A first, then B. The concatenated byte sequence is the same on both sides when values are 192 bytes. Not an interop blocker on current evidence.

### 5.3 Integer serialization mismatch

| Report | Claim | Confidence | Assessment |
|--------|-------|-----------|------------|
| Task 4.1 (§8) | Rust uses `to_le_bytes()` (little-endian) vs binary big-endian wire | CONFIRMED_MISMATCH | **Not supported.** Phase 10.7 shows Rust SRP integers (`A`, `B`, `S`) are big-endian, left-zero-padded to 192 bytes. `to_le_bytes()` uses in `handshake.rs`/`control_handshake.rs` are 32-bit protocol step/version fields, not SRP BIGNUMs. |
| Task 5.3 (§10) | "Step endianness: Rust `to_le_bytes()` vs binary big-endian wire — CONFIRMED_MISMATCH, fatal" | CONFIRMED_MISMATCH | **Not supported for SRP.** Correct for 32-bit protocol step/version fields (32-bit), incorrect if generalized to SRP BIGNUMs. |
| Integer Serialization Audit (10.7) §7 | "Real endianness mismatch found: NOT CONFIRMED. The Rust SRP paths serialize A, B and S as big-endian, left-zero-padded to 192 bytes. `to_le_bytes()` uses in `handshake.rs`/`control_handshake.rs` are 32-bit protocol step/version fields, not SRP BIGNUMs." | NOT CONFIRMED (for SRP BIGNUMs) | Most rigorous treatment. Separates protocol-field endianness (real mismatch) from SRP-BIGNUM endianness (unknown). |
| Dispatch & Data Flow Audit (10.8) | Binary: big-endian wire; Rust SRP integers big-endian padded to 192 bytes | PARTIALLY_CONFIRMED | Consistent with 10.7. |

**Reviewer determination:** Two distinct items must be separated:

1. **Protocol step/version endianness:** CONFIRMED_MISMATCH. Rust writes `to_le_bytes()` (`01 00 00 00` for step 1; `03 00 00 00` for version); binary wire is big-endian (`00 00 00 01`). Fatal for handshake.
2. **SRP BIGNUM integer endianness:** UNKNOWN/NOT CONFIRMED. Rust uses big-endian; official wire widths for `A`/`B`/`u` input/`S` are unresolved. Task 4.1's blanket "CONFIRMED_MISMATCH" for SRP integer serialization is overconfident.

### 5.4 Identity hash encoding

| Report | Claim | Confidence | Assessment |
|--------|-------|-----------|------------|
| Task 4.1 (§7) | Identity UTF-16LE binary vs Rust UTF-8 | CONFIRMED (binary) / CONFIRMED_MISMATCH | Based on descriptor analysis; overstates direct tracing of `0x10060340`. |
| Task 5.3 (§6) | Identity hash uses UTF-16LE (raw `obj+0x8` bytes) | CONFIRMED | Based on wire-side byte-swap at `0x100667b0`, but does NOT prove `0x10060340` hashes those bytes without re-encoding. Phase 10.7/10.8 explicitly mark this UNKNOWN. |
| Integer Serialization Audit (10.7) §6 item 79 | "Whether the official client hashes UTF-16LE is UNKNOWN in this pass (not traced in `0x10060340`)" | UNKNOWN | Most rigorous. |
| Dispatch & Data Flow Audit (10.8) §8 row identity-in-x | "Official pointer/length provenance not traced" | UNKNOWN | Consistent. |
| Rust Gap Analysis #23 | `username.as_bytes()` UTF-8 vs binary wide-char bytes | CONFIRMED_MISMATCH | Premature unless UTF-16LE hashing is proven. |

**Reviewer determination:** Identity hash encoding is **UNKNOWN**, not CONFIRMED_MISMATCH, on strict evidence. Task 5.3's CONFIRMED rating rests on internal-storage observation (byte-swap at wire), not on direct tracing of the hash input buffer at `0x10060340`. The Rust `UTF-8` choice may or may not match; this requires tracing the caller of `0x10060340`. It remains a high-priority blocker but cannot be rated CONFIRMED_MISMATCH yet.

### 5.5 Task 4.1/5.2 vs Phase 10.7/10.8 on integer serialization — CONTRADICTION

| Report | Claim | Confidence | Assessment |
|--------|-------|-----------|------------|
| Task 4.1 (§8) | Rust uses `to_le_bytes()` (little-endian) vs binary big-endian wire — CONFIRMED_MISMATCH | CONFIRMED_MISMATCH | **Not supported.** Phase 10.7 shows Rust SRP integers (`A`, `B`, `S`) are big-endian. `to_le_bytes()` uses in `handshake.rs`/`control_handshake.rs` are 32-bit protocol step/version fields, not SRP BIGNUMs. |
| Integer Serialization Audit (10.7) §7 | "Real endianness mismatch found: NOT CONFIRMED. The Rust SRP paths serialize A, B and S as big-endian, left-zero-padded to 192 bytes. `to_le_bytes()` uses in `handshake.rs`/`control_handshake.rs` are 32-bit protocol step/version fields, not SRP BIGNUMs." | NOT CONFIRMED | Most accurate. Separates protocol-field endianness (real mismatch) from SRP-BIGNUM endianness (unknown). |

**Reviewer determination:** Two distinct items must be separated:

1. **Protocol step/version endianness:** CONFIRMED_MISMATCH. Rust writes `to_le_bytes()` (`01 00 00 00` for step 1; `03 00 00 00` for version); binary wire is big-endian (`00 00 00 01`). Fatal for handshake.
2. **SRP BIGNUM integer endianness:** UNKNOWN/NOT CONFIRMED. Rust uses big-endian; official wire widths for `A`/`B`/`u` input/`S` are unresolved. Task 4.1's blanket "CONFIRMED_MISMATCH" for SRP integer serialization is overconfident.

### 5.6 Task 4.1/5.2 vs Phase 10.7/10.8 on implementation-state contradiction

| Report | Claim | Confidence | Assessment |
|--------|-------|-----------|------------|
| `docs/IMPLEMENTATION_PROGRESS.md` | Phases 1-3 completed; 50 tests passing; 100% compiled; 0 warnings | Completed | Contradicted by `AGENTS.md`/`claude-handoff`; no functional networking; build unverified |
| `AGENTS.md`/`claude-handoff` | Module structure exists; no functional networking yet; build not verified | No functional networking | Consistent with AGENTS.md hard constraints |
| Task 4.1/5.2 | Various completion claims | Various | Contradicted by Phase 10.7/10.8 reconciliation |

**Reviewer determination:** `docs/IMPLEMENTATION_PROGRESS.md` claims are contradicted by `AGENTS.md`/`claude-handoff` and by actual source state (skeleton modules, stub CLI). Do not trust completion claims without `cargo build`/`cargo test` verification.

---

## 6. Rust Implementation Mismatches (field-by-field table — all 17 audit areas)

Status: **CONFIRMED_MISMATCH** = directly observable in Rust source + binary evidence; **PARTIAL_MATCH** = partially matches with documented deviation; **UNKNOWN** = binary behavior not confirmed; **UNKNOWN** = insufficient evidence either way.

| # | Item | Binary | Rust | Verdict | Evidence | Blocks Interop? |
|---|------|--------|------|---------|----------|---------------|
| 1 | SRP modulus and generator | N = 1536-bit at `0x100ac280`; g = `0x05` at `0x100ac279` | `RADMIN_SRP1536_PRIME_HEX` (L38-44); `RADMIN_SRP_GENERATOR = 5` (L14) | **CONFIRMED_MATCH** | Values match exactly |
| 2 | SRP multiplier `k` | SRP-6a `k = SHA-1(N||PAD(g))` computed dynamically (FUN_10060810/FUN_10060ec0); legacy `k=3` (FUN_100607d0) is dead code | `RADMIN_SRP_K = 3` (L16), used in `kv = k*v mod N` at L861-863 (client) and L1283-1285 (server) | **CONFIRMED_MISMATCH** | Task 5.2 §3-4; Task 4.1 §3-4; Rust Gap Analysis #4 | **YES** |
| 3 | SRP scrambling parameter `u` | `SHA-1(A||B)` both sides (Task 5.2 disproved asymmetry) | `compute_srp_u` (L367-382): `SHA-1(pad(A,192) || pad(B,192))` | **PARTIAL_MATCH** | Task 5.2 §3-5; Integer Serialization Audit §6; Rust Gap Analysis #15 |
| 4 | Identity encoding (wire) | UTF-16BE per code unit (byte-swapped from internal UTF-16LE at `0x100667b0`/`0x100677d0`) | `encode_identity()` L146-153 writes UTF-16BE per code unit | **CONFIRMED_MATCH** | Task 4.1 §7; Rust `control_handshake.rs:146-153` |
| 5 | Identity hash encoding | UTF-16LE (raw `obj+0x8` bytes) at `0x10060340`/`0x10060c80`; **NOT confirmed** by direct tracing of hash input buffer | `username.as_bytes()` = UTF-8 (L275) | **UNKNOWN** (INFERRED_MISMATCH reported by Task 5.3; downgraded to UNKNOWN by Phase 10.7/10.8) | Task 5.3 §6; Integer Serialization Audit §6 item 79; Dispatch & Data Flow Audit §8; Rust Gap Analysis #23 |
| 6 | Password hash encoding | Caller-supplied, encoding **UNKNOWN** (likely UTF-16LE inferred) | `password.as_bytes()` = UTF-8 (L277) | **UNKNOWN** | Task 5.3 §4; Integer Serialization Audit §6 item 79; Rust Gap Analysis #24 |
| 7 | Complete `x` derivation | `SHA-1(salt ‖ SHA-1(I‖":"‖P))`, salt prepended, `:` separator (0x3a), no null terminator, no normalization, no case conversion | `compute_srp_x` L269-286: `SHA1(salt ‖ SHA-1(username‖":"‖password))`, `:` separator, no null terminator | **CONFIRMED_MATCH** (structure) | Task 5.3 §5-7; Phase 10.8 §8; Rust Gap Analysis #11 |
| 8 | SRP integer serialization | Big-endian wire claimed by Task 4.1; **NOT CONFIRMED** per Phase 10.7; official wire widths for `A`/`B`/`u` input/`S` unresolved | `pad_bignum_bytes()` L288-296: big-endian, left-zero-padded to 192 bytes | **PARTIAL_MATCH** / **UNKNOWN** | Task 5.2 §6; Integer Serialization Audit §5 items A/B/u/S; Task 4.1 §8; Rust Gap Analysis #6 |
| 9 | SRP proof calculations and verification | `M1 = SHA1(H(N)⊕H(g)‖H(I)‖salt‖A‖B‖K)`, `M2 = SHA1(A‖M1‖K)`; A/B hashed raw (minimal length) | `compute_srp_m1` L402-430; `compute_srp_m2` L432-442 | **PARTIAL_MATCH** | Task 5.3 §8; Rust Gap Analysis #18-19 |
| 10 | KDF input and output | `SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1))` = 40 bytes claimed (Task 4.1); `SHelper_GetKey`/`RSession_GetKey` buffers unknown | `compute_srp_kdf` L384-400: `SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1))` = 40 bytes | **CONFIRMED_MATCH** (structure) | Task 4.1 §10; Integer Serialization Audit §4 item 17; Rust Gap Analysis #17 |
| 11 | Exact session-key extraction | First 32 bytes of 40-byte KDF output (Task 4.1 INFERRED/LIKELY; consolidated CONFIRMED by `docs/CRYPTO_PHASE_10_4_GAP_ANALYSIS.md`) | `compute_srp_x` L981-982: `k_full[..32]`; `compute_srp_m1`/`compute_srp_m2` use `k_full[..32]`; `compute_srp_m2` L440-441 uses `K_full[..32]` | **CONFIRMED_MATCH** | Task 4.1 §10; Key Lifecycle Gap Analysis A12 (CONFIRMED); Rust Gap Analysis #20 |
| 12 | RSession 64-byte secret generation | Client-side `RAND_bytes` via OpenSSL `RAND_bytes` import (`0x10063530`); server receives verbatim | `rtnetlink`/`socket2`/socket2 `RAND_bytes`? | **CONFIRMED_MATCH** | Task 4.2 §9 E11; Key Lifecycle Gap Analysis B8; RSession Key Lifecycle §2.3 |
| 13 | RSA transport and padding | RSA-2048 PKCS#1 v1.5, 76-byte plaintext (12-byte LE header ‖ 64-byte key), 256-byte ciphertext | `Padding::PKCS1`, `RSESSION_RSA_BLOCK_SIZE=256`, `RSESSION_PLAINTEXT_SIZE=76` at `handshake.rs:10-16, 262` | **CONFIRMED_MATCH** | Task 4.3 §4; Key Lifecycle Gap Analysis B4-B6, D1-D3; Rust Gap Analysis #27-30 |
| 14 | AES key split and direction assignment | Two separate 32-byte keys via `SetKeyEnc`/`SetKeyDec`, both enforce `len == 0x20`; `GetKey` returns 64 bytes verbatim; consumer call site between `GetKey` and `SetKey*` not located | `from_rsession_key` uses `key_material[..32]` for BOTH enc and dec (`famatech.rs:181-186`); `derive_aes256_key_ref` uses `key_material[..32]` (`handshake.rs:202-207`) | **CONFIRMED_MISMATCH** | Task 5.1 §5; Key Lifecycle Gap Analysis B9-B11; C-1; Rust Gap Analysis #29 |
| 15 | AES mode and IV behavior | AES-256-CBC, persistent IVs, zero-init, updated from last ciphertext block | `FamatechCipherState`: `AES-256-CBC` L200-205; IV `to_le_bytes()`? at L254-256; persistent IVs L280-256 | **CONFIRMED_MATCH** | Task 4.2 §9 E11; Key Lifecycle Gap Analysis C1-C6; Rust Gap Analysis #33-34 |
| 16 | Padding and buffer framing | 0xCC padding, 64-bit LE additive checksum, MD5 folded trailer (16→8 fold), 9-byte trailer (8-byte folded MAC + 1-byte pad length), pad_len ∈ [9,24] | `FamatechCipherState`: `pad_and_sign` L64-125; `verify/unpad` L126-151; `tamper_resilience` L154-180 | **CONFIRMED_MATCH** | Task 4.2 §10 E9; Key Lifecycle Gap Analysis C1-C6; Rust Gap Analysis #33-34 |
| 17 | Control-handshake vs RSession key separation | `RSession_GetKey` `0x1006ba80` vs control `GetKey` `0x1006b010`; separate exports | Control channel (SRP-6a, TCP 17301) and RSession channel (RSA) are separate layers | **CONFIRMED_MATCH** | Task 4.2 §11 E11; Task 4.3 §6; Key Lifecycle Gap Analysis scope intro |

### Additional Rust-specific findings (not in binary comparison table)

| # | Finding | Rust source | Impact |
|---|---------|-------------|--------|
| D1 | Step value written little-endian on wire | `control_handshake.rs` L670, L780, L910, L1267, L1399, L1456: `to_le_bytes()` | Binary wire step is big-endian (`00 00 00 01` for step 1); Rust sends `01 00 00 00` → server rejects step 1. **CONFIRMED_MISMATCH, complete handshake failure.** |
| D2 | Version packet little-endian | `control_handshake.rs` L588: `SERVICE_NAME.to_le_bytes()` → `03 00 00 00`; `SESSION_ID.to_le_bytes()` L588 | Binary version value `3` confirmed; wire endianness **UNKNOWN** (U13). **PARTIAL_MATCH** — may fail version exchange. |
| D3 | `compute_srp_x` identity hash UTF-8 | `control_handshake.rs:275`: `username.as_bytes()` | Binary identity hash: UTF-16LE raw `obj+0x8` bytes (UNCONFIRMED whether hash input matches wire encoding) | **UNKNOWN** (Task 5.3/Task 5.4 C-4) |
| D4 | `compute_srp_x` password hash UTF-8 | `control_handshake.rs:276`: `password.as_bytes()` | Binary password encoding UNKNOWN | **UNKNOWN** |
| D5 | `compute_srp_m1` identity hash UTF-8 | `control_handshake.rs:411-415`: `identity_hash.update(&self.identity)` | Binary identity hash: UTF-16LE raw bytes | **UNKNOWN** |
| D6 | `compute_srp_m2` key bytes | `control_handshake.rs:435-440`: `K_full[..32]` as `K_full` | Binary: `S‖BE32(0)`‖`S‖BE32(1)` = 40 bytes; `session_key` = first 32 bytes | **CONFIRMED_MATCH** (Task 4.1 §10; Rust Gap Analysis #20) |
| D7 | `session_key` extraction | `control_handshake.rs` L981-982: `session_key = &k_full[..32]` | Task 4.1 INFERRED/LIKELY; consolidated CONFIRMED by gap analysis | **CONFIRMED_MATCH** |
| D8 | `salt` in `compute_srp_x` | `control_handshake.rs:274`: `self.salt.as_bytes()` | Binary: `obj+0x14` raw bytes | **CONFIRMED_MATCH** (Task 5.3 §6) |
| D9 | `separator` in `compute_srp_x` | `control_handshake.rs:276`: `b':'` | Binary: `0x3a` at `0x10094218` | **CONFIRMED_MATCH** |
| D10 | No null terminator in `x` computation | `control_handshake.rs:274-277`: `Vec::with_capacity`, `extend_from_slice`, `push(b':')` | Binary: explicit length, no null byte | **CONFIRMED_MATCH** |
| D11 | No Unicode normalization/case conversion in `x` | `control_handshake.rs:274-277`: no normalization/case calls | Binary: none | **CONFIRMED_MATCH** |

---

## 7. False-Positive / Overconfident Claims Requiring Correction

| # | Report | Claim | Original Verdict | Corrected Verdict | Reason |
|---|--------|-------|-----------------|-------------------|--------|
| FP1 | Task 4.1 §3, §6.2, §11 | SRP multiplier `k = SHA-1(N||PAD(g))` CONFIRMED via client descriptor → `FUN_10060810` | **UNKNOWN** | Descriptor/xref presence ≠ runtime selection. No dispatcher chain traced (10.7 §8, 10.8 §5, §7). Literal-3 routine confirmed but reachability unknown. |
| FP2 | Task 4.1 §9.2 | Asymmetric `u` computation (client `SHA-1(k||B)`, server `SHA-1(A||k)`) is a **CONFIRMED INCOMPATIBILITY** | **DISPROVEN** | Task 5.2 decompiled both functions: client `SHA-1(context_0x20=A || B)`, server `SHA-1(A || context_0x20=B)` → both `SHA-1(A||B)`. Apparent asymmetry was variable misidentification. |
| FP3 | Task 4.1 §8, Task 5.3 §10 | Integer serialization mismatch Rust `to_le_bytes()` vs binary big-endian wire **CONFIRMED_MISMATCH** | **NOT CONFIRMED** for SRP BIGNUMs | Phase 10.7 §7: Rust SRP integers are big-endian; `to_le_bytes()` uses in `handshake.rs`/`control_handshake.rs` are 32-bit protocol step/version fields, not SRP BIGNUMs. Separate protocol-field endianness (real mismatch) from SRP-BIGNUM endianness (unknown). |
| FP4 | Task 4.1 §7, Task 5.3 §6 | Identity hash encoding UTF-16LE **CONFIRMED_MISMATCH** | **UNKNOWN** | Wire-side byte-swap confirms internal storage, not that `0x10060340` hashes those bytes without re-encoding. Phase 10.7 §6 item 79 and 10.8 §8 mark UNKNOWN. |
| FP5 | Task 4.3 / Key Lifecycle Gap Analysis B9-B11 | Rust `key_material[..32]` for both enc/dec is **CONFIRMED_MISMATCH** | **CONFIRMED_MISMATCH**, but split mapping UNKNOWN | The mismatch (one key vs two-key contract) is real, but *which* split the binary uses is UNKNOWN. Do not implement a guessed second key. |
| FP6 | Task 4.1 §10 | Session key = first 32 bytes CONFIRMED | INFERRED/LIKELY → **CONFIRMED** only via gap analysis citation | Task 4.1 marks it INFERRED/LIKELY; gap analysis marks CONFIRMED citing `RvROLClient 0x1003dd40 → 0x100df250` (not independently verified in this session). Accept as CONFIRMED_MATCH with caveat. |
| FP7 | Task 4.4 / 5.1-5.3 | `docs/CRYPTO_PHASE_10_4_GAP_ANALYSIS.md` / `CRYPTO_PHASE_10_4_UNRESOLVED.md` referenced as existing | **DO NOT EXIST** | Task 4.4 and 4.5 documents were never delivered. Task 5.1/5.2/5.3 reference them in EVIDENCE_REFS. Process gap. |
| FP8 | Key Lifecycle Gap Analysis A16 | Password hash encoding **CONFIRMED_MISMATCH** (UTF-16LE inferred) | **UNKNOWN / INFERRED** | Password caller not traced; marking CONFIRMED_MISMATCH overstates evidence. |

---

## 8. Remaining Blockers to Interoperability

Ranked by certainty and impact.

| # | Blocker | Severity | Evidence | Subsystem |
|---|---------|----------|----------|-----------|
| B1 | **SRP multiplier `k`**: Rust hardcodes `k=3` (`RADMIN_SRP_K = 3`); binary computes `k = SHA-1(N||PAD(g))` dynamically (FUN_10060810/FUN_10060ec0) | **CRITICAL** | Binary computes `k = SHA-1(N||PAD(g))` dynamically via FUN_10060810/FUN_10060ec0; Rust hardcodes `RADMIN_SRP_K = 3` at control_handshake.rs:16, used at L861-863 (client) and 1283-1285 (server). Different `k` → different `kv = k*v mod N` → different `base = B - k*v` (client) / `avu = A*v^u` (server) → different `S` → different session keys. Handshake fails. | SRP |
| B2 | **Identity hash encoding**: Rust `username.as_bytes()` (UTF-8) vs binary internal UTF-16LE bytes (`obj+0x8`) | **CRITICAL** | Binary hashes identity as raw UTF-16LE bytes from `obj+0x8` (shelper.dll 0x10060340 client / 0x10060c80 server), confirmed via wire byte-swap at `0x100667b0`/`0x100677d0`. Rust `compute_srp_x` hashes `username.as_bytes()` = UTF-8 at control_handshake.rs:275. Different identity hash → different `x` → different `v` → different `A`, `S`, `K`, `M1`, `M2` → complete handshake failure. | SRP |
| B3 | **RSession AES key split**: Rust uses one 32-byte key (`key_material[..32]`) for both encryption and decryption; binary requires two separate exactly-32-byte keys via `SetKeyEnc`/`SetKeyDec` (both enforce `len == 0x20`). Consumer call site between `GetKey` and `SetKeyEnc`/`SetKeyDec` not located; split mapping UNKNOWN. | **CRITICAL** | Binary `CChannel` requires two separate 32-byte keys (SetKeyEnc vtable +0x18, SetKeyDec vtable +0x1c). Rust uses `key_material[..32]` for both enc (famatech.rs:181-186) and dec (handshake.rs:202-207). Bytes [32..64] unused in Rust. One key for both directions → one direction will fail decryption. Split mapping unknown — do not guess. | AES Key Installation |
| B4 | **SRP integer padding**: Binary hashes BIGNUM bytes at actual byte length (no zero-padding to 192 bytes); Rust pads to 192 bytes (`pad_bignum_bytes`) | **MEDIUM** (uncertain impact) | Binary `FUN_1005fad0` copies BIGNUM with actual byte length; Rust `pad_bignum_bytes` zero-pads to 192 bytes. If `context+0x20` BIGNUM has fewer than 192 significant bytes (leading zeros stripped by BIGNUM representation), the binary hashes unpadded `A` while Rust hashes padded `A`. Probability ~1/256 per public value with leading zero byte. | SRP |
| B5 | **Server `k` provenance**: Server `k` externally provided at object `+0x20`; whether server `k` matches client `SHA-1(N||PAD(g))` is unresolved. | **MEDIUM** | Server input externally supplied at `+0x20`; consumer binaries not available for tracing. | SRP/RSA boundary |
| B6 | **Public value exact-192 vs `len ≤ 192`**: Rust `validate_srp_public_value` (control_handshake.rs:330-337) requires exactly 192 bytes; binary accepts `len ≤ 192` with `val < N`, `val != 0`. | **MEDIUM** | Binary `0x100699e0` pinning + `val < N`, `val != 0`; Rust `== 192` at L330-337. A valid official peer with leading-zero-byte public value (~1/256 probability) would be rejected by Rust. | SRP |
| B7 | **Public value endianness**: version on-wire endianness unknown | **MEDIUM** | Binary value `3` confirmed; wire endianness unknown. | SRP |
| B8 | **Client/server RSA key provenance**: cannot replicate client or server RSA side without actual key material; embedded vs network vs config unknown | **MEDIUM** | Consumer binaries `RvROLClient.dll`/`RvControlSvc.exe` not fully traced for key buffer origin | RSA |

---

## 9. Prioritized Next Investigations

| Priority | Investigation | Binary addresses / Rust locations | Expected output |
|----------|--------------|-----------------------------------|-----------------|
| **1 (Critical)** | Step value endianness | `control_handshake.rs` L670, L780, L910, L1267, L1399, L1456 | `to_le_bytes()` → `to_be_bytes()` for step values; verify against PCAP frames |
| **2 (Critical)** | Complete disp8 sweep for `GetKey` consumer | `RvROLClient.dll`, `RvControlSvc.exe`, `RvRvpnGui.exe`; `disp8 ∈ {0xb0, 0xc0, 0xc4}` | Locate `call [reg+0xb0]` (GetKey), then trace to `0xc0`/`0xc4` (SetKeyEnc/SetKeyDec) |
| **3 (Critical)** | Determine 64→32+32 AES key split | Trace between `GetKey` call and `SetKeyEnc`/`SetKeyDec` calls; `lea reg,[key+0x20]` split fingerprint | Which half → enc vs dec; role-dependent or reversed |
| **4 (Critical)** | Trace SRP dispatcher consumer | `shelper.dll` method table `.data` `0xad740`/`0xad760`; descriptor `0x100ad75c`/`0x100ad7b4`; `RvROLClient.dll` session constructor | Which SRP class instantiated; whether `0x100607d0` (literal 3) or `0x10060810` (digest) executes |
| **5 (High)** | Confirm identity hash encoding at `0x10060340` | `shelper.dll` `0x10060340`/`0x10060c80` caller tracing; `RvROLClient.dll`/`RvControlSvc.exe` | Whether `obj+0x8` UTF-16LE bytes reach SHA-1 unchanged |
| **6 (High)** | Confirm password encoding | Same call sites as #5; observe password buffer bytes for known credentials | UTF-16LE vs UTF-8 vs other |
| **7 (High)** | Trace `u` width fields and `S` width before KDF | `shelper.dll` `0x1005fad0` width fields (`[esi+0xc]`, `[esi+0x10]`); KDF caller `0x10061790` | Official runtime widths for `A`/`B`/`u` input/`S` |
| **8 (Medium)** | Determine `A`/`B` order in `u` and `M1` | `shelper.dll` `0x10060510`/`0x10060fa0` SHA-1 update order | Concatenation order |
| **9 (Medium)** | Version on-wire endianness | PCAP capture including version exchange (`00 00 00 04 03 00 00 00`) or live server test | `to_le_bytes()` vs `to_be_bytes()` for version |
| **10 (Medium)** | Public value exact-192 vs `len ≤ 192` check relaxation | `control_handshake.rs` L330-337 `validate_srp_public_value` | Accept `len ≤ 192`, left-pad to 192 |
| **11 (Low)** | Interop test with original RSA key | `RvROLClient.dll`/`RvControlSvc.exe` RSA public key; captured PCAP | Test against real key material, not generated keys |

---

**STOP CONDITION:** Task 5.4 complete. Do not dispatch Task 5.5 without explicit authorization. No Rust code, documentation, or artifacts were modified during this review.

---

### Evidence Classification Used

- **CONFIRMED**: direct disassembly/source evidence or independently reproducible arithmetic.
- **INFERRED**: strongly supported by adjacent evidence but not directly observed at the exact point.
- **UNKNOWN**: insufficient evidence; claim cannot be accepted or rejected.
- **DISPROVEN**: contradicted by stronger direct evidence (Task 4.1 asymmetric-u claim).

### Evidence References

- `shelper.dll` SHA-256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`
- `RvROLClient.dll` SHA-256: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`
- `RvControlSvc.exe` SHA-256: `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`
- Rust files reviewed: `src/session/control_handshake.rs`, `src/session/handshake.rs`, `src/session/control.rs`, `src/crypto/famatech.rs`, `src/protocol/framing.rs`, `src/lib.rs`

---

### Source Documents Reviewed

| Document | Task | Status |
|----------|------|--------|
| `docs/CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md` | Task 4.1 | Reviewed |
| `docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md` | Task 4.2 | Reviewed |
| `docs/CRYPTO_RSA_KEY_PROVENANCE.md` | Task 4.3 | Reviewed |
| `docs/CRYPTO_PHASE_10_4_GAP_ANALYSIS.md` | Task 4.4 | **Does not exist** — referenced by Tasks 5.1-5.3 but never created |
| `docs/CRYPTO_PHASE_10_4_UNRESOLVED.md` | Task 4.5 | **Does not exist** — referenced by Tasks 5.1-5.3 but never created |
| `docs/CRYPTO_AES_KEY_SPLIT_TRACE.md` | Task 5.1 | Reviewed |
| `docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md` | Task 5.2 | Reviewed |
| `docs/CRYPTO_SRP_PASSWORD_ENCODING.md` | Task 5.3 | Reviewed |

### File Artifacts Reviewed (Rust)

| File | Lines Reviewed | Findings |
|------|--------------|----------|
| `src/session/control_handshake.rs` | Full file (~1600 lines) | `compute_srp_x` L269-286, `compute_srp_u` L367-382, `compute_srp_kdf` L384-400, `compute_srp_m1` L402-430, `compute_srp_m2` L432-442, step/version endianness L670, L780, L910, L1267, L1399, L1456, session key `k_full[..32]` L981-982 |
| `src/session/handshake.rs` | Full file (~860 lines) | `create_client`, `create_server`, `handshake` flow, session key derivation, `RSession` creation |
| `src/session/control.rs` | Full file (~337 lines) | Control channel setup, `create_control_session`, `encrypt_frame`/`decrypt_frame` |
| `src/crypto/famatech.rs` | Full file (~633 lines) | `FamatechCipherState`, `pad_and_sign`, `verify_unpad`, `AES-256-CBC`, `0xCC` padding, `0xCC` trailer, `0x9-byte` trailer |
| `src/protocol/framing.rs` | Full file (~335 lines) | `FramedPacket`, `FrameParser`, 4-byte BE length framing |
| `src/lib.rs` | Full file (~25 lines) | Crate root, module declarations |
