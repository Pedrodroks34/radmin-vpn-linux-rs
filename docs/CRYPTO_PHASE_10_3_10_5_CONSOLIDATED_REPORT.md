# CRYPTO_PHASE_10_3_10_5_CONSOLIDATED_REPORT.md

# Unified Phase 10.3–10.5 — Cryptographic Lifecycle Reconstruction, Protocol Analysis & Compatibility Remediation (Consolidated)

## 1. Executive Summary

This document is the single consolidated reconciliation of the Radmin VPN cryptographic
investigation. It merges Phases 10.3 (lifecycle/key exchange), 10.4 (reconstruction,
AES/RSA, cross-validation) and 10.5 (compatibility audit and remediation) into one
coherent specification of the official Windows implementation and a direct comparison with
the Rust client.

Headline results:

- The SRP group is a fixed **1536-bit** modulus (`N` at `shelper.dll` RVA `0x100ac280`,
  `g = 5` at `0x100ac279`). Multiplier `k = SHA-1(N || PAD192(g))` (SRP-6a), recomputed
  independently in Python; the legacy constant `k = 3` (`FUN_100607d0`) is dead code.
- `x = SHA-1(salt || SHA-1(identity || ":" || password))` is confirmed at the instruction
  level (`0x10060340` client, `0x10060c80` server): identity from `obj+0x8`,
  separator `":"` at `0x10094218`, password as a caller-supplied `(ptr, len)`.
- `context+0x20` is the object's **own public ephemeral** — `A = g^a mod N` on the client
  (`FUN_10060410`), `B = g^b mod N` on the server (`FUN_10060d80`); `u = SHA-1(A || B)` is
  symmetric (`FUN_10060510` / `FUN_10060fa0`).
- The 64-byte RSession secret (`SHelper_RSession_GetKey` at `0x1006ba80`) is returned
  verbatim with no transform. Two separate 32-byte AES keys are required by `SetKeyPair`
  (`0x1006a630`); which half feeds encryption vs decryption remains **UNKNOWN** (missing
  consumer call site).
- Password encoding is **UNKNOWN** (caller outside `shelper.dll` not traced). Identity
  wire encoding is UTF-16BE; identity hash encoding is reported as UTF-16LE from the
  `obj+0x8` buffer — see the encodings caveat in §7.
- RSA is 2048-bit PKCS#1 v1.5 for RSession key establishment; key provenance is **UNKNOWN**.
- Overall readiness: **NOT READY** for interoperability testing; several blockers are
  mathematical (solvable only by dynamic execution) rather than implementation errors.

No outcome of this consolidated phase relies on textbook SRP alone; every confirmed claim is
tied to a binary address or an independent calculation. Where evidence is insufficient the
classification is left as UNKNOWN.

---

## 2. Repository Baseline and Provenance (Verified 2026-11-08)

| Item | Value |
|------|-------|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` (docs: add SRP integer serialization audit) |
| Working tree | Dirty; 3 tracked files modified with Phase 10.5 remediation (k=SHA-1(N\|\|PAD(g)) via `srp_k()`; identity UTF-16 via `encode_identity()`; `srp_k` exported in `src/session/mod.rs`) + ~30 untracked analysis files |
| Binaries | `shelper.dll` `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`; `RvROLClient.dll` `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`; `RvControlSvc.exe` `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` |
| Tools | Ghidra 12.2 headless, GNU objdump, python3; `cargo test` passes (147 unit + 5 integration) |

All binary hashes were re-verified this phase with `sha256sum`; nothing was modified.

---

## 3. Historical Reconciliation

| Claim (phase, date) | Earlier position | Reconciled position | Evidence |
|---|---|---|---|
| Multiplier `k = 3` (pre-10.5 Rust) | `RADMIN_SRP_K: u32 = 3` | DEAD CODE | `FUN_100607d0` not referenced by SRP-6a descriptors; `FUN_10060810`/`FUN_10060ec0` compute `SHA-1(N‖PAD192(g))` |
| `k = SHA-1(N‖PAD(g))` (10.5) | Implemented via `srp_k()` | CONFIRMED | Re-verified this phase; Python hash = `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233` |
| `u` asymmetric (legacy 4.1) | Client `SHA-1(k‖B)`, server `SHA-1(A‖k)` | DISPROVEN | Both sides hash `A‖B`; order differs, concatenated bytes identical |
| `u` symmetric (10.5) | `SHA-1(A‖B)` | CONFIRMED | `FUN_10060510`/`FUN_10060fa0` |
| Identity UTF-8 (pre-10.5) | `username.as_bytes()` | INVALID | Binary hashes raw UTF-16 from `obj+0x8` |
| Identity UTF-16LE in hash (10.5) | `encode_identity()` | PARTIAL (see §7) | `encode_identity()` emits UTF-16BE; internal `obj+0x8` is UTF-16LE per byte-swap analysis |
| AES single key (pre-10.5 Rust) | `key_material[..32]` both directions | INVALID | `SetKeyPair` (0x1006a630) takes two pointers, both `len==0x20` |
| AES split mapping (10.5/10.10/10.11) | Unknown | UNKNOWN (consumer call site still missing) | disp8 indirect dispatch defeats static scan |
| Version endianness | Big-endian claimed in 10.5 notes | LITTLE-ENDIAN | PCAP shows `03 00 00 00`; 0 BE occurrences |
| Wire is big-endian everywhere | Assumed | PARTIALLY_DISPROVEN | Version is LE; framing/BIGNUM/TLV-header are BE (different layers) |

No earlier report was overwritten; contradictions are resolved in favor of the most
recent, instruction-level evidence.

---

## 4. Cryptographic Lifecycle (Phase 10.3 Consolidation)

Observed chain (component → responsibility → crypto role):

- `RvRvpnGui.exe` — GUI front-end; drives the named-pipe broker
  (`\\.\pipe\RadminVpnGuiChannel`) and **does not** perform crypto itself.
- `RvControlSvc.exe` — control service; suspected RSession consumer; resolves all
  `SHelper_*` functions via `GetProcAddress` (`FUN_00442290`).
- `RvROLClient.dll` — ROL client library; also resolves the same table
  (`FUN_1003fbd0`); imports only `SHelper_Init` statically.
- `shelper.dll` — the crypto library: SRP-6a (control handshake), RSession (RSA key
  establishment), CChannel (AES-256-CBC), RSA helper.

Lifecycle:

1. `InitDll` resolves the 47-entry function-pointer table (offset `+0x58…+0xec`).
2. SRP-6a control handshake (`x → v → A/B → u → S → K → M1/M2`) establishes the control
   session key (`K` = 40 bytes; first 32 = AES-256 key).
3. RSession handshake (RSA PKCS#1 v1.5, 2048-bit) establishes a 64-byte secret per
   session; the consumer splits it into two directional AES-256 keys.
4. Frames on port 17301 are 4-byte-BE-length-prefixed; payloads padded with `0xCC` to a
   multiple of 16, terminated by a 9-byte folded-MD5 trailer; CBC with persistent IVs.

Phase 10.3 items that remain open: the `FUN_100092e0` jump table (dispatcher detail),
the exact RSAHelper key-function RVAs, the `+0x28`/`+0x30` object fields, and whether
OAEP/MGF is present (only PKCS#1 v1.5 confirmed; OAEP absence is not proven).

---

## 5. Protocol Findings

| Field | Encoding | Evidence | Confidence |
|---|---|---|---|
| Frame length prefix | 4-byte big-endian `u32` (excludes header) | AGENTS.md, PCAP, `framing.rs` | CONFIRMED |
| Protocol version | `03 00 00 00` little-endian | PCAP (5 occurrences), `SHELPER_PROTOCOL_VERSION` | CONFIRMED |
| Control packet | `00 00 00 04 03 00 00 00` (keepalive/ACK, ×4) | PCAP | CONFIRMED |
| Control port | TCP 17301 | PCAP, AGENTS.md | CONFIRMED |
| TLV header | `(tag & 0xF8000000) \| (len & 0x07FFFFFF)`, BE | Rust `encode_item()` | PARTIAL |
| SRP step values | UNKNOWN (no PCAP of SRP exchange) | — | UNKNOWN |
| Payload sizes | ≡ 0 mod 16 (0xCC padding) | PCAP | CONFIRMED |
| TLS | None | PCAP | CONFIRMED |

Do not generalize the little-endian version encoding to SRP integers — SRP BIGNUMs are
big-endian (see §6.3).

---

## 6. SRP Reconstruction and Compatibility

### 6.1 Group and multiplier

| Parameter | Value | Source |
|---|---|---|
| `N` | 1536-bit prime `e634471e…c7` | `0x100ac280`; matches `RADMIN_SRP1536_PRIME_HEX` |
| `g` | `5` | `0x100ac279`; matches `RADMIN_SRP_GENERATOR` |
| `k` | `SHA-1(N ‖ PAD192(g))` = `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233` | `FUN_10060810` / `FUN_10060ec0`; Python-verified; matches Rust `srp_k()` |

### 6.2 Identity / password / x

`x = SHA-1(salt ‖ SHA-1(identity ‖ ":" ‖ password))` — re-verified this phase at
`0x10060340`: identity from `obj+0x8` (`mov 0x8(%esi),%eax`), separator `0x10094218`
with length 1, password from caller stack (`mov 0x10(%ebp),%edx`), two `SHA1_Update`
stages, then `x` stored via BIGNUM conversion at `obj+0x1c`.

### 6.3 Integer serialization

N, g, A, B, u, k, S are all BIGNUMs serialized **big-endian**; BIGNUM-to-bytes uses the
actual byte length (`FUN_1005fad0`, `FUN_1005f710`). Rust pads public values to exactly
192 bytes (`validate_srp_public_value`); the binary accepts `len ≤ 192` with leading-zero
stripping — a minor length-classification divergence.

### 6.4 u and S

- Client (`FUN_10060510`): `SHA-1(context_0x20 ‖ B)`.
- Server (`FUN_10060fa0`): `SHA-1(A ‖ context_0x20)`.
- With `context+0x20 = A/B` (§7), both are `SHA-1(A‖B)`.
- `S_client = (B − k·v)^(a+u·x) mod N`; `S_server = (A·v^u)^b mod N`.
- Python: `S_client == S_server` for both UTF-8 and UTF-16LE password paths.

### 6.5 KDF

`K = SHA-1(S‖BE32(0)) ‖ SHA-1(S‖BE32(1))` (40 bytes); first 32 bytes are the AES-256 key.
Matches Rust `compute_srp_kdf()`.

### 6.6 M1 / M2

M1 accumulator at `context+0x38+0x60` (server) / `context+0x38` (client) confirmed.
Exact input order and component list: PARTIALLY_CONFIRMED; Rust `compute_srp_m1()` /
`compute_srp_m2()` match the documented structure but are not instruction-verified.

---

## 7. Identity and Password Encoding — Critical Distinction

Three different representations must not be conflated:

| Representation | Encoding | Evidence |
|---|---|---|
| Identity **on the wire** | UTF-16**BE** (every code unit swapped) | `encode_identity()` per code unit writes `(c >> 8, c & 0xFF)`; decode mirrors it |
| Identity **in the SRP object** (`obj+0x8`) | UTF-16**LE** (internal form) | byte-swap at `0x100667b0` region |
| Identity **fed to the x hash** | the raw `obj+0x8` buffer | `mov 0x8(%esi),%eax` at `0x10060361` → `SHA1_Update` |

Because the hash reads `obj+0x8` directly, the hash input is the **internal** form, not
the wire form. If that internal form is UTF-16LE, then Rust's `encode_identity()` —
which emits UTF-16BE — differs from the binary in the **hash input** even though it
matches the **wire** form.

Phase 10.5 moved identity from UTF-8 to UTF-16 ("LE") via `encode_identity()`, but the
helper actually produces BE, so the correction is only half-landed. The LE-vs-BE
question for the hash input is MEDIUM-confidence inferential; a dynamic breakpoint on
`0x10060340` with a known identity string ("A" → `41 00` vs `00 41`) settles it.

Password: passed as a raw caller `(ptr, len)` with no transformation inside
`shelper.dll`; encoding is UNKNOWN (UTF-8 vs UTF-16LE vs ANSI). Rust uses UTF-8.
No source change is made on speculation.

---

## 8. AES Key Derivation and Installation

- `SHelper_RSession_GetKey` (`0x1006ba80`): returns a **64-byte heap copy verbatim**
  (no KDF, XOR or byte transform); length 0x40.
- `SetKeyPair` (`0x1006a630`): takes **two pointers**; validates both lengths
  (`cmp $0x20,%eax; jne fail; cmp %eax,%ecx; jne fail`); calls vtable `+0x18`
  (SetKeyEnc) and `+0x1c` (SetKeyDec).
- AESCryptor: AES-256-CBC, enc key at `+0x4`, dec key at `+0xF8`, persistent IVs at
  `+0x1EC`/`+0x1FC`, zero-initialized, continuous CBC chaining, 0xCC padding with
  9-byte folded-MD5 trailer.

**Classification: NOT CONFIRMED that the two 32-byte keys differ.** Two pointers do not
prove different contents; two initialization calls do not prove different key material.
Rust `FamatechCipherState::from_rsession_key()` uses `key_material[..32]` for both
directions (`src/crypto/famatech.rs:181-186`), leaving bytes `[32..64]` unused.
Whether the official consumer passes `buf[0..32]`/`buf[32..64]`, the reverse, or the
same slice twice remains UNKNOWN because the consumer call site (disp8 indirect
`call [reg+0xb0/c0/c4]`) has not been located statically.

---

## 9. RSA Reconstruction and Provenance

| Parameter | Value | Evidence |
|---|---|---|
| Size | 2048-bit (256 bytes) | `RSESSION_RSA_BLOCK_SIZE = 256` |
| Padding | PKCS#1 v1.5 | `Padding::PKCS1` paths |
| Plaintext | 76 bytes: 3×u32 LE client params + 64-byte key material | `RSESSION_PLAINTEXT_SIZE = 76`, `RSESSION_CLIENT_HEADER_SIZE = 12` |
| Server token | 4 bytes LE u32 | `RSESSION_SERVER_TOKEN_SIZE = 4` |
| Public exponent | `0x010001` (65537) | `DEFAULT_RSA_PUBLIC_EXPONENT` |

Key provenance (embedded vs loaded vs received) is **UNKNOWN**; no RSA blob was located
in `.rdata` this phase. Rust's `Rsa::from_public_components` matches the import
interface, but no official key material is present to interoperate against. OAEP/MGF
has not been observed; its absence does not constitute a proof of absence.

---

## 10. Rust Compatibility Matrix

| Operation | Windows | Rust | Evidence | Status |
|---|---|---|---|---|
| SRP N/g | 1536-bit / 5 | Same constants | byte-for-byte match | COMPATIBLE |
| SRP k | `SHA-1(N‖PAD192(g))` | `srp_k()` | hash equality | COMPATIBLE |
| SRP x | `SHA-1(salt‖SHA-1(I‖":"‖P))` | Same formula, UTF-16BE identity, UTF-8 password | binary + Rust source | POTENTIAL_MISMATCH (encodings) |
| Identity wire | UTF-16BE | `encode_identity()` BE | byte order | COMPATIBLE |
| Identity hash input | raw `obj+0x8` (LE-inferred) | UTF-16BE helper output | LE vs BE | POTENTIAL_MISMATCH |
| Password encoding | UNKNOWN | UTF-8 | no caller trace | UNKNOWN |
| SRP A/B | `g^a`,`g^b` at `context+0x20` | `compute_srp_A/B` equivalents | mod_exp | COMPATIBLE (strongly supported) |
| SRP u | `SHA-1(A‖B)` symmetric | `compute_srp_u()` 192-byte pad | binary | COMPATIBLE |
| SRP S | client/server formulas | Same formulas | Python S_c=S_s | COMPATIBLE (mathematical) |
| Session K | 40-byte KDF | `compute_srp_kdf()` | structure | COMPATIBLE |
| M1/M2 | accumulator-based | single-shot hashes | partial | PARTIAL |
| AES key derivation | 64B verbatim, 2×32B required | `from_rsession_key` one key twice | binary + source | INCOMPATIBLE (until mapping proven) |
| AES mode/IV/padding/trailer | AES-256-CBC, persistent IV, 0xCC, 9B trailer | Same | famatech.rs | COMPATIBLE |
| RSA | 2048-bit PKCS#1 v1.5 | Same parameters | source | COMPATIBLE (parameters only) |
| RSA key provenance | UNKNOWN | test keys generated | no official blob | UNKNOWN |
| Protocol serialization | BE framing/TLV, LE version | `to_be_bytes` TLV, LE version, LE steps | PCAP + source | PARTIAL (steps unverified) |

---

## 11. Implemented Corrections

**This phase: none.** No source was modified.

Pre-existing working-tree modifications (from Phase 10.5, preserved untouched):
- `src/session/control_handshake.rs`: `RADMIN_SRP_K = 3` → `srp_k()` computing
  `SHA-1(N‖PAD192(g))`; identity hash input switched from UTF-8 to
  `encode_identity()` (UTF-16BE); updated test.
- `src/session/mod.rs`: exports `srp_k`.
- `docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md`: expanded audit (k=SHA-1(N‖PAD(g)),
  symmetric u, dead k=3 path).

These are justified by direct binary evidence and are kept. The UTF-16LE-vs-BE hash
question and AES split are NOT changed here because the mismatch is not yet directly
demonstrated.

---

## 12. Remaining Blockers (by impact)

1. **P0** — AES split mapping (which 32 bytes → enc/dec). Missing consumer call site.
2. **P0** — Password encoding in `x`. Caller of `0x10060340`/`0x10060c80` outside `shelper.dll`.
3. **P0** — Identity hash bytes (UTF-16LE internal vs UTF-16BE helper output).
4. **P1** — `context+0x20` runtime proof (dynamic confirmation).
5. **P1** — M1/M2 exact construction (instruction-level).
6. **P1** — RSA key provenance/blobs.
7. **P2** — SRP step-value endianness on the wire.
8. **P2** — `+0x24`/`+0x2c`/`+0x30`/`+0x34` field semantics; `FUN_100092e0` jump table.

## 13. Final Readiness Assessment

**NOT READY** for interoperability testing. The SRP mathematical core is reconstructed
and internally consistent, and k/u/x/K are confirmed, but three P0 encoding/key-mapping
blockers would each independently cause handshake failure if wrong. Compiling and passing
unit tests are not evidence of interoperability (per AGENTS.md).

---

## 14. Tests Executed

- `cargo test`: 147 unit + 5 integration tests pass (post-revalidation this phase).
- No Rust source was modified in this phase; the test suite validates the pre-existing
  Phase 10.5 corrections.

## 15. Integrity

- No Rust source, historical documentation, binary, PCAP, or Ghidra artifact modified.
- No commits, pushes, branches, or pull requests.
- HEAD remains `95e304e0855a6faf4eece932484cb00e36620a6e`.
- New files created by this consolidated phase:
  `docs/CRYPTO_PHASE_10_3_10_5_CONSOLIDATED_REPORT.md`,
  `docs/CRYPTO_PHASE_10_3_10_5_EVIDENCE.json`,
  `docs/CRYPTO_PHASE_10_3_10_5_OPEN_QUESTIONS.md`.
