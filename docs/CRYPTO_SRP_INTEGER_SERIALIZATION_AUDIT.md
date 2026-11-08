# SRP Integer Serialization and Endianness Audit (Phase 10.7)

## 1. Executive Summary

- **Branch / HEAD audited:** `main` at `c07e990a8dbb4caa3d67d6558522e2b65d210727` (`origin/main`, clean working tree).
- **Real endianness mismatch found:** NOT CONFIRMED. The Rust SRP paths serialize `A`, `B` and `S` as big-endian, left-zero-padded, 192-byte buffers. The official binary's byte layout for these values is only partially established (see Section 7).
- **Central finding (contradicts the investigation brief):** the official client's multiplier slot (`shelper.dll!0x100607d0`) uses the **integer 3**, not `SHA1(N || PAD(g,192))`. The SHA-1 formula is arithmetically correct for the known-answer digest `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233`, but no code path that hashes `N` was found in the examined slots.
- **Verdict:** the evidence does NOT authorize changing `k`, `u`, or the padding of `S` in Task 5.5.

## 2. Repository Integrity

| Item | Value |
|---|---|
| Repository root | `/tmp/repo-now` (fresh clone of `Pedrodroks34/radmin-vpn-linux-rs`) |
| Branch | `main` (tracking `origin/main`) |
| HEAD | `c07e990a8dbb4caa3d67d6558522e2b65d210727` |
| Working tree | clean (`git status --short --branch`: `## main...origin/main`) |
| Documentation baseline `5c0fc8b…` | present, on `origin/archive/docs-2026-11` (not on `main`) |
| Previous HEAD `3adb92f…` | present in object store |
| Phase 10.5/10.4 documents named in the brief | not on `main` (archived to `archive/docs-2026-11`) |

No source, manifest, lockfile, test or document was modified. This report is the only new file, created in the analysis clone and not committed.

## 3. Evidence Inventory

| Artifact | SHA-256 | Use |
|---|---|---|
| `binaries/radmin_ext/shelper.dll` | `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4` | SRP routines, method tables, k slot |
| `binaries/radmin_ext/RvControlSvc.exe` | `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` | service (not analyzed for SRP in this pass) |
| `binaries/radmin_ext/RvROLClient.dll` | `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177` | client caller (not traced in this pass) |

Hashes were computed in the handoff package during earlier phases and re-verified for `shelper.dll` in this pass. Ghidra projects were not opened (no Ghidra in this environment).

## 4. SRP Data Flow (Rust, `src/session/control_handshake.rs`)

```
username (&str) ──encode_identity (UTF-16BE)──► wire item TAG_IDENTITY        [line 146, 671]
username.as_bytes() (UTF-8) ──► compute_srp_x: SHA1(salt || SHA1(user ":" pass))  [lines 269-285]
password.as_bytes() (UTF-8) ─┘
username.as_bytes() (UTF-8) ──► compute_srp_m1: H_I = SHA1(user)               [line 419]

N (BigNum hex, 192 B)  ─► step-2 item padded to 192 (line 1271)
                        ─► compute_srp_m1 uses prime_n.to_vec() (minimal)       [line 899, 1386]
g  = 5 (u8)            ─► compute_srp_m1: H_g = SHA1([g])                      [line 415]
k  = RADMIN_SRP_K = 3  ─► BigNum::from_u32(3), kv = k*v mod N                  [lines 16, 861, 1283]
A  = g^a mod N         ─► pad_bignum_bytes(…,192) (client)                      [line 778]
B  = (k v + g^b) mod N ─► pad_bignum_bytes(…,192) (server)                      [line 1301]
u  = SHA1(PAD192(A)||PAD192(B)) as BigNum (big-endian)                          [lines 367-381]
S  = (B-kv)^(a+ux) (client) / (A v^u)^b (server) mod N
S_bytes = pad_bignum_bytes(S.to_vec(), 192)  ─► compute_srp_kdf (SHA1(S||be32(0/1)))  [lines 894-897, 1381-1384]
M1 = SHA1(H_xor || H_I || salt || A_bytes || B_bytes || K_full)                 [lines 402-430]
M2 = SHA1(A_bytes || M1 || K_full)                                              [lines 432-441]
```

Callers verified by grep: `compute_srp_u` is called only from the handshake state machine; `pad_bignum_bytes` is called from 14 sites (A, B, S, N, u input, tests).

## 5. Integer Serialization Matrix

| Value | Math | Source type | Length | Order | Padding | Hash input / wire | Rust | Official | Byte-identical? |
|---|---|---|---|---|---|---|---|---|---|
| `N` | 1536-bit prime | BigNum (hex) | 192 B | big-endian | none in M1 (minimal); 192 when sent | M1: minimal; wire: 192 | `prime_n.to_vec()` / pad at line 1271 | 192 B constant in `shelper.dll` `.data` RVA `0xac280` (file offset `0xaa880`, one occurrence) | STRONGLY_INFERRED for the 192 B constant; hash-input width UNKNOWN |
| `g` | 5 | u8 | 1 B | n/a | none | M1: `SHA1([5])` | `sha1(&[g_byte])` | `0x100ac279` = `0x05` (documented) | CONFIRMED value; hash width UNKNOWN |
| `k` | 3 (Rust) / SHA-1 digest (brief) | BigNum from u32 | 1 B as integer | big-endian | n/a | used as BigNum | `BigNum::from_u32(3)` | slot `0x100607d0` pushes literal `3`, passes BN to `0x10060510` | **CONFIRMED**: official slot uses 3; reachability via method table `.data` `0xad74c` |
| `a` | private | SecretBigNum | ≤192 B | big-endian | n/a | not serialized | `random_srp_exponent` (CSPRNG, `[1,N-1]`) | CSPRNG at client; width UNKNOWN | UNKNOWN |
| `b` | private | SecretBigNum | ≤192 B | big-endian | n/a | not serialized | same | same | UNKNOWN |
| `A` | public | BigNum | 192 B | big-endian | left-zero-pad to 192 | wire + u + M1 + M2 | line 778 | official width UNKNOWN (client slot not traced) | UNKNOWN |
| `B` | public | BigNum | 192 B | big-endian | left-zero-pad to 192 | wire + u + M1 | line 1301 | official width UNKNOWN | UNKNOWN |
| `u` | scrambling | BigNum from SHA1 digest | 20 B digest | big-endian integer | input padded to 192 | `SHA1(PAD(A)||PAD(B))` | lines 367-381 | server slot `0x10060810` hashes a BIGNUM byte buffer whose length comes from object field `0xc(%esi)` or `0x10(%esi)` | input width UNKNOWN |
| `S` | shared secret | BigNum | ≤192 B | big-endian | left-zero-pad to 192 before KDF | KDF input | lines 894-895, 1381-1382 | not traced | UNKNOWN |
| `M1`, `M2` | proof | 20 B digest | 20 B | n/a | n/a | see Section 4 | lines 402-441 | not traced | UNKNOWN |

Distinctions applied: a width difference alone is not an endianness mismatch. `to_le_bytes()` uses in `handshake.rs` (lines 254-256, 317, 488-490, 502) and `control_handshake.rs` (lines 588, 598, 670, 707, etc.) are **32-bit protocol step/version fields**, not SRP BIGNUMs. They are not evidence of a little-endian SRP integer.

## 6. Rust Serialization Helper Analysis

- `pad_bignum_bytes(bytes, target)` (lines 288-295): if `len >= target` returns the input **unchanged** (no truncation, no rejection); otherwise prepends `target - len` zero bytes. Output is big-endian, fixed-width when the input is shorter, and variable-width when longer. Zero is one byte (`[0]`) from `BigNum::to_vec()` and becomes 192 zero-padded bytes when padded. Callers relying on the length guard before it (non-canonical length rejection, lines near 1130/1156) make the over-length case unreachable for `A` and `B`; for `S` and `u` the over-length case would pass through unchanged.
- `to_be_bytes()` in `compute_srp_kdf` (lines 390, 394) encodes the 32-bit counter big-endian. Consistent with SHA-1 KDF counter convention; not an SRP integer.
- `encode_identity` (lines 146-153) produces UTF-16 **big-endian** code units. It is used only for the wire item (line 671) and decoded by `decode_identity` (line 156). It is not used for hashing.
- Hashing identity: `compute_srp_x` (line 275) and `compute_srp_m1` (line 419) hash `username.as_bytes()`, i.e. **UTF-8**. The brief says the legacy code hashes UTF-8. This matches the Rust code; whether the official client hashes UTF-16LE is UNKNOWN in this pass (not traced in `0x10060340`).

## 7. Official Binary Analysis

### 7.1 Method tables (`shelper.dll` `.data`)

Pointer table starting at RVA `0xad740` (file offset `0xaa600` + delta `0x1a00`):

| RVA | Pointer | Role (inferred from shape) |
|---|---|---|
| `0xad740` | `0x100602f0` | client slot 0 |
| `0xad744` | `0x10060340` | client slot 1 (`x` routine: two SHA-1 inits, 0x1006037f/0x10060c80 pattern) |
| `0xad748` | `0x10060410` | client slot 2 (BIGNUM arithmetic, no direct SHA-1) |
| `0xad74c` | `0x100607d0` | client slot 3 (**literal `3` passed to BN constructor**) |
| `0xad750` | `0x10060900` | client slot 4 |
| `0xad754` | `0x100609a0` | client slot 5 |
| `0xad75c` | `0x100a3df0` | name pointer ("SRP-6a client (tjw)") |
| `0xad760`–`0xad780` | `0x10060140 … 0x100609a0` | server table; slot 6 at `0xad778` = `0x10060810` (`u`-style routine) |
| `0xad7b4` | `0x100a3e18` | name pointer ("SRP-6a server (tjw)") |

Method-table location and names are CONFIRMED. Slot-to-role assignment is INFERRED from function shape.

### 7.2 Multiplier routine `0x100607d0` (client slot 3)

```
100607d5: push $0x3
100607d7: call 0x1005f6e0          ; BN from the immediate 3
100607ee: call 0x10060510          ; BN-based routine with the multiplier object
100607f6: call 0x1005fa00          ; release multiplier object
```

CONFIRMED: this routine's multiplier is the **integer 3** passed through a BIGNUM object. It does not hash `N`.

### 7.3 Routine `0x10060810` (server slot 6)

```
10060833: call 0x10028810          ; SHA-1 init (96-byte context)
10060838: call 0x1005f4b0          ; BN value
1006083d: mov 0xc(%esi),%edx       ; width/field from the object
10060844: call 0x1005fad0          ; BN -> byte buffer (width = edx)
10060849..10060854: push (%edi),4(%edi); call 0x100285f0   ; SHA-1 update over buffer
```

CONFIRMED: the hashed buffer is a BIGNUM serialization whose length comes from `0x4(%edi)`. The width argument `0xc(%esi)` (or `0x10(%esi)` in the alternate branch, gated by `testb $0x2,0x4(%esi)`) determines the byte width. The value stored in those object fields was not traced; therefore **the 192-byte width of `u`'s input is UNKNOWN in the official binary**.

### 7.4 Searches that did not find an SRP digest of `N`

- `SHA1(N || PAD(g,192))` was not located as a call sequence in the examined slots. A search for SHA-1 update call sites grouped by function (`0x100601b0` … `0x10061790`) found updates whose lengths are register or stack values, not constants; a complete data-flow trace would be required.
- Constant search: the SHA-1 round constant `0x5a827999` is present; it does not identify the k routine.

## 8. Multiplier `k` Verification

Independent computation (separate Python script, `hashlib`, no Rust call):

| Layout | Digest |
|---|---|
| `SHA1(N ‖ PAD(5,192))` | `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233` (matches documented known-answer) |
| `SHA1(N ‖ [5])` (minimal g) | `0c95b5b39ccb66e4461a116269ed055d882b70df` |
| `SHA1(N ‖ reversed PAD(5,192))` | `048c79478a559e6dbf030489b906424b30fc17b1` |
| Rust `RADMIN_SRP_K` = 3 | BigNum `3` (20-byte digest form `0000…0003`) |

Classification:
- The SHA-1 formula and its known-answer value: **CONFIRMED as arithmetic**; **UNKNOWN** whether the official client uses it.
- Official slot `0x100607d0` uses the integer **3**: **CONFIRMED** (disassembly). Reachability: **STRONGLY_INFERRED** through the `.data` method table at `0xad74c`; no direct call site exists, and the caller that dispatches through this table was not traced.
- Therefore the claim "official `k = SHA1(N||PAD(g))`" is **not supported** by the binary as examined, and the Rust value `k = 3` is **consistent with the examined official slot**. Whether a second official path computes the digest is UNKNOWN.
- The Rust test `test_srp_group_parameters` asserts `RADMIN_SRP_K == 3` (line 1559). That test locks the current value; it is not an interoperability proof.

## 9. Scrambling Parameter `u` Verification

- Rust: `u = SHA1(PAD192(A) ‖ PAD192(B))`, digest read as big-endian BigNum (lines 367-381). Client passes padded `A` and received `B`; server passes received `A` (normalized to 192 by F8) and padded `B` (lines 1130-1134, 1301).
- Official: slot `0x10060810` hashes a BIGNUM byte buffer whose width comes from object field `0xc(%esi)`/`0x10(%esi)`. Concatenation order (`A` then `B`) was NOT confirmed in this pass; the two `SHA1` updates in `0x10060810` cover one BIGNUM each and the order of the two calls was not mapped to `A`/`B`.
- Classification: **INFERRED** that the official `u` is `SHA1` over two BIGNUM buffers; **UNKNOWN** width, concatenation order, and whether leading zeros are preserved.

## 10. Public Ephemeral Values `A` and `B`

- Rust client `A`: `pad_bignum_bytes(a.to_vec(), 192)` (line 778). Rust server `B`: same (line 1301).
- Official: the BIGNUM-to-bytes conversion (`0x1005fad0`) takes a runtime width. The value of that width at the `A`/`B` sites was not traced.
- Wire format of `A`/`B` item: fixed 192 bytes in Rust; official width **UNKNOWN**.
- Client and server behavior symmetry in Rust is CONFIRMED by the state machine; official symmetry UNKNOWN.

## 11. Shared Secret `S` Serialization

- Rust: `S` is serialized as `pad_bignum_bytes(S.to_vec(), 192)` before the KDF on both sides (lines 894-895, 1381-1382). The KDF hashes `S_bytes ‖ be32(counter)` (lines 384-400).
- Official: not traced. Whether leading zeros are retained before the KDF is **UNKNOWN**.
- This is the one place where a width difference would change the KDF output for identical mathematical `S`. Its resolution requires tracing the KDF caller (`0x10061790`).

## 12. Identity and Password Byte Boundaries

- Wire identity: UTF-16BE, produced by `encode_identity` (Rust) and by the official byte-swap in `0x10066680` case 0 (already documented, CONFIRMED in earlier phase).
- Hash identity: Rust uses UTF-8 (`as_bytes`). The brief's claim of official UTF-16LE hashing is **UNKNOWN** in this pass.
- Password encoding: Rust uses `password.as_bytes()` (UTF-8). Official caller input type and conversion: **UNKNOWN**. No encoding change is justified.

## 13. Independent Known-Answer Vectors

| Vector | Inputs (exact bytes) | Expected | Rust output | Binary-derived | Byte-for-byte |
|---|---|---|---|---|---|
| `k` (SHA-1 form) | `N` (192 B, `e634471e…`) ‖ `PAD(5,192)` | `7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233` | not computed (Rust uses 3) | none | Rust does not implement this formula |
| `k` (literal) | BigNum `3` | `3` | `RADMIN_SRP_K = 3` | slot `0x100607d0` | consistent |
| `u` | `PAD192(A) ‖ PAD192(B)` | not computed here (A, B require a run) | Rust function exists | none | not verified |
| identity hash | `"user"` UTF-8 vs UTF-16LE | not computed (no official reference) | UTF-8 | none | UNKNOWN |

No official test vector was fabricated. Vectors from the Rust implementation were not used as expected values.

## 14. Documentation Contradictions

| Document (archive branch, not on `main`) | Claim | Verified behavior | Recommended correction |
|---|---|---|---|
| `CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md` (on `main`) | Official `k = SHA1(N‖PAD(g))` | Slot `0x100607d0` uses literal `3`; formula not found in examined path | Mark `k` as UNKNOWN, keep literal-3 evidence |
| `CRYPTO_SRP_SCRAMBLING_VERIFICATION.md` (on `main`) | `u` widths fixed at 192 | Width comes from runtime object field | Mark width UNKNOWN |
| `CRYPTO_SRP_PASSWORD_ENCODING.md` (on `main`) | UTF-16LE identity hashing | Not traced | Mark UNKNOWN |
| Earlier Phase 10.4/10.5 reports (archive branch) | "Rust uses little-endian SRP integers" | Rust SRP integers are big-endian; little-endian uses are 32-bit protocol fields | Retract the claim |

I did not edit these documents (read-only task).

## 15. Test and Validation Results

- `cargo fmt --all -- --check`: exit 0, no differences.
- `cargo check` / `cargo test --locked --all-targets` were not run in this pass; the earlier audit recorded 118 unit tests and 8 integration tests passing on this line. This pass did not re-run them, so no new pass/fail claim is made.
- Tests that pin current behavior: `test_srp_group_parameters` (`RADMIN_SRP_K == 3`), `test_identity_utf16_byte_swapping` (round-trip), `test_random_srp_exponent_bounds_and_bit_length`, `test_validate_srp_public_value_strict_checks`.
- Missing: any known-answer test for `k`, `u`, `S` KDF input, or fixed-width zero-prefix behavior of `pad_bignum_bytes`. The existing "padding" test checks length only through the validators.
- Tests that compare two Rust implementations with the same helper (round-trip, client vs server with `ControlServerSession`) prove internal consistency only.

## 16. Phase 10.5 Implementation Specification

**No implementation is authorized by this report.** The following is the specification that would be required if the evidence supported change. Each item is conditional.

1. `RADMIN_SRP_K` (line 16) and call sites (lines 861, 1283): **do not change** to SHA-1 `k`. Evidence supports literal `3` in the examined official slot. Required before any change: trace the caller that dispatches through the method table at `.data` `0xad74c`.
2. `compute_srp_u` (lines 367-381): **do not change**. Required: determine the width field `0xc(%esi)`/`0x10(%esi)` at the `0x10060810` call site and the order of the two SHA-1 updates.
3. `compute_srp_kdf` input (lines 894-895, 1381-1382): **do not change**. Required: trace the KDF caller `0x10061790` to confirm whether `S` is padded to 192.
4. `pad_bignum_bytes` (lines 288-295): behavior for over-length input (pass-through) is an open risk. A safe future change would reject over-length values at the call site rather than silently passing them. Not implemented here.
5. Identity hash (lines 275, 419): **do not change** UTF-8 to UTF-16LE. Required: trace the official `0x10060340` caller path for the identity bytes.
6. New known-answer tests (only after the above are resolved): `k` form, `u` input, KDF input, pad zero-prefix.
7. Existing tests to update: `test_srp_group_parameters` (locks `k = 3`) must change only together with item 1.

Unknown behavior to leave untouched: password encoding, `A`/`B` official width, `u` width and order, `S` pre-KDF width, identity hash encoding.

Risks of changing the current code: the current Rust path is internally consistent and has been exercised end to end; changing `k`, `u` or `S` widths without evidence would break interoperability assumptions that are currently untested either way.

## 17. Remaining Unknowns

1. Caller of the method-table slot `0x100607d0` (the k routine).
2. Value of object fields `0xc(%esi)` / `0x10(%esi)` / `0x4(%esi)` (`u` width and flag).
3. Order of `A` and `B` in `u` and in `M1`.
4. Width of `A`, `B` and `S` in official BIGNUM-to-bytes conversion (`0x1005fad0`).
5. Official identity hash encoding (UTF-8 vs UTF-16LE).
6. Official password encoding.
7. Whether the second official path (`0x10060410`, BIGNUM arithmetic) computes any digest-based `k`.

## 18. Final Verdict

| Question | Answer |
|---|---|
| Does Rust serialize SRP BIGNUM values big-endian or little-endian? | **Big-endian**, fixed-width 192 B for `A`, `B`, `S` (padded); minimal for `N` in M1. |
| Does `pad_bignum_bytes` match the official padding behavior? | **UNKNOWN**. Rust is left-zero-pad big-endian; official runtime width not traced. |
| Is there a real integer endianness incompatibility? | **NOT CONFIRMED.** The 32-bit `to_le_bytes` uses are protocol fields, not SRP integers. |
| Is there a fixed-width versus variable-width incompatibility? | **UNKNOWN**; official widths for `A`, `B`, `u` input and `S` are not established. |
| Exact bytes for `k`? | Rust: integer 3. Official slot: integer 3 (CONFIRMED). SHA-1 digest form: arithmetic verified, use **UNKNOWN**. |
| Exact bytes for `u`? | Rust: `PAD192(A)‖PAD192(B)`. Official: BIGNUM buffer of runtime width; **UNKNOWN**. |
| How are `A` and `B` serialized on the wire? | Rust: 192 B big-endian. Official: **UNKNOWN**. |
| How is `S` serialized before KDF? | Rust: 192 B big-endian. Official: **UNKNOWN**. |
| Is identity hashing UTF-16LE in the official implementation? | **UNKNOWN** (not traced). |
| What remains unknown about password encoding? | Everything beyond the Rust UTF-8 choice. |
| Which SRP changes are justified for Task 5.5? | **None** on current evidence. |
| Is evidence sufficient to authorize implementation? | **No.** |

Evidence classification used: CONFIRMED (disassembly or independent arithmetic), STRONGLY_INFERRED (table reachability), INFERRED (slot role), UNKNOWN, DISPROVEN (none in this pass).
