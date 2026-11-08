# Cryptographic Phase 10.4 — Unresolved Questions

**Project:** Radmin VPN Linux client (Rust, independent)
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs
**Language:** English
**Status:** Consolidation of Phase 10.4 (Tasks 4.1–4.4) open items

---

## 1. Scope and Method

This document consolidates every unresolved question that materially affects
interoperability with the official Radmin VPN Windows client
(`Radmin_VPN_2.1.4951.1.exe`), drawn from:

- Task 4.1 — `docs/CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md` (§13)
- Task 4.2 — `docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md` (§16)
- Task 4.3 — `docs/CRYPTO_RSA_KEY_PROVENANCE.md` (§10)
- Task 4.4 — `docs/CRYPTO_PHASE_10_4_GAP_ANALYSIS.md` (§8 Remaining Blockers)

Each item records:

- the question or uncertainty
- current evidence
- why it remains unresolved
- what evidence would resolve it
- the affected subsystem
- priority: Critical / High / Medium / Low

Items already resolved by Tasks 4.1–4.4 are excluded (§4). No item is marked
resolved unless the evidence is sufficient.

Confidence classifications follow the project convention: CONFIRMED /
INFERRED / UNKNOWN. All evidence comes from read-only static binary analysis of
`shelper.dll` (SHA-256 `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`);
consumer binaries `RvROLClient.dll` / `RvControlSvc.exe` were not available for
local analysis.

---

## 2. Consolidated Unresolved Questions

| ID | Priority | Question | Subsystem |
|----|----------|----------|-----------|
| U-1 | Critical | RSession 64→32+32 AES key split mapping and enc/dec assignment | AES key installation (RSession → CChannel) |
| U-2 | High | Server `u` computation unverified; asymmetric `u` real flaw or mutually exclusive paths? | SRP control channel |
| U-3 | High | Password encoding in the binary (UTF-16LE vs UTF-8 vs other) | SRP control channel (verifier `x`) |
| U-4 | Medium | Do both SRP client and server paths execute in the same session? | SRP control channel |
| U-5 | Medium | RSA public exponent `e` value (imported from caller, not hardcoded) | RSA key transport (RSession) |
| U-6 | Medium | Server private key origin (which component supplies the 8 component buffers) | RSA key transport (RSession server) |
| U-7 | Medium | Server `k` provenance — does server-provided `k` match client SHA-1(N‖g)? | SRP control channel (`k`) |
| U-8 | Medium | Is the session key exactly the first 32 bytes of the 40-byte KDF output? | SRP key derivation |
| U-9 | Medium | RSession 12-byte header field semantics (+0x04 / +0x08 / +0x0c) | RSession key transport (RSA plaintext header) |
| U-10 | Medium | Consumer identity — `RvControlSvc.exe` vs `RvROLClient.dll` as RSession consumer | RSession → CChannel hand-off |
| U-11 | Medium | Persistent IV consequence — rekey or reset per frame / session boundary? | AES encryption contexts |

---

## 3. Detailed Items

### U-1. RSession 64→32+32 AES key split mapping and enc/dec assignment
**Priority:** Critical

**Question:** Which half of the 64-byte RSession secret feeds the encrypt
direction and which feeds the decrypt direction, and is the mapping
role-dependent? Equivalently: does the consumer split `secret[0..32]`→enc /
`secret[32..64]`→dec, reverse it, use one key for both directions, or derive
two keys some other way?

**Current evidence:**
- `shelper.dll` requires two separate exactly-32-byte keys: `SetKeyEnc`
  (`0x1006ab00`, vtable slot +0x18 → `AES_set_encrypt_key`, bits=256) and
  `SetKeyDec` (`0x1006aac0`, vtable slot +0x1c → `AES_set_decrypt_key`,
  bits=256); both reject `len != 0x20` (Task 4.2 §7–8, CONFIRMED).
- `CChannel_CreateClient` (`0x1006a8b0`, inner `FUN_1006a630`) requires both
  keys at creation time (CONFIRMED).
- `GetKey` (`0x1006ba80`) returns all 64 bytes verbatim — `shelper.dll`
  performs NO division or transformation (Task 4.2 §7, CONFIRMED).
- Rust `derive_aes256_key_ref` (`famatech.rs`) uses `key_material[..32]` for
  BOTH enc and dec; bytes [32..64] unused (Task 4.4 §6 C4,
  CONFIRMED_MISMATCH).
- The consumer call site between `GetKey` and `SetKeyEnc`/`SetKeyDec` was NOT
  located in `RvROLClient.dll` (disp8 indirect calls defeated static analysis)
  (Task 4.2 §16 Q4; Task 4.4 §8).

**Why it remains unresolved:** The split decision is made by the consumer
(`RvROLClient.dll` or `RvControlSvc.exe`), neither available for local
call-site tracing. `shelper.dll` hands the 64-byte buffer to the consumer as
one contiguous block and performs no split.

**What evidence would resolve it:** Trace `call [reg+disp8]` sites for
`GetKey` (disp8 0xb0), `SetKeyEnc` (0xc0), `SetKeyDec` (0xc4) in
`RvROLClient.dll` and `RvControlSvc.exe`; a `lea reg,[key+0x20]` pattern
between `GetKey` and `SetKey*` would reveal the `[0..32]`/`[32..64]` split
fingerprint (Task 4.2 §17 steps 1–2).

**Subsystem affected:** AES key installation — RSession → CChannel hand-off.

**Interoperability impact:** Complete one-direction failure. If the binary uses
different keys for enc/dec and Rust uses one key for both, traffic encrypted in
one direction cannot be decrypted in the other.

---

### U-2. Server `u` computation unverified
**Priority:** High

**Question:** What is the server-side computation of the SRP multiplier `u`?
Is it `SHA-1(A‖k)` as Task 4.1 inferred, or something else? Is the
client/server `u` asymmetry (client `SHA-1(k‖B)` vs server `SHA-1(A‖k)`) a
real protocol flaw, or are the client and server paths mutually exclusive?

**Current evidence:**
- Client `u = SHA-1(k‖B)` is CONFIRMED (Task 4.1 §9.2).
- Server `u` computation rests on `FUN_10060fa0` (@ `0x10060fa0`), which was
  NEVER disassembled (Task 4.4 §5 C1; CRYPTO_UNRESOLVED_QUESTIONS.md A-iii:
  "NOT DISASSEMBLED (budget expired)").
- Task 4.1's "asymmetric u" claim (labeled CONFIRMED, CRITICAL INCOMPATIBILITY)
  is UNSUPPORTED by instruction-level evidence — the binary functions were
  never disassembled (Task 4.4 §5, resolution C1).
- Rust computes `SHA-1(A‖B)` symmetrically for client and server
  (`control_handshake.rs` `compute_srp_u`) — cannot be confirmed as correct
  without disassembling the binary (Task 4.4 §5).

**Why it remains unresolved:** Budget exhausted before `FUN_10060510` and
`FUN_10060fa0` could be disassembled. No instruction-level evidence exists for
the server `u` hash inputs or byte order.

**What evidence would resolve it:** Disassemble `FUN_10060510` (client S core,
`0x10060510–0x100606a0`) and `FUN_10060fa0` (server S core,
`0x10060fa0` range) in `shelper.dll`; identify the `u` hash inputs and byte
order for both paths; determine whether both paths execute in one session
(see U-4).

**Subsystem affected:** SRP control-channel authentication.

**Interoperability impact:** Complete handshake failure. If `u` differs between
sides, the shared secret `S`, session key `K`, and proofs `M1`/`M2` all
diverge.

---

### U-3. Password encoding in the binary
**Priority:** High

**Question:** What character encoding does the binary use for password hashing
in the SRP verifier `x = SHA-1(salt ‖ H(identity ‖ ":" ‖ password))`? Is the
password UTF-16LE (like the confirmed identity encoding), UTF-8, or another
encoding?

**Current evidence:**
- Identity encoding is CONFIRMED UTF-16LE in the binary (Task 4.1 §7;
  `0x10060340`/`0x10060c80` per CRYPTO_UNRESOLVED_QUESTIONS.md B-4).
- Password encoding was NOT found/traced in `shelper.dll` (Task 4.1 §7;
  Task 4.4 §8 blocker 3). Password hash encoding: UNKNOWN (binary) vs UTF-8
  (Rust).
- Rust `compute_srp_x` hashes `password.as_bytes()` = UTF-8
  (`control_handshake.rs` L276). If the binary uses UTF-16LE, `x` differs,
  cascading to `v`, `A`, `S`, `K`, `M1`, `M2` — complete handshake failure
  (CONFIRMED_MISMATCH if UTF-16LE; inferred, not directly traced).

**Why it remains unresolved:** Password processing code is outside
`shelper.dll` (possibly in `RvROLClient.dll` or `RvControlSvc.exe`); consumer
binaries unavailable for local tracing.

**What evidence would resolve it:** Trace password processing outside
`shelper.dll`; locate the server `x` computation (`0x10060c80`) and its
caller-supplied password byte string; compare byte encoding against UTF-16LE
and UTF-8.

**Subsystem affected:** SRP control channel — verifier `x` computation.

**Interoperability impact:** Complete handshake failure. Wrong password
encoding → wrong `x` → wrong verifier `v` → wrong `A`, `S`, `K`, `M1`, `M2`.

---

### U-4. Whether both SRP client and server paths execute in the same session
**Priority:** Medium

**Question:** Do the SRP-6a client and server descriptor paths (client
descriptor `0x100ad75c` → `FUN_10060810`; server descriptor `0x100ad7b4`
→ `FUN_10060fa0`) ever instantiate in the same session, or are they mutually
exclusive (different roles, different connections)?

**Current evidence:**
- Both descriptors exist in `shelper.dll` `.data` (`0x100ad75c` /
  `0x100ad7b4`) with class name strings "SRP-6a client (tjw)" /
  "SRP-6a server (tjw)" (Task 4.1 §3, CONFIRMED).
- Client descriptor xrefs connect directly to `FUN_10060810` (SRP-6a `k`
  calculation) (CONFIRMED).
- Descriptor existence ≠ usage proof (Task 4.1 §3 NOTE). No evidence that both
  paths execute in one session (Task 4.4 §8 blocker 4).
- If both paths run together with asymmetric `u` (client `SHA-1(k‖B)` vs
  server `SHA-1(A‖k)`), session keys would mismatch (Task 4.1 §9.2).

**Why it remains unresolved:** No live-session tracing, no PCAP containing
decryptable SRP frames, and no consumer-binary call-chain evidence showing both
descriptors instantiated together.

**What evidence would resolve it:** Trace session construction in
`RvROLClient.dll`/`RvControlSvc.exe` to see which descriptor(s) are used; or
decrypt captured control-channel traffic and observe whether client and server
SRP messages appear in one session.

**Subsystem affected:** SRP control channel.

**Interoperability impact:** Conditional. If both paths execute together, the
`u` asymmetry (U-2) becomes a real flaw causing handshake failure. If mutually
exclusive, no impact.

---

### U-5. RSA public exponent `e` value
**Priority:** Medium

**Question:** What is the RSA public exponent `e` supplied by the caller to
`CreateClient`/`CreateServer` (imported at `RSA+0x14` via `BN_bin2bn`)? Is it
the commonly assumed `65537` (`0x010001`)?

**Current evidence:**
- Public exponent is imported from the caller's `e` buffer, NOT hardcoded in
  `shelper.dll` (Task 4.3 §4; Task 4.4 §8 blocker 5). Value unknown.
- `BN_bin2bn` (`0x10008a40`) imports raw big-endian bytes into `RSA+0x14`
  (CONFIRMED).
- Rust assumes `0x010001` = 65537 (unverified against the binary).

**Why it remains unresolved:** The `e` buffer originates in the consumer
(`RvROLClient.dll`/`RvControlSvc.exe`), which was unavailable for local
analysis. No PCAP or memory dump exposes the supplied exponent value.

**What evidence would resolve it:** Confirm the exponent value actually
supplied in observed sessions (PCAP analysis of the RSA plaintext, or consumer
binary tracing of `CreateClient`/`CreateServer` callers); search consumer
`.rdata` for exponent blobs.

**Subsystem affected:** RSA key transport (RSession).

**Interoperability impact:** Conditional. RSA encryption with the wrong public
exponent produces ciphertext the server cannot decrypt — handshake failure. If
the value is 65537 (likely), no impact.

---

### U-6. Server private key origin
**Priority:** Medium

**Question:** Which component supplies the 8 private-key component buffers
(`n`, `e`, `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp`) to `CreateServer`
(`0x1006b8f0`)? Are they embedded in a consumer binary, loaded from a
config/certificate file, or received over the network?

**Current evidence:**
- Server imports all 8 components as caller-supplied `(buf,len)` pairs via
  `FUN_10065f70` → `BN_bin2bn` into `RSA+0x10..+0x2c` (Task 4.3 §3.2,
  CONFIRMED mechanism).
- `shelper.dll` neither generates nor embeds any key material — every buffer
  arrives as a caller argument (CONFIRMED).
- Ultimate origin UNKNOWN; consumer binaries `RvROLClient.dll` /
  `RvControlSvc.exe` unavailable for local analysis (Task 4.3 §3.4;
  Task 4.4 §8 blocker 6).

**Why it remains unresolved:** No local access to consumer binaries; no
`.rdata` key-component blob search performed on them; no callers of
`CreateServer` traced.

**What evidence would resolve it:** Trace `CreateServer` (`0x1006b8f0`)
callers in `RvControlSvc.exe`/`RvROLClient.dll`; search consumer `.rdata` for
256-byte modulus blobs and 8 private-key components; determine whether keys are
static or rotated.

**Subsystem affected:** RSA key transport (RSession server side).

**Interoperability impact:** Complete server-side failure. Without the server's
actual RSA private key, Rust cannot implement the server side of RSession key
establishment.

---

### U-7. Server `k` provenance (does server `k` match client SHA-1(N‖g)?)
**Priority:** Medium

**Question:** The server's SRP multiplier `k` is provided externally at object
offset +0x20 (not computed as SHA-1(N‖g)). Does the server-provided `k` match
the client's `SHA-1(N‖g)`? If not, what value does the server use?

**Current evidence:**
- Client `k = SHA-1(N‖g)` is CONFIRMED (`FUN_10060810` @ `0x10060810`,
  client descriptor offset 0x1c) (Task 4.1 §6.2, CONFIRMED).
- Server `k` is taken externally at object +0x20 by `FUN_10060fa0`
  (Task 4.1 §5, §13 Q1; INFERRED mechanism, value unknown).
- Legacy `k = 3` (`FUN_100607d0`) exists but is NOT referenced by either SRP
  descriptor (Task 4.1 §6.2, CONFIRMED).
- Whether server-provided `k` equals client `SHA-1(N‖g)` could not be
  determined from `shelper.dll` alone (Task 4.1 §3.1).

**Why it remains unresolved:** Requires tracing `RvROLClient.dll` or
`RvControlSvc.exe` callers of `FUN_10060fa0` to observe the value written at
object +0x20. Consumer binaries unavailable.

**What evidence would resolve it:** Trace callers of `FUN_10060fa0`;
compare the externally provided `k` against `SHA-1(N‖g)`; confirm whether the
server uses SRP-6a `k` or a different value.

**Subsystem affected:** SRP control channel (multiplier `k`) / SRP–RSA boundary.

**Interoperability impact:** Complete handshake failure. Mismatched `k` → wrong
`S` → wrong session key and proofs.

---

### U-8. Session key = first 32 bytes of KDF output?
**Priority:** Medium

**Question:** Is the SRP session key exactly the first 32 bytes of the 40-byte
KDF output (`SHA-1(S‖BE32(0)) ‖ SHA-1(S‖BE32(1))`), or are some other bytes
used / transformed?

**Current evidence:**
- KDF = `SHA-1(S‖BE32(0)) ‖ SHA-1(S‖BE32(1))` = 40 bytes, big-endian counter,
  CONFIRMED (`FUN_10061790` @ `0x10061790`) (Task 4.1 §10).
- Session key = first 32 bytes of KDF output: INFERRED/LIKELY in Task 4.1;
  confirmed by Rust source (`control_handshake.rs` first-32-bytes, no
  transformation) but NOT confirmed by binary instruction-level evidence
  (Task 4.1 §13 Q4; Task 4.4 §8 C5).
- All 40 KDF bytes are used in Rust (32 for key, 8+ for M1/M2 proofs) —
  compatibility confirmed on the Rust side, but binary-side usage of bytes
  [32..40] not independently verified.

**Why it remains unresolved:** The binary does not explicitly mark which KDF
bytes become the session key; no wire-level confirmation exists.

**What evidence would resolve it:** Wire traffic analysis confirming the first
32 KDF bytes are used as the AES-256 control-channel key; or disassembly of
the `SHelper_GetKey` control-channel path (`0x1006b010`) showing byte
selection from the 40-byte KDF blob.

**Subsystem affected:** SRP control channel — key derivation.

**Interoperability impact:** Complete control-channel failure if Rust uses the
wrong KDF bytes as the AES key.

---

### U-9. RSession 12-byte header field semantics (+0x04 / +0x08 / +0x0c)
**Priority:** Medium

**Question:** What do the three little-endian u32 header fields in the
76-byte RSA plaintext (12-byte header ‖ 64-byte key) represent semantically?
Are they protocol version, flags, session identifiers, or opaque?

**Current evidence:**
- Plaintext structure CONFIRMED: 76 bytes = `LE32(h0) ‖ LE32(h1) ‖ LE32(h2) ‖ key[64]`
  (Task 4.2 §4; CONFIRMED).
- Header fields read from session +0x04/+0x08/+0x0c, set by `FUN_1006a690`
  from `CreateClient` args h0,h1,h2 (Task 4.2 §4, CONFIRMED).
- Treated as opaque dwords in `shelper.dll`; no semantic binding found
  (Task 4.2 §16 Q2; Task 4.4 §8 C-4). Server stores them at +0x14..+0x1c
  after decryption but never interprets beyond length validation
  (CRYPTO_UNRESOLVED_QUESTIONS.md C-2).

**Why it remains unresolved:** No consumer-binary callers of `CreateClient`
were traced; no PCAP plaintext exposure (RSA-encrypted). Semantics live in the
consumer, not `shelper.dll`.

**What evidence would resolve it:** Trace `CreateClient` (`0x1006b860`)
callers to learn what h0/h1/h2 encode; or decrypt captured RSA transport
frames and correlate header values with session state.

**Subsystem affected:** RSession key transport (RSA plaintext header).

**Interoperability impact:** Conditional. If the header fields encode
version/flags/session IDs that the peer validates, Rust must set them
correctly. If truly opaque, no impact.

---

### U-10. Consumer identity (`RvControlSvc.exe` vs `RvROLClient.dll`)
**Priority:** Medium

**Question:** Which component is the RSession consumer — the one that calls
`SHelper_RSession_GetKey` and then `CChannel_SetKeyEnc`/`SetKeyDec`? Is it
`RvControlSvc.exe`, `RvROLClient.dll`, or another binary?

**Current evidence:**
- `RvROLClient.dll` imports exactly one function from `shelper.dll`:
  `SHelper_Init` (static import, IAT `0x1011121c`); all other shelper
  functions resolved dynamically via `GetProcAddress` (Task 1.2, CONFIRMED;
  KEY_EXCHANGE_ANALYSIS.md §3).
- `RvROLClient.dll` API-table slots +0xb0 (`GetKey`), +0xc0 (`SetKeyEnc`),
  +0xc4 (`SetKeyDec`) are resolved, but NO call sites were located in
  `RvROLClient.dll` (KEY_EXCHANGE_ANALYSIS.md §3.4, §8 U1).
- `SHelper_RSession_GetKey` (`0x1006ba80`) and control-handshake `GetKey`
  (`0x1006b010`) are confirmed separate paths (Task 4.2 §6, E11; CONFIRMED).
- Consumer likely `RvControlSvc.exe` (strong indication, untraced) but not
  confirmed (Task 4.2 §16 Q4; Task 4.4 §8).

**Why it remains unresolved:** disp8 indirect call sweep was cut short by
budget; `RvControlSvc.exe` was not available for local analysis; no consumer
call site between `GetKey` and `SetKey*` found anywhere.

**What evidence would resolve it:** Complete disp8 sweep (`FF 50..57 B0` /
`C0` / `C4`) in `RvROLClient.dll`, `RvControlSvc.exe`, `RvRvpnGui.exe`;
trace instructions between `GetKey` call and `SetKeyEnc`/`SetKeyDec`; check
`rvpn_launcher.exe` and `adapter_hook.dll` if no site in the three known
images (Task 4.2 §17).

**Subsystem affected:** RSession → CChannel hand-off / AES key installation /
overall consumer architecture.

**Interoperability impact:** High if the consumer performs additional key
transformation (KDF, hashing, role-dependent split) unknown to Rust — but no
evidence of such transformation exists (`shelper.dll` performs none).

---

### U-11. Persistent IV consequence (rekey / reset per frame?)
**Priority:** Medium

**Question:** Does the peer ever rekey or reset AES-CBC IVs per frame or per
session boundary? IVs are confirmed zero-initialized at construction and
persistent across frames (updated from the last ciphertext block), but
cross-session behavior is unknown.

**Current evidence:**
- AESCryptor object (0x20c bytes, vftable `0x100832a0`): enc IV at +0x1ec,
  dec IV at +0x1fc, zero-initialized at construction (`FUN_10062b60`),
  persistent across frames, updated from last ciphertext block during CBC
  (Task 4.2 §9; CONTROL_PROTOCOL.md §6.4, CONFIRMED).
- No per-frame IV reset observed within a session; IV reset only on new
  session (new AESCryptor object) (Task 4.2 §9, CONFIRMED within observed
  scope).
- Whether rekey/IV reset occurs across reconnects or session boundaries is not
  determined (CRYPTO_UNRESOLVED_QUESTIONS.md C-6, E-1).

**Why it remains unresolved:** AESCryptor object lifecycle was not traced
across session teardown/reconnect; no evidence of rekey logic in consumer
binaries.

**What evidence would resolve it:** Trace AESCryptor construction/destruction
across reconnects; search consumer binaries for IV re-init (`memset` of
+0x1ec/+0x1fc) or new AESCryptor allocation mid-session.

**Subsystem affected:** AES encryption contexts (control and RSession channels).

**Interoperability impact:** Conditional. If IVs reset/rekey at session
boundaries Rust must match; if truly persistent for the session, current Rust
(persistent IVs) is correct. Dropped/reordered frames break decryption either
way (no resync observed).

---

## 4. Items Explicitly Resolved or Excluded

The following questions from older reports were reviewed and are NOT carried
forward as unresolved, because Tasks 4.1–4.4 resolved them or they do not
materially affect interoperability:

| Item | Disposition | Basis |
|------|-------------|-------|
| Integer serialization mismatch (Rust `to_le_bytes` vs big-endian wire) | RESOLVED — not a mismatch | Rust `pad_bignum_bytes` produces big-endian wire output matching the binary (Task 4.4 §6 C2). Task 4.1 "INCOMPATIBLE" verdict here was a FALSE POSITIVE. |
| Asymmetric `u` computation claimed CONFIRMED | UNSUPPORTED — not confirmed | Binary functions `0x10060510`/`0x10060fa0` never disassembled; claim cannot be confirmed. Tracked as U-2/U-4 instead. |
| Legacy `k=3` SRP-6 class in use | RESOLVED — not used | Legacy `k=3` function `FUN_100607d0` referenced only from `0x100ad74c`, not from either SRP-6a descriptor (Task 4.1 §6.2). |
| KDF = `SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1))` = 40 bytes | RESOLVED — CONFIRMED | `FUN_10061790` @ `0x10061790` (Task 4.1 §10). |
| SRP-6a client class (`k=SHA-1(N‖g)`) | RESOLVED — CONFIRMED | Client descriptor `0x100ad75c` → `FUN_10060810` xref chain (Task 4.1 §3). |
| RSA/SRP separation | RESOLVED — CONFIRMED | Disjoint vtables/functions, no intra-module xrefs in `shelper.dll` (Task 4.3 §6). |
| No KDF on RSession path | RESOLVED — CONFIRMED | Complete callee set of `FUN_1006a2b0` contains no hash calls (Task 4.2 §12). |
| AES-256-CBC, persistent IVs, 0xCC padding, 9-byte trailer | RESOLVED — CONFIRMED | `FUN_10069c20`/`FUN_10069f90`/`FUN_10003b30` (Task 4.2 §10). |
| Famatech trailer not a keyed MAC | RESOLVED — CONFIRMED | Unkeyed: additive checksum → MD5 → fold, no key material enters (Task 4.2 §10; CONTROL_PROTOCOL.md §6.6). |

---

## 5. Consolidated Priority List

| Priority | ID | Item | Subsystem | Primary evidence gap |
|----------|----|------|-----------|---------------------|
| Critical | U-1 | 64→32+32 split mapping and enc/dec assignment | AES key installation | Consumer call sites (GetKey → SetKey*) not located |
| High | U-2 | Server `u` computation unverified | SRP control channel | `FUN_10060510`/`FUN_10060fa0` never disassembled |
| High | U-3 | Password encoding in binary | SRP control channel (verifier `x`) | Password processing outside shelper.dll not traced |
| Medium | U-4 | Both SRP paths in same session? | SRP control channel | No live-session/consumer-binary descriptor usage evidence |
| Medium | U-5 | Public exponent `e` value | RSA key transport | Caller-supplied `e` buffer value unknown |
| Medium | U-6 | Server private key origin | RSA key transport (server) | Consumer binaries unavailable; CreateServer callers untraced |
| Medium | U-7 | Server `k` provenance | SRP control channel (`k`) | Object +0x20 `k` value not observed from callers |
| Medium | U-8 | Session key = first 32 KDF bytes? | SRP key derivation | Binary-side KDF byte selection not confirmed |
| Medium | U-9 | Header field semantics | RSession key transport | Header fields opaque; consumer callers untraced |
| Medium | U-10 | Consumer identity | RSession → CChannel hand-off | No GetKey/SetKey* call site located in any consumer |
| Medium | U-11 | Persistent IV consequence | AES encryption contexts | Cross-session IV lifecycle not traced |

---

## 6. Evidence References

All evidence drawn from read-only static analysis of `shelper.dll`
(SHA-256 `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`),
with cross-references to `RvROLClient.dll`, `RvControlSvc.exe`, `RvRvpnGui.exe`
(where available), and PCAP captures. Source documents:

- `docs/CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md` (Task 4.1)
- `docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md` (Task 4.2)
- `docs/CRYPTO_RSA_KEY_PROVENANCE.md` (Task 4.3)
- `docs/CRYPTO_PHASE_10_4_GAP_ANALYSIS.md` (Task 4.4)
- `docs/KEY_EXCHANGE_ANALYSIS.md` (Phase 1 Task 3.2)
- `docs/CONTROL_PROTOCOL.md` (Phase 1 Task 3.3)
- `docs/CRYPTO_UNRESOLVED_QUESTIONS.md` (prior investigations A–G)

---

**COMPLIANCE:** Documentation only. No Rust source modified. No artifacts
modified (except this new file). No commits or pushes.

**STOP CONDITION:** Task 4.5 deliverable 1 complete.