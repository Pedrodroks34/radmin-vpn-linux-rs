# Cryptographic Analysis — Unresolved Questions

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Commit-base:** df8ce07  
**Language:** English  
**Status:** Investigation phase — consolidated open items  

---\n\n## 1. Scope

This document consolidates every unresolved question from Investigations A–G
(cryptographic deep audit). Each item records:

- The investigation it came from
- The question / gap
- Why it matters (impact if wrong)
- The exact function address(es) or source location to investigate next
- Confidence level of any partial findings

Items are **not** ordered by priority. Priority is left to the implementer
based on which gaps block interoperability.

---\n\n## 2. Investigation A — MD5 Implementation and Digest Folding

### A-1: No dynamic test-vector execution

**Question:** Does the recovered MD5 implementation produce byte-identical output
to RFC 1321 / OpenSSL test vectors on arbitrary inputs?

**Why it matters:** All MD5-related conclusions rest on structural/constant
identity (IV `0x67452301...`, 92-byte context, `0x80` padding, LE assembly,
LE output, RFC round constants). No execution means no 100% proof of
correctness for edge cases (empty input, exact 55/56/64 byte boundaries,
multi-block messages).

**Where to investigate:** `shelper.dll` `0x100638f0` (MD5 wrapper),
`0x10004780` (compression), `0x10004e50` (update), `0x10004f30` (final).
**Method:** Emulate or instrument `shelper.dll` with controlled inputs and
compare against a known-good MD5 implementation.

**Status:** UNKNOWN (blocked — dynamic execution not possible in this session).

---

### A-2: `RvROLClient.dll` call-site identification for Encrypt/DecryptBuffer

**Question:** Which function(s) in `RvROLClient.dll` call
`SHelper_CChannel_EncryptBuffer` (`0x1006aa10`) and
`SHelper_CChannel_DecryptBuffer` (`0x1006a930`)?

**Why it matters:** The trailer (folded MD5 + 0xCC padding) is applied inside
`shelper.dll`, but the call sites determine which protocol layer uses it
(control channel vs RSession vs data channel) and whether any post-trailer
transformation occurs.

**Where to investigate:** `RvROLClient.dll` API table at `api+0xc8` /
`api+0xcc` (set via `GetProcAddress` at `0x1003fd5c–0x1003fd86`),
indirect calls `call [reg+0xc8]` / `call [reg+0xcc]`.

**Status:** UNKNOWN (indirect calls through cached table; `+0xc8/+0xcc`
collide with unrelated struct fields).

---

### A-3: AES decrypt behavior for non-block-aligned input

**Question:** Does `FUN_10062d60` (AES-CBC decrypt, `vtable+8`) reject,
truncate, or over-read when input length is not a multiple of 16?

**Why it matters:** `FUN_10069d70` calls the decrypt slot **before** `0x10069f90`
validates `len % block == 0`. If the decrypt routine does not reject
non-block-aligned input, a malformed packet could cause an out-of-bounds read
or silent decryption of garbage.

**Where to investigate:** `shelper.dll` `0x10069d70` → `0x10062d60`,
`0x10069f90` validation gate at `0x10069fe5–0x1006a010`.

**Status:** UNKNOWN (worth follow-up — possible robustness/DoS surface).

---

### A-4: Purpose attribution of the folded MD5 trailer

**Question:** Is the trailer intended as (a) corruption/format detection for a
legacy transport, (b) a weak anti-tamper measure, or (c) something else?

**Why it matters:** The classification affects how the Rust implementation
should be evaluated. If it is merely format detection, the lack of a keyed MAC
is not a "bug" relative to the original — it is intentional design.

**Where to investigate:** No strings, logs, or caller-level evidence found in
`shelper.dll` or `RvROLClient.dll`. May require analysis of `RvControlSvc.exe`
or original documentation.

**Status:** HYPOTHESIS ("corruption/format detection for a legacy transport"
inferred from construction; no direct evidence).

---

### A-5: Why two MD5 implementations exist

**Question:** Which product paths use the OpenSSL-style `md5_block_asm_data_order`
at `0x10009580` vs the C build at `0x10004780`?

**Why it matters:** The trailer path uses `0x10004780` exclusively. If another
code path uses `0x10009580` with different behavior (e.g., different padding or
output), any component sharing that path would produce different digests.

**Where to investigate:** `shelper.dll` `0x10005050` / `0x10005130` (wrapper
pair reaching `0x10009580`), xrefs from those functions.

**Status:** UNKNOWN (not required for Investigation A).

---

## 3. Investigation B — SRP-6a Control Authentication

### B-1: Which SRP class is instantiated (k = H(N‖PAD(g)) vs k = 3)?

**Question:** Does the deployed control channel use the SRP-6a class
(`k = SHA1(N_bytes ‖ PAD(g, 192))`) or the legacy class (`k = 3`)?

**Why it matters:** Rust hardcodes `RADMIN_SRP_K = 3`. If the binary uses the
SRP-6a class, this is a **CONFIRMED_MISMATCH** and the shared secret `S` will
differ — complete handshake failure.

**Where to investigate:** Cross-reference `\"SRP-6a client (tjw)\"` string at
`0x100a3df0` (ptr `0x100ad75c → vtable 0x100ad760`) and
`\"SRP-6a server (tjw)\"` at `0x100a3e18` (ptr `0x100ad7b4 → vtable
0x100ad7b8`) from the session constructor in `RvROLClient.dll`.

**Status:** UNVERIFIED — highest-priority blocker for SRP interoperability.

---

### B-2: `obj+0x30` auxiliary buffer in M1

**Question:** Does `obj+0x30` ever contain non-empty data, and if so, what is
it? `FUN_10060510`/`FUN_10060fa0` append this buffer to the M1 hash when
`len > 0`.

**Why it matters:** If non-empty, Rust's M1 computation
(`compute_srp_m1` L402-430) which does not include this block will produce a
different M1 — handshake failure.

**Where to investigate:** `shelper.dll` `0x10060510` (client), `0x10060fa0`
(server), writer of `obj+0x30`.

**Status:** UNKNOWN.

---

### B-3: Public value form inside M1 (padded vs minimal)

**Question:** Does the binary hash `A` and `B` in raw minimal `BN_bn2bin` form
or padded 192-byte form inside M1? `u` uses padded forms (CONFIRMED), but M1
hashes A/B as caller-supplied bytes.

**Why it matters:** Rust's `compute_srp_m1` hashes `a_bytes`/`b_bytes` as
passed. A leading-zero byte in A or B would change M1 if padding differs.

**Where to investigate:** Call sites of M1 computation in `shelper.dll`
(`0x10060410` appends A, `0x10060510` appends B), and Rust call sites in
`control_handshake.rs` (`compute_srp_m1` callers at L1267, 1399, 1456).

**Status:** PARTIAL — binary hashes minimal form; Rust call-site padding
unverified.

---

### B-4: Password encoding in x hash

**Question:** Is the password hashed as UTF-16LE wide characters (inferred from
the identity source) or UTF-8? `x = H(salt ‖ H(I ‖ ":" ‖ P))`.

**Why it matters:** Rust's `compute_srp_x` hashes `password.as_bytes()` = UTF-8
(L276). If the binary uses UTF-16LE, `x` differs — cascading to `v`, `A`, `S`,
`K`, `M1`, `M2` — complete handshake failure.

**Where to investigate:** `shelper.dll` `0x10060c80` (server x computation),
caller-supplied password byte string.

**Status:** CONFIRMED_MISMATCH if password is UTF-16LE (inferred, not directly
traced).

---

### B-5: Version field on-wire endianness

**Question:** Is the version value `3` sent as big-endian (`00 00 00 03`) or
little-endian (`03 00 00 00`)? Rust writes `to_le_bytes()` at L588.

**Why it matters:** PCAP captures start after version exchange, so the wire
encoding was never observed. If wrong, the version exchange fails before SRP
begins.

**Where to investigate:** PCAP capture including the 8-byte version frame
`00 00 00 04 03 00 00 00`, or live server testing.

**Status:** PARTIAL_MATCH — value matches, endianness unverified.

---

### B-6: Server canonical-M2 output slot

**Question:** Does `FUN_100612f0` finalize canonical M2 into `ctx+0x6a` or
`ctx+0x1A8`? The decompiler output shows `ctx+0x6a` on the canonical path,
while `0x10061450` reads `ctx+0x1A8`.

**Why it matters:** If the slot is wrong, the server's M2 comparison reads the
wrong digest — either false accept or false reject.

**Where to investigate:** `shelper.dll` `0x10061000–0x100612F0` (server M2
finalization), `0x10061450` (comparison read).

**Status:** UNRESOLVED (re-disassemble required).

---

### B-7: Exact client dispatcher entry

**Question:** What is the exact entry point and jump-table layout of the client
state dispatcher? Earlier trace identified `0x10066fdc` but Ghidra resolves
`0x100665b0–0x100667a7` to logging helper and `0x10066680` is not a function
entry.

**Why it matters:** State numbers (`{0,2,4,6}` for client) and transitions
depend on the correct dispatcher entry.

**Where to investigate:** `shelper.dll` `0x10066fdc` region, client vtable
`0x100ad760`.

**Status:** UNKNOWN (earlier trace unreliable).

---

### B-8: Rejection sampling difference

**Question:** Does the lack of rejection sampling in the binary
(`rand192 + 1536`, no range check) cause any interoperability difference?

**Why it matters:** Rust rejects exponents outside `(1, N−1)` for up to 128
tries. Only `A = g^a mod N` is transmitted, so an out-of-range `a` still
produces a valid `A` (just with slightly different distribution). No
interoperability impact expected, but not proven.

**Where to investigate:** `shelper.dll` `0x10060410` / `0x10060d80` vs Rust
`random_srp_exponent` L298-324.

**Status:** UNVERIFIED (behavioral divergence, no interop impact expected).

---

## 4. Investigation C — RSession Key Establishment

### C-1: 64 → two 32-byte AES keys: split vs derivation

**Question:** Does the consumer split the 64-byte RSession secret as
`key_enc = secret[0..32]`, `key_dec = secret[32..64]`, or does it derive two
keys via a hash/KDF?

**Why it matters:** Rust's `derive_aes256_key_ref` takes `key_material[..32]`
for both enc and dec (same key for both directions). If the binary uses
different keys for enc/dec, traffic encrypted with one direction's key cannot
be decrypted with the other — complete failure in one direction.

**Where to investigate:** `RvControlSvc.exe` `GetProcAddress` resolver +
call sites of `RSession_GetKey` (`0x1006ba80`), `SetKeyEnc` (`0x1006ab00`),
`SetKeyDec` (`0x1006aac0`). No indirect call sites found in
`RvROLClient.dll`.

**Status:** HYPOTHESIS / UNVERIFIED — highest-priority blocker for RSession
interoperability.

---

### C-2: Client 4-byte ACK semantics

**Question:** What does the client's 4-byte ACK value mean? The server stores
`+0x14 = LE32(blob)` but never interprets it beyond length validation.

**Why it matters:** If the ACK is a server-chosen cookie that the client must
echo correctly, Rust must generate it properly. If it is an echo of `+0x04`,
the client must track and return the server's value.

**Where to investigate:** `shelper.dll` client state-2 branch
(`0x1006a5eb` → state 2 → 3), server state-2 branch.

**Status:** UNKNOWN.

---

### C-3: Server RSA key provenance

**Question:** Which component supplies the 8 component buffers
(`n,e,d,p,q,dmp1,dmq1,iqmp`) to `RSession_CreateServer`? Are they embedded in
`RvROLClient.dll` or loaded at runtime?

**Why it matters:** Without the server's actual RSA private key, Rust cannot
implement the server side of RSession key establishment.

**Where to investigate:** `RvROLClient.dll` / `RvControlSvc.exe` callers of
`SHelper_RSession_CreateServer` (`0x1006b8f0`), embedded key data in `.rdata`.

**Status:** UNKNOWN.

---

### C-4: Header field semantics (`+0x04..+0x0c`, `+0x14..+0x1c`)

**Question:** What do the 12-byte header fields and decrypted header fields
represent semantically? They are treated as opaque dwords in `shelper.dll`.

**Why it matters:** If these fields encode protocol version, flags, or
session identifiers, Rust must set them correctly.

**Where to investigate:** `shelper.dll` `FUN_1006a690` (client init copies
12-byte header), `FUN_1006a2b0` server store path.

**Status:** UNKNOWN.

---

### C-5: TwoFishV2 vftable `0x100832c4`

**Question:** Is the TwoFishV2-shaped vftable at `0x100832c4` dead code, or is
it instantiated somewhere not yet found?

**Why it matters:** If instantiated, the cipher might be TwoFish, not AES-256,
in some code path — contradicting the AES-256-CBC conclusion.

**Where to investigate:** `shelper.dll` `.rdata` `0x100832c4`, xrefs to this
vftable.

**Status:** UNKNOWN (likely dead code, no instantiation found).

---

### C-6: Persistent-IV consequence / key rotation

**Question:** Does the peer ever rekey or reset IVs per frame? No key rotation
observed within a session.

**Why it matters:** If IVs are truly persistent and never reset, long sessions
accumulate more ciphertext under the same IV chain. Also, dropped/reordered
frames break decryption until rekeying — no recovery mechanism observed.

**Where to investigate:** `shelper.dll` AESCryptor object lifecycle,
`RvROLClient.dll`/`RvControlSvc.exe` session teardown/rekey logic.

**Status:** UNKNOWN.

---

## 5. Investigation D — RSA Operations

### D-1: Server RSA key provenance (duplicate of C-3)

See C-3. Same question, same impact, same location.

**Status:** UNKNOWN.

---

### D-2: RSA key rotation

**Question:** Does the server ever rotate its RSA key pair during operation?

**Why it matters:** If keys rotate, Rust must handle key rollover and
backward compatibility with old ciphertexts.

**Where to investigate:** `RvROLClient.dll` / `RvControlSvc.exe` key reload
logic after `SHelper_RSession_CreateServer`.

**Status:** UNKNOWN.

---

### D-3: `RSA_free` zeroization

**Question:** Does OpenSSL 1.0.1f's `RSA_free` in this build zeroize key
material before freeing?

**Why it matters:** Affects memory-forensics security assessment, not
interoperability. Do not claim secure wiping in the spec without verification.

**Where to investigate:** OpenSSL 1.0.1f source / binary `RSA_free` behavior.

**Status:** STRONG INDICATION (upstream behavior), unverified in this binary.

---

### D-4: `DecryptBuffer_Private` extra parameter

**Question:** What is the 5th stack argument of `DecryptBuffer_Private`
(`ret $0x14`)? The core takes 3 args; extra out/flag parameter meaning not
recovered.

**Why it matters:** Do not reimplement that export from its name alone —
incorrect assumptions could introduce behavioral divergence.

**Where to investigate:** `shelper.dll` `DecryptBuffer_Private` disassembly.

**Status:** UNKNOWN.

---

## 6. Investigation E — Symmetric Encryption

### E-1: Per-frame IV reset

**Question:** Is the IV ever reset between frames, or is it truly persistent
for the entire session?

**Why it matters:** Rust implements persistent IVs matching the binary. If the
binary resets IVs periodically (e.g., after N frames), Rust would diverge.

**Where to investigate:** `shelper.dll` AESCryptor object `+0x1ec`/`+0x1fc`
lifecycle, any `memset` or re-init of IV buffers.

**Status:** CONFIRMED persistent (no reset observed), but not exhaustively
traced across session boundaries.

---

### E-2: Key rotation

See C-6 / D-2. No key rotation observed.

**Status:** UNKNOWN (not observed → assume none).

---

### E-3: First-block IV = zero weakness

**Question:** Is the all-zero initial IV an intentional design choice or an
oversight?

**Why it matters:** Makes the first block equivalent to ECB encryption. Minor
weakness but not an interop blocker — Rust matches this behavior.

**Where to investigate:** `shelper.dll` AESCryptor constructor
(`FUN_10062b60`), initial IV initialization.

**Status:** CONFIRMED (zero IV at init), intent UNKNOWN.

---

## 7. Investigation G — Rust Implementation Gap Analysis

### G-1: Step value endianness (CONFIRMED_MISMATCH — fix required)

**Rust:** `1u32.to_le_bytes()` → `01 00 00 00` at L670, 780, 910, 1267, 1399,
1456 in `control_handshake.rs`.  
**Binary:** 4-byte big-endian `00 00 00 01`.  
**Impact:** Complete handshake failure — server rejects step 1 immediately.  
**Fix:** Change all step `to_le_bytes()` to `to_be_bytes()`.

---

### G-2: Identity/password encoding in x (CONFIRMED_MISMATCH — fix required)

**Rust:** `username.as_bytes()` / `password.as_bytes()` = UTF-8 at
`compute_srp_x` L274-277.  
**Binary:** UTF-16LE wide chars at `0x10060340`/`0x10060c80`.  
**Impact:** `x` differs → `v`, `A`, `S`, `K`, `M1`, `M2` all differ → complete
handshake failure even with step endianness fixed.  
**Fix:** Hash UTF-16LE byte sequences for username and password.

---

### G-3: Multiplier k (UNVERIFIED — potential CONFIRMED_MISMATCH)

**Rust:** `RADMIN_SRP_K = 3`.  
**Binary:** SRP-6a class uses `k = SHA1(N_bytes ‖ PAD(g, 192))`; legacy class
uses `k = 3`.  
**Impact:** If SRP-6a class is deployed, `S` differs → complete handshake
failure.  
**Fix:** Determine deployed class (B-1); if SRP-6a, compute `k` at runtime.

---

### G-4: Exact-192 length check (PARTIAL_MATCH)

**Rust:** `bytes.len() == 192` strict (L330-337).  
**Binary:** `len ≤ 192` with `val < N`, `val != 0`.  
**Impact:** Valid official peer with leading-zero-byte public value (~1/256
probability) rejected by Rust.  
**Fix:** Accept `len ≤ 192`, left-pad to 192 bytes.

---

### G-5: Version endianness (PARTIAL_MATCH)

**Rust:** `to_le_bytes()` → `03 00 00 00` at L588.  
**Binary:** Value `3` confirmed, wire endianness unknown.  
**Impact:** Version exchange failure if wrong endianness.  
**Fix:** Determine wire encoding from PCAP with version exchange or live test.

---

### G-6: Public value padding in M1 (PARTIAL_MATCH)

**Rust:** Hashes `a_bytes`/`b_bytes` as passed by caller.  
**Binary:** Hashes raw minimal `BN_bn2bin` form.  
**Impact:** If Rust caller passes padded values, M1 differs.  
**Fix:** Verify call sites pass minimal-form (unpadded) public values.

---

### G-7: No control-channel message integration (NOT_IMPLEMENTED)

**Binary:** TLV-structured control messages (Login, LoginResponse,
JoinNetwork, etc.) after SRP-6a handshake.  
**Rust:** `src/protocol/control.rs` defines message types but no integration
with encrypted control channel.  
**Impact:** Control channel cannot carry application messages.  
**Fix:** Implement control message send/receive over the AES-256-CBC channel.

---

### G-8: No RSession-transport integration (PARTIAL)

**Binary:** `RSessionServer` server-side RSA decryption + token emission.  
**Rust:** `RSessionServer` exists in `src/session/handshake.rs` but
integration with transport layer not verified.  
**Impact:** RSession key establishment not wired to actual network transport.  
**Fix:** Wire `RSessionServer`/`ControlClientNegotiator` to `TcpChannel`.

---

### G-9: Tests validate internal consistency only (UNVERIFIED for interop)

**Rust tests:** Use `Rsa::generate(2048)` — generated key, not the original
binary's key. No test against captured PCAP traffic or `RvROLClient.dll`'s
actual RSA public key.  
**Impact:** No evidence of interoperability with the original implementation.  
**Fix:** Add test using the original binary's RSA public key and/or replay
captured PCAP traffic.

---

## 8. Consolidated Priority List for Implementation

| Priority | Issue | Investigation | Binary Address(es) | Rust Location |
|----------|-------|---------------|-------------------|---------------|
| 1 (Critical) | Step value endianness | B-5 / G-1 | `0x100626e0` | `control_handshake.rs` L670, 780, 910, 1267, 1399, 1456 |
| 2 (Critical) | Identity/password encoding in x | B-4 / G-2 | `0x10060340`, `0x10060c80` | `control_handshake.rs` L269-286 |
| 3 (Critical) | Multiplier k class | B-1 / G-3 | `0x10060810`, `0x100ad760`, `0x100ad7b8` | `control_handshake.rs` L16 |
| 4 (High) | 64 → two 32-byte AES key split | C-1 / G- (gap) | `0x1006ba80`, `0x1006ab00`, `0x1006aac0` | `famatech.rs` `derive_aes256_key_ref` |
| 5 (High) | Public value length check | B-5 / G-4 | `0x100699e0` | `control_handshake.rs` L330-337 |
| 6 (Medium) | Version endianness | B-5 / G-5 | `0x1006b1d0` | `control_handshake.rs` L588 |
| 7 (Medium) | Public value padding in M1 | B-3 / G-6 | `0x10060410`, `0x10060510` | `control_handshake.rs` `compute_srp_m1` callers |
| 8 (Low) | Control message integration | G-7 | N/A | `src/protocol/control.rs` |
| 9 (Low) | RSession transport integration | G-8 | `0x1006b8f0`, `0x1006b860` | `src/session/handshake.rs` `RSessionServer` |
| 10 (Low) | Interop test with original key | G-9 | `RvROLClient.dll` RSA public key | `src/session/*` test modules |

---\n\n**Generated file:** `docs/CRYPTO_UNRESOLVED_QUESTIONS.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered