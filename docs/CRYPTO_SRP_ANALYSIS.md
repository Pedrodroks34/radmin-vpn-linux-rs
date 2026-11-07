# Cryptographic Analysis — SRP-6a Control Authentication

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Binaries analyzed:** `shelper.dll` (sha256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`), `RvROLClient.dll` (sha256: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`)  
**Language:** English  
**Status:** Investigation phase — evidence-backed, hypotheses clearly marked  

---

## 1. Scope

This document analyzes the SRP-6a control authentication in `shelper.dll` (Family B) and `RvROLClient.dll`, and compares it against the current Rust implementation in `src/session/control_handshake.rs` and `src/session/control.rs`. It is part of Investigation B of the cryptographic deep audit.

All findings are from static disassembly (instruction-level). Dynamic execution was **not possible**; confidence rests on structural and constant-level identity.

---

## 2. SRP Group Parameters

| Parameter | Value | Binary Evidence | Confidence |
|---|---|---|---|
| **N** (modulus) | 1536-bit (192 bytes, big-endian), starts `e634471e75f2d76a…`, ends `…216cd54c7` | `shelper.dll 0x100ac280`, length `0xC0`, pinned via `memcmp` at `0x100699e0` | CONFIRMED |
| **g** (generator) | `0x05` (1 byte) | `shelper.dll 0x100ac279`, descriptor `0x100ac358 → (0x100ac279, 1)` | CONFIRMED |
| **k** (multiplier) | SRP-6a class: `SHA1(N_bytes ‖ PAD(g,192))`, 20-byte digest; legacy class: `BN_set_word(3)` | `0x10060810 → 0x10060510` (SRP-6a); `0x100607d0` `BN_set_word(3)` (legacy vtable `0x100ad74c`) | STRONG INDICATION (role of each class unresolved) |
| **Hash** | SHA-1, standard IV `67452301 efcdab89 98badcfe 10325476 c3d2e1f0`, 20-byte BE output | `0x10028810` (Init), `0x100285f0` (Update), `0x100286d0` (Final) | CONFIRMED |
| **Version** | `3` | `0x1006b1d0` returns `0x3`; `0x1006ab80` checks `param_1 == 3` | CONFIRMED |
| **Group pinning** | Fail-closed `memcmp` of 192-byte N and 1-byte g against pinned table | `0x100699e0` | CONFIRMED |

### 2.1 Critical Conflict on k

The object registered as `"SRP-6a client (tjw)"` (vtable `0x100ad760`, string pointer `0x100ad75c → 0x100a3df0`) derives `k = SHA1(N_bytes ‖ PAD(g,192))`, i.e. canonical SRP-6a per RFC 5054.

The legacy path `BN_set_word(3)` at `0x100607d0` belongs to a *different* vtable slot at `0x100ad74c` (string pointer `0x100ad7b4 → 0x100a3e18`, `"SRP-6a server (tjw)"`).

**Which class the Radmin control channel instantiates was not proven.** This determines whether Rust's `k = 3` is correct or a mismatch. Resolve by cross-referencing the `"SRP-6a client (tjw)"` string / vtable `0x100ad760` from the session constructor in `RvROLClient.dll`.

---

## 3. Handshake State Machine

The wire protocol is a 6-step TLV exchange. Framing confirmed: 4-byte big-endian header `(tag & 0xF8000000) | (length & 0x07FFFFFF)`, followed by payload (`builder 0x100626e0`, parser `0x10062900`). Tag constants asserted by parser bounds checks: `0x10` step (len 4), `0x20` identity (≤ `0x2800`), `0x30` salt, `0x40` N, `0x50` g, `0x60` ephemeral, `0x70` proof (each ≤ `0x2800`).

### 3.1 Step Field Endianness (CONFIRMED)

The builder emits the step as **4-byte big-endian** (`00 00 00 01` for step 1), **NOT** little-endian. The existing `docs/CONTROL_HANDSHAKE_SPEC.md` claim of little-endian step values is **REFUTED**. Class: CONFIRMED for emission; STRONG INDICATION for receive-side dispatch (parser header is big-endian; step dispatch consistent).

### 3.2 Step Table

| Step | Direction | Tags | Payload Semantics |
|---|---|---|---|
| 1 | C→S | `0x10` + `0x20` | step = `00 00 00 01` (BE), identity |
| 2 | S→C | `0x10` + `0x30` + `0x40` + `0x50` | step = `00 00 00 02`, salt, N, g |
| 3 | C→S | `0x10` + `0x60` | step = `00 00 00 03`, A = g^a mod N |
| 4 | S→C | `0x10` + `0x60` | step = `00 00 00 04`, B = g^b mod N |
| 5 | C→S | `0x10` + `0x70` | step = `00 00 00 05`, M1 |
| 6 | S→C | `0x10` + `0x70` | step = `00 00 00 06`, M2 |

### 3.3 Client State Machine (STRONG INDICATION)

Entry/state numbering from jump-table trace at `0x10066fdc`, states `{0,2,4,6}`:

- **State 0:** Build step-1 + identity TLV; identity converted to UTF-16 and **byte-swapped to big-endian per code unit** for the wire; internal buffer stored at object `+0x08`; advance.
- **State 2:** Receive step 2; validate N/g via `0x100699e0`; store salt at `+0x14`; compute `x` (`0x10060340`), then `v = g^x mod N` (`0x100602f0`); random `a` and `A = g^a mod N` (`0x10060410`); send step 3 + A.
- **State 4:** Receive step 4 + B; validate B; compute `u`, `S` (`0x10060810` → `0x10060510`); finalize M1 (`0x100609a0`); send step 5 + M1.
- **State 6:** Receive step 6 + M2; verify (`0x10060900`, slot `+0x1c`); mark established; session key = `K[0..32]`.

### 3.4 Server State Machine (STRONG INDICATION)

Entry `0x100670d0`, dispatcher `DEC EAX` → states 1/3/5 at `0x100676b1` / `0x100673fa` / `0x10067165`:

- **State 1:** Receive step 1 + identity; byte-swap UTF-16 identity back to little-endian (`0x100677d0`); store; send step 2 + salt + N + g.
- **State 3:** Receive step 3 + A; validate; generate `b`, `B` (`0x10060ec0` → `0x10060d80`, `B = g^b`); compute `u`, `S` (`0x10060fa0`); send step 4 + B.
- **State 5:** Receive step 5 + M1; verify (`0x100612f0`); emit M2; send step 6 + M2; mark complete.

**Object layout** (both classes, confirmed from init/destroy and method bodies): `+0x00` class tag (`0xc` client / `0x1c` server), `+0x04` flags = `3` (bit 1 = PAD mode), `+0x08` identity buffer, `+0x0c` N, `+0x10` g, `+0x14` salt buffer, `+0x18` v, `+0x1c` x, `+0x20` own public (A/B), `+0x24` private exponent, `+0x28` u, `+0x2c` S, `+0x30` auxiliary buffer (checked `len>0`), `+0x34` vtable field, `+0x38` hash-context block (`malloc(0xE8)` client / `0x1BC` server).

---

## 4. Mathematical Operations

`PAD(x)` = 192-byte left-zero-padded big-endian; `RAW(x)` = minimal big-endian. `⊕` = byte-wise XOR of 20-byte digests. `H` = SHA-1.

### 4.1 x (CONFIRMED)

Client `0x10060340`, server `0x10060c80`:

```
inner = H( identity_bytes ‖ ":" ‖ password_bytes )     // ":" is DAT_10094218, 1 byte
x     = H( salt_bytes ‖ inner )                        // salt FIRST
v     = g^x mod N                                      // server (0x10060c80) / client 0x100602f0
```

**Salt-before-inner ordering confirmed.** The separator is a 1-byte literal.

### 4.2 k (STRONG INDICATION)

Client `0x10060810`, only in SRP-6a class:

```
k = H( N_bytes ‖ PAD(g) )
```

Padding branch selected by `obj+0x04 & 2`, and `obj+0x04 == 3`, so padded branch is live.

### 4.3 u (CONFIRMED)

Client `0x10060510`, server `0x10060fa0`:

```
u = H( PAD(A) ‖ PAD(B) )
```

Padding branch selected by `obj+0x04 & 2`, and `obj+0x04 == 3`, so padded branch is live.

### 4.4 Ephemeral Generation (CONFIRMED)

`A = g^a mod N` (`0x10060410`), `B = g^b mod N` (`0x10060d80`). Exponent is `RAND_bytes(192)`, then `BN_add_word(a, 1536)` (`0x1005f830` = `BN_copy` + `BN_add_word`). **No rejection sampling** in the binary.

### 4.5 Shared Secret (CONFIRMED)

Client `0x10060510`:

```
base = ( B − k·v ) mod N            // 0x1005f860 = BN_sub, 0x1005f880 = BN_mul, 0x1005f810 = BN_add, 0x1005f8c0 = BN_mod
exp  = a + u·x                      // BN_mod_mul(0x1005f900) for u·x, BN_add for +a
S    = base^exp mod N               // BN_mod_exp 0x1005f940
```

Server `0x10060fa0`:

```
S = ( A · v^u )^b mod N
```

BN wrapper identities verified by decompiling `0x100161a0` (mul), `0x10016770` (sign-aware add), `0x10025d30` (div/mod), `0x100263b0` (mul-then-mod).

### 4.6 KDF (CONFIRMED)

`0x10061790(out, 0x28, S_bytes, S_len)`:

```
K[0..20]  = H( S ‖ BE32(0) )
K[20..40] = H( S ‖ BE32(1) )
```

Counter is 4-byte big-endian; output 40 bytes.

### 4.7 M1 (CONFIRMED ordering)

Client accumulator `ctx+0x00`; server accumulator `ctx+0x60`:

```
M1 = H( H(N) ⊕ H(g) ‖ H(identity_bytes) ‖ salt ‖ A ‖ B ‖ K )
```

Sequence, client: `0x100601b0` appends `H(N)⊕H(g)`, `H(I)`, `salt`; `0x10060410` appends `A`; `0x10060510` appends `B`, then `K` (40 B), then optional auxiliary buffer `obj+0x30`; `0x100609a0` finalizes. Server: `0x10060b10` appends `H(N)⊕H(g)`, `H(I)`, `salt`; `0x10060fa0` appends `A` (peer), `B` (own), `K`.

Optional `obj+0x30` extra block: **UNKNOWN** (writer and whether ever non-empty not determined).

### 4.8 M2

**Client (STRONG INDICATION):** `ctx+0x60` receives `A` (`0x10060410`), then `M1`, then `K` (`0x100609a0`) ⇒ `M2 = H(A ‖ M1 ‖ K)`; compared in `0x10060900`. Verify body not re-disassembled.

**Server (CONFIRMED structure, output slot UNRESOLVED):** `0x100612f0` accepts **two** M1 candidates — first `H(B ‖ A ‖ K)` finalization (`ctx+0x120`), then canonical `M1` (`ctx+0x60`). On canonical path it appends `M1` and `K` to `ctx+0x00` (which holds `A`) ⇒ `M2 = H(A ‖ M1 ‖ K)`. On legacy path it finalizes `ctx+0xC0` (holds `A ‖ K` only) ⇒ `H(A ‖ K)`.

Canonical-path digest destination (`ctx+0x6a` in decompiler output, vs `ctx+0x1A8` read by `0x10061450`) is **UNRESOLVED** — re-disassemble `0x10061000–0x100612F0`.

### 4.9 Security Observations

- **Non-constant-time M1 comparison (CONFIRMED):** `0x100612f0` compares received proof word-by-word with early `goto` on first mismatch — server's M1 check is timing-sensitive.
- **Double-acceptance path (CONFIRMED):** Server accepts two M1 forms, widening the accepted-proof surface. This is deliberate legacy compatibility behavior.

### 4.10 Session Key

40-byte KDF output; `RvROLClient.dll 0x1003dd40` computes `len = min(available, 0x20)` and `0x100df250` installs a 32-byte key (rejects lengths ≤ `0x1f`) through callbacks at `this+0x20` / `this+0x24` (separate encrypt/decrypt key slots).

---

## 5. Rust Implementation Comparison Matrix

| # | Item | Binary Evidence | Rust (`src/session/control_handshake.rs`) | Verdict |
|---|---|---|---|---|
| 1 | N modulus | `0x100ac280`, 192 B BE | `RADMIN_SRP1536_PRIME_HEX` (192 B) | **CONFIRMED_MATCH** |
| 2 | g | `0x100ac279 = 0x05` | `RADMIN_SRP_GENERATOR = 5`, `H(g) = SHA1([5])` | **CONFIRMED_MATCH** |
| 3 | k multiplier | SRP-6a class: `H(N‖PAD(g))`; legacy class: `BN_set_word(3)` | `RADMIN_SRP_K = 3` | **UNVERIFIED** — high risk: if SRP-6a class is used this is a `CONFIRMED_MISMATCH` |
| 4 | SHA-1 hash | Standard SHA-1, 20-byte BE digest | `sha1()` | **CONFIRMED_MATCH** |
| 5 | TLV framing | BE u32 `(tag&0xF8000000)\|(len&0x07FFFFFF)`, tags `0x10…0x70` | `encode_item`/`decode_items` identical mask and BE header | **CONFIRMED_MATCH** |
| 6 | Version | `0x1006b1d0 → 3`; `0x1006ab80` `== 3` | `SHELPER_PROTOCOL_VERSION = 3`, written `to_le_bytes()` (L588) | **PARTIAL_MATCH** — value matches, on-wire endianness of version field unverified |
| 7 | x computation | `H(I‖":"‖P)`, `H(salt‖·)`; identity from object `+0x08` = UTF-16LE wide chars; password passed as wide bytes | `username.as_bytes()` and `password.as_bytes()` = UTF-8 | **CONFIRMED_MISMATCH** (salt-first order matches; byte encoding does not) |
| 8 | KDF | `H(S‖BE32(i))`, 40 B | `0u32.to_be_bytes()` / `1u32.to_be_bytes()`, 40 B | **CONFIRMED_MATCH** |
| 9 | M1 formula | `H(H(N)⊕H(g)‖H(I)‖salt‖A‖B‖K)`; A/B hashed in **RAW** minimal form (`BN_bn2bin` without padding); optional `obj+0x30` block | Ordering identical; `sha1(username.as_bytes())`; A/B passed as caller bytes; no extra block | **PARTIAL_MATCH** — identity encoding mismatch; verify A/B padding at call sites |
| 10 | M2 formula | Canonical path `H(A‖M1‖K)`; legacy path `H(A‖K)`; both accepted on verify | `sha1(a_bytes‖m1‖k_full)` | **PARTIAL_MATCH** — canonical path matches; server accepts legacy second form Rust does not model |
| 11 | Session key | First 32 B of 40-B K (`min(len,32)`, install requires ≥32) | `k_full[..CONTROL_SESSION_KEY_SIZE]` (32) | **CONFIRMED_MATCH** |
| 12 | Validation | Group pinned in `0x100699e0`; ephemeral: `len ≤ 192`, `val < N`, `val != 0`; base `> 1`, `base+1 != N` | `len == 192` (strict), `!= 0`, `< N`, `val mod N != 0`; no group pinning | **PARTIAL_MATCH** — Rust's exact-192 check can reject a valid official peer value whose `BN_bn2bin` form is shorter |
| 13 | Key install | `RvROLClient 0x100df250` sets 32-byte enc/dec keys via `this+0x20`/`this+0x24` | 32-byte key handed to transport | **CONFIRMED_MATCH** |
| 14 | Identity encoding | Wire: UTF-16 **big-endian** (byte-swap of internal UTF-16LE at `0x100667b0`; server swaps back at `0x100677d0`); hashed: **UTF-16LE** | `encode_identity` = UTF-16BE (wire ✔); hashing uses UTF-8 (✘) | **PARTIAL_MATCH** — wire matches, hashed bytes are a `CONFIRMED_MISMATCH` |
| 15 | Step value endianness | 4-byte **big-endian** (`00 00 00 01`) | `1u32.to_le_bytes()` (L670, 780, 910, 1267, 1399, 1456) | **CONFIRMED_MISMATCH** — immediate handshake failure |

---

## 6. Impact Summary

Two defects are **independently fatal** before any crypto is even exercised:

1. **Step endianness (CONFIRMED_MISMATCH):** The step field is emitted little-endian in Rust (`to_le_bytes()`) while the binary emits big-endian (`00 00 00 01`). The server will reject step 1 immediately.
2. **Identity/password encoding (CONFIRMED_MISMATCH):** `x` and `H(I)` hash UTF-8 bytes in Rust while the binary hashes UTF-16LE wide characters. Even with a corrected step field, `x`, `v`, `A`, `S`, `K`, `M1`, `M2` will all differ.

A third latent mismatch:

3. **k value (UNVERIFIED):** If the deployed class is the SRP-6a class (`k = H(N‖PAD(g))`), Rust's hardcoded `k = 3` is a `CONFIRMED_MISMATCH`. If the legacy class is used, `k = 3` matches. The class instantiation must be determined from `RvROLClient.dll`.

And an interoperability risk:

4. **Exact-192 length check (PARTIAL_MATCH):** Rust requires `len == 192` strictly. The binary accepts `len ≤ 192` (padded). A valid official peer whose `BN_bn2bin` form is shorter than 192 bytes (probability ≈ 1/256 per public value with a leading zero byte) would be rejected by Rust.

---

## 7. Evidence Table

| # | Claim | Binary / RVA | Caller → Callee | Constants / Sizes | Class |
|---|---|---|---|---|---|
| 1 | N pinned, 192 B BE | `shelper.dll 0xAC280` | group table `0xAC350` | `0xC0` bytes, `e634471e…` | CONFIRMED |
| 2 | g = 5 | `0xAC279` | table `0xAC358` | 1 byte `0x05` | CONFIRMED |
| 3 | Group pinning, fail-closed | `0x699E0` | state 2 (client), state 1 (server) | `memcmp` 192 + 1 | CONFIRMED |
| 4 | SHA-1 primitives | `0x28810`/`0x285F0`/`0x286D0` | all hash sites | IV `67452301…`, 20-B out | CONFIRMED |
| 5 | TLV builder/parser | `0x626E0` / `0x62900` | all steps | BE header, tags `10,20,30,40,50,60,70`, cap `0x2800` | CONFIRMED |
| 6 | Version = 3 | `0x6B1D0`, `0x6AB80` | handshake | `3` | CONFIRMED |
| 7 | k = H(N‖PAD(g)) | `0x60810 → 0x60510` | client slot 6 | 20-B digest, 192-B pad | STRONG INDICATION |
| 8 | legacy k = 3 | `0x607D0` | vtable `0xad74c` slot 3 | `BN_set_word(3)` | STRONG INDICATION (role unresolved) |
| 9 | x = H(salt‖H(I‖":"‖P)) | `0x60340`, `0x60C80` | client slot 4 / server slot 4 | `":"` = `DAT_10094218` | CONFIRMED |
| 10 | v = g^x mod N | `0x602F0`, `0x60C80` | slots 3/4 | `BN_mod_exp 0x5F940` | CONFIRMED |
| 11 | u = H(PAD(A)‖PAD(B)) | `0x60510`, `0x60FA0` | slots 6 | pad = `obj+0x04 & 2`, `obj+0x04 = 3` | CONFIRMED |
| 12 | S = (B−k·v)^(a+u·x) | `0x60510` | client slot 6 | `BN_sub`/`BN_mul`/`BN_add`/`BN_mod`/`BN_mod_exp` | CONFIRMED |
| 13 | S = (A·v^u)^b | `0x60FA0` | server slot 6 | same BN set | CONFIRMED |
| 14 | Exponent = rand192 + 1536 | `0x60410`, `0x60D80` | slots 5 | `BN_add_word` = `0x5F830` | CONFIRMED |
| 15 | KDF H(S‖BE32(i)), 40 B | `0x61790` | `0x60510`, `0x60FA0` | `0x28`, 4-B BE counter | CONFIRMED |
| 16 | M1 ordering | `0x601B0`, `0x60B10`, `0x60410`, `0x60FA0`, `0x609A0` | slots 2/5/6/8 | 20-B XOR, raw salt, A‖B‖K | CONFIRMED (order) |
| 17 | M2 client = H(A‖M1‖K) | `0x60410`, `0x609A0`, `0x60900` | slots 5/8/7 | 20 + 40 B appended | STRONG INDICATION |
| 18 | M2 server, 2 accepted M1 forms | `0x612F0` | server slot 7 | `ctx+0x120`, `ctx+0x60`, `ctx+0xC0` | CONFIRMED (structure) / UNRESOLVED (canonical output slot) |
| 19 | Non-constant-time M1 compare | `0x612F0` | server slot 7 | wordwise early-exit | CONFIRMED |
| 20 | Session key = first 32 B | `RvROLClient 0x3DD40` → `0xDF250` | key install | `min(len, 0x20)`, reject `≤ 0x1f` | CONFIRMED |
| 21 | Client/server class names | ptrs `0xAD75C`/`0xAD7B4` → strs `0xA3DF0`/`0xA3E18` | vtables `0xAD760`/`0xAD7B8` | `"SRP-6a … (tjw)"` | CONFIRMED |
| 22 | Object + ctx layout | init `0x60140`/`0x60A80` | — | `0xE8` client / `0x1BC` server ctx | CONFIRMED |
| 23 | Identity wire swap | `0x667B0`-region (C), `0x677D0` (S) | states 0/1 | UTF-16LE ↔ BE per code unit | STRONG INDICATION (earlier trace) |

---

## 8. Unresolved Questions

1. **Which class is instantiated?** SRP-6a (`k = H(N‖PAD(g))`) or legacy `k = 3`. Resolve by xref to `"SRP-6a client (tjw)"` string / vtable `0x100ad760` from session constructor in `RvROLClient.dll`.
2. **`obj+0x30` in M1.** `0x10060510`/`0x10060fa0` append this auxiliary buffer to M1 hash when `len > 0`. Writer and whether ever non-empty unknown; if non-empty, M1 differs from Rust.
3. **A/B form inside M1.** Binary hashes `BN_bn2bin` minimal-length publics (unpadded), while `u` uses padded 192-byte forms. Rust's `compute_srp_m1(n_bytes, g_byte, …, a_bytes, b_bytes, …)` must be checked at call sites to see whether `a_bytes`/`b_bytes` are minimal or padded; a leading-zero byte in A or B would change M1.
4. **Password encoding in `x`.** `0x10060c80` hashes caller-supplied password byte string. Almost certainly UTF-16LE (same wide-char source as identity), but caller not captured. If UTF-16LE, Rust's UTF-8 password is a second `CONFIRMED_MISMATCH` inside `x`.
5. **Version/step on-wire endianness.** Step is settled (BE). Version constant written `to_le_bytes()` in Rust; binary only proves value is `3`. Determine wire encoding before claiming match.
6. **Server canonical-M2 output slot.** `0x100612f0` finalizes into `ctx+0x6a` in decompiler output on canonical path, while `0x10061450` reads `ctx+0x1A8`. Re-disassemble `0x10061000–0x100612F0`.
7. **Exact client dispatcher entry.** Jump table at `0x10066fdc` from earlier trace, but Ghidra resolves `0x100665b0–0x100667a7` to logging helper and `0x10066680` is not a function entry. Re-derive dispatcher before quoting state numbers.
8. **Rejection sampling.** Rust rejects exponents outside `(1, N−1)` for up to 128 tries; binary does no sampling (`rand192 + 1536`). Not an interop difference (only `A` matters) but documented behavioral divergence.
9. **`0x10060900` verify body** and `0x1005ff40` vtable wrapper not re-disassembled after tool budget expired; client M2 comparison and `+0x10` slot mapping rest on earlier trace plus vtable bytes.

---

## 8. Documentation Corrections Required

`docs/CONTROL_HANDSHAKE_SPEC.md` is wrong on at least three points:

1. **Step values are big-endian, not little-endian** (current doc claims little-endian).
2. **`0x10060510` is the `u`/`S` computation, not a public-value validator** (current doc mislabels it).
3. **`0x100ad75c`/`0x100ad7b4` are *pointers* to class-name strings, the strings themselves are at `0x100a3df0` (`"SRP-6a client (tjw)"`) and `0x100a3e18` (`"SRP-6a server (tjw)"`)** (current doc implies they are the strings directly).

---

## 9. Evidence Sources

- `shelper.dll` sha256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4` (REA static analysis, VAs listed above)
- `RvROLClient.dll` sha256: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177` (`0x1003dd40`, `0x100df250`)
- `src/session/control_handshake.rs` lines 98–153, 264–442, 588, 670, 780, 910, 1267, 1399, 1456, 981–985, 1463–1467
- `docs/CONTROL_HANDSHAKE_SPEC.md` (claim set; contains the three corrected errors in §4)
- `AGENTS.md` (constraints: no Wine/VM/driver, no invented protocol facts, no proprietary binaries committed)

No `evidence-cache:<id>` refs were available; all evidence is from local binaries.

---

**Generated file:** `docs/CRYPTO_SRP_ANALYSIS.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered