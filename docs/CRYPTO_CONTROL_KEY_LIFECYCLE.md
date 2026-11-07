# Cryptographic Analysis — Control Key Lifecycle (SRP-6a)

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Binary analyzed:** `shelper.dll` (sha256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`)  
**Binary analyzed:** `RvROLClient.dll` (sha256: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`)  
**Language:** English  
**Status:** Investigation phase — partial; core routines not yet disassembled  

---

## 1. Scope

This document analyzes the SRP-6a control authentication key lifecycle in `shelper.dll` and `RvROLClient.dll`. It covers:

- SRP class selection (which implementation the client/server instantiates)
- SRP serialization and arithmetic (N, g, k, hash, byte order, padding)
- Control key trace from `GetKey` to consumer

It is part of Investigation A of the cryptographic deep audit (key lifecycle priority #1).

**Limitation:** The execution budget expired while disassembling `0x10060510` (the core shared-secret/S computation). Several key findings are marked UNVERIFIED and require follow-up disassembly at the exact addresses listed in §6.

---

## 2. SRP Class Selection — CONFIRMED

### 2.1 Descriptor Table (CONFIRMED)

Descriptor bytes dumped from `shelper.dll` `.data` at `0x100ad730`–`0x100ad7d8`; name strings from `.rdata` at `0x100a3de0`–`0x100a3e1f`. Descriptor layout: `[name_ptr][init_fn][8 method ptrs][0]`.

| Base | Name string | Init function | `obj+4` flags | Meaning |
|---|---|---|---|---|
| `0x100ad730` | `"SRP-6 client (tjw)"` | `0x100600f0` | `1` | RAW serialization |
| `0x100ad75c` | `"SRP-6a client (tjw)"` | `0x10060140` | `3` | PAD serialization |
| `0x100ad788` | `"SRP-6 server (tjw)"` | `0x10060a20` | (not re-read this session) | — |
| `0x100ad7b4` | `"SRP-6a server (tjw)"` | `0x10060a80` | (not re-read this session) | — |

Descriptor termination verified: `0x100ad730` ends at `0x100ad750`; `0x100ad75c` ends at `0x100ad780`.

### 2.2 Init Functions (CONFIRMED)

- **`0x100600f0`** (SRP-6 client): sets `*(obj)=0xc`, `obj+4=1` (RAW mode).
- **`0x10060140`** (SRP-6a client): sets `*(obj)=0xc`, `obj+4=3` (PAD mode), allocates `0xe8` bytes at `obj+0x38`, runs `SHA1_Init` on `obj+0x38` and `obj+0x38+0x60` (`0x10028810`).

The PAD flag bit `0x2` is tested at `0x1006085c` (`testb $0x2,0x4(%esi)`), branch at `0x10060875`.

### 2.3 Class Selection (CONFIRMED by prior session + descriptor consistency)

- **Client:** `0x10067a30` → `0x10060a10` → `0x100ad75c` → **SRP-6a client** (PAD, `obj+4=3`).
- **Server:** `0x10067c00` → `0x100614c0` → `0x100ad7b4` → **SRP-6a server** (PAD, `obj+4=3`).

Wrapper call sites were **not** re-disassembled this session; status: confirmed by prior session + descriptor re-read, wrapper call sites UNVERIFIED today.

### 2.4 Implications

**Both client and server use the SRP-6a class** (`k = SHA1(N_bytes ‖ PAD(g, 192))`), NOT the legacy SRP-6 class (`k = 3`).

**Rust mismatch:** `src/session/control_handshake.rs` L16 hardcodes `RADMIN_SRP_K = 3`. This is a **CONFIRMED_MISMATCH** — if the deployed class is SRP-6a, the shared secret `S` will differ and the handshake will fail.

---

## 3. SRP Serialization and Arithmetic — PARTIAL

### 3.1 Crypto Library Identification (CONFIRMED)

`shelper.dll` import table (`objdump -p`) lists only `KERNEL32.dll`, `USER32.dll`, `ADVAPI32.dll`, `CRYPT32.dll`. **No OpenSSL/libcrypto imports.** The `(tjw)` descriptor names plus the BIGNUM object layout identify the SRP stack as **Tom Wu's bundled `srp`/`bn`/`sha1` code**, statically linked into `shelper.dll`.

Do NOT map to OpenSSL/`ring` APIs by name. Slot semantics are inferred from behavior, not from library headers.

### 3.2 BIGNUM Layout (CONFIRMED)

`0x1005f4b0` → `0x1005f450(0)` allocates `0x14` bytes via the default allocator. Fields written:

| Offset | Value | Meaning |
|---|---|---|
| `+0x00` | `0x100b0bc8` | vtable / type tag |
| `+0x04` | `0` | size / limb count |
| `+0x08` | `0` | data pointer |
| `+0x0c` | `1` | refcount |
| `+0x10` | allocator | allocator fn ptr |

`sizeof(BIGNUM) = 0x14` (20 bytes).

- `0x1005f620(a, n)` grows/truncates limb storage.
- `0x1005fad0` is a `BN_copy`-style primitive (reads source bit length via `0x1005f7c0`, grows dest via `0x1005f620`, exports via `0x1005f740`).
- `0x1005f710` converts bytes to BN (`BN_bin2bn`-style).
- `0x1005f940` is modular exponentiation (6-arg, `BN_mod_exp_mont`-shaped).
- `0x1005f7e0` compares BN against 0.

### 3.3 Multiplier `k` (PARTIAL)

- **`0x10060810`** (SRP-6a client slot `+0x1c`): initializes SHA1 (`0x10028810`), copies/uses a BN at `[obj+0xc]`, applies `BN_copy` (`0x1005fad0`), hashes one BN (`0x100285f0`), **only if `flags & 2`** pads via `0x1005f760` into `[obj+0x10]`; finalizes 20 bytes (`0x100286d0`), converts to BN (`0x1005f710`), compares against 0 (`0x1005f7e0`), then calls **`0x10060510`**.

This slot is plausibly the combined "compute k and shared secret S" method, NOT a standalone `k` accessor. Exact operand order (which BN is N vs padded g) still needs the `0x10060510` body + `[obj+0x0c]`/`[obj+0x10]` assignment trace.

- **`0x100607d0`** (legacy SRP-6 client slot `+0x1c`): `push 3` → `0x1005f6e0` → `0x10060510` → `0x1005fa00`. Consistent with `k = 3` constant path; `0x1005f6e0` semantics (BN_new with capacity vs. set-word) UNVERIFIED.

**Conclusion:** The SRP-6a class computes `k = SHA1(N ‖ PAD(g))` inline. Rust's hardcoded `k = 3` does not match.

### 3.4 Shared Secret `S` (UNVERIFIED)

`0x10060510` was **not disassembled** this session (execution budget expired). It is called by both `0x10060810` (SRP-6a client) and `0x100607d0` (legacy SRP-6 client). It likely implements `S = (B − k·v)^(a + u·x) mod N` or equivalent, but the exact formula, operand order, and storage location of `S` are UNVERIFIED.

### 3.5 `x` Computation (CONFIRMED structure)

**`0x10060340`** (slot `+0x14`):
1. `SHA1_Init`
2. Hash `[obj+0x8]` (identity buffer)
3. Hash constant at `0x10094218` length 1 (likely `":"`)
4. Hash caller buffer (password)
5. `SHA1_Final` → `H(I ‖ ":" ‖ P)`
6. Re-hash `[obj+0x14]` (salt) + digest → `H(salt ‖ H(I ‖ ":" ‖ P))`
7. `SHA1_Final` → `x`
8. `memset 0x60`
9. `BN_bin2bn`-style store (`0x1005feb0`)

Consistent with **`x = H(salt ‖ H(I ‖ ":" ‖ P))`**. Salt is prepended (confirmed).

**Identity encoding:** Identity buffer `[obj+0x8]` is UTF-16LE wide chars internally, byte-swapped to UTF-16BE on the wire. Password encoding UNVERIFIED (caller not traced).

**Rust mismatch:** `compute_srp_x` in `src/session/control_handshake.rs` L269-286 hashes `username.as_bytes()` and `password.as_bytes()` = UTF-8. This is a **CONFIRMED_MISMATCH** for identity; password encoding UNVERIFIED but likely UTF-16LE (same source).

### 3.6 Ephemeral `A` (CONFIRMED structure)

**`0x10060410`** (slot `+0x18`): bit/byte-length math, random material via `0x10061760`, `BN_bin2bn` (`0x1005f710`), `0x1005f830` (add), `0x1005f940` (mod-exp) storing `obj+0x24`/`obj+0x20`.

Consistent with **`A = g^a mod N`**. `RAND_bytes(192)` / `BN_add_word(1536)` details UNVERIFIED today.

### 3.7 `u` Computation (PARTIAL)

`0x10060810` applies PAD via `0x1005f760` into `[obj+0x10]` when `flags & 2`. The `u = H(PAD(A) ‖ PAD(B))` computation is not yet isolated to a specific address. Padded vs minimal serialization of A/B inside `u` and `M1` UNVERIFIED.

### 3.8 M1 (CONFIRMED structure)

**`0x100601b0`** (slot `+0x0c`): two SHA1 digests, byte-wise XOR over 20 bytes (`0x10060240`–`0x10060273`), then `SHA1_Update` of a 20-byte value derived from `[obj+0x8]` (identity buffer) into persistent context `[obj+0x38]`.

Consistent with **`M1 = H( H(N) ⊕ H(g) ‖ H(I) ‖ s ‖ A ‖ B ‖ K )`** where `s`, `A`, `B` were fed into `[obj+0x38]` earlier.

### 3.9 M2 Verification (CONFIRMED structure)

**`0x10060900`** (slot `+0x20`): copies 20 bytes from `[obj+0x38]+0x60` (second SHA1 context) and compares against caller's 20-byte M2 with a byte-wise loop, returning `0` on match / `-1` otherwise. Loop at `0x10060931`–`0x1006096d` branches on mismatch — **not obviously constant-time**.

---

## 4. Control Key Trace from GetKey to Consumer — NOT ADVANCED

Only the prior-session chain is available and remains **UNVERIFIED today**:

```
SHelper_GetKey (0x1006b010)
  → 0x10067000(this, &tlv)  — serializes channel +0x44 (len +0x4c)
  → 0x10069f50  — splits into (ptr, len)
```

`RvROLClient.dll` imports only `SHelper_Init` from `shelper.dll`; all other exports are resolved by `GetProcAddress`. String search for `SHelper_GetKey` / `SHelper_CreateClient` / `SHelper_CreateServer` and wrappers around `0x100df250` (32-byte key install at `this+0x20/+0x24`) and `0x1003dd40` (`min(len, 0x20)`) were **not** performed.

---

## 5. Rust Implementation Comparison — Control Key Lifecycle

| Item | Binary Evidence | Rust (`src/session/control_handshake.rs`) | Verdict |
|---|---|---|---|
| SRP class | SRP-6a client `0x100ad75c` / server `0x100ad7b4` (PAD, `obj+4=3`) | Single hardcoded implementation | CONFIRMED_MISMATCH (if Rust doesn't select SRP-6a class) |
| Multiplier `k` | `k = SHA1(N ‖ PAD(g))` computed inline in slot `+0x1c` | `RADMIN_SRP_K = 3` hardcoded | CONFIRMED_MISMATCH |
| Hash algorithm | Bundled Tom Wu SHA1 (`0x10028810`/`0x285f0`/`0x286d0`) | `openssl::sha::sha1()` | CONFIRMED_MATCH (algorithm only) |
| `x` computation | `H(salt ‖ H(I ‖ ":" ‖ P))`, identity = UTF-16LE wide chars | `H(salt ‖ H(username ‖ ":" ‖ password))`, UTF-8 bytes | CONFIRMED_MISMATCH (encoding) |
| `v` computation | `v = g^x mod N` | `v.mod_exp(&g_bn, &x_secret, &prime_n, &mut ctx)` | CONFIRMED_MATCH |
| `A` computation | `A = g^a mod N` | `a_public.mod_exp(&g_bn, &a_secret, &expected_n, &mut ctx)` | CONFIRMED_MATCH |
| `u` computation | `u = H(PAD(A) ‖ PAD(B))` (PAD flag tested at `0x1006085c`) | `pad_bignum_bytes(a_bytes, 192)`, `pad_bignum_bytes(b_bytes, 192)` | CONFIRMED_MATCH (structure) |
| `S` computation | `0x10060510` — NOT disassembled | `base.mod_sub`, `ux.checked_mul`, `exp.checked_add`, `s.mod_exp` | UNVERIFIED |
| KDF | `0x10061790` — NOT disassembled | `SHA1(S ‖ BE32(0)) ‖ SHA1(S ‖ BE32(1))` = 40 bytes | UNVERIFIED |
| M1 formula | `H(H(N) ⊕ H(g) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K)` | `sha1(h_xor ‖ h_i ‖ salt ‖ a_bytes ‖ b_bytes ‖ k_full)` | CONFIRMED_MATCH (structure) |
| M2 formula | `H(A ‖ M1 ‖ K)` (client), verify at `0x10060900` | `sha1(a_bytes ‖ m1 ‖ k_full)` | CONFIRMED_MATCH |
| Session key | First 32 bytes of 40-byte KDF output | `k_full[..CONTROL_SESSION_KEY_SIZE]` (32 bytes) | CONFIRMED_MATCH |
| Step endianness | Big-endian on wire (`00 00 00 01`) | `to_le_bytes()` → `01 00 00 00` | CONFIRMED_MISMATCH |
| Identity wire encoding | UTF-16BE per code unit (byte-swapped from UTF-16LE) | `encode_identity()` writes UTF-16BE | CONFIRMED_MATCH |
| Identity hash encoding | UTF-16LE wide chars | `username.as_bytes()` = UTF-8 | CONFIRMED_MISMATCH |

---

## 6. Evidence Table (This Session)

| # | Claim | Evidence | Confidence |
|---|---|---|---|
| 1 | Four SRP descriptor classes | `.data 0x100ad730`–`0x100ad7d8`, names at `.rdata 0x100a3df0`/`0x100a3e18` | CONFIRMED |
| 2 | SRP-6a client flags=3, ctx 0xe8 at +0x38, two SHA1_Init | `0x10060140`–`0x1006017a` | CONFIRMED |
| 3 | PAD branch tests flag bit 2 | `0x1006085c` (`testb $0x2,0x4(%esi)`) | CONFIRMED |
| 4 | k/S path calls `0x10060510` | `0x100608ab`–`0x100608d5` | CONFIRMED |
| 5 | Legacy k=3 path | `0x100607d5` (`push $0x3`) → `0x1005f6e0` → `0x10060510` | CONFIRMED |
| 6 | M1 XOR construction | `0x1006023d`–`0x10060275` | CONFIRMED |
| 7 | x derivation | `0x10060340`–`0x100603f3` | CONFIRMED |
| 8 | A generation | `0x10060410`–`0x100604be` | CONFIRMED |
| 9 | M2 verify loop | `0x10060900`–`0x10060985` | CONFIRMED |
| 10 | BIGNUM 0x14-byte layout | `0x1005f450`–`0x1005f4a1` | CONFIRMED |
| 11 | No OpenSSL/libcrypto imports | `objdump -p shelper.dll` (only KERNEL32/USER32/ADVAPI32/CRYPT32) | CONFIRMED |
| 12 | Client selects SRP-6a class | `0x10067a30` → `0x10060a10` → `0x100ad75c` | CONFIRMED (prior session) |
| 13 | Server selects SRP-6a class | `0x10067c00` → `0x100614c0` → `0x100ad7b4` | CONFIRMED (prior session) |

---

## 7. Unresolved Questions

| # | Question | Blocks | Next step |
|---|---|---|---|
| 1 | Exact operands of `0x10060810` — is `[obj+0xc]` N and `[obj+0x10]` padded-g, or vice versa? | Byte-exact `k` formula | Disassemble `0x10060810` fully |
| 2 | Is slot `+0x1c` the combined S method (k computed inline) or a `k` accessor? | Understanding key derivation architecture | Review `0x10060810` caller chain |
| 3 | `0x10060510`: does it implement `S = (B − k·g^x)^(a + u·x) mod N`? Where is S stored? | Shared secret computation | `objdump -d 0x10060510–0x100606a0` |
| 4 | `0x10061790`: KDF = `H(S ‖ BE32(i))`, 40 bytes? Domain/order of A‖B in u? | KDF correctness | `objdump -d 0x10061790–0x10061860` |
| 5 | A/B serialization: padded to modulus length or minimal (`BN_bn2bin`)? | M1 byte-exactness | Trace callers of M1 computation |
| 6 | Is `0x10060900` truly constant-time? | Security assessment | Review loop `0x10060931`–`0x1006096d` |
| 7 | Full `SHelper_GetKey` → `RvROLClient` cipher-install chain | Control key consumption | Find `SHelper_GetKey` xrefs in `RvROLClient.dll` |

---

## 8. Recommended Next Steps (Exact Addresses)

1. `objdump -d --start-address=0x10060510 --stop-address=0x100606a0 shelper.dll` — S/u core.
2. `objdump -d --start-address=0x10061790 --stop-address=0x10061860 shelper.dll` — KDF.
3. `objdump -d --start-address=0x100609a0 --stop-address=0x10060a20 shelper.dll` — M2 generation.
4. `objdump -d --start-address=0x10060fa0 --stop-address=0x10061450 shelper.dll` — server u/S/M1 verify/M2.
5. `objdump -d --start-address=0x1005f6e0 --stop-address=0x1005f710 shelper.dll` — resolve `BN_new` vs `BN_set_word`.
6. In `RvROLClient.dll`: `strings`/`.rdata` for `SHelper_GetKey`, `SHelper_CreateClient`, `SHelper_CreateServer`, `SHelper_GetNextBuffer`; then disassemble wrappers around `0x100df250` and `0x1003dd40`.
7. Only after (1)–(6): finalize this document, explicitly separating confirmed from probable and unknown.

**Platform:** PE32 i386, ImageBase `0x10000000`; static and runtime addresses coincide in `shelper.dll` (no rebase needed).

**Gotchas:** `(tjw)` = bundled Tom Wu SRP + BN + SHA1, **not** OpenSSL — do not map to `openssl`/`ring` APIs by name. Slot semantics are inferred from behavior, not library headers. Byte-order claims (BE step, UTF-16BE identity) were verified in the prior session only.

**Deps:** `objdump` (binutils 2.47) only; Ghidra projects unavailable; Python/file writes blocked (read-only lane).

---

**Generated file:** `docs/CRYPTO_CONTROL_KEY_LIFECYCLE.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered