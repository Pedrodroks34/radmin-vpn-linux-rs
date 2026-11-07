# Cryptographic Analysis — RSession Key Lifecycle

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Binary analyzed:** `shelper.dll` (sha256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`)  
**Binary analyzed:** `RvROLClient.dll` (sha256: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`)  
**Binary analyzed:** `RvControlSvc.exe` (sha256: `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`)  
**Language:** English  
**Status:** Investigation phase — consumer not located; key mapping UNKNOWN  

---

## 1. Scope

This document analyzes the RSession 64-byte secret lifecycle in `shelper.dll` and its consumers:

- 64-byte secret generation
- RSA transport (76-byte plaintext → 256-byte ciphertext)
- `GetKey` hand-off to consumer
- Exact directional key mapping (enc vs dec)

It is part of Investigation B of the cryptographic deep audit (key lifecycle priority #2).

**Limitation:** The `call [reg+disp8]` sweep that would locate the `GetKey` consumer was cut short by the execution budget. The consumer binary and exact key mapping are UNKNOWN.

---

## 2. RSession Exchange Reconstruction

### 2.1 Entry Points (CONFIRMED)

| Function | Address | Signature | Role |
|---|---|---|---|
| `SHelper_RSession_CreateClient` | `0x1006b860` | `(u32 h0, u32 h1, u32 h2, void* n, u32 nlen, void* e, u32 elen)` | Client init |
| `SHelper_RSession_CreateServer` | `0x1006b8f0` | `(u32 id, 8 × (buf,len))` | Server init |

Both allocate `malloc(0x34)` (52-byte session object), call `FUN_10069bc0` (constructor), then role-specific init:

- `FUN_1006a690` (client): stores header dwords `h0,h1,h2` at `+0x04/+0x08/+0x0c`, sets role `+0x20=0`, state `+0x24=0`
- `FUN_1006a700` (server): stores `id` at `+0x04`, sets role `+0x20=1`, state `+0x24=1`

Both call `FUN_10065f50` (`RSA_new`) then import key components:
- Client: `FUN_10066170` imports `n` at RSA `+0x10`, `e` at RSA `+0x14`
- Server: `FUN_10065f70` imports full private set `n,e,d,p,q,dmp1,dmq1,iqmp` at RSA `+0x10..+0x2c`

### 2.2 Client State Machine (CONFIRMED)

`FUN_1006a2b0`, role 0, state 0:

```
memset(&local_5c, 0, 0x48)          ; zero plaintext bytes 4..75
local_60 = header[0]  (*(u32*)(this+0x04))
local_5c = header[1]  (*(u32*)(this+0x08))
local_58 = header[2]  (*(u32*)(this+0x0c))
FUN_10063530(&local_54, 0x40)       ; 64 random bytes at plaintext[12..75]
this+0x28 = this+0x2c = 0
free(this+0x30); this+0x30 = malloc(0x40)
this+0x28 = this+0x2c = 0x40; memcpy(this+0x30, &local_54, 0x40)
FUN_10065ec0(this, &local_60, 0x4c, &outbuf)   ; RSA pub-encrypt 76 bytes
FUN_10062ad0(param_3, &outbuf)                   ; move to caller output
state = 2
```

**76-byte plaintext layout (CONFIRMED):** `LE32(h0) ‖ LE32(h1) ‖ LE32(h2) ‖ key[64]`
- Header fields stored as native x86 little-endian 32-bit stores
- Header semantic fields remain opaque

**CSPRNG (CONFIRMED):** `FUN_10063530(buf, 0x40)` → `FUN_10005410()` dispatches `DAT_100b015c[1]` — the OpenSSL 1.0.x `RAND_METHOD.bytes` slot. Randomness comes from the statically linked OpenSSL RAND engine.

**Only 0x4c bytes stored:** client keeps the same 64 bytes at `+0x30` that it transmitted. No client-side KDF between `RAND_bytes` and `+0x30`.

### 2.3 RSA Transport (CONFIRMED at instruction level)

`FUN_10065ec0` (`0x10065ec0`):

```
PUSH ECX                 ; rsa
CALL 0x100092a0          ; RSA_size(rsa) -> 0x100 (256)
PUSH EAX                 ; size
CALL 0x100627a0          ; buffer alloc
PUSH 0x1                 ; padding = 1 = RSA_PKCS1_PADDING
PUSH [EBP-4]             ; rsa
PUSH [ESI+8]             ; to   = buffer->data
PUSH EDI                 ; from = plaintext (76 bytes)
PUSH EBX                 ; flen = 0x4c
CALL 0x100092c0          ; RSA_public_encrypt (meth+4)
```

`FUN_100092c0` = `RSA_METHOD.rsa_pub_enc` at meth+4
`FUN_100092a0` = `RSA_size` reading `rsa+0x10` (`RSA.n`)

Ciphertext length = **256 bytes** for 2048-bit modulus. PKCS#1 v1.5 block = `00 02 FF…FF 00 4C …` (169 bytes of `0xFF` padding) — high-value fingerprint for PCAP correlation.

### 2.4 Server State Machine (CONFIRMED)

`FUN_1006a2b0`, role 1, state 1:

```
FUN_10065db0(this, in, inlen, &outbuf)   ; RSA private decrypt
require outbuf.len == 0x4c
this+0x14 = dword[0]                     ; header[0]
this+0x18 = dword[1]                     ; header[1]
this+0x1c = dword[2]                     ; header[2]
free(this+0x30); this+0x30 = malloc(0x40); memcpy(this+0x30, data+12, 0x40)
state = 2
zeroize+free(decrypt buffer)
out = malloc(4); *out = *(u32*)(this+0x04); state = 3; this+0x10 = 1
```

**Server 4-byte token (CONFIRMED):** its own `CreateServer` arg0 (`+0x04`), NOT derived from client key/header/hash. Client stores reply at `+0x14` and never interprets it.

**Both sides end with:**
- Peer-supplied 4-byte identifier (client `+0x14` ← server `+0x04`; server `+0x14` ← client `h0`)
- Established flag `+0x10 = 1`

**No KDF exists on this path.** Complete callee set of `FUN_1006a2b0`: `{memset, RAND, malloc, memcpy, RSA_pub_enc, RSA_priv_dec, buffer move/zeroize}`. No MD5, SHA-1, HKDF, PBKDF, HMAC, or hash call reachable from client or server RSession establishment.

---

## 3. GetKey Consumer Trace

### 3.1 GetKey Signature (CONFIRMED — CORRECTION)

`shelper.dll!0x1006ba80`:

```c
int SHelper_RSession_GetKey(void *session, void **out_ptr, uint32_t *out_len);
```

Implementation:
```c
FUN_100626c0(local);                 // zero {len,cap,data}
*out_ptr = 0; *out_len = 0;
if (FUN_1006a270(session, local)) {  // guard + COPY
    if (FUN_10069f50(local, out_ptr, out_len)) { FUN_10062b10(local); return 1; }
}
FUN_10062b10(local); return 0;
```

- `FUN_1006a270` requires `+0x10 != 0` (established), `+0x30 != 0`, `+0x28 != 0`, then `FUN_10062800(buf, this+0x30, this+0x28)`
- `FUN_10062800` = `FUN_100627a0(buf, len)` (allocates new heap block of `len`) then `memcpy(buf->data, src, len)`
- `FUN_10069f50` moves ownership out: `*out_ptr = buf->data; *out_len = buf->len;`
- `FUN_10062b10` = destructor: `FUN_1006c120(data, 0, len)` (secure zero-fill) then `free(data)`

**Key consequence:** the consumer receives a **privately owned heap copy of exactly 64 bytes (`+0x28 = 0x40`)** that it must destroy with the zeroize-then-free destructor. The prior claim "GetKey returns `(+0x30, +0x28)`" in `docs/CRYPTO_RSESSION_ANALYSIS.md` is **wrong**.

**Session deletion does not invalidate the consumer's copy** — `SHelper_RSession_Delete` (`0x1006b9e0`) zeroes/frees `+0x30` but the consumer's copy is a separate allocation.

### 3.2 Consumer Location — UNKNOWN

| Check | Result |
|---|---|
| Callers of RSession exports inside `shelper.dll` | Zero (re-verified) |
| `RvROLClient.dll` resolver `FUN_1003fbd0` field map | `GetKey→+0xb0`, `SetKeyEnc→+0xc0`, `SetKeyDec→+0xc4`, `EncryptBuffer→+0xc8`, `CreateClient→+0x98`, `GetNextBuffer→+0xa4` |
| `RvControlSvc.exe` resolver `FUN_00442290` | Identical field map |
| `call [reg+0xb0/c0/c4/98]` disp32 | Zero matches (negative) |
| `call [reg+disp8]` sweep | **NOT COMPLETED** — budget exhausted |
| `RvRvpnGui.exe` | Contains same string block at same VAs; `SHelper_RSession_GetKey` text present |

**The consumer is not located.** Composition is reached via disp8 encoding, copied function-pointer struct, or is dead code in these three images.

---

## 4. Exact Key Mapping Table

| Offset | Length | Transformation | Destination | Purpose | Confidence |
|---|---|---|---|---|---|
| `secret[0..64]` | 64 | none (raw `RAND_bytes`) | session `+0x30` (malloc 0x40) | canonical session secret, both roles | CONFIRMED |
| `secret[0..64]` | 64 | none | 76-byte plaintext `[12..76]` | RSA-PKCS#1 v1.5 transport | CONFIRMED |
| `[12..76]` | 64 | RSA-2048 private decrypt | server session `+0x30` | server-side copy, byte-identical | CONFIRMED |
| `secret[0..64]` | 64 | alloc + `memcpy` (copy) | caller-owned heap via `GetKey` | hand-off to CChannel layer | CONFIRMED |
| `secret → enc key` | 32 | **unknown** | `CChannel+0x04` (`AES_KEY`) | TX direction | UNKNOWN |
| `secret → dec key` | 32 | **unknown** | `CChannel+0xf8` (`AES_KEY`) | RX direction | UNKNOWN |

**Not established:** split `[0..32]`/`[32..64]`, reversed split, identical key both directions, KDF, or role-dependent swap.

`SetKeyEnc`/`SetKeyDec` semantics were **not re-disassembled this session** (prior-session claim: enforce `len == 0x20`, call `AES_set_encrypt_key`/`AES_set_decrypt_key` with bits=256 — UNVERIFIED).

**Structural inconsistency:** A 64-byte secret delivered to a channel API taking exactly two 32-byte keys is inconsistent with Rust's `derive_aes256_key_ref()` returning `key_material[..32]` for **both** directions — leaving 32 bytes unused with no evidence supporting that choice.

---

## 5. Rust Implementation Comparison

| Item | Binary Evidence | Rust (`src/session/handshake.rs`) | Verdict |
|---|---|---|---|
| Secret size | 64 bytes (`0x40`) | `RSESSION_KEY_MATERIAL_SIZE = 64` | CONFIRMED_MATCH |
| Plaintext size | 76 bytes (`0x4c`) | `RSESSION_PLAINTEXT_SIZE = 76` | CONFIRMED_MATCH |
| RSA block size | 256 bytes | `RSESSION_RSA_BLOCK_SIZE = 256` | CONFIRMED_MATCH |
| Header size | 12 bytes | `RSESSION_CLIENT_HEADER_SIZE = 12` | CONFIRMED_MATCH |
| Header layout | 3× LE u32 client_params | `to_le_bytes()` at L254-258 | CONFIRMED_MATCH |
| RSA padding | PKCS#1 v1.5 (mode 1) | `Padding::PKCS1` | CONFIRMED_MATCH |
| RNG | OpenSSL `RAND_METHOD.bytes` | `rand_bytes()` | CONFIRMED_MATCH |
| No KDF | No hash on path | No KDF | CONFIRMED_MATCH |
| Server token | CreateServer arg0 (4 bytes) | `server_token.to_le_bytes()` | CONFIRMED_MATCH |
| Key → enc | UNKNOWN | `key_material[..32]` | **CONFIRMED_MISMATCH** (unsupported) |
| Key → dec | UNKNOWN | `key_material[..32]` (same as enc) | **CONFIRMED_MISMATCH** (unsupported) |
| 64-byte secret usage | All 64 bytes transported | Only first 32 used | **CONFIRMED_MISMATCH** |

---

## 6. Evidence Table

| # | Claim | Evidence | Class |
|---|---|---|---|
| 1 | Client plaintext = 12-byte header + 64 random bytes | `FUN_1006a2b0` body | CONFIRMED |
| 2 | Header = 3× native LE u32 | `FUN_1006a690` stores to `+4/+8/+0xc` | CONFIRMED |
| 3 | RNG = OpenSSL RAND_METHOD.bytes | `FUN_10063530`→`FUN_10005410`→`DAT_100b015c[1]` | CONFIRMED |
| 4 | RSA padding = PKCS#1 v1.5 | `PUSH 0x1` at `0x10065f05`/`0x10065de8` | CONFIRMED |
| 5 | Ciphertext = 256 bytes | `RSA_size` → `0x100` | CONFIRMED |
| 6 | Server requires `len == 0x4c` | server branch of `FUN_1006a2b0` | CONFIRMED |
| 7 | Server token = CreateServer arg0 | `*out = *(u32*)(this+0x04)` | CONFIRMED |
| 8 | Client copy at `+0x30`, `+0x28=+0x2c=0x40` | `malloc(0x40)` + stores | CONFIRMED |
| 9 | GetKey returns owned 64-byte copy | `0x1006ba80` → `FUN_1006a270` → `FUN_10062800` → `FUN_10069f50` | CONFIRMED |
| 10 | Destructor zeroizes then frees | `FUN_10062b10` → `FUN_1006c120` → `free` | CONFIRMED |
| 11 | No KDF/hash on RSession path | complete callee set of `FUN_1006a2b0` | CONFIRMED |
| 12 | Resolver field map | `FUN_1003fbd0`, `FUN_00442290` | CONFIRMED |
| 13 | 64→32+32 key split | no evidence | UNKNOWN |

---

## 7. Unresolved Questions

| # | Question | Blocks | Next step |
|---|---|---|---|
| 1 | Where is `GetKey` called? | Key mapping, consumer architecture | Complete disp8 sweep (`FF 50..57 B0`) |
| 2 | Is the loader reachable? | Whether path is dead code | Trace `FUN_1003fbd0` incoming ref `0x10115d70` |
| 3 | `SetKeyEnc`/`SetKeyDec` byte semantics | Confirm 32-byte enforcement | Disassemble `0x1006ab00`/`0x1006aac0` |
| 4 | Which half feeds which direction; role-dependent? | Key mapping table | Trace call sites between GetKey and SetKey* |
| 5 | Is 64-byte secret re-derived (hashed) in consumer? | KDF possibility | Find consumer, trace post-GetKey calls |

---

## 8. Recommended Next Steps (Exact Addresses)

1. Complete the missed sweep:
   `search_bytes pattern "ff5000" mask "fff800"` in `RvROLClient.dll`, `RvControlSvc.exe`, `RvRvpnGui.exe`; filter `disp8 ∈ {0xb0, 0xb4, 0xc0, 0xc4, 0xc8}`
2. Disassemble `0x1006ab00` (`SetKeyEnc`) and `0x1006aac0` (`SetKeyDec`) in `shelper.dll`
3. Disassemble `0x1006a630` (`CChannel_CreateClient` inner) — confirm two mandatory 32-byte key args
4. Trace instructions between `GetKey` call and `SetKeyEnc`/`SetKeyDec` — `lea reg,[key+0x20]` = `[0..32]`/`[32..64]` split fingerprint
5. If no call site in the three images, check `rvpn_launcher.exe` and `adapter_hook.dll` before concluding dead code

**Platform:** PE32 i386, ImageBase `0x10000000`. No dynamic execution possible.

**Corrections owed to `docs/CRYPTO_RSESSION_ANALYSIS.md`:**
- (a) `GetKey` signature is `bool (session, void**, uint32_t*)` returning a zeroizing heap copy — not `(+0x30,+0x28)`
- (b) Session deletion does not invalidate the consumer's separate allocation
- (c) No KDF exists on the RSession path
- (d) Key mapping E12 remains UNKNOWN with the added constraint that the consumer contract (two 32-byte keys) is unproven

---

**Generated file:** `docs/CRYPTO_RSESSION_KEY_LIFECYCLE.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered