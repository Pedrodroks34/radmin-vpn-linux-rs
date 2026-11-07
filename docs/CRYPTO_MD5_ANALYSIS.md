# Cryptographic Analysis — MD5 Implementation and Digest Folding

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Binary analyzed:** `shelper.dll` (sha256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`)  
**Language:** English  
**Status:** Investigation phase — evidence-backed  

---

## 1. Scope

This document analyzes the MD5 implementation in `shelper.dll`, the 8-byte digest folding operation, the input to the digest, and every consumer of the folded value. It is part of Investigation A of the cryptographic deep audit.

All findings are from static disassembly (instruction-level) of `shelper.dll`. Dynamic execution (test-vector verification) was **not possible** in this session (Python/Wine blocked); confidence rests on exact structural and constant-level identity with RFC 1321 / OpenSSL.

---

## 2. MD5 Implementation

### 2.1 Function Inventory

| Address | Role | Evidence |
|---|---|---|
| `0x10005250` | `MD5_Init(ctx)` | `memset(ctx, 0, 0x5c)`; sets A,B,C,D = `0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`; returns 1 |
| `0x10004e50` | `MD5_Update(ctx, data, len)` | `ecx=data`, `edx=len`, `ctx` pointer; bit-count with carry; block processing |
| `0x10004f30` | `MD5_Final(out, ctx)` | `edi=ctx`; writes `0x80` pad, length field LE, compress, emits 16 LE bytes |
| `0x10004780` | `md5_compress(ctx, data, nblocks)` | `eax=0x54` (0x54 bytes stack via `__chkstk`); loads A/B/C/D from context; nblocks guard |
| `0x10004ccc` | `md5_block` (round constants) | `lea esi,[edx+esi*1+0x6ed9eba1]` — RFC 1321 round-3 constant |
| `0x10009580` | `md5_block_asm_data_order` | OpenSSL-style asm MD5; constants `0xd76aa478`, `0x242070db`, `0x6ed9eba1`; **not** used by trailer path |
| `0x100638f0` | `MD5_of_buffer(out, data, len=8)` | Wrapper: `Init`+`Update`+`Final`; 0x5c-byte context frame; `ret 4` |

### 2.2 Context Structure (CONFIRMED)

The context is 92 bytes, matching OpenSSL `MD5_CTX`:

| Offset | Field | Size |
|---|---|---|
| `+0x00` | A (state word) | 4 bytes |
| `+0x04` | B (state word) | 4 bytes |
| `+0x08` | C (state word) | 4 bytes |
| `+0x0c` | D (state word) | 4 bytes |
| `+0x10` | Nl (low bit count) | 4 bytes |
| `+0x14` | Nh (high bit count) | 4 bytes |
| `+0x18` | data buffer | 64 bytes |
| `+0x58` | num (buffer offset) | 4 bytes |

The wrapper at `0x100638f0` allocates exactly `0x5c` bytes (`[ebp-0x60]`) with the stack cookie at `[ebp-4]`, independently bounding the struct size to 92 bytes.

### 2.3 Update Semantics (CONFIRMED)

- Bit count: `Nl + (len<<3)` with carry into `Nh`; then `Nh += len >> 29`.
- If `num != 0` and `num+len < 0x40`: `memcpy` into `data+num`, `num += len`, return 1.
- Else fill to 64 bytes, `md5_compress(ctx, block, 1)`, `num = 0`.
- Compress `len >> 6` blocks in place; copy tail; `num = tail`.
- `len == 0` returns 1 without touching state. No `data == NULL` check.

### 2.4 Finalize Semantics (CONFIRMED)

Standard RFC 1321 behavior:
1. Write `0x80` at `data[num]`, `num++`.
2. If `num > 0x38` (56): zero-fill to 64, compress, `num = 0`.
3. Zero-fill to 56 bytes.
4. Copy 64-bit bit count **little-endian** from `ctx+0x10..+0x17` into `data[0x38..0x3f]` (byte-by-byte `movzx`/`shr`).
5. Compress final block.
6. `memset(data, 0, 0x40)`; `num = 0`.
7. Emit A,B,C,D as 16 **little-endian** bytes.

**Minor observation:** `MD5_Final` clears only `data` and `num`, never A–D or the full context. The wrapper `0x100638f0` does not wipe its 0x60-byte frame. Digest state and the 8-byte input remain on the stack after return.

### 2.5 Endianness (CONFIRMED)

- Message words assembled byte-by-byte **little-endian** (`0x100047c0–0x100047fb`: `movzx` + `shl` + `or`).
- Bit-length field **little-endian**.
- Digest output **little-endian** (16 bytes).
- This is RFC 1321 / OpenSSL-equivalent behavior, compiled by MSVC.

### 2.6 Second MD5 Copy (CONFIRMED)

`0x10009580` is a separate OpenSSL `md5_block_asm_data_order` implementation (constants `0xd76aa478` encoded as `lea eax,[eax+ebp*1-0x28955b88]`, `0x242070db`, `0x6ed9eba1`). Reached from wrapper pair `0x10005050`/`0x10005130`. **Not used** by the trailer path (which uses `0x10004780` exclusively).

---

## 3. Digest Folding

### 3.1 Location and Code (CONFIRMED)

The fold is **not** inside `MD5_Final`. It lives in the two callers of `MD5_of_buffer`:

**Encrypt path** (`0x10069ce0–0x10069d15`), fully unrolled, 8 iterations:

```
movzx eax, byte [ebp-0xc]   ; digest[8]
add   byte [ebp-0x14], al   ; fold[0] += digest[8]
...
movzx eax, byte [ebp-0x5]   ; digest[15]
add   byte [ebp-0xd], al    ; fold[7] += digest[15]
```

- Destination = same 16-byte buffer the digest was written to: `out = [ebp-0x14]`, so `digest[0..15] = [ebp-0x14 .. ebp-0x5]`.
- `fold[i] = (digest[i] + digest[8+i]) mod 256`, `i = 0..7`, **8-bit `add`**, wraparound, **no carry propagation**.
- High half (`digest[8..15]`) is discarded; low half overwritten by result.
- Output: 8 bytes at `[ebp-0x14]`, copied to `[ebp-0x20]` (`mov eax,[ebp-0x14]` / `mov eax,[ebp-0x10]`), stored with `movq` at `out + total_len - 9`; pad/length byte at `out + total_len - 1` (`0x10069d2a–0x10069d3a`).

**Verifier** (`0x1006a03c–0x1006a074`), identical 8 unrolled `movzx`/`add BYTE` pairs, then `cmp [edi+esi-9], [ecx]` and `cmp [edi+esi-5], [ecx+4]` (`0x1006a077`, `0x1006a07f`).

### 3.2 Algebraic Properties

- The fold is **byte-wise additive**, not XOR.
- It maps 128 bits → 64 bits.
- It is linear over `(Z/256)^8` per coordinate pair **only if** the halves were added as integers; with `mod 256` carry discard, it is an additive-homomorphic projection: `fold(D)` depends only on `D mod 256` per coordinate.
- **Not a cryptographic mixing step.** It is a fixed 64-bit compression of a 128-bit value.

---

## 4. The 8-byte Digest Input

### 4.1 Origin (CONFIRMED)

The call at `0x10069cd7` pushes `[ebp-0x20]` as `ecx` and `edx = 8`, out = `[ebp-0x14]`:

```
lea eax,[ebp-0x14] ; push eax      ; out  (16 bytes)
mov edx,0x8                        ; len = 8
push eax
lea ecx,[ebp-0x20]                 ; data = checksum buffer
call 0x100638f0
```

**Producer: `FUN_1006a0c0(src=[ebp+8], len=[ebp+0xc], out=[ebp+0x10])` (CONFIRMED).**
- `n = len >> 3`; loop: `add ebx,[esi] / adc edi,[esi+4] / add esi,8 / dec n` — **sum of little-endian 64-bit words, with carry into the high dword**, modulo 2^64.
- Remainder `len & 7` bytes accumulated via `__allshl` (`0x1006d680`): byte *j* contributes `byte << (8j)`, i.e. the trailing partial word is **zero-padded on the high end** of a LE64 word.
- Final value = `Σ LE64(words) mod 2^64`, written little-endian (`mov [edx],ecx` low; `mov [edx+4],eax` high).

**Input range:** Called with `len = total_len - 9` over `[esi+8]`, i.e. **message ‖ 0xCC filler**, excluding the 9-byte trailer. `total_len = ((block + 8 + len) / block) * block`, so `total_len - len ∈ [9, block+8]` (no `pad == 8` case; the `+block` term forces a full extra block when `len+8 ≡ 0 mod block`).

**Constancy:** Deterministic function of the plaintext. **No key, no IV, no session/counter input, no global state.** Not a nonce, not a challenge, not random. Varies per message only because the message varies. Always exactly 8 bytes because the producer is a 64-bit sum.

**Consequence:** MD5 is invoked on an 8-byte message with a fixed 8-byte length field, so it always runs **exactly one 64-byte compression block** (8 data + 0x80 + 55 zero + 8 length). The MD5 call is therefore a fixed, keyless 64-bit→128-bit map, followed by the fold back to 64 bits.

---

## 5. Consumer Trace

### 5.1 Call Sites of the Wrapper (CONFIRMED)

Only two call sites of `MD5_of_buffer` (`0x100638f0`) exist in the entire image:

```
0x10069cdb: call 0x100638f0    ; EncryptBuffer path — build trailer
0x1006a037: call 0x100638f0    ; DecryptBuffer path — verify trailer
```

### 5.2 Encrypt Path (`SHelper_CChannel_EncryptBuffer`)

```
0x1006aa10 SHelper_CChannel_EncryptBuffer (export ord 6)
   └ 0x10069e60 (block size from vtable+0xc = 0x10)
       └ 0x10069c20(outStruct, data, len, block)
           ├ 0x100627a0  alloc total_len
           ├ 0x1006c980  memcpy plaintext
           ├ 0x1006a0c0  checksum(len = total_len-9)
           ├ 0x100638f0  MD5(8 bytes)   ← 0x10069cdb
           ├ fold + movq at buf+total_len-9, pad byte at total_len-1
           └ (caller) vtable+4 = 0x10062e00 : AES-CBC encrypt in place, len = total_len
```

### 5.3 Decrypt Path (`SHelper_CChannel_DecryptBuffer`)

```
0x1006a930 SHelper_CChannel_DecryptBuffer (export ord 4)
   └ 0x10069d70
       ├ vtable+8 = 0x10062d60 : AES-CBC decrypt in place (BEFORE any length check)
       └ 0x10069f90(outBuf, outLen, buf, len, block)  ← 0x10069dcb
           ├ reject unless len%block==0, len>9, 9<=pad<block+9, pad<len
           ├ 0x1006a0c0  checksum(len-9)
           ├ 0x100638f0  MD5(8 bytes)   ← 0x1006a037
           ├ fold, compare 8 bytes at buf+len-9
           └ *outBuf = buf, *outLen = len - pad
```

### 5.4 No Other Readers (CONFIRMED)

The fold buffer is a stack local (`[ebp-0x14]`/`[ebp-0x20]`), so it has no symbol or data xref. Its only materialization outside the stack is the 8-byte `movq` into the caller's output buffer. The 8 bytes are therefore visible outside `shelper.dll` **only as ciphertext**, because they are written before the AES pass.

### 5.5 Downstream (CONFIRMED at resolution level, UNKNOWN at call-site level)

- `RvROLClient.dll` import table contains **only** `SHelper_Init` from `Shelper.dll` (ordinal 0x16).
- `SHelper_CChannel_EncryptBuffer` / `DecryptBuffer` are resolved at runtime with `GetProcAddress`: names at `.rdata` `0x10116068` / `0x10116088`, stored into the API table at `api+0xc8` / `api+0xcc` (`RvROLClient.dll` `0x1003fd5c–0x1003fd86`).
- Function-level call sites of those two slots inside `RvROLClient.dll` were **not** isolated (indirect calls through cached table; `+0xc8/+0xcc` also used by unrelated structs). Marked UNKNOWN.

---

## 6. Construction Classification

### 6.1 What It Is (CONFIRMED)

**Unkeyed redundancy/format trailer inside an AES-256-CBC envelope.**

Encode (with `block = 16`, `src` length `L`, `k = pad_len - 9 ∈ [0,15]`):

```
P   = src ‖ 0xCC^k ‖ T
T   = fold8( MD5( LE64( S( src ‖ 0xCC^k ) ) ) ) ‖ pad_len     ; T = 9 bytes
pad_len = total_len - L ,  total_len = ((block+8+L)/block)*block ,  pad_len ∈ [9, block+8]
C   = AES-256-CBC_encrypt(P)        (in place, IV = channel enc IV at obj+0x1ec)
```

Decode reverses this and enforces `len % 16 == 0`, `len > 9`, `9 <= pad_len <= 24`, `pad_len < len`, then compares the recomputed 8-byte fold and returns `len - pad_len`.

### 6.2 What It Is NOT (CONFIRMED by absence of key material)

| Claim | Verdict | Reason |
|---|---|---|
| MAC / authenticated encryption | REFUTED | `S`, `MD5`, fold consume only plaintext; no key, IV, or secret input |
| KDF / PRF / nonce / challenge-response | REFUTED | Value never transmitted in cleartext outside CBC envelope; not fed to key setup (`SetKeyEnc`/`SetKeyDec` accept exactly 0x20 bytes) |
| Password hash | REFUTED | Message-local checksum, not key derivation |

### 6.3 Strength Assessment (CONFIRMED structure, MEDIUM intent)

`S` is a **64-bit word-additive checksum** — order-insensitive and trivially malleable (insert/remove balanced 8-byte words, or permute 8-byte blocks, without changing `S`). `MD5` over only 8 bytes followed by a byte-wise fold yields a 64-bit, keyless, easily computable function; collision finding is bounded by ~2^32 birthday work, and the fold mixes poorly (byte-wise additive).

**The construction provides error/format detection against accidental corruption and naive tampering, NOT cryptographic integrity. Do not model it as a MAC or as AEAD.**

### 6.4 Probable Purpose (HYPOTHESIS)

Padding + length field + self-consistency check for a legacy transport that predates AEAD — reject malformed/truncated packets and establish plaintext length without an explicit length prefix. **No string, log, or caller-level evidence ties it to a stated design intent.**

---

## 7. Evidence Table

| # | Address | Bytes / Instruction | Finding | Verdict |
|---|---|---|---|---|
| E1 | `0x10005250` | `6a 5c / 6a 00 / 56 / e8 …` ; `c7 06 01 23 45 67` … | MD5_Init, memset 0x5c + RFC IV | CONFIRMED |
| E2 | `0x10004e50` | `lea ecx,[eax+edi*8]`, `inc [esi+0x14]`, `shr eax,0x1d` | Bit-count with carry + `len>>29` | CONFIRMED |
| E3 | `0x10004f30` | `mov byte [ebx+esi],0x80`; `cmp ebx,0x38` | 0x80 pad + 0x38 split | CONFIRMED |
| E4 | `0x10004f7d–0x10004fb2` | 8× `movzx` + `mov byte [esi+0x38+n]` | LE 64-bit bit length | CONFIRMED |
| E5 | `0x10004fcb–0x1000503f` | `mov [eax+n],cl` / `shr edx,8` | 16-byte LE digest output | CONFIRMED |
| E6 | `0x10004780` | `mov eax,0x54; call 0x1006d450`; `movzx/shl/or` | MD5 compression, explicit LE word load | CONFIRMED |
| E7 | `0x10004ccc` | `lea esi,[edx+esi*1+0x6ed9eba1]` | RFC round-3 constant in compression body | CONFIRMED |
| E8 | `0x100095ac` | `lea eax,[eax+ebp*1-0x28955b88]` | `-0x28955b88` ≡ `0xd76aa478`; separate OpenSSL-style MD5 | CONFIRMED |
| E9 | `0x100638f0` | `83 ec 60`; ctx `[ebp-0x60]`; `ret 4` | 92-byte context, init/update/final wrapper, returns 1 | CONFIRMED |
| E10 | `0x10069ce0–0x10069d15` | 8× `movzx eax,[ebp-0xc+i]` + `add [ebp-0x14+i],al` | `fold[i]=digest[i]+digest[8+i] mod 256` | CONFIRMED |
| E11 | `0x10069d18–0x10069d3a` | `movq xmm0,[ebp-0x20]`; `movq [eax+ecx-9],xmm0`; `mov [eax+ecx-1],dl` | 8-byte fold at `len-9`, pad byte at `len-1` | CONFIRMED |
| E12 | `0x10069c6b–0x10069c77` | `lea [ecx+8]; add eax,ebx; div ecx; imul eax,ecx` | `total_len = ((block+8+L)/block)*block` | CONFIRMED |
| E13 | `0x10069ca3–0x10069cb4` | `mov byte [eax+ecx],0xcc`; `sub al,bl` | `0xCC` filler, `pad_len` byte | CONFIRMED |
| E14 | `0x1006a0c0` | `add ebx,[esi] / adc edi,[esi+4] / shr eax,3` | 64-bit LE word-additive checksum | CONFIRMED |
| E15 | `0x1006a1d2–0x1006a1e2` | `shl ecx,3; call 0x1006d680` (`__allshl`) | tail byte *j* shifted by `8j` | CONFIRMED |
| E16 | `0x1006a03c–0x1006a074` | 8× `movzx` + `add BYTE [ebp-0x14+i]` | Verifier mirrors fold exactly | CONFIRMED |
| E17 | `0x1006a077`,`0x1006a07f` | `cmp eax,[ecx]` / `cmp eax,[ecx+4]` | 8-byte compare at `buf+len-9` | CONFIRMED |
| E18 | `0x10069fe5–0x1006a010` | `div ecx; test edx,edx`; `cmp esi,9`; `lea eax,[ecx+9]`; `cmp ebx,9` | Validation gate `len%block`, `len>9`, `9<=pad<=block+8`, `pad<len` | CONFIRMED |
| E19 | `0x10069d9b–0x10069dab` | `call [eax+8]` before `0x10069f90` | CBC decrypt runs before length validation | CONFIRMED (code order) |
| E20 | `0x1006aa10` | `lea ebx,[ebp-0xc]`; `call 0x10069e60`; `ret 0x14` | `EncryptBuffer(this,src,len,*outBuf,*outLen)` | CONFIRMED |
| E21 | `0x1006a930` | `call 0x10069d70`; `ret 0x14` | `DecryptBuffer` symmetric to E20 | CONFIRMED |
| E22 | Export ord 4/6 | EAT `0006a930` / `0006aa10` | export → address mapping | CONFIRMED |
| E23 | `0x10069ed2` / `0x10069dcb` | single `call` each | sole callers of `0x10069c20` / `0x10069f90` | CONFIRMED |
| E24 | `0x1006aac0`,`0x1006ab00` | `cmp eax,0x20` ; `call [eax+0x1c]` / `[eax+0x18]` | Key length fixed at 32 bytes | CONFIRMED |
| E25 | `RvROLClient 0x1003fd64–0x1003fd86` | `push 0x10116068` / `0x10116088`; `mov [ebx+0xc8],eax` | Dynamic `GetProcAddress` of Encrypt/DecryptBuffer into API table | CONFIRMED |
| E26 | `RvROLClient` import | `SHelper_Init` only | No static binding to cipher exports | CONFIRMED |

---

## 8. Independent Verification (A.7)

**PARTIAL.** Dynamic execution was blocked in this session (Python/Wine unavailable). No RFC 1321 test vectors were executed. However, the following were verified independently of the fold logic:

- IV (`0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`)
- 92-byte context layout
- `0x80` padding rule
- `> 0x38` extra-block rule
- LE bit-count field
- LE message-word assembly
- LE digest output (16 bytes)
- RFC 1321 round constants (`0xd76aa478`, `0x242070db`, `0x6ed9eba1`)

All match the reference algorithm exactly, so byte-for-byte agreement with RFC 1321 vectors follows from algorithm identity rather than from execution.

---

## 9. Unresolved Questions

1. **No dynamic test-vector run.** RFC 1321 vectors not executed. Confidence rests on structural/constant identity. *(Blocked, external.)*
2. **`RvROLClient.dll` call-site identification.** Which function feeds `api+0xc8`/`api+0xcc` was not resolved; calls are indirect through a cached table and `+0xc8` collides with unrelated struct fields. *(UNKNOWN.)*
3. **AES layer behavior for non-block-aligned input on decrypt.** `0x10069d70` calls `vtable+8` before `0x10069f90` validates `len % block == 0`. Whether `0x10062d60` truncates, over-reads, or rejects is undetermined. *(Worth follow-up — possible robustness/DoS surface.)*
4. **Purpose attribution.** "Corruption/format detection for a legacy transport" is a HYPOTHESIS inferred from construction; no string, log, or caller-level evidence ties it to stated design intent.
5. **Why two MD5 implementations exist** (`0x10004780` C build vs `0x10009580` OpenSSL asm) and which product paths use the asm copy beyond `0x10005050`/`0x10005130`. *(Not required for A; UNKNOWN.)*

---

**Generated file:** `docs/CRYPTO_MD5_ANALYSIS.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered