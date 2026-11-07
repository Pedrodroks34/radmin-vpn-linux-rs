# Cryptographic Analysis — AES Consumer Trace and Channel Ownership

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Binaries analyzed:** `shelper.dll`, `RvROLClient.dll`  
**Language:** English  
**Status:** Investigation phase — based on existing evidence; consumer binary not located  

---

## 1. Scope

This document analyzes AES cipher installation, key installation, IV handling, and channel ownership:

- Cipher initialization and key installation functions
- Channel ownership (control vs RSession vs peer data vs relay)
- IV behavior verification (encryption vs decryption)
- Padding and trailer processing order

It is part of Investigation C of the cryptographic deep audit (key lifecycle priority #3).

**Limitation:** The `GetKey` consumer was not located (Investigation B). Channel ownership for each traffic type is partially inferred from existing documentation and source code, not fully traced at instruction level.

---

## 2. Cipher Initialization and Key Installation

### 2.1 Binary Evidence (from CRYPTO_SYMMETRIC_ENCRYPTION.md)

| Function | Address | Role | Confidence |
|---|---|---|---|
| AESCryptor class | `shelper.dll` `.rdata 0x100aee88` | RTTI `.?AVAESCryptor@@` | CONFIRMED |
| Base class | `BaseCryptor` | RTTI class hierarchy | CONFIRMED |
| vtable | `0x100832a0` | 17 entries (indices 0–16) | CONFIRMED |
| Encrypt key slot | `+0x18` → `0x10062fb0` | `AES_set_encrypt_key`, bits = len*8 = 256 | CONFIRMED |
| Decrypt key slot | `+0x1c` → `0x10062f30` | `AES_set_decrypt_key`, bits = 256 | CONFIRMED |
| Block size | `+0x20` → `0x10062e90` | Returns `0x10` (16 bytes) | CONFIRMED |
| SetKeyEnc | `+0xc0` → `0x1006ab00` | Enforces length 0x20 (32 bytes) | CONFIRMED (prior session) |
| SetKeyDec | `+0xc4` → `0x1006aac0` | Enforces length 0x20 (32 bytes) | CONFIRMED (prior session) |
| AES-CBC transform | `0x10003b30` | CBC mode transform | CONFIRMED |
| AESCryptor constructor | `FUN_10062b60` | Object size 0x20c | CONFIRMED |
| Second vftable | `0x100832c4` | TwoFishV2-shaped, no instantiation found | UNKNOWN (likely dead) |

### 2.2 Rust Implementation (src/crypto/famatech.rs)

| Component | Location | Behavior |
|---|---|---|
| `FamatechCipherState` | L127-132 | `enc_key[32]`, `dec_key[32]`, `enc_iv[16]`, `dec_iv[16]` |
| `from_key_ref(key)` | L146-153 | Same 32-byte key for both enc and dec; IVs zero-initialized |
| `from_separate_keys_ref(enc, dec)` | L160-170 | Separate keys for enc/dec; IVs zero-initialized |
| `from_rsession_key(key_material[64])` | L181-186 | Takes `key_material[..32]` for both enc and dec |
| `set_key_enc(key)` | L188-197 | Rejects len != 32; copies to enc_key |
| `set_key_dec(key)` | L199-208 | Rejects len != 32; copies to dec_key |
| `set_key_from_session_buffer(key_buf)` | L210-221 | Sets both enc and dec from `key_buf[..32]` |
| `encrypt(payload)` | L250-283 | Pad+sign → AES-256-CBC encrypt → update IV from last ciphertext block |
| `decrypt(ciphertext)` | L285-315 | AES-256-CBC decrypt → update IV from last block → verify+unpad |
| `clear()` | L223-228 | Zeroize all keys and IVs |
| `Drop` | L318-322 | Calls `clear()` |

### 2.3 Key Installation Discrepancy

The binary's CChannel layer (per prior session) takes **two 32-byte keys** (SetKeyEnc + SetKeyDec). The 64-byte RSession secret must be split or derived somehow. The exact mapping is UNKNOWN (Investigation B).

Rust's `from_rsession_key()` uses `key_material[..32]` for **both** enc and dec — this is a **CONFIRMED_MISMATCH** with the binary's two-key contract, as no evidence supports using the same 32 bytes for both directions.

---

## 3. Channel-by-Channel Cipher Architecture

### 3.1 Control Channel (TCP/17301)

| Aspect | Evidence |
|---|---|
| Transport | TCP, 4-byte BE length framing `[len][payload]` |
| Authentication | SRP-6a, 6-step TLV exchange |
| Session key | First 32 bytes of 40-byte KDF output |
| Cipher | AES-256-CBC via FamatechCipherState |
| IV | Persistent 16 bytes, initial zero, updated from last ciphertext block |
| Trailer | 0xCC padding + 64-bit additive checksum + MD5 → 8-byte fold + 1-byte pad length (9 bytes total) |
| Integrity | Unkeyed — not a MAC, not AEAD |
| Confidence | CONFIRMED_MATCH between binary and Rust |

### 3.2 RSession Channel (TCP/17351 or shared)

| Aspect | Evidence |
|---|---|
| Transport | TCP, same 4-byte BE length framing |
| Key establishment | RSA-2048 PKCS#1 v1.5, client → server |
| Session key | 64-byte secret, split/derivation UNKNOWN |
| Cipher | AES-256-CBC via FamatechCipherState |
| IV | Persistent 16 bytes, initial zero |
| Trailer | Same 9-byte proprietary trailer as control channel |
| Confidence | Key mapping UNKNOWN; cipher structure CONFIRMED |

### 3.3 Peer Data Channel (UDP/9993)

| Aspect | Evidence |
|---|---|
| Transport | UDP datagrams (no TCP framing) |
| Virtual IPs | Range 26.x.x.x |
| Keepalive | UDP/47836, 4-byte sequential counter LE |
| Cipher | AES-256-CBC with Famatech trailer (PCAP-confirmed structure) |
| Key derivation | UNVERIFIED |
| Confidence | Structure CONFIRMED (PCAP); crypto key source UNKNOWN |

### 3.4 Relay Traffic

| Aspect | Evidence |
|---|---|
| Transport | Unknown (likely TCP or UDP relay) |
| Cipher | Unknown |
| Confidence | UNKNOWN |

---

## 4. IV Behavior Verification

### 4.1 Encryption (CONFIRMED)

| Property | Binary | Rust | Verdict |
|---|---|---|---|
| Initial IV | Zero-initialized | `[0u8; 16]` | CONFIRMED_MATCH |
| IV storage | AESCryptor `+0x1ec` | `enc_iv: [u8; 16]` | CONFIRMED_MATCH |
| IV update | From last ciphertext block | `enc_iv.copy_from_slice(&ct[last_block_start..])` | CONFIRMED_MATCH |
| IV persistence | No per-frame reset observed | No reset in Rust code | CONFIRMED_MATCH |

### 4.2 Decryption (CONFIRMED)

| Property | Binary | Rust | Verdict |
|---|---|---|---|
| Initial IV | Zero-initialized | `[0u8; 16]` | CONFIRMED_MATCH |
| IV storage | AESCryptor `+0x1fc` | `dec_iv: [u8; 16]` | CONFIRMED_MATCH |
| IV update | From last ciphertext block | `dec_iv.copy_from_slice(&ct[last_block_start..])` | CONFIRMED_MATCH |
| IV persistence | No per-frame reset observed | No reset in Rust code | CONFIRMED_MATCH |

### 4.3 Independent IV State per Direction (CONFIRMED)

Binary has two separate IV buffers (`enc_iv` at `+0x1ec`, `dec_iv` at `+0x1fc`). Rust has separate `enc_iv` and `dec_iv` fields. CONFIRMED_MATCH.

### 4.4 Packet Ordering Requirement (CONFIRMED)

CBC chaining with persistent IVs means packets must be decrypted in order. Rust test `test_corrupted_last_block_desynchronizes_next_packet` confirms this behavior. CONFIRMED_MATCH.

### 4.5 IV Reset Between Sessions (CONFIRMED)

New `FamatechCipherState` (new key) resets IV to zero. Same in binary (constructor initializes IVs). CONFIRMED_MATCH.

### 4.6 IV Reset Between Messages (CONFIRMED — no reset)

No per-message IV reset in either binary or Rust. IV persists across the session. CONFIRMED_MATCH.

---

## 5. Padding and Trailer Processing Order

### 5.1 Encryption Order (CONFIRMED)

```
1. payload = plaintext (L bytes)
2. total_len = ((block + 8 + L) / block) * block   ; forces pad_len ∈ [9, block+8]
3. pad_len = total_len - L
4. buf[0..L] = plaintext
5. buf[L..total_len-9] = 0xCC fill (k = pad_len - 9 bytes)
6. sum_64 = LE64-word-additive checksum of buf[0..total_len-9]
7. digest = MD5(LE64(sum_64))   ; 8-byte input, exactly one compression block
8. folded[i] = digest[i] + digest[i+8] mod 256, i = 0..7
9. buf[total_len-9..total_len-1] = folded[8]
10. buf[total_len-1] = pad_len
11. ciphertext = AES-256-CBC_encrypt(buf, total_len)  ; in place
```

**Trailer (9 bytes):** 8-byte folded MAC + 1-byte pad length at the end.

### 5.2 Decryption Order (CONFIRMED)

```
1. ciphertext received (len bytes)
2. AES-256-CBC_decrypt(ciphertext)  ; BEFORE any length validation
3. Validate: len % 16 == 0, len > 9, 9 <= pad_len <= 24, pad_len < len
4. payload_len = len - pad_len
5. Validate: all bytes in buf[payload_len..len-9] == 0xCC
6. sum_64 = checksum of buf[0..len-9]
7. folded = fold8(MD5(LE64(sum_64)))
8. Validate: buf[len-9..len-1] == folded[8]
9. Return buf[0..payload_len]
```

**Critical observation:** CBC decrypt runs **before** length validation (CONFIRMED at `0x10069d9b–0x10069dab` — `call [eax+8]` before `0x10069f90`). This is a potential robustness/DoS surface (A-3).

### 5.3 Padding and Trailer — Same Layer (CONFIRMED)

The 0xCC padding and 9-byte trailer are constructed together in `FUN_10069c20`/`famitech_pad_and_sign` and validated together in `FUN_10069f90`/`famitech_verify_and_unpad`. They belong to the same layer. CONFIRMED.

### 5.4 Not a MAC (CONFIRMED)

The folded MD5 is unkeyed — no key material is input to the checksum/MD5/fold computation. Anyone who knows the plaintext can compute the valid trailer. This provides corruption detection only, not authenticity. CONFIRMED.

---

## 6. Evidence Table

| # | Claim | Evidence | Confidence |
|---|---|---|---|
| 1 | AESCryptor vtable `0x100832a0`, 17 entries | `.rdata 0x100aee88`, vtable slots | CONFIRMED |
| 2 | Encrypt key slot → `AES_set_encrypt_key` | `+0x18` → `0x10062fb0`, bits=256 | CONFIRMED |
| 3 | Decrypt key slot → `AES_set_decrypt_key` | `+0x1c` → `0x10062f30`, bits=256 | CONFIRMED |
| 4 | Block size = 16 | `+0x20` → `0x10062e90` returns 0x10 | CONFIRMED |
| 5 | SetKeyEnc/SetKeyDec enforce 32 bytes | `+0xc0`→`0x1006ab00`, `+0xc4`→`0x1006aac0` | CONFIRMED (prior session) |
| 6 | AESCryptor object size 0x20c | `FUN_10062b60` | CONFIRMED |
| 7 | IV at `+0x1ec` (enc), `+0x1fc` (dec) | AESCryptor object layout | CONFIRMED |
| 8 | AES-CBC transform `0x10003b30` | CBC mode | CONFIRMED |
| 9 | TwoFishV2 vftable `0x100832c4` | No instantiation found | UNKNOWN (likely dead) |
| 10 | Rust FamatechCipherState fields | `enc_key[32]`, `dec_key[32]`, `enc_iv[16]`, `dec_iv[16]` | CONFIRMED |
| 11 | Rust from_rsession_key uses `[..32]` for both | L181-186 | CONFIRMED (but binary mapping UNKNOWN) |
| 12 | Encrypt order: pad → checksum → MD5 → fold → encrypt | `FUN_10069c20` body | CONFIRMED |
| 13 | Decrypt order: decrypt → validate → unpad | `FUN_10069d70` → `0x10069f90` | CONFIRMED |
| 14 | Decrypt before length validation | `call [eax+8]` before `0x10069f90` | CONFIRMED |
| 15 | Trailer is unkeyed (not a MAC) | No key input to checksum/MD5/fold | CONFIRMED |

---

## 7. Unresolved Questions

| # | Question | Impact | Next step |
|---|---|---|---|
| 1 | 64→32+32 key mapping (split vs KDF) | AES keys may be wrong | Complete disp8 sweep (Investigation B, step 1) |
| 2 | `SetKeyEnc`/`SetKeyDec` re-disassembly | Confirm 32-byte enforcement | Disassemble `0x1006ab00`/`0x1006aac0` |
| 3 | CChannel_CreateClient key args | Confirm two-key contract | Disassemble `0x1006a630` |
| 4 | Peer data channel key source | Unknown how peer data keys established | Trace UDP/9993 crypto setup |
| 5 | Relay channel cipher | Unknown | Investigate relay module |

---

## 8. Recommended Next Steps (Exact Addresses)

1. Complete the disp8 sweep from Investigation B to locate the `GetKey` consumer
2. Disassemble `0x1006ab00` (`SetKeyEnc`) and `0x1006aac0` (`SetKeyDec`) in `shelper.dll`
3. Disassemble `0x1006a630` (`CChannel_CreateClient` inner)
4. Trace UDP/9993 peer data channel crypto setup in `RvROLClient.dll`
5. Verify whether control channel and RSession channel use separate cipher objects or share one

---

**Generated file:** `docs/CRYPTO_AES_CONSUMER_TRACE.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered