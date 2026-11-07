# Cryptographic Analysis — Symmetric Encryption (AES-256-CBC)

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Binaries analyzed:** `shelper.dll`, `RvROLClient.dll`  
**Language:** English  
**Status:** Investigation phase — evidence-backed  

---

## 1. Scope

This document analyzes the symmetric encryption used by the original Radmin VPN implementation:
- Cipher algorithm and mode
- Key size and source
- IV/nonce generation and handling
- Padding scheme
- Authentication / integrity mechanism
- AEAD usage (or lack thereof)
- Counter / sequence-number behavior
- Replay protection
- Packet framing around encrypted data
- Cipher initialization and reset behavior
- Error handling
- Key rotation
- Session termination and key cleanup

It covers control traffic (TCP/17301), RSession traffic (TCP/17351 or shared channel), and data-channel traffic (UDP/9993).

---

## 2. Cipher Algorithm and Mode (CONFIRMED)

### 2.1 Algorithm

**AES-256** is confirmed. Evidence:

| Evidence | Address / Location | Detail |
|---|---|---|
| AESCryptor class | `shelper.dll` `.rdata` `0x100aee88` — `.?AVAESCryptor@@` | RTTI string confirmed |
| Base class | `BaseCryptor` | RTTI class hierarchy confirmed |
| vtable | `0x100832a0` | 17 entries, indices 0–16 |
| Encrypt slot | `+0x18` → `0x10062fb0` | `AES_set_encrypt_key`, bits = `len*8` = 256 |
| Decrypt slot | `+0x1c` → `0x10062f30` | `AES_set_decrypt_key` |
| Block size | `+0x20` → `0x10062e90` | Returns `0x10` (16 bytes) |
| SetKeyEnc | `+0xc0` → `0x1006ab00` | Enforces length 0x20 (32 bytes) |
| SetKeyDec | `+0xc4` → `0x1006aac0` | Enforces length 0x20 (32 bytes) |
| AES-CBC transform | `0x10003b30` | `Cipher::aes_256_cbc()` in Rust matches |

**CONFIRMED:** AES-256-CBC is the symmetric cipher. No other cipher (TwoFish, Blowfish, etc.) is instantiated in the observed code paths. A second vftable `0x100832c4` (TwoFishV2-shaped) exists in `.rdata` but has no instantiation site — likely dead code.

### 2.2 Mode

**CBC mode** is confirmed. The OpenSSL `EVP_CIPHER` used is `aes_256_cbc()`:
- `shelper.dll` vtable slot `+0x18` maps to `AES_set_encrypt_key` with 256 bits
- `shelper.dll` vtable slot `+0x1c` maps to `AES_set_decrypt_key` with 256 bits
- Rust `FamatechCipherState::encrypt`/`decrypt` uses `Cipher::aes_256_cbc()` with `Mode::Encrypt`/`Mode::Decrypt`

**No AEAD is used.** There is no GCM, CCM, or EAX mode anywhere in the observed code paths. Encryption and integrity are separate layers (and the integrity layer is unkeyed, see Section 6).

---

## 3. Key Size (CONFIRMED)

**32 bytes (256 bits)** for both encryption and decryption keys.

Evidence:
- `SHelper_CChannel_CreateClient` (`0x1006a8b0`) requires two keys of exactly 32 bytes
- `SetKeyEnc` (`0x1006ab00`) rejects `len != 0x20`
- `SetKeyDec` (`0x1006aac0`) rejects `len != 0x20`
- `RvROLClient.dll` `0x1003dd40` computes `len = min(available, 0x20)` and `0x100df250` installs a 32-byte key
- Rust `FamatechCipherState` uses `AES_256_KEY_SIZE = 32` everywhere
- Rust `derive_aes256_key_ref` extracts `key_material[..32]` from the 64-byte RSession key material

---

## 4. IV / Nonce Handling (CONFIRMED)

### 4.1 IV Size

**16 bytes** (one AES block), confirmed:
- AESCryptor object size `0x20c`
- IV at `+0x1ec` (encrypt), `+0x1fc` (decrypt) — two separate IV buffers
- Rust `FamatechCipherState` has `enc_iv: [u8; BLOCK_SIZE]` and `dec_iv: [u8; BLOCK_SIZE]` where `BLOCK_SIZE = 16`

### 4.2 IV Generation

**Persistent IVs — no per-frame IV derivation.** CONFIRMED:

- Only two IV buffers exist per cipher state object (`enc_iv`, `dec_iv`)
- No per-call IV reset or derivation was observed
- On encrypt: after encrypting, `self.enc_iv.copy_from_slice(&ciphertext[last_block_start..])` — the IV is updated to the last ciphertext block (standard CBC chaining)
- On decrypt: after decrypting, `self.dec_iv.copy_from_slice(&ciphertext[last_block_start..])` — same for decryption
- Initial IV is zero-initialized (`[0u8; BLOCK_SIZE]`)

**Initial IV is all zeros.** This means the first block of the first message under a given key is XORed with an all-zero IV, which is equivalent to ECB for the first block.

### 4.3 IV Reset Behavior

No IV reset between messages. The IV persists across frames within a session. If frames are lost or reordered, decryption will fail (the CBC chain is stateful and desynchronization-sensitive). Confirmed by Rust regression test `test_corrupted_last_block_desynchronizes_next_packet`.

---

## 5. Padding Scheme (CONFIRMED)

### 5.1 Structure

The padding scheme is **proprietary** (not PKCS#7, not ISO 7816-4):

```
P   = src ‖ 0xCC^k ‖ T
T   = fold8( MD5( LE64( S( src ‖ 0xCC^k ) ) ) ) ‖ pad_len     ; T = 9 bytes
pad_len = total_len - L ,  total_len = ((block+8+L)/block)*block ,  pad_len ∈ [9, block+8]
```

Where:
- `src` = plaintext (L bytes)
- `0xCC^k` = k bytes of 0xCC fill
- `S(x)` = 64-bit additive checksum over x (LE word-additive, mod 2^64)
- `fold8(y)` = byte-wise `y[i] + y[i+8] mod 256` for i = 0..7 (8 bytes from 16-byte MD5)
- `pad_len` = total_len - L (1 byte)

Total trailer overhead: **9 bytes** (8-byte folded MAC + 1-byte pad length).

### 5.2 Pad Length Range

`pad_len ∈ [9, block+8]`. For block = 16: `pad_len ∈ [9, 24]`. This is enforced by:
- Encrypt: `debug_assert!((MIN_PAD_LEN..=MAX_PAD_LEN).contains(&pad_len))` where `MIN_PAD_LEN = 9`, `MAX_PAD_LEN = 24`
- Decrypt: explicit check `9 <= pad_len <= 24` and `pad_len < len`

**Note:** `pad_len == 8` is impossible because `total_len = ((block + 8 + L) / block) * block` forces `total_len - len ∈ [9, block+8]`. There is no case where padding is exactly 8 bytes.

### 5.3 Padding Byte

`0xCC` fill. All padding bytes (between plaintext and trailer) are set to `0xCC`.

### 5.4 Trailer Structure (9 bytes)

| Offset | Size | Content |
|---|---|---|
| `total-9` | 8 | Folded MD5 digest: `fold8(MD5(LE64(checksum(plaintext ‖ 0xCC^k))))` |
| `total-1` | 1 | Pad length (`pad_len`) |

---

## 6. Authentication / Integrity (CONFIRMED: NOT AUTHENTICATED)

### 6.1 The Trailer is Unkeyed

The 8-byte folded MD5 digest is computed from:
1. 64-bit additive checksum of `plaintext ‖ 0xCC^k` (no key)
2. MD5 of the 8-byte checksum (no key)
3. Byte-wise fold of the 16-byte MD5 to 8 bytes (no key)

**No key material is ever input to this computation.** Anyone who knows the plaintext can compute the valid trailer. This is **not a MAC** and provides no authenticity.

### 6.2 Encryption Without Authentication

AES-256-CBC is malleable: an attacker who can modify ciphertext blocks can predictably change corresponding plaintext blocks (bit-flipping attack). The folded MD5 trailer does not prevent this because:
- The attacker can recompute the checksum and folded MD5 for any modified plaintext
- The trailer is computed over plaintext, not ciphertext
- No key is involved in the trailer computation

### 6.3 No Replay Protection

There is no sequence number, nonce, or timestamp included in the authenticated data. The folded MD5 covers only the plaintext payload and padding, not any sequence or session context.

### 6.4 Security Assessment

| Property | Status | Reason |
|---|---|---|
| Confidentiality | CONFIRMED (conditional) | AES-256-CBC with proper key provides confidentiality if key is secret and IV handling is correct |
| Integrity | REFUTED | Unkeyed folded MD5 can be forged by anyone who knows plaintext |
| Authenticity | REFUTED | No keyed MAC; no authentication of ciphertext |
| Replay protection | REFUTED | No sequence numbers, nonces, or timestamps in authenticated data |
| Malleability | CONFIRMED | AES-CBC is bit-flip malleable; unkeyed trailer doesn't prevent it |

---

## 7. Packet Framing Around Encrypted Data

### 7.1 Control Channel (TCP/17301)

```
[4-byte big-endian length][encrypted payload]
```

- Length excludes the 4-byte header itself
- Length = payload size in bytes
- Fragmentation across TCP segments occurs for messages > MSS
- Confirmed in PCAP: frame 77 (length=0x000000c0=192, tcp.len=196), frame 80 (length=0x20=32, tcp.len=36), frame 81 (length=0x100=256, tcp.len=260)
- Fragmented example: frame 100 (first 1436 payload bytes) + frame 101 (remaining 1156 payload bytes) = 2592 total = 0x0a20

### 7.2 RSession Channel

RSession uses the same framing: 4-byte BE length prefix + encrypted payload. The Rust `FramedPacket` struct and `FrameParser` implement this:
- `FramedPacket::new(payload)` → `[4-byte BE length][payload]`
- `FrameParser::feed()` reassembles fragmented TCP segments

### 7.3 Peer Data Channel (UDP/9993)

UDP datagrams are used directly (no TCP framing). Each UDP datagram contains one complete encrypted Radmin message. No length prefix within the UDP payload (UDP length field provides the size).

---

## 8. Cipher Initialization and Reset

### 8.1 Initialization

- `FamatechCipherState::new(key)` — zero-initializes both IVs, copies key to both enc_key and dec_key
- `FamatechCipherState::from_key_ref(key)` — same, from reference
- `FamatechCipherState::from_separate_keys(enc_key, dec_key)` — separate keys for enc/dec
- `FamatechCipherState::from_rsession_key(key_material)` — takes first 32 bytes of 64-byte RSession key material for both enc and dec

### 8.2 Reset Behavior

- `clear()` — zeroizes enc_key, dec_key, enc_iv, dec_iv
- `Drop` implementation calls `clear()`
- IV is NOT reset between messages within a session (persistent CBC chaining)
- A new `FamatechCipherState` (new key) resets IV to zero

### 8.3 Key Rotation

No key rotation is observed within a session. The key is installed once during handshake and used for the entire session. No rekeying mechanism is observed in the binaries or Rust code.

### 8.4 Session Termination

- `clear()` zeroizes all key material and IVs
- `Drop` calls `clear()`
- `ControlConnection::close()` and `SessionManager::close()` call `cleanup_resources()` which clears cipher state and closes the TCP channel

---

## 9. Rust Implementation vs Binary Evidence

### 9.1 Matches (CONFIRMED_MATCH)

| Item | Binary | Rust | Verdict |
|---|---|---|---|
| AES-256-CBC | `0x10062fb0`/`0x10062f30` | `Cipher::aes_256_cbc()` | CONFIRMED_MATCH |
| 32-byte key | `SetKeyEnc`/`SetKeyDec` reject ≠0x20 | `AES_256_KEY_SIZE = 32` | CONFIRMED_MATCH |
| 16-byte IV | `+0x1ec`/`+0x1fc` | `enc_iv: [u8; 16]`, `dec_iv: [u8; 16]` | CONFIRMED_MATCH |
| Persistent IV | Only 2 IV buffers per object | IV updated from last ciphertext block, no reset | CONFIRMED_MATCH |
| 0xCC padding | `mov byte [eax+ecx],0xcc` | `PAD_BYTE = 0xCC` | CONFIRMED_MATCH |
| 9-byte trailer | `pad_len` at `len-1`, fold at `len-9` | `TRAILER_SIZE = 9` | CONFIRMED_MATCH |
| Pad range [9,24] | Validation gate at `0x10069fe5` | `MIN_PAD_LEN = 9`, `MAX_PAD_LEN = 24` | CONFIRMED_MATCH |
| LE word-additive checksum | `add ebx,[esi]/adc edi,[esi+4]` | `famitech_checksum_64` (LE u64 words) | CONFIRMED_MATCH |
| MD5 over 8-byte checksum | `0x100638f0` over 8 bytes | `MD5` over 8-byte sum | CONFIRMED_MATCH |
| Byte-wise fold `mod 256` | `add [ebp-0x14+i],al` (8-bit add) | `folded[i] = digest[i].wrapping_add(digest[i+8])` | CONFIRMED_MATCH |
| Persistent IV across frames | `enc_iv`/`dec_iv` updated from last block | `enc_iv.copy_from_slice(&ciphertext[last_block_start..])` | CONFIRMED_MATCH |
| Zero IV initialization | `memset`-equivalent | `[0u8; BLOCK_SIZE]` | CONFIRMED_MATCH |
| Zeroize on drop | `Drop` calls `clear()` | `Drop for FamatechCipherState` calls `clear()` | CONFIRMED_MATCH |
| Frame framing `[4-byte BE len][payload]` | PCAP frames 77, 80, 81, 82, 87, 88, 93, 94 | `FramedPacket::to_bytes()` / `FrameParser` | CONFIRMED_MATCH |

### 9.2 Potential Mismatches (UNVERIFIED or PARTIAL)

| Item | Binary | Rust | Status | Notes |
|---|---|---|---|---|
| 64→32 key split | `RSession+0x30` = 64 bytes | `key_material[..32]` | UNVERIFIED | Split point and enc/dec ordering not observed in binaries |
| Per-frame IV reset | No reset observed | No reset in Rust code | CONFIRMED_MATCH | Both persistent |
| Key rotation | Not observed | No key rotation in Rust | CONFIRMED_MATCH | Both single-key per session |
| Enc/dec separate keys | Separate vtable slots `+0x18`/`+0x1c` | `from_separate_keys()` supported | CONFIRMED_MATCH | Both support separate keys |
| RSession key = first 32 of 64 | Hypothesis E12 | `from_rsession_key` takes `[0..32]` | UNVERIFIED | Split not observed in binaries |

---

## 10. Security Summary

### 10.1 What the Encryption Provides

- **Confidentiality:** AES-256-CBC with a 32-byte key provides strong confidentiality, assuming the key is secret and the IV handling doesn't leak information.
- **Integrity:** NOT provided. The unkeyed folded MD5 trailer can be forged by anyone who knows the plaintext.
- **Authenticity:** NOT provided. No keyed MAC or signature on ciphertext.
- **Replay protection:** NOT provided. No sequence numbers or nonces in authenticated data.

### 10.2 Known Weaknesses

1. **Unkeyed integrity:** Anyone who can predict plaintext can forge valid trailers. This enables cut-and-paste attacks and bit-flipping attacks where the attacker recomputes the trailer.
2. **Persistent IVs:** If the same key encrypts many messages, the CBC IV chain persists. This is standard for stream-oriented protocols but means that losing synchronization (dropped/reordered frames) breaks decryption until rekeying.
3. **No key rotation:** The same key is used for the entire session. Long sessions accumulate more ciphertext under the same key, which is generally acceptable for AES-256-CBC but limits the amount of data safe under a single key (2^64 blocks for CBC, far beyond practical limits).
4. **First-block IV = zero:** The initial IV is all zeros, making the first block equivalent to ECB encryption. This is a minor weakness but not critical for typical VPN traffic.

### 10.3 Recommendations for Rust Implementation

The Rust implementation faithfully reproduces the binary's behavior. If interoperability with the original Radmin client is the goal, the current implementation is **correct** for the observed protocol. If the goal is also to improve security, the following changes would be needed (but would break interoperability):

1. Add an encrypt-then-MAC (e.g., HMAC-SHA256) over ciphertext
2. Add per-message nonces or sequence numbers
3. Add key rotation
4. Use random per-message IVs instead of persistent CBC chaining

---

**Generated file:** `docs/CRYPTO_SYMMETRIC_ENCRYPTION.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered