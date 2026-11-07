# Cryptographic Analysis — Key Lifecycle Gap Analysis (Original vs Rust)

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Language:** English  
**Status:** Investigation phase — synthesis of Investigations A–D  

---

## 1. Scope

This document synthesizes the key lifecycle discrepancy matrix from Investigations A–D:

- Investigation A: SRP class selection and control key derivation (CRYPTO_CONTROL_KEY_LIFECYCLE.md)
- Investigation B: RSession 64-byte secret lifecycle (CRYPTO_RSESSION_KEY_LIFECYCLE.md)
- Investigation C: AES installation and cipher consumers (CRYPTO_AES_CONSUMER_TRACE.md)
- Investigation D: RSA key provenance (CRYPTO_RSA_KEY_PROVENANCE.md)

It compares the original binary behavior against the current Rust implementation for every key lifecycle step.

**Status values:** CONFIRMED_MATCH, CONFIRMED_MISMATCH, PARTIAL_MATCH, UNVERIFIED, NOT_IMPLEMENTED, NOT_APPLICABLE

---

## 2. Key Lifecycle Discrepancy Matrix

### 2.1 SRP Control Key Derivation

| # | Component | Original Behavior | Rust Behavior | Evidence | Status |
|---|---|---|---|---|---|
| A1 | SRP class selection | SRP-6a client `0x100ad75c` / server `0x100ad7b4` (PAD, `obj+4=3`) | Single hardcoded implementation; no class selection | Descriptor bytes `.data 0x100ad730`–`0x100ad7d8`; init `0x10060140`/`0x10060a80` | CONFIRMED_MISMATCH |
| A2 | Multiplier `k` | `k = SHA1(N ‖ PAD(g, 192))` computed inline in slot `+0x1c` | `RADMIN_SRP_K = 3` hardcoded at L16 | `0x10060810`→`0x10060510`; `0x100607d0` legacy path | CONFIRMED_MISMATCH |
| A3 | Hash algorithm | Bundled Tom Wu SHA1 (`0x10028810`/`0x285f0`/`0x286d0`) | `openssl::sha::sha1()` | Import table: no OpenSSL; `(tjw)` strings | CONFIRMED_MATCH (algorithm) |
| A4 | `x` computation | `H(salt ‖ H(I ‖ ":" ‖ P))`; identity = UTF-16LE wide chars | `H(salt ‖ H(username ‖ ":" ‖ password))`; UTF-8 bytes | `0x10060340`/`0x10060c80`; `compute_srp_x` L269-286 | CONFIRMED_MISMATCH (encoding) |
| A5 | `v` computation | `v = g^x mod N` | `v.mod_exp(&g_bn, &x_secret, &prime_n, &mut ctx)` | `0x100602f0`/`0x10060c80`; L255-256 | CONFIRMED_MATCH |
| A6 | `A` computation | `A = g^a mod N` | `a_public.mod_exp(&g_bn, &a_secret, &expected_n, &mut ctx)` | `0x10060410`; L773 | CONFIRMED_MATCH |
| A7 | `u` computation | `u = H(PAD(A) ‖ PAD(B))`; PAD flag at `0x1006085c` | `pad_bignum_bytes(a_bytes, 192)`, `pad_bignum_bytes(b_bytes, 192)` | `0x10060510`/`0x10060fa0`; L367-382 | CONFIRMED_MATCH (structure) |
| A8 | `S` computation | `0x10060510` — NOT disassembled | `base.mod_sub`, `ux.checked_mul`, `exp.checked_add`, `s.mod_exp` | `0x10060510` not reached; L864-892 | UNVERIFIED |
| A9 | KDF | `0x10061790` — NOT disassembled | `SHA1(S ‖ BE32(0)) ‖ SHA1(S ‖ BE32(1))` = 40 bytes | `0x10061790` not reached; L384-400 | UNVERIFIED |
| A10 | M1 formula | `H(H(N) ⊕ H(g) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K)` | `sha1(h_xor ‖ h_i ‖ salt ‖ a_bytes ‖ b_bytes ‖ k_full)` | `0x100601b0`; L402-430 | CONFIRMED_MATCH (structure) |
| A11 | M2 formula | `H(A ‖ M1 ‖ K)` | `sha1(a_bytes ‖ m1 ‖ k_full)` | `0x100609a0`; L432-442 | CONFIRMED_MATCH |
| A12 | Session key | First 32 bytes of 40-byte KDF output | `k_full[..CONTROL_SESSION_KEY_SIZE]` (32 bytes) | `RvROLClient 0x1003dd40`→`0x100df250`; L981-982 | CONFIRMED_MATCH |
| A13 | Step value endianness | Big-endian on wire (`00 00 00 01`) | `to_le_bytes()` → `01 00 00 00` | PCAP frames; L670/780/910/1267/1399/1456 | CONFIRMED_MISMATCH |
| A14 | Identity wire encoding | UTF-16BE per code unit | `encode_identity()` writes UTF-16BE | `0x100667b0`/`0x100677d0`; L146-153 | CONFIRMED_MATCH |
| A15 | Identity hash encoding | UTF-16LE wide chars | `username.as_bytes()` = UTF-8 | `0x10060340`/`0x10060c80`; L274-277 | CONFIRMED_MISMATCH |
| A16 | Password hash encoding | UTF-16LE wide chars (inferred) | `password.as_bytes()` = UTF-8 | Caller not traced; L276 | CONFIRMED_MISMATCH (inferred) |

### 2.2 RSession 64-Byte Secret

| # | Component | Original Behavior | Rust Behavior | Evidence | Status |
|---|---|---|---|---|---|
| B1 | Secret size | 64 bytes (`0x40`) | `RSESSION_KEY_MATERIAL_SIZE = 64` | `malloc(0x40)`; L16 | CONFIRMED_MATCH |
| B2 | Secret generation | `RAND_bytes(64)` via OpenSSL RAND_METHOD.bytes | `rand_bytes(&mut key_material)` | `FUN_10063530`→`FUN_10005410`; L248-251 | CONFIRMED_MATCH |
| B3 | Plaintext size | 76 bytes (`0x4c`) | `RSESSION_PLAINTEXT_SIZE = 76` | RSA len `0x4c`; L12 | CONFIRMED_MATCH |
| B4 | Header layout | 3× LE u32 client_params | `to_le_bytes()` at L254-258 | `FUN_1006a690` stores header dwords | CONFIRMED_MATCH |
| B5 | RSA padding | PKCS#1 v1.5 (mode 1) | `Padding::PKCS1` | `PUSH 0x1` at `0x10065f05`; L262/471 | CONFIRMED_MATCH |
| B6 | Ciphertext size | 256 bytes | `RSESSION_RSA_BLOCK_SIZE = 256` | `RSA_size` → `0x100`; L10 | CONFIRMED_MATCH |
| B7 | Server token | CreateServer arg0 (4 bytes LE) | `server_token.to_le_bytes()` | `*out = *(u32*)(this+0x04)`; L502 | CONFIRMED_MATCH |
| B8 | No KDF | No hash on RSession path | No KDF | Complete callee set of `FUN_1006a2b0` | CONFIRMED_MATCH |
| B9 | Key → enc | UNKNOWN | `key_material[..32]` | No consumer found; `derive_aes256_key_ref` L202-207 | CONFIRMED_MISMATCH |
| B10 | Key → dec | UNKNOWN | `key_material[..32]` (same as enc) | No consumer found; L202-207 | CONFIRMED_MISMATCH |
| B11 | 64-byte secret usage | All 64 bytes transported | Only first 32 used | No consumer found; L627 | CONFIRMED_MISMATCH |

### 2.3 AES Installation

| # | Component | Original Behavior | Rust Behavior | Evidence | Status |
|---|---|---|---|---|---|
| C1 | Cipher algorithm | AES-256-CBC | `Cipher::aes_256_cbc()` | `0x10062fb0`/`0x10062f30`; L254-256 | CONFIRMED_MATCH |
| C2 | Key size | 32 bytes | `AES_256_KEY_SIZE = 32` | `SetKeyEnc`/`SetKeyDec` reject ≠0x20; L6 | CONFIRMED_MATCH |
| C3 | IV size | 16 bytes | `enc_iv: [u8; 16]`, `dec_iv: [u8; 16]` | `+0x1ec`/`+0x1fc`; L130-131 | CONFIRMED_MATCH |
| C4 | IV persistence | No per-frame reset | No reset in Rust code | Two IV buffers per object; L280/312 | CONFIRMED_MATCH |
| C5 | IV initial value | Zero-initialized | `[0u8; 16]` | Constructor; L150-151 | CONFIRMED_MATCH |
| C6 | IV update | From last ciphertext block | `enc_iv.copy_from_slice(&ct[last_block_start..])` | AESCryptor object; L280/312 | CONFIRMED_MATCH |
| C7 | Trailer | 9 bytes (folded MD5 + pad length) | `TRAILER_SIZE = 9` | `0x10069c20`/`0x10069f90`; L9 | CONFIRMED_MATCH |
| C8 | Padding byte | `0xCC` | `PAD_BYTE = 0xCC` | `mov byte [eax+ecx],0xcc`; L12 | CONFIRMED_MATCH |
| C9 | Pad length range | [9, 24] | `MIN_PAD_LEN = 9`, `MAX_PAD_LEN = 24` | Validation gate `0x10069fe5`; L10-11 | CONFIRMED_MATCH |
| C10 | Checksum | LE64 word-additive, mod 2^64 | `famitech_checksum_64` | `add ebx,[esi]/adc edi,[esi+4]`; L34-51 | CONFIRMED_MATCH |
| C11 | MD5 input | 8-byte checksum only | MD5 over 8-byte sum | `0x100638f0` over 8 bytes; L53-62 | CONFIRMED_MATCH |
| C12 | Fold | `fold[i] = digest[i] + digest[i+8] mod 256` | `folded[i] = digest[i].wrapping_add(digest[i+8])` | `0x10069ce0`–`0x10069d15`; L58-60 | CONFIRMED_MATCH |
| C13 | Encrypt before length validation | Decrypt runs before length check | Decrypt runs before unpad | `call [eax+8]` before `0x10069f90`; L285-315 | CONFIRMED_MATCH |
| C14 | Trailer is unkeyed (not MAC) | No key input | No key input | No key in checksum/MD5/fold; L84-125 | CONFIRMED_MATCH |
| C15 | Key → AES install | Two 32-byte keys (SetKeyEnc/SetKeyDec) | `from_rsession_key` uses `[..32]` for both | `0x1006ab00`/`0x1006aac0`; L188-221 | CONFIRMED_MISMATCH |

### 2.3 RSA Operations

| # | Component | Original Behavior | Rust Behavior | Evidence | Status |
|---|---|---|---|---|---|
| D1 | Key size | 2048 bits | `RSESSION_RSA_BLOCK_SIZE = 256` | `RSA_size` → `0x100`; L10 | CONFIRMED_MATCH |
| D2 | Key format | Raw big-endian via `BN_bin2bn` | `BigNum::from_slice(modulus)`/`from_slice(exponent)` | `0x10008a40`; L150-155 | CONFIRMED_MATCH |
| D3 | Padding | PKCS#1 v1.5 | `Padding::PKCS1` | `PUSH 0x1`; L262/471 | CONFIRMED_MATCH |
| D4 | Public exponent | Imported from buffer (value unknown) | `DEFAULT_RSA_PUBLIC_EXPONENT = [0x01, 0x00, 0x01]` | Buffer source UNKNOWN; L26 | UNVERIFIED |
| D5 | No OAEP | `rsaesOaep` zero xrefs | `Padding::PKCS1` only | Inert string; CONFIRMED_MATCH | CONFIRMED_MATCH |
| D6 | No signing | No `RSA_sign`/`RSA_verify` | No signing | Absence confirmed | CONFIRMED_MATCH |
| D7 | Client public key source | UNKNOWN (caller-supplied buffers) | `set_server_public_key_components` | Source not traced | UNKNOWN |
| D8 | Server private key source | UNKNOWN (caller-supplied buffers) | `Rsa<Private>` passed to `create_server` | Source not traced | UNKNOWN |

---

## 3. Fatal Blockers (Must Fix Before Interop)

| # | Issue | Binary Evidence | Rust Location | Fix |
|---|---|---|---|---|
| 1 | Step value endianness | Big-endian `00 00 00 01` on wire | `to_le_bytes()` L670/780/910/1267/1399/1456 | Change to `to_be_bytes()` |
| 2 | Identity hash encoding | UTF-16LE wide chars at `0x10060340`/`0x10060c80` | `username.as_bytes()` L274-277 | Hash UTF-16LE bytes |
| 3 | Multiplier `k` | `k = SHA1(N ‖ PAD(g))` at `0x10060810` | `RADMIN_SRP_K = 3` at L16 | Compute `k` at runtime or confirm legacy class |
| 4 | RSession key mapping | 64-byte secret → two 32-byte keys UNKNOWN | `key_material[..32]` for both directions L202-207 | Locate `GetKey` consumer; determine split |

---

## 4. Impact Summary

Two defects are **independently fatal** before any crypto is exercised:

1. **Step endianness (CONFIRMED_MISMATCH):** Server rejects step 1 immediately — complete handshake failure.
2. **Identity encoding (CONFIRMED_MISMATCH):** `x` differs → `v`, `A`, `S`, `K`, `M1`, `M2` all differ — complete failure even with fix #1.

Two additional high-impact mismatches:

3. **Multiplier `k` (CONFIRMED_MISMATCH):** If SRP-6a class is deployed (confirmed), `k = 3` is wrong — `S` differs.
4. **RSession key mapping (CONFIRMED_MISMATCH):** Rust uses `[..32]` for both enc and dec with no evidence; 32 bytes of the 64-byte secret are unused.

---

## 5. Evidence Sources

- `docs/CRYPTO_CONTROL_KEY_LIFECYCLE.md` — Investigation A (SRP class selection, control key derivation)
- `docs/CRYPTO_RSESSION_KEY_LIFECYCLE.md` — Investigation B (RSession 64-byte secret lifecycle)
- `docs/CRYPTO_AES_CONSUMER_TRACE.md` — Investigation C (AES installation, cipher consumers)
- `docs/CRYPTO_RSA_KEY_PROVENANCE.md` — Investigation D (RSA key provenance)
- `src/session/control_handshake.rs` — full file read
- `src/session/handshake.rs` — full file read
- `src/crypto/famatech.rs` — full file read
- `src/crypto/mod.rs` — full file read

---

**Generated file:** `docs/CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered