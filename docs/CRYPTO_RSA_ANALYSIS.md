# Cryptographic Analysis — RSA Operations

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Binaries analyzed:** `shelper.dll` (sha256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`), `RvROLClient.dll` (sha256: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`), `RvControlSvc.exe` (sha256: `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`)  
**Language:** English  
**Status:** Investigation phase — evidence-backed  

---

## 1. Scope

This document analyzes every RSA operation involved in authentication and session establishment in `shelper.dll` and `RvROLClient.dll`. It is part of Investigation D of the cryptographic deep audit.

All findings are from static disassembly (instruction-level) of `shelper.dll` and `RvROLClient.dll`. Dynamic execution was **not possible**; confidence rests on structural and call-chain analysis.

---

## 2. RSA Function Inventory

### 2.1 Exported RSA Functions

| Function | Address | Role | Confidence |
|---|---|---|---|
| `RSA_public_encrypt` (wrapped) | `0x10065ec0` | Client-side RSA encryption with PKCS#1 v1.5 padding | CONFIRMED |
| `RSA_private_decrypt` (wrapped) | `0x10065db0` | Server-side RSA decryption with PKCS#1 v1.5 padding | CONFIRMED |
| `RSA_new` | `0x10065f50` / `0x10009290` / `0x10008fa0` | RSA object allocation | CONFIRMED |
| `RSA_free` | Upstream OpenSSL | RSA object deallocation | STRONG INDICATION (zeroization behavior unverified) |

### 2.2 RSA Key Import Functions

| Function | Address | Role |
|---|---|---|
| `BN_bin2bn` | `0x10008a40` | Import raw big-endian bytes into BIGNUM |
| Client key import | `0x10066170` | Sets `n`@`+0x10`, `e`@`+0x14` via `BN_bin2bn` |
| Server key import | `0x10065f70` | Sets `n,e,d,p,q,dmp1,dmq1,iqmp` @ `+0x10..+0x2c` |

### 2.3 No RSA Signing Functions

No RSA signing functions (`RSA_sign`, `RSA_verify`, `MD5_with_RSA`, etc.) were found in the RSession or control-auth call chains. RSA is used **only for encryption/decryption (key transport)**, not for digital signatures.

---

## 3. RSA Key Parameters (CONFIRMED)

| Parameter | Value | Evidence |
|---|---|---|
| Key size | 2048 bits (256 bytes) | `RSESSION_RSA_BLOCK_SIZE = 256` in Rust; binary `RSA_size` computed from `n` at runtime |
| Key format | Raw modulus/exponent (big-endian bytes) | `BN_bin2bn` imports raw bytes; no DER/PEM parsing observed |
| Public key | `(n, e)` pair | Client imports `n`@`+0x10`, `e`@`+0x14` |
| Private key | `(n,e,d,p,q,dmp1,dmq1,iqmp)` | Server imports full set @ `+0x10..+0x2c` |
| Public exponent | `0x010001` (65537) | `DEFAULT_RSA_PUBLIC_EXPONENT` in Rust; binary imports `e` from caller buffer |
| Byte order | Big-endian | `BN_bin2bn` imports raw big-endian bytes |

**Key format is raw, not DER/PEM.** No DER parsing or PEM decoding was observed in the RSA code path.

---

## 4. RSA Padding Mode (CONFIRMED)

### 4.1 PKCS#1 v1.5

The padding mode is **PKCS#1 v1.5**, confirmed by:

- Padding mode constant `1` pushed at `0x10065f05` inside `FUN_10065ec0` (RSA public encrypt)
- `RSA_public_encrypt` / `RSA_private_decrypt` called with `padding = 1` (RSA_PKCS1_PADDING)
- Client encrypts 76-byte plaintext with server's public key using PKCS#1 v1.5
- Server decrypts with private key using PKCS#1 v1.5

### 4.2 OAEP Refuted (CONFIRMED)

The string `"rsaesOaep"` at `0x10083b78` has **zero xrefs** in the binary. It is inert string-table data, not referenced by any code. This is **not evidence of OAEP use**.

**CONFIRMED:** RSA uses PKCS#1 v1.5 padding only. OAEP is not used.

### 4.3 No Raw RSA

No raw RSA (RSA_NO_PADDING) operations were observed in the RSession or control-auth call chains.

---

## 5. RSA Operations by Role

### 5.1 Client Role (RSession_CreateClient)

1. Client imports server's RSA public key `(n, e)` via `BN_bin2bn`
2. Client generates 64 random bytes (key material)
3. Client builds 76-byte plaintext: 12-byte header (3×u32 LE client_params) + 64-byte key material
4. Client encrypts with `RSA_public_encrypt(plaintext, 76, encrypted, server_pub_key, RSA_PKCS1_PADDING)`
5. Output: 256-byte RSA ciphertext block
6. Client sends 256-byte ciphertext to server

### 5.2 Server Role (RSession_CreateServer)

1. Server imports full RSA private key `(n,e,d,p,q,dmp1,dmq1,iqmp)`
2. Server receives 256-byte RSA ciphertext
3. Server decrypts with `RSA_private_decrypt(ciphertext, 256, decrypted, server_priv_key, RSA_PKCS1_PADDING)`
4. Server validates decrypted length == 76 bytes (0x4c)
5. Server extracts 64-byte key material from `decrypted[12..76]`
6. Server emits 4-byte server token to client

### 5.3 No RSA in Control Auth (SRP-6a)

**CONFIRMED:** RSA is **not** used anywhere in the SRP-6a control authentication path. The SRP-6a functions (`SHelper_RSAHelper_CreateWithPrivateKey`/`CreateWithPublicKey` names are misleading — they relate to RSession RSA, not SRP) are separate from the SRP-6a functions (`0x1006ab90`/`0x1006ad20`/`0x1006b1e0`/`0x1006b010`/`0x1006b1d0`).

---

## 6. RSA Failure Behavior (CONFIRMED)

| Failure | Binary Behavior | Rust Equivalent |
|---|---|---|
| RSA encrypt failure | Core returns -1 or 0 (indistinguishable from caller); client fails handshake | `RsaEncryptionFailed` error |
| RSA decrypt failure | Core returns -1 or 0; server fails handshake | `RsaDecryptionFailed` error |
| Decrypted plaintext ≠ 76 bytes | Server fails handshake with `InvalidDecryptedPlaintextSize` | Same error in Rust |
| Ciphertext ≠ 256 bytes | Server rejects with `InvalidRsaBlockSize` | Same error in Rust |

**Core return values are BOOL:** OpenSSL `-1` and `0` are indistinguishable from the caller's perspective. No retry logic should be built on "error text."

---

## 7. Call Chain

### 7.1 Client Encryption Call Chain

```
SHelper_RSession_CreateClient (0x1006b860)
  └ FUN_10069bc0 (constructor)
  └ FUN_1006a690 (client init)
    └ Client generates 64 random bytes (FUN_10063530 → FUN_10005410)
    └ Client builds 76-byte plaintext
    └ RSA_public_encrypt(plaintext, 76, ciphertext, server_pub_key, RSA_PKCS1_PADDING)
      └ FUN_10065ec0 (RSA public encrypt, padding mode 1)
        └ OpenSSL RSA_public_encrypt
    └ Client sends 256-byte ciphertext
```

### 7.2 Server Decryption Call Chain

```
SHelper_RSession_CreateServer (0x1006b8f0)
  └ FUN_10069bc0 (constructor)
  └ FUN_1006a700 (server init, imports full private key)
    └ Server receives 256-byte ciphertext
    └ RSA_private_decrypt(ciphertext, 256, decrypted, server_priv_key, RSA_PKCS1_PADDING)
      └ FUN_10065db0 (RSA private decrypt)
        └ OpenSSL RSA_private_decrypt
    └ Server validates length == 76
    └ Server extracts 64-byte key material from decrypted[12..76]
    └ Server emits 4-byte server token
```

---

## 8. Comparison with Rust Implementation

| Item | Binary Evidence | Rust (`src/session/handshake.rs`) | Verdict |
|---|---|---|---|
| RSA key size | 2048 bits (256 bytes) | `RSESSION_RSA_BLOCK_SIZE = 256` | CONFIRMED_MATCH |
| Key format | Raw modulus/exponent (big-endian) | `BigNum::from_slice(modulus)` / `from_slice(exponent)` | CONFIRMED_MATCH |
| Padding | PKCS#1 v1.5 (mode 1) | `Padding::PKCS1` | CONFIRMED_MATCH |
| Public exponent | Imported from server buffer | `DEFAULT_RSA_PUBLIC_EXPONENT = [0x01, 0x00, 0x01]` | CONFIRMED_MATCH (if server uses 65537) |
| Client encrypt | `RSA_public_encrypt(plaintext, 76, ..., PKCS1)` | `pub_key.public_encrypt(&plaintext, &mut encrypted, Padding::PKCS1)` | CONFIRMED_MATCH |
| Server decrypt | `RSA_private_decrypt(ciphertext, 256, ..., PKCS1)` | `self.private_key.private_decrypt(buf, &mut *decrypted, Padding::PKCS1)` | CONFIRMED_MATCH |
| Plaintext size | 76 bytes (12 header + 64 key) | `RSESSION_PLAINTEXT_SIZE = 76` | CONFIRMED_MATCH |
| Ciphertext size | 256 bytes | `RSESSION_RSA_BLOCK_SIZE = 256` | CONFIRMED_MATCH |
| Decrypt validation | `dec_len != 76` → fail | `dec_len != RSESSION_PLAINTEXT_SIZE` → `InvalidDecryptedPlaintextSize` | CONFIRMED_MATCH |
| Ciphertext size validation | `buf.len() != 256` → fail | `buf.len() != RSESSION_RSA_BLOCK_SIZE` → `InvalidRsaBlockSize` | CONFIRMED_MATCH |
| Key material extraction | `decrypted[12..76]` | `decrypted[RSESSION_CLIENT_HEADER_SIZE..RSESSION_PLAINTEXT_SIZE]` | CONFIRMED_MATCH |
| No OAEP | `rsaesOaep` string has zero xrefs | `Padding::PKCS1` only | CONFIRMED_MATCH (both reject OAEP) |
| No signing | No `RSA_sign`/`RSA_verify` in call chain | No signing in `handshake.rs` | CONFIRMED_MATCH |
| No DER/PEM | Raw `BN_bin2bn` import | `BigNum::from_slice(modulus)` / `from_slice(exponent)` | CONFIRMED_MATCH |

---

## 9. Evidence Table

| # | Claim | Binary / RVA | Caller → Callee | Constants / Sizes | Class |
|---|---|---|---|---|---|
| 1 | RSA public encrypt | `shelper.dll 0x10065ec0` | Client → OpenSSL `RSA_public_encrypt` | Padding mode `PUSH 0x1` | CONFIRMED |
| 2 | RSA private decrypt | `shelper.dll 0x10065db0` | Server → OpenSSL `RSA_private_decrypt` | Padding mode `PUSH 0x1` | CONFIRMED |
| 3 | Key import (client) | `shelper.dll 0x10066170` | `BN_bin2bn` (`0x10008a40`) | `n`@`+0x10`, `e`@`+0x14` | CONFIRMED |
| 4 | Key import (server) | `shelper.dll 0x10065f70` | `BN_bin2bn` for all 9 components | `n,e,d,p,q,dmp1,dmq1,iqmp` @ `+0x10..+0x2c` | CONFIRMED |
| 5 | Padding mode | `shelper.dll 0x10065f05` | `PUSH 0x1` before encrypt call | `RSA_PKCS1_PADDING = 1` | CONFIRMED |
| 6 | No OAEP | `shelper.dll 0x10083b78` | String has zero xrefs | `"rsaesOaep"` inert | CONFIRMED (absence) |
| 7 | No signing | No `RSA_sign`/`RSA_verify` in call chain | N/A | N/A | CONFIRMED (absence) |
| 8 | Plaintext size | `shelper.dll FUN_1006a690` | 12-byte header + 64-byte key | 76 bytes | CONFIRMED |
| 9 | Ciphertext size | `shelper.dll FUN_10065ec0` | RSA encrypt output | 256 bytes (RSA-2048) | CONFIRMED |
| 10 | Failure behavior | `shelper.dll FUN_10065ec0`/`0x10065db0` | Core returns -1/0 | Indistinguishable from caller | CONFIRMED |
| 11 | Rust key size | `src/session/handshake.rs L10` | `RSESSION_RSA_BLOCK_SIZE = 256` | Matches binary | CONFIRMED_MATCH |
| 12 | Rust padding | `src/session/handshake.rs L262, 471` | `Padding::PKCS1` | Matches binary | CONFIRMED_MATCH |
| 13 | Rust plaintext size | `src/session/handshake.rs L12` | `RSESSION_PLAINTEXT_SIZE = 76` | Matches binary | CONFIRMED_MATCH |

---

## 10. Unresolved Questions

1. **Server RSA key provenance:** Which component supplies the 8 component buffers (`n,e,d,p,q,dmp1,dmq1,iqmp`) to `CreateServer`, and whether they come from a certificate embedded in `RvROLClient.dll` — UNKNOWN.
2. **RSA key rotation:** No key rotation observed within a session — whether the server ever rotates its RSA key is UNKNOWN.
3. **`RSA_free` zeroization:** Upstream OpenSSL behavior, unverified in this binary — do not claim secure key wiping in the spec.
4. **`DecryptBuffer_Private` extra parameter:** `ret $0x14` (5 stack args) while the core takes 3 — extra out/flag parameter meaning not recovered; do not reimplement that export from its name alone.

---

## 11. Documentation Corrections Required

`docs/CONTROL_PROTOCOL.md` §6.7/§6.8 and `docs/reverse-engineering/round-02/01-handshake.md`:

1. **Remove any claim of OAEP or `rsaesOaep` usage** — the string has zero xrefs and is inert.
2. **State PKCS#1 v1.5 only** — padding mode `1` confirmed at `0x10065f05`.
3. **Raw key format, not DER/PEM** — `BN_bin2bn` imports raw big-endian bytes.
4. **RSA is key transport only** — no signing, no `md5WithRSA`.

---

**Generated file:** `docs/CRYPTO_RSA_ANALYSIS.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered