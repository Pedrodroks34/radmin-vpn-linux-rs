# Cryptographic Analysis — RSA Key Provenance

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Binaries analyzed:** `shelper.dll`, `RvROLClient.dll`, `RvControlSvc.exe`  
**Language:** English  
**Status:** Investigation phase — key provenance unresolved  

---

## 1. Scope

This document analyzes RSA key provenance — where the client obtains the server public key, where the server obtains its private key, key rotation, and key validation. It is part of Investigation D of the cryptographic deep audit (key lifecycle priority #4).

**Limitation:** Key provenance could not be traced at instruction level. The server's private key source and key rotation behavior are UNKNOWN.

---

## 2. RSA Key Parameters (CONFIRMED)

| Parameter | Value | Evidence | Confidence |
|---|---|---|---|
| Key size | 2048 bits (256 bytes) | `RSA_size` → `0x100`; `RSESSION_RSA_BLOCK_SIZE = 256` | CONFIRMED |
| Key format | Raw modulus/exponent (big-endian) | `BN_bin2bn` imports raw bytes; no DER/PEM parsing | CONFIRMED |
| Public key | `(n, e)` pair | Client imports `n`@RSA+0x10, `e`@RSA+0x14 | CONFIRMED |
| Private key | `(n,e,d,p,q,dmp1,dmq1,iqmp)` | Server imports full set @RSA+0x10..+0x2c | CONFIRMED |
| Public exponent | `0x010001` (65537) | `DEFAULT_RSA_PUBLIC_EXPONENT` in Rust; imported from buffer in binary | CONFIRMED (value), UNVERIFIED (binary source) |
| Byte order | Big-endian | `BN_bin2bn` imports raw big-endian | CONFIRMED |
| Padding | PKCS#1 v1.5 (mode 1) | `PUSH 0x1` at `0x10065f05`/`0x10065de8` | CONFIRMED |
| OAEP | NOT used | `rsaesOaep` string has zero xrefs | CONFIRMED (absence) |
| Signing | NOT used | No `RSA_sign`/`RSA_verify` in call chain | CONFIRMED (absence) |

---

## 3. Client Public Key Source — UNKNOWN

### 3.1 What We Know

The client calls `SHelper_RSession_CreateClient(0x1006b860)` with `(h0, h1, h2, n, nlen, e, elen)` — the server's RSA public key modulus and exponent are passed as caller-supplied buffers.

### 3.2 What We Don't Know

| Question | Status |
|---|---|
| Where does the client obtain `(n, e)`? | UNKNOWN |
| Is the key embedded in `RvROLClient.dll` or `RvRvpnGui.exe`? | UNKNOWN |
| Is it received over the network before RSession? | UNKNOWN |
| Is it stored in configuration? | UNKNOWN |
| Is the key static or rotated? | UNKNOWN |

**Search needed:** Look for the modulus `e634471e…` (SRP N) or RSA modulus bytes in `.rdata` of `RvROLClient.dll`, `RvControlSvc.exe`, `RvRvpnGui.exe`. Look for `GetProcAddress` calls that resolve key-loading functions.

---

## 4. Server Private Key Source — UNKNOWN

### 4.1 What We Know

The server calls `SHelper_RSession_CreateServer(0x1006b8f0)` with 8 `(buf, len)` pairs for `(n, e, d, p, q, dmp1, dmq1, iqmp)` plus a parameter. These buffers are caller-supplied.

### 4.2 What We Don't Know

| Question | Status |
|---|---|
| Which component supplies the 8 component buffers? | UNKNOWN |
| Are they embedded in `RvROLClient.dll` or `RvControlSvc.exe`? | UNKNOWN |
| Are they loaded from a file at runtime? | UNKNOWN |
| Is the same key used across multiple sessions? | UNKNOWN (likely yes, but unproven) |
| Is there key rotation? | UNKNOWN |

**Search needed:** Search `.rdata` of `RvROLClient.dll` and `RvControlSvc.exe` for 256-byte modulus blobs. Trace callers of `SHelper_RSession_CreateServer` via the resolver field map (`FUN_1003fbd0` / `FUN_00442290`).

---

## 5. Key Import Flow (CONFIRMED)

### 5.1 Client Import

```
CreateClient(n_buf, nlen, e_buf, elen)
  → FUN_10069bc0 (ctor, malloc 0x34)
  → FUN_1006a690 (init, role=0)
  → FUN_10065f50 (RSA_new)
  → FUN_10066170 (import n at RSA+0x10, e at RSA+0x14 via BN_bin2bn)
```

### 5.2 Server Import

```
CreateServer(id, n,nlen,e,elen,d,dlen,p,plen,q,qlen,dmp1,dmp1len,dmq1,dmq1len,iqmp,iqmplen,param)
  → FUN_10069bc0 (ctor, malloc 0x34)
  → FUN_1006a700 (init, role=1)
  → FUN_10065f50 (RSA_new)
  → FUN_10065f70 (import all 9 components at RSA+0x10..+0x2c via BN_bin2bn)
```

### 5.3 BN_bin2bn (CONFIRMED)

`BN_bin2bn` at `0x10008a40` — imports raw big-endian bytes into BIGNUM. No DER parsing, no PEM decoding, no certificate validation.

---

## 6. Key Rotation — UNKNOWN

No key rotation observed within a session. Whether the server ever rotates its RSA key pair is UNKNOWN. No key reload or rollback logic was traced.

---

## 7. Key Validation — UNKNOWN

Whether the client validates the server's public key (e.g., modulus size check, primality test) before use is UNKNOWN. The binary's `SetServerPublicKey` in Rust checks `rsa.size() == 256`, but the binary's validation behavior was not traced.

---

## 8. RSA Operations by Role (CONFIRMED)

### 8.1 Client Role

1. Import server's RSA public key `(n, e)` via `BN_bin2bn`
2. Generate 64 random bytes (OpenSSL RAND_METHOD.bytes)
3. Build 76-byte plaintext: 12-byte LE header + 64-byte key material
4. `RSA_public_encrypt(plaintext, 76, ciphertext, server_pub_key, RSA_PKCS1_PADDING)`
5. Output: 256-byte RSA ciphertext block
6. Send 256-byte ciphertext to server

### 8.2 Server Role

1. Import full RSA private key via `BN_bin2bn`
2. Receive 256-byte RSA ciphertext
3. `RSA_private_decrypt(ciphertext, 256, decrypted, server_priv_key, RSA_PKCS1_PADDING)`
4. Validate decrypted length == 76 bytes (0x4c)
5. Extract 64-byte key material from `decrypted[12..76]`
6. Emit 4-byte server token to client

---

## 9. Evidence Table

| # | Claim | Evidence | Confidence |
|---|---|---|---|
| 1 | RSA-2048 (256 bytes) | `RSA_size` → `0x100` | CONFIRMED |
| 2 | Raw big-endian key format | `BN_bin2bn` import | CONFIRMED |
| 3 | PKCS#1 v1.5 padding | `PUSH 0x1` | CONFIRMED |
| 4 | No OAEP | `rsaesOaep` zero xrefs | CONFIRMED (absence) |
| 5 | No signing | No `RSA_sign`/`RSA_verify` in chain | CONFIRMED (absence) |
| 6 | Client imports `(n, e)` | `FUN_10066170` at RSA `+0x10`/`+0x14` | CONFIRMED |
| 7 | Server imports full private set | `FUN_10065f70` at RSA `+0x10..+0x2c` | CONFIRMED |
| 8 | Client public key source | Caller-supplied buffers to `CreateClient` | UNKNOWN |
| 9 | Server private key source | Caller-supplied buffers to `CreateServer` | UNKNOWN |
| 10 | Key rotation | Not observed | UNKNOWN |
| 11 | Key validation | Not traced | UNKNOWN |

---

## 10. Unresolved Questions

| # | Question | Impact | Next step |
|---|---|---|---|
| 1 | Client public key provenance | Can't replicate client side | Search `.rdata` for modulus blobs; trace `CreateClient` callers |
| 2 | Server private key provenance | Can't replicate server side | Search `.rdata` for private key components; trace `CreateServer` callers |
| 3 | Public exponent value in binary | May differ from 65537 | Trace `e` buffer source |
| 4 | Key rotation | Session security | Trace key reload logic |
| 5 | Public key validation | Security assessment | Trace validation calls after import |

---

## 11. Recommended Next Steps (Exact Addresses)

1. Search `RvROLClient.dll` `.rdata` for 256-byte modulus blobs matching the SRP N or RSA modulus
2. Search `RvControlSvc.exe` `.rdata` for RSA private key components
3. Trace callers of `SHelper_RSession_CreateClient` (`0x1006b860`) via `GetProcAddress` resolver
4. Trace callers of `SHelper_RSession_CreateServer` (`0x1006b8f0`) via `GetProcAddress` resolver
5. Check `rvpn_launcher.exe` and `adapter_hook.dll` for embedded keys

---

**Generated file:** `docs/CRYPTO_RSA_KEY_PROVENANCE.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered