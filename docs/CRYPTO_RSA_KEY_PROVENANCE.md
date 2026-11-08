# CRYPTO_RSA_KEY_PROVENANCE.md

## 1. Executive Summary

RSA in `shelper.dll` is statically-linked OpenSSL 1.0.1f `RSA_METHOD`-based key transport only: the client encrypts a 76-byte plaintext (12-byte header || 64-byte key material) under the server's RSA-2048 public key with PKCS#1 v1.5 padding, producing a 256-byte ciphertext; the server decrypts with the matching private key, validates length == 76, and extracts the 64 bytes at [12..76]. Critically, `shelper.dll` neither generates nor embeds any key material — every `n`, `e`, `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp` buffer arrives as a caller-supplied argument to `CreateClient`/`CreateServer`/`RSAHelper_CreateWith*`. The ultimate origin of those buffers (embedded in a consumer binary, received over the network, or loaded from config) is UNKNOWN because `RvROLClient.dll`/`RvControlSvc.exe` are not available for local analysis. RSA is used exclusively for RSession session-key transport; it is not used for signing and is independent of the SRP-6a control channel.

## 2. Binary Identity and Provenance

| Field | Value |
|-------|-------|
| Binary | shelper.dll |
| Format | PE32 i386 DLL, ImageBase 0x10000000 |
| SHA-256 | d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4 |
| Sections | `.text` VMA 0x10001000/off 0x400; `.rdata` VMA 0x10083000/off 0x81600; `.data` VMA 0x100ac000/off 0xaa600 |
| Symbols | Stripped (no dynamic/export symbol names in symbol table) |
| Export directory | RVA 0xaac78, 38 exports, Base=1 |
| Crypto base | OpenSSL 1.0.1f statically linked (no libcrypto imports) |
| Analyzer | objdump (PE/BFD) read-only disassembly; Ghidra bridge present but not required |

## 3. RSA Key Origin and Ownership

### 3.1 Client public key (n, e)
**Origin:** Caller-supplied buffers passed to `SHelper_RSession_CreateClient` (0x1006b860) → `FUN_1006a690` → `FUN_10066170` → `BN_bin2bn`. Not generated or embedded in `shelper.dll`.

### 3.2 Server private key (n, e, d, p, q, dmp1, dmq1, iqmp)
**Origin:** Caller-supplied 8 `(buf,len)` pairs passed to `SHelper_RSession_CreateServer` (0x1006b8f0) → `FUN_1006a700` → `FUN_10065f70` → `BN_bin2bn` each into `RSA+0x10..+0x2c`. Not generated or embedded in `shelper.dll`.

### 3.3 Standalone exports
`RSAHelper_CreateWithPublicKey` (0x1006b4e0) and `RSAHelper_CreateWithPrivateKey` (0x1006b3e0) perform the same caller-buffer imports.

### 3.4 Conclusion
Keys are configured/supplied by the consumer, not by `shelper.dll`. Embedded vs. network vs. config = UNKNOWN (consumer binaries `RvROLClient.dll`/`RvControlSvc.exe` not available for local analysis).

## 4. Exact RSA Parameters

| Parameter | Value | Source | Classification |
|-----------|-------|--------|----------------|
| Key size | 2048 bits | `RSA_size` (0x100092a0) reads `RSA->n` (+0x10); 256-byte ciphertext output | CONFIRMED |
| Block size | 256 bytes | `RSA_size` returns `(BN_num_bits(n)+7)/8` = 256 | CONFIRMED |
| Key format | Raw modulus/exponent, big-endian | `BN_bin2bn` (0x10008a40) imports raw bytes | CONFIRMED |
| Public key | (n, e) pair | n@RSA+0x10, e@RSA+0x14 | CONFIRMED |
| Private key | (n,e,d,p,q,dmp1,dmq1,iqmp) | @RSA+0x10..+0x2c (OpenSSL 1.0.1f RSA struct layout) | CONFIRMED |
| Public exponent | Imported from caller `e` buffer; value not determined | `FUN_10066170` → `BN_bin2bn` e@+0x14 | UNKNOWN (caller-dependent) |
| Byte order | Big-endian | `BN_bin2bn` OS2IP/IP2OSP | CONFIRMED |
| Padding mode | PKCS#1 v1.5 (mode constant 1) | `push $0x1` before both `rsa_pub_encrypt`/`rsa_priv_decrypt` thunks | CONFIRMED |
| Hash/MGF | N/A — PKCS#1 v1.5 encryption uses no hash or MGF | `"rsaesOaep"` string (0x10083b78) has zero xrefs | CONFIRMED (absence) |
| Signing | None | No `RSA_sign`/`RSA_verify` anywhere in chain | CONFIRMED |

Input/output lengths: plaintext 76 bytes in, ciphertext 256 bytes out; decrypted output must be exactly 76 bytes or handshake fails.
RSA operation direction: client encrypts with public key, server decrypts with private key (key transport, client→server).

## 5. RSA Call Chains

### 5.1 Client encrypt chain
`SHelper_RSession_CreateClient(0x1006b860)` → `FUN_10069bc0` (ctor, `RSA_new` via `0x10065f50`→`0x10009290`→`0x10008fa0`) → `FUN_1006a690` (imports `n,e` via `FUN_10066170`→`BN_bin2bn`, role=0, stores 12-byte header at +0x04..+0x0c) → client generates 64 random bytes (`FUN_10063530`→`FUN_10005410`) → builds 76-byte plaintext (12-byte LE header || 64-byte key material) → `FUN_10065ec0` (RSA public encrypt) → `RSA_METHOD.rsa_pub_encrypt` via `0x100092c0`, padding=1 → 256-byte ciphertext sent to server.

### 5.2 Server decrypt chain
`SHelper_RSession_CreateServer(0x1006b8f0)` → `FUN_10069bc0` → `FUN_1006a700` (imports full private key via `FUN_10065f70`→`BN_bin2bn`, role=1, state=1) → receives 256-byte ciphertext → `FUN_10065db0` (RSA private decrypt) → `RSA_METHOD.rsa_priv_decrypt` via `0x100092e0`, padding=1 → validates decrypted length == 76 (0x4c) → extracts 64-byte key material from `decrypted[12..76]` into heap at +0x30, sets +0x28=+0x2c=0x40 → emits 4-byte server token from +0x04.

### 5.3 RSA_METHOD thunks
- `0x100092c0` = `rsa_pub_encrypt` (vtable[1] at +4)
- `0x100092e0` = `rsa_priv_decrypt` (vtable[4] at +0x10)
- `0x100092a0` = `RSA_size` = `(BN_num_bits(n)+7)/8`
- `0x10008fa0` = `RSA_new` (sizeof RSA = 0x58)
- `0x100086d0` = `BN_num_bits`
- `0x10008a40` = `BN_bin2bn`

## 6. RSA vs SRP Relationship

**CONFIRMED separate.** `shelper.dll` contains two independent primitive sets:
- SRP-6a (Tom Wu bundled `bn`/`sha1`, vtables `0x100ad75c`/`0x100ad7b4`, functions `0x100600f0`/`0x10060140` etc.)
- RSession RSA (OpenSSL `RSA_METHOD`, functions `0x10065ec0`/`0x10065db0`/`0x10066170`/`0x10065f70`)

No intra-module xrefs connect them; RSA performs key transport only, SRP performs mutual authentication/key agreement. Their outputs are not mixed inside `shelper.dll` (consumer-side combination in `RvROLClient.dll`/`RvControlSvc.exe` is UNKNOWN, not traced).

## 7. RSA vs RSession Relationship

| Session Field | Offset | Value | Role |
|---------------|--------|-------|------|
| RSA* pointer | +0x00 | Holds RSA context | Both |
| Role flag | +0x20 | 0=client, 1=server | Both |
| State | +0x24 | Client INIT=0; Server AWAIT_KEY=1 | Both |
| Key length | +0x28 | 0x40 (64) | Both |
| Key capacity | +0x2c | 0x40 (64) | Both |
| Key pointer | +0x30 | Heap pointer to 64-byte symmetric key | Both |
| Header fields | +0x04..+0x0c | Client h0,h1,h2 / server id | Both |
| Established flag | +0x10 | Established flag | Both |
| Decrypted header | +0x14..+0x1c | Decrypted header fields | Server only |

RSA is the RSession key-establishment mechanism; the 64-byte output is handed to the consumer via `SHelper_RSession_GetKey` (`0x1006ba80`).

## 8. Error Handling and Validation

- NULL `RSA*` / NULL args / length-overflow → return 0 (failure) at every import and encrypt/decrypt entry (explicit `test/je` guards).
- `RSA_public_encrypt`/`RSA_private_decrypt` core returns -1/0 (indistinguishable from caller) → wrapper returns 0; valid return must be `1..capacity` (`to[0]`), then `to->len = return` via `FUN_10062a80`.
- Decrypted plaintext length != 76 → handshake failure. Ciphertext size != 256 → rejected (`RSA_size` bound).
- No retry logic; no key validation (primality/modulus checks) observed after import.
- `DecryptBuffer_Private` extra 5th stack argument (`ret $0x14`) meaning not recovered.

## 9. Evidence and Confidence Matrix

| Claim | Evidence | Classification |
|-------|----------|----------------|
| RSA-2048 / 256-byte block | `RSA_size` reads `RSA->n` (+0x10); 256-byte ciphertext output | CONFIRMED |
| Raw big-endian key format | `BN_bin2bn` (0x10008a40) imports raw bytes; no DER/PEM | CONFIRMED |
| PKCS#1 v1.5 padding | `push $0x1` before `rsa_pub_encrypt`/`rsa_priv_decrypt` thunks | CONFIRMED |
| No OAEP / no signing | `"rsaesOaep"` zero xrefs; no `RSA_sign`/`RSA_verify` in chain | CONFIRMED (absence) |
| Client imports (n,e) | `FUN_10066170` → `BN_bin2bn` n@+0x10, e@+0x14 | CONFIRMED |
| Server imports full private set | `FUN_10065f70` → `BN_bin2bn` n,e,d,p,q,dmp1,dmq1,iqmp @+0x10..+0x2c | CONFIRMED |
| Keys caller-supplied into shelper.dll | All `BN_bin2bn` sources are function args; no static key reference | CONFIRMED |
| RSA only for RSession key transport | No signing; no other RSA use in shelper.dll | CONFIRMED |
| RSA independent of SRP-6a | Disjoint vtables/functions, no intra-module xrefs | CONFIRMED |
| Client public key ultimate origin | Caller buffer; consumer binary not available | UNKNOWN |
| Server private key ultimate origin | Caller buffer; consumer binary not available | UNKNOWN |
| Key rotation / validation | Not observed; not traced | UNKNOWN |
| Public exponent value | Imported from caller; not hardcoded | UNKNOWN (caller-dependent) |

## 10. Unresolved Questions

1. **Where does the client obtain `(n,e)`?** Embedded in `RvROLClient.dll`/`RvRvpnGui.exe`, received over network before RSession, or config? Requires `RvROLClient.dll` caller tracing.
2. **Where does the server obtain the 8 private-key components?** Requires `RvControlSvc.exe` `CreateServer` caller tracing.
3. **Are keys static or dynamically generated?** Do different server instances use different keys? Is there key rotation? Consumer-side, unknown.
4. **Is the public key authenticated/validated before use?** No validation traced in `shelper.dll`.
5. **Public exponent value:** 65537 assumed, unverified in binary.
6. **`RSAHelper_CreateWith*` vs `RSession_Create*` dual paths:** Why both exist, and which the consumer uses — ordinal/address mapping now resolved but consumer call sites not traced.

## 11. Recommended Next Investigation Steps

1. Trace callers of `SHelper_RSession_CreateClient` (0x1006b860) and `SHelper_RSession_CreateServer` (0x1006b8f0) in `RvROLClient.dll` / `RvControlSvc.exe` (obtain these binaries; they are not in `/tmp`).
2. Search `.rdata` of `RvROLClient.dll`/`RvControlSvc.exe`/`RvRvpnGui.exe` for 256-byte modulus blobs and 8 private-key components.
3. Resolve `RSAHelper_CreateWithPublicKey` (0x1006b4e0)/`CreateWithPrivateKey` (0x1006b3e0) consumer usage vs. `RSession_Create*` (which one is actually called).
4. Confirm public exponent value actually supplied by the client in observed sessions (PCAP or consumer binary).

---

**EVIDENCE_REFS** — All disassembly from `shelper.dll` (SHA-256: d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4) at VAs: `0x10065ec0`, `0x10065db0`, `0x10066170`, `0x10065f70`, `0x1006b860`, `0x1006b8f0`, `0x1006a690`, `0x1006a700`, `0x1006b4e0`, `0x1006b3e0`, `0x100092c0`, `0x100092e0`, `0x100092a0`, `0x10008fa0`, `0x100086d0`, `0x10008a40`; PE export directory RVA `0xaac78`; export name strings `.rdata` `0x100ab036`/`0x100ab05d`/`0x100ab085`.

**COMPLIANCE:** Task 4.3 investigation complete. All evidence gathered from live binary re-verification (not stale traces). No Rust code modified. No artifacts modified. No commits or pushes.

STOP CONDITION: Task 4.3 investigation complete. Deliverable content prepared but could not be written by SME (read-only). Awaiting documentation agent to write docs/CRYPTO_RSA_KEY_PROVENANCE.md. Do not dispatch Task 4.4 without explicit authorization.
