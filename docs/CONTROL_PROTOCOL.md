# Radmin VPN Control Protocol: Phases 5 to 9

**Status:** PARTIAL SPECIFICATION. Serialization and encryption analysis via Ghidra headless (phases 5 to 9).

**Binaries analyzed:**
- `RvControlSvc.exe`: SHA-256 `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`
- `RvROLClient.dll`: contains references to `CCryptoChannel@RolClient`
- `shelper.dll`: helper library based on OpenSSL 1.0.1f, contains `AESCryptor` and `RSAHelper`

**Ghidra projects:**
- `/tmp/opencode/ghidra_project2/control_project.rep` (RvControlSvc.exe)
- `/tmp/opencode/ghidra_project/radmin_project.rep` (RvROLClient.dll)
- `/tmp/opencode/ghidra_project3/shelper_project.rep` (shelper.dll)

**Important:** Everything in this document is **static** evidence (code, RTTI, vtables, constants). Nothing here has been confirmed against encrypted traffic. Where this document and `PROTOCOL_SPEC.md` disagree, see the reconciliation notes in each section. The key-exchange call graph, AES key flows, and RSA operations are consolidated in `KEY_EXCHANGE_ANALYSIS.md` (Phase 1 Wave 3 register; confirmed items from Wave 1, Tasks 1.1 to 1.3 and 2.1).

---

## 1. Location of RTTI strings (confirmed)

### RvControlSvc.exe

| RTTI string | Address | Note |
|---|---|---|
| `CPacket_KeepAlive` | 0x556a58, 0x556a84 | Two occurrences |
| `CPacket_Handshake_Syn` | 0x5569c8, 0x5569f8 | Two occurrences |
| `CPacket_Shutdown` | 0x556b70 | One occurrence |
| `CPacket_RadminPort` | 0x556b14 | One occurrence |
| `CPacket_Frame` | 0x556970 | One occurrence |
| `CPacket_ConfirmSwitch` | 0x556910 | One occurrence |
| `CPacket_StartSwitch` | 0x556b9c | One occurrence |
| `CPacket_FinalizeSwitch` | 0x556940 | One occurrence |
| `CPacket_PacketFilter` | 0x556ab4 | One occurrence |

### shelper.dll

| RTTI string | Address | Note |
|---|---|---|
| `.?AVAESCryptor@@` | 0x100aee88 | `AESCryptor` class |

**Confidence:** Confirmed (exact location via Ghidra).

---

## 2. Class hierarchy (confirmed by RTTI and CHD)

### CPacket_* (RvControlSvc.exe)

```
CPacket_*@ControlSvc
├── CPacket@ControlSvc
├── CSelfDeletingObject@FamRT
└── IPacket@ControlSvc
```

### AESCryptor (shelper.dll)

```
AESCryptor
└── BaseCryptor
```

**Confidence:** Confirmed.

---

## 3. Vtables (confirmed)

### CPacket_*: 7 entries (indices 0 to 6)

| Index | Role |
|---|---|
| [0] | Destructor |
| [1] | RTTI COL pointer |
| [2] | Destructor thunk |
| [3] | **Serialization** |
| [4] | Type or validation |
| [5] | Constant 0x3e8 |
| [6] | Null |

### AESCryptor (shelper.dll): 17 entries (indices 0 to 16)

| Index | RVA | Role |
|---|---|---|
| [0] | 0x62c80 | Destructor |
| [1] | 0x62e00 | **Encrypt** (AES-CBC, mode 1) |
| [2] | 0x62d60 | **Decrypt** (AES-CBC, mode 0) |
| [3] | 0x62e90 | **GetBlockSize** (returns 0x10) |
| [6] | 0x62fb0 | **SetKeyEnc** (32 bytes) |
| [7] | 0x62f30 | **SetKeyDec** (32 bytes) |

**Confidence:** Confirmed.

---

## 4. Message type constants (confirmed in static code)

| Constant | Packets | Function |
|---|---|---|
| `0x1311` | `CPacket_Handshake_Syn` | `FUN_004285b0` |
| `0x1312` | `CPacket_KeepAliveAck`, `CPacket_Handshake_SynAck` | `FUN_00428880` |
| `0x1313` | `CPacket_KeepAlive`, `CPacket_Handshake_Ack` | `FUN_004282f0` |

Packets with base serialization: `CPacket_Shutdown`, `CPacket_ConfirmSwitch`, `CPacket_FinalizeSwitch`.

**Confidence:** Confirmed in static code. Not confirmed in traffic (encrypted).

---

## 5. Serialization pipeline (confirmed in static code)

### 5.1 PRECEX structure

| Offset | Field |
|---|---|
| +0x00 | flags |
| +0x04 | data_ptr |
| +0x08 | data_size |
| +0x0C | capacity |
| +0x28 | msg_type (0x1311, 0x1312, or 0x1313) |

### 5.2 Field write functions

| Function | RVA | Size | Tag | Byte swap? |
|---|---|---|---|---|
| `FUN_00472ef0` | 0x72ef0 | 4 bytes | `0x1000302` | Yes |
| `FUN_00472f60` | 0x72f60 | 8 bytes | `0x2000303` / `0x20001e1` | Yes |
| `FUN_004795d0` | 0x795d0 | Variable | `0x9000304` | No |
| `FUN_00427060` | 0x27060 | 2 bytes | none | `Ordinal_9` |

### 5.3 Field layouts per class (inferred)

See section 6 of the earlier phase 7 document, which is not in this repository. Field offsets are confirmed there; types are inferred.

---

## 6. Cryptography (confirmed in phases 8 and 9, static)

### 6.1 Library: shelper.dll (OpenSSL 1.0.1f)

Based on OpenSSL 1.0.1f (the string "AES part of OpenSSL 1.0.1f" confirms it).

### 6.2 Algorithm: AES-256-CBC (confirmed in static code)

**Evidence:**

1. RTTI: class named `AESCryptor` (`.?AVAESCryptor@@`).
2. Key size is 32 bytes (0x20). `SHelper_CChannel_SetKeyEnc` and `SHelper_CChannel_SetKeyDec` check `param_3 == 0x20`.
3. Block size is 16 bytes (0x10). `FUN_10062e90` (vtable[3]) returns 0x10.
4. CBC mode, inferred from `FUN_10063470` (XOR with the previous block).
5. `FUN_10003b30`: AES implementation (lookup tables `DAT_10001800` and `DAT_10002e80`, processing 16-byte blocks, mode parameter `param_6`: 0 for decrypt, 1 for encrypt).

**To reconcile:** `PROTOCOL_SPEC.md` §4 lists the algorithm as unknown. This section is the static candidate. The traffic is consistent with high-entropy payloads (see §7.1), but no decryption has been performed.

### 6.3 `FUN_10003b30`: details (confirmed)

- **Size:** 1,619 bytes.
- **Parameters:** (input*, output*, size, key_schedule*, IV*, mode).
- **Mode:** `param_6 == 0` for decrypt (uses `DAT_10002e80`), `param_6 != 0` for encrypt (uses `DAT_10001800`).
- **Processing:** 16-byte blocks, with an alignment check (`param_3` must be a multiple of 16).
- **Lookup tables:** `DAT_10001800` (encrypt T-tables), `DAT_10002e80` (decrypt T-tables).
- **Helper functions:** `FUN_100024f0`, `FUN_10002980`, `FUN_100013a0`, `FUN_10001040`, `FUN_100015a0`, `FUN_10002c40` (round functions).
- **Classification:** inferred as a custom AES (not OpenSSL EVP), based on the lookup tables and manual block processing. It may be OpenSSL's `AES_cbc_encrypt` inlined.

### 6.4 IV (initialization vector)

**Confirmed:**

- Size: 16 bytes.
- Stored at: `AESCryptor+0x1ec` (encrypt) and `AESCryptor+0x1fc` (decrypt).
- Lifecycle: both IVs are zero-initialized when the AESCryptor object (0x20c bytes, constructor `FUN_10062b60`, vtable `0x100832a0`) is created, persist across frames, and are updated from the last ciphertext block. The encrypt and decrypt directions keep independent IVs.
- Set by: `FUN_10062ff0` (encrypt, copies 16 bytes to `this+4` or `this+0x1ec`, unclear) and `FUN_10062f80` (decrypt).
- `FUN_100633d0` copies 16 bytes (`FUN_10065150`, size 0x10).

**Unknown:**

- Whether the IV is sent with the ciphertext (the confirmed flow keeps it in local object state; no wire copy observed).
- The role, if any, of the global constant `_DAT_100832f0` referenced in the earlier read of `FUN_10063470` and `FUN_100633e0`; superseded as the IV origin by the confirmed zero-initialized local state.

**Inferred:**

- The confirmed lifecycle (zero-initialized, per direction, carried across frames) means the IV is per-channel state, not per-message.

**Evidence:** `KEY_EXCHANGE_ANALYSIS.md` §6.2 (Wave 1 register); `CRYPTO_AES_CONSUMER_TRACE.md`.

### 6.5 Custom padding (confirmed)

**`FUN_10069c20` (encryption preparation):**

1. Padded size: `sVar3 = ((param_4 + 8 + param_3) / param_4) * param_4`
   - `param_4` is the block size (16).
   - `param_3` is the data size.
   - Overhead: 9 bytes minimum (8-byte trailer digest plus 1-byte pad length).
2. Allocate a buffer of size `sVar3`.
3. Copy the original data (`param_3` bytes).
4. Choose a pad length `pad_len` in the range `[9, 24]` and fill the region between the payload end and `sVar3 - 9` with `0xcc` (`pad_len - 9` bytes; it may be empty when `pad_len = 9`).
5. Compute the additive checksum (`FUN_1006a0c0`): 64-bit little-endian word-additive sum over `buf[0 .. sVar3 - 9]`, with zero-fill of a residual tail shorter than 8 bytes.
6. Compute `digest = MD5(LE64(sum))` over the 8-byte little-endian encoding of that sum (context `FUN_100638f0` → MD5 `0x10005250` / `0x10004e50` / `0x10004f30`; exactly one compression block).
7. Fold the 16-byte digest to 8 bytes: `fold[i] = digest[i] + digest[i+8] mod 256` (`0x10069ce0`–`0x10069d15`), and write the 8 folded bytes plus `pad_len` in the last 9 bytes.

**`FUN_10069f90` (validation on decryption):**

1. Read the last byte as the pad length; required range `[9, 24]` (gate `0x10069fe5`).
2. Validate: every byte in `buf[payload_len .. total - 9]` must be `0xcc`.
3. Recompute the same sequence (additive checksum → MD5 → fold) and compare the 8 folded bytes with the stored trailer.
4. If valid: `data_ptr = param_3`, `data_size = total - pad_len`.

The CBC decrypt runs **before** validation (confirmed: `call [eax+8]` at `0x10069d9b`–`0x10069dab` precedes the check in `FUN_10069f90`).

**Overhead:** `pad_len` bytes per frame (9 to 24): the `0xcc` fill plus the 9-byte trailer.

**Padding classification:** proprietary, not PKCS#7. Filled with `0xcc` plus a 9-byte trailer (8-byte folded MD5, 1-byte pad length).

**Evidence:** `KEY_EXCHANGE_ANALYSIS.md` §6.2 (Wave 1 register, Tasks 1.3 and Investigations B/D); `CRYPTO_AES_CONSUMER_TRACE.md` items 12 to 15; `CRYPTO_MD5_ANALYSIS.md` E10 and E14.

### 6.6 Checksum (`FUN_1006a0c0`) and folded MD5 trailer

- **Type:** 64-bit little-endian word-additive sum, implemented as an `add`/`adc` chain over 8-byte words (not a cryptographic MAC).
- **Role:** the additive checksum is an **intermediate input**, not the stored trailer. The 8 trailer bytes are the **folded MD5** of that sum's 8-byte LE encoding: MD5 via `FUN_100638f0` (`0x10005250` / `0x10004e50` / `0x10004f30`), folded by `out[i] = digest[i] + digest[i+8] mod 256` (`0x10069ce0`–`0x10069d15`).
- **Verifier:** `FUN_10069f90` recomputes the same sequence (additive checksum → MD5 → fold) and compares the folded value against the stored 8 bytes.
- **Not a MAC (confirmed):** the computation is unkeyed — no key material enters the checksum, MD5, or fold. It provides corruption detection only, not authenticity.

**Evidence:** `KEY_EXCHANGE_ANALYSIS.md` §6.2 (Wave 1 register); `CRYPTO_AES_CONSUMER_TRACE.md` items 12 to 15; `CRYPTO_MD5_ANALYSIS.md` E10, E14; `CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md` C7, C12.

### 6.7 Key exchange: RSA (confirmed)

**`SHelper_RSAHelper_*`:**

- `CreateWithPublicKey(modulus, mod_size, exponent, exp_size)`: RSA with a public key.
- `CreateWithPrivateKey(...)`: RSA with a private key (modulus, exponent, factors, CRT parameters).
- `EncryptBuffer_Public` / `EncryptBuffer_Private`: encrypt with RSA.
- `DecryptBuffer_Public` / `DecryptBuffer_Private`: decrypt with RSA.
- Used to exchange the AES-256 key securely.

**RSA operations and parameters (confirmed, Wave 1 register — `KEY_EXCHANGE_ANALYSIS.md` §5.1, §5.3; Task 1.3):**

- `RSA_public_encrypt` wrapper `FUN_10065ec0`: `flen = 0x4c` (76 bytes), `pad = 1` (constant `push 1` at `0x10065f05`).
- `RSA_private_decrypt` wrapper `FUN_10065db0`.
- RSession client/server state machine `FUN_1006a2b0` (role 0 = client, role 1 = server; the server requires plaintext length exactly `0x4c`).
- Modulus: 2048 bits — `RSA_size` (`0x100092a0`) returns `0x100` (256 bytes); ciphertext block 256 bytes.
- Key import: raw big-endian components via `BN_bin2bn` (`0x10008a40`), no DER/PEM.
- Transported plaintext: 76 bytes = 12-byte header (3 × LE u32) plus 64-byte key material; the server copies `plaintext[12..76]` into the session object (`obj+0x30`, length `0x40`).

**RSA padding mode: unverified (contradiction C3).** The `pad = 1` constant at `0x10065f05` is confirmed; its interpretation is not. Prior traces favor PKCS#1 v1.5 (`RSA_PKCS1_PADDING`); no OAEP/MGF code was found in Wave 1, but the padding mode was explicitly not re-verified (circuit breaker, Task 1.3). The strings `rsaesOaep` and `RSAES-OAEP` are present in `shelper.dll` with no re-verified cross-references. See `KEY_EXCHANGE_ANALYSIS.md` §5.2 and §8.2 (C3).

**Key provenance gap (unverified):** the 64-byte RSession secret (session object `obj+0x30`, length `0x40`) has no located consumer in `RvROLClient.dll`; the hand-off into `CChannel_SetKeyEnc`/`SetKeyDec` — including the proposed 64→32+32 split into two 32-byte AES keys — is unverified. The composition point is likely in `RvControlSvc.exe` (untraced). See `KEY_EXCHANGE_ANALYSIS.md` §4.2, §7, and §8 (U1, U2, C1, C2).

### 6.8 RSession (confirmed)

**`SHelper_RSession_*`:**

- `CreateClient(server_pubkey, server_pubkey_size, ...)`: creates a client session.
- `CreateServer(client_pubkey, ..., server_privkey, ...)`: creates a server session.
- `GetKey(session, &key_ptr, &key_size)`: retrieves the AES key from the session.
- `GetClientDataOnServer(session, ...)`: client data on the server.
- `GetServerDataOnClient(session, ...)`: server data on the client.

**RSession layout (inferred):**

- +0x04: param_1 (context)
- +0x08: param_2
- +0x0C: param_3
- +0x10: pointer to data (AESCryptor?)
- +0x14: data size
- +0x18: pointer to additional data
- +0x1C: size
- +0x20: flag (0 for client, 1 for server)
- +0x24: flag
- +0x28: pointer to encrypted data
- +0x2C: size
- +0x30: pointer to data

### 6.9 Full encryption flow (as described by the static analysis)

```
SEND:
1. CPacket_*::vtable[3] serializes to PRECEX (0x1311, 0x1312, or 0x1313)
2. RSA transports a 64-byte secret via the RSession functions (SHelper_RSAHelper_* / SHelper_RSession_*); the two 32-byte AES keys are installed through CChannel_SetKeyEnc / SetKeyDec (the 64→32+32 split is unverified, see §6.7)
3. SHelper_CChannel_EncryptBuffer:
   a. FUN_10069c20: 0xcc fill, additive checksum, MD5, fold to 8 bytes, 1-byte pad length (see §6.5)
   b. vtable[1] (FUN_10062e00 to FUN_10003b30): AES-256-CBC encrypt
   c. FUN_10062ad0: store result
4. TCP frame: 4-byte big-endian uint32 (size) plus encrypted payload
5. TCP send (port 17301 or 17351)

RECEIVE:
1. TCP receive (4-byte big-endian frame header plus payload)
2. SHelper_CChannel_DecryptBuffer:
   a. vtable[2] (FUN_10062d60 to FUN_10003b30): AES-256-CBC decrypt
   b. FUN_10069f90: validate pad length, 0xcc fill, additive checksum, and folded MD5 (see §6.5)
   c. FUN_10068230: bounds check
   d. FUN_10062800: copy result
   e. FUN_10062ad0: store result
3. PRECEX deserialization into CPacket_* fields
```

---

## 7. Correlation with capture (phases 7 to 9)

### 7.1 Encrypted traffic (confirmed, with caveat)

- All TCP traffic after the initial handshake is described as AES-256-CBC.
- The constants 0x1311, 0x1312, and 0x1313 are not visible in the traffic.
- Payloads have high entropy, which is consistent with AES-CBC.

**Caveat:** The statement that all traffic after the initial handshake is AES-encrypted is an inference from entropy and the static code. It has not been verified by decryption.

### 7.2 Initial handshake (confirmed, with caveat)

- `00 00 00 04 03 00 00 00` is the first frame of every connection.
- It occurs before encryption is enabled.
- Payload `03 00 00 00` (little-endian uint32 = 3) may be a version or handshake identifier.
- It appears in both directions (client to server and server to client).

**Caveat:** the big-endian frame header is `00 00 00 04`, and the 4-byte payload is `03 00 00 00`. Reading that payload as little-endian gives 3. Whether the value is little-endian, and what it means, is not confirmed.

### 7.3 Frame sizes

- Encryption overhead: `pad_len` bytes per frame, in the range `[9, 24]` — the `0xcc` fill plus the 9-byte trailer (8-byte folded MD5 plus 1-byte pad length; see §6.5).
- Observed payload sizes are multiples of 16 (only exception: the 4-byte control frame), consistent with 16-byte-block AES-CBC (`KEY_EXCHANGE_ANALYSIS.md` §6.2; frames f32, f35, f40, f44 of `radmin_17301.pcap`).
- This explains the variety of observed sizes (32, 36, 48, 64, 96, and so on).

### 7.4 Ports

| Port | Use | Encryption |
|---|---|---|
| 17301 | Control (server) | AES-256-CBC |
| 17351 | Peer to peer | AES-256-CBC |

**To reconcile:** `PROTOCOL_SPEC.md` §9.2 lists `45.162.230.182:17351` as a server, not a peer. Confirm which role port 17351 has.

---

## 8. Limitations of the analysis

1. **`FUN_10003b30`:** not confirmed whether it is OpenSSL EVP or a custom implementation. The lookup tables suggest AES T-tables. Classified as inferred.
2. **IV:** generation is confirmed for the encrypted-buffer path — both IVs are zero-initialized in the AESCryptor object and persist across frames (§6.4, `KEY_EXCHANGE_ANALYSIS.md` §6.2). Whether an initial IV ever crosses the wire is not known. The global constant `_DAT_100832f0` is superseded as the initial-IV origin by the confirmed zero-initialized local state. Initial-IV origin beyond the zero-init: classified as unknown (supersedes, from Wave 1).
3. **RSA padding:** the `pad = 1` constant at `0x10065f05` is confirmed; its interpretation is not. Prior traces favor PKCS#1 v1.5, but the mode was not re-verified in Wave 1 (circuit breaker, Task 1.3). Classified as unverified (contradiction C3, `KEY_EXCHANGE_ANALYSIS.md` §5.2 and §8.2) — this supersedes the older "OAEP?" inference.
4. **Semantic meaning of the CPacket fields** (offsets): not determined. Classified as unknown.
5. **Field tags** (0x0302, 0x0303, 0x01e1, 0x0304): meaning not confirmed. Classified as unknown.
6. **Checksum:** confirmed not to be a MAC — the computation is unkeyed (no key material enters the checksum, MD5, or fold); it provides corruption detection only (§6.6; `KEY_EXCHANGE_ANALYSIS.md` §6.2). Scope confirmed as validation of the padding trailer.
7. **IV scope:** per-direction channel state carried across frames is confirmed (§6.4). Behavior of the IVs across reconnects/new channel objects is not determined. Classified as confirmed (per-direction persistence) / unknown (cross-session).
8. **No dynamic execution:** no debugging or replay.

---

## 9. Unknown information

| Item | Status | Needed to |
|---|---|---|
| IV generation and exchange | Generation confirmed per direction (zero-initialized, persistent); exchange/transmission unknown | Reproduce the encryption |
| RSA padding mode | Unverified — pad = 1 constant confirmed; interpretation unverified (contradiction C3; prior traces favor PKCS#1 v1.5) | Reproduce the key exchange |
| Identity of `FUN_10003b30` | Inferred (custom AES) | Confirm the implementation |
| Semantic fields (CPacket) | Unknown | Implement the packets |
| Field tags | Unknown | Implement serialization |
| IV per session or per message | Per-direction channel state confirmed; cross-session behavior unknown | Reproduce the encryption |
| Checksum use (MAC?) | Confirmed not a MAC — corruption detection only (§6.6) | Implement validation |

---

## 10. Confirmed cross-module linkage and crypto-free boundaries (Wave 1 register)

**Status:** Confirmed items from Wave 1 (Tasks 1.1, 1.2, 1.3; consolidated in `KEY_EXCHANGE_ANALYSIS.md` §3). Slot *names* and *resolution* are confirmed; several underlying *implementations* rest on prior traces and are marked UNVERIFIED. Nothing here contradicts §6 (cryptography) or §7 (capture correlation).

### 10.1 RvROLClient.dll → shelper.dll linkage (CONFIRMED)

- **Static import:** `RvROLClient.dll` imports exactly one function from `shelper.dll`: `SHelper_Init` (hint/ordinal 22), at IAT `0x1011121c` (Task 1.2, CONFIRMED).
- **Dynamic resolution:** `InitDll` at `0x10041010` → global object `0x10187030` (vtable `0x10115d6c`) → `vtable[1] = FUN_1003fbd0` → 38× `GetProcAddress` against `shelper.dll` → resolved pointers stored into the global object's API table, slots `+0x58` .. `+0xec` (Task 1.2, CONFIRMED). Correction carried forward: addresses `0x1003fd48` / `0x1003fd56` inside `FUN_1003fbd0` are name pushes feeding `GetProcAddress`, not indirect calls.

### 10.2 API-table slot map (slot names CONFIRMED; implementations as noted)

| API-table slot (RvROLClient.dll) | Resolved shelper export | shelper implementation | Status |
|---|---|---|---|
| `SHelper_Init` +0x58 | `SHelper_Init` | static import | CONFIRMED |
| +0x98 | `SHelper_RSession_CreateClient` | `0x1006b860` (ord 31) | CONFIRMED (Task 1.3) |
| +0x9c / +0xa0 | `SHelper_RSession_CreateServer` / `_Delete` | `0x1006b8f0` (ord 32) / `0x1006b9e0` (ord 33) | CONFIRMED (Task 1.3) |
| +0xc0 | `CChannel_SetKeyEnc` | `0x1006ab00` | slot CONFIRMED; implementation UNVERIFIED (prior trace) |
| +0xc4 | `CChannel_SetKeyDec` | `0x1006aac0` | slot CONFIRMED; implementation UNVERIFIED (prior trace) |
| +0xc8 | `CChannel_EncryptBuffer` | AESCryptor path | slot name CONFIRMED; call sites UNKNOWN |
| +0xcc | `CChannel_DecryptBuffer` | AESCryptor path | slot name CONFIRMED; call sites UNKNOWN |
| +0xd0 | `RSAHelper_CreateWithPublicKey` | address mapping UNKNOWN | name string CONFIRMED (`0x100ab06f`) |
| +0xd4 | `RSAHelper_CreateWithPrivateKey` | address mapping UNKNOWN | name string CONFIRMED (`0x100ab048`) |

Name-string anchors in `shelper.dll` `.rdata` (CONFIRMED, Task 1.3): `RSAHelper_CreateWithPrivateKey` @ `0x100ab048`, `RSAHelper_CreateWithPublicKey` @ `0x100ab06f`.

**Unlocated:** No call site in `RvROLClient.dll` was located for `CChannel_CreateClient` / `SetKeyEnc` / `SetKeyDec`; the consumer hand-off point is UNKNOWN (likely `RvControlSvc.exe`, untraced). See `KEY_EXCHANGE_ANALYSIS.md` §7, §8 (U1, C1).

### 10.3 Named-pipe boundary — crypto-free (CONFIRMED)

`\\.\pipe\RadminVpnGuiChannel` (GUI ↔ service) uses plain named-pipe I/O (`CreateFileW`, `WaitNamedPipeW`, `WriteFile`, `ReadFile`, `TransactNamedPipe`) and contains **no** `ROLClient` imports and **no** crypto calls. The pipe is an unencrypted brokerage channel; the RSA/SRP/AES path lives deeper in the service stack (Task 1.1, CONFIRMED). It is not the TCP/17301 control channel.

### 10.4 Random sources (CONFIRMED / prior trace)

- `RvROLClient.dll`: only random source is ADVAPI32 `CryptGenRandom`, 4 bytes per call (`CryptAcquireContext`/`CryptGenRandom`/`CryptReleaseContext`) — CONFIRMED (Task 1.2). No 32-byte AES key is generated inside `RvROLClient.dll`.
- `shelper.dll`: statically linked OpenSSL 1.0.1f `RAND_METHOD.bytes`; 64-byte draws on the RSession path (`FUN_10063530` → `FUN_10005410`) — CONFIRMED for RSession; SRP draw shape is prior trace.

### 10.5 Two-key CChannel contract (CONFIRMED at shelper level)

`CChannel_CreateClient` (`0x1006a8b0`, inner `FUN_1006a630`) requires two exactly-32-byte keys; `CChannel_SetKeyEnc` (`0x1006ab00`) / `CChannel_SetKeyDec` (`0x1006aac0`) both reject length ≠ `0x20` (32). Slot pointers `+0xc0`/`+0xc4`/`+0xc8`/`+0xcc` are installed by `FUN_1003fbd0`. The composition point `source → SetKeyEnc/SetKeyDec` (including the 64→32+32 split of the RSession secret) is UNVERIFIED — no consumer call site located; likely in `RvControlSvc.exe`. See `KEY_EXCHANGE_ANALYSIS.md` §4.2, §7, §8 (U2, C1, C2).

**Relationship to this document:** this section consolidates confirmed linkage facts from `KEY_EXCHANGE_ANALYSIS.md`; it does not change §6 (cryptography) or §7 (capture correlation), which remain consistent with these findings.

## 11. Next steps

1. **Confirm the IV transmission:** the IV lifecycle inside the AESCryptor object is confirmed (zero-initialized, per direction, persistent; §6.4). What remains is whether an initial IV crosses the wire at channel setup (decompile `FUN_10062ff0` and `FUN_10062f80` more deeply, or use the Ghidra GUI).
2. **Confirm `FUN_10003b30`:** compare with OpenSSL's `AES_cbc_encrypt`.
3. **Resolve RSA padding mode:** re-disassemble the context around the confirmed `pad = 1` constant at `0x10065f05` (contradiction C3) before any key-exchange implementation.
4. **Decrypt traffic:** use the extracted keys to decrypt the captures. This is the step that would move the cryptography from static to confirmed.
5. **Correlate packets:** map `CPacket_*` to network frames.
6. **Only then** implement in `src/protocol/packets.rs` and `src/crypto/mod.rs`.

**Do not implement the Rust packets until the specification is complete.**

**Do not declare compatibility until it has been demonstrated with real tests against the official Windows client.**
