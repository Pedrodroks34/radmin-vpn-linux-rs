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

**Important:** Everything in this document is **static** evidence (code, RTTI, vtables, constants). Nothing here has been confirmed against encrypted traffic. Where this document and `PROTOCOL_SPEC.md` disagree, see the reconciliation notes in each section.

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
- Set by: `FUN_10062ff0` (encrypt, copies 16 bytes to `this+4` or `this+0x1ec`, unclear) and `FUN_10062f80` (decrypt).
- `FUN_100633d0` copies 16 bytes (`FUN_10065150`, size 0x10).

**Unknown:**

- How the IV is generated (fixed, derived from the key, or random).
- Whether it is sent with the ciphertext.
- Whether it is per session or per message.
- Initial value (global constant `_DAT_100832f0`, used in `FUN_10063470` and `FUN_100633e0`).

**Inferred:**

- `FUN_10063470` (CBC encrypt) initializes the IV from the global `_DAT_100832f0` and XORs it with the plaintext block by block.
- `FUN_100633e0` (CBC decrypt) initializes the IV from `_DAT_100832f0` and XORs with the previous ciphertext block.
- The global `_DAT_100832f0` may be a default or fixed IV.

### 6.5 Custom padding (confirmed)

**`FUN_10069c20` (encryption preparation):**

1. Padded size: `sVar3 = ((param_4 + 8 + param_3) / param_4) * param_4`
   - `param_4` is the block size (16).
   - `param_3` is the data size.
   - Overhead: 9 bytes (8-byte checksum plus 1 size byte).
2. Allocate a buffer of size `sVar3`.
3. Copy the original data (`param_3` bytes).
4. Fill the rest with `0xcc`.
5. Compute the checksum (`FUN_1006a0c0`): 64-bit sum of 8-byte blocks.
6. Store the checksum (8 bytes) and `(block_size - data_size mod block_size)` (1 byte) in the last 9 bytes.

**`FUN_10069f90` (validation on decryption):**

1. Read the last byte as the padding count (`uVar3`).
2. Validate: `9 < uVar3 < param_5 + 9` (`param_5` is the block size).
3. Compute the checksum and compare it with the stored value.
4. If valid: `data_ptr = param_3`, `data_size = param_4 - uVar3`.

**Overhead:** 9 bytes per message (8 checksum, 1 size).

**Padding classification:** proprietary, not PKCS#7. Filled with `0xcc` plus a 9-byte trailer.

### 6.6 Checksum (`FUN_1006a0c0`)

- **Type:** 64-bit sum, not a cryptographic MAC.
- **Algorithm:** accumulates 8-byte blocks (little-endian uint64) into a 64-bit sum.
- **Size:** 8 bytes (64 bits).
- **Use:** integrity of the padding, not of the full payload.

**Unknown:** whether it is used as a MAC or only to validate the padding.

### 6.7 Key exchange: RSA (confirmed)

**`SHelper_RSAHelper_*`:**

- `CreateWithPublicKey(modulus, mod_size, exponent, exp_size)`: RSA with a public key.
- `CreateWithPrivateKey(...)`: RSA with a private key (modulus, exponent, factors, CRT parameters).
- `EncryptBuffer_Public` / `EncryptBuffer_Private`: encrypt with RSA.
- `DecryptBuffer_Public` / `DecryptBuffer_Private`: decrypt with RSA.
- Used to exchange the AES-256 key securely.

**RSA padding:** unknown. The strings `rsaesOaep` and `RSAES-OAEP` are present in `shelper.dll`, but the padding mode in use is not confirmed.

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
2. RSA exchanges the AES-256 key (SHelper_RSAHelper_*)
3. SHelper_CChannel_EncryptBuffer:
   a. FUN_10069c20: padding (0xcc fill, 8-byte checksum, 1-byte size)
   b. vtable[1] (FUN_10062e00 to FUN_10003b30): AES-256-CBC encrypt
   c. FUN_10062ad0: store result
4. TCP frame: 4-byte big-endian uint32 (size) plus encrypted payload
5. TCP send (port 17301 or 17351)

RECEIVE:
1. TCP receive (4-byte big-endian frame header plus payload)
2. SHelper_CChannel_DecryptBuffer:
   a. vtable[2] (FUN_10062d60 to FUN_10003b30): AES-256-CBC decrypt
   b. FUN_10069f90: validate padding and checksum
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

- Encryption overhead: up to 16 bytes of padding plus 9 bytes of trailer, 25 bytes in total.
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
2. **IV:** how it is generated or whether it is transmitted is not known. The global constant `_DAT_100832f0` is used as the initial IV. Classified as unknown.
3. **RSA padding:** the string "RSAES-OAEP" was found, but which mode is used is not confirmed. Classified as inferred.
4. **Semantic meaning of the CPacket fields** (offsets): not determined. Classified as unknown.
5. **Field tags** (0x0302, 0x0303, 0x01e1, 0x0304): meaning not confirmed. Classified as unknown.
6. **Checksum:** not known whether it is a MAC or only used to validate padding. Classified as unknown.
7. **IV per session or per message:** not determined. Classified as unknown.
8. **No dynamic execution:** no debugging or replay.

---

## 9. Unknown information

| Item | Status | Needed to |
|---|---|---|
| IV generation and exchange | Unknown | Reproduce the encryption |
| RSA padding mode | Inferred (OAEP?) | Reproduce the key exchange |
| Identity of `FUN_10003b30` | Inferred (custom AES) | Confirm the implementation |
| Semantic fields (CPacket) | Unknown | Implement the packets |
| Field tags | Unknown | Implement serialization |
| IV per session or per message | Unknown | Reproduce the encryption |
| Checksum use (MAC?) | Unknown | Implement validation |

---

## 10. Next steps

1. **Identify the IV:** decompile `FUN_10062ff0` and `FUN_10062f80` more deeply, or use the Ghidra GUI.
2. **Confirm `FUN_10003b30`:** compare with OpenSSL's `AES_cbc_encrypt`.
3. **Decrypt traffic:** use the extracted keys to decrypt the captures. This is the step that would move the cryptography from static to confirmed.
4. **Correlate packets:** map `CPacket_*` to network frames.
5. **Only then** implement in `src/protocol/packets.rs` and `src/crypto/mod.rs`.

**Do not implement the Rust packets until the specification is complete.**

**Do not declare compatibility until it has been demonstrated with real tests against the official Windows client.**
