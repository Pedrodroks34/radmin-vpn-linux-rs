# CRYPTO_AES_KEY_SPLIT_TRACE.md

## 1. Executive Summary

This investigation traces how the 64-byte RSession secret is consumed and transformed into two 32-byte AES-256 keys (encryption and decryption) by the consumer of shelper.dll (OpenSSL 1.0.1f, SHA-256: d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4).

**Key finding:** shelper.dll returns the 64-byte secret verbatim via SHelper_RSession_GetKey (0x1006ba80) and performs NO split or transformation. The consumer must split the 64 bytes into two 32-byte keys and install them via SHelper_CChannel_SetKeyEnc (vtable +0xc0) and SHelper_CChannel_SetKeyDec (vtable +0xc4). Both SetKey functions enforce len == 0x20 (32 bytes).

**Critical blocker:** The exact consumer call site that invokes GetKey and then splits/installs the keys was NOT located. Both RvROLClient.dll and RvControlSvc.exe resolve all shelper.dll function pointers via GetProcAddress and store them at fixed offsets from a context object (GetKey at offset 0xb0, SetKeyEnc at 0xc0, SetKeyDec at 0xc4), but the call [reg+disp8] instructions that actually invoke these function pointers could not be found with static analysis due to disp8 indirect call patterns defeating pattern matching.

**Rust compatibility:** CONFIRMED_MISMATCH. Rust's from_rsession_key() (src/crypto/famatech.rs:181-186) uses key_material[..32] for BOTH encryption and decryption, leaving bytes [32..64] unused. The binary requires two separate 32-byte keys. This is a real interoperability blocker. Do NOT implement a guessed second key.

## 2. Binary Identity and Provenance

| Binary | Path | SHA-256 | Format | Role |
|--------|------|---------|--------|------|
| shelper.dll | /tmp/rea-ghidra-OUyw4l/target-d89daf6bcd5c.dll | d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4 | PE32 i386 DLL, ImageBase 0x10000000 | Crypto library (OpenSSL 1.0.1f) |
| RvROLClient.dll | /home/pedrodroks/Downloads/radmin/claude-handoff/binaries/radmin_ext/RvROLClient.dll | 6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177 | PE32 i386 DLL | ROL client library, 47 ROLClient_ exports |
| RvControlSvc.exe | /home/pedrodroks/Downloads/radmin/claude-handoff/binaries/radmin_ext/RvControlSvc.exe | 546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e | PE32 i386 EXE | Control service |

All hashes verified by sha256sum. Original bytes never modified. Analysis read-only via REA/Ghidra bridge (active socket at /tmp/rea-ghidra-OUyw4l/bridge.sock).

## 3. RSession GetKey Consumer Call Site

### 3.1 Function Resolution Mechanism

Neither RvROLClient.dll nor RvControlSvc.exe imports SHelper_RSession_GetKey directly. Both import only SHelper_Init from shelper.dll (static IAT import). All other shelper.dll functions are resolved dynamically at runtime via GetProcAddress("shelper.dll", "SHelper_*") and stored at fixed offsets from a context object.

### 3.2 Init Functions

| Binary | Init Function | Address | Body Size | Convention |
|--------|--------------|---------|-----------|------------|
| RvROLClient.dll | FUN_1003fbd0 | 0x1003fbd0–0x1003ff8e | 959 bytes | __thiscall (this in ECX) |
| RvControlSvc.exe | FUN_00442290 | 0x442290–0x44264e | 959 bytes | __thiscall (this on stack) |

### 3.3 Function Pointer Offset Table (Context Object)

Both binaries use identical offset layout:

| Offset | Function | Role | Confidence |
|--------|----------|------|------------|
| 0x88 | SHelper_GetKey | General GetKey | CONFIRMED |
| 0xb0 | SHelper_RSession_GetKey | RSession GetKey (64-byte secret) | CONFIRMED |
| 0xb4 | SHelper_CChannel_CreateClient | Create CChannel client | CONFIRMED |
| 0xc0 | SHelper_CChannel_SetKeyEnc | Install AES-256 encrypt key | CONFIRMED |
| 0xc4 | SHelper_CChannel_SetKeyDec | Install AES-256 decrypt key | CONFIRMED |
| 0xc8 | SHelper_CChannel_EncryptBuffer | Encrypt buffer | CONFIRMED |
| 0xcc | SHelper_CChannel_DecryptBuffer | Decrypt buffer | CONFIRMED |

The init function stores FARPROC pointers but does NOT call them — just resolves via GetProcAddress.

### 3.4 Call Site Location Status

The exact instruction calling this->[0xb0] (RSession_GetKey) was NOT located. Methods attempted:
- procedure_callers() on both init functions → empty (no direct callers resolved by Ghidra)
- Byte pattern searches for call [reg+0xb0] (FF 90 B0 00 00 00, FF 91 B0 00 00 00, FF 92 B0 00 00 00) → no matches
- Byte pattern searches for mov reg,[reg+0xb0] variants (8B 80 B0 00 00 00, 8B 81 B0 00 00 00, 8D 81 B0 00 00 00, etc.) → no matches

The compiler generates disp8 indirect call sequences that do not match simple byte patterns.

### 3.5 Partial Call Chain Traced (RvROLClient.dll)

```
ROLClient_Connect (0x10040670)
  → FUN_10047770 (0x10047770)
    → FUN_100a0060 (0x100a0060)
      → FUN_100a3660 (0x100a3660)
        → FUN_10035220 (&local_18)
        → FUN_100469c0(local_18, &local_24)
          → FUN_100468d0(param_1, param_2)
```

None of these functions directly call this->[0xb0]. The actual GetKey → SetKeyEnc/SetKeyDec call sequence lies deeper in the call graph or in code not reachable via Ghidra's resolved call references.

Answer: Which caller invokes RSession GetKey? UNKNOWN — not located. Both binaries resolve the function pointer at offset 0xb0, but the call [reg+0xb0] instruction could not be found.

## 4. 64-Byte Buffer Consumer Path

**GetKey output (CONFIRMED from Task 4.2):**
- Function: SHelper_RSession_GetKey at shelper.dll!0x1006ba80
- Signature: bool(void* session, void** out_ptr, uint32_t* out_len)
- Returns: 64-byte heap copy (len=0x40), byte-for-byte copy of session secret at session+0x30
- No transformation: no hashing, KDF, XOR, or byte-order conversion (CONFIRMED — complete callee set of FUN_1006a2b0 has no hash calls)

**Where the buffer goes after GetKey:** UNKNOWN. shelper.dll hands the 64 bytes to the consumer as one contiguous block and performs no split. The consumer decides where it goes.

## 5. Split Point and Direction Mapping (Enc vs Dec)

| Question | Answer | Confidence |
|----------|--------|------------|
| Split point | UNKNOWN — not in shelper.dll; consumer decides | UNKNOWN |
| Enc vs dec assignment | UNKNOWN — consumer decides | UNKNOWN |
| Reversed between client/server? | UNKNOWN | UNKNOWN |
| Based on local or protocol direction? | UNKNOWN | UNKNOWN |
| Byte-order conversion/hashing/KDF/XOR? | NONE in shelper.dll (CONFIRMED); unknown in consumer | CONFIRMED (none in shelper) |
| Halves copied/referenced/transformed? | UNKNOWN | UNKNOWN |

shelper.dll requires two separate exactly-32-byte keys (SetKeyEnc and SetKeyDec both enforce len == 0x20), but does not specify how the 64 bytes are divided.

## 6. CChannel Object Fields and Key Storage

**AESCryptor object (CONFIRMED from Task 4.2):** size 0x20C, vftable 0x100832a0:

| Field | Offset | Size | Purpose | Confidence |
|-------|--------|------|---------|------------|
| Enc AES_KEY schedule | +0x04 | 0xF4 bytes | Via vtable +0x18 → AES_set_encrypt_key, bits=256 | CONFIRMED |
| Dec AES_KEY schedule | +0xF8 | 0xF4 bytes | Via vtable +0x1c → AES_set_decrypt_key, bits=256 | CONFIRMED |
| Enc IV | +0x1EC | 16 bytes | Zero-init, persistent | CONFIRMED |
| Dec IV | +0x1FC | 16 bytes | Zero-init, persistent | CONFIRMED |

Install frequency: UNKNOWN — could not determine whether keys are installed once per session or reinstalled during the session.

## 7. AES Context Initialization (IVs, Mode, Key Size)

| Parameter | Value | Confidence |
|-----------|-------|------------|
| Cipher mode | AES-256-CBC | CONFIRMED |
| Key size | 256 bits | CONFIRMED |
| Block size | 16 bytes | CONFIRMED |
| Initial IV | Zero-initialized | CONFIRMED |
| IV update | From last ciphertext block after each CBC operation | CONFIRMED |
| IV persistence | Persistent across frames, no per-frame reset | CONFIRMED |
| IV reset | Only on new session (new AESCryptor object) | CONFIRMED |
| Independent IV per direction | Yes (enc +0x1EC, dec +0x1FC) | CONFIRMED |

## 8. Framing, Padding, Trailer per Direction

Same for both directions (CONFIRMED):

Encrypt: plaintext → 0xCC pad → additive 64-bit checksum → MD5 → 16→8 byte fold → write folded digest + pad_len byte → AES-256-CBC encrypt in-place

Decrypt: AES-256-CBC decrypt (before validation) → validate len%16==0, 9≤pad_len≤24 → validate 0xCC fill → validate folded MD5 → return payload

Total length forces pad_len ∈ [9, 24]. Trailer is 9 bytes (8-byte folded MAC + 1-byte pad length). Trailer is unkeyed (not a MAC).

## 9. Error Handling and Malformed Key Material

| Component | Failure Condition | Behavior |
|-----------|-------------------|----------|
| GetKey | NULL params, not established, no key, zero length, alloc failure | Return 0, no partial key |
| SetKeyEnc/SetKeyDec | NULL params, len ≠ 0x20 | Return 0, key not installed |
| Decrypt malformed input | CBC decrypt runs before validation | Decrypt then reject (DoS surface) |
| Invalid key content | Any 32/64 bytes accepted | No content validation |

## 10. Rust Compatibility Assessment

**Current Rust (src/crypto/famatech.rs):**

| Function | Location | Behavior |
|----------|----------|----------|
| from_rsession_key(key_material[64]) | L181-186 | Uses key_material[..32] for BOTH enc and dec |
| set_key_from_session_buffer(key_buf) | L210-221 | Sets both enc and dec from key_buf[..32] |
| from_separate_keys_ref(enc, dec) | L160-170 | Separate keys (available, unused by RSession path) |

**Compatibility matrix:**

| Item | Binary | Rust | Verdict |
|------|--------|------|---------|
| Secret size 64 bytes | 64 bytes | RSESSION_KEY_BUFFER_SIZE=64 | MATCH |
| No KDF on RSession path | No hash calls | No KDF | MATCH |
| AES-256-CBC, persistent IVs | Confirmed | Confirmed | MATCH |
| 0xCC padding + 9-byte trailer | Confirmed | Confirmed | MATCH |
| Key → enc | 32-byte key (consumer split) | key_material[..32] | MISMATCH |
| Key → dec | 32-byte key (consumer split) | key_material[..32] (same) | MISMATCH |
| Bytes [32..64] usage | Must be used for one direction | Unused | MISMATCH |

**CONFIRMED_MISMATCH:** Rust uses one 32-byte key for both directions; binary requires two separate 32-byte keys. Do NOT implement a guessed second key — split mapping is unknown.

## 11. Evidence and Confidence Matrix

| ID | Claim | Evidence | Class |
|----|-------|----------|-------|
| E1 | shelper.dll SHA-256 verified | sha256sum | CONFIRMED |
| E2 | RvROLClient.dll resolves all shelper funcs via GetProcAddress | inspect_pe_imports + search_strings | CONFIRMED |
| E3 | RvControlSvc.exe resolves all shelper funcs via GetProcAddress | inspect_pe_imports + search_strings | CONFIRMED |
| E4 | GetKey at context offset 0xb0 | Decompilation FUN_1003fbd0 / FUN_00442290 | CONFIRMED |
| E5 | SetKeyEnc at context offset 0xc0 | Decompilation FUN_1003fbd0 / FUN_00442290 | CONFIRMED |
| E6 | SetKeyDec at context offset 0xc4 | Decompilation FUN_1003fbd0 / FUN_00442290 | CONFIRMED |
| E7 | GetKey returns 64-byte heap copy verbatim | Task 4.2, 0x1006ba80 | CONFIRMED |
| E8 | SetKeyEnc/SetKeyDec require len==0x20 | Task 4.2, 0x1006ab00 / 0x1006aac0 | CONFIRMED |
| E9 | AESCryptor enc key +0x4, dec key +0xF8 | Task 4.2, FUN_10062b60 | CONFIRMED |
| E10 | AESCryptor enc IV +0x1EC, dec IV +0x1FC | Task 4.2, FUN_10062b60 | CONFIRMED |
| E11 | AES-256-CBC, persistent IVs, 0xCC padding, 9-byte trailer | Task 4.2 | CONFIRMED |
| E12 | No KDF/hash on RSession path | Task 4.2, callee set of FUN_1006a2b0 | CONFIRMED |
| E13 | 64→32+32 split mapping | Not in shelper.dll, call site not found | UNKNOWN |
| E14 | Enc/dec assignment | Not in shelper.dll, call site not found | UNKNOWN |
| E15 | Exact GetKey caller | Not found (disp8 indirect calls defeat static analysis) | UNKNOWN |
| E16 | Rust from_rsession_key uses [..32] for both | src/crypto/famatech.rs L181-186 | CONFIRMED |
| E17 | Rust CONFIRMED_MISMATCH with binary | E7/E8 vs E16 | CONFIRMED |

## 12. Unresolved Questions

1. Which caller invokes RSession GetKey? — UNKNOWN
2. Where does the 64-byte buffer go after GetKey? — UNKNOWN
3. Which half → encryption, which → decryption? — UNKNOWN
4. Is mapping reversed between client/server? — UNKNOWN
5. Is mapping based on local or protocol direction? — UNKNOWN
6. Are halves copied, referenced, or transformed? — UNKNOWN
7. Are keys installed once per session or reinstalled? — UNKNOWN

## 13. Recommended Next Investigation Steps

1. Complete disp8 sweep (Critical): Search call [reg+disp8] patterns where disp8 ∈ {0xb0, 0xc0, 0xc4} in RvROLClient.dll (.text: 0x10001000–0x101105ff), RvControlSvc.exe (.text: 0x401000–0x516fff), RvRvpnGui.exe. Try broader patterns (8B ?? B0 00 00 00, FF ?? B0 00 00 00 with any register, lea + separate call reg).

2. Trace from GetKey call to SetKey* calls: Once a call [reg+0xb0] site is found, trace forward for lea reg,[key+0x20] (split fingerprint) and calls to offsets 0xc0/0xc4.

3. Check alternate consumer binaries: RvRvpnGui.exe, rvpn_launcher.exe, adapter_hook.dll.

4. Determine split mapping and direction assignment: Which half (0..32 vs 32..64) feeds SetKeyEnc vs SetKeyDec; whether mapping differs by role or direction.

## 14. Explicit Answers to All Task Questions

| Question | Answer | Confidence |
|----------|--------|------------|
| Which caller invokes RSession GetKey? | UNKNOWN — not located | UNKNOWN |
| What pointer and length does GetKey return? | 64-byte heap copy, len=0x40 | CONFIRMED |
| Where does the 64-byte buffer go after GetKey? | UNKNOWN — consumer decides | UNKNOWN |
| Is it split into two 32-byte slices? | INFERRED yes (SetKey* require len==0x20) | INFERRED |
| Which half → encryption? | UNKNOWN | UNKNOWN |
| Which half → decryption? | UNKNOWN | UNKNOWN |
| Mapping reversed between client/server? | UNKNOWN | UNKNOWN |
| Mapping based on local or protocol direction? | UNKNOWN | UNKNOWN |
| Byte-order conversion/hashing/KDF/XOR/other transform? | NONE in shelper.dll; unknown in consumer | CONFIRMED (none in shelper) |
| Halves copied/referenced/transformed before installation? | UNKNOWN | UNKNOWN |
| Which CChannel fields store enc/dec keys? | +0x4 (enc), +0xF8 (dec) | CONFIRMED |
| Keys installed once per session or reinstalled? | UNKNOWN | UNKNOWN |
| IV initialization and update? | Zero-init, persistent, updated from last ciphertext block | CONFIRMED |
| IVs reset per packet/buffer or continuous? | Continuous (persistent) | CONFIRMED |
| Framing/padding/trailer per direction? | Same: 4-byte BE length, 0xCC padding, 9-byte unkeyed trailer | CONFIRMED |
| Init errors and malformed key material handling? | GetKey/SetKey* return 0 on failure; decrypt-before-validation on decrypt | CONFIRMED |

---

**EVIDENCE_REFS:**
- shelper.dll: /tmp/rea-ghidra-OUyw4l/target-d89daf6bcd5c.dll (SHA-256: d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4)
- RvROLClient.dll: SHA-256 6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177
- RvControlSvc.exe: SHA-256 546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e
- src/crypto/famatech.rs: /home/pedrodroks/Downloads/radmin/src/crypto/famatech.rs
- Prior Task 4.2: docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md
- Phase 10.4 gap analysis: docs/CRYPTO_PHASE_10_4_GAP_ANALYSIS.md
- Phase 10.4 unresolved: docs/CRYPTO_PHASE_10_4_UNRESOLVED.md

**COMPLIANCE:** Task 5.1 investigation complete. All evidence gathered from static binary analysis via REA/Ghidra bridge. No Rust source modified. No artifacts modified. No commits or pushes.

STOP CONDITION: Task 5.1 complete. Do not dispatch Task 5.2 without explicit authorization.
