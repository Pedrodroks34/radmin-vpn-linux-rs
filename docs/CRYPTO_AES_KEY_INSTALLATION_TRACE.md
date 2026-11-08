# CRYPTO_AES_KEY_INSTALLATION_TRACE.md

## 1. Executive Summary

The complete RSession AES key installation lifecycle is traced at instruction level against shelper.dll. The 64-byte secret is generated client-side only via OpenSSL RAND, packaged into a 76-byte plaintext (12-byte little-endian header ‖ 64-byte key), RSA-2048 PKCS#1 v1.5 encrypted under the server's public key, transmitted, server-decrypted, length-validated (must equal 0x4c), and stored verbatim at session+0x30 with length 0x40. GetKey returns a privately owned heap copy of exactly 64 bytes. The consumer splits the 64 bytes into two 32-byte AES-256 keys (enc via vtable slot +0x18, dec via +0x1c) installed into an AESCryptor object (0x20c bytes, vftable 0x100832a0) using AES-256-CBC with persistent IVs, 0xCC padding, and a 9-byte unkeyed trailer (folded MD5 of 64-bit additive checksum + pad-length byte). No KDF exists anywhere on the RSession path. RSession_GetKey (0x1006ba80) and control-handshake GetKey (0x1006b010) are confirmed separate paths.

## 2. Binary Identity and Provenance

| Field | Value |
|-------|-------|
| File | target-d89daf6bcd5c.dll (shelper.dll) |
| SHA-256 | d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4 (verified by sha256sum) |
| Format | PE32 i386 DLL, ImageBase 0x10000000, 5 sections, little-endian |
| Crypto base | OpenSSL 1.0.1f (statically linked) |
| PDB | Shelper.pdb (GUID 8fbbf627-1949-4782-aafa-fec0eee40801, age 2) |
| Analyzer | Ghidra 12.1.2 via REA bridge, read-only ephemeral project; original bytes never written |

## 3. RSession Secret Generation and Transport

**Where generated:** Client-side only, inside FUN_1006a2b0 (state-machine worker), role=0 (client), state 0 → 1.

**How:** `FUN_10063530((uint)&local_54, 0x40)` calls `FUN_10005410()`, which resolves `DAT_100b015c[1]` (OpenSSL RAND_METHOD.bytes slot) via indirect call and fills a 64-byte stack buffer (local_54).

**Independently by client, server, or both:** Client only. The server does not generate a secret; it decrypts the client's transport and stores the received 64 bytes verbatim.

**Dataflow:** local_54 (64 random bytes) → session +0x30 (malloc 0x40, memcpy 0x40) with +0x28=+0x2c=0x40 → encrypted via RSA → transmitted to server → server decrypts → stored at server session +0x30, byte-identical.

## 4. RSA Encryption of the Secret

**Plaintext structure (CONFIRMED):** 76 bytes (0x4c) = `LE32(header[0]) ‖ LE32(header[1]) ‖ LE32(header[2]) ‖ key[64]`. Header fields read from session +0x04, +0x08, +0x0c (set by FUN_1006a690 from CreateClient args h0,h1,h2). Key bytes at local_54 offset 0..63. RSA encrypt called as `FUN_10065ec0(this, &local_60, 0x4c, &out)` where &local_60 points at header[0] (consecutive with header[1], header[2], then local_54 on stack).

**12-byte header CONFIRMED:** 3 × native LE u32 fields. Sizes: 4+4+4=12 bytes. Byte order: little-endian (x86 native stores). Semantics: opaque — treated as dwords, no semantic binding found in shelper.dll.

**Which RSA key:** Client's RSA public key (n, e), imported via FUN_10066170 (BN_bin2bn at RSA+0x10=n, RSA+0x14=e) from CreateClient arguments. Padding: RSA_PKCS1_PADDING (mode constant 1, `PUSH 0x1` equivalent via indirect method call). Ciphertext: 256 bytes (RSA_size = 0x100 for 2048-bit modulus).

## 5. Server Decryption and Validation

**Server path:** FUN_1006a2b0, role=1, state 1 → 2 → 3 in one call.

1. `FUN_10065db0(this, in, inlen, &out)` → `FUN_100092e0()` (RSA_METHOD.rsa_priv_dec jumptable dispatcher) performs RSA private decryption.
2. Validates decrypted length `local_6c[0] == 0x4c` (76 bytes exactly).
3. Copies decrypted[0] → session+0x14, decrypted[1] → session+0x18, decrypted[2] → session+0x1c (the client's 3 header dwords).
4. `free(session+0x30); session+0x30 = malloc(0x40); memcpy(session+0x30, decrypted+12, 0x40)` — stores the 64-byte key verbatim starting at decrypted byte offset 12.
5. Sets session+0x28 = session+0x2c = 0x40.
6. State +0x24 incremented to 2; then a 4-byte reply buffer allocated containing `*(u32*)(session+0x04)` (the server's own CreateServer id arg), state → 3, established +0x10 = 1.

**Validation:** Only length check (==0x4c). No checksum, no MAC, no KDF on the decrypted data.

## 6. GetKey Output (Pointer and Length)

**Address:** 0x1006ba80 = SHelper_RSession_GetKey.

**Signature:** `bool(void* session, void** out_ptr, uint32_t* out_len)`

**Guard (FUN_1006a270):** requires `session != NULL`, `*(int*)(session+0x10) != 0` (established), `*(int*)(session+0x30) != 0` (key pointer), `*(int*)(session+0x28) != 0` (key length). If any check fails, returns false (0).

**Copy:** `FUN_10062800(local_buf, *(session+0x30), *(size_t*)(session+0x28))` — allocates `*(session+0x28)` bytes via FUN_100627a0, then `FUN_1006c980` (memcpy) copies that many bytes from `*(session+0x30)` into the new heap block.

**Ownership transfer (FUN_10069f50):** `*out_ptr = buf->data; *out_len = buf->len;` then zeroes the struct fields (NULLs data, len, cap).

**Exact output:** Pointer to a freshly allocated heap buffer of exactly `*(session+0x28)` = 0x40 = 64 bytes, containing a byte-for-byte copy of the session secret. Length out-param = 0x40. Return value = 1 (success) or 0 (failure).

**Destructor (FUN_10062b10):** `FUN_1006c120(data, 0, len)` secure zero-fill then `free(data)`. Caller must invoke this to destroy the copy.

**Session deletion does not invalidate consumer's copy** — SHelper_RSession_Delete (0x1006b9e0) zeroes/frees session+0x30 but the consumer's GetKey copy is a separate allocation.

## 7. 64-Byte Buffer Division/Transformation

**shelper.dll performs NO division or transformation.** GetKey returns all 64 bytes verbatim (raw RAND output, no hashing, no KDF).

**Consumer must split:** CChannel_CreateClient inner (FUN_1006a630 at 0x1006a630) requires two keys of exactly 0x20 (32) bytes each: `SetKeyEnc(key1, 0x20)` then `SetKeyDec(key3, 0x20)`. Both SetKeyEnc and SetKeyDec enforce `len == 0x20` and call vtable slots +0x18/+0x1c respectively (AES_set_encrypt_key / AES_set_decrypt_key, bits = 256).

**Split point and enc/dec assignment:** NOT determined by shelper.dll. UNKNOWN from binary evidence — determined by the consumer (RvControlSvc.exe or RvROLClient.dll), whose GetKey call site was not located (disp8 indirect calls defeated static analysis).

## 8. Directional Key Mapping (Enc vs Dec)

**Separate directional keys, NOT identical.** SetKeyEnc installs AES-256 encrypt key via vtable +0x18; SetKeyDec installs AES-256 decrypt key via vtable +0x1c. CChannel_CreateClient requires both keys (32 bytes each) at creation time.

**Which half feeds which direction:** UNKNOWN — not observable in shelper.dll. The 64-byte secret is handed to the consumer as one contiguous 64-byte buffer; the consumer decides the split (e.g. secret[0..32]→enc, secret[32..64]→dec, or reversed, or role-dependent).

## 9. AES Context Initialization and Storage

**AESCryptor object:** size 0x20c, vftable 0x100832a0 (17 vtable slots). Constructor FUN_10062b60: sets vftable at +0, zeroes encryption key schedule at +4 (0xf4 bytes), zeroes decryption key schedule at +0xf8 (0xf4 bytes), zeroes trailing fields at +0x1ec..+0x208.

**Key storage:** Enc AES_KEY at +0x4 (installed via vtable +0x18 → AES_set_encrypt_key, bits=256). Dec AES_KEY at +0xf8 (installed via vtable +0x1c → AES_set_decrypt_key, bits=256).

**IV storage:** Enc IV at +0x1ec, dec IV at +0x1fc (16 bytes each), zero-initialized at construction, persistent across frames (updated from last ciphertext block during CBC operation). No per-frame IV reset observed. IV reset only on new session (new AESCryptor object).

## 10. AES Mode, Key Size, IV, Padding, Framing

**Mode:** AES-256-CBC. Vtable slot +4 = encrypt transform (FUN_10003b30, AES-CBC), slot +8 = decrypt transform. Block size 16 (vtable +0x20 returns 0x10).

**Key size:** 256 bits (bits = len×8 = 0x20×8 = 256) for both encrypt and decrypt key schedules.

**IV:** Zero-initialized at construction. Persistent across frames — updated from the last ciphertext block after each operation (CBC chaining). No per-frame IV reset observed. IV reset only on new session (new AESCryptor object).

**Padding:** 0xCC fill. `total = ((block + 8 + payload) / block) * block` forces pad_len ∈ [9, block+8] (for block=16: 9..24). Bytes [payload..total-9] filled with 0xCC.

**Trailer (9 bytes):** bytes [total-9..total-1] = 8-byte folded MD5 digest; byte [total-1] = pad length. Checksum: 64-bit additive (LE64 word-additive) over buf[0..total-9]. MD5 over the 8-byte checksum (single compression block). Fold: out[i] += out[i+8] mod 256 for i=0..7.

**Framing/processing order:**
- Encrypt (FUN_10069e60 → FUN_10069c20 pad+sign → vtable+4 AES-CBC encrypt in-place): payload → pad with 0xCC → compute 64-bit checksum → MD5 → fold 16→8 bytes → write folded digest + pad length → AES-256-CBC encrypt entire buffer in-place.
- Decrypt (FUN_10069d70 → vtable+8 AES-CBC decrypt in-place → FUN_10069f90 verify+unpad): AES-256-CBC decrypt **before** any validation → check len%16==0, 9≤pad_len≤24, pad_len<len → verify 0xCC fill → recompute checksum/MD5/fold → compare with stored trailer → return payload.

**Critical:** Decrypt runs before length validation — malformed input triggers CBC decrypt on attacker-controlled data before rejection.

## 11. 0xCC Padding and 9-Byte Trailer — RSession Path Verification

**CONFIRMED same layer:** Both EncryptBuffer (0x1006aa10 → FUN_10069e60 → FUN_10069c20) and DecryptBuffer (0x1006a930 → FUN_10069d70 → FUN_10069f90) use identical pad+sign and verify+unpad functions.

**NOT part of RSession key transport:** The RSession key transport (client→server) uses raw RSA-PKCS#1 v1.5 on the 76-byte plaintext with NO 0xCC padding and NO trailer. The 0xCC padding + 9-byte trailer belong exclusively to the CChannel frame encryption/decryption layer, which is used AFTER RSession key installation to protect subsequent session traffic. Direction: both encrypt and decrypt (symmetric frame protection).

## 12. KDF vs Direct Slices

**CONFIRMED: Direct slices, no KDF.** Complete callee set of FUN_1006a2b0 (both client and server branches): memset (FUN_1006c120), RAND (FUN_10063530→FUN_10005410), malloc, memcpy (FUN_1006c980), RSA_pub_enc (FUN_10065ec0→FUN_100092c0), RSA_priv_dec (FUN_10065db0→FUN_100092e0), buffer move/free (FUN_10062ad0/FUN_10062250). No MD5, SHA-1, HKDF, PBKDF2, HMAC, or any hash call reachable from RSession establishment.

The 64 bytes are used verbatim: client keeps its copy, server stores received copy byte-identical. The 64→32+32 reduction happens purely at the CChannel API boundary (two separate SetKey* calls with len==0x20), performed by the consumer.

## 13. Error Handling

- **GetKey:** Returns 0 if any out-param is NULL, or if the guard fails (not established, no key pointer, zero key length), or if the heap copy allocation fails. Never returns a partial or invalid key.
- **SetKeyEnc/SetKeyDec:** Return 0 if channel pointer, key pointer, or length pointer is NULL, or if length ≠ 0x20. Key not installed on failure.
- **CreateClient/CreateServer:** Return NULL if `InterlockedCompareExchange(&DAT_100b0154, 1, 1)` fails (already initialized — singleton guard), if malloc(0x34) fails, or if role-specific init fails (calls SHelper_RSession_Delete / SHelper_CChannel_Delete on failure).
- **RSA encrypt/decrypt:** Return false on null RSA context, null buffers, zero lengths, or crypto operation failure.
- **Malformed input on decrypt:** CBC decrypt executes before validation — attacker-controlled ciphertext is decrypted, then rejected only if length/padding/trailer checks fail. Potential robustness/DoS surface.
- **Invalid key material:** No validation of key content (any 32 bytes accepted by SetKey*; any 64 bytes accepted by GetKey store). AES key schedule itself may fail internally but the wrapper returns based on the vtable call result.

## 14. Rust Compatibility Assessment (reference, from Task 4.1 report)

| Item | Binary | Rust | Verdict |
|---|---|---|---|
| Secret size | 64 bytes | RSESSION_KEY_MATERIAL_SIZE=64 | MATCH |
| Plaintext size | 76 bytes | RSESSION_PLAINTEXT_SIZE=76 | MATCH |
| RSA block | 256 bytes | RSESSION_RSA_BLOCK_SIZE=256 | MATCH |
| Header size | 12 bytes, 3×LE u32 | RSESSION_CLIENT_HEADER_SIZE=12, to_le_bytes() | MATCH |
| RSA padding | PKCS#1 v1.5 | Padding::PKCS1 | MATCH |
| No KDF | No hash on path | No KDF | MATCH |
| Key → enc | Two separate 32-byte keys (consumer splits) | key_material[..32] for enc | MISMATCH (unsupported) |
| Key → dec | Two separate 32-byte keys | key_material[..32] for dec (same as enc) | MISMATCH (unsupported) |
| 64-byte usage | All 64 bytes transported & stored | Only first 32 bytes used | MISMATCH |

## 15. Evidence and Confidence Matrix

| ID | Claim | Evidence | Class |
|------|-------|----------|-------|
| E1 | 7 RSession exports, ordinals 31-37 | Export table + list_procedures | CONFIRMED |
| E2 | 64-byte RNG via OpenSSL RAND_METHOD.bytes | FUN_10063530→FUN_10005410→DAT_100b015c[1] | CONFIRMED |
| E3 | Plaintext = 12-byte LE header ‖ 64-byte key | FUN_1006a2b0 client branch | CONFIRMED |
| E4 | RSA PKCS#1 v1.5, 256-byte ciphertext | FUN_10065ec0→FUN_100092c0, mode 1, RSA_size=0x100 | CONFIRMED |
| E5 | Server validates len==0x4c, stores key at +0x30, len 0x40 | FUN_1006a2b0 server branch | CONFIRMED |
| E6 | GetKey returns owned 64-byte heap copy | 0x1006ba80 → FUN_1006a270 → FUN_10062800 → FUN_10069f50 | CONFIRMED |
| E7 | SetKeyEnc/SetKeyDec require len==0x20, AES-256 | 0x1006ab00 / 0x1006aac0, vtable +0x18/+0x1c | CONFIRMED |
| E8 | CChannel needs two 32-byte keys | FUN_1006a630 (0x1006a630) | CONFIRMED |
| E9 | AES-256-CBC, persistent IVs, 0xCC padding, 9-byte trailer | FUN_10069c20 / FUN_10069f90 / FUN_10003b30 | CONFIRMED |
| E10 | No KDF/hash on RSession path | Complete callee set of FUN_1006a2b0 | CONFIRMED |
| E11 | RSession_GetKey ≠ control GetKey | 0x1006ba80 vs 0x1006b010, different guards/data | CONFIRMED |
| E12 | 64→32+32 split mapping | Not in shelper.dll | UNKNOWN |
| E13 | Enc/dec assignment per role | Not in shelper.dll | UNKNOWN |

## 16. Unresolved Questions

1. **64→32+32 split point and enc/dec assignment:** Which half feeds enc vs dec, and is it role-dependent? Requires tracing consumer call sites between GetKey and SetKeyEnc/SetKeyDec in RvControlSvc.exe/RvROLClient.dll (disp8 sweep blocked by budget previously).
2. **Header field semantics:** +0x04/+0x08/+0x0c treated as opaque dwords; no semantic binding found.
3. **Server RSA key provenance:** Which component supplies the 8 private key buffers to CreateServer; whether from embedded certificate.
4. **Consumer identity:** RvControlSvc.exe vs RvROLClient.dll as the RSession consumer — GetKey call site not located.
5. **Persistent IV consequence:** Whether peer ever rekeys/resets IVs per frame; if truly persistent, CBC chain is desynchronization-sensitive.

## 17. Recommended Next Investigation Steps

1. Complete the missed disp8 sweep: search for `FF 50..57 B0` (GetKey), `FF 50..57 C0` (SetKeyEnc), `FF 50..57 C4` (SetKeyDec) in RvROLClient.dll, RvControlSvc.exe, RvRvpnGui.exe; filter for disp8 ∈ {0xb0, 0xc0, 0xc4}.
2. Trace instructions between GetKey call and SetKeyEnc/SetKeyDec — `lea reg,[key+0x20]` pattern would reveal the [0..32]/[32..64] split fingerprint.
3. If no call site in the three known images, check rvpn_launcher.exe and adapter_hook.dll before concluding dead code.
4. Disassemble FUN_1006a690 and FUN_1006a700 to confirm header field storage offsets (currently inferred from state machine usage).
5. Investigate whether control channel and RSession channel share one AESCryptor or use separate objects.

---

**EVIDENCE_REFS** — All raw bytes reads from /tmp/rea-ghidra-KCSGad/target-d89daf6bcd5c.dll (SHA-256: d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4). Evidence IDs: ev_01607fc89699a3f6bf9053ace9b0c4b55835373ea43e61c165c2a9dff1f1eaa8 (GetKey), ev_409545fc3ad6377dbef1ec917a6660c4019a4f5b540e450a75987696a9f37f41 (GetKey guard), ev_076e5edb2c2fd39c0a4bfeab17fea6aa794204cf99f52bb1bbf49cbc231dfadf (ownership transfer), ev_90a9cc404723c842fe90831a4d7ab11ff16e9a9ff04687b2426566d253a53982 (destructor), ev_d4feafb0ae40a9e32ac26f8cb759342ac3f0cf31571a8f56ba93f222fdd60e00 (alloc+copy), ev_8d9194bb77700d02a009549c35902f475f5e5ef7b2165afba0a3dfffa15910bb (SetKeyEnc), ev_a3d163f8e7713ffe8c24b9655c6d2b853db5df38993e3974dc9c6130f8513a96 (SetKeyDec), ev_9ed335126a62ebf937d856f00a0e003512c12ef8e773b8e15633aa8ee5933e76 (CreateClient), ev_970b33eadd07930c8079bd0fb7b40a6c0e19fa17b6719e8bc33000768b796ce5 (CreateServer), ev_829450b817716cb849d700d835f3cb12aeeec7b8fe66945f2711a3d5b910f2a9 (state machine), ev_259d5e0e2305e53e5d8873cffe106c9e126de3b57ec74518b75ca08a271bc3f3 (RAND), ev_2efca537fa7cfa78604ca2939a0a013df99bb991fe4b227be3ad621c00d06505 (RSA pub-enc), ev_dee19ea8b489869acbabd85d12c0f6886f494e2d4991fb5dbd6abb81c46b4f71 (RSA priv-dec), ev_73f6103f51b827d956dccfec893a2e63fe34d2343222a10254c029f15c586f9f (CChannel inner), ev_5a1c7e2134ae37ba7a6baa65ee22071f5b4f2015171d8e1ca0324ca683c3c172 (AESCryptor ctor), ev_a291e026667dc3f754c5d9587ae78cd1d1bedae4f4448b571ae4f7c1c0881d38 (pad+sign), ev_79627ae416ac27f5533cbf29037948a70358a62dbca9f917a10fb80c41392b46 (verify+unpad), ev_f8bd0b1f07be5a25b4f9e7e9f0cd90ce42c6e9a82b4b5fa9a1b3ba0d64792299 (AES-CBC), ev_4a5b4352ce586ff0d01695da9f45fbe84b2fb67b8a7ad76e7b1e62bff5bc7fa3 (control GetKey)

**COMPLIANCE:** Task 4.2 investigation complete. All evidence gathered from live binary re-verification (not stale traces). No Rust code modified. No artifacts modified. No commits or pushes.

STOP CONDITION: Task 4.2 investigation complete. Deliverable content prepared but could not be written by SME (read-only). Awaiting documentation agent to write docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md. Do not dispatch Task 4.3 without explicit authorization.
