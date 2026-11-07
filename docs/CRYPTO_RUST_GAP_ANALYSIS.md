# Cryptographic Analysis — Rust Implementation Gap Analysis

**Project:** Radmin VPN Linux client (Rust, independent)  
**Repository:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
**Commit-base:** df8ce07  
**Language:** English  
**Status:** Investigation phase — evidence-backed discrepancy matrix  

---

## 1. Scope and Methodology

This document compares the original Radmin VPN implementation (as reverse-engineered from `shelper.dll`, `RvROLClient.dll`, `RvControlSvc.exe`, `RvRvpnGui.exe`) against the current Rust implementation in `src/`. It is part of Investigation G of the cryptographic deep audit.

For each cryptographic component, the document lists:
- Original binary behavior (from static analysis of Ghidra decompilation and REA evidence)
- Rust implementation behavior (from source code)
- Evidence for each side
- Discrepancy status

Discrepancy status values:
- **CONFIRMED_MATCH** — Rust matches binary behavior, verified by direct evidence
- **CONFIRMED_MISMATCH** — Rust differs from binary, verified by direct evidence
- **PARTIAL_MATCH** — Rust matches partially but has a documented deviation
- **UNVERIFIED** — Binary behavior not fully confirmed; Rust behavior may or may not match
- **NOT_IMPLEMENTED** — Component exists in binary but not in Rust
- **NOT_APPLICABLE** — Component not present in one or both implementations

**No component is marked CONFIRMED_MATCH without direct evidence.** Tests that validate only internal consistency (round-trip within Rust) are explicitly noted as not providing interoperability evidence.

---

## 2. Discrepancy Matrix

| # | Component | Original Behavior | Rust Behavior | Evidence | Status |
|---|---|---|---|---|---|
| 1 | Control framing | `[4-byte BE length][payload]`, length excludes header | `FramedPacket::to_bytes()` / `FrameParser` with BE u32 length | Binary frames 77, 80, 81, 82, 87, 88, 93, 94 in `radmin-connect.pcapng`; Rust `src/protocol/framing.rs` | CONFIRMED_MATCH |
| 2 | TLV tag format | `(tag & 0xF8000000) \| (len & 0x07FFFFFF)`, BE header | `encode_item(tag, payload)`: `(tag & 0xF800_0000) \| (payload.len() as u32 & 0x07FF_FFFF)`, `to_be_bytes()` | Binary builder `0x100626e0`, parser `0x10062900`; Rust `src/protocol/tlv.rs` | CONFIRMED_MATCH |
| 3 | TLV tags | `0x10` step, `0x20` identity, `0x30` salt, `0x40` N, `0x50` g, `0x60` ephemeral, `0x70` proof | `TAG_STEP=0x10000000`, `TAG_IDENTITY=0x20000000`, `TAG_SALT=0x30000000`, `TAG_MODULUS=0x40000000`, `TAG_GENERATOR=0x50000000`, `TAG_PUBLIC_EPHEMERAL=0x60000000`, `TAG_PROOF=0x70000000` | Binary `0x10066680`/`0x100670d0`; Rust `src/session/control_handshake.rs` L24-36 | CONFIRMED_MATCH |
| 4 | Step value on wire | 4-byte **big-endian** (`00 00 00 01` for step 1) | `1u32.to_le_bytes()` → `01 00 00 00` | Binary builder `0x100626e0` emits BE; Rust `control_handshake.rs` L670, 780, 910, 1267, 1399, 1456 | **CONFIRMED_MISMATCH** |
| 5 | Version value | `3` | `SHELPER_PROTOCOL_VERSION = 3` | Binary `0x1006b1d0` returns `0x3`; Rust `control_handshake.rs` L10 | CONFIRMED_MATCH |
| 6 | Version on-wire endianness | Unknown (binary only proves value = 3) | `to_le_bytes()` → `03 00 00 00` | Rust `control_handshake.rs` L588; binary `0x1006b1d0` only confirms value | PARTIAL_MATCH |
| 7 | SRP group N | `0x100ac280`, 192 bytes BE | `RADMIN_SRP1536_PRIME_HEX` (192 chars hex) | Binary pinned at `0x100ac280`; Rust `control_handshake.rs` L38-44 | CONFIRMED_MATCH |
| 8 | SRP group g | `0x100ac279 = 0x05` | `RADMIN_SRP_GENERATOR = 5` | Binary `0x100ac279`; Rust `control_handshake.rs` L14 | CONFIRMED_MATCH |
| 9 | SRP multiplier k | SRP-6a class: `k = SHA1(N_bytes ‖ PAD(g,192))`; legacy class: `k = 3` | `RADMIN_SRP_K = 3` | Binary `0x10060810` (SRP-6a), `0x100607d0` (legacy); Rust `control_handshake.rs` L16 | **UNVERIFIED** — which class instantiated unknown |
| 10 | Hash function | SHA-1, 20-byte BE output | `openssl::sha::sha1()` | Binary `0x10028810`/`0x285f0`/`0x286d0`; Rust `control_handshake.rs` uses `openssl::sha::sha1` | CONFIRMED_MATCH |
| 11 | x computation | `H(salt ‖ H(I ‖ ":" ‖ P))`, identity from UTF-16LE wide chars | `H(username.as_bytes() ‖ ":" ‖ password.as_bytes())` = UTF-8 bytes | Binary `0x10060340`/`0x10060c80`; Rust `compute_srp_x` L269-286 | **CONFIRMED_MISMATCH** (byte encoding differs) |
| 12 | v computation | `v = g^x mod N` | `v.mod_exp(&g_bn, &x_secret, &prime_n, &mut ctx)` | Binary `0x100602f0`/`0x10060c80`; Rust `control_handshake.rs` L255-256 | CONFIRMED_MATCH |
| 13 | Ephemeral a | `RAND_bytes(192)`, `1 < a < N-1` no rejection sampling | `rand_bytes(192)`, rejection sampling `1 < a < N-1` up to 128 tries | Binary `0x10060410`; Rust `random_srp_exponent` L298-324 | PARTIAL_MATCH (sampling differs, but output distribution over valid range is same) |
| 14 | A = g^a mod N | `BN_mod_exp` | `a_public.mod_exp(&g_bn, &a_secret, &expected_n, &mut ctx)` | Binary `0x10060410`; Rust `control_handshake.rs` L773 | CONFIRMED_MATCH |
| 15 | u = H(PAD(A) ‖ PAD(B)) | `PAD(x)` = 192-byte left-zero-padded BE; `obj+0x04 & 2` selects padded | `pad_bignum_bytes(a_bytes, 192)`, `pad_bignum_bytes(b_bytes, 192)` | Binary `0x10060510`/`0x10060fa0`; Rust `compute_srp_u` L367-382 | CONFIRMED_MATCH |
| 16 | S = (B − k·v)^(a + u·x) mod N | `BN_sub`/`BN_mul`/`BN_add`/`BN_mod`/`BN_mod_exp` | `base.mod_sub(...)`, `ux.checked_mul(...)`, `exp.checked_add(...)`, `s.mod_exp(...)` | Binary `0x10060510`; Rust `control_handshake.rs` L864-892 | CONFIRMED_MATCH |
| 17 | KDF | `SHA1(S ‖ BE32(0)) ‖ SHA1(S ‖ BE32(1))` = 40 bytes | `SHA1(S_bytes ‖ 0u32.to_be_bytes()) ‖ SHA1(S_bytes ‖ 1u32.to_be_bytes())` = 40 bytes | Binary `0x10061790`; Rust `compute_srp_kdf` L384-400 | CONFIRMED_MATCH |
| 18 | M1 | `H(H(N) ⊕ H(g) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K)`; A/B hashed in RAW minimal form | `sha1(h_xor ‖ h_i ‖ salt ‖ a_bytes ‖ b_bytes ‖ k_full)`; `h_i = sha1(username.as_bytes())` | Binary `0x100601b0`/`0x10060410`/`0x10060510`/`0x100609a0`; Rust `compute_srp_m1` L402-430 | PARTIAL_MATCH (identity encoding differs; A/B padding at call sites needs verification) |
| 19 | M2 | `H(A ‖ M1 ‖ K)` | `sha1(a_bytes ‖ m1 ‖ k_full)` | Binary `0x100609a0`; Rust `compute_srp_m2` L432-442 | CONFIRMED_MATCH |
| 20 | Session key | First 32 bytes of 40-byte K | `k_full[..CONTROL_SESSION_KEY_SIZE]` (32 bytes) | Binary `RvROLClient 0x1003dd40` → `0x100df250`; Rust `control_handshake.rs` L981-982 | CONFIRMED_MATCH |
| 21 | Key install | `SetKeyEnc`/`SetKeyDec` accept exactly 32 bytes | `FamatechCipherState::from_rsession_key(key_material)` takes `[0..32]` | Binary `0x1006ab00`/`0x1006aac0` reject ≠0x20; Rust `from_rsession_key` L181-186 | CONFIRMED_MATCH |
| 22 | Identity encoding on wire | UTF-16LE wide chars, byte-swapped to UTF-16BE per code unit | `encode_identity()`: `username.encode_utf16()`, writes big-endian per code unit | Binary `0x100667b0` (client), `0x100677d0` (server); Rust `encode_identity` L146-153 | CONFIRMED_MATCH (wire format matches) |
| 23 | Identity encoding in hash | UTF-16LE wide chars | `username.as_bytes()` = UTF-8 | Binary `0x10060340`/`0x10060c80` hashes wide-char bytes; Rust `compute_srp_x` L274-277 hashes UTF-8 | **CONFIRMED_MISMATCH** |
| 24 | Password encoding in x hash | UTF-16LE wide chars (inferred from identity source) | `password.as_bytes()` = UTF-8 | Binary `0x10060c80` (server) — caller not traced; Rust `compute_srp_x` L276 | **CONFIRMED_MISMATCH** (inferred; password caller not traced in binary) |
| 25 | Public value validation | `len ≤ 192`, `val < N`, `val != 0`; base `> 1`, `base+1 != N` | `len == 192` (strict), `!= 0`, `< N`, `val mod N != 0`; no group pinning | Binary `0x100699e0` (pinning), `0x10060510` (validation); Rust `validate_srp_public_value` L326-365 | PARTIAL_MATCH (Rust exact-192 may reject valid short BN_bn2bin output; no group pinning in Rust) |
| 26 | Password hash in control messages | `SHA1(password)` (SHA-1 over UTF-8 bytes?) | `hash_network_password(password)` = `sha1(password.as_bytes())` = SHA-1 over UTF-8 | Binary not traced for password hash in control messages; Rust `protocol/control.rs` L21-23 | UNVERIFIED |
| 27 | RSA public key size | 2048 bits (256 bytes) | `RSESSION_RSA_BLOCK_SIZE = 256`, `rsa.size() == 256` required | Binary `FUN_10066170` imports `(n, e)`; Rust `set_server_public_key_components` L148-166 | CONFIRMED_MATCH |
| 28 | RSA padding | PKCS#1 v1.5 (padding mode 1) | `Padding::PKCS1` | Binary `0x10065ec0` `PUSH 0x1`; Rust `handshake.rs` L262, 471 | CONFIRMED_MATCH |
| 29 | RSA operation | Client encrypts 76-byte plaintext with server public key; server decrypts with private key | `pub_key.public_encrypt(&plaintext, &mut encrypted, Padding::PKCS1)`; `self.private_key.private_decrypt(buf, &mut *decrypted, Padding::PKCS1)` | Binary `FUN_10065ec0`/`FUN_10065db0`; Rust `handshake.rs` L262, 471 | CONFIRMED_MATCH |
| 30 | Plaintext structure | 12-byte header (3×u32 LE client_params) + 64-byte key material = 76 bytes | `plaintext[0..4] = client_params[0].to_le_bytes()` ... `plaintext[12..76] = key_material` | Binary `FUN_1006a690` (client init); Rust `get_next_buffer` State 0 L253-258 | CONFIRMED_MATCH |
| 31 | Server token | 4 bytes, LE u32 | `server_token.to_le_bytes().to_vec()`; `u32::from_le_bytes(buf[0..4])` | Binary server emits 4-byte blob from `+0x04`; Rust `RSessionServer::create_server` L502, `get_next_buffer` State 2 L317 | CONFIRMED_MATCH |
| 32 | Key split | Hypothesis: `key_enc = secret[0..32]`, `key_dec = secret[32..64]` | `derive_aes256_key_ref()` returns `key_material[..32]` | Binary split not observed (UNVERIFIED); Rust takes first 32 bytes for both enc and dec | UNVERIFIED |
| 33 | Symmetric cipher | AES-256-CBC | `Cipher::aes_256_cbc()` | Binary `0x10062fb0`/`0x10062f30`; Rust `famatech.rs` L254-256 | CONFIRMED_MATCH |
| 34 | IV handling | Persistent 16-byte IV, updated from last ciphertext block, initial IV = zero | `enc_iv.copy_from_slice(&ciphertext[last_block_start..])`; initial `[0u8; 16]` | Binary AESCryptor object `+0x1ec`/`+0x1fc`; Rust `famatech.rs` L280, L312 | CONFIRMED_MATCH |
| 35 | Trailer | 0xCC fill + 64-bit additive checksum + MD5 → 8-byte fold + 1-byte pad length (9 bytes total) | `famitech_pad_and_sign` / `famitech_verify_and_unpad` | Binary `0x10069c20`/`0x10069f90`; Rust `famatech.rs` L64-125 | CONFIRMED_MATCH |
| 36 | Zeroization | `clear()` zeroizes keys and IVs; `Drop` calls `clear()` | `clear()` zeroizes; `Drop` impl calls `clear()` | Binary `SHelper_RSession_Delete` `0x1006b9e0`; Rust `Drop for FamatechCipherState` L318-322, `Drop for ControlClientNegotiator` L557-561, `Drop for RSessionServer` L536-540 | CONFIRMED_MATCH |
| 37 | Error handling | Fail-closed on validation failures | `fail_and_clear()` sets state to `Failed`, returns `Err` | Binary state machines transition to failed state; Rust `fail_and_clear()` L350-354, `fail_session` L578-584 | CONFIRMED_MATCH |
| 38 | Test evidence | N/A (binary tests not available) | Round-trip tests within Rust only; SRP test emulator with generated RSA key | Rust tests use `Rsa::generate(2048)` — NOT the original binary's key; no cross-implementation test | UNVERIFIED (Rust tests validate internal consistency only) |

---

## 3. Detailed Analysis of Critical Mismatches

### 3.1 Step Value Endianness (CONFIRMED_MISMATCH)

**Binary:** The SRP-6a step field is emitted as **4-byte big-endian** (`00 00 00 01` for step 1). This was confirmed by observing the TLV builder `0x100626e0` which writes the header in big-endian, and the step values in observed PCAP traffic.

**Rust:** `control_handshake.rs` uses `1u32.to_le_bytes()` → `01 00 00 00` at lines 670, 780, 910, 1267, 1399, 1456.

**Impact:** The server will reject step 1 immediately because the step value `0x01000000` (little-endian 1) does not equal the expected `1` when read as big-endian. **This is a complete handshake failure — no interoperability is possible without fixing this.**

**Fix required:** Change all `to_le_bytes()` calls for step values to `to_be_bytes()` in `control_handshake.rs`.

### 3.2 Identity/Password Encoding (CONFIRMED_MISMATCH)

**Binary:** The identity (username) is stored internally as UTF-16LE wide characters but is **byte-swapped to UTF-16BE per code unit** on the wire (`0x100667b0` client, `0x100677d0` server). The password is hashed as part of `x = H(salt ‖ H(I ‖ ":" ‖ P))` where `I` is the identity. The password byte encoding was not directly traced but is inferred to be UTF-16LE (same source as identity).

**Rust:** `encode_identity()` correctly writes UTF-16BE on the wire (L146-153). However, `compute_srp_x()` hashes `username.as_bytes()` and `password.as_bytes()`, which are **UTF-8** byte sequences (L274-277).

**Impact:** Even with the step endianness fixed, `x` will differ because `SHA1(UTF-8(username) ‖ ":" ‖ UTF-8(password)) ≠ SHA1(UTF-16LE(username) ‖ ":" ‖ UTF-16LE(password))`. This cascades to `v`, `A`, `S`, `K`, `M1`, `M2` — the entire handshake fails.

**Fix required:** Change `compute_srp_x` to hash UTF-16LE byte sequences for both username and password, matching the binary's internal representation.

### 3.3 Multiplier k (UNVERIFIED)

**Binary:** Two classes exist:
- SRP-6a class: `k = SHA1(N_bytes ‖ PAD(g, 192))` (canonical SRP-6a per RFC 5054)
- Legacy class: `k = 3` (hardcoded)

Which class the Radmin control channel instantiates was not determined. The string pointers `"SRP-6a client (tjw)"` at `0x100a3df0` and `"SRP-6a server (tjw)"` at `0x100a3e18` point to vtables `0x100ad760`/`0x100ad7b4`, but the instantiation path was not traced.

**Rust:** `RADMIN_SRP_K = 3` (hardcoded).

**Impact:** If the deployed class is SRP-6a, Rust's `k = 3` is wrong and the shared secret `S` will differ. If the legacy class is used, `k = 3` matches.

**Fix required:** Determine which class is instantiated in `RvROLClient.dll` session constructor. If SRP-6a, change `RADMIN_SRP_K` to `SHA1(N_bytes ‖ PAD(g, 192))` computed at runtime.

### 3.4 Exact-192 Length Check (PARTIAL_MATCH)

**Binary:** `validate_srp_public_value` accepts `len ≤ 192` with `val < N` and `val != 0`. A `BN_bn2bin` output shorter than 192 bytes (leading zero byte) would be accepted.

**Rust:** `validate_srp_public_value` requires `bytes.len() == RADMIN_SRP1536_MODULUS_LEN` (exactly 192) at L330-337.

**Impact:** A valid official peer whose public value has a leading zero byte (probability ≈ 1/256) would be rejected by Rust. This is an interoperability edge case, not a complete failure.

**Fix required:** Change Rust to accept `len ≤ 192` and left-pad to 192 bytes before processing, matching the binary's behavior.

### 3.5 Version Endianness (PARTIAL_MATCH)

**Binary:** The version constant `3` is confirmed, but the on-wire byte order was not directly observed (PCAP captures start after version exchange).

**Rust:** `create_version_packet()` writes `SHELPER_PROTOCOL_VERSION.to_le_bytes()` → `03 00 00 00` at L587-589.

**Impact:** If the binary expects big-endian (`00 00 00 03`), the version exchange fails. If it expects little-endian, Rust matches.

**Fix required:** Determine the on-wire version endianness from a capture that includes the version exchange, or test against a live server.

### 3.6 Public Value Padding in M1 (PARTIAL_MATCH)

**Binary:** `M1` hashes `A` and `B` in their **raw minimal form** (`BN_bn2bin` output without padding), while `u` uses padded 192-byte forms.

**Rust:** `compute_srp_m1(n_bytes, g_byte, username, salt, a_bytes, b_bytes, k_full)` hashes `a_bytes` and `b_bytes` as passed by the caller. The caller must ensure correct padding.

**Impact:** If the caller passes unpadded `a_bytes`/`b_bytes` (minimal `BN_bn2bin` output), M1 matches. If padded, M1 differs.

**Fix required:** Verify call sites pass minimal-form (unpadded) public values, matching the binary's `BN_bn2bin` behavior.

---

## 4. Components Not Implemented in Rust

| Component | Binary Behavior | Rust Status | Notes |
|---|---|---|---|
| Control channel messages (Login, LoginResponse, JoinNetwork, etc.) | TLV-structured control messages after SRP-6a handshake | **NOT_IMPLEMENTED** | `src/protocol/control.rs` defines message types but no integration with the encrypted control channel |
| RSession server (`RSessionServer`) | Server-side RSA decryption, token emission | **PARTIAL** | `src/session/handshake.rs` has `RSessionServer` but integration with transport layer not verified |
| Control channel state machine (6 steps) | Full SRP-6a handshake on TCP/17301 | **NOT_IMPLEMENTED** | `ControlClientNegotiator` exists but no integration with `TcpChannel` for control port |
| Key rotation | None observed | **NOT_IMPLEMENTED** | No key rotation in either binary or Rust |
| Persistent IV reset on rekey | Not applicable (no rekey) | **NOT_IMPLEMENTED** | Same as binary |

---

## 5. Components Not in Binary but Present in Rust

| Component | Rust Behavior | Notes |
|---|---|---|
| TLV message type system (U32, U64, I32, Bool, Float, Double, Buffer, StringUtf8, etc.) | Full TLV encoding/decoding with validation | Binary uses only U32 and Buffer types; Rust has a more general TLV system |
| Bool value/raw mismatch validation | Rust rejects `value != decoded(raw)` | Binary does not appear to validate this |
| Message size limits (65535 bytes max) | `MAX_TLV_MESSAGE_SIZE = 65535` | Binary limits unknown |
| Record count limits (1024 max) | `MAX_TLV_RECORDS_PER_MESSAGE = 1024` | Binary limits unknown |

---

## 6. Test Coverage Assessment

The Rust test suite (`#[cfg(test)]` modules) provides **internal consistency verification only**:

- `test_session_full_handshake_and_encrypted_data_exchange` — Tests client-server handshake with a **generated** RSA-2048 key (`Rsa::generate(2048)`), not the original binary's key. Validates that client and Rust server agree with each other.
- `test_rsession_full_handshake_and_cchannel_key_installation` — Same, tests RSession handshake with generated key.
- All framing/TLV tests — Use synthetic data, not captured PCAP traffic.

**No test validates interoperability with the original binary's key material or protocol behavior.** A test against `RvROLClient.dll`'s actual RSA public key, or against captured PCAP traffic, would be required for interoperability evidence.

---

## 7. Recommended Fixes (Priority Order)

| Priority | Issue | Fix | Binary Evidence |
|---|---|---|---|
| 1 (Critical) | Step value endianness | Change `to_le_bytes()` to `to_be_bytes()` for all step values in `control_handshake.rs` | PCAP frames + binary builder `0x100626e0` |
| 2 (Critical) | Identity/password encoding in `x` | Hash UTF-16LE byte sequences for username and password in `compute_srp_x` | Binary `0x10060340`/`0x10060c80` hashes wide-char bytes |
| 3 (High) | Multiplier k | Determine which class is instantiated; if SRP-6a, compute `k = SHA1(N_bytes ‖ PAD(g,192))` at runtime | Binary vtable `0x100ad760`/`0x100ad7b4` |
| 4 (Medium) | Public value length check | Accept `len ≤ 192` and left-pad to 192 bytes | Binary `0x100699e0` accepts `len ≤ 192` |
| 5 (Medium) | Version endianness | Determine on-wire byte order; adjust `to_le_bytes()`/`to_be_bytes()` accordingly | PCAP capture with version exchange needed |
| 6 (Low) | Public value padding in M1 | Verify call sites pass minimal-form (unpadded) public values | Binary `BN_bn2bin` output |

---

## 8. Evidence Sources

- `shelper.dll` sha256: `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4`
- `RvROLClient.dll` sha256: `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177`
- `RvControlSvc.exe` sha256: `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`
- `src/session/control_handshake.rs` — full file read
- `src/session/control.rs` — full file read
- `src/session/handshake.rs` — full file read
- `src/crypto/famatech.rs` — full file read
- `src/crypto/mod.rs` — full file read
- `src/protocol/control.rs` — full file read
- `src/protocol/tlv.rs` — full file read (1521+ lines)
- `src/protocol/framing.rs` — full file read (335+ lines)
- `src/transport/mod.rs` — full file read (549+ lines)
- `docs/CONTROL_HANDSHAKE_SPEC.md` — contains errors corrected in this analysis
- `docs/PCAP_THIRD_ROUND_AUDIT.md` — third-round audit findings

---

**Generated file:** `docs/CRYPTO_RUST_GAP_ANALYSIS.md`  
**Original binaries and PCAPs:** Preserved, unmodified  
**Rust source code:** Unaltered