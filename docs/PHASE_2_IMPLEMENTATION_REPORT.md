# Phase 2 Implementation Report — SHelper Handshake of the Control Connection (`PHASE_2_IMPLEMENTATION_REPORT.md`)

> **Repository**: https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
> **Source branch**: `feature/control-channel-handshake`  
> **Target branch**: `main` (base commit: `8d6f09c`, merge of PR #5)  
> **Status**: Completed — Tests Run and Passed (126 passed, 1 ignored due to environmental requirements, 0 failures)

---

## 1. Executive Summary

Phase 2 successfully completed the reverse engineering and the Rust implementation of the second family of handshakes exported by `shelper.dll` (Family B: `SHelper_*`), corresponding to the **handshake of the control connection and network management** operating on TCP port `17301`.

Unlike Family A (`SHelper_RSession_*`, implemented in Phase 1), which uses RSA-2048 with `RSA_PKCS1_PADDING`, Family B was proven to be a strict implementation of the **SRP-6a** protocol (Secure Remote Password, variant by Thomas J. Wu) with a 1536-bit modular prime ($g = 5, k = 3$) and SHA-1, coupled with a compact TLV framing system (5-bit tags and 27-bit lengths).

All of the logic was implemented in Rust in a clean, modular and testable way in the new files `src/session/control_handshake.rs` and `src/session/control.rs`, integrated with the existing Famatech cryptographic channel (`FamatechCipherState`, AES-256-CBC) and re-exported in `src/session/mod.rs`.

---

## 2. Modified and Created Files

| File | Nature of the Change |
|---|---|
| [`CONTROL_HANDSHAKE_SPEC.md`](CONTROL_HANDSHAKE_SPEC.md) | **New**: Formal forensic technical specification of the SRP-6a control protocol, confidence matrix, 1536-bit group parameters, sequence diagram, TLV framing and KDF. |
| [`src/session/control_handshake.rs`](src/session/control_handshake.rs) | **New**: Complete implementation of the `SHelper_*` routines: encoding/decoding of TLV items, SRP-6a mathematical computations with OpenSSL BigNum, 40-byte KDF, $M_1$/$M_2$ proof, client (`ControlClientNegotiator`), test server (`ControlServerSession`) and 10 unit tests. |
| [`src/session/control.rs`](src/session/control.rs) | **New**: Manager of the control connection (`ControlConnection`), validation of the protocol version (3), execution of the SRP flow over `TcpChannel`, installation of the AES-256 key and exchange of encrypted messages. |
| [`src/session/mod.rs`](src/session/mod.rs) | **Modified**: Exposure of the `control` and `control_handshake` submodules and re-export of the corresponding public types. |
| [`tests/integration_test.rs`](tests/integration_test.rs) | **Modified**: Addition of the integration tests `test_e2e_phase2_control_channel_srp_handshake_and_continuity` and `test_pcap_radmin_17301_control_frames_validation`. |
| [`PHASE_2_IMPLEMENTATION_REPORT.md`](PHASE_2_IMPLEMENTATION_REPORT.md) | **New**: This consolidated report. |
| [`PHASE_2_UNRESOLVED.md`](PHASE_2_UNRESOLVED.md) | **New**: Formal record of open items and next steps (Phase 3: TLV catalog for login and network management). |

---

## 3. Reverse Engineering Evidence

### 3.1 Functions Analyzed in `shelper.dll`
- `0x1006ab90` (`SHelper_CreateClient`): initialization of the SRP-6a client instance (`0x21d4` bytes) and installation of the group-parameter validator at `0x100699e0`.
- `0x1006ad20` (`SHelper_CreateServer`): initialization of the SRP-6a server instance.
- `0x1006b1d0` (`SHelper_GetNetworkProtocolVersion`): returns the constant `3`.
- `0x1006ab80` (`SHelper_CheckNetworkProtocolVersion`): checks whether `param_1 == 3`.
- `0x1006b1e0` (`SHelper_GetNextBuffer`): dispatches to `0x10066680` (client) or `0x100670d0` (server).
- `0x10066680` (client SRP state machine):
  - `case 0`: builds Step 1 (`Tag 0x10000000`) + UTF-16BE identity (`Tag 0x20000000`).
  - `case 2`: processes Step 2 (Salt `Tag 0x30`, $N$ `Tag 0x40`, $g$ `Tag 0x50`), generates exponent $a$, emits Step 3 + ephemeral $A$ (`Tag 0x60`, 192 bytes).
  - `case 4`: processes Step 4 (ephemeral $B$ `Tag 0x60`, 192 bytes), computes $u = \text{SHA1}(\text{PAD}(A) \ || \ \text{PAD}(B))$, $S$, $K_{\text{full}}$ via KDF and emits Step 5 + proof $M_1$ (`Tag 0x70`, 20 bytes).
  - `case 6`: processes Step 6 (proof $M_2$ `Tag 0x70`, 20 bytes), validates it against the computed $M_2$ and marks the handshake as established.
- `0x10061790` (KDF): derivation of 40 bytes ($0x28$) via iterative SHA-1 over $S \ || \ \text{counter}_{\text{be32}}$.
- `0x100626e0` and `0x10062900`: assembly and disassembly of TLV items with a 5-bit tag (`0xF8000000`) and a 27-bit length (`0x07FFFFFF`).
- `0x100ac280`: hardcoded 1536-bit prime modulus $N$ (192 bytes).
- `0x100ac279`: generator $g = 5$.
- `0x100607d0`: multiplier $k = 3$.

### 3.2 Functions Analyzed in `RvROLClient.dll`
- `0x1003fbd0`: loader of the `shelper.dll` symbols in `CSRPHelperLoader`.
- `0x100dc6e0` and `0x100dd160`: instantiation and invocations of `CSRPHelperInstance` and `CSRPClient`.
- `0x1003f0f0`: executor of the client handshake loop, through successive calls to `SHelper_GetNextBuffer` until `bFinished == true`.
- `0x1003dd40` and `0x100df250`: extraction of the first 32 bytes of the key via `SHelper_GetKey` and installation in the `CChannel` with AES-256-CBC.

### 3.3 Correlation with PCAP Captures
- `radmin_17301.pcap` (TCP flows `49494` and `49493` to `148.113.190.78:17301` and `198.244.203.247:17301`):
  - Pkt #32 / #40: `00 00 00 04 03 00 00 00` (version exchange).
  - Pkt #37: frame with length `0xc0` (192 bytes) containing the client's ephemeral $A$.
  - Pkt #42: frame with length `0x100` (256 bytes) from the server.
  - Pkt #43 / #46: frames of `0xe0` (224 bytes).
  - Pkt #47 / #50: frames of `0x30` (48 bytes) containing the proofs $M_1$ and $M_2$.
- `radmin_vm2.pcap` (TCP flows `49526`, `49537`, `49538` to `17301`):
  - They reproduce, with mathematical exactness, the same sequence of sizes and steps of the control handshake.

---

## 4. Tests Performed and Results

1. **Unit tests (`cargo test --lib`)**:
   - `test_version_packet`: validates generation and validation of the protocol version (3).
   - `test_item_tlv_encode_decode`: validates encoding and decoding of multiple TLV items and tags.
   - `test_item_tlv_truncated`: validates rejection of corrupted or incomplete buffers.
   - `test_identity_utf16_byte_swapping`: validates UTF-16BE encoding and decoding.
   - `test_srp_group_parameters`: validates the 1536-bit modulus, generator 5 and multiplier 3.
   - `test_srp_kdf_40_bytes`: validates the 40-byte KDF.
   - `test_full_srp_handshake_success`: end-to-end in-memory negotiation between `ControlClientNegotiator` and `ControlServerSession`, with mutual agreement on the 32-byte key and successful Famatech encryption.
   - `test_srp_handshake_wrong_password_fails`: validates strict rejection when the password is incorrect.
   - `test_srp_handshake_tampered_m2_fails`: validates detection of a tampered $M_2$ proof.
   - `test_srp_handshake_unexpected_step`: validates rejection of an out-of-order transition.
   - `test_random_srp_exponent_bounds_and_bit_length`: validates that the generated exponents lie strictly in $1 < exp < N - 1$, bit length $\ge 1500$, and distinctness between samples generated by the CSPRNG.
   - `test_validate_srp_public_value_strict_checks`: validates strict rejection of non-canonical lengths ($!= 192$ bytes), value 0, value $N$ and value $N+1$.
   - `test_srp_handshake_bad_username_fails_closed`: validates rejection of an incorrect user by the server, with a fail-closed transition.
   - `test_srp_handshake_tampered_m1_fails_closed`: validates detection of a tampered $M_1$ proof, with a fail-closed transition.
   - `test_srp_handshake_invalid_client_a_rejected_by_server`: validates rejection of $A$ out of bounds ($A = 0$) by the server, with a fail-closed transition.
   - `test_srp_handshake_invalid_server_b_rejected_by_client`: validates rejection of a truncated $B$ by the client, with a fail-closed transition.
   - `test_srp_handshake_divergent_group_parameters_rejected`: validates rejection of divergent $g$ or $N$ parameters (divergent value, multi-byte, empty, truncated to 191B, expanded to 193B, tampered value), with a fail-closed transition.
   - `test_control_session_explicit_clear`: validates that the explicit call to `clear()` overwrites derived keys and secrets with zeros.
   - `test_control_sessions_raii_drop`: validates the lifecycle and secure disposal by RAII of `ControlClientNegotiator` and `ControlServerSession` in the initial, intermediate and established states.
   - `test_secret_bignum_explicit_clear`: validates the isolated clearing of the BigNum limbs (`num_bits() == 0`).
   - `test_secret_bignum_drop_executes_clear`: validates automatic disposal by `Drop` with `BN_clear`, via deterministic thread-local instrumentation without concurrency between threads.
   - `test_rsession_server_drop_*`: a set of 5 tests covering disposal of `RSessionServer` in the initial state, after processing a valid block, in the established session, after an idempotent `clear()` call followed by drop, and after a processing failure.
   - `test_control_client_transition_failure_zeroizes_ephemeral_secrets`: validates that failures in Steps 2, 4 and 6 transition to `Failed` and discard the ephemeral secrets.
   - `test_control_server_transition_failure_zeroizes_ephemeral_secrets`: validates that failures in Steps 1, 3 and 5 transition to `Failed` and discard the ephemeral secrets.
   - `test_control_handshake_debug_redacted` and `test_cipher_state_debug_redacted`: confirm that credentials, keys and bignums are masked as `[REDACTED]`.
   - `test_failed_session_cannot_be_reused`: ensures that sessions in the `Failed` state reject any subsequent invocation of `step()`.
2. **Integration tests (`tests/integration_test.rs`)**:
   - `test_e2e_phase2_control_channel_srp_handshake_and_continuity`: simulated local TCP server + `ControlConnection` client, complete handshake (version + SRP-6a) and bidirectional exchange of multiple encrypted commands via AES-256-CBC.
   - `test_e2e_phase2_control_channel_srp_tampered_proof_fails_closed`: TCP loopback with injection of a tampered $M_1$ proof, validating rejection with `ProofVerificationFailed`, server state `Failed`, fail-closed shutdown of the transport and absence of panics (with the server task explicitly awaited).
   - `test_e2e_phase2_control_channel_srp_tampered_m2_fails_closed`: TCP loopback with injection of a tampered $M_2$ proof, validating rejection by the client with fail-closed behavior and a clean server termination without panics.
   - `test_pcap_radmin_17301_control_frames_validation`: validation against real framing vectors from `radmin_17301.pcap`.
3. **Consolidated final metrics of the fifth audit round**:
   - `cargo fmt --check`: **Passed** (zero differences).
   - `cargo clippy --all-targets --all-features -- -D warnings`: **Passed** (zero warnings across the entire tree).
   - `cargo test --locked`: **127 tests evaluated** (118 unit tests passed + 1 environmental TAP ignored; 8 integration tests passed; 0 failures). Total of **126 tests passed**.
4. **Lifecycle and memory safety guarantees**:
   - Hardening of the lifecycle of the 32-byte AES keys: `session_key()` returns `Option<Zeroizing<[u8; 32]>>`, `session_key_ref()` allows direct access by reference `&[u8; 32]`, and `create_cipher_state()` initializes the channel directly via `from_key_ref` without allocating intermediate temporary buffers that are not zeroized.
   - The constructors of `FamatechCipherState` (`from_key_ref`, `from_separate_keys_ref`, `from_rsession_key`) eliminate redundant copies and ensure that any arguments passed by value are protected and cleared via `Zeroizing`.
   - `Drop` implementation with an idempotent routine in `RSessionServer` and `HandshakeNegotiator` for explicit clearing of `key_material` via `Zeroize::zeroize()`.
   - `SecretBigNum` RAII wrapper on all exponents, verifiers and intermediate secrets, with an unconditional call to `BN_clear` before heap deallocation (`BN_free`).
   - Zeroization via `Zeroizing` for cipher buffers, passwords, salts, the digest of the $M_1$/$M_2$ proofs and the KDF keys.
   - Full `Debug` redaction and removal of improper `Clone` on the cipher state.
   - **Documented boundaries and technical limitations**: the application applies deterministic zeroization to the structures and buffers under Rust's control and to the limbs under `SecretBigNum`. Physical and external-ecosystem limitations include ephemeral scratch buffers internal to `BN_CTX` allocated by the OpenSSL C library (whose recycling depends on the C context), and potential paging to a swap partition by the operating system kernel in the absence of `mlock(2)` privileges.
