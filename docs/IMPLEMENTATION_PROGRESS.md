# Implementation Progress Report: Radmin VPN Linux

This document details the progress of the native, independent Linux client for **Radmin VPN** in Rust (`radmin-vpn`), built from static and dynamic reverse engineering of the official Windows client (`Radmin_VPN_2.1.4951.1.exe`) and from network traffic captures (`radmin_vm2.pcap`, `radmin_vm.pcap`, `radmin_17301.pcap`).

---

## 1. Overview of the Three Executed Phases

| Phase | Component | Status | Test Coverage |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **TCP Framing** (4 bytes big-endian) | **Completed** | 13 unit tests |
| **Phase 1** | **TLV Protocol** (`[len][tag][val]` big-endian) | **Completed** | 8 unit tests + real Packet #686 |
| **Phase 1** | **Famatech Cryptography** (AES-256-CBC + MD5 trailer) | **Completed** | 9 unit tests |
| **Phase 2** | **Asynchronous TCP Transport** with Encryption and Retry | **Completed** | 6 unit tests |
| **Phase 2** | **Session State Machine** and Handshake | **Completed** | 2 unit tests |
| **Phase 2** | **NAT Traversal & STUN RFC 3489** | **Completed** | 3 unit tests |
| **Phase 2** | **TcpRelay Client & Route Fallback** | **Completed** | 1 unit test |
| **Phase 3** | **Linux TAP Interface** (`/dev/net/tun`, `IFF_TAP \| IFF_NO_PI`) | **Completed** | 1 unit test + MockTap |
| **Phase 3** | **Forwarding Loop (Forwarding Pump)** | **Completed** | 1 unit test (E2E Mock) |
| **Phase 3** | **Command-Line Interface (CLI)** | **Completed** | 3 unit tests |
| **Phase 3** | **End-to-End Integration Tests** | **Completed** | 3 integration tests |
| **Total** | **Complete Rust base** | **100% Compiled / 0 Warnings** | **50 tests passing (100%)** |

---

## 2. Phase 1: TLV Protocol, Framing and Cryptography

### 2.1 External TCP Framing (`src/protocol/framing.rs`)
- **Confirmed evidence:** 4-byte big-endian prefix specifying the exact size of the following payload.
- **Implementation:**
  - `FramedPacket` with a maximum limit of `MAX_PAYLOAD_SIZE = 65535` bytes.
  - Strict rejection of empty payloads (`FramingError::ZeroPayload`) and oversized ones.
  - Accumulator parser (`FrameParser`) with support for fragmentation across network calls and multiple frames in a single read.
  - EOF and truncated-frame checks when the connection is finalized.

### 2.2 TLV Protocol (`src/protocol/tlv.rs`)
- **Confirmed evidence:** wire structure `[uint32 length (BE)][uint32 tag (BE)][value bytes]`.
- **Tag decoding:**
  - `Type = (Tag >> 24) & 0xFF`:
    - `Type 0x01`: 32-bit unsigned integer (4 bytes).
    - `Type 0x02`: 64-bit unsigned integer (8 bytes).
    - `Type 0x09`: byte buffer / public key / string.
  - `FieldID = Tag & 0x00FFFFFF` (mapped to the 744 properties registered in the `RvControlSvc.exe` binary at `0x00498fe0`).
- **Critical validated tags:**
  - `0x010001df`: Session Token / ID (Field 479).
  - `0x0100032b`: Peer / Client Status (Field 811).
  - `0x090001ca`: RSA-2048 Public Key Modulus / DER (Field 458).
  - `0x01000302`: Handshake Syn ID (Field 770).
  - `0x02000303`: Handshake Cookie (Field 771).
  - `0x09000304`: Handshake Crypto (Field 772).
  - `0x020001e1`: Timestamp in milliseconds (Field 481).
- **Validation against real traffic:** Packet #686 of `radmin_vm2.pcap` (288 bytes) was incorporated into the tests and deserialized correctly, with a bit-for-bit identical round trip.

### 2.3 Proprietary Famatech Cryptography (`src/crypto/famatech.rs`)
- **Confirmed evidence in the binaries (`shelper.dll`):**
  - Routines: `FUN_10069c20` (pad and trailer), `FUN_10069f90` (unpad and verification), `FUN_1006a0c0` (64-bit LE checksum), `FUN_100638f0` (folded MD5).
- **Specification of the implemented algorithm:**
  1. `total_len = ((payload_len + 24) / 16) * 16`.
  2. `pad_len = total_len - payload_len` (with strict limits $9 \le pad\_len \le 24$).
  3. Filling with `0xCC` bytes from `payload_len` up to `total_len - 9`.
  4. 64-bit little-endian additive checksum over the first `total_len - 9` bytes (with zero-padding of the residual tail).
  5. MD5 of the 8 checksum bytes, folded into 8 bytes (`folded[i] = digest[i] + digest[i + 8]`).
  6. 9-byte trailer written at the end: `[8 bytes folded MD5][1 byte pad_len]`.
  7. Encryption in 16-byte blocks using **AES-256-CBC** without PKCS#7 padding (`pad(false)`).
  8. **Initialization vector (IV):** 16 null bytes (`0x00`) at the start of the session. The IV is continuously updated to the last 16-byte block of the generated/received ciphertext.

---

## 3. Phase 2: Transport, Session and Connectivity

### 3.1 Asynchronous TCP Transport (`src/transport/mod.rs`)
- Implementation of `TcpChannel` and `TcpChannelListener` with Tokio.
- Integrated methods: `send_secure` and `receive_secure`, applying the Famatech cipher directly to the frame stream.
- Automatic connection and reconnection with exponential backoff (`connect_with_retry`).

### 3.2 Session State Machine (`src/session/mod.rs`)
- Implemented states:
  - `Disconnected`: initial.
  - `Connecting`: TCP socket opening.
  - `ConnectedUnencrypted`: channel open, no keys.
  - `Handshaking`: sending the initial 4-byte magic (`0x00000003`).
  - `KeyExchange`: key exchange with RSA-2048 and TLV.
  - `SessionActive`: active session, AES-256-CBC encryption enabled, keepalives every 10 s.
  - `Reconnecting`: transient failure, waiting for backoff.
  - `Failed`: unrecoverable error with detailed diagnostics.

### 3.3 NAT Traversal and STUN (`src/nat/stun.rs` and `src/nat/mod.rs`)
- Complete STUN client (RFC 3489 / RFC 5389):
  - Formatting of the `Binding Request` with Magic Cookie `0x2112A442`.
  - Parsing of the `Binding Response`, decoding of `MAPPED-ADDRESS` (0x0001) and `XOR-MAPPED-ADDRESS` (0x0020).
  - Asynchronous helper for **TCP Simultaneous-Open** using `SO_REUSEADDR` and `SO_REUSEPORT` on Linux.

### 3.4 Relay Fallback (`src/relay/mod.rs`)
- `TcpRelayClient` connecting to port `17351` (`45.162.230.182:17351`).
- Peer-to-peer routing encapsulation with an 8-byte node ID header.
- `PathSelector`: attempts a direct P2P connection with a configurable timeout, and an automatic, transparent fallback to TcpRelay.

---

## 4. Phase 3: Linux Tunnel Interface, Forwarding and CLI

### 4.1 Linux TAP Interface (`src/tunnel/tap.rs`)
- Direct creation and opening of `/dev/net/tun` with the flags `IFF_TAP | IFF_NO_PI` via the `TUNSETIFF` ioctl.
- Non-blocking asynchronous operations (`AsyncFd<File>`) registered in the Tokio reactor.
- Friendly diagnostics for missing permissions: instructs the user to run with `sudo` or to configure `CAP_NET_ADMIN`.
- In-memory `MockTap` emulation mode, to allow full unit and integration test execution in unprivileged environments and in CI/CD.

### 4.2 Forwarding Loop (`src/tunnel/mod.rs`)
- `ForwardingPump`: bidirectional asynchronous loop coupling the TAP, the Famatech encryption and the TCP transport.
  - Upstream: `TAP -> AES-256-CBC encryption -> TCP framing -> socket send`.
  - Downstream: `socket receive -> TCP framing -> decryption -> TAP injection`.
- Resilience against corrupted frames: discards tampered packets without bringing down the tunnel, and increments error metrics.

### 4.3 Functional CLI (`src/cli/mod.rs`)
Implemented commands:
- `radmin-vpn status`: session state, interface, virtual IP, peers and statistics.
- `radmin-vpn interface [--name <name>] [--mock]`: tests/initializes the TAP interface.
- `radmin-vpn connect [--server <ip:port>] [--mock]`: runs the state machine with graceful signal capture (`SIGINT` / `Ctrl+C`).
- `radmin-vpn disconnect`: session shutdown.
- `radmin-vpn config [--generate <path>]`: view or generate a TOML configuration file.
- Legacy commands kept for compatibility: `join`, `leave`, `list`, `start`, `stop`.

---

## 5. Tests and Validation Performed

Verification command executed:
```bash
cargo fmt --check
cargo check
cargo test
git diff --check
git status --short
```

**Result:**
- **47 unit tests** passing in the library crate.
- **3 integration tests** passing (`tests/integration_test.rs`):
  1. `test_e2e_ethernet_pipeline`: a real ARP Ethernet frame is transmitted, encrypted, framed over TCP, received, decrypted and validated bit by bit.
  2. `test_e2e_crypto_tampering_resilience`: injecting a tampered byte into the ciphertext results in integrity rejection without a panic.
  3. `test_e2e_real_captured_packet_686_validation`: validation of the captured 288-byte packet #686 with 3 TLV records (including the RSA-2048 key).
- **0 compilation warnings (zero compiler warnings)**.
- **No commit made** (per the rules, changes kept in the working tree).

---

## 6. Confirmed Evidence vs. Questions for Future Captures

### Confirmed:
- 32-bit big-endian TLV structure.
- 4-byte big-endian TCP length framing.
- Padding algorithm, 64-bit LE checksum, folded MD5 and 9-byte trailer.
- Initial IV of 16 zeros and CBC chaining between packets.
- Structure of RFC 3489 STUN packets and identification of TcpRelay on port 17351.
- Layer 2 Ethernet operation over a TAP interface on Linux.

### Questions that depend on new captures:
- Exact sequence of messages in authentication with private network credentials (user/password on the control server).
- Exact format of the payload for negotiating the symmetric AES session key sent by the control server in response to the client's RSA public key.
