# Readiness Matrix for the Rust Client Implementation (Round 02)

This document assesses the feasibility and technical readiness of implementing each subsystem in the native Linux Rust client (`radmin-vpn-linux-rs`), based strictly on the evidence confirmed during this round of reverse engineering.

---

## 1. Technical Readiness Matrix

| Module / Subsystem | Readiness Status | External Dependency / Blockers | Target Rust Files |
|---|---|---|---|
| **TCP Framing & Magic (0x03000000)** | **READY** | None | `src/transport/framing.rs` |
| **RSA-2048 / AES-256 Handshake (`HandshakeNegotiator`)** | **READY** | Server public key | `src/session/handshake.rs` |
| **Symmetric Cipher & Proprietary Trailer (`CryptoChannel`)** | **READY** | `aes`, `cbc` crates | `src/crypto/famatech.rs` |
| **Famatech TLV Serialization and Parser** | **READY** | None | `src/protocol/tlv.rs` |
| **Network Authentication and SHA-1 Hashing** | **READY** | `sha1` crate | `src/session/auth.rs` |
| **Linux TAP Layer (`/dev/net/tun`) & Packet Pump** | **READY** | `CAP_NET_ADMIN` privilege | `src/adapter/tap.rs` |
| **STUN RFC 3489 Client (NAT Discovery)** | **READY** | Asynchronous UDP sockets | `src/p2p/stun.rs` |
| **TcpRelay Forwarding Client (Port 17351)** | **READY** | None | `src/transport/relay.rs` |
| **IPC Layer (UNIX Domain Socket)** | **READY** | None | `src/ipc/server.rs` |
| **Teredo Tunneling (RFC 4380)** | **OPTIONAL (NEEDS RESEARCH)** | Local IPv6 support | `src/p2p/teredo.rs` |

---

## 2. Implementation Specifications Ready for Rust

### 2.1 Symmetric Cipher and Trailer (`src/crypto/famatech.rs`)
The trailer implementation and padding validation must strictly follow the specification extracted from `shelper.dll`:

```rust
// Mandatory trailer encoding rules:
// 1. total_len = ((payload_len + 24) / 16) * 16;
// 2. pad_len = total_len - payload_len; // 9 <= pad_len <= 24
// 3. buffer[payload_len .. total_len - 9].fill(0xCC);
// 4. checksum = sum_64bit_additive_little_endian(&buffer[0 .. total_len - 9]);
// 5. buffer[total_len - 9 .. total_len - 1].copy_from_slice(&checksum.to_le_bytes());
// 6. buffer[total_len - 1] = pad_len as u8;
// 7. aes_256_cbc_encrypt(key, &mut iv, buffer); // IV is persistent and updated in place
```

### 2.2 Handshake State Machine (`src/session/handshake.rs`)
The integration in `src/session/` must eliminate any immediate transition to `SessionActive` without network validation:

```rust
pub enum HandshakeState {
    /// 1. Sends magic framing [00 00 00 04] + [03 00 00 00], waits for an identical reply
    WaitingMagicEcho,
    /// 2. Generates 64 random bytes, builds the 76-byte block, encrypts it with RSA-2048 PKCS#1 v1.5,
    ///    sends 256 bytes and waits for the 4 bytes from the server
    WaitingServerHello {
        client_key_material: [u8; 64],
    },
    /// 3. Receives the 4-byte token, derives the AES-256 key from the first 32 bytes of
    ///    `client_key_material`, initializes the IV with zeros and activates the symmetric channel
    SessionActive {
        session_token: u32,
        crypto: CryptoChannel,
    },
    Failed(HandshakeError),
}
```

### 2.3 Local Network Device Interface (`src/adapter/tap.rs`)
Direct replacement of the Windows NDIS driver (`NetMP60_1_1_64.sys`) on Linux:
1. Open `/dev/net/tun` with `O_RDWR | O_NONBLOCK`.
2. Issue `ioctl(fd, TUNSETIFF, &ifr)` with the flags `IFF_TAP | IFF_NO_PI`.
3. Set the MTU to 1500 bytes with `SIOCSIFMTU`.
4. Set the virtual MAC address with `SIOCSIFHWADDR`.
5. Attach to a `tokio::io::unix::AsyncFd` for non-blocking asynchronous read and write of 1514-byte Ethernet frames.

---

## 3. Automated Test Plan with Extracted Vectors

To ensure conformance without regressions in the future implementation stage:
1. **64-bit checksum test:** A vector extracted directly from `shelper.dll` validating the little-endian sum of 8-byte words and the handling of excess bytes.
2. **Padding / unpadding test:** Verification that payloads of varying lengths (for example 1 to 1500 bytes) always result in strict multiples of 16 bytes, and that `pad_len` stays between 9 and 24 with `0xCC` padding.
3. **IV chaining test:** Validation that two consecutive CBC-encrypted blocks use the last 16 bytes of the previous block as the subsequent IV.
4. **TLV deserialization test:** Parsing of the Login, JoinNetwork and error-response blocks using the tags catalogued in `03-tlv-catalog.md`.
5. **STUN Binding test:** Simulation of a STUN response with attributes `0x0001`, `0x0004` and `0x0005`, as captured in packet #839 of `radmin_vm2.pcap`.
