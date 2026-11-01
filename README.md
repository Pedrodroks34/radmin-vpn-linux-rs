# Radmin VPN for Linux

An independent Linux client for Radmin VPN, written in Rust and based on reverse engineering of the official `Radmin_VPN_2.1.4951.1.exe` installer and its components.

**Project status:** Early development. The project currently consists of module scaffolding and ongoing protocol research. No functional networking implementation is available yet.

## Overview

The goal is to develop a native Linux client capable of interoperating with the Radmin VPN network, without relying on Wine or alternative VPN services.

Development is based on static and dynamic analysis of the official Windows client, including its binaries, network traffic, communication protocols, and cryptographic mechanisms.

The implementation is written in Rust, with an emphasis on modularity, maintainability, and compatibility with Linux networking infrastructure.

## Development Status

The project is currently in its research and initial implementation stage. The modules below represent the planned architecture and are not necessarily functional.

| Module | Responsibility | Status |
|---|---|---|
| `protocol` | ROS signaling protocol | Planned |
| `discovery` | Server discovery via DNS/DoH | Planned |
| `identity` | Device identity management | Planned |
| `authentication` | Authentication handshake | Planned |
| `crypto` | Encrypted communication channels | Planned |
| `transport` | UDP, TCP, and relay transports | Planned |
| `session` | Session lifecycle management | Planned |
| `network` | Virtual networks and membership | Planned |
| `routing` | Routing table management | Planned |
| `peer` | Peer discovery | Planned |
| `nat` | NAT detection and hole punching | Planned |
| `relay` | Relay server communication | Planned |
| `tunnel` | Linux TUN/TAP interface | Planned |
| `daemon` | Background service and systemd integration | Planned |
| `cli` | Command-line interface | Planned |
| `config` | Persistent configuration | Planned |

## Reverse Engineering Research

The following components and technical details have been identified during the analysis of the official Windows client.

| Component | Findings |
|---|---|
| Installer | Inno Setup installer containing a nested MSI package |
| Control service | `RvControlSvc.exe` |
| GUI communication | Named pipe: `\\.\pipe\RadminVpnGuiChannel` |
| ROL client | `RvROLClient.dll`, with 47 `ROLClient_*` exports |
| NAT client | `RvUESClient.dll`, including `UESC_GetTcpNatType` |
| Network driver | `NetMP60.sys`, an NDIS virtual miniport |
| Virtual device | `\Device\RVPNNETMP` |

**Installer SHA-256:**

    e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7

**Code signing certificate:** DigiCert → Famatech Corp. (Road Town, VG).

These findings are part of the ongoing reverse engineering effort. Identifying a component does not necessarily mean its complete behavior or protocol has been understood.

## Roadmap

The following work is planned before a functional networking implementation can be considered:

1. **Protocol analysis**
   - Identify ROS signaling servers and their communication ports.
   - Analyze packet structures and message framing.
   - Understand the authentication handshake.
   - Identify the cryptographic algorithms and key exchange mechanisms.

2. **Binary analysis**
   - Continue decompilation and analysis of `RvROLClient.dll`.
   - Investigate `RvControlSvc.exe` and its communication mechanisms.
   - Correlate static analysis findings with captured network traffic.

3. **Protocol specification**
   - Document confirmed protocol behavior in `docs/PROTOCOL_SPEC.md`.
   - Clearly distinguish confirmed findings, hypotheses, and unknowns.

4. **Implementation**
   - Implement protocol components incrementally.
   - Develop transport, authentication, and encryption layers.
   - Integrate Linux networking through TUN/TAP.
   - Build the CLI and background service.

## AI-Assisted Development

This project contains code generated with the assistance of AI tools.

AI-generated contributions are part of the current development process and should not be assumed to be fully verified, production-ready, or correct without review and testing.

The codebase is still being refined. Some comments and documentation may be verbose, repetitive, or inconsistent. Cleaning up and standardizing code comments is planned as part of the ongoing maintenance work.

## Building

### Requirements

- Rust toolchain
- Cargo

### Compile

    cargo build

### Run

    cargo run -- --help

**Note:** Since the project is still in early development, the available commands and functionality may be limited.

## Legal Notice

This project is an independent reverse engineering effort intended for interoperability, research, and educational purposes.

- It does not use or distribute code from Famatech Corp.
- It does not depend on Wine, ZeroTier, Tailscale, Hamachi, or other VPN services.
- It does not introduce custom cryptographic algorithms.
- Radmin VPN and Famatech are trademarks of their respective owners.

This project is not affiliated with, endorsed by, or supported by Famatech Corp.

## License

This project is licensed under the [MIT License](LICENSE).
