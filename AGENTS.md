# AGENTS.md — Radmin VPN reverse-engineering repo

## Repo layout

- `Radmin_VPN_2.1.4951.1.exe` — original Windows installer (Inno Setup + nested MSI, 54 MB). Do not modify.
- `src/` — Rust Linux client (early scaffold, compiles, no network logic yet).
- `docs/` — REA findings and protocol spec.
  - `docs/REFERENCE_PROJECT_ANALYSIS.md` — analysis of external project `baptisterajaut/radmin-vpn-linux` (Wine-based, cloned to `references/radmin-vpn-linux/`).
- `references/radmin-vpn-linux/` — cloned external project (Wine-based Radmin VPN for Linux). GPL-3.0. Do NOT copy code into our Rust project; use only as conceptual reference.
- `/tmp/opencode/radmin_ext/` — extracted installer contents (outside repo, not version-controlled). Source of truth for static binary analysis.
- `/tmp/radmin_vm.pcap`, `/tmp/radmin_vm2.pcap` — Wireshark/tshark captures from VM (192.168.122.77).
- `/tmp/radmin_17301.pcap` — filtered capture of port 17301 traffic.
- `/tmp/opencode/ghidra_12.2/` — Ghidra 12.2 extracted (for decompilation). Database already built at `/tmp/opencode/ghidra_project/radmin_project.rep`.

## Build / verify

From repo root (`/home/pedrodroks/Downloads/radmin`):

```
cargo build        # builds OK (1 warning: unused import in src/main.rs)
cargo run -- --help
```

No test suite, no CI, no lint/format config. `cargo build` is the only verified command.

## Architecture (what is real vs. placeholder)

The Rust project is a module skeleton mirroring the Windows components found in the installer:

| Module | Maps to Windows binary | Status |
|---|---|---|
| `src/protocol/packets.rs` | `RvROLClient.dll` packet types (~40 RTTI names) | All fields are `_raw: Vec<u8>` placeholders |
| `src/discovery/mod.rs` | DNS/DoH (`https://%hs/dns-query`) | Config only, no live resolution |
| `src/nat/mod.rs` | `RvUESClient.dll` NAT detection | Types only, no detection logic |
| `src/crypto/mod.rs` | `CCryptoChannel` | Algorithms unknown; placeholder only |
| `src/transport/mod.rs` | `ROLClient_Send/Receive` | Format unknown; placeholder only |
| `src/session/mod.rs` | `CRosSessionId` | State machine not implemented |
| `src/tunnel/mod.rs` | `NetMP60.sys` NDIS virtual adapter | TUN/TAP abstraction, not wired up |
| `src/daemon/mod.rs` | `RvControlSvc.exe` Windows service | Not implemented |
| `src/cli/mod.rs` | `RvRvpnGui.exe` Qt GUI | Stub commands only |

## Critical constraints (do not violate)

- **Do not invent packet fields, ports, algorithms, or server addresses.** Every `desconhecido`/`unknown` in `docs/PROTOCOL_SPEC.md` is genuinely unknown from static analysis.
- **Do not implement crypto from scratch.** `CCryptoChannel` exists but its algorithm is undetermined.
- **No Wine, no Windows VM drivers, no third-party VPN (ZeroTier/Tailscale/Hamachi) as base.**
- **Do not declare compatibility.** Not demonstrated against the official Windows client.

## Where findings live

- `docs/REVERSE_ENGINEERING.md` — phase 1 findings (components, imports, exports, certificates, driver).
- `docs/PROTOCOL_SPEC.md` — phase 2 protocol spec. Includes traffic capture findings (section 9).
- REA evidence IDs are cited in those docs; extracted binaries remain in `/tmp/opencode/radmin_ext/`.

## Traffic capture findings (confirmed via tshark)

- **Radmin control port:** `17301` (TCP)
- **Main server IP:** `148.113.190.78` (also `198.244.203.247`, `45.162.230.182` as alternates)
- **Frame format:** 4-byte big-endian `uint32_t` = payload size (excludes header), followed by payload bytes
- **Control packet:** `00 00 00 04 03 00 00 00` (size=4 + payload `03 00 00 00`) — likely keepalive/ACK
- **Reconnection:** new TCP connection (different source port) to same 17301 after disconnect
- Captures in `/tmp/radmin_vm2.pcap` and `/tmp/radmin_17301.pcap`

## Tooling

- **Ghidra 12.2:** extracted at `/tmp/opencode/ghidra_12.2/ghidra_12.2_PUBLIC/` — use `analyzeHeadless` or GUI to decompile `RvROLClient.dll` and `RvControlSvc.exe`
- **tshark/wireshark:** available at `/usr/bin/tshark`, `/usr/bin/wireshark` (use `doas` for root)
- Java 27 available (`/usr/bin/java`)

## Entry points

- Rust lib: `src/lib.rs` (re-exports all modules)
- Rust binary: `src/main.rs` (CLI via clap, stub commands)
- Analysis target: `/tmp/opencode/radmin_ext/RvROLClient.dll` and `RvControlSvc.exe` are the highest-value binaries.
