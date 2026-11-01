# AGENTS.md

Guidance for AI agents and contributors working on this repository.

## Purpose

Independent Linux client for Radmin VPN, written in Rust, based on reverse engineering of the official Windows client (`Radmin_VPN_2.1.4951.1.exe`). The project is in early development: the module structure exists, but there is no functional networking yet.

## Repository layout

- `src/`: Rust crate (`radmin-vpn`). Library in `src/lib.rs`, binary in `src/main.rs`.
- `docs/`: reverse engineering findings and protocol specification.
  - `docs/REVERSE_ENGINEERING.md`: phase 1 findings (components, imports, exports, certificates, driver).
  - `docs/PROTOCOL_SPEC.md`: phase 2 protocol specification, including traffic capture findings (section 9).
  - `docs/CONTROL_PROTOCOL.md`: control channel notes.
  - `docs/REFERENCE_PROJECT_ANALYSIS.md`: analysis of an external reference project.
- `references/`: local clones of external projects, git-ignored. Conceptual reference only.
- `Radmin_VPN_2.1.4951.1.exe`, `*.dll`, `*.sys`, `*.pcap`: proprietary binaries and captures. Git-ignored. Never commit them and never modify them.

Local analysis artifacts (extracted installer, Ghidra project, pcap captures) live outside the repository, under `/tmp`. They are not persistent and must not be assumed to exist. Paths to them in `docs/` are working references, not guarantees.

## Build and verification

```
cargo build
cargo run -- --help
```

Known state: the build is not yet verified in every environment. Before claiming it compiles, run `cargo build` and report the actual result.

There is no CI, no test suite beyond unit tests in `src/protocol/framing.rs`, and no lint or format config. When changing code, run at least:

```
cargo build
cargo test
cargo clippy
```

Report any failure in the final message. Do not hide it.

## Module status

| Module | Maps to Windows component | Status |
|---|---|---|
| `protocol` | `RvROLClient.dll` packet types | Packet fields are `_raw: Vec<u8>` placeholders. Framing (`framing.rs`) is implemented and tested. |
| `discovery` | DNS over HTTPS (`https://%hs/dns-query`) | Config only, no live resolution |
| `nat` | `RvUESClient.dll` NAT detection | Types only |
| `crypto` | `CCryptoChannel` | Placeholder. Algorithm unknown. |
| `transport` | `ROLClient_Send` / `ROLClient_Receive` | Placeholder. Wire format unknown. |
| `session` | `CRosSessionId` | State machine not implemented |
| `tunnel` | `NetMP60.sys` NDIS virtual adapter | Abstraction only, not connected to a real TUN/TAP device |
| `daemon` | `RvControlSvc.exe` | Not implemented |
| `cli` | `RvRvpnGui.exe` | Stub commands only |
| `authentication`, `identity`, `peer`, `network`, `routing`, `relay`, `config` | various | Skeleton |

## Hard constraints

- Do not invent packet fields, ports, algorithms, key sizes, server addresses, or IP ranges. Anything not confirmed by static or dynamic analysis is marked as unknown in the docs and in code.
- Do not implement cryptography from scratch. Use `ring` or `rustls`. Map algorithms to them only after they are confirmed by analysis.
- Do not use Wine, Windows VM drivers, or third-party VPNs (ZeroTier, Tailscale, Hamachi) as a base or a dependency.
- Do not copy code from reference projects, especially GPL-licensed ones. Reference them conceptually and write original code.
- Do not claim compatibility with the official client unless it has been demonstrated against it, and say how it was demonstrated.
- Do not commit proprietary binaries, captures, or dumps.

## Code style

- No comments in code. Do not add `//`, `///`, `//!`, or block comments. Make names and types carry the meaning. Put explanations of reverse engineering findings in `docs/`, not in source files.
- When editing a file that already has comments, remove the comments in the lines you touch. Do not add new ones.
- Follow `rustfmt` defaults and resolve `clippy` warnings in code you touch.
- Keep placeholders explicit: use `todo!()` or a typed error such as `anyhow::anyhow!("not implemented: ...")`, not silent `Ok(())` returns.
- Avoid `unwrap()` and `expect()` outside tests and constant initialization.
- Keep the module boundaries from the table above. Add a module only with a clear mapping to a confirmed component.

## Documentation rules

- Separate three categories in every finding: confirmed, probable, unknown.
- Cite the evidence (binary, export name, capture frame) for each confirmed claim.
- Update `docs/PROTOCOL_SPEC.md` when a finding changes. Do not leave the spec contradicting the code.
- Write documentation in the language already used by the file you are editing. The README is in English.

## Known traffic findings

These come from tshark captures (not versioned, see above):

- Control port: TCP `17301`.
- Observed server IPs: `148.113.190.78` (main), `198.244.203.247` and `45.162.230.182` (alternates).
- Frame format: 4-byte big-endian `uint32` with the payload size (header excluded), followed by the payload.
- Observed control packet: `00 00 00 04 03 00 00 00` (size 4, payload `03 00 00 00`). Probably keepalive or ACK. Not confirmed.
- After a disconnect, the client opens a new TCP connection (new source port) to the same port 17301.

## Tooling

- Ghidra 12.2 for decompiling `RvROLClient.dll` and `RvControlSvc.exe`. Use `analyzeHeadless` or the GUI. The two binaries are the highest-value analysis targets.
- `tshark` / Wireshark for captures. Use `doas` for root operations where needed.
- Java is required for Ghidra.

## Working agreements for agents

- Read the relevant doc in `docs/` before changing a module that maps to a Windows component.
- Prefer small, verifiable changes. State what was built, tested, and not tested.
- If a task needs an unknown protocol detail, stop and report the gap instead of guessing.
