# Unresolved Questions and Next Steps — Phase 2 (`PHASE_2_UNRESOLVED.md`)

> **Project**: Radmin VPN Linux (Interoperability with the Official Client)  
> **Phase**: Phase 2 — SHelper Handshake of the Control Connection  
> **Date**: 2026-11-02  

---

## 1. Scope Effectively Resolved in Phase 2

1. **Identification and formalization of Family B (`SHelper_*`)**:
   - Definitive resolution that `SHelper_*` (`0x1006ab90`) implements **SRP-6a** (Thomas J. Wu) and constitutes the protocol of the control connection on port `17301`, dissociating it from `SHelper_RSession_*` (RSA-2048, Phase 1).
2. **SRP-6a mathematics**:
   - Parameters proven by reverse engineering of `shelper.dll`: 1536-bit prime $N$ (`0x100ac280`), $g = 5$, $k = 3$, SHA-1 hash and 40-byte KDF (`0x10061790`).
3. **TLV framing of the payloads**:
   - 4-byte header framing (`tag` in 5 bits, `length` in 27 bits) in network byte order.
4. **Rust implementation and cryptographic channel**:
   - `ControlClientNegotiator`, `ControlServerSession` and `ControlConnection` operating with `FamatechCipherState` (AES-256-CBC) and tested end to end with 101 passing tests.

---

## 2. Open Questions for Phase 3 (Out of Scope for Phase 2)

### 2.1 TLV Catalog for Login and Network Management (Post-Handshake)
- **Description**: Once the AES-256 encrypted channel of the control connection is established, the official client exchanges binary messages for account authentication, retrieval of the network list and member management.
- **Required evidence**:
  - Mapping of the internal structures of the TLV messages decrypted from `radmin_17301.pcap` (post-handshake packets from #51 onward, such as the 208-byte client frame and the 2576-byte server frame).
  - Disassembly of the message dispatch tables in `RvROLClient.dll!RolClient::CRosProtocol_SRP_ManageNetwork` and `CRosProtocol_ClientLogin`.
- **Impact**: Does not block the connectivity and security of the control channel, but is required for account login and joining virtual networks.

### 2.2 Peer Discovery and P2P Signaling
- **Description**: Mechanisms for exchanging public and local endpoints (IP/port) between nodes to establish direct tunnels (STUN / Teredo / UDP hole punching).
- **Available evidence**: Preliminary modules in `src/nat/` and captures in `radmin_vm.pcap`.
- **Next step**: Connect the endpoint signaling received over the Phase 2 control channel to the tunnel orchestrator.

### 2.3 Resilience and Reconnection with a Multi-Node Cluster
- **Description**: The captures show concurrent connections to multiple edge servers (`148.113.190.78:17301` and `198.244.203.247:17301`).
- **Current behavior**: The client connects to a specified endpoint.
- **Future evolution**: Implement a pool of redundant control connections with automatic reconnection and failover.
