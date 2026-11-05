# General Reverse Engineering Evidence Index (Round 02)

This document structurally catalogs all virtual memory addresses (VA), file offsets, symbols, packet identifiers in PCAP captures, and cross-references that support the technical conclusions of the ten investigation fronts.

---

## 1. Table of Analyzed Binaries and Artifacts

| File | Size (Bytes) | Architecture | Abbreviated SHA-256 | Role in the System |
|---|---|---|---|---|
| `RvControlSvc.exe` | 1,835,008 | x86 (32-bit PE) | `...` | Main system service, orchestrator and TLV tables |
| `RvRvpnGui.exe` | 2,502,656 | x86 (32-bit PE) | `...` | Official user interface and Named Pipe IPC client |
| `RvROLClient.dll` | 983,040 | x86 (32-bit PE) | `...` | Client for the Famatech ROL network and coordination service |
| `RvUESClient.dll` | 417,792 | x86 (32-bit PE) | `...` | Internal asynchronous messaging subsystem |
| `shelper.dll` | 806,912 | x86 (32-bit PE) | `...` | OpenSSL + CryptoAPI cryptographic engine |
| `NetMP60_1_1_64.sys` | 67,584 | x64 (64-bit PE) | `...` | NDIS 6.0 miniport driver for the virtual adapter |
| `radmin_17301.pcap` | 1,258,496 | pcapng | N/A | TCP traffic capture on ports 17301 and 17351 (Relay) |
| `radmin_vm2.pcap` | 3,489,792 | pcapng | N/A | STUN traffic capture (UDP 17309-17349) and Teredo (UDP 3544) |
| `radmin_vm.pcap` | 2,150,400 | pcapng | N/A | Full session capture in a virtual machine environment |

---

## 2. Index of Functions and Virtual Addresses by Front

### Front 1: Handshake and Key Exchange
* `shelper.dll!0x1006b860` (`SHelper_RSession_CreateClient`): Constructor of the client's RSA handshake session.
* `shelper.dll!0x1006a2b0` (`SHelper_RSession_GetNextBuffer`): Dispatcher of the handshake state machine (States 0, 1, 2, 3).
* `shelper.dll!0x1006a512`: State 0 — generation of 64 key bytes via `RAND_bytes`, 12-byte header and RSA encryption of 76 bytes.
* `shelper.dll!0x1006a4cc`: State 2 — validation and reading of the 4-byte session token received from the server (`cmp eax, 4`).
* `shelper.dll!0x1006ba80` (`SHelper_RSession_GetKey`): Extraction of the first 32 bytes of key material to derive the AES-256 key.

### Front 2: Cryptography and Frame Format
* `shelper.dll!0x10065de8`: Call to `RSA_public_encrypt` with `push 1` (`RSA_PKCS1_PADDING`).
* `shelper.dll!0x10062ca9`: Zero initialization (`xorps xmm0, xmm0`) of the encryption IVs (`esi+0x1ec`) and decryption IVs (`esi+0x1fc`).
* `shelper.dll!0x10062e00` / `0x10062d60`: Encryption and decryption routines calling OpenSSL `AES_cbc_encrypt` (`0x10003b30`), maintaining continuous IV chaining.
* `shelper.dll!0x10069c20`: Aligned-size calculation routine: `((payload_len + 24) / 16) * 16`.
* `shelper.dll!0x1006a0c0`: Little-endian 64-bit additive checksum algorithm over the range `[0 .. total_len - 9]`.
* `shelper.dll!0x10069f90`: Frame validation and unpacking routine (validates `9 <= pad_len <= 24` and verifies the checksum).

### Front 3: TLV Catalog
* `RvControlSvc.exe!0x00498fe0`: Global table containing the 723 TLV property descriptors.
* `RvControlSvc.exe!0x41537e`: Handler of property `0x010001e3` as a network operational attribute (`UINT32`).
* `RvROLClient.dll!0x1004ef1c`: Processing of tag `0x010001e3` alongside `0x040001e7` (boolean) and `0x0200025e` (uint64 timestamp).
* `RvControlSvc.exe!0x488ae0`: Generic TLV serialization engine (32-bit BE tag + 32-bit BE length + value).

### Front 4: Authentication and Networks
* `shelper.dll!0x10065790`: Network password hashing via CryptoAPI using `CALG_SHA1` (`0x8004`), producing a 20-byte digest for tag `0x090001cd`.
* `RvROLClient.dll!0x100412a0`: Entry point of `ROLClient_JoinNetwork`.
* `RvROLClient.dll!0x1004a090`: Construction of the `JoinNetworkRequest` TLV message.
* `RvROLClient.dll!0x1004a115`: Check of the return status codes in tag `0x010001df`.

### Front 5: TcpRelay
* `RvControlSvc.exe!0x43fb60`: Transport enum conversion function: `0 -> "TCP"`, `1 -> "UDP"`, `2 -> "TcpRelay"`.
* `RvROLClient.dll!0x1004d220`: Establishment of the relay tunnel on port 17351.

### Front 6: NAT and STUN
* `RvROLClient.dll!0x10051180`: Routine that sends the RFC 3489 STUN Binding Request.
* `RvROLClient.dll!0x10051640`: Decoding of attributes `0x0001` (MAPPED-ADDRESS), `0x0004` (SOURCE-ADDRESS) and `0x0005` (CHANGED-ADDRESS).

### Front 7: Teredo
* `RvROLClient.dll!0x10052310`: Deobfuscation of the port (`XOR 0xFFFF`) and IPv4 address (`XOR 0xFFFFFFFF`) of the Teredo client (`CTeredoThread`).

### Front 8: Windows IPC
* `RvControlSvc.exe!0x519e74`: UTF-16 string `\\.\pipe\RadminVpnGuiChannel`.
* `RvControlSvc.exe!0x40f052` / `0x47de40`: Creation of the Named Pipe with a 200-instance limit.
* `RvRvpnGui.exe!0x4e8eb0`: Function `FUN_004e8eb0`, connection to the pipe via `0x5352d0` and emission of the initial command `0x3f6` at `0x4e8f78`.
* `RvRvpnGui.exe!0x4e2ac0`: Central IPC message dispatcher and handling of commands `0x3ec`, `0x3ed`, `0x3ee`, `0x3ef`, `0x3f6`.

### Front 9: NDIS Driver
* `NetMP60_1_1_64.sys!0x14000c05c`: Configuration of `NDIS_DEVICE_OBJECT_ATTRIBUTES` with the name `\Device\RVPNNETMP` and registration via `NdisRegisterDeviceEx` (`0x14000c08f`).
* `NetMP60_1_1_64.sys!0x1400030cc`: Asynchronous IRP queuing routine returning `STATUS_PENDING` (`0x103` at `0x140003222`).
* `RvControlSvc.exe!0x4aff8a`: IOCTL `0x224020` (Media Status, 1 byte out).
* `RvControlSvc.exe!0x4b003a`: IOCTL `0x224018` (Link speed/MTU, 4 bytes out).
* `RvControlSvc.exe!0x4b00a4`: IOCTL `0x22801c` (Set state/MTU, 4 bytes in).
* `RvControlSvc.exe!0x4b0123`: IOCTL `0x228014` (Set MAC Address, 6 bytes in).
* `RvControlSvc.exe!0x4b017f`: IOCTL `0x22c004` (Adapter Control & Event Exchange, 8 bytes in, 12 bytes out).

---

## 3. Index of Packets in Network Captures (PCAP)

| Capture | Packet Number | Source / Destination Address | Protocol / Port | Identified Data / Meaning |
|---|---|---|---|---|
| `radmin_17301.pcap` | #35 | `192.168.122.77:49493 -> 198.244.203.247:17301` | TCP (8 bytes) | Magic Framing `00 00 00 04` + Magic Payload `03 00 00 00` |
| `radmin_17301.pcap` | #44 | `198.244.203.247:17301 -> 192.168.122.77:49493` | TCP (8 bytes) | Server Echo of the Magic: `00 00 00 04 03 00 00 00` |
| `radmin_17301.pcap` | #46 | `192.168.122.77:49493 -> 198.244.203.247:17301` | TCP (260 bytes) | RSA-2048 Client Hello (76-byte encrypted payload) |
| `radmin_17301.pcap` | #48 | `198.244.203.247:17301 -> 192.168.122.77:49493` | TCP (8 bytes) | Server Hello with the 4-byte session token |
| `radmin_17301.pcap` | #50 | `192.168.122.77:49493 -> 198.244.203.247:17301` | TCP | First frame encrypted with AES-256-CBC and the 0xCC trailer |
| `radmin_17301.pcap` | #688..#710 | `192.168.122.77:49502 <-> 198.244.203.247:17351` | TCP Relay | Establishment of the TcpRelay forwarding tunnel and exchange of E2E-encrypted data |
| `radmin_vm2.pcap` | #10 | `192.168.122.77 -> 20.201.205.4:3544` | UDP Teredo | Initialization packet of the IPv6-over-UDP Teredo tunnel |
| `radmin_vm2.pcap` | #796 | `192.168.122.77:54536 -> 198.244.203.247:17348` | UDP STUN | STUN RFC 3489 Binding Request (`0x0001`) |
| `radmin_vm2.pcap` | #839 | `198.244.203.247:17348 -> 192.168.122.77:54536` | UDP STUN | STUN Binding Response returning the reflexive IP `<CLIENT-PUBLIC-IP>:54536` |
