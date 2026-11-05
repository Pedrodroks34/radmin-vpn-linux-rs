# Open Questions and Certainty Classification (Round 02)

This document rigorously classifies all findings as **CONFIRMED** facts, **CORROBORATED** evidence, plausible **HYPOTHESES**, and technical gaps marked **UNKNOWN**, prioritizing what still depends on real interoperability tests.

---

## 1. General Classification of Findings

| Component / Functionality | Status | Confidence Level | Justification / Evidence |
|---|---|---|---|
| **Framing Magic (4B BE + `03 00 00 00`)** | **CONFIRMED** | 100% | Validated in `shelper.dll` and packet #35/#44 in `radmin_17301.pcap` |
| **Client Hello format (RSA-2048 PKCS#1 v1.5 with 76B block)** | **CONFIRMED** | 100% | Disassembly of `SHelper_RSession_GetNextBuffer` (`0x1006a512`) |
| **Server Hello Token (4 bytes)** | **CONFIRMED** | 100% | Disassembly of State 2 (`0x1006a4cc`) and packet #48 |
| **AES-256 key derivation (first 32B of the ephemeral key)** | **CONFIRMED** | 100% | Disassembly of `SHelper_RSession_GetKey` and `SetKeyEnc` (`0x1006ab00`) |
| **IV initialization with 16 zeros and continuous chaining** | **CONFIRMED** | 100% | Disassembly of the constructor (`0x10062ca9`) and calls to `AES_cbc_encrypt` |
| **Proprietary Trailer (16B alignment, 0xCC padding, 64-bit sum, PadLen 9..24)** | **CONFIRMED** | 100% | Disassembly of `FUN_10069c20`, `FUN_1006a0c0` and `FUN_10069f90` |
| **Semantics of TLV tag `0x010001e3` as a network operational attribute** | **CONFIRMED** | 100% | Disassembly in `RvControlSvc.exe` (`0x41537e`) and `RvROLClient.dll` (`0x1004ef1c`) |
| **Network password hashing via SHA-1 (`0x090001cd`)** | **CONFIRMED** | 100% | Disassembly of `0x10065790` calling CryptoAPI with `CALG_SHA1` (`0x8004`) |
| **STUN protocol RFC 3489 on UDP port 17309..17349** | **CONFIRMED** | 100% | Attributes 0x0001, 0x0004 and 0x0005 decoded in `radmin_vm2.pcap` |
| **Teredo deobfuscation (XOR 0xFFFF and XOR 0xFFFFFFFF)** | **CONFIRMED** | 100% | Disassembly of `CTeredoThread` in `RvROLClient.dll` (`0x10052310`) |
| **Driver IOCTL codes (`0x22c004`, `0x228014`, `0x22801c`, `0x224018`, `0x224020`)** | **CONFIRMED** | 100% | Disassembly of `DeviceIoControl` calls in `RvControlSvc.exe` |
| **Named Pipe IPC (`\\.\pipe\RadminVpnGuiChannel`) and commands `0x3ec..0x3f6`** | **CONFIRMED** | 100% | Disassembly in `RvRvpnGui.exe` (`0x4e8eb0`) and `RvControlSvc.exe` (`0x40f052`) |
| **Mechanism for obtaining the server's RSA public key** | **CORROBORATED** | 80% | RSA key embedded in the binary/configuration, but the dynamic update mechanism is not fully mapped |
| **Key renewal policy (rekeying period)** | **HYPOTHESIS** | 50% | Indications of rekeying after an inactivity timer expires or a volume limit is reached, with no explicit trigger in the PCAP |
| **Mapping of all 723 TLV property descriptors** | **CORROBORATED** | 75% | Table of types and tags extracted in full from `0x00498fe0`; detailed semantics of 45 priority tags identified |

---

## 2. Priority Open Questions

### Question 1 (HIGH priority): Provisioning and anchoring of the server's RSA public key
* **Current situation:** In the client handshake (`shelper.dll!0x1006a540`), the server's RSA public key is passed as a parameter through the pointer `[esi + 0x18]`.
* **Technical gap:** Does the official client load the coordination RSA key directly from a trusted key table embedded in the `.rdata` section of the executable, or does it accept dynamic keys negotiated previously?
* **Validation strategy:** Locate the certificate/public-key table in `.rdata` of `RvROLClient.dll` and check whether strict digital signature verification (certificate pinning) is enforced, or whether any standard RSA-2048 key is accepted on private servers.

### Question 2 (MEDIUM priority): Rekeying frequency and keepalive
* **Current situation:** In the `radmin_17301.pcap` flow, the control session stays open for minutes exchanging small telemetry packets without renewing the AES key negotiated initially.
* **Technical gap:** Does the protocol require periodic rekeying by time (for example, every hour) or by bytes transmitted? Or is the session purely persistent until the socket is disconnected?
* **Validation strategy:** Run a long session with high-volume traffic (for example, a continuous 5 GB iperf file transfer through the VPN) to observe whether the server sends a TLV message requesting a new handshake.

### Question 3 (LOW priority): Complete bitmask of the attributes in `0x010001e3`
* **Current situation:** We have confirmed that `0x010001e3` is a 32-bit network attribute used for routing control and permissions.
* **Technical gap:** What exactly are all the flag bits mapped in the 32 bits (for example, bit 0 = broadcast enabled, bit 1 = client isolation, bit 2 = access to local subnets)?
* **Validation strategy:** Compare network configuration captures with different administrative settings enabled in the official GUI.
