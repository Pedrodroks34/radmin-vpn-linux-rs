# Front 7: Teredo Tunneling Mechanism

**Certainty classification:** CONFIRMED (identification of the `CTeredoThread` class in `RvROLClient.dll` and UDP traffic on port 3544 captured in `radmin_vm2.pcap`)

---

## 1. Overview of Teredo Use in Radmin VPN

Radmin VPN includes a complete tunneling subsystem based on the **Teredo standard (RFC 4380)**, implemented in the internal class `CTeredoThread` of the `RvROLClient.dll` library. The main purpose of this mechanism is to provide an alternative point-to-point connectivity path through IPv6 encapsulated in UDP packets, when the intermediate network infrastructure blocks classic IPv4 P2P protocols or implements aggressive NATs.

---

## 2. Network Traffic Evidence (`radmin_vm2.pcap`)

In the network capture `radmin_vm2.pcap`, at packet #10:
* **Transport protocol:** UDP
* **Destination port:** `3544` (default port assigned by IANA for the Teredo service)
* **Relay server IP:** `20.201.205.4:3544` (official public Teredo infrastructure of Microsoft)

The client sends routing requests and Teredo test packets with a null authentication header to qualify the viability of the IPv6 tunnel.

---

## 3. Teredo Address Structure and Deobfuscation

The Teredo IPv6 address generated and processed by the client has 128 bits structured as defined in RFC 4380:

```
+----------------+----------------+----------------+----------------+
| Prefix 32 bits | Server IPv4    | Flags 16 bits  | Obfuscated Port|
| (2001:0000::)  | 32 bits        |                | 16 bits        |
+----------------+----------------+----------------+----------------+
| Obfuscated IPv4 Address (32 bits)                                 |
+-------------------------------------------------------------------+
```

### 3.1 Deobfuscation Routine in `RvROLClient.dll`
In the disassembled code of `CTeredoThread`:
To work around NAT devices that inspect the payload for local IP addresses to translate incorrectly (*ALG - Application Layer Gateway*), Teredo obfuscates the reflexive port and IP by applying a bitwise `XOR` operation:

$$\text{RealPort} = \text{ObfuscatedPort} \oplus \text{0xFFFF}$$

$$\text{RealIPv4} = \text{ObfuscatedIPv4} \oplus \text{0xFFFFFFFF}$$

The disassembly of `RvROLClient.dll` implements this deobfuscation directly:
```x86asm
0x10052310: movzx eax, word ptr [esi + 0x28] ; reads obfuscated port
0x10052314: xor eax, 0xffff                  ; deobfuscates port via XOR 0xFFFF
0x10052319: mov dword ptr [esi + 0x30], eax  ; stores the peer's real port
0x1005231c: mov eax, dword ptr [esi + 0x2a]  ; reads obfuscated IPv4
0x1005231f: xor eax, 0xffffffff              ; deobfuscates IPv4 via XOR 0xFFFFFFFF
0x10052324: mov dword ptr [esi + 0x34], eax  ; stores the decoded reflexive IP
```

---

## 4. Selection Priority in the Client Architecture

In the transport decision tree of Radmin VPN, the Teredo mechanism operates as a **secondary fallback strategy**:
1. If direct IPv4 P2P (UDP/TCP) fails;
2. If the client has an active Teredo adapter or support;
3. The client attempts communication via IPv6 encapsulation over Teredo through UDP port 3544 before finally falling back to the centralized `TcpRelay` server (port 17351).
