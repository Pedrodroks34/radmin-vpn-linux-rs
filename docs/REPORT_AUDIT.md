# Critical Audit of the Radmin VPN Reverse Engineering Report
**File:** `docs/REPORT_AUDIT.md`  
**Author:** Antigravity (Google DeepMind - Advanced Agentic Coding)  
**Date:** November 1, 2026  
**Binaries audited:** `RvControlSvc.exe`, `RvROLClient.dll`, `RvUESClient.dll`, `shelper.dll`, `NetMP60_1_1_64.sys`  
**PCAPs audited:** `radmin_17301.pcap`, `radmin_vm2.pcap`, `radmin_vm.pcap`  

---

## 1. Introduction and Methodology

This independent technical audit was carried out to rigorously verify the conclusions previously documented in the report `RELATORIO_ENGENHARIA_REVERSA_RADMIN.md`. 

No previous claim was accepted a priori. All conclusions were subjected to cross-verification:
1. **Inspection of raw packets** in the original PCAPs (`dpkt`, `scapy`).
2. **Instruction-by-instruction disassembly and decompilation** of the binaries into x86/x64 assembly (`capstone`, Ghidra 12.2).
3. **Development and execution of independent tests** for encoding/decoding with synthetic data.

---

## 2. Validation of the TLV Format

### 2.1 Confirmation of the Wire Structure
- **Declared structure:** `[uint32 length][uint32 tag][value]`
- **Validation status:** **CONFIRMED WITH PRECISION.**
- **Evidence in traffic:**
  - In the file **`radmin_vm2.pcap`**, **Packet #686** (and correlated #5486 and #5631 in `radmin_vm.pcap`):
    - External TCP framing: `00 00 01 20` (Big-Endian `0x0120` = 288 bytes).
    - **Record 1:**
      - Length: `00 00 00 04` (4 bytes)
      - Tag: `01 00 01 df` (`Type 1`, Field `0x1df`)
      - Value: `00 00 00 01` (uint32 = 1)
    - **Record 2:**
      - Length: `00 00 00 04` (4 bytes)
      - Tag: `01 00 03 2b` (`Type 1`, Field `0x32b`)
      - Value: `00 00 00 02` (uint32 = 2)
    - **Record 3:**
      - Length: `00 00 01 00` (256 bytes)
      - Tag: `09 00 01 ca` (`Type 9`, Field `0x1ca`)
      - Value: 256 bytes of an RSA-2048 public key.
    - **Exact sum:** `(4 + 4 + 4) + (4 + 4 + 4) + (4 + 4 + 256) = 12 + 12 + 264 = 288 bytes`. The size matches the external framing `0x0120` exactly.

### 2.2 Discovery of the Global Schema Catalog (Binary)
- **Function:** `FUN_00498fe0` in `RvControlSvc.exe` (`0x00498fe0`).
- **Critical finding:** This function is a massive static initializer that registers **744 field descriptors** in the global table `0x5a52b4` through calls to the function `0x004aec20`.
- **Mapping of the audited fields:**
  - **`0x010001df`:** Registered at `0x0049fccd` with the call `call 0x4aec20` (BSS object at `0x59cb2c`).
  - **`0x0100032b`:** Registered at `0x0049fd18` with the call `call 0x4aec20` (BSS object at `0x59cb5c`).
  - **`0x090001ca`:** Registered at `0x0049f46d` with the call `call 0x4aec20` (BSS object at `0x59c618`).
- **Wire encoders in `RvControlSvc.exe`:**
  - `FUN_00488ae0`: base serializer that performs `_byteswap_ulong` on the length and the tag (ensuring Big-Endian on the network).
  - `FUN_00472ef0`: validates `tag & 0xFF000000 == 0x01000000` (32-bit integer).
  - `FUN_00472f60`: validates `tag & 0xFF000000 == 0x02000000` (64-bit integer).
  - `FUN_004795d0`: validates `tag & 0xFF000000 == 0x09000000` (arbitrary buffer).

### 2.3 Separation of Framing
- Transport-level framing is **separate** from TLV framing:
  - Every TCP frame on the network begins with a fixed 4-byte header: `[uint32 Big-Endian Length]`.
  - Before the encrypted channel is established, the payload is a concatenated sequence of TLV records.
  - After encryption is activated, the 4-byte header indicates the length of the cryptographic block (always a multiple of 16 bytes). The TLV content travels inside the decrypted block.

---

## 3. Validation of the Cryptography (`shelper.dll`)

### 3.1 Reconstructed and Verified Pseudocode

#### Padding and Trailer Preparation (Before Encryption - `FUN_10069c20`)
```python
def famatech_pad_and_sign(payload: bytes, block_size: int = 16) -> bytes:
    payload_len = len(payload)
    if payload_len == 0 or block_size >= 256:
        raise ValueError("Invalid size")
        
    # 1. Computation of the aligned total size:
    # In assembly: eax = block_size + 8 + payload_len; eax /= block_size; eax *= block_size;
    total_len = ((payload_len + 24) // block_size) * block_size
    pad_len = total_len - payload_len  # 9 <= pad_len <= 24 (for block_size=16)

    buf = bytearray(total_len)
    buf[:payload_len] = payload

    # 2. Filling with 0xCC bytes up to total_len - 9
    for i in range(payload_len, total_len - 9):
        buf[i] = 0xCC

    # 3. 64-bit additive checksum (FUN_1006a0c0) over the first (total_len - 9) bytes
    sum_64 = 0
    num_u64 = (total_len - 9) // 8
    for i in range(num_u64):
        word = int.from_bytes(buf[i * 8 : (i + 1) * 8], 'little')
        sum_64 = (sum_64 + word) & 0xFFFFFFFFFFFFFFFF
        
    rem = (total_len - 9) % 8
    if rem > 0:
        tail = bytes(buf[num_u64 * 8 : total_len - 9]) + b'\x00' * (8 - rem)
        word = int.from_bytes(tail, 'little')
        sum_64 = (sum_64 + word) & 0xFFFFFFFFFFFFFFFF

    # 4. MD5 hash of the 8 checksum bytes (FUN_100638f0)
    sum_bytes = sum_64.to_bytes(8, 'little')
    md5_digest = bytearray(hashlib.md5(sum_bytes).digest()) # 16 bytes

    # 5. Fold the MD5 into 8 bytes (lines 0x10069ce0 to 0x10069d15)
    trailer_mac = bytearray(8)
    for i in range(8):
        trailer_mac[i] = (md5_digest[i] + md5_digest[i + 8]) & 0xFF

    # 6. Writing the trailer: 8 bytes of MAC + 1 byte of pad_len
    buf[total_len - 9 : total_len - 1] = trailer_mac
    buf[total_len - 1] = pad_len

    return bytes(buf)
```

#### Verification and Padding Removal (After Decryption - `FUN_10069f90`)
1. Decrypts the block with AES-256-CBC.
2. Reads `pad_len = buf[total_len - 1]`.
3. Validates: `9 <= pad_len <= (block_size + 9)`. If invalid, rejects.
4. Validates whether the bytes in `buf[total_len - pad_len .. total_len - 10]` are all `0xCC`.
5. Recalculates the 64-bit checksum over `buf[0 .. total_len - 9]`.
6. Recalculates the folded MD5 and compares it with the 8 bytes in `buf[total_len - 9 .. total_len - 1]`.
7. If identical, returns the authentic payload from `buf[0 .. total_len - pad_len]`.

### 3.2 Key and IV Initialization
- **Key size:** 32 bytes (256 bits), verified in `SHelper_CChannel_SetKeyEnc` (`0x1006ab00: cmp param_3, 0x20`).
- **IV initialization:**
  - In the AES channel initialization function (`0x10062c16` and `0x10062cac`):
    ```asm
    0x10062c16: xorps  xmm0, xmm0
    0x10062c1c: movdqu xmmword ptr [esi + 0x1ec], xmm0   ; Encrypt IV = 16 zeros
    0x10062c24: movdqu xmmword ptr [esi + 0x1fc], xmm0   ; Decrypt IV = 16 zeros
    ```
  - **The initial IV is exactly 16 null bytes (`0x00`).**
  - The subsequent IV is updated in place by OpenSSL's CBC mode (`FUN_10003b30` / `AES_cbc_encrypt`), chaining the final blocks of each packet sent/received.
- **Order of application:** The trailer and the padding are calculated and appended **BEFORE** encryption. The receiver runs AES-CBC decryption **BEFORE** verifying and removing the trailer.

### 3.3 Independent Test Performed
A regression test was run in Python using the `cryptography` library and synthetic data vectors covering all size equivalence classes:
- Payloads tested: 4, 5, 7, 8, 15, 16, 23, 24 and 100 bytes.
- All tests succeeded: 100% integrity verified, correct padding removal, and identical reconstruction of the original data.

---

## 4. Validation of P2P Communication and NAT Traversal

### 4.1 Irrefutable Evidence of Direct Peer-to-Peer Communication
- **Identified endpoints:**
  - Local client: `192.168.122.77`
  - Remote peer: `<PEER-IP-A>:62565` (residential public IP).
- **Evidence in the PCAP `radmin_vm2.pcap`:**
  1. **Active P2P session:** Between packets #65 and #599, both nodes maintain an established TCP connection, transmitting regular keepalive/data frames (`00 00 00 10 ...`, 16 bytes of encrypted payload) at intervals of approximately 10 seconds.
  2. **Clean closure:** In packets #600 and #607, the session is closed bilaterally with `FIN-ACK` flags (`0x11`).
  3. **Reconnection via TCP Simultaneous-Open:**
     - Packet #696 (`t=1793481039.325`): Local sends SYN seq=3817256890 to `<PEER-IP-A>:62565` from port `49527`.
     - Packet #703 (`t=1793481039.342`): Remote peer sends SYN seq=2399116486 to `192.168.122.77:49527`.
     - Packet #704 (`t=1793481039.342`): Local replies with SYN-ACK (`flags 0x12`).
     - Packet #714 (`t=1793481039.388`): Remote peer replies with ACK (`flags 0x10`).
     - **Conclusion:** The four-way TCP handshake by simultaneous open was completed successfully and the direct P2P connection was re-established.

### 4.2 Role of Port 17351 (`TcpRelay`)
- **Critical audit:** Port 17351 is **not a pure control channel**, but the formal service **`TcpRelay`**.
- **Evidence in the binary (`RvControlSvc.exe`):**
  - At `0x0043fb60`, there is the channel-enum conversion function:
    ```
    Type 0 -> "TCP"
    Type 1 -> "UDP"
    Type 2 -> "TcpRelay" (string at 0x0051df00)
    ```
  - At `0x0043fb81`, the formatting string logs: `'%ls' via %hs/%hs` (e.g., `'NodeName' via TcpRelay/outgoing`).
- **Behavior on the network:** Each connection to `45.162.230.182:17351` negotiates an independent RSA session and, from then on, carries the same encrypted and framed packets that would be sent directly between peers.

### 4.3 Demonstration of the Correlation of Teredo with the Radmin Peers
The audit proved, statically and on the network, that the Teredo traffic is directly associated with Radmin VPN:
1. **Evidence in the binary:** In `RvROLClient.dll`, the RTTI C++ class was located:
   `RolClient::teredo::CTeredoThread` (strings at `0x10103608` and `0x10103620`).
2. **RFC 4380 decoding of the packets in the PCAP:**
   The IPv6 packets encapsulated in UDP 54778 were mathematically decoded:
   - `2001:0:14c9:cd04:2c09:2a05:44c4:38d8`:
     - Server: `20.201.205.4` (Microsoft Teredo Relay)
     - **Client public IP:** `<CLIENT-PUBLIC-IP>` (external IP of the local machine `192.168.122.77`)
     - Mapped port: `54778`
   - `2001:0:14c9:cd04:28ed:3718:4cdd:5377`:
     - **Peer public IP:** `<PEER-IP-A>` (the exact remote node with which Radmin established direct TCP!)
     - Mapped port: `51431`
   - `2001:0:14c9:cd04:4d7:1ce6:4e8f:b01d`:
     - **Peer public IP:** `<PEER-IP-B>` (the second remote node to which the client fired the SYN of packet #784).
3. **Internal payloads:** The encapsulated packets carry NAT traversal bubbles (NextHeader 59) and TCP SYN packets directed at the service ports of the remote node.

---

## 5. Validation of the TAP Driver (`NetMP60_1_1_64.sys`)

### 5.1 Transport of Ethernet Frames
- **Status:** **CONFIRMED.**
- The driver `NetMP60_1_1_64.sys` registers itself as a virtual NDIS 6.0 miniport with Ethernet media (`NdisMedium802_3`).
- The routines `FUN_00476b60` (`ReadFile`) and `FUN_00476c10` (`WriteFile`) in `RvControlSvc.exe` transfer buffers that contain the complete 14-byte Ethernet header (`DMAC + SMAC + EtherType`) followed by the IP payload.

### 5.2 Asynchronous Synchronization
- In `FUN_0047d5c0` (read) and `FUN_0047d8a0` (write), the operations are triggered with `OVERLAPPED` structures (`this + 0x5c` and `this + 0x7c`).
- The service explicitly handles the return `GetLastError() == 0x3e5` (`ERROR_IO_PENDING`), marking the pending flags at `this + 0x78` and `this + 0x98`.
- Synchronization and unblocking occur via `GetOverlappedResult` (`0x5171c0`), associated with loops using `CancelIoEx` (`0x5171bc`) for graceful cancellation.

### 5.3 Critical Correction: Discovery of the Configuration IOCTLs
The preliminary report erroneously stated that no IOCTL was used. The audit located **5 calls to `DeviceIoControl` (`0x517170`)** directed at the driver handle in `RvControlSvc.exe`:
- **`0x228014` (at `0x4b011d`):** Sends a 6-byte buffer. This is the configuration of the **MAC address** of the virtual interface (`NetVRadminMacAddress`).
- **`0x224018` (at `0x4b0034`):** Queries the status and attributes of the interface.
- **`0x224020` (at `0x4aff84`):** Reads transmission statistics.
- **`0x22801c` (at `0x4b009e`):** Configures network parameters / link state (Up/Down).
- **`0x22c004` (at `0x4b0179`):** Registration handshake and synchronization of the service with the miniport.

### 5.4 Equivalence on Linux
The equivalence with `IFF_TAP | IFF_NO_PI` is **fully functional and sufficient**, with the following architectural mapping:
1. **Packet I/O:** Asynchronous `ReadFile` and `WriteFile` on Windows map directly to `read()` and `write()` (or asynchronous I/O with `tokio::io::AsyncReadExt` / `AsyncWriteExt`) on the file descriptor `/dev/net/tun`.
2. **Replacement of the IOCTLs:**
   - IOCTL `0x228014` (MAC) -> `SIOCSIFHWADDR` (or Netlink via `rtnetlink`).
   - IOCTL `0x22801c` (Link Up) -> `SIOCSIFFLAGS` with `IFF_UP | IFF_RUNNING`.
   - MTU configuration -> `SIOCSIFMTU`.

---

## 6. Comparative Table: Audited Conclusions

| Item Analyzed | Previous Conclusion | Audit Verdict | Technical Justification |
| :--- | :--- | :--- | :--- |
| **Reference to Pkt #686** | "Packet #686 in `radmin_vm.pcap`" | **CORRECTED** | Packet #686 in `radmin_vm.pcap` is TLS/Akamai. The packet with TLV records is **#686 in `radmin_vm2.pcap`** (and #5486 in `radmin_vm.pcap`). |
| **Big-Endian TLV structure** | `[Len:4][Tag:4][Val:N]` | **CONFIRMED** | Verified mathematically in the packets and confirmed in the catalog of 744 fields in `FUN_00498fe0`. |
| **Fields 0x1df, 0x32b, 0x1ca** | Handshake / RSA key | **CONFIRMED** | Located at the schema registration points `0x49fccd`, `0x49fd18` and `0x49f46d`. |
| **Symmetric cipher** | AES-256-CBC | **CONFIRMED** | Confirmed in `FUN_10062fb0`, `FUN_10062e00` and the OpenSSL wrappers. |
| **Initial IV** | Not detailed | **CONFIRMED / EXPANDED** | The initial IV is **16 zeroed bytes (`0x00`)**, as demonstrated at `0x10062c16`. |
| **Trailer position** | Not specified | **CONFIRMED / SPECIFIED** | The trailer is added **before** encryption and validated **after** decryption. |
| **Driver IOCTLs** | "No IOCTL needed" | **REJECTED / CORRECTED** | There are 5 IOCTLs on Windows (`0x228014`, etc.) for MAC and status; on Linux, they map to Netlink / standard socket `ioctl`. |
| **Port 17351** | Generic relay | **CONFIRMED / SPECIFIED** | Official `TcpRelay` enum (`0x51df00`), preceded by a formal RSA handshake. |
| **Teredo as transport** | Hypothesis based on ports | **CONFIRMED WITH PROOF** | Discovery of the class `RolClient::teredo::CTeredoThread` and decoding of the RFC 4380 addresses mapping to the same IPs as the peers. |
| **Direct P2P communication** | P2P assumption | **CONFIRMED WITH PROOF** | Packets #65..#599 and the simultaneous-open handshake in packets #696/#703/#704 prove real direct peer traffic. |

---

## 7. Pending Questions for Future Captures

1. **Dynamic switch to pure UDP between peers:**
   - Although the `UDP` enum exists (`0x51defc`) and the STUN tests are performed over UDP, the available PCAPs document continuous P2P data transfer over direct TCP and over Teredo/Relay tunnels. A capture containing intensive file transfer on networks without UDP blocking is recommended to audit whether there is a custom UDP protocol or whether UDP is restricted to STUN/Teredo.
2. **Compression algorithm:**
   - The export `ROLClient_SetCompression` is present in `RvROLClient.dll`, but all captured sessions operated with compression disabled. The exact algorithm (probably zlib or lzo) awaits a capture with compressed traffic.
