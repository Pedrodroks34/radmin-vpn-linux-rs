# Unresolved Questions and Known Limitations — After Phase 1 (`PHASE_1_UNRESOLVED.md`)

> **Note on the item resolved in Phase 1:**  
> The question raised in the previous audit about how the **64 bytes (`0x40`)** returned by `SHelper_RSession_GetKey` (`shelper.dll!0x1006ba80` -> `0x1006a270`) are converted into the **32-byte (`0x20`)** AES-256 key of `SHelper_CChannel` was **100% resolved** by disassembly of `RvROLClient.dll!0x100df250` (`CChannelWrapper::Create`), `0x100df470` (`CChannelWrapper::SetKey`), `0x10096f0d..0x10096f21` and `0x100969de..0x10096a16`: the official client checks `key_len >= 0x20` and passes `&key_buf[0..32]` to both `SHelper_CChannel_SetKeyEnc` (`0x10062e00`) and `SHelper_CChannel_SetKeyDec` (`0x10062d60`).

---

## 1. `SHelper_*` State Machine of the Central Connection on Port `17301` (`radmin_17301.pcap` #32..#50)

- **What is undefined**:
  - The exact internal format and the cryptographic operations of each of the intermediate packets (`192B`, `32B`, `256B`, `224B`, `224B`, `48B`, `48B`) exchanged after the version frame `[03 00 00 00]` on TCP port `17301`.
- **What has already been investigated**:
  - We identified in `RvROLClient.dll!0x100dc6e0` and `0x1003dd40..0x1003f530` that `shelper.dll` exports two distinct families:
    1. `SHelper_RSession_*` (`0x1006b860` / `0x1006a2b0`: `256B` `C->S` RSA PKCS#1 v1.5 with `76B` plaintext -> `4B` `S->C` token), used by `RvROLClient.dll!0x10096660..0x10096ff2` and fully implemented in this Phase 1.
    2. `SHelper_*` (`0x1006ab90` `SHelper_CreateClient`, `0x1006ad20` `SHelper_CreateServer`, `0x1006b1e0` `SHelper_GetNextBuffer`, `0x1006b010` `SHelper_GetKey`, `0x1006b1d0` `SHelper_GetNetworkProtocolVersion = 3`), used by `RvROLClient.dll!0x1003eb30` on port `17301`.
  - We correlated the packets of `radmin_17301.pcap` by separating the two concurrent TCP flows (`49494` and `49493`), showing that packet #44 (`S->C`, `4B` `03000000` on `49493`), #35/#46 (`S->C`, `192B`) and #39/#48 (`S->C`, `256B`) belong to the `SHelper_*` machine (`0x1006b1e0`) and not to the `SHelper_RSession_*` machine (`0x1006a2b0`).
- **What evidence is missing**:
  - The complete disassembly of the internal subroutines called by `shelper.dll!0x1006b1e0` (in the range `0x10066800..0x10069b00`) and the extraction of the central server's public-key parameters passed to `SHelper_CreateClient` (`0x1006ab90`).
- **What additional analysis would resolve the question**:
  - Statically disassemble `shelper.dll!0x10066800..0x10069b00` and `RvROLClient.dll!0x1003eb30..0x1003f530` to document each state of `SHelper_GetNextBuffer` (`0x1006b1e0`) and extract the central server's RSA modulus from the `.rdata` segment of `RvROLClient.dll` / `RvControlSvc.exe`.

---

## 2. Meaning of the 3 Header DWORDs (`client_params: [u32; 3]`) and of the `server_token` (`u32`) in `SHelper_RSession`

- **What is undefined**:
  - The higher-level semantic meaning of the 3 DWORDs (`[esi+0x04..+0x0c]`, bytes `0..12` of the 76-byte RSA plaintext) passed to `SHelper_RSession_CreateClient`, and of the 4-byte `server_token` passed to `SHelper_RSession_CreateServer`.
- **What has already been investigated**:
  - In `shelper.dll!0x1006b860` (`0x1006a690`), `0x1006a512`, `0x1006a30c`, `0x1006a4cc`, `0x1006bbb0` and `0x1006bc30`, we confirmed that `shelper.dll` treats these values as opaque 32-bit integers carried inside the handshake and made available to the remote peer after `is_established == 1`.
  - In `RvROLClient.dll!0x10096bf0..0x10097060`, we verified that after `RSession::GetNextBuffer` completes, the server calls `0x100dd090` (`GetClientDataOnServer`) and validates the value in `0x100dc890`.
- **What evidence is missing**:
  - Identify the exact values passed by the callers of `RvROLClient.dll!0x10096660` and validated in `0x100dc890`.
- **What additional analysis would resolve the question**:
  - Disassemble `RvROLClient.dll!0x10096660..0x10096800` and `0x100dc890` to map the fields of the calling object that feed `d0, d1, d2` and `server_token`.

---

## 3. Decrypted Content of the Post-Handshake Control Packets (Phases 2 and 3)

- **What is undefined**:
  - The plaintext payloads of the encrypted packets exchanged after activation of `SHelper_CChannel` in the captures `radmin_17301.pcap`, `radmin_vm.pcap` and `radmin_vm2.pcap`.
- **What has already been investigated**:
  - We established that the AES-256 key of each session is generated dynamically via `RAND_bytes` (`0x10063530`) at the time of the handshake and encrypted with RSA-2048 PKCS#1 v1.5.
- **What evidence is missing**:
  - Because the historical PCAPs did not come with a memory dump of the ephemeral keys of those sessions, the post-handshake packets in the PCAPs cannot be decrypted offline without the server's private key or the buffer of `SHelper_GetKey` / `SHelper_RSession_GetKey`.
- **What additional analysis would resolve the question**:
  - For Phases 2 and 3, combine the static analysis of the TLV serializers/parsers in `RvROLClient.dll` (`0x10029aa0`, `0x1002b2c0`) with dynamic instrumentation (Frida/x64dbg at `shelper.dll!0x10063000` `CChannel_Encrypt` and `0x100630f0` `CChannel_Decrypt`), if a Windows VM with the official client is available.
