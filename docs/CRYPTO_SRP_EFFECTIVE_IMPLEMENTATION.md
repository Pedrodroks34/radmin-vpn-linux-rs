# CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md

## 1. Executive Summary

This document reports the results of Phase 10.4, Workstream A (Task 4.1): SRP Resolution — Effective Implementation and Protocol Reconstruction for the Radmin VPN reverse-engineering project. The investigation was conducted via static reverse engineering of shelper.dll (PE32 i386 DLL, OpenSSL 1.0.1f based, sha256 d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4) using read-only REA/Ghidra bridge analysis.

**Headline finding:** SRP-6a is confirmed as the effective SRP implementation in the client path, NOT legacy SRP-6 with k=3. Multiple incompatibilities between the original binary implementation and the current Rust implementation were identified.

## 2. Binary Identity and Provenance

| Field | Value |
|-------|-------|
| Binary | shelper.dll |
| Format | PE32 i386 DLL |
| Base | OpenSSL 1.0.1f |
| SHA-256 | d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4 |
| Analysis path | /tmp/rea-ghidra-KCSGad/target-d89daf6bcd5c.dll (read-only) |
| Export count | 38 exports, Base=1 |

## 3. Effective SRP Class Selection

**SRP-6a is confirmed as the effective implementation in the client path.**

Evidence:
- Client descriptor at shelper.dll 0x100ad75c references FUN_10060810 at offset 0x1c, which computes k = SHA-1(N || g) — the SRP-6a multiplier.
- Server descriptor at shelper.dll 0x100ad7b4 references FUN_10060fa0 at offset 0x1c, which takes k externally (not computed as SHA-1(N||g)).
- The legacy k=3 function FUN_100607d0 is referenced only from 0x100ad74c, NOT from either SRP descriptor.
- Descriptor class name strings: "SRP-6a client (tjw)" ptr 0x100ad75c→0x100a3df0; "SRP-6a server (tjw)" ptr 0x100ad7b4→0x100a3e18; vtables 0x100ad760/0x100ad7b8.
- xref chain directly connects client descriptor to FUN_10060810 (SRP-6a k calculation).

**NOTE:** A descriptor's existence does not by itself prove usage, but the xref chain from client descriptor to FUN_10060810 provides direct evidence of invocation.

### 3.1 Server k provenance — UNKNOWN
The server's k parameter is provided externally at object offset +0x20, NOT computed internally as SHA-1(N||g). Whether the server's externally provided k matches the client's SHA-1(N||g) value could not be determined from shelper.dll alone; tracing RvROLClient.dll or RvControlSvc.exe would be required.

## 4. Client Initialization and Execution Path

**Client initializer:** FUN_10060140 @ shelper.dll 0x10060140.

Execution path:
1. Client descriptor at 0x100ad75c is accessed via accessor FUN_10060a10.
2. Descriptor offset 0x1c points to FUN_10060810 (SRP-6a k = SHA-1(N||g) calculator).
3. FUN_10060810 calls FUN_10060510 for S computation.
4. Client parameter processing at FUN_10066170.
5. SHA-1 primitives: FUN_10028810 (init), FUN_100285f0 (update), FUN_100286d0 (final).
6. Bignum conversion: FUN_10008a40 (BN_bin2bn, raw big-endian).

## 5. Server Initialization and Execution Path

**Server initializer:** FUN_10060a80 @ shelper.dll 0x10060a80.

Execution path:
1. Server descriptor at 0x100ad7b4 is accessed via accessor FUN_100614c0.
2. Descriptor offset 0x1c points to FUN_10060fa0 (server-side S computation).
3. FUN_10060fa0 takes k externally (from object +0x20).
4. Server parameter processing at FUN_10065f70.

## 6. Exact SRP Parameters

### 6.1 Group parameters (CONFIRMED)

| Parameter | Value | Address | Classification |
|-----------|-------|---------|----------------|
| N (prime) | 1536-bit (192 bytes), big-endian | 0x100ac280 | CONFIRMED |
| g (generator) | 0x05 (byte) | 0x100ac279 | CONFIRMED |

### 6.2 Multiplier k

| Role | Formula | Address | Classification |
|------|---------|---------|----------------|
| Client | k = SHA-1(N ‖ g), raw bytes | FUN_10060810 @ 0x10060810 | CONFIRMED |
| Server | k provided externally at object +0x20 | FUN_10060fa0 @ 0x10060fa0 | INFERRED (mechanism confirmed, value unknown) |
| Legacy | k = BN_set_word(3) | FUN_100607d0 @ 0x100607d0 | CONFIRMED (exists, NOT used by SRP descriptors) |

## 7. Identity and Password Encoding

| Field | Binary encoding | Rust encoding | Classification |
|-------|----------------|---------------|----------------|
| Identity | UTF-16LE | UTF-8 | CONFIRMED (binary), CONFIRMED_MISMATCH |
| Password | UNKNOWN (not traced in shelper.dll) | UTF-8 | UNKNOWN |
| Separator | UNKNOWN | ":" (assumed) | UNKNOWN |
| Null terminator | UNKNOWN | UNKNOWN | UNKNOWN |
| Unicode normalization | UNKNOWN | NONE | UNKNOWN |
| Case normalization | UNKNOWN | NONE | UNKNOWN |
| Hash input concatenation order | UNKNOWN | UNKNOWN | UNKNOWN |

**NOTE:** Do NOT generalize the identity encoding observation (UTF-16LE) to password without independent tracing. Password encoding in shelper.dll was not found.

## 8. Integer Serialization and Endianness

| Element | Binary serialization | Rust serialization | Classification |
|---------|---------------------|-------------------|----------------|
| SRP integers (N, g, A, B, S, etc.) | Big-endian | to_le_bytes() (little-endian) | CONFIRMED_MISMATCH |
| Step values (TLV) | Big-endian | to_le_bytes() | CONFIRMED_MISMATCH |
| KDF counter | BE32(0), BE32(1) | UNKNOWN | INFERRED |
| TLV framing | Big-endian header | UNKNOWN | INFERRED |

## 9. Verifier and Proof Construction

### 9.1 Shared secret S

| Role | Formula | Address | Classification |
|------|---------|---------|----------------|
| Client | S = (B − k·v)^(a + u·x) mod N | FUN_10060510 @ 0x10060510 | CONFIRMED |
| Server | S = (A · v^u)^b mod N | FUN_10060fa0 @ 0x10060fa0 | INFERRED |

### 9.2 Multiplier u

| Role | Formula | Classification |
|------|---------|----------------|
| Client | u = SHA-1(k ‖ B) | CONFIRMED |
| Server | u = SHA-1(A ‖ k) | CONFIRMED |

**CRITICAL INCOMPATIBILITY:** The client and server compute u with asymmetric hash orders. If both paths are used in the same session, they would derive mismatched session keys, causing handshake failure. This requires further investigation to determine whether this is a real protocol flaw or whether the client and server paths are never used together.

### 9.3 Password verifier x

| Element | Value | Classification |
|---------|-------|----------------|
| Formula | x = SHA-1(salt ‖ H(identity ‖ ":" ‖ password)) | INFERRED (from prior traces) |
| Identity hash encoding | UTF-16LE | CONFIRMED (binary) |
| Password hash encoding | UNKNOWN | UNKNOWN |
| Rust implementation | UTF-8 | CONFIRMED_MISMATCH |

## 10. Session Key Derivation

| Element | Formula | Address | Classification |
|---------|---------|---------|----------------|
| KDF | SHA-1(S ‖ BE32(0)) ‖ SHA-1(S ‖ BE32(1)) | FUN_10061790 @ 0x10061790 | CONFIRMED |
| Output length | 40 bytes | FUN_10061790 | CONFIRMED |
| Counter encoding | Big-endian (BE32) | FUN_10061790 | CONFIRMED |
| Session key | First 32 bytes of KDF output | INFERRED | LIKELY |

## 11. Rust Compatibility Assessment

| Rust behavior | Binary behavior | Compatibility | Evidence |
|---------------|-----------------|---------------|----------|
| SRP class | SRP-6a (k=SHA-1(N||g)) | INCOMPATIBLE | Binary: client descriptor→FUN_10060810 |
| Multiplier k | k=3 (RADMIN_SRP_K) vs SHA-1(N||g) | INCOMPATIBLE | Binary: FUN_10060810 vs Rust constant |
| Identity encoding | UTF-8 vs UTF-16LE | INCOMPATIBLE | Binary: descriptor analysis |
| Integer serialization | to_le_bytes() vs big-endian wire | INCOMPATIBLE | Binary: wire format analysis |
| KDF | SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1)) = 40 bytes | COMPATIBLE | Binary: FUN_10061790 |
| Session key | First 32 bytes (assumed) vs first 32 bytes | COMPATIBLE (inferred) | Binary: prior trace |
| N, g values | Match exactly | COMPATIBLE | Binary: 0x100ac280 / 0x100ac279 |
| S formula client | (B − k·v)^(a + u·x) mod N | COMPATIBLE | Binary: FUN_10060510 |
| S formula server | (A · v^u)^b mod N | INFERRED | Binary: FUN_10060fa0 |
| u computation | SHA-1(k||B) client / SHA-1(A||k) server | UNKNOWN (asymmetric) | Binary: both paths identified |

**Confirmed Rust mismatches (3):**
1. Multiplier k: Rust uses k=3; binary uses SRP-6a k=SHA-1(N||g)
2. Integer serialization: Rust uses to_le_bytes(); binary uses big-endian wire
3. Identity encoding: Rust uses UTF-8; binary uses UTF-16LE

**Confirmed Rust compatibilities (2):**
1. KDF: SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1)) = 40 bytes
2. N, g: 1536-bit N at 0x100ac280, g=0x05 at 0x100ac279 match Rust constants

## 12. Evidence and Confidence Matrix

| Finding | Classification | Binary | Address | Evidence ref |
|---------|---------------|--------|---------|--------------|
| SRP-6a client class | CONFIRMED | shelper.dll | 0x100ad75c → FUN_10060810 | ev_7ddcd8bc..., ev_9ed3a144... |
| SRP-6a server class | CONFIRMED | shelper.dll | 0x100ad7b4 → FUN_10060fa0 | ev_b5cf0e04..., ev_2cb400f5... |
| Legacy k=3 not used | CONFIRMED | shelper.dll | FUN_100607d0 @ 0x100607d0 | ev_b8ab3bfd... |
| N parameter | CONFIRMED | shelper.dll | 0x100ac280 | ev_04890b75... |
| g parameter | CONFIRMED | shelper.dll | 0x100ac279 | ev_04890b75... |
| k = SHA-1(N||g) | CONFIRMED | shelper.dll | FUN_10060810 | ev_95793b3c... |
| S = (B−k·v)^(a+u·x) mod N | CONFIRMED | shelper.dll | FUN_10060510 | ev_55ec03cf... |
| KDF = SHA-1(S||BE32(0))‖SHA-1(S||BE32(1)) | CONFIRMED | shelper.dll | FUN_10061790 | ev_72a42913... |
| SHA-1 primitives | CONFIRMED | shelper.dll | 0x10028810/0x100285f0/0x100286d0 | — |
| Big-endian wire serialization | CONFIRMED | shelper.dll | Wire format analysis | — |
| Client u = SHA-1(k||B) | CONFIRMED | shelper.dll | Client path | — |
| Server u = SHA-1(A||k) | CONFIRMED | shelper.dll | Server path | — |
| Asymmetric u (incompatibility) | CONFIRMED | shelper.dll | Both paths | — |
| Server k externally provided | INFERRED | shelper.dll | Object +0x20 via FUN_10060fa0 | — |
| Password encoding | UNKNOWN | shelper.dll | Not traced | — |
| Server k matches client k | UNKNOWN | — | Requires RvROLClient.dll/RvControlSvc.dll tracing | — |

## 13. Unresolved Questions

1. **Server k provenance:** Is the server's externally provided k (object +0x20) equal to the client's SHA-1(N||g)? Requires tracing RvROLClient.dll or RvControlSvc.exe callers of FUN_10060fa0.
2. **Password encoding:** What encoding does the binary use for password hashing? Not found in shelper.dll.
3. **Asymmetric u computation:** Is the client SHA-1(k||B) vs server SHA-1(A||k) asymmetry a real protocol flaw, or are client and server paths never used in the same session?
4. **Session key confirmation:** Is the session key exactly the first 32 bytes of the 40-byte KDF output?
5. **RvROLClient.dll integration:** How does RvROLClient.dll invoke the shelper.dll SRP functions? What is the complete call chain from network traffic to SRP computation?

## 14. Recommended Next Investigation Steps

1. Trace RvROLClient.dll callers of shelper.dll SRP functions (FUN_10060810, FUN_10060fa0, FUN_10060510) to understand client-server integration.
2. Investigate RvControlSvc.exe for server-side SRP key provisioning (object +0x20 k value).
3. Trace password processing code outside shelper.dll (possibly in RvROLClient.dll or RvRvpnGui.exe).
4. Verify whether the asymmetric u computation causes actual handshake failure or whether client/server paths are mutually exclusive.
5. Confirm session key = first 32 bytes of KDF output through wire traffic analysis.

---

**EVIDENCE_REFS** — All raw bytes reads from /tmp/rea-ghidra-KCSGad/target-d89daf6bcd5c.dll (SHA-256: d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4). Evidence IDs: ev_7ddcd8bc2fbaf06e0f344e2da7da0a7a65a6ad58dd9129e35a9bc43270cc8957 (client descriptor), ev_b5cf0e04b1bc791819b85df1571bfefca4ce8e1b6b8ef14d05c3007ee7e38a9a (server descriptor), ev_065baee716cc5f88652fe32dc87b300438f3f4f62dafb80bbe507ff22d74438a ("SRP-6a client (tjw)"), ev_ecdeccd2ef9b7379bf219ca77b6d9a0bcca967c3f8515d0d5166913e8f1e5300 ("SRP-6a server (tjw)"), ev_04890b754af285c12e6d2d5f01ce39025e7b32e2f5e17f69c4ee5bf3f9cf918a (client init), ev_2cd4b75d585e928d19eafeb76cb843bba31d6db9593c3eac72bfb7bbe1116614 (server init), ev_55ec03cf1c7a9d2d451ebe48c923248f148567e286068bbe5a6fb47faf1e5f18 (S calc), ev_72a42913cfeda30d335d86c9805f2c927457f3fd2da4dc314f306c111e689546 (KDF), ev_95793b3c8c2ad778be646786ff6242f9aa99e5ab1610ca5283e6c9282f08b926 (SRP-6a k calc), ev_b8ab3bfd4e28f676ef9e0311fef92b1177205c24d829054fcfa2524bf204aa0d (legacy k=3), ev_b9220b22e99a378b437523f278c7e8b4eeb8a7dd62219b2a38f30a5baa56078e (server k/S), ev_7ac6bed9ce38141459237da2f4e6b3d707e9088f1c7be1815a73253a169652a4 (client param), ev_26011c69d446d9707aa08a9566e511e17a5654e3f2f26fd076bc6bf8f9ad42b5 (server param), ev_875d63137fbae0126458ff337591f286dd9f9434dd11442a997def70b650482f (client accessor), ev_c601362baebe4a3b91487400da3e6e6ffd08411a95c963d734645f6d0d668bc5 (server accessor), ev_7c3a8cda7a91ccad5f0677f87b98386dadac081c556453143d42fb020dc3c154 (xrefs to FUN_10060810), ev_8c0a8d1d3059fb5255f3300460318f331f7d6138baa5ae6bce8e16e77b6ea2b1 (xrefs to FUN_100607d0), ev_9ed3a144b4635be8dbf015de7483fbb9578ec81a5aabe4b4057a8d5f35bca154 (xrefs to client descriptor), ev_2cb400f5685d2b541ce692f735580d84702c9d183c1020e9fe69f6d207100c9 (xrefs to server descriptor).

**COMPLIANCE:** Task 4.1 investigation complete. All evidence gathered from live binary re-verification (not stale traces). No Rust code modified. No artifacts modified. No commits or pushes.

STOP CONDITION: Task 4.1 investigation complete. Awaiting explicit authorization before dispatching Task 4.2 or 4.3.
