# CRYPTO_PHASE_10_15_STATIC_PASSWORD_ENCODING_RECONSTRUCTION.md

# Phase 10.15 — Static Caller-Side Password Encoding Reconstruction

## 1. Executive Summary

This phase attempted to resolve the remaining P0 password-encoding blocker using
static binary analysis only, without Windows VM execution.

**Result: Password encoding remains `UNKNOWN`.**

No Rust source code was modified.

Static analysis confirmed:
- `shelper.dll` receives the password as raw `(ptr, len)` with **no transformation**
  inside the helper (instruction-level evidence at `0x10060340`/`0x10060c80`).
- Both consumer binaries import Unicode conversion APIs (`MultiByteToWideChar`,
  `WideCharToMultiByte`), but no conversion call was traced to the SRP password path.
- The caller-side encoding cannot be determined from the available binaries.

Per the phase policy ("if static evidence is insufficient, preserve UNKNOWN"),
no change to Rust's UTF-8 password handling was made.

---

## 2. Initial Git State

| Item | Value |
|---|---|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| Working tree | 3 tracked modified (Phase 10.5 + 10.14 identity) + ~38 untracked |
| Commit / push | None |

---

## 3. Available Artifact Inventory

| Artifact | Path | SHA-256 / Status |
|---|---|---|
| `shelper.dll` | `claude-handoff/binaries/radmin_ext/shelper.dll` | `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4` ✓ |
| `RvROLClient.dll` | `claude-handoff/binaries/radmin_ext/RvROLClient.dll` | `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177` ✓ |
| `RvControlSvc.exe` | `claude-handoff/binaries/radmin_ext/RvControlSvc.exe` | `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` ✓ |
| `Radmin.exe` (installer) | `claude-handoff/binaries/radmin_ext/Radmin.exe` | `5fc07f57d1d1a46bf080dd833511d5166235ffc2c00812faf46d99f008384d21` ✓ |
| PCAPs | `pcaps/radmin_17301.pcap`, `pcaps/radmin_vm2.pcap` | Available (see §12) |
| Ghidra projects | `/tmp/ghidra_work_rol2/`, `/tmp/rea-ghidra-KCSGad/` | Existing |

All hashes match the historical values. The VM (`win10`, KVM/virt-manager) is
**not available** (confirmed: no `qemu-kvm`, `virt-manager`, `x64dbg`, or `windbg`
in PATH).

---

## 4. Binary Provenance and Hashes

| Binary | Format | Size | SHA-256 |
|--------|--------|------|---------|
| `shelper.dll` | PE32 i386 DLL, ImageBase 0x10000000 | — | `d89daf6b…` ✓ |
| `RvROLClient.dll` | PE32 i386 DLL | — | `6ba7dfec…` ✓ |
| `RvControlSvc.exe` | PE32 i386 EXE | — | `546efad9…` ✓ |

---

## 5. Functions and Callers Identified

### 5.1 `shelper.dll` SRP password functions

| Function | VA | Role | Verified |
|---|---|---|---|
| Client x computation | `0x10060340` | `x = SHA-1(salt ‖ SHA-1(I ‖ ":" ‖ P))` | YES (objdump) |
| Server x computation | `0x10060c80` | Same formula, server side | YES (objdump) |

Both functions are **structurally identical**:
- Identity from `obj+0x8` as `{ptr, len}` (UTF-16LE, confirmed Phase 10.14)
- Separator `":"` (0x3a) at `0x10094218`, length 1
- Password from caller stack `[ebp+16]` with length `[ebp+12]`
- Salt from `obj+0x14` as `{ptr, len}`
- Two SHA-1 stages, no password transformation

### 5.2 `shelper.dll` export functions

| Export | VA | Purpose |
|---|---|---|
| `SHelper_CreateClient` | `0x1006ab90` | SRP client object creation |
| `SHelper_CreateServer` | `0x1006ac80` | SRP server object creation |
| `SHelper_SetUserParams` | `0x1006bbe0` | Set user parameters (incl. password) |

These are the entry points that receive credentials from the caller.

### 5.3 Caller search results

**No direct calls to `0x10060340` or `0x10060c80` were found** in any binary.
These functions are reached via:
- Virtual function tables in the SRP object
- Function pointer dispatch from `SHelper_CreateClient`/`SHelper_CreateServer`
- Internal `shelper.dll` call chain

The password enters `shelper.dll` through the export functions above. The
caller is in `RvROLClient.dll` or `RvControlSvc.exe`.

---

## 6. Call Graph

```
RvROLClient.dll / RvControlSvc.exe (caller)
    │
    ├─ UI layer collects password (encoding: UNKNOWN)
    │      │
    │      └─ ??? conversion ??? (NOT TRACED)
    │              │
    │              └─ password bytes (encoding: UNKNOWN)
    │                      │
    │                      └─► SHelper_CreateClient / SHelper_CreateServer / SHelper_SetUserParams
    │                              │
    │                              └─► shelper.dll SRP object
    │                                      │
    │                                      └─► 0x10060340 / 0x10060c80 (x computation)
    │                                              │
    │                                              └─► SHA1_Update(password_ptr, password_len)
    │                                                      (RAW, NO TRANSFORM)
```

The gap is the `??? conversion ???` step. Static analysis cannot determine
whether the password is converted via `MultiByteToWideChar` or passed directly.

---

## 7. Caller Matrix

| Caller | Call mechanism | Password source | Transformations | Pointer argument | Length argument | Encoding conclusion |
|---|---|---|---|---|---|---|
| `RvROLClient.dll` (via `SHelper_CreateClient`) | Indirect (function pointer table) | Not traced | NOT TRACED | `[ebp+16]` in shelper | `[ebp+12]` in shelper | **UNKNOWN** |
| `RvControlSvc.exe` (via `SHelper_CreateServer`) | Indirect | Not traced | NOT TRACED | `[ebp+16]` | `[ebp+12]` | **UNKNOWN** |
| `shelper.dll` internal | Vtable dispatch | `obj+0x8` (identity), caller stack (password) | None (verbatim) | Direct | Direct | **Raw bytes, encoding TBD by caller** |

---

## 8. Unicode Conversion Evidence

### 8.1 Imports found

Both consumer binaries import Unicode conversion APIs:

| API | RvROLClient.dll | RvControlSvc.exe |
|---|---|---|
| `MultiByteToWideChar` | YES (0x10111108) | YES (0x1011722c) |
| `WideCharToMultiByte` | YES (0x10111104) | YES (0x101171d8) |
| `LCMapStringW` | YES | YES |
| `GetACP` | YES | YES |

### 8.2 Call sites in RvROLClient.dll

**MultiByteToWideChar** (converts ANSI/UTF-8 → UTF-16):
- `0x100a5b63` — in a string buffer management function
- `0x100a5b9f` — same function
- `0x100a5daa`, `0x100a5dd8` — additional sites
- `0x100ff5ed` — elsewhere

**WideCharToMultiByte** (converts UTF-16 → ANSI/UTF-8):
- `0x100a625c` — in a file/string handling function
- `0x100a62df` — same function
- `0x100dc223`, `0x100dc270` — SRP-adjacent? (not confirmed)
- `0x100e25da`, `0x100e2617`, `0x100ff6a5` — various

### 8.3 Critical caveat

The presence of conversion APIs in the import table (and even call sites in the
binary) **does not prove** that the password path uses them. The observed call
sites are in:
- String buffer management (0x100a5b63 context)
- File operation handling (0x100a625c context)
- General utility functions

**None of the observed conversion call sites was traced to the SRP password
path.** The conversion may serve UI display, file paths, logging, or other
non-password purposes.

### 8.4 Required distinction

| Representation | Status |
|---|---|
| UI input (what user types) | UNKNOWN |
| Internal application string | UNKNOWN |
| Password buffer passed to `shelper.dll` | UNKNOWN (caller-side, not traced) |
| Password bytes consumed by SHA-1 | RAW pointer from caller, encoding TBD |

---

## 9. `shelper.dll` Password Data Flow

### 9.1 Instruction-level trace (0x10060340)

```asm
0x10060340: push %ebp
0x10060341: mov %esp,%ebp
0x10060343: sub $0x78,%esp
...
0x10060351: mov 0x8(%ebp),%esi        ; this (SRP object)
0x10060355: mov 0xc(%ebp),%edi        ; password_len
0x10060358: lea -0x78(%ebp),%eax      ; SHA1 context
0x1006035c: call 0x10028810           ; SHA1_Init
0x10060361: mov 0x8(%esi),%eax        ; identity ptr (obj+0x8)
0x10060364: mov 0x4(%eax),%ecx        ; identity len
0x10060367: mov (%eax),%edx           ; identity data
0x1006036f: call 0x100285f0           ; SHA1_Update(identity)
0x10060374: push $0x1                 ; separator len = 1
0x10060379: push $0x10094218          ; separator = ":" (0x3a)
0x1006037f: call 0x100285f0           ; SHA1_Update(":")
0x10060384: mov 0x10(%ebp),%edx       ; password ptr (from caller)
0x10060387: push %edx
0x1006038b: push %edi                 ; password_len
0x1006038d: call 0x100285f0           ; SHA1_Update(password) ← RAW
```

**Key observations:**
- Password pointer read directly from stack `[ebp+0x10]` (caller argument)
- Password length from `[ebp+0xc]` (caller argument)
- **No copy, no transformation, no encoding conversion** before SHA1_Update
- Password bytes are hashed **exactly as received** from the caller

### 9.2 What this proves

The `shelper.dll` layer is **encoding-agnostic**. It hashes whatever bytes the
caller provides. The encoding decision is made entirely in the caller, before
`SHelper_CreateClient`/`SHelper_CreateServer`/`SHelper_SetUserParams` is invoked.

---

## 10. SHA-1 Consumption Path

The password bytes reach SHA-1 in exactly one operation:

```
SHA1_Update(ctx, password_ptr, password_len)
    ↑ from [ebp+0x10]     ↑ from [ebp+0xc]
```

No intermediate buffer, no null terminator handling, no byte swapping.
The length is used as-is. The pointer is dereferenced as-is.

---

## 11. Comparison of the Two SRP Paths

| Aspect | Client (0x10060340) | Server (0x10060c80) |
|---|---|---|
| Structure | Identical | Identical |
| Args | (this, password_len, password_ptr) | Same |
| Identity source | `obj+0x8` | `obj+0x8` |
| Password source | Caller stack | Caller stack |
| SHA-1 stages | 2 (inner + outer) | 2 |
| Transformation | None | None |

**Conclusion:** Both paths are symmetric variants. The password handling is
identical. If the client uses encoding X, the server must also use encoding X
(or the handshake would fail between the official client and server).

---

## 12. PCAP Evidence

Available PCAPs:
- `pcaps/radmin_17301.pcap` — control port traffic
- `pcaps/radmin_vm2.pcap` — peer traffic

**PCAPs cannot reveal password encoding directly.** The SRP protocol transmits
derived values (`A`, `B`, `M1`, `M2`, `S`), not the password itself. Without
known plaintext passwords for the captured sessions, the PCAP cannot be used
to reverse-engineer the encoding.

No correlation between PCAP contents and password encoding was possible.

---

## 13. Independent Candidate Calculations

The following are **candidate** calculations, not confirmed official vectors.
All use the known identity `A` (UTF-16LE: `41 00`) and salt from the test
vector in Phase 10.14.

### 13.1 UTF-8 password candidate

Password: `"p"` → UTF-8 bytes: `70`

```
Inner input:  41 00 3a 70                    (identity_LE + ":" + password_UTF8)
Inner SHA1:   [SHA-1 digest]
Outer input:  [salt] || [inner digest]
Outer SHA1:   x (final)
```

### 13.2 UTF-16LE password candidate

Password: `"p"` → UTF-16LE bytes: `70 00`

```
Inner input:  41 00 3a 70 00                 (identity_LE + ":" + password_LE)
Inner SHA1:   [different digest]
Outer input:  [salt] || [inner digest]
Outer SHA1:   x (different final value)
```

### 13.3 Test vectors (synthetic, not official)

| Password | UTF-8 hex | UTF-16LE hex | UTF-16BE hex |
|---|---|---|---|
| `p` | `70` | `70 00` | `00 70` |
| `päss` | `70 c3 a4 73 73` | `70 00 e4 00 73 00 73 00` | `00 70 00 e4 00 73 00 73` |
| `😀` | `f0 9f 98 80` | `3d d8 00 de` | `d8 3d de 00` |

These are **synthetic test inputs**, not official Windows vectors. They exist
only to specify the expected byte sequences for future dynamic verification.

---

## 14. Final Password Encoding Classification

**Classification: `UNKNOWN`**

Rationale:
1. `shelper.dll` receives raw bytes; encoding is determined by the caller.
2. The caller (`RvROLClient.dll` / `RvControlSvc.exe`) was not traced to the
   specific `SHelper_CreateClient` call site with password arguments.
3. Unicode conversion APIs exist in both binaries but were not connected to
   the SRP password path via call-graph tracing.
4. No dynamic execution is available to capture the actual bytes.

**What remains unknown:**
- Whether the password is converted via `MultiByteToWideChar` (→ UTF-16LE)
- Whether it is passed as-is (→ UTF-8)
- Whether the caller uses a different path entirely

---

## 15. Rust Changes

**None.** Per the phase policy, no password encoding change was made because
the static evidence does not meet the CONFIRMED threshold.

Current Rust behavior (unchanged):
```rust
// src/session/control_handshake.rs:300
cred_buf.extend_from_slice(password.as_bytes());  // UTF-8
```

This may be incorrect if the Windows caller uses UTF-16LE, but changing it
without proof would be speculation.

---

## 16. Test Results

```
$ cargo test
  Finished `test` profile [unoptimized + debuginfo]
  152 tests passed, 0 failed, 1 ignored (pre-existing: requires /dev/net/tun)
  5 integration tests passed, 0 failed
```

All existing tests pass. No tests were modified in this phase.

---

## 17. Limitations Caused by Unavailable Windows Runtime

The following could not be determined without dynamic analysis:

1. **Password encoding** — the sole remaining P0 blocker from Phase 10.14
2. **RvControlSvc.exe AES mapping** — the control service consumer was not traced
3. **Identity UTF-16LE confirmation** — STRONGLY_SUPPORTED but not CONFIRMED
   (one breakpoint on 0x10060340 would confirm)

The VM environment (`win10`, KVM/virt-manager, 192.168.122.77) is no longer
available. Reconstructing it is explicitly out of scope for this phase.

---

## 18. Remaining Evidence Gaps

| Gap | Impact | Resolution path |
|---|---|---|
| Password encoding | P0 — blocks interoperability | Dynamic breakpoint on `0x10060340` |
| AES same-pointer in RvControlSvc.exe | P1 — affects server-side | Breakpoint on `0x1006a630` in control svc process |
| Identity LE confirmation | P1 — upgrade to CONFIRMED | Breakpoint on `0x10060340` + `0x10060361` |
| RSA key provenance | P1 — RSession unimplementable | Search `.rdata` for key blobs |

---

## 19. Updated Compatibility Matrix

| Component | Evidence status | Rust status | Notes |
|---|---|---|---|
| SRP N and g | CONFIRMED | Compatible | No change |
| SRP k | CONFIRMED | Compatible | No change |
| SRP u | CONFIRMED | Compatible | No change |
| SRP identity hash encoding | STRONGLY_SUPPORTED (UTF-16LE) | **Corrected** (Phase 10.14) | `encode_identity_le()` |
| Identity wire encoding | STRONGLY_SUPPORTED (UTF-16BE) | Compatible | `encode_identity()` unchanged |
| Password encoding | **UNKNOWN** | Unknown (UTF-8) | Dynamic analysis required |
| SRP S and K | CONFIRMED | Compatible | No change |
| AES key split | RESOLVED_STRONGLY_SUPPORTED | Compatible | Same 32B both directions |
| M1/M2 | PARTIAL | Existing impl | No scope expansion |
| RSA key provenance | UNKNOWN | Existing impl | No scope expansion |

---

## 20. Recommended Next Phase

**Dynamic analysis session** with user authorization to:
1. Start the Windows VM (`win10`)
2. Attach debugger to the client process
3. Set breakpoint on `shelper.dll!0x10060340`
4. Initiate SRP handshake with controlled credentials
5. Capture password buffer bytes

A single session resolves the password encoding (P0) and confirms identity
(P1). The remaining remediation is a minimal change in `compute_srp_x()`.

---

## 21. Integrity Confirmation

- **No Rust source code was modified** during Phase 10.15.
- **No historical documentation was overwritten.**
- **No binaries, PCAPs, or Ghidra databases were modified** (read-only objdump analysis only).
- **No commits, pushes, branches, or pull requests were created.**
- **No VM was started, no process was attached, no live capture was performed.**
- **HEAD remains at `95e304e0855a6faf4eece932484cb00e36620a6e`.**
- **Deliverables created:**
  - `docs/CRYPTO_PHASE_10_15_STATIC_PASSWORD_ENCODING_RECONSTRUCTION.md` (this file)
  - `docs/CRYPTO_PHASE_10_15_STATIC_BYTE_VECTORS.json`
