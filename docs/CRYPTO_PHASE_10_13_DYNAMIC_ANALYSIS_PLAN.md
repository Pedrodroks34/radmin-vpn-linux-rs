# CRYPTO_PHASE_10_13_DYNAMIC_ANALYSIS_PLAN.md

# Dynamic Analysis Plan — Unresolved P0 Blockers (Phase 10.13)

## 1. Password Encoding (OQ-2) — REQUIRES_DYNAMIC_ANALYSIS

### 1.1 Objective

Determine the exact byte encoding of the password supplied to the SRP `x` hash.

### 1.2 Breakpoint plan

| Item | Value |
|---|---|
| Module | `shelper.dll` |
| Function | `0x10060340` (client x computation) |
| Breakpoint location | Function entry (`0x10060340`) |
| Calling convention | `__stdcall`-ish; args at `[ebp+8]` (this), `[ebp+12]` (password_len), `[ebp+16]` (password_ptr) |
| Also check | `0x10060c80` (server x computation) |
| VM | `win10` (historical: 192.168.122.77, KVM/virt-manager) |
| Tool | x64dbg or WinDbg; install breakpoint `bp shelper.10060340` |

### 1.3 Memory inspection

At the breakpoint, read the password buffer:

| Register/Offset | Content |
|---|---|
| `EDX` at `0x10060384` | Password data pointer |
| `EDI` at `0x10060355` | Password length (bytes) |
| `[EDI]` dereference | Actual password bytes |

Capture: Dump `EDI` bytes starting at `EDX`.

### 1.4 Test credentials

Use a controlled test:

- Username: `"A"` (identity)
- Password: `"p"` (single ASCII)
- Expected byte sequences:
  - UTF-8: `70`
  - UTF-16LE: `70 00`
  - UTF-16BE: `00 70`
  - ANSI: `70`

A single ASCII character distinguishes all encodings by length (1 vs 2 bytes)
and content.

### 1.5 Expected observations

| Observation | Interpretation |
|---|---|
| `70` (len=1) | UTF-8 or ANSI |
| `70 00` (len=2) | UTF-16LE |
| `00 70` (len=2) | UTF-16BE |
| `70 00 00 00` (len=4) | UTF-32LE (unlikely) |
| Longer buffer with null terminator | Null-terminated string (unlikely given `0x10060384` uses explicit len) |

### 1.6 Success criteria

The encoding is confirmed if the captured bytes match exactly one encoding from
the table above. A non-ASCII test (e.g., "é") would further confirm by checking
for the multi-byte UTF-8 sequence `C3 A9` vs UTF-16LE `E9 00` vs UTF-16BE `00 E9`.

### 1.7 Call stack

Record the full call stack to identify the caller module and function, which
traces the password provenance chain back to the application input.

---

## 2. Identity Hash Encoding Confirmation (OQ-3) — RESOLVED_STRONGLY_SUPPORTED

This blocker is resolved to STRONGLY_SUPPORTED based on:
1. Binary reads `obj+0x8` raw for hash (no swap at `0x10060361`).
2. Binary byte-swaps a **copy** for wire (`0x100667b0`).
3. Windows native string format is UTF-16LE.

### 2.1 Optional confirmation breakpoint

Same breakpoint as password (`0x10060340`). At `0x10060361`, read `obj+0x8`:

| Offset | Content |
|---|---|
| `EAX` after `mov 0x8(%esi),%eax` | Identity struct pointer |
| `[EAX]` | Data pointer |
| `[EAX+4]` | Length |

Test identity: `"A"` → expected `41 00` (LE) or `00 41` (BE).

### 2.2 Success criteria

If the buffer contains `41 00`, identity hash = UTF-16LE is CONFIRMED.
If `00 41`, identity hash = UTF-16BE is CONFIRMED (and the STRONGLY_SUPPORTED
conclusion was wrong).

---

## 3. AES Mapping Confirmation (OQ-1) — RESOLVED_STRONGLY_SUPPORTED

This blocker is resolved to STRONGLY_SUPPORTED based on two independent call paths
in `RvROLClient.dll` both passing the same buffer pointer for enc and dec.

### 3.1 Optional confirmation breakpoint

| Item | Value |
|---|---|
| Module | `RvROLClient.dll` |
| Function | `0x100df250` (SetKeyPair wrapper) |
| Breakpoint | Function entry |

### 3.2 Memory inspection

At the breakpoint, read `0xc(%ebp)` and `0x14(%ebp)` (key1_ptr and key2_ptr).
Compare the two pointers. If they are equal, same-key is CONFIRMED.
If they differ by 0x20, the halves are `buf[0..32]` and `buf[32..64]`.

### 3.3 Success criteria

If both pointers are identical, the STRONGLY_SUPPORTED conclusion is CONFIRMED.
If they differ, the mapping is `FIRST_32_ENC_SECOND_32_DEC` and Rust is WRONG.

### 3.4 RvControlSvc.exe gap

The control service (`FUN_00442290`) resolves GetKey but its consumer was not
traced. A breakpoint on `shelper.dll!0x1006a630` in the control service process
would confirm whether it also uses same-pointer or different halves.

---

## 4. Execution Context (All Experiments)

### 4.1 VM requirements

- Windows 10 VM with Radmin VPN installed
- Ability to initiate a connection to a test server
- Debugger attached to the client process (`RvControlSvc.exe` or `RvROLClient.dll` host)

### 4.2 Thread identity

SRP handshake typically runs on a single worker thread. Record the thread ID at
each breakpoint to ensure the same session is being observed.

### 4.3 Lifecycle stage

SRP x computation occurs during the initial authentication phase, before any
encrypted communication. AES key installation occurs after the RSession handshake
completes. These are separate sessions/phases.

---

## 5. Summary of Required Dynamic Experiments

| Experiment | Blocker | Breakpoint | Success = | Priority |
|---|---|---|---|---|
| EXP-1 | Password encoding | `shelper.dll!0x10060340` | Password bytes match one encoding | P0 |
| EXP-2 | Identity LE confirmation | `shelper.dll!0x10060340` + `0x10060361` | `41 00` vs `00 41` | P1 |
| EXP-3 | AES same-pointer | `RvROLClient.dll!0x100df250` | Both ptr args identical | P1 |
| EXP-4 | RvControlSvc.exe AES | `shelper.dll!0x1006a630` in control svc process | Pointer comparison | P1 |

**Minimum dynamic session needed:** A single debugger session with breakpoints on
`0x10060340` (password + identity) would resolve both P0 remaining items.
