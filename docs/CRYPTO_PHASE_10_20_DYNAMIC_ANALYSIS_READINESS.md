# CRYPTO_PHASE_10_20_DYNAMIC_ANALYSIS_READINESS.md

# Phase 10.20 — Dynamic Analysis Readiness & Instrumentation Plan

## 1. Executive Summary

This phase prepares a precise, reproducible dynamic-analysis procedure for the
remaining Radmin VPN interoperability blockers.

**No dynamic execution was performed.** No Windows VM, QEMU, debugger, or live
process was available. All breakpoints and procedures are specified but not
executed.

Three workstreams are planned:
- **A — Password encoding:** Breakpoint on `shelper.dll!0x10060340` to capture
  password pointer and length.
- **B — M2 accumulator:** Breakpoint on `shelper.dll!0x100609a0` to capture
  SHA-1 context states and input bytes.
- **C — RSA constructor:** Breakpoint on `shelper.dll!0x1006b4e0` to capture
  key components.

One instrumented session is sufficient to resolve all three P0/P1 blockers.

---

## 2. Repository State

| Item | Value |
|---|---|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| Working tree | 3 tracked modified + 71 untracked |
| Commit / push | None |

---

## 3. Current Infrastructure Limitations

The current environment does **not** provide:

| Resource | Available |
|---|---|
| Windows VM | NO — no QEMU/KVM, no virt-manager |
| Windows debugger | NO — no x64dbg, no WinDbg |
| Live Radmin process | NO |
| Runtime instrumentation | NO |
| Linux GDB | YES (but no Windows target) |

**No breakpoint was installed or tested. No runtime data was captured.**

The phase is strictly preparation. The plan is ready to execute when a
Windows environment becomes available.

---

## 4. Password Breakpoint Plan

### 4.1 Target

| Item | Value |
|---|---|
| Module | `shelper.dll` |
| Function | `0x10060340` (client x computation) |
| Also check | `0x10060c80` (server x computation) |
| Breakpoint | Function entry |

### 4.2 Calling convention

Standard x86 __stdcall. Arguments on stack:

| Offset | Argument | Register at entry |
|---|---|---|
| `[ebp+8]` | `this` (SRP object) | `ESI` after prologue |
| `[ebp+12]` | `password_len` | `EDI` after prologue |
| `[ebp+16]` | `password_ptr` | `EDX` at `0x10060384` |

### 4.3 Data to capture

1. **Password pointer:** `EDX` at `0x10060384` (`mov 0x10(%ebp),%edx`)
2. **Password length:** `EDI` at `0x10060355` (`mov 0xc(%ebp),%edi`)
3. **Raw password bytes:** Dereference `EDX`, dump `EDI` bytes
4. **Identity buffer:** `obj+0x8` from `ESI` — pointer and length
5. **Identity bytes:** Dereference identity pointer
6. **Call stack:** Full stack trace with module-relative addresses

### 4.4 Test credentials

| Test | Password | UTF-8 | UTF-16LE | UTF-16BE | ANSI |
|---|---|---|---|---|---|
| T1 | `p` | `70` (1B) | `70 00` (2B) | `00 70` (2B) | `70` (1B) |
| T2 | `päss` | `70 c3 a4 73 73` (5B) | `70 00 e4 00 73 00 73 00` (8B) | `00 70 00 e4 00 73 00 73` (8B) | `70 e4 73 73` (4B) |
| T3 | `😀` (U+1F600) | `f0 9f 98 80` (4B) | `3d d8 00 de` (4B) | `d8 3d de 00` (4B) | N/A |

### 4.5 Observation mapping

| Observation | Length | Encoding | Confidence |
|---|---|---|---|
| `70` | 1 | UTF-8 or ANSI | PARTIAL (T2 distinguishes) |
| `70 00` | 2 | UTF-16LE | **CONFIRMED** (if T2 also UTF-16LE) |
| `00 70` | 2 | UTF-16BE | **CONFIRMED** (if T2 also UTF-16BE) |
| `70 c3 a4 73 73` | 5 | UTF-8 | **CONFIRMED** |
| `70 e4 73 73` | 4 | ANSI (Cp1252) | **CONFIRMED** |

### 4.6 Success criteria

The encoding is **CONFIRMED** if:
- T1 and T2 both match the same candidate encoding
- Length matches the expected byte count for that encoding
- Bytes match the expected hexadecimal sequence

---

## 5. M2 Capture Plan

### 5.1 Target

| Item | Value |
|---|---|
| Module | `shelper.dll` |
| Function | `0x100609a0` (M2 computation) |
| Also check | `0x100612f0` (M1 verification) |

### 5.2 SHA-1 context states to capture

At the M2 function entry, dump all four contexts at `context+0x38`:

| Context | Offset | Purpose |
|---|---|---|
| Primary | `+0x00` | Accumulates ... (TBD) |
| M1/M2 accumulator | `+0x60` | A, M1, K for M2 |
| K context | `+0xc0` | Session key material |
| M2 verification | `+0x120` | Verification context |

Each context is 0x60 bytes. Dump full 0x180 bytes.

### 5.3 SHA-1 input captures

Set hardware breakpoints on SHA-1 update function `0x100285f0`:

| Breakpoint | What to capture |
|---|---|
| First update in M2 | Pointer, length, raw bytes |
| Second update (K) | Pointer, length, 40 bytes |

### 5.4 BIGNUM buffer capture

At `0x100609c3` (`call 0x1005f620`):
- Capture BIGNUM pointer
- Capture requested size (0x14 = 20)
- Capture buffer capacity before and after

At `0x100609d4` (`SHA1_Final`):
- Capture output buffer contents (20 bytes)
- Capture BIGNUM length field (should be 20)

At `0x100609e9` (`SHA1_Update`):
- Capture data pointer
- Capture length (should be 20)
- Capture raw bytes
- **Verify: Are all 20 bytes present? Are leading zeros preserved?**

### 5.5 Distinguishing representations

| Observation | Interpretation |
|---|---|
| 20 bytes, no leading zeros | Raw digest (Rust-compatible) |
| <20 bytes (leading zeros stripped) | BIGNUM integer serialization |
| 20 bytes, leading zeros present | Raw digest (leading zeros preserved) |
| Variable length | BIGNUM with stripping |

The capture will definitively determine which representation is used.

---

## 6. RSA Constructor Capture Plan

### 6.1 Target

| Item | Value |
|---|---|
| Module | `shelper.dll` |
| Function | `0x1006b4e0` (CreateWithPublicKey) |
| Also check | `0x1006b3e0` (CreateWithPrivateKey) |

### 6.2 Arguments to capture (public key)

| Stack offset | Argument | Capture |
|---|---|---|
| `[ebp+8]` | n_ptr | Dereference, dump bytes |
| `[ebp+12]` | n_len | Value (should be 256) |
| `[ebp+16]` | e_ptr | Dereference, dump bytes |
| `[ebp+20]` | e_len | Value (should be 3 for 0x010001) |

### 6.3 Arguments to capture (private key)

All 16 arguments (8 ptr+len pairs). Record each pointer and dereference to dump bytes.

### 6.4 Caller information

Capture full call stack. Record:
- Caller module and function
- Module-relative return address
- Thread ID

### 6.5 Component source tracing

From the captured pointers, determine if the buffers:
- Are in `.rdata` (static/embedded)
- Are on heap (allocated at runtime)
- Are in a file mapping (loaded from disk)
- Are in network buffers (received)

This identifies the key provenance.

---

## 7. RSA Call-Site Narrowing Strategy

### 7.1 Problem

4705 calls to IAT slot `0x10175158` in `RvROLClient.dll`. The RSA constructor
call site is hidden among them.

### 7.2 Narrowing strategy

1. **Cross-reference search:** Find all code that loads `SHelper_RSAHelper_CreateWithPublicKey`
   via `GetProcAddress`. The string name is at a known address in `.rdata`.

2. **Function pointer storage:** Find where the resolved pointer is stored
   (object field, global variable, or stack slot).

3. **Indirect call sites:** Find `call *reg` or `call *[mem]` instructions that
   use the stored pointer.

4. **Argument preparation:** For each candidate call site, check if the
   preceding code sets up 4 arguments (n_ptr, n_len, e_ptr, e_len).

5. **Runtime confirmation:** If static narrowing fails, set a breakpoint on
   the function itself (0x1006b4e0) and capture the one that hits.

### 7.3 Runtime observation (fallback)

Breakpoint on `shelper.dll!0x1006b4e0` entry. When it hits:
- Capture call stack (return address → caller function)
- Capture all 4 arguments
- This definitively identifies the caller

---

## 8. One-Session Execution Sequence

### 8.1 Preparation

1. Start Windows VM (`win10`)
2. Install Radmin VPN client
3. Attach debugger (x64dbg/WinDbg) to `RvControlSvc.exe` or `RvROLClient.dll` host process
4. Set breakpoints:
   - `bp shelper.10060340` (password)
   - `bp shelper.100609a0` (M2)
   - `bp shelper.1006b4e0` (RSA public key)
   - `bp shelper.1006b3e0` (RSA private key)

### 8.2 SRP handshake (password + M2)

1. Configure client with test credentials:
   - Username: `"A"` (identity)
   - Password: `"p"` (test password T1)
2. Initiate connection to test server
3. Breakpoint hits at `0x10060340`:
   - Capture password ptr, len, bytes
   - Capture identity ptr, len, bytes
   - Capture call stack
4. Continue to M2 breakpoint at `0x100609a0`:
   - Dump all 4 SHA-1 contexts (0x180 bytes)
   - Capture BIGNUM buffer
   - Capture each SHA-1 update input

### 8.3 RSA handshake (RSession)

1. With SRP complete, RSession key exchange begins
2. Breakpoint hits at `0x1006b4e0`:
   - Capture n_ptr, n_len, e_ptr, e_len
   - Dereference and dump key bytes
   - Capture call stack
3. Breakpoint hits at `0x1006b3e0` (if server side):
   - Capture all 16 arguments
   - Dump all component buffers

### 8.4 Repeat with test credentials

Repeat SRP handshake with:
- Password `"päss"` (T2: non-ASCII)
- Password `"😀"` (T3: non-BMP)

This confirms the encoding across multiple test cases.

---

## 9. Capture Data Schema

Evidence is organized as:

```text
phase-10.20/
├── environment.md              # VM specs, binary hashes, debugger version
├── breakpoint-plan.md          # Breakpoint addresses and conditions
├── password-captures/
│   ├── PW-001.json            # T1: "p"
│   ├── PW-002.json            # T2: "päss"
│   └── PW-003.json            # T3: "😀"
├── m2-captures/
│   ├── M2-001.json            # SHA-1 context dumps
│   └── M2-002.json            # BIGNUM buffer capture
├── rsa-captures/
│   ├── RSA-001.json           # Public key components
│   └── RSA-002.json           # Private key components
├── call-stacks/
│   ├── CS-001.txt             # Password call stack
│   ├── CS-002.txt             # M2 call stack
│   └── CS-003.txt             # RSA call stack
├── raw-dumps/
│   └── (binary dumps)
└── capture-index.json          # Master index of all captures
```

See `docs/CRYPTO_PHASE_10_20_CAPTURE_SCHEMA.json` for the JSON schema.

---

## 10. Expected Evidence

| Blocker | Evidence needed | Classification after capture |
|---|---|---|
| Password encoding | Password bytes + length at 0x10060340 | CONFIRMED (if matches one encoding) |
| M2 BIGNUM step | SHA-1 context + BIGNUM buffer | CONFIRMED (if bytes match one representation) |
| RSA key source | Component buffers + call stack | STRONGLY_SUPPORTED or CONFIRMED |

---

## 11. Failure Conditions

| Failure | Cause | Mitigation |
|---|---|---|
| Breakpoint not hit | Wrong function address (ASLR) | Use module-relative offset: `shelper.10060340` |
| VM cannot run Radmin | Missing dependencies | Use portable Radmin build or installer |
| Debugger cannot attach | Process protection | Use admin privileges or early attach |
| Password buffer zeroized | Function clears after use | Capture at entry, before `SHA1_Update` |
| BIGNUM buffer reallocated | Resize changes pointer | Capture after `0x1005f620` returns |

---

## 12. Remaining Uncertainties

Even after dynamic analysis, some questions may remain:
- Whether the password is cached or re-derived (lifecycle)
- Whether RSA keys rotate (long-term behavior)
- Whether M2 accumulator is reused across sessions

These are P2 and do not block interoperability.

---

## 13. Exact Prerequisites for Phase 10.21

### 13.1 Infrastructure

- [ ] Windows 10 VM (KVM/virt-manager or equivalent)
- [ ] Radmin VPN client installed and functional
- [ ] Test Radmin server (or loopback server)
- [ ] Debugger attached (x64dbg or WinDbg)
- [ ] Test accounts configured

### 13.2 Breakpoints

- [ ] `shelper.dll!0x10060340` (password)
- [ ] `shelper.dll!0x10060c80` (password server)
- [ ] `shelper.dll!0x100609a0` (M2)
- [ ] `shelper.dll!0x1006b4e0` (RSA public key)
- [ ] `shelper.dll!0x1006b3e0` (RSA private key)

### 13.3 Test data

- [ ] Username: `"A"`, `"José"`, `"😀"`
- [ ] Passwords: `"p"`, `"päss"`, `"😀"`
- [ ] Capture directory structure ready

### 13.4 Authorization

- [ ] User authorizes VM start
- [ ] User authorizes debugger attachment
- [ ] User authorizes live Radmin session

---

## 14. Integrity Confirmation

- **No Rust source code was modified** during Phase 10.20.
- **No historical documentation was overwritten.**
- **No binaries or PCAPs were modified.**
- **No commits, pushes, branches, or pull requests were created.**
- **HEAD remains at `95e304e0855a6faf4eece932484cb00e36620a6e`.**
- **No dynamic execution was performed.**
- **Deliverables created:**
  - `docs/CRYPTO_PHASE_10_20_DYNAMIC_ANALYSIS_READINESS.md` (this file)
  - `docs/CRYPTO_PHASE_10_20_CAPTURE_SCHEMA.json`
