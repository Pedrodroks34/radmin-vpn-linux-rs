# SRP Dispatch and Runtime Data-Flow Audit (Phase 10.8)

## 1. Executive Summary

This is a read-only reconciliation of the Phase 10.5 and 10.7 SRP claims. The available `shelper.dll` evidence proves that two different SRP-related routines exist, but it does not prove which descriptor is instantiated by the handshake consumer. Therefore the dispatch contradiction is only partially resolved.

The strongest directly observed result is that `FUN_100607d0` at RVA `0x607d0` constructs a BIGNUM from the literal integer `3` and passes it to `FUN_10060510`. `FUN_10060810` at RVA `0x60810` performs SHA-1 over two serialized BIGNUM buffers and then passes the digest onward; its first input is a BIGNUM obtained from the object at `esi+0xc`, and its second input is a BIGNUM obtained from `esi+0x10` under a flag-controlled path. This makes it a digest routine, but the available evidence does not establish that it is the multiplier `k` routine, nor that the two operands are `N` and `g`.

The method-table bytes and descriptor names are present, but no complete executable handshake-to-indirect-call chain was recovered in this environment. A function pointer or descriptor name is not treated as proof of runtime selection. No code or existing documentation was modified; this report is the only repository file added.

## 2. Repository and Binary Provenance

The investigation was performed on branch `main`, HEAD `95e304e0855a6faf4eece932484cb00e36620a6e` (`docs: add SRP integer serialization audit`). The initial working tree was clean. The archive branch `archive/docs-2026-11` was present.

The relevant binary hashes are:

| Artifact | SHA-256 | Format |
|---|---|---|
| `Radmin_VPN_2.1.4951.1.exe` | `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7` | PE32 i386 GUI, 11 sections |
| `claude-handoff/binaries/original/Radmin_VPN_2.1.4951.1.exe` | `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7` | PE32 i386 GUI, 11 sections |
| `claude-handoff/binaries/radmin_ext/shelper.dll` | `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4` | PE32 i386 DLL |
| `claude-handoff/binaries/radmin_ext/RvROLClient.dll` | `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177` | PE32 i386 DLL |
| `claude-handoff/binaries/radmin_ext/RvControlSvc.exe` | `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` | PE32 i386 console executable |

The two installer copies are byte-identical. The exact binary used by each historical report cannot be independently proven from report metadata alone, but the archived reports identify the same `shelper.dll` hash above. No Ghidra executable was available in this session; the binary instructions below were independently checked with GNU `objdump` and raw PE bytes.

## 3. Historical Report Reconciliation

Phase 10.5 reported active SRP-6a dispatch and `k = SHA-1(N || PAD(g))`. Phase 10.7 correctly warned that a table pointer and an isolated function are not proof of execution, while reporting the literal-3 routine and leaving dispatch unresolved. The Phase 10.5 conclusion is therefore not reproducible from the currently available call-chain evidence and is downgraded to an unverified hypothesis.

The historical claim that `FUN_10060810` is unambiguously the `k` calculator is contradicted by its observed data flow: it hashes two BIGNUM serializations and later uses the resulting digest in another routine. That is compatible with several SRP digest roles, including `u`, `k`, or proof material. The operands and caller-provided object fields were not established here.

## 4. SRP Method Table Reconstruction

The `.data` section begins at RVA `0xac000`, file offset `0xaa600`; therefore RVA `0xad740` is file offset `0xabd40`. The bytes at that offset decode as little-endian function pointers:

| RVA | File offset | Raw pointer | Interpreted VA |
|---:|---:|---:|---:|
| `0xad740` | `0xabd40` | `f0 02 06 10` | `0x100602f0` |
| `0xad744` | `0xabd44` | `40 03 06 10` | `0x10060340` |
| `0xad748` | `0xabd48` | `10 04 06 10` | `0x10060410` |
| `0xad74c` | `0xabd4c` | `d0 07 06 10` | `0x100607d0` |
| `0xad750` | `0xabd50` | `00 09 06 10` | `0x10060900` |
| `0xad754` | `0xabd54` | `a0 09 06 10` | `0x100609a0` |

The next word at `0xad758` is zero, and `0xad75c` contains `0x100a3df0`, a pointer to the string reported by prior analysis as `SRP-6a client (tjw)`. A second sequence begins at `0xad760` and includes the server-side function pointers reported historically, including `0x10060810` at RVA `0xad778`; its name pointer is at `0xad7b4` and points to `0x100a3e18`. The exact semantic slot count and descriptor layout are not independently proven by a typed structure in this session.

The table is in writable `.data`, not executable code. No relocation processing or initializer that replaces these entries was found with the available static tools. Consequently, the table layout is confirmed as bytes and pointers, while the client/server role and slot semantics remain inferred from neighboring names and prior reports.

## 5. Dispatcher and Call Graph

The required chain `handshake entry → object initialization → descriptor selection → indirect call → concrete routine` was not recovered. Direct calls to the concrete routines are not equivalent to indirect dispatch through the table. The available `objdump` search and raw-data inspection did not identify a unique instruction sequence that loads `0xad740` or `0xad760`, selects a role-dependent slot, and calls through it.

Thus:

- table existence: CONFIRMED;
- descriptor strings and pointer locations: CONFIRMED from the table bytes and prior local analysis;
- table consumer: UNKNOWN;
- role/version negotiation selecting a table: UNKNOWN;
- runtime replacement of entries: NOT OBSERVED, not disproven;
- reachability of `FUN_100607d0` or `FUN_10060810` from the real handshake: UNKNOWN.

## 6. Concrete Function Evidence

### 6.1 `FUN_100607d0` (VA `0x100607d0`, RVA `0x607d0`)

`objdump` shows:

```text
100607d5: 6a 03                 push 0x3
100607d7: e8 04 ef ff ff        call 0x1005f6e0
100607ee: e8 1d fd ff ff        call 0x10060510
100607f6: e8 05 f2 ff ff        call 0x1005fa00
```

The immediate `3` is passed to the BIGNUM constructor at `0x1005f6e0`; the resulting object is passed as an argument to `0x10060510` and then released. The literal-3 behavior is CONFIRMED. Its runtime selection is UNKNOWN.

### 6.2 `FUN_10060810` (VA `0x10060810`, RVA `0x60810`)

This function initializes SHA-1 at `0x10028810`, obtains a BIGNUM at `0x1005f4b0`, serializes it with `0x1005fad0`, and updates SHA-1 at `0x100285f0`. The first serialization width is loaded from `[esi+0xc]`. A flag at `[esi+4]` controls a second path involving `[esi+0x10]` and `0x1005f760`; a second SHA-1 update follows. The digest is finalized at `0x100286d0`, converted to a BIGNUM, and passed to `0x10060510`.

This proves a two-buffer BIGNUM digest path. It does not prove `k = SHA-1(N || PAD(g))`, because the provenance of the BIGNUM object and width fields is unresolved.

### 6.3 `FUN_10060ec0` / `FUN_10060fa0`

The historical reports use both names for the server-side region. The available PE disassembly has a function entry at `0x10060fa0` (RVA `0x60fa0`), which reads an externally supplied pointer at `[esi+0x20]`, serializes it, and hashes it with additional buffers. It therefore demonstrates an externally supplied BIGNUM input, not a standalone proof that the server computes `k`. The exact `0x10060ec0` entry/role distinction is unresolved in the available evidence and is not silently merged with `0x10060fa0`.

## 7. `k` Conclusion

The official value/formula cannot be established conclusively from the reachable runtime path available here.

- `FUN_100607d0`: literal integer `3`, CONFIRMED.
- `FUN_10060810`: SHA-1 over two runtime BIGNUM buffers, CONFIRMED; assignment to `k`, UNKNOWN.
- Server input at `0x10060fa0`: externally supplied BIGNUM involvement, CONFIRMED; equality to client `k`, UNKNOWN.
- Arithmetic candidate `SHA-1(N || PAD(5,192)) = 7b12a483fe77c3ed56e5a4dd8e7acc4fe7ec1233`: independently reproducible, but not proof of official use.

Therefore `RADMIN_SRP_K = 3` is not proven compatible with the complete official handshake, but replacing it with the digest is also not authorized. The correct status is UNKNOWN, not CONFIRMED_MISMATCH.

## 8. `u`, Serialization, Identity, and Rust Comparison

The Rust implementation uses:

| Component | Current Rust | Official evidence | Status |
|---|---|---|---|
| `k` | BIGNUM `3`, `control_handshake.rs:16,861,1283` | Literal-3 routine exists; digest path also exists | UNKNOWN |
| `u` input order | `PAD192(A) || PAD192(B)`, lines 367–381 | Two runtime BIGNUM buffers in `FUN_10060810`; operand identity/order unresolved | PARTIALLY_CONFIRMED |
| `A`, `B` | Big-endian, left-padded to 192 bytes, lines 778 and 1301 | Runtime width passed to BIGNUM conversion; exact width unresolved | PARTIALLY_CONFIRMED |
| `S` before KDF | Big-endian, padded to 192, lines 894–895 and 1381–1382 | Not traced to the official KDF caller | UNKNOWN |
| identity wire | UTF-16BE code units, lines 146–153 | Prior local evidence supports byte-swapped UTF-16 wire form | PARTIALLY_CONFIRMED |
| identity in `x` | UTF-8 plus `:` plus password, lines 269–285 | Official pointer/length provenance not traced | UNKNOWN |
| password | UTF-8, lines 275–277 | Official encoding not established | UNKNOWN |

The Rust `u` implementation is internally consistent and the arithmetic candidate is standard-looking, but no byte-level official `u` vector is available. The Rust public-value and KDF paths require fixed 192-byte inputs; official runtime widths remain unresolved. The prior claim of a confirmed Rust mismatch for `k` is therefore withdrawn pending dispatch evidence.

## 9. Independent Validation and Limitations

Independent checks used `sha256sum`, `file`, PE section headers, raw `xxd` bytes, GNU `objdump -d -Mintel`, `tshark` availability checks, Git history/tree inspection, and direct Rust source inspection. The SHA-1 candidate was mathematically validated separately from Rust using the known modulus and generator values documented in the repository history. No official handshake vector exposed enough values to validate `k`, `u`, or `S` byte-for-byte.

Ghidra was not available and was not claimed as used. No dynamic execution, Windows runtime, Wine, VM, or driver was used. The absence of a recovered dispatcher is the principal limitation.

## 10. Remaining Unknowns

1. The concrete consumer that loads the client/server table.
2. The exact indirect slot selected for each handshake role.
3. Whether initialization replaces or patches the table.
4. Whether `FUN_100607d0` executes in the official handshake.
5. Whether `FUN_10060810` computes `k`, `u`, or another digest in the selected path.
6. The provenance and value of the server-side `k` input.
7. Runtime widths and leading-zero behavior for `A`, `B`, `u` inputs, and `S`.
8. Official identity and password bytes supplied to `x`.

## 11. Phase 10.5 Implementation Readiness

**PARTIALLY.** The investigation authorizes no code remediation. It establishes a confirmed literal-3 path and a separate confirmed two-BIGNUM SHA-1 path, but not the dispatcher that selects either path. It is therefore unsafe to replace `RADMIN_SRP_K`, change identity hashing, change `compute_srp_u`, or alter BIGNUM padding.

A follow-up investigation should trace table consumers and the caller arguments into `FUN_10060810` and `FUN_10060fa0` using a disassembler with cross-reference and data-flow support, then validate against an observed handshake. Only after that evidence should an implementation task be opened.

## 12. Repository Safety Verification

This report is the only new repository file. No Rust source, existing documentation, manifest, lockfile, binary, capture, or Git metadata was modified. No commit, branch switch, push, or reset was performed.
