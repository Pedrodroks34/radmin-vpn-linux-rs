# CRYPTO_PHASE_10_3_10_5_OPEN_QUESTIONS.md

# Open Questions — Unified Phase 10.3–10.5 (Consolidated)

This file lists the unresolved questions remaining after the consolidation. Each entry
states why it matters, the existing evidence, the missing evidence, and the exact next
investigation step.

---

## OQ-1 — AES split mapping (P0)

- **Question:** Which half of the 64-byte RSession secret (`[0..32]` vs `[32..64]`)
  feeds AES encryption and which feeds decryption?
- **Why it matters:** Rust `from_rsession_key()` uses `key_material[..32]` for both
  directions (`famatech.rs:181-186`). If the official consumer passes two different
  halves, one direction fails decryption.
- **Existing evidence:** `GetKey` (0x1006ba80) returns 64 bytes verbatim; `SetKeyPair`
  (0x1006a630) receives two pointers and validates both lengths == 0x20.
- **Missing evidence:** The consumer call site that derives the two pointers. disp8
  indirect dispatch (`call [reg+0xb0/c0/c4]`) has not been located statically.
- **Next step:** Dynamic breakpoint on `0x1006a630`; compare pointer args with the
  GetKey buffer. Alternatively, a disp8-aware byte-pattern sweep over the consumer
  binaries.

## OQ-2 — Password encoding in x (P0)

- **Question:** Is the password hashed as UTF-8, UTF-16LE, UTF-16BE, or ANSI?
- **Why it matters:** `x`, `v`, `A`, `S`, `K`, `M1`, `M2` all depend on it. Rust uses
  UTF-8 (`password.as_bytes()`).
- **Existing evidence:** `shelper.dll` takes the password as caller-supplied raw
  `(ptr, len)` at `0x10060340`/`0x10060c80` with no transformation inside.
- **Missing evidence:** The caller conversion. `RvROLClient.dll`/`RvControlSvc.exe`
  call sites not traced.
- **Next step:** Dynamic breakpoint on `0x10060340`; inspect password buffer for a
  known test string.

## OQ-3 — Identity hash bytes LE vs BE (P0)

- **Question:** Does the `x` hash consume the internal UTF-16LE buffer at `obj+0x8`,
  or the wire UTF-16BE form?
- **Why it matters:** Rust `encode_identity()` emits UTF-16BE and feeds it to
  `compute_srp_x()`. If the binary hashes UTF-16LE, `x` differs even though the wire
  identity matches.
- **Existing evidence:** Wire byte-swap at `0x100667b0`; hash reads `obj+0x8` raw at
  `0x10060361`. LE-inference is MEDIUM confidence.
- **Missing evidence:** Byte-exact capture of the hashed identity buffer.
- **Next step:** Dynamic breakpoint on `0x10060340`; inspect the identity buffer
  bytes for "A" (`41 00` = LE, `00 41` = BE).

## OQ-4 — context+0x20 runtime proof (P1)

- **Question:** Is `context+0x20` definitively `A` on the client and `B` on the server
  at runtime?
- **Why it matters:** The symmetric `u = SHA-1(A‖B)` conclusion rests on this.
- **Existing evidence:** `FUN_10060410`/`FUN_10060d80` write `context+0x20` after
  `mod_exp` (`0x1005f940`) calls — STRONGLY_SUPPORTED.
- **Missing evidence:** Runtime confirmation.
- **Next step:** Breakpoint after the `mod_exp` call; compare with `g^a` / `g^b`.

## OQ-5 — M1/M2 exact construction (P1)

- **Question:** What is the exact input order and component list for M1 and M2?
- **Why it matters:** Rust uses single-shot hashes; the binary accumulates incrementally.
- **Existing evidence:** M1 accumulator at `context+0x38+0x60`; documented formulas
  `M1 = SHA-1(H(N)⊕H(g)‖H(I)‖salt‖A‖B‖K)`, `M2 = SHA-1(A‖M1‖K)`.
- **Missing evidence:** Full disassembly of `0x100612f0`/`0x100609a0` and their callers.
- **Next step:** Disassemble the M1/M2 regions; intercept hash inputs dynamically.

## OQ-6 — RSA key provenance (P1)

- **Question:** Where do the server's RSA public key and private key come from?
- **Why it matters:** RSession cannot be implemented without the official key material.
- **Existing evidence:** RSA-2048 PKCS#1 v1.5, exponent 65537, 76-byte plaintext.
- **Missing evidence:** Embedded blob (`.rdata` search negative so far), file load,
  network delivery, or runtime generation.
- **Next step:** Search resources and imports for key-loading APIs; trace
  `CreateClient`/`CreateServer` callers.

## OQ-7 — SRP step-value endianness (P2)

- **Question:** Are SRP step values (and other protocol integers) little- or
  big-endian on the wire?
- **Why it matters:** Rust uses `to_le_bytes()` for step values; the version field is
  confirmed little-endian, but SRP step values have not been captured.
- **Existing evidence:** PCAP captures `03 00 00 00` version; no SRP exchange captured.
- **Missing evidence:** A PCAP containing the full SRP handshake.
- **Next step:** Capture an SRP handshake (requires a Windows session).

## OQ-8 — Residual fields and dispatcher (P2)

- **Question:** What are `context+0x24`, `+0x2c`, `+0x30`, `+0x34`, and the
  `FUN_100092e0` jump table?
- **Why it matters:** Low direct impact, but they may affect the M1/S computation paths.
- **Existing evidence:** Field map through `+0x28` (u); M1 accumulator `+0x38`.
- **Missing evidence:** Writes/reads to the remaining offsets.
- **Next step:** Full object-field read/write sweep with Ghidra.

---

**Note on redundancy:** The consolidated report
(`CRYPTO_PHASE_10_3_10_5_CONSOLIDATED_REPORT.md`) is the primary artifact and
incorporates the Phase 10.10–10.12 findings; this file is the actionable checklist
derived from it. Neither replaces the historical reports, which are preserved.
