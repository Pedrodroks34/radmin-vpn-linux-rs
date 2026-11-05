# Front 2: Cryptographic Architecture and Frame Format

**Certainty classification:** CONFIRMED (full disassembly of `shelper.dll` in the cipher, padding, checksum and IV-chaining routines)

---

## 1. Overview of the Cryptographic Layer

The secure channel of Radmin VPN operates through a symmetric **AES-256 block cipher in CBC (Cipher Block Chaining) mode**, combined with a proprietary authentication and padding structure at the end of each frame.

The cryptographic primitives are provided by a statically linked version of OpenSSL embedded in `shelper.dll`.

---

## 2. Asymmetric Negotiation and RSA Padding

The asymmetric handshake uses **2048-bit RSA** keys.
The disassembly of the public-key and private-key call routines in `shelper.dll` reveals the standard padding mode:

### 2.1 Disassembly of RSA Encryption / Decryption (`0x10065ec0` / `0x10065db0`)
At `0x10065de8`:
```x86asm
0x10065de0: mov eax, dword ptr [ebp + 0x10] ; output buffer
0x10065de3: mov ecx, dword ptr [ebp + 0xc]  ; input buffer
0x10065de6: push 1                          ; Padding constant: RSA_PKCS1_PADDING = 1
0x10065de8: push dword ptr [ebp + 0x14]     ; RSA structure (key)
0x10065deb: push eax                        ; destination
0x10065dec: push dword ptr [ebp + 8]        ; flen (payload size)
0x10065def: push ecx                        ; input
0x10065df0: call 0x100067a0                 ; OpenSSL RSA_public_encrypt / RSA_private_decrypt
0x10065df5: add esp, 0x14
```

> [!IMPORTANT]
> The argument pushed onto the stack is invariably `push 1`, corresponding to `RSA_PKCS1_PADDING` of the PKCS#1 v1.5 specification. No routine invokes `RSA_NO_PADDING` (`Padding::NONE`) or `RSA_PKCS1_OAEP_PADDING`.

---

## 3. AES-256-CBC Symmetric Cipher Configuration

### 3.1 Key Initialization and Expansion
The exported routines `SHelper_CChannel_SetKeyEnc` (`0x1006ab00`) and `SHelper_CChannel_SetKeyDec` (`0x1006aac0`) receive the 32-byte (256-bit) key:

```x86asm
0x1006aacc: cmp eax, 0x20          ; strict validation: must be exactly 32 bytes
0x1006aad0: jne 0x1006ab30
0x1006aad5: push 0x100             ; bits = 256
0x1006aada: push dword ptr [ebp + 8] ; pointer to the 32 bytes
0x1006aadd: add ecx, 0x10          ; AES_KEY context
0x1006aae0: push ecx
0x1006aae1: call 0x10003cb0        ; OpenSSL AES_set_decrypt_key / AES_set_encrypt_key
```

### 3.2 Initialization Vector (IV) Setup and Chaining
The channel state keeps two 16-byte initialization vectors:
* `[esi + 0x1ec]`: Encryption IV (Tx)
* `[esi + 0x1fc]`: Decryption IV (Rx)

In the channel constructor (`0x10062ca9`):
```x86asm
0x10062ca9: xorps xmm0, xmm0        ; clears the register with 16 zero bytes
0x10062cac: movups xmmword ptr [esi + 0x1ec], xmm0 ; Tx IV = [0x00; 16]
0x10062cb4: movups xmmword ptr [esi + 0x1fc], xmm0 ; Rx IV = [0x00; 16]
```

During encryption (`0x10062e00`) and decryption (`0x10062d60`):
```x86asm
0x10062e15: push 1                  ; AES_ENCRYPT = 1
0x10062e17: lea eax, [esi + 0x1ec]  ; pointer to the persistent IV
0x10062e1d: push eax
0x10062e1e: lea eax, [esi + 0x10]   ; pointer to the expanded AES_KEY structure
0x10062e21: push eax
0x10062e22: push edi                ; destination (ciphertext)
0x10062e23: push ebx                ; total length aligned to 16
0x10062e24: push edx                ; input (plaintext with trailer)
0x10062e25: call 0x10003b30        ; OpenSSL AES_cbc_encrypt
```

> [!NOTE]
> The standard OpenSSL `AES_cbc_encrypt` function updates the IV buffer passed to it directly in memory with the last 16 bytes of ciphertext generated or consumed. Therefore, **the IV is never sent over the network** and **is not reset to zero between subsequent frames**, guaranteeing continuous chaining in CBC flow with protection against replay attacks.

---

## 4. Proprietary Trailer Structure and Padding Algorithm

Unlike the common PKCS#7 padding, the Famatech architecture uses a hybrid integrity and padding trailer designed to validate structural integrity and prevent truncation.

### 4.1 Frame Size Calculation
The function `FUN_10069c20` calculates the final buffer size before encryption:

$$\text{TotalSize} = \left\lfloor \frac{\text{PayloadLen} + 24}{16} \right\rfloor \times 16$$

The total size is guaranteed to be a strict multiple of 16 bytes (the AES block size).
The number of padding and trailer bytes is given by:

$$\text{PadLen} = \text{TotalSize} - \text{PayloadLen}$$

As a consequence of the formula above, the value of `PadLen` lies in the range:
$$9 \le \text{PadLen} \le 24$$

### 4.2 Anatomy of the Pre-Encryption Block (Plaintext)
```
+--------------------------+-----------------------+------------------------+-----------+
| USEFUL DATA (TLV)        | PADDING 0xCC          | 64-bit ADDITIVE CHECKSUM| PAD_LEN  |
| (PayloadLen bytes)       | (PadLen - 9 bytes)    | (8 bytes, Little-End.) | (1 byte)  |
+--------------------------+-----------------------+------------------------+-----------+
|<----------------- Area Covered by the Checksum ---------------------------->|           |
|<------------------------ TotalSize (Multiple of 16) ------------------------------>|
```

1. **Padding zone:** If $(\text{PadLen} - 9) > 0$, this region is filled repeatedly with the constant byte `0xCC`.
2. **64-bit additive checksum:** Computed over the range $[0 \dots \text{TotalSize} - 9]$ (including the payload and all `0xCC` bytes).
3. **Length byte (`PadLen`):** The last byte of the aligned block stores exactly the numeric value of $\text{PadLen}$.

### 4.3 Additive Checksum Algorithm (`0x1006a0c0`)
The routine walks the buffer in 8-byte (64-bit) little-endian words, accumulating the result:

```x86asm
0x1006a0c0: push ebp
0x1006a0c1: mov ebp, esp
0x1006a0c3: mov ecx, dword ptr [ebp + 8]   ; pointer to the data [0 .. TotalSize - 9]
0x1006a0c6: mov edx, dword ptr [ebp + 0xc] ; size in bytes to sum
0x1006a0c9: xor eax, eax                  ; accum_low = 0
0x1006a0cb: xor esi, esi                  ; accum_high = 0
0x1006a0cd: shr edx, 3                    ; divide by 8 (number of qwords)
0x1006a0d0: test edx, edx
0x1006a0d2: je 0x1006a0e6
0x1006a0d4: add eax, dword ptr [ecx]      ; adds low 32 bits
0x1006a0d6: adc esi, dword ptr [ecx + 4]  ; adds with carry to the high 32 bits
0x1006a0d9: add ecx, 8
0x1006a0dc: dec edx
0x1006a0dd: jne 0x1006a0d4
0x1006a0df: mov edx, esi                  ; edx:eax = 64-bit checksum
0x1006a0e1: pop ebp
0x1006a0e2: ret 8
```

If bytes remain over $((\text{TotalSize} - 9) \bmod 8 \ne 0)$, the remaining bytes are added to the accumulator zero-extended.

---

## 5. Validation and Unpacking Algorithm (`0x10069f90`)

On reception and decryption of a frame:
1. The decrypted size is verified to be a multiple of 16 and $\ge 16$.
2. The last byte is read: `pad_len = buffer[total_len - 1]`.
3. Range validation: if `pad_len < 9` or `pad_len > 24`, the routine aborts immediately (`return 0`), indicating corruption or an incorrect key.
4. The 64-bit checksum stored at bytes $[\text{total\_len} - 9 \dots \text{total\_len} - 2]$ is extracted in little-endian.
5. The additive checksum is recalculated over the slice $[0 \dots \text{total\_len} - 9]$. If it differs from the stored checksum, the frame is discarded and the channel is marked as failed (`0x1006a01b`).
6. The function returns the legitimate length of the useful data: $\text{PayloadLen} = \text{total\_len} - \text{pad\_len}$.

> [!TIP]
> **Clarification of a previous hypothesis:** In preliminary reports, the hypothesis of a "MD5 folded to 8 bytes" was considered. The detailed disassembly of `FUN_1006a0c0` conclusively showed that the integrity sum is a **little-endian 64-bit additive sum with carry propagation**, with no invocation of MD5 or SHA anywhere in the symmetric frame validation process.
