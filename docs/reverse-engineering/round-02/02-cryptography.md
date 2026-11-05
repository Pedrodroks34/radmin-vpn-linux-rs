# Frente 2: Arquitetura Criptográfica e Formato dos Quadros

**Classificação de Certeza:** CONFIRMADO (desmontagem completa de `shelper.dll` nas rotinas de cifra, preenchimento, soma de verificação e encadeamento de IV)

---

## 1. Visão Geral da Camada Criptográfica

O canal seguro do Radmin VPN opera através de uma cifra simétrica de bloco **AES-256 no modo CBC (Cipher Block Chaining)**, combinada com uma estrutura proprietária de autenticação e padding no final de cada quadro. 

As primitivas criptográficas são fornecidas por uma versão estaticamente vinculada do OpenSSL incorporada em `shelper.dll`.

---

## 2. Negociação Assimétrica e Padding RSA

O handshake assimétrico utiliza chaves **RSA de 2048 bits**.
A desmontagem das rotinas de chamada de chave pública e privada em `shelper.dll` revela o modo de preenchimento padronizado:

### 2.1 Desmontagem da Cifragem / Decifragem RSA (`0x10065ec0` / `0x10065db0`)
Em `0x10065de8`:
```x86asm
0x10065de0: mov eax, dword ptr [ebp + 0x10] ; buffer de saída
0x10065de3: mov ecx, dword ptr [ebp + 0xc]  ; buffer de entrada
0x10065de6: push 1                          ; Constante de preenchimento: RSA_PKCS1_PADDING = 1
0x10065de8: push dword ptr [ebp + 0x14]     ; estrutura RSA (chave)
0x10065deb: push eax                        ; destino
0x10065dec: push dword ptr [ebp + 8]        ; flen (tamanho do payload)
0x10065def: push ecx                        ; entrada
0x10065df0: call 0x100067a0                 ; OpenSSL RSA_public_encrypt / RSA_private_decrypt
0x10065df5: add esp, 0x14
```

> [!IMPORTANT]
> O argumento empurrado na pilha é invariavelmente `push 1`, correspondendo a `RSA_PKCS1_PADDING` da especificação PKCS#1 v1.5. Nenhuma rotina invoca `RSA_NO_PADDING` (`Padding::NONE`) ou `RSA_PKCS1_OAEP_PADDING`.

---

## 3. Configuração da Cifra Simétrica AES-256-CBC

### 3.1 Inicialização e Expansão da Chave
As rotinas exportadas `SHelper_CChannel_SetKeyEnc` (`0x1006ab00`) e `SHelper_CChannel_SetKeyDec` (`0x1006aac0`) recebem a chave de 32 bytes (256 bits):

```x86asm
0x1006aacc: cmp eax, 0x20          ; validação estrita: deve possuir exatamente 32 bytes
0x1006aad0: jne 0x1006ab30
0x1006aad5: push 0x100             ; bits = 256
0x1006aada: push dword ptr [ebp + 8] ; ponteiro para os 32 bytes
0x1006aadd: add ecx, 0x10          ; contexto AES_KEY
0x1006aae0: push ecx
0x1006aae1: call 0x10003cb0        ; OpenSSL AES_set_decrypt_key / AES_set_encrypt_key
```

### 3.2 Inicialização e Encadeamento do Vetor de Inicialização (IV)
O estado do canal mantém dois vetores de inicialização de 16 bytes:
* `[esi + 0x1ec]`: IV de Cifragem (Tx)
* `[esi + 0x1fc]`: IV de Decifragem (Rx)

No construtor do canal (`0x10062ca9`):
```x86asm
0x10062ca9: xorps xmm0, xmm0        ; limpa registrador com 16 bytes de zeros
0x10062cac: movups xmmword ptr [esi + 0x1ec], xmm0 ; Tx IV = [0x00; 16]
0x10062cb4: movups xmmword ptr [esi + 0x1fc], xmm0 ; Rx IV = [0x00; 16]
```

Na execução da cifragem (`0x10062e00`) e decifragem (`0x10062d60`):
```x86asm
0x10062e15: push 1                  ; AES_ENCRYPT = 1
0x10062e17: lea eax, [esi + 0x1ec]  ; ponteiro para IV persistente
0x10062e1d: push eax
0x10062e1e: lea eax, [esi + 0x10]   ; ponteiro para estrutura AES_KEY expandida
0x10062e21: push eax
0x10062e22: push edi                ; destino (ciphertext)
0x10062e23: push ebx                ; comprimento total alinhado a 16
0x10062e24: push edx                ; entrada (plaintext com trailer)
0x10062e25: call 0x10003b30        ; OpenSSL AES_cbc_encrypt
```

> [!NOTE]
> A função padrão `AES_cbc_encrypt` do OpenSSL atualiza o buffer do IV apontado diretamente na memória com os últimos 16 bytes de texto cifrado gerados ou consumidos. Portanto, **o IV nunca é reenviado em rede** e **não é resetado para zero entre quadros subsequentes**, garantindo encadeamento contínuo em fluxo CBC com proteção contra ataques de repetição.

---

## 4. Estrutura do Trailer Proprietário e Algoritmo de Padding

Ao contrário do padding PKCS#7 comum, a arquitetura Famatech utiliza um trailer híbrido de integridade e preenchimento projetado para validar a integridade estrutural e prevenir truncamentos.

### 4.1 Cálculo do Tamanho do Quadro
A função `FUN_10069c20` calcula o tamanho do buffer final antes da cifragem:

$$\text{TamanhoTotal} = \left\lfloor \frac{\text{PayloadLen} + 24}{16} \right\rfloor \times 16$$

O tamanho total é garantidamente um múltiplo estrito de 16 bytes (bloco AES).
O número de bytes de preenchimento e trailer é dado por:

$$\text{PadLen} = \text{TamanhoTotal} - \text{PayloadLen}$$

Como decorrência da fórmula acima, o valor de `PadLen` varia no intervalo:
$$9 \le \text{PadLen} \le 24$$

### 4.2 Anatomia do Bloco Pré-Cifragem (Plaintext)
```
+--------------------------+-----------------------+------------------------+-----------+
| DADOS ÚTEIS (TLV)        | PADDING 0xCC          | CHECKSUM ADITIVO 64-bit| PAD_LEN   |
| (PayloadLen bytes)       | (PadLen - 9 bytes)    | (8 bytes, Little-End.) | (1 byte)  |
+--------------------------+-----------------------+------------------------+-----------+
|<----------------- Zona Coberta pelo Checksum ---------------------------->|           |
|<------------------------ TamanhoTotal (Múltiplo de 16) ------------------------------>|
```

1. **Zona de Preenchimento:** Se $(\text{PadLen} - 9) > 0$, essa região é preenchida repetidamente com o byte constante `0xCC`.
2. **Soma de Verificação Aditiva de 64 bits:** Calculada sobre a faixa $[0 \dots \text{TamanhoTotal} - 9]$ (incluindo o payload e todos os bytes `0xCC`).
3. **Byte de Comprimento (`PadLen`):** O último byte do bloco alinhado armazena exatamente o valor numérico de $\text{PadLen}$.

### 4.3 Algoritmo da Soma de Verificação Aditiva (`0x1006a0c0`)
A rotina percorre o buffer agrupando em palavras de 8 bytes (64 bits) em little-endian, acumulando o resultado:

```x86asm
0x1006a0c0: push ebp
0x1006a0c1: mov ebp, esp
0x1006a0c3: mov ecx, dword ptr [ebp + 8]   ; ponteiro para dados [0 .. TamanhoTotal - 9]
0x1006a0c6: mov edx, dword ptr [ebp + 0xc] ; tamanho em bytes a somar
0x1006a0c9: xor eax, eax                  ; accum_low = 0
0x1006a0cb: xor esi, esi                  ; accum_high = 0
0x1006a0cd: shr edx, 3                    ; divide por 8 (quantidade de qwords)
0x1006a0d0: test edx, edx
0x1006a0d2: je 0x1006a0e6
0x1006a0d4: add eax, dword ptr [ecx]      ; soma low 32 bits
0x1006a0d6: adc esi, dword ptr [ecx + 4]  ; soma com carry high 32 bits
0x1006a0d9: add ecx, 8
0x1006a0dc: dec edx
0x1006a0dd: jne 0x1006a0d4
0x1006a0df: mov edx, esi                  ; edx:eax = 64-bit checksum
0x1006a0e1: pop ebp
0x1006a0e2: ret 8
```

Se houver sobra de bytes $((\text{TamanhoTotal} - 9) \pmod 8 \ne 0)$, os bytes restantes são somados ao acumulador estendidos com zeros.

---

## 5. Algoritmo de Validação e Desempacotamento (`0x10069f90`)

Na recepção e decifragem de um quadro:
1. O tamanho decifrado é verificado como múltiplo de 16 e $\ge 16$.
2. O último byte é lido: `pad_len = buffer[total_len - 1]`.
3. Validação de faixa: se `pad_len < 9` ou `pad_len > 24`, a rotina aborta imediatamente (`return 0`), indicando corrupção ou chave incorreta.
4. O checksum de 64 bits gravado nos bytes $[\text{total\_len} - 9 \dots \text{total\_len} - 2]$ é extraído em little-endian.
5. O checksum aditivo é recalculado sobre a fatia $[0 \dots \text{total\_len} - 9]$. Se diferir do checksum gravado, o quadro é descartado e o canal é marcado com falha (`0x1006a01b`).
6. A função retorna o comprimento legítimo dos dados úteis: $\text{PayloadLen} = \text{total\_len} - \text{pad\_len}$.

> [!TIP]
> **Esclarecimento de Hipótese Anterior:** Em relatórios preliminares, cogitou-se a hipótese de um "MD5 dobrado para 8 bytes". A desmontagem minuciosa de `FUN_1006a0c0` comprovou categoricamente que a soma de integridade é uma **soma aditiva little-endian de 64 bits com adição de carry**, sem qualquer invocação de MD5 ou SHA no processo de validação de quadros simétricos.
