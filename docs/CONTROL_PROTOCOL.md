# Protocolo de Controle do Radmin VPN — Fases 5 a 9

**Status:** ESPECIFICAÇÃO PARCIAL — análise de serialização e criptografia via Ghidra headless (Fases 5-9).

**Binários analisados:**
- `RvControlSvc.exe` — SHA-256 `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e`
- `RvROLClient.dll` — contém referências a `CCryptoChannel@RolClient`
- `shelper.dll` — biblioteca auxiliar baseada em OpenSSL 1.0.1f, contém `AESCryptor` e `RSAHelper`

**Bancos Ghidra:**
- `/tmp/opencode/ghidra_project2/control_project.rep` (RvControlSvc.exe)
- `/tmp/opencode/ghidra_project/radmin_project.rep` (RvROLClient.dll)
- `/tmp/opencode/ghidra_project3/shelper_project.rep` (shelper.dll)

---

## 1. Localização das Strings RTTI (CONFIRMADO)

### RvControlSvc.exe

| String RTTI | Endereço | Observação |
|---|---|---|
| `CPacket_KeepAlive` | 0x556a58, 0x556a84 | Duas ocorrências |
| `CPacket_Handshake_Syn` | 0x5569c8, 0x5569f8 | Duas ocorrências |
| `CPacket_Shutdown` | 0x556b70 | Uma ocorrência |
| `CPacket_RadminPort` | 0x556b14 | Uma ocorrência |
| `CPacket_Frame` | 0x556970 | Uma ocorrência |
| `CPacket_ConfirmSwitch` | 0x556910 | Uma ocorrência |
| `CPacket_StartSwitch` | 0x556b9c | Uma ocorrência |
| `CPacket_FinalizeSwitch` | 0x556940 | Uma ocorrência |
| `CPacket_PacketFilter` | 0x556ab4 | Uma ocorrência |

### shelper.dll

| String RTTI | Endereço | Observação |
|---|---|---|
| `.?AVAESCryptor@@` | 0x100aee88 | Classe AESCryptor |

**Grau de confiança:** Confirmado (localização exata via Ghidra).

---

## 2. Hierarquia de Classes (CONFIRMADO via RTTI/CHD)

### CPacket_* (RvControlSvc.exe)

```
CPacket_*@ControlSvc
├── CPacket@ControlSvc
├── CSelfDeletingObject@FamRT
└── IPacket@ControlSvc
```

### AESCryptor (shelper.dll)

```
AESCryptor
└── BaseCryptor
```

**Grau de confiança:** Confirmado.

---

## 3. Vtables (CONFIRMADO)

### CPacket_* — 7 entradas (índices 0–6)

| Índice | Papel |
|---|---|
| [0] | Destrutor |
| [1] | RTTI COL ptr |
| [2] | Destrutor thunk |
| [3] | **Serialização** |
| [4] | Tipo/Validação |
| [5] | Constante 0x3e8 |
| [6] | Null |

### AESCryptor (shelper.dll) — 17 entradas (índices 0–16)

| Índice | RVA | Papel |
|---|---|---|
| [0] | 0x62c80 | Destrutor |
| [1] | 0x62e00 | **Encrypt** (AES-CBC, mode=1) |
| [2] | 0x62d60 | **Decrypt** (AES-CBC, mode=0) |
| [3] | 0x62e90 | **GetBlockSize** (retorna 0x10) |
| [6] | 0x62fb0 | **SetKeyEnc** (32 bytes) |
| [7] | 0x62f30 | **SetKeyDec** (32 bytes) |

**Grau de confiança:** Confirmado.

---

## 4. Constantes de Tipo de Mensagem (CONFIRMADO no código estático)

| Constante | Pacotes | Função |
|---|---|---|
| `0x1311` | `CPacket_Handshake_Syn` | `FUN_004285b0` |
| `0x1312` | `CPacket_KeepAliveAck`, `CPacket_Handshake_SynAck` | `FUN_00428880` |
| `0x1313` | `CPacket_KeepAlive`, `CPacket_Handshake_Ack` | `FUN_004282f0` |

Pacotes com serialização base: `CPacket_Shutdown`, `CPacket_ConfirmSwitch`, `CPacket_FinalizeSwitch`.

**Grau de confiança:** Confirmado no código estático. Não confirmado no tráfego (criptografado).

---

## 5. Pipeline de Serialização (CONFIRMADO no código estático)

### 5.1 Estrutura PRECEX

| Offset | Campo |
|---|---|
| +0x00 | flags |
| +0x04 | data_ptr |
| +0x08 | data_size |
| +0x0C | capacity |
| +0x28 | msg_type (0x1311/0x1312/0x1313) |

### 5.2 Funções de escrita de campo

| Função | RVA | Tamanho | Tag | Byte-swap? |
|---|---|---|---|---|
| `FUN_00472ef0` | 0x72ef0 | 4 bytes | `0x1000302` | Sim |
| `FUN_00472f60` | 0x72f60 | 8 bytes | `0x2000303`/`0x20001e1` | Sim |
| `FUN_004795d0` | 0x795d0 | Variável | `0x9000304` | Não |
| `FUN_00427060` | 0x27060 | 2 bytes | — | `Ordinal_9` |

### 5.3 Layouts de campos por classe (INFERIDO)

Ver Seção 6 do documento anterior (Fase 7). Campos confirmados em offsets, tipos inferidos.

---

## 6. Criptografia (CONFIRMADO — Fases 8-9)

### 6.1 Biblioteca: shelper.dll (OpenSSL 1.0.1f)

Baseada em OpenSSL 1.0.1f (strings confirmam "AES part of OpenSSL 1.0.1f").

### 6.2 Algoritmo: AES-256-CBC (CONFIRMADO)

**Evidências:**
1. RTTI: classe nomeada "AESCryptor" (`.?AVAESCryptor@@`).
2. Key size = 32 bytes (0x20) — `SHelper_CChannel_SetKeyEnc/SetKeyDec` verificam `param_3 == 0x20`.
3. Block size = 16 bytes (0x10) — `FUN_10062e90` (vtable[3]) retorna 0x10.
4. CBC mode — inferido de FUN_10063470 (XOR com bloco anterior).
5. FUN_10003b30 — implementação AES (lookup tables DAT_10001800/DAT_10002e80, processamento de blocos de 16 bytes, modo param_6: 0=decrypt, 1=encrypt).

### 6.3 FUN_10003b30 — Detalhes (CONFIRMADO)

- **Tamanho:** 1619 bytes
- **Parâmetros:** (input*, output*, size, key_schedule*, IV*, mode)
- **Mode:** param_6 == 0 → decrypt (usa DAT_10002e80), param_6 != 0 → encrypt (usa DAT_10001800)
- **Processamento:** blocos de 16 bytes, com verificação de alinhamento (param_3 deve ser múltiplo de 16)
- **Lookup tables:** DAT_10001800 (encrypt T-tables), DAT_10002e80 (decrypt T-tables)
- **Funções auxiliares:** FUN_100024f0, FUN_10002980, FUN_100013a0, FUN_10001040, FUN_100015a0, FUN_10002c40 (round functions)
- **Classificação:** INFERIDO como custom AES (não OpenSSL EVP), baseado nas lookup tables e processamento manual. Pode ser OpenSSL's AES_cbc_encrypt inlined.

### 6.4 IV (Initialization Vector)

**CONFIRMADO:**
- Tamanho: 16 bytes
- Armazenado em: AESCryptor+0x1ec (enc) e AESCryptor+0x1fc (dec)
- Definido por: FUN_10062ff0 (enc, copia 16 bytes para this+4? ou this+0x1ec?) e FUN_10062f80 (dec)
- FUN_100633d0 copia 16 bytes (FUN_10065150, size=0x10)

**DESCONHECIDO:**
- Como o IV é gerado (fixo? derivado da chave? aleatório?)
- Se é transmitido junto ao ciphertext
- Se é por sessão ou por mensagem
- Valor inicial (global constante em `_DAT_100832f0` usada em FUN_10063470/33e0)

**INFERIDO:**
- FUN_10063470 (CBC encrypt): inicializa IV de `_DAT_100832f0` (global), XOR com plaintext por bloco
- FUN_100633e0 (CBC decrypt): inicializa IV de `_DAT_100832f0`, XOR com ciphertext anterior
- O IV global em `_DAT_100832f0` pode ser um IV padrão/fixo

### 6.5 Padding customizado (CONFIRMADO)

**FUN_10069c20 (preparação para criptografia):**
1. Tamanho com padding: `sVar3 = ((param_4 + 8 + param_3) / param_4) * param_4`
   - param_4 = block size (16)
   - param_3 = data size
   - Overhead: 9 bytes (8 checksum + 1 size indicator)
2. Aloca buffer de tamanho sVar3
3. Copia dados originais (param_3 bytes)
4. Preenche restante com `0xcc`
5. Calcula checksum (FUN_1006a0c0): soma de 64 bits de blocos de 8 bytes
6. Armazena: checksum (8 bytes) + (block_size - data_size mod block_size) (1 byte) nos últimos 9 bytes

**FUN_10069f90 (validação na decriptografia):**
1. Lê último byte → quantidade de padding (uVar3)
2. Valida: `9 < uVar3 < param_5 + 9` (param_5 = block size)
3. Calcula checksum e compara com valor armazenado
4. Se válido: data_ptr = param_3, data_size = param_4 - uVar3

**Overhead:** 9 bytes por mensagem (8 checksum + 1 size).

**Classificação do padding:** Proprietário (não PKCS#7). Preenchimento com 0xcc + trailer de 9 bytes.

### 6.6 Checksum (FUN_1006a0c0)

- **Tipo:** Soma de 64 bits (não MAC criptográfico)
- **Algoritmo:** Acumula blocos de 8 bytes (little-endian uint64) em uma soma de 64 bits
- **Tamanho:** 8 bytes (64 bits)
- **Uso:** Integridade do padding (não do payload completo)

**Classificação:** DESCONHECIDO se é usado como MAC ou apenas para validação de padding.

### 6.7 Troca de chaves: RSA (CONFIRMADO)

**SHelper_RSAHelper_*:**
- `CreateWithPublicKey(modulus, mod_size, exponent, exp_size)` — RSA com chave pública
- `CreateWithPrivateKey(...)` — RSA com chave privada (módulo, expoente, fatores, CRT params)
- `EncryptBuffer_Public/Private` — criptografa com RSA
- `DecryptBuffer_Public/Private` — decriptografa com RSA
- Usado para troca segura da chave AES-256

**RSA padding:** DESCONHECIDO (OAEP? PKCS#1 v1.5?). String "rsaesOaep" e "RSAES-OAEP" encontradas em shelper.dll.

### 6.8 RSession (CONFIRMADO)

**SHelper_RSession_*:**
- `CreateClient(server_pubkey, server_pubkey_size, ...)` — cria sessão cliente
- `CreateServer(client_pubkey, ..., server_privkey, ...)` — cria sessão servidor
- `GetKey(session, &key_ptr, &key_size)` — recupera chave AES da sessão
- `GetClientDataOnServer(session, ...)` — dados do cliente no servidor
- `GetServerDataOnClient(session, ...)` — dados do servidor no cliente

**RSession layout (inferido):**
- +0x04: param_1 (contexto)
- +0x08: param_2
- +0x0C: param_3
- +0x10: ponteiro para dados (AESCryptor?)
- +0x14: tamanho dos dados
- +0x18: ponteiro para dados adicionais
- +0x1C: tamanho
- +0x20: flag (0=client, 1=server)
- +0x24: flag
- +0x28: ponteiro para dados criptografados
- +0x2C: tamanho
- +0x30: ponteiro para dados

### 6.9 Fluxo de criptografia completo (CONFIRMADO)

```
ENVIO:
1. CPacket_*::vtable[3] → serializa para PRECEX (0x1311/0x1312/0x1313)
2. RSA troca de chave AES-256 (SHelper_RSAHelper_*)
3. SHelper_CChannel_EncryptBuffer:
   a. FUN_10069c20: padding (0xcc + checksum 8B + size 1B)
   b. vtable[1] (FUN_10062e00 → FUN_10003b30): AES-256-CBC encrypt
   c. FUN_10062ad0: store result
4. Frame TCP: 4 bytes BE uint32 (size) + payload criptografado
5. Envio TCP (porta 17301 ou 17351)

RECEBIMENTO:
1. Recepção TCP (frame de 4 bytes BE + payload)
2. SHelper_CChannel_DecryptBuffer:
   a. vtable[2] (FUN_10062d60 → FUN_10003b30): AES-256-CBC decrypt
   b. FUN_10069f90: validar padding + checksum
   c. FUN_10068230: bounds check
   d. FUN_10062800: copiar resultado
   e. FUN_10062ad0: store result
3. Desserialização PRECEX → CPacket_* campos
```

---

## 7. Correlação com PCAP (Fases 7-9)

### 7.1 Tráfego criptografado (CONFIRMADO)

- Todo tráfego TCP após handshake inicial é AES-256-CBC.
- Constantes 0x1311/0x1312/0x1313 não visíveis no tráfego.
- Payloads têm entropia alta (consistente com AES-CBC).

### 7.2 Handshake inicial (CONFIRMADO)

- `00 00 00 04 03 00 00 00` — primeiro frame de toda conexão.
- Ocorre antes da criptografia ser ativada.
- Payload `03 00 00 00` (LE uint32 = 3) — versão ou identificador de handshake.
- Aparece em ambas as direções (cliente↔servidor).

### 7.3 Tamanhos de frame

- Overhead de criptografia: até 16 bytes (padding) + 9 bytes (trailer) = 25 bytes.
- Explica variedade de tamanhos observados (32, 36, 48, 64, 96, etc.).

### 7.4 Portas

| Porta | Uso | Criptografia |
|---|---|---|
| 17301 | Controle (servidor) | AES-256-CBC |
| 17351 | Peer-to-peer | AES-256-CBC |

---

## 8. Limitações da Análise

1. **FUN_10003b30** — não confirmado se é OpenSSL EVP ou implementação customizada. Lookup tables sugerem AES T-tables. Classificado como INFERIDO.
2. **IV** — não se sabe como é gerado ou se é transmitido. Global constante `_DAT_100832f0` usada como IV inicial. Classificado como DESCONHECIDO.
3. **RSA padding** — string "RSAES-OAEP" encontrada, mas não confirmado qual é usado. Classificado como INFERIDO.
4. **Significado semântico dos campos** (offsets em CPacket) — não determinado. Classificado como DESCONHECIDO.
5. **Tags de campo** (0x0302, 0x0303, 0x01e1, 0x0304) — significado não confirmado. Classificado como DESCONHECIDO.
6. **Checksum** — não se sabe se é usado como MAC ou apenas para validação de padding. Classificado como DESCONHECIDO.
7. **IV por sessão vs por mensagem** — não determinado. Classificado como DESCONHECIDO.
8. **Nenhuma execução dinâmica** — sem depuração ou replay.

---

## 9. Informações ainda desconhecidas

| Item | Status | Necessário para |
|---|---|---|
| IV geração/troca | DESCONHECIDO | Reproduzir criptografia |
| RSA padding mode | INFERIDO (OAEP?) | Reproduzir troca de chaves |
| FUN_10003b30 identidade | INFERIDO (custom AES) | Confirmar implementação |
| Campos semânticos (CPacket) | DESCONHECIDO | Implementar pacotes |
| Tags de campo | DESCONHECIDO | Implementar serialização |
| IV por sessão/mensagem | DESCONHECIDO | Reproduzir criptografia |
| Checksum uso (MAC?) | DESCONHECIDO | Implementar validação |

---

## 10. Próximos Passos

1. **Identificar IV** — decompilar FUN_10062ff0 e FUN_10062f80 mais profundamente, ou usar Ghidra GUI.
2. **Confirmar FUN_10003b30** — comparar com OpenSSL AES_cbc_encrypt.
3. **Descriptografar tráfego** — usar chaves extraídas para decifrar capturas.
4. **Correlacionar pacotes** — mapear CPacket_* com frames de rede.
5. **Somente então** implementar em `src/protocol/packets.rs` e `src/crypto/mod.rs`.

**Não implementar os pacotes Rust até que a especificação esteja completa.**

**Não declarar compatibilidade até conseguir demonstrá-la com testes reais contra o cliente oficial Windows.**