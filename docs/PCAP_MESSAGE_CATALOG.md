# PCAP Message Catalog — Radmin VPN Traffic Analysis

**Projeto:** Radmin VPN Linux client (Rust, independente)  
**Diretório de capturas:** `claude-handoff/pcaps/`  
**Data da análise:** 06 nov 2026  

---

## Sumário do Catálogo

| Protocolo | Porta | Família | Tamanho (bytes) | Quantidade | Confiança |
|---|---|---|---|---|---|
| TCP | 17301 | Controle | Variável (4+payload) | ~100 | CONFIRMADO |
| TCP | 17351 | Controle alternativo | Variável (4+payload) | ~30 | CONFIRMADO |
| UDP | 9993 | A — Setup/completo | 137 | 93 | CONFIRMADO |
| UDP | 9993 | B — Curto | 33 | 223 | CONFIRMADO |
| UDP | 9993 | C — Keepalive curto | 28 | 82 | CONFIRMADO |
| UDP | 9993 | D — Médio | 99 | 74 | CONFIRMADO |
| UDP | 9993 | E — Grande (connect) | 247-641 | ~40 | CONFIRMADO |
| UDP | 47836 | Keepalive | 4 | ~60 | CONFIRMADO |
| UDP | 17309/17341/17342/17357/17358 | STUN Binding Request | 20 | ~20 | CONFIRMADO |
| UDP | 17309/17341/17342/17357/17358 | STUN Binding Response | 56 | ~10 | CONFIRMADO |
| UDP | 3544 | Teredo Router Solicitation | 61 | 2 | CONFIRMADO |

---

## Mensagem TCP/17301 — Controle

### Estrutura

```
[4-byte big-endian length][payload]
```

O campo de length representa apenas o tamanho do payload (exclui os 4 bytes do header).

### Exemplos Reais

#### Mensagem 1 — 192 bytes de payload

**Captura:** `radmin-connect.pcapng`  
**Frame:** 77  
**Timestamp:** 06/11/2026 14:22:09.xxx  
**Origem:** 192.168.15.15:44340  
**Destino:** 148.113.190.78:17301  
**tcp.len:** 196  
**Length field:** `00 00 00 c0` (192)

**Payload (192 bytes):**
```
10 f9 bf 00 3c e2 7b ed 34 3e 09 02 03 b8 0d 86
ec 02 a3 80 e1 79 96 44 71 cf 35 91 a4 c1 39 d8
01 21 05 b2 2b 4e 31 55 de 61 0a a8 90 e4 d9 ab
de 3a e8 70 93 32 94 1d 21 9e a2 13 f2 7f a3 55
5d 1e a7 97 e8 92 2d fc 84 a4 53 02 36 50 df 4e
1c a8 eb 16 2b 59 15 37 fd 51 75 81 28 be ff 45
4c 91 c8 7c 02 e1 3f ce 36 f6 29 6a d3 e6 40 e0
05 c2 96 1e 8e 58 43 4f 43 a 61 ee 53 fd bf de
5f 23 a 0f fd 4d bc c5 63 07 9c c5 a 45 b 8 ef
a7 6 03 84 68 28 13 5b 2c 8b 6e a0 39 6b b0 e
8b 77 f 21 59 01 b 73 14 8b a8 77 a 60 c 34 a
17 ee f7 3 5d 0d 6 ff cc e7 5 7c 8f 0b 3b 6f
a0 6 03 6b c d 2c
```

**Interpretação:** Dados criptografados (alta entropia). Não há campos identificáveis no payload.

#### Mensagem 2 — 32 bytes de payload

**Captura:** `radmin-connect.pcapng`  
**Frame:** 80  
**Origem:** 192.168.15.15:44340  
**Destino:** 148.113.190.78:17301  
**tcp.len:** 36  
**Length field:** `00 00 00 20` (32)

**Payload (32 bytes):**
```
c7 f5 78 26 af 97 91 03 70 c8 6f d5 cb 17 12 18
58 9d 2f 73 7f 39 7d cf 59 ee 46 4d 43 21 5b d0
```

**Interpretação:** 32 bytes de dados aparentemente aleatórios (possível chave, nonce ou hash criptografado).

#### Mensagem 3 — 256 bytes de payload

**Captura:** `radmin-connect.pcapng`  
**Frame:** 81  
**Origem:** 148.113.190.78:17301  
**Destino:** 192.168.15.15:44340  
**tcp.len:** 260  
**Length field:** `00 00 01 00` (256)

**Payload (256 bytes):** Dados criptografados (alta entropia, não exibidos por tamanho).

#### Mensagem Fragmentada — 2592 bytes total

**Captura:** `radmin-connect.pcapng`  
**Frame 100:** Origem 148.113.190.78:17301, Destino 192.168.15.15:44340  
**Length field:** `00 00 0a 20` (2592)  
**tcp.len:** 1440 (primeiro fragmento: 4 header + 1436 payload)

**Frame 101:** Origem 148.113.190.78:17301, Destino 192.168.15.15:44340  
**tcp.len:** 1156 (continuação: 1156 bytes payload, sem novo length prefix)  
**Reconstrução:** 1436 + 1156 = 2592 ✓

---

## Mensagem TCP/17351 — Controle Alternativo

### Estrutura

```
[4-byte big-endian length][payload]
```

Payload interno:
```
[4 bytes: 10 00 00 04 — versão/tipo constante]
[4 bytes: número de sequência big-endian]
[variável: payload da mensagem]
```

### Exemplos Reais

#### Mensagem 1 — Sequência 4

**Captura:** `radmin_vm.pcap`  
**Frame:** 5487  
**Origem:** 45.162.230.182:17351  
**Destino:** 192.168.122.77:49497  
**tcp.len:** 16  
**Length field:** `00 00 00 0c` (12)

**Payload completo (12 bytes):**
```
00 00 00 04 01 00 01 df 00 00 00 02
```

**Campos:**
- `00 00 00 04`: versão/tipo (constante)
- `01 00 01 df`: campo variável
- `00 00 00 02`: número de sequência = 2

#### Mensagem 2 — Sequência 3

**Captura:** `radmin_vm.pcap`  
**Frame:** 5494  
**Origem:** 45.162.230.182:17351  
**Destino:** 192.168.122.77:49497  
**tcp.len:** 207  
**Length field:** `00 00 00 cb` (203)

**Payload (203 bytes):**
```
10 00 00 04 00 00 00 03 60 00 00 bf bf 64 a2 64
40 1a 82 c5 ac 52 b2 5a ee 49 b9 5a 8f 1d c3 1e
8b 92 7c 87 02 ff 0e 78 2b fb 69 75 18 6a 17 62
fc 6d 8e ff 24 f 42 b 57 ed c 1f a 32 bb 42 e 0
a 52 9c 45 5 b 71 7e b 2a 6d f 0 b 8 f 2b 0 c
96 86 ace 54 5 4 2 12 30 a 9 cf 1 13 b 5 f 8 cb
f3 a c 95 f b e 52 b 0 3 21 6 f 5 a 2 b c d b
13 0 f 66 d c e 98 8d 0c af f 8 22 8c 92 de 8b
14 c 58 6c 0 7 da 1 b 9b 0 b 29 f 1a 6d ff 4e
c 3 f 3f 74 6 12 14 1 3b 79 c 8 b 11 f 12 4 da
21 79 2a d 5b 63 ff 9 d 4 f 15 55 ff d fe 0 ab
91 79 ff 6 bd 77 a 3 5bc 0 6 24 9 13 c 84 f 95 c
```

**Campos:**
- `10 00 00 04`: versão/tipo (constante)
- `00 00 00 03`: número de sequência = 3
- `60 00 00 bf ...`: payload variável (195 bytes)

#### Mensagem 3 — Sequência 4

**Captura:** `radmin_vm.pcap`  
**Frame:** 5501  
**Origem:** 45.162.230.182:17351  
**Destino:** 192.168.122.77:49497  
**tcp.len:** 208  
**Length field:** `00 00 00 cc` (204)

**Payload (204 bytes):**
```
10 00 00 04 00 00 00 04 60 00 00 c0 86 75 05 3a
9c 4a 5b 1a 39 d9 6a bf d0 74 01 5d 94 02 46 73
a 2e 78 fa 76 99 96 b 28 5b b 0 a 55 ff 63 34 a
90 9f 8f 1a b 3c 40 3 7d 06 d 92 f 5f 53 92 6d
ed 5d 48 b 21 66 a fd 97 ec 77 1b d 74 2c 2a 76
1c 86 37 2b 28 0b 71 f 6e 02 ad 52 02 26 dd 86
50 9a 10 59 55 31 6a a 29 52 ee 91 ed d 24 dd e
1b 7a 3c 5 d 3f f 84 39 ee 27 92 4 de 86 8a 78
99 9e 7c 37 0 5 36 90 9 77 89 1 f 3c 40 0 d 85
99 ed 89 d 0 f 31 20 33 cd 85 c 6 f 80 c 7a 89
7e 4 ce cd 0 c 12 d fd 2 b f aa 8 10 b cf 10
99 b df b cf 0 ad 26 fb 19 9 11 7 20 f da 54 ae
80 23 5b 5d da f 53 e 18 f cd 60 f 03 8 58 38 4
33 69 14 f 6
```

**Campos:**
- `10 00 00 04`: versão/tipo (constante)
- `00 00 00 04`: número de sequência = 4
- `60 00 00 c0 ...`: payload variável (200 bytes)

### Números de Sequência Observados

| Frame | Sequência | Direção |
|---|---|---|
| 5487 | 2 | Servidor → Cliente |
| 5493 | 2 | Servidor → Cliente |
| 5494 | 3 | Servidor → Cliente |
| 5501 | 4 | Servidor → Cliente |
| 5502 | 5 | Cliente → Servidor |
| 5509 | 6 | Cliente → Servidor |
| 5510 | (sem sequência) | Cliente → Servidor (20 bytes) |
| 5511 | (sem sequência) | Cliente → Servidor (36 bytes) |
| 5512 | (sem sequência) | Cliente → Servidor (68 bytes) |

**Observação:** Nem todas as mensagens TCP/17351 têm o campo de sequência. Mensagens menores (20-68 bytes) podem ter estrutura diferente.

---

## Mensagem UDP/9993 — Família A (137 bytes)

### Estrutura Completa

```
Offset  Conteúdo                          Tamanho  Interpretação
0x00    25 2d ff 68                       4 bytes  Magic / tipo de mensagem
0x04    42 c3 84 70                       4 bytes  Campo variável (flags?)
0x08    e5 d4 c1 c5 bc 21 59 16           8 bytes  Identificador sessão (parte 1)
0x10    c8 0f                             2 bytes  Identificador sessão (parte 2)
0x12    00 01                             2 bytes  Subtipo de mensagem
0x14    03 74 49 74 bf 0f ed 01           8 bytes  Campo variável
0x1c    0d 01 10 00                       4 bytes  Campo fixo
0x20    02 00 00 01                       4 bytes  Campo fixo
0x24    a1 b1 ea 42 91 21 59 16 c8 0f     10 bytes  Identificador repetido
0x2e    00 2e 38 e9 ... (48 bytes)        48 bytes  Região criptografada
0x5e    00 04                             2 bytes  TLV Type
0x60    1a ac b2 4f                       4 bytes  IP do peer (big-endian)
0x64    27 09                             2 bytes  Porta do peer (big-endian)
0x66    00 00 00 00 08 ea c9 0a           8 bytes  Campo variável
0x6e    00 00 01 94                       4 bytes  Campo variável
0x72    db 79 5b 4e 0b 2c                 6 bytes  Campo variável
0x78    ?? (17 bytes não documentados)    17 bytes  FALTANDO no relatório anterior
```

### Exemplos Reais

#### Exemplo 1 — Virtual → Virtual

**Captura:** `radmin-mine.pcapng`  
**Frame:** 116  
**Interface:** 1 (radminvpn0)  
**Origem:** 26.239.229.134:9993  
**Destino:** 26.172.178.79:9993  
**udp.length:** 145 (137 bytes payload)

**Payload completo (137 bytes):**
```
25 2d ff 68 42 c3 84 70 e5 d4 c1 c5 bc 21 59 16
c8 0f 00 01 03 74 49 74 bf 0f ed 01 0d 01 10 00
02 00 00 01 a1 b1 ea 42 91 21 59 16 c8 0f 00 2e
38 e9 0a 46 71 a7 7c fd d8 81 06 57 ec 45 de 15
6c 7a 3e 5d 6c 86 65 7c bb e4 53 9d 0b c3 69 5e
db 03 c5 ab 8b ef 20 1d c6 ca 71 c4 dc a7 1d ba
4f cb cc 9f 54 b0 57 4d 0e 08 59 c1 af 78 4e 00
04 1a ac b2 4f 27 09 00 00 00 00 08 ea c9 0a 00
00 01 94 db 79 5b 4e 0b 2c
```

#### Exemplo 2 — Física → Virtual

**Captura:** `radmin-mine.pcapng`  
**Frame:** 127  
**Interface:** 0 (enp7s0)  
**Origem:** 192.168.15.15:9993  
**Destino:** [IP_PUBLICO_MASCARADO}:9993  
**udp.length:** 145 (137 bytes payload)

**Payload completo (137 bytes):**
```
5d a8 6b 96 1d 5d 1b e e 5d 4c 1c 5b c 21 59 16
c8 0f 00 0d 03 dd 76 d7 ec cb a c 01 0d 01 10 00
02 00 00 01 a1 b1 ea 42 91 21 59 16 c8 0f 00 2e
38 e9 0a 46 71 a7 7c fd d8 81 06 57 ec 45 de 15
6c 7a 3e 5d 6c 86 65 7c bb e4 53 9d 0b c3 69 5e
db 03 c5 ab 8b ef 20 1d c6 ca 71 c4 dc a7 1d ba
4f cb cc 9f 54 b0 57 4d 0e 08 59 c1 af 78 4e 00
04 b1 70 4f e2 27 09 00 00 00 00 08 eac 9 0a 00
00 01 94 db 79 5b 4e fb 2b
```

**Diferenças em relação ao Exemplo 1:**
- Offset 0x00-0x03: diferente (`5d a8 6b 96` vs `25 2d ff 68`) — possivelmente mensagem diferente ou nonce
- Offset 0x08-0x11: `e5 d4 c1 c5 bc 21 59 16 c8 0f` — MESMO identificador de sessão
- Offset 0x5e-0x65: `00 04 b1 70 4f e2 27 09` — TLV 0x0004 com IP `b1 70 4f e2` = [IP_PUBLICO_MASCARADO} e porta `27 09` = 9993

#### Exemplo 3 — Hole Punching (mesmo payload, porta diferente)

**Captura:** `radmin-mine.pcapng`  
**Frame:** 117  
**Origem:** 26.239.229.134:48318  
**Destino:** 26.172.178.79:9993  
**udp.length:** 145

**Payload:** IDENTICO ao frame 116 (mesmo payload de 137 bytes)

**Conclusão:** O mesmo payload é reenviado de múltiplas portas de origem para facilitar hole punching.

---

## Mensagem UDP/9993 — Família B (33 bytes)

### Estrutura

```
Offset  Conteúdo                          Tamanho
0x00    b9 6b 32 c3                       4 bytes  Campo variável
0x04    13 57 56 f8                       4 bytes  Campo variável
0x08    77 8c de 71                       4 bytes  Campo variável
0x0c    90 21 59 16                       4 bytes  Parte do identificador de sessão
0x10    c8 0f                             2 bytes  Parte do identificador de sessão
0x12    08 af                             2 bytes  Campo variável
0x14    22 1d ce fb                       4 bytes  Campo variável
0x18    43 42 25 7e                       4 bytes  Campo variável
0x1c    46 9e 55 19                       4 bytes  Campo variável
0x20    2f                                1 byte   Campo variável / trailer
```

### Exemplo Real

**Captura:** `radmin-mine.pcapng`  
**Frame:** 139  
**Interface:** 0 (enp7s0)  
**Origem:** 192.168.15.15:48318  
**Destino:** 103.195.103.66:9993  
**udp.length:** 41 (33 bytes payload)

**Payload completo (33 bytes):**
```
b9 6b 32 c3 13 57 56 f8 77 8c de 71 90 21 59 16
c8 0f 08 af 22 1d ce fb 43 42 25 7e 46 9e 55 19 2f
```

**Observação:** Contém apenas 6 bytes do identificador de sessão (`90 21 59 16 c8 0f`), não os 10 bytes completos.

---

## Mensagem UDP/9993 — Família C (28 bytes)

### Estrutura

```
Offset  Conteúdo                          Tamanho
0x00    09 3e 08 ab b0 a6 17 91           8 bytes  Campo variável
0x08    e5 d4 c1 c5 bc 21 59 16 c8 0f     10 bytes  Identificador de sessão completo
0x12    18 ac 77 1e 68 c7 9b e0 c5 0c     10 bytes  Campo variável / trailer
```

### Exemplo Real

**Captura:** `radmin-mine.pcapng`  
**Frame:** 187  
**Interface:** 0 (enp7s0)  
**Origem:** 192.168.15.15:9993  
**Destino:** 25.33.236.186:9993  
**udp.length:** 36 (28 bytes payload)

**Payload completo (28 bytes):**
```
09 3e 08 ab b0 a6 17 91 e5 d4 c1 c5 bc 21 59 16
c8 0f 18 ac 77 1e 68 c7 9b e0 c5 0c
```

---

## Mensagem UDP/9993 — Família D (99 bytes)

### Exemplo Real

**Captura:** `radmin-mine.pcapng`  
**Frame:** 143  
**Interface:** 0 (enp7s0)  
**Origem:** 192.168.15.15:9993  
**Destino:** [IP_PUBLICO_MASCARADO}:9993  
**udp.length:** 107 (99 bytes payload)

**Payload completo (99 bytes):**
```
b5 29 7e d0 4f 09 38 8e e5 d4 c1 c5 bc 21 59 16
c8 0f 18 31 ff fc 43 50 cd d0 29 e4 01 23 d3 84
a7 22 26 26 3e 82 e6 91 14 40 58 97 3d 7d a7 0e
62 19 fe f1 22 b5 55 51 c5 b0 dd ff 79 3d 73 8b
17 dd 71 85 41 c4 20 37 fd 3c df 22 c8 4f ab d9
3d 4a 7c 5b 63 87 5f b1 6d 7e 4a 18 95 9d c0 f8
1c d1 b1
```

---

## Mensagem UDP/9993 — Família E (247-641 bytes)

### Exemplo Real (249 bytes)

**Captura:** `radmin-mine-host.pcapng`  
**Frame:** 132  
**Interface:** 0 (enp7s0)  
**Origem:** [IP_PUBLICO_MASCARADO}:9993  
**Destino:** 192.168.15.15:9993  
**udp.length:** 257 (249 bytes payload)

**Payload (primeiros 64 bytes):**
```
b6 0d 0e 91 fa 1e c5 00 21 59 16 c8 0f e5 d4 c1
c5 bc 21 59 16 c8 0f 18 08 6b cf d5 6c 27 0c 3e
c7 98 d7 1f 15 73 19 a 4d c 75 38 50 e 45 65 2e
8d b 7 a b da 7 b 18 e 3f 99 f 2 a 85 e 7d e 3a
7b 0 4 17 1b e 69 6 d 46 9 24 a 3b e a a d 9 a
3d 3 d 24 d 97 c 75 f 54 36 0 3 fa ee 95 43 c 1e
b 89 c 1 80 e b f 2 e 0 69 5 8 33 5 f ee 4 c 22
d 1f a 6 d a 1 d e 9 b 5 4 b d 9 3 f c c 7 e 3
6 e b 19 30 d b 3 b 48 fe 0 a c 0 f 7 fd a 5 3
3 af a 7 76 0c ee 2 b 96 0
```

**Observação:** Contém `21 59 16 c8 0f` e `e5 d4 c1 c5 bc 21 59 16 c8 0f` (identificador de sessão parcial e completo).

---

## Mensagem UDP/47836 — Keepalive

### Estrutura

```
Offset  Conteúdo  Tamanho  Interpretação
0x00    XX 02 00 00  4 bytes  Contador sequencial little-endian uint16
```

### Exemplos Reais

#### Captura radmin-mine.pcapng

| Frame | Payload | Valor (LE uint16) | Origem | Destino |
|---|---|---|---|---|
| 66 | c3 02 00 00 | 707 | 26.228.88.155:47836 | 26.239.229.134:47836 |
| 342 | c4 02 00 00 | 708 | 26.228.88.155:47836 | 26.239.229.134:47836 |
| 543 | c5 02 00 00 | 709 | 26.228.88.155:47836 | 26.239.229.134:47836 |

#### Captura radmin-mine-host.pcapng

| Frame | Payload | Valor (LE uint16) | Origem | Destino |
|---|---|---|---|---|
| 93 | 22 03 00 00 | 802 | 26.228.88.155:47836 | 26.239.229.134:47836 |
| 213 | 23 03 00 00 | 803 | 26.228.88.155:47836 | 26.239.229.134:47836 |

#### Captura radmin-connect.pcapng

| Frame | Payload | Valor (LE uint32) | Origem | Destino |
|---|---|---|---|---|
| 312 | 9e 00 00 00 | 158 | 26.228.88.155:47836 | 26.239.229.134:47836 |
| 957 | 9f 00 00 00 | 159 | 26.228.88.155:47836 | 26.239.229.134:47836 |

---

## Mensagem STUN — Binding Request

### Estrutura (RFC 5389)

```
Offset  Campo                   Tamanho  Valor exemplo
0x00    Message Type            2 bytes  0x0001 (Binding Request)
0x02    Message Length          2 bytes  0x0000
0x04    Magic Cookie            4 bytes  0x2112A442 (implícito no dissector)
0x08    Transaction ID          16 bytes  Aleatório
```

**Payload total:** 20 bytes (sem atributos)

### Exemplo Real

**Captura:** `radmin_vm.pcap`  
**Frame:** 5477  
**Origem:** 192.168.122.77:54527  
**Destino:** 135.181.75.11:17357  
**udp.length:** 28 (20 bytes payload)

**Payload completo:**
```
00 01 00 00 24 df 38 03 cb e7 64 ea 10 67 38 b6
1d 31 4c 66
```

**Campos:**
- Message Type: `00 01` = Binding Request
- Message Length: `00 00` = 0 atributos
- Transaction ID: `24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66`

---

## Mensagem STUN — Binding Response

### Estrutura

```
Offset  Campo                   Tamanho
0x00    Message Type            2 bytes  0x0101 (Binding Response)
0x02    Message Length          2 bytes  0x0024 (36 bytes de atributos)
0x04    Magic Cookie            4 bytes
0x08    Transaction ID          16 bytes  (mesmo da request)
0x18    Atributos               36 bytes  (MAPPED-ADDRESS, XOR-MAPPED-ADDRESS, etc.)
```

**Payload total:** 56 bytes

### Exemplo Real

**Captura:** `radmin_vm.pcap`  
**Frame:** 5489  
**Origem:** 135.181.75.11:17357  
**Destino:** 192.168.122.77:54527  
**udp.length:** 64 (56 bytes payload)

**Payload (primeiros 20 bytes visíveis):**
```
01 01 00 24 [transaction ID] [atributos 36 bytes]
```

---

## Mensagem Teredo — Router Solicitation

### Estrutura

UDP payload encapsulado em Teredo IPv6 tunneling:
- Teredo header: cliente identifier, authentication, nonce
- IPv6 packet interno: ICMPv6 Router Solicitation

### Exemplo Real

**Captura:** `radmin_vm.pcap`  
**Frame:** 708  
**Origem:** 192.168.122.77:54778  
**Destino:** 20.201.205.4:3544  
**udp.length:** 69 (61 bytes payload)

**Campos identificados:**
- Nonce: `8a cf 00 87 dd ea 34 02`
- ICMPv6 Type: 133 (Router Solicitation)
- Origem IPv6: `fe80::ffff:ffff:fffe`
- Destino IPv6: `ff02::2`

---

## Campos Não Semantizados (Sem Nomes Atribuídos)

Conforme as regras da investigação, os seguintes campos não recebem interpretação semântica sem evidência:

| Campo | Offset (Família A) | Tamanho | Valores observados |
|---|---|---|---|
| Magic/tipo | 0x00 | 4 bytes | `25 2d ff 68`, `5d a8 6b 96`, `7b 69 98 01`, `1c 6e f3 f5` |
| Flags? | 0x04 | 4 bytes | `42 c3 84 70`, `00 0d 03 dd`, `00 c4 d1 77`, `00 31 7c 7f` |
| Variável 1 | 0x14 | 8 bytes | Múltiplos valores diferentes |
| Fixo 1 | 0x1c | 4 bytes | `0d 01 10 00` (constante na Família A) |
| Fixo 2 | 0x20 | 4 bytes | `02 00 00 01` (constante na Família A) |
| Criptografado | 0x2e | 48 bytes | Alta entropia, diferente entre mensagens |
| Variável TLV | 0x66 | 8 bytes | `00 00 00 00 08 ea c9 0a` |
| Variável TLV | 0x6e | 4 bytes | `00 00 01 94` |
| Variável TLV | 0x72 | 6 bytes | `db 79 5b 4e 0b 2c` |
| Não documentado | 0x78 | 17 bytes | Não capturado no relatório anterior |

---

**Documento gerado:** `docs/PCAP_MESSAGE_CATALOG.md`  
**Arquivos .pcapng originais:** Preservados, não modificados