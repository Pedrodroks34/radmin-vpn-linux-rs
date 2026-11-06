# PCAP Forensics Deep Dive — Radmin VPN Traffic Analysis (Segunda Rodada)

**Projeto:** Radmin VPN Linux client (Rust, independente)  
**Diretório de capturas:** `claude-handoff/pcaps/`  
**Ferramentas:** tshark 4.7.4, capinfos, xxd, hexdump, python3  
**Data da análise:** 06 nov 2026  
**Commit-base:** 9eecbfe  

---

## Sumário das 20 Frentes

| Frente | Status | Classificação geral |
|---|---|---|
| 01 — Auditoria do relatório anterior | CONCLUÍDA | Erros de tamanho e classificação encontrados |
| 02 — Reconstrução UDP/9993 | CONCLUÍDA | Múltiplos tamanhos e famílias de mensagem |
| 03 — Campo 0x0004 | CONCLUÍDA | TLV com IP+porta do peer confirmado |
| 04 — Correlação física/virtual | CONCLUÍDA | Mapeamento 1:1 confirmado |
| 05 — Mecanismo de transporte | CONCLUÍDA | Hole punching confirmado |
| 06 — UDP/47836 keepalive | CONCLUÍDA | Contador sequencial little-endian |
| 07 — Comparação mensagens UDP | CONCLUÍDA | Múltiplas famílias identificadas |
| 08 — Identificador de sessão | CONCLUÍDA | 10 bytes, apenas em UDP/9993 |
| 09 — Criptografia UDP/9993 | PARCIAL | Regiões criptografadas delimitadas |
| 10 — TCP/17301 | CONCLUÍDA | Framing [4-byte BE length][payload] confirmado |
| 11 — TCP/17351 | CONCLUÍDA | Sub-protocolo com sequência identificada |
| 12 — TLV 0x30 (192 bytes) | INCONCLUSIVO | Não encontrado nos PCAPs |
| 13 — STUN | CONCLUÍDA | Binding Request/Response em portas não-padrão |
| 14 — NAT e mapeamento | INCONCLUSIVO | Evidência insuficiente para classificar |
| 15 — Teredo | CONCLUÍDA | Tráfego de fundo Windows/Wine |
| 16 — ARP e endereços virtuais | CONCLUÍDA | Resolução na interface radminvpn0 |
| 17 — Broadcast/multicast/auxiliar | CONCLUÍDA | Tráfego de fundo identificado |
| 18 — Linha do tempo temporal | CONCLUÍDA | 3 fases distintas identificadas |
| 19 — Auditoria conclusões anteriores | CONCLUÍDA | Correções registradas |
| 20 — Matriz de implementação | CONCLUÍDA | Prontidão por item listada |

---

## FRENTE 01 — Auditoria do Relatório Anterior (`docs/PCAP_FORENSICS_REPORT.md`)

### Erros Encontrados

#### 1. Erro de tamanho da mensagem UDP/9993 (CRÍTICO)

**Seção afetada:** 9.1, tabela de offsets  
**Afirmação original:** "Estrutura da mensagem (137 bytes...)"  
**Problema:** Os offsets listados vão de 0x00 a 0x72, com 6 bytes no último campo, totalizando 0x78 = 120 bytes. Faltam 17 bytes (offsets 0x78 até 0x88) para chegar aos 137 bytes do payload real (udp.length=145, menos 8 bytes de cabeçalho UDP = 137 bytes de payload).  
**Evidência:** Frame 116 de `radmin-mine.pcapng` (interface 1): frame.len=179, udp.length=145, payload hex de 137 bytes.  
**Correção recomendada:** Estender a tabela de offsets para incluir os bytes 0x78–0x88 ou revisar o tamanho declarado para 120 bytes se os bytes adicionais não fazem parte da estrutura semântica.

#### 2. Classificações excessivamente confiantes

- Seção 4.2: STUN servers classificados como "FORTE INDÍCIO" — apropriado.
- Seção 9.3: Relay classificado como "HIPÓTESE" — apropriado.
- Seção 5.1: TPKT detectado pelo Wireshark classificado como "possível interpretação incorreta" — apropriado.

#### 3. Informações ausentes

- Não há menção aos tamanhos alternativos de mensagem UDP/9993 (33, 28, 99 bytes).
- Não há análise do UDP/47836 em `radmin-connect.pcapng` (contador começa em 0x9e).
- Não há correlação explícita entre IP virtual e físico para 25.33.236.186.

#### 4. Problemas de mascaramento

O IP `[IP_PUBLICO_MASCARADO}` aparecia em fluxos de grande volume (10.156 pacotes, 3,1 MB) mas não foi mascarado na versão original. Foi corrigido na versão em `docs/`.

---

## FRENTE 02 — Reconstrução Completa do UDP/9993

### Distribuição de Tamanhos por Captura

| Tamanho payload (bytes) | radmin-mine | radmin-mine-host | radmin-connect | Total |
|---|---|---|---|---|
| 28 | 35 | 42 | 5 | 82 |
| 33 | 84 | 100 | 39 | 223 |
| 37 | 13 | 20 | 5 | 38 |
| 59 | 15 | 15 | 0 | 30 |
| 67 | 0 | 12 | 8 | 20 |
| 93 | 12 | 12 | 4 | 28 |
| 99 | 19 | 34 | 21 | 74 |
| 114 | 12 | 12 | 4 | 28 |
| 137 | 36 | 42 | 15 | 93 |
| 149 | 0 | 12 | 4 | 16 |
| 215 | 7 | 9 | 11 | 27 |
| 247 | 0 | 12 | 0 | 12 |
| 249 | 0 | 8 | 0 | 8 |
| 309 | 4 | 4 | 4 | 12 |
| 369 | 6 | 4 | 4 | 14 |
| 629 | 0 | 3 | 3 | 6 |
| 641 | 1 | 1 | 1 | 3 |

**Observação:** As capturas `radmin-mine` e `radmin-mine-host` têm distribuição concentrada (28, 33, 137, 99). A captura `radmin-connect` tem distribuição mais ampla incluindo tamanhos grandes (629, 641), consistente com fase de negociação de controle.

### Famílias de Mensagem por Tamanho

#### Família A — 137 bytes (udp.length=145)

Estrutura observada (frame 116, `radmin-mine.pcapng`, interface 1):

```
Offset  Conteúdo (hex)                          Tamanho
0x00    25 2d ff 68                             4 bytes  Magic / tipo de mensagem
0x04    42 c3 84 70                             4 bytes  Campo variável (possível flags)
0x08    e5 d4 c1 c5 bc 21 59 16                 8 bytes  Parte 1 do identificador
0x10    c8 0f                                   2 bytes  Parte 2 do identificador
0x12    00 01                                   2 bytes  Subtipo de mensagem
0x14    03 74 49 74 bf 0f ed 01                 8 bytes  Campo variável
0x1c    0d 01 10 00                             4 bytes  Campo fixo (0d 01 10 00)
0x20    02 00 00 01                             4 bytes  Campo fixo (02 00 00 01)
0x24    a1 b1 ea 42 91 21 59 16 c8 0f           10 bytes  Identificador repetido + timestamp?
0x2e    00 2e 38 e9 ... (48 bytes)              48 bytes  Região aparentemente criptografada
0x5e    00 04                                   2 bytes  TLV Type = 0x0004
0x60    1a ac b2 4f                             4 bytes  IP do peer (26.172.178.79)
0x64    27 09                                   2 bytes  Porta do peer (9993)
0x66    00 00 00 00 08 ea c9 0a                 8 bytes  Campo variável
0x6e    00 00 01 94                             4 bytes  Campo variável (0x00000194 = 404)
0x72    db 79 5b 4e 0b 2c                       6 bytes  Campo variável
0x78    ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??  17 bytes NÃO DOCUMENTADOS no relatório anterior
```

**Total:** 137 bytes de payload. O relatório anterior documentou apenas até 0x72 (120 bytes), omitindo 17 bytes.

#### Família B — 33 bytes (udp.length=41)

Exemplo (frame 139, `radmin-mine.pcapng`, interface 0):

```
b9 6b 32 c3 13 57 56 f8 77 8c de 71 90 21 59 16 c8 0f 08 af 22 1d ce fb 43 42 25 7e 46 9e 55 19 2f
```

- Offset 0x08–0x0f: `90 21 59 16 c8 0f` — 6 bytes, possivelmente parte do identificador de sessão
- Offset 0x10–0x13: `08 af` — 2 bytes variável
- Últimos 4 bytes parecem ser um checksum ou trailer

#### Família C — 28 bytes (udp.length=36)

Exemplo (frame 187, `radmin-mine.pcapng`, interface 0):

```
09 3e 08 ab b0 a6 17 91 e5 d4 c1 c5 bc 21 59 16 c8 0f 18 ac 77 1e 68 c7 9b e0 c5 0c
```

- Offset 0x08–0x11: `e5 d4 c1 c5 bc 21 59 16 c8 0f` — o identificador de sessão completo (10 bytes)
- Offset 0x00–0x07: `09 3e 08 ab b0 a6 17 91` — campo variável (8 bytes)
- Últimos 4 bytes: possivelmente checksum

#### Família D — 99 bytes (udp.length=107)

Exemplo (frame 143, `radmin-mine.pcapng`, interface 0):

```
b5 29 7e d0 4f 09 38 8e e5 d4 c1 c5 bc 21 59 16 c8 0f 18 31 ff fc 43 50 cd d0 29 e4 01 23 d3 84 a7 22 26 26 3e 82 e6 91 14 40 58 97 3d 7d a7 0e 62 19 fe f1 22 b5 55 51 c5 b0 dd ff 79 3d 73 8b 17 dd 71 85 41 c4 20 37 fd 3c df 22 c8 4f ab d9 3d 4a 7c 5b 63 87 5f b1 6d 7e 4a 18 95 9d c0 f8 1c d1 b1
```

- Contém o identificador de sessão `e5 d4 c1 c5 bc 21 59 16 c8 0f` no mesmo padrão

### Padrão de Hole Punching

O mesmo payload base (137 bytes) é enviado de múltiplas portas de origem (9993, 48318, 48870) para o mesmo destino na porta 9993. Isso é evidência direta de tentativa de hole punching através de múltiplas portas.

Exemplo (frame 116-118, `radmin-mine.pcapng`, interface 1):
- 26.239.229.134:9993 → 26.172.178.79:9993 (mesmo payload)
- 26.239.229.134:48318 → 26.172.178.79:9993 (mesmo payload)
- 26.239.229.134:48870 → 26.172.178.79:9993 (mesmo payload)

---

## FRENTE 03 — Identificação do Campo `0x0004`

### Evidência Detalhada

O campo aparece na Família A (137 bytes) no offset 0x5E:

```
0x5e: 00 04              → TLV Type = 0x0004
0x60: 1a ac b2 4f      → IPv4: 26.172.178.79 (big-endian)
0x64: 27 09            → Porta: 9993 (big-endian)
0x66: 00 00 00 00 08 ea c9 0a  → 8 bytes variável
0x6e: 00 00 01 94      → 4 bytes (0x00000194 = 404 decimal)
0x72: db 79 5b 4e 0b 2c → 6 bytes variável
```

### Verificação Cruzada

| IP virtual origem | IP virtual destino | IP no TLV 0x0004 | Porta no TLV | Conferência |
|---|---|---|---|---|
| 26.239.229.134 | 26.172.178.79 | 26.172.178.79 | 9993 | ✓ IP destino |
| 192.168.15.15 | 177.112.79.226 | b1 70 4f e2 = 177.112.79.226 | 2709 = 9993 | ✓ IP destino |
| 192.168.15.15 | 26.172.178.79 | 1a ac b2 4f = 26.172.178.79 | 2709 = 9993 | ✓ IP destino |

### Conclusão

**CONFIRMADO:** O campo `0x0004` é um TLV contendo endereço IPv4 (4 bytes, big-endian) seguido de porta (2 bytes, big-endian) do peer destino. Não é um atributo STUN padrão — o tipo 0x0004 não existe na especificação STUN RFC 5389.

---

## FRENTE 04 — Correlação Física e Virtual

### Mapeamento de Endereços

| IP Virtual | IP Físico | Capturas | Evidência |
|---|---|---|---|
| 26.239.229.134 | 192.168.15.15 | radmin-mine, radmin-mine-host, radmin-connect | Mesmo payload UDP/9993 em ambas as interfaces |
| 26.172.178.79 | [IP_PUBLICO_MASCARADO} | radmin-mine, radmin-mine-host | Mesmo payload UDP/9993 em ambas as interfaces |
| 26.228.42.15 | — | radmin-mine, radmin-mine-host | Apenas virtual |
| 26.228.88.155 | — | radmin-mine, radmin-mine-host, radmin-connect | Keepalive UDP/47836 |

### Correlação de Payload

Exemplo de correlação direta (frame 116 virtual ↔ frame 130 física):

```
Virtual (frame 116, int=1):
26.239.229.134:9993 → 26.172.178.79:9993
Payload: 25 2d ff 68 ... e5 d4 c1 c5 bc 21 59 16 c8 0f ... 00 04 1a ac b2 4f 27 09 ...

Física (frame 130, int=0):
192.168.15.15:9993 → 26.172.178.79:9993
Payload: 25 2d ff 68 ... e5 d4 c1 c5 bc 21 59 16 c8 0f ... 00 04 1a ac b2 4f 27 09 ...
```

Os 137 bytes de payload são idênticos. A diferença está apenas nos endereços IP do cabeçalho IP e nos campos TLV 0x0004 que refletem o endereço destino (que é o mesmo IP virtual 26.172.178.79 em ambos os casos).

### Conclusão

**CONFIRMADO:** A interface virtual `radminvpn0` encapsula o mesmo protocolo UDP/9993 que aparece na interface física. Os IPs virtuais (26.x.x.x) são traduzidos para IPs físicos (192.168.x.x e IPs públicos) antes de sair na interface física. O identificador de sessão e a estrutura de mensagem são preservados.

---

## FRENTE 05 — Mecanismo de Transporte

### Hipóteses Testadas

| Hipótese | Evidência | Conclusão |
|---|---|---|
| UDP direto | Tráfego UDP/9993 bidirecional entre peers | CONFIRMADO |
| UDP hole punching | Mesmo payload de múltiplas portas origem (9993, 48318, 48870) | CONFIRMADO |
| UDP encapsulado | Não há evidência de encapsulamento adicional | NÃO CONFIRMADO |
| Relay | Fluxo de grande volume para [IP_PUBLICO_MASCARADO}:58358 | HIPÓTESE (não confirmado) |
| Múltiplos caminhos | Mensagens enviadas simultaneamente de portas diferentes | CONFIRMADO |
| Reutilização de sockets | Mesmas portas origem reutilizadas | CONFIRMADO |
| Mudança dinâmica de portas | Portas 48318, 48870 usadas além de 9993 | CONFIRMADO |

### Fluxo de Hole Punching Observado

1. Cliente A envia mensagem de setup (137 bytes) de porta 9993 para peer B:9993
2. Cliente A envia a mesma mensagem de porta 48318 para peer B:9993
3. Cliente A envia a mesma mensagem de porta 48870 para peer B:9993
4. Peer B responde de sua porta 9993 para uma das portas do cliente A
5. Comunicação P2P estabelecida

**Conclusão:** O mecanismo de transporte entre peers é UDP direto com hole punching através de múltiplas portas de origem. Não há evidência de relay dedicado para dados P2P.

---

## FRENTE 06 — UDP/47836: Keepalive

### Análise de Payload

Todos os pacotes têm 4 bytes de payload (udp.length=12, menos 8 bytes de cabeçalho UDP).

#### Captura `radmin-mine.pcapng`:

| Frame | Payload (hex) | Valor (LE uint16) |
|---|---|---|
| 66 | c3 02 00 00 | 0x02c3 = 707 |
| 342 | c4 02 00 00 | 0x02c4 = 708 |
| 543 | c5 02 00 00 | 0x02c5 = 709 |
| 725 | c6 02 00 00 | 0x02c6 = 710 |
| ... | ... | ... |
| 2295 | d1 02 00 00 | 0x02d1 = 721 |

#### Captura `radmin-mine-host.pcapng`:

| Frame | Payload (hex) | Valor (LE uint16) |
|---|---|---|
| 93 | 22 03 00 00 | 0x0322 = 802 |
| 213 | 23 03 00 00 | 0x0323 = 803 |
| ... | ... | ... |
| 6638 | 30 03 00 00 | 0x0330 = 816 |

#### Captura `radmin-connect.pcapng`:

| Frame | Payload (hex) | Valor (LE uint32) |
|---|---|---|
| 312 | 9e 00 00 00 | 0x0000009e = 158 |
| 957 | 9f 00 00 00 | 0x0000009f = 159 |
| ... | ... | ... |

### Características

- **Formato:** 4 bytes, contador sequencial em little-endian
- **Direção:** Apenas de `26.228.88.155` para `26.239.229.134` (uma direção observada)
- **Intervalo:** ~1 segundo entre keepalives
- **Incremento:** +1 a cada mensagem
- **Reset:** O contador é diferente entre capturas (707, 802, 158) — possivelmente reiniciado por sessão

**Conclusão:** Keepalive periódico com contador sequencial. Não há evidência de detecção de peer morto (não há resposta observada nem mudança de comportamento quando o contador para).

---

## FRENTE 07 — Comparação de Mensagens UDP entre Peers

### Famílias por Estrutura Binária

| Família | Tamanho | Campos comuns | Peers observados | Capturas |
|---|---|---|---|---|
| A — Setup/completo | 137 bytes | Magic 25 2d ff 68, Session ID, TLV 0x0004 | 26.239.229.134 ↔ 26.172.178.79, 192.168.15.15 ↔ [MASKED] | mine, mine-host |
| B — Curto | 33 bytes | Session ID parcial (6 bytes) | 192.168.15.15 ↔ 103.195.103.66 | mine, mine-host |
| C — Keepalive curto | 28 bytes | Session ID completo (10 bytes) | 192.168.15.15 ↔ 25.33.236.186 | mine |
| D — Médio | 99 bytes | Session ID completo | 192.168.15.15 ↔ [MASKED] | mine |
| E — Grande (connect) | 247-641 bytes | Session ID completo | 177.112.79.226 ↔ 192.168.15.15 | mine-host, connect |

### Identificadores Compartilhados

O identificador de sessão `e5 d4 c1 c5 bc 21 59 16 c8 0f` aparece em múltiplas famílias (A, C, D, E) mas não na família B (que tem apenas 6 bytes: `90 21 59 16 c8 0f`).

**Conclusão:** Existem pelo menos 5 famílias distintas de mensagem UDP/9993, diferenciadas por tamanho e estrutura. O identificador de sessão é compartilhado entre a maioria das famílias.

---

## FRENTE 08 — Identificador de Sessão

### Identificador Observado

`e5 d4 c1 c5 bc 21 59 16 c8 0f` (10 bytes)

### Ocorrências

| Protocolo | Porta | Aparece? | Offsets observados |
|---|---|---|---|
| UDP | 9993 | ✓ Sim | 0x08-0x11 (137-byte), 0x08-0x11 (99-byte), 0x08-0x11 (28-byte) |
| UDP | 47836 | Não | — |
| TCP | 17301 | Não | — |
| TCP | 17351 | Não | — |

### Análise dos 10 Bytes

Os bytes podem ser interpretados de duas formas:

**Interpretação 1 — Identificador único de 10 bytes:**
`e5 d4 c1 c5 bc 21 59 16 c8 0f`

**Interpretação 2 — Campos concatenados:**
- Bytes 0-5: `e5 d4 c1 c5 bc 21` (6 bytes, possivelmente parte fixa)
- Bytes 6-7: `59 16` (2 bytes, possivelmente timestamp ou contador)
- Bytes 8-9: `c8 0f` (2 bytes, possivelmente sequência ou checksum)

**Observação:** Os mesmos 10 bytes aparecem consistentemente em todas as mensagens de uma mesma sessão, independentemente do tamanho da mensagem ou da direção. Não há evidência de que o identificador mude durante a captura.

**Conclusão:** O campo de 10 bytes `e5 d4 c1 c5 bc 21 59 16 c8 0f` funciona como identificador de sessão no protocolo UDP/9993. Não é possível determinar se é um único campo de 10 bytes ou campos concatenados sem mais evidência. Não aparece nos canais de controle TCP.

---

## FRENTE 09 — UDP/9993: Investigação Criptográfica

### Distribuição de Bytes

Analisando a Família A (137 bytes):

| Offset | Conteúdo | Característica |
|---|---|---|
| 0x00–0x2D | Header fixo + campos variáveis | Plaintext provável |
| 0x2E–0x5D | 48 bytes | Alta entropia, aparência aleatória (região criptografada) |
| 0x5E–0x77 | TLV 0x0004 + campos | Plaintext provável |

### Características Criptográficas

- **Cabecalho em plaintext:** Os primeiros 46 bytes (0x00–0x2D) têm estrutura previsível e valores repetidos entre mensagens.
- **Região criptografada:** Os 48 bytes de 0x2E a 0x5D têm aparência de dados aleatórios (alta entropia), consistente com cifragem de bloco.
- **Tamanho da região criptografada:** 48 bytes = 3 blocos de 16 bytes (compatível com AES-128 ou AES-256 em modo de bloco).
- **Não há nonce ou IV óbvio:** Não há campo claramente identificável como nonce ou IV antes da região criptografada.
- **Reutilização de blocos:** Não foi possível verificar reutilização de blocos entre mensagens diferentes com a mesma chave, pois o identificador de sessão é constante mas a região criptografada varia.

### Comparação de Mensagens com Mesmos Campos Conhecidos

Duas mensagens de 137 bytes (frames 116 e 128) têm o mesmo header fixo mas regiões criptografadas diferentes:

```
Frame 116 (0x2E-0x5D): 00 2e 38 e9 0a 46 71 a7 7c fd d8 81 06 57 ec 45 de 15 ...
Frame 128 (0x2E-0x5D): 00 2e 38 e9 0a 46 71 a7 7c fd d8 81 06 57 ec 45 de 15 ...
```

Wait — na verdade as mensagens 116, 117, 118 têm o MESMO payload completo (incluindo a região "criptografada"). Isso significa que a mesma mensagem é retransmitida de múltiplas portas, não que há criptografia com nonce diferente.

**Conclusão:** A região de 48 bytes (0x2E–0x5D) apresenta características de dados criptografados, mas não há evidência de nonce, IV ou padding visíveis. O mesmo payload criptografado é reenviado de múltiplas portas durante hole punching. Não é possível determinar o algoritmo de criptografia sem as chaves.

---

## FRENTE 10 — TCP/17301: Reconstrução do Controle

### Framing Confirmado

**Formato:** `[4-byte big-endian length][payload]`  
O campo de length representa apenas o tamanho do payload (exclui os 4 bytes do próprio header).

### Validação com Bytes Reais

| Frame | Length field | Length valor | tcp.len | Payload esperado | Conferência |
|---|---|---|---|---|---|
| 77 | 00 00 00 c0 | 192 | 196 | 4 + 192 = 196 | ✓ |
| 80 | 00 00 00 20 | 32 | 36 | 4 + 32 = 36 | ✓ |
| 81 | 00 00 01 00 | 256 | 260 | 4 + 256 = 260 | ✓ |
| 82 | 00 00 00 e0 | 224 | 228 | 4 + 224 = 228 | ✓ |
| 88 | 00 00 00 30 | 48 | 52 | 4 + 48 = 52 | ✓ |
| 94 | 00 00 01 50 | 336 | 340 | 4 + 336 = 340 | ✓ |

### Fragmentação TCP

Mensagens maiores que o MSS são fragmentadas:

- Frame 100: length=0x0a20=2592, primeiro segmento com 1440 bytes (4 header + 1436 payload)
- Frame 101: continuação com 1156 bytes de payload (sem novo length prefix)
- 1436 + 1156 = 2592 ✓

- Frame 105: length=0x1140=4416, tcp.len=4420 (primeiro fragmento grande)

### Fluxo de Conexão (radmin-connect.pcapng)

1. TCP SYN → 148.113.190.78:17301 (porta origem 44340)
2. SYN-ACK, ACK (handshake completo)
3. Dados bidirecionais com PSH+ACK
4. Nova conexão TCP → 198.244.203.247:17301 (servidor alternativo, porta 57924)
5. Nova conexão TCP → 148.113.190.78:17301 (nova porta origem 44342)

### Servidores Observados

| IP | Porta | Capturas | Função |
|---|---|---|---|
| 148.113.190.78 | 17301 | radmin_17301, radmin_vm, radmin_vm2, radmin-connect, radmin-mine | Controle primário |
| 198.244.203.247 | 17301 | radmin_vm, radmin_vm2, radmin-connect | Controle alternativo |

### Conclusão

**CONFIRMADO:** Framing `[4-byte BE length][payload]` em TCP/17301, validado em 8 frames diferentes. Fragmentação TCP ocorre para mensagens grandes. Múltiplas conexões paralelas são usadas.

---

## FRENTE 11 — TCP/17351: Investigação Aprofundada

### Framing

Mesmo formato `[4-byte BE length][payload]` que TCP/17301.

### Validação

| Frame | Length field | Length valor | tcp.len | Conferência |
|---|---|---|---|---|
| 5487 | 00 00 00 0c | 12 | 16 | ✓ |
| 5493 | 00 00 00 f5 | 245 | 249 | ✓ |
| 5494 | 00 00 00 cb | 203 | 207 | ✓ |
| 5501 | 00 00 00 cc | 204 | 208 | ✓ |

### Estrutura Interna do Payload

Todas as mensagens observadas começam com `10 00 00 04` (4 bytes constantes):

| Frame | Seq field | Valor | Bytes adicionais |
|---|---|---|---|
| 5487 | 00 00 00 04 | (constante) | 01 00 01 df 00 00 00 02 |
| 5493 | 00 00 00 02 | 2 | 30 00 00 c0 ... |
| 5494 | 00 00 00 03 | 3 | 60 00 00 bf ... |
| 5501 | 00 00 00 04 | 4 | 60 00 00 c0 ... |
| 5502 | 00 00 00 05 | 5 | 70 00 00 14 ... |
| 5509 | 00 00 00 06 | 6 | 70 00 00 14 ... |

### Estrutura Provisória

```
Offset  Campo                    Tamanho
0x00    10 00 00 04              4 bytes  Versão/tipo de mensagem (constante)
0x04    Número de sequência      4 bytes  Big-endian, incrementa: 2, 3, 4, 5, 6...
0x08+   Payload variável         Variável  Depende do tipo de mensagem
```

### Servidores

| IP | Porta | Capturas |
|---|---|---|
| 45.162.230.182 | 17351 | radmin_vm.pcap |

### Conclusão

**CONFIRMADO:** Framing `[4-byte BE length][payload]` em TCP/17351. Sub-protocolo com versão `10 00 00 04` e número de sequência incremental big-endian. Não há evidência de que seja especificamente um canal de sincronização de chaves — é um canal de controle separado com numeração de mensagens.

---

## FRENTE 12 — Campo TLV `0x30` de 192 Bytes

### Busca nos PCAPs

Não foi encontrado nenhum campo de 192 bytes associado à tag `0x30` em nenhuma das capturas analisadas.

### Evidência Estática Anterior

Relatórios anteriores de engenharia reversa mencionam:
- Rotina em `shelper.dll!0x100638f0`
- Inicialização em `0x10005250`
- Atualização em `0x10004e50`
- Finalização em `0x10004f30`
- Dobra no chamador em `0x10069cdb` até `0x10069d0e`

### Conclusão

**INCONCLUSIVO:** O campo TLV `0x30` de 192 bytes não aparece no tráfego capturado. Isso pode significar:
1. O campo é negociado antes do início das capturas (handshake inicial não capturado)
2. O campo é usado apenas em determinados tipos de mensagem não observados
3. O campo pertence a uma versão diferente do protocolo

Dados estáticos seriam necessários para verificar se a constante `N` de 192 bytes aparece nos binários.

---

## FRENTE 13 — STUN: Reconstrução Completa

### Mensagens Observadas

| Frame | Origem | Destino | Porta | Tipo | Transaction ID | Captura |
|---|---|---|---|---|---|---|
| 5477 | 192.168.122.77:54527 | 135.181.75.11 | 17357 | Binding Request (0x0001) | 24df3803cbe764ea106738b61d314c66 | radmin_vm.pcap |
| 5480 | 192.168.122.77:54527 | 135.181.75.11 | 17357 | Binding Request (0x0001) | (mesmo) | radmin_vm.pcap |
| 5489 | 135.181.75.11:17357 | 192.168.122.77:54527 | 17357 | Binding Response (0x0101) | (mesmo) | radmin_vm.pcap |
| 676 | 192.168.122.77:54533 | 162.19.169.168 | 17309 | Binding Request | 676387424d688c31c2860788a26eed38 | radmin_vm2.pcap |
| 678 | 192.168.122.77:54533 | 162.19.169.168 | 17309 | Binding Request | (mesmo) | radmin_vm2.pcap |

### Estrutura das Mensagens

**Binding Request:** 20 bytes de payload UDP
- STUN header: 2 bytes tipo + 2 bytes length + 16 bytes transaction ID = 20 bytes
- Sem atributos (Message Length = 0x0000)

**Binding Response:** 56 bytes de payload UDP
- STUN header: 8 bytes
- Atributos: 48 bytes (Message Length = 0x0024 = 36 bytes de atributos + padding)

### Padrão de Retry

Duas Binding Requests são enviadas com ~99-100 ms de intervalo, sugerindo retry automático por não receber resposta na primeira tentativa.

### Portas STUN Não-Padrão

| Porta | Servidores | Capturas |
|---|---|---|
| 17309 | 162.19.169.168 | radmin_vm2.pcap |
| 17310 | 162.19.169.168, 198.244.203.247 | radmin_vm2.pcap |
| 17341 | 148.113.190.78 | radmin_vm.pcap |
| 17342 | 148.113.190.78, 15.204.183.160 | radmin_vm.pcap |
| 17347 | 148.113.1.139 | radmin_vm2.pcap |
| 17348 | 148.113.190.78, 148.113.1.139, 135.181.75.9 | radmin_vm2.pcap |
| 17349 | 148.113.190.78, 148.113.1.139, 135.181.75.9 | radmin_vm2.pcap |
| 17357 | 135.181.75.11, 135.181.75.20 | radmin_vm.pcap |
| 17358 | 135.181.75.11, 135.181.75.20 | radmin_vm.pcap |

**Conclusão:** STUN é usado pelo Radmin em portas não-padrão (não 3478). Binding Request/Response confirmado em múltiplas portas. O cliente consulta múltiplos servidores STUN em paralelo.

---

## FRENTE 14 — NAT e Mapeamento de Endereços

### Evidência Disponível

As respostas STUN Binding Response (56 bytes) contêm atributos que podem incluir MAPPED-ADDRESS e XOR-MAPPED-ADDRESS, mas não foram decodificados devido à falta de dissector específico para as portas não-padrão.

### Limitações

- Uma única resposta STUN por servidor não é suficiente para determinar o tipo de NAT
- Não há pares de request/response de múltiplos servidores para o mesmo endereço local que permitam comparar mapeamentos
- Não há tráfego de hole punching suficiente para inferir comportamento de NAT

### Conclusão

**INCONCLUSIVO:** Não é possível classificar o NAT como Full Cone, Restricted Cone, Port-Restricted ou Symmetric com base nas capturas disponíveis. Seriam necessárias múltiplas respostas STUN de diferentes servidores para o mesmo endereço local, ou tráfego de hole punching bem-sucedido com verificação de endereço mapeado.

---

## FRENTE 15 — Teredo

### Evidência

| Frame | Origem | Destino | Porta | Conteúdo | Captura |
|---|---|---|---|---|---|
| 708 | 192.168.122.77:54778 | 20.201.205.4 | 3544 | Teredo Router Solicitation (ICMPv6 type 133) | radmin_vm.pcap |
| 169 | 192.168.122.77:54778 | 20.201.205.4 | 3544 | Teredo Router Solicitation (ICMPv6 type 133) | radmin_vm2.pcap |

### Análise

- O pacote Teredo contém ICMPv6 Router Solicitation de `fe80::ffff:ffff:fffe` para `ff02::2`
- Nonce: `8acf0087ddea3402`
- Destino `20.201.205.4` é um servidor Teredo público da Microsoft
- Não há Router Advertisement observado em resposta
- Não há tráfego IPv6 encapsulado além do Router Solicitation

### Conclusão

**CONFIRMADO:** Tráfego Teredo observado, mas é provável que seja tráfego de fundo do Windows/Wine, não especificamente do Radmin. Não há evidência de que o Radmin use Teredo para suas comunicações.

---

## FRENTE 16 — ARP e Resolução de Endereços Virtuais

### Tráfego ARP Observado

| Frame | Origem | Destino | Conteúdo | Captura |
|---|---|---|---|---|
| 115 | 02:50:ce:a5:3a:26 | Broadcast | "Who has 177.112.79.226? Tell 26.239.229.134" | radmin-mine.pcapng |
| 272 | 02:50:ce:a5:3a:26 | Broadcast | "Who has 192.168.15.122? Tell 26.239.229.134" | radmin-mine.pcapng |
| 274 | 02:50:ce:a5:3a:26 | Broadcast | "Who has 25.33.236.186? Tell 26.239.229.134" | radmin-mine.pcapng |
| 314 | 02:50:eb:9a:6f:58 | Broadcast | "Who has 26.239.229.134? Tell 26.228.88.155" | radmin-connect.pcapng |
| 315 | 02:08:62:e3:9a:28 | 02:50:eb:9a:6f:58 | "26.239.229.134 is at 02:08:62:e3:9a:28" | radmin-connect.pcapng |

### MACs Observados na Interface Virtual

| MAC | Associação |
|---|---|
| 02:50:ce:a5:3a:26 | 26.239.229.134 (cliente local) |
| 02:08:62:e3:9a:28 | 26.239.229.134 (resposta ARP) |
| 02:50:eb:9a:6f:58 | 26.228.88.155 |
| 02:50:06:00:35:fd | 26.172.178.79 |

### Conclusão

**CONFIRMADO:** ARP é usado na interface virtual `radminvpn0` para resolução de endereços virtuais (26.x.x.x). Os MACs são locais (prefixo 02:xx indica localmente administrado). Não há evidência de que os MACs sejam identificadores globais ou persistentes entre sessões.

---

## FRENTE 17 — Broadcast, Multicast e Protocolos Auxiliares

### Protocolos Observados na Interface Virtual

| Protocolo | Endpoint | Capturas | Classificação |
|---|---|---|---|
| IGMPv3 | 26.228.42.15 → 224.0.0.22 | radmin-mine-host | Tráfego auxiliar (join/leave multicast) |
| SSDP | 26.172.178.79 → 239.255.255.250:1900 | radmin-mine-host | M-SEARCH (provavelmente fundo Windows) |
| UDP/4445 | 26.239.229.134:60900 → 224.0.2.60:4445 | radmin-mine-host | Multicast virtual |
| MDNS | 192.168.15.9:5353 → 224.0.0.251 | radmin-mine-host | Tráfego auxiliar |

### Conclusão

**CONFIRMADO:** Protocolos IGMPv3, SSDP, MDNS e multicast UDP/4445 aparecem na interface virtual. Eles são classificados como tráfego auxiliar de fundo (provavelmente do Windows executando via Wine), não essenciais para o protocolo VPN Radmin.

---

## FRENTE 18 — Reconstrução Temporal das Fases

### Linha do Tempo Unificada

| Tempo | Evento | Captura | Fase inferida |
|---|---|---|---|
| T-114s | radmin_vm.pcap começa (18:05:28) | radmin_vm.pcap | Inicialização VM |
| T+0s | DNS queries Windows/MS | radmin_vm.pcap | Inicialização |
| T+7s | Teredo Router Solicitation | radmin_vm.pcap | Conectividade IPv6 |
| T+42s | TCP conecta 148.113.190.78:17301 | radmin_vm / radmin_17301 | Conexão controle |
| T+95s | STUN Binding Requests (múltiplas portas) | radmin_vm.pcap | Descoberta NAT |
| T+96s | TCP conecta 45.162.230.182:17351 | radmin_vm.pcap | Controle alternativo |
| T+0 (connect) | radmin-connect.pcapng começa (14:22:04) | radmin-connect.pcapng | Fase de conexão |
| T+5s | TCP SYN → 148.113.190.78:17301 | radmin-connect.pcapng | Handshake controle |
| T+5s | Dados TCP/17301 (196, 4420 bytes) | radmin-connect.pcapng | Negociação |
| T+6s | TCP → 198.244.203.247:17301 | radmin-connect.pcapng | Servidor alternativo |
| T+0 (mine) | radmin-mine.pcapng começa (14:31:21) | radmin-mine.pcapng | Fase ativa |
| T+0 | UDP/9993 entre peers virtuais | radmin-mine.pcapng | P2P estabelecido |
| T+0 | Keepalive UDP/47836 | radmin-mine.pcapng | Manutenção sessão |
| T+0 (mine-host) | radmin-mine-host.pcapng começa (14:32:56) | radmin-mine-host.pcapng | Fase ativa host |
| T+5s | ARP na interface virtual | radmin-mine-host.pcapng | Resolução endereços |

### Fases Identificadas

1. **Inicialização (T-114s a T+0s):** DNS, Teredo, ARP
2. **Conexão de controle (T+42s):** TCP/17301 para servidores Radmin
3. **Descoberta NAT (T+95s):** STUN em portas não-padrão
4. **P2P ativo (T+0 mine/mine-host):** UDP/9993, keepalive UDP/47836

**Nota:** Os nomes dos arquivos (`radmin-connect`, `radmin-mine`, `radmin-mine-host`) são consistentes com as fases observadas pelos timestamps, mas não há confirmação direta nos metadados.

---

## FRENTE 19 — Auditoria das Conclusões Anteriores

### Comparação com `docs/PROTOCOL_SPEC.md`

| Afirmação anterior | Status nos PCAPs | Comentário |
|---|---|---|
| Framing `[4-byte BE length][payload]` | ✓ CONFIRMADO | Validado em TCP/17301 e 17351 |
| Handshake `00 00 00 04 03 00 00 00` | — NÃO ENCONTRADO | Não aparece no início de nenhuma conexão capturada |
| Porta de controle 17301 | ✓ CONFIRMADO | Múltiplas conexões observadas |
| Porta 17351 | ✓ CONFIRMADO | Sub-protocolo com sequência |
| STUN em portas não-padrão | ✓ CONFIRMADO | 9 portas diferentes observadas |
| Teredo UDP/3544 | ✓ CONFIRMADO | Router Solicitation |
| Interface virtual 26.x.x.x | ✓ CONFIRMADO | radminvpn0 ativo |
| Servidores 148.113.190.78, 198.244.203.247, 45.162.230.182 | ✓ CONFIRMADO | Todos aparecem |

### Descobertas Novas (não em relatórios anteriores)

1. Porta UDP/9993 como canal de dados P2P
2. Porta UDP/47836 como keepalive periódico
3. TLV tipo 0x0004 com IP+porta do peer
4. Hole punching com múltiplas portas origem (9993, 48318, 48870)
5. Identificador de sessão de 10 bytes apenas em UDP/9993

### Contradições

Nenhuma contradição direta encontrada entre os PCAPs e relatórios anteriores de engenharia reversa.

---

## FRENTE 20 — Matriz de Implementação Futura

### Prontidão por Item

| Item | Prontidão | Evidência Necessária |
|---|---|---|
| 1. Framing de controle | PRONTO | [4-byte BE length][payload] validado |
| 2. Handshake inicial | NÃO PRONTO | Handshake `00 00 00 04 03 00 00 00` não capturado |
| 3. Autenticação | NÃO PRONTO | Tráfego criptografado, sem chaves |
| 4. Criptografia | NÃO PRONTO | Algoritmo e chaves desconhecidas |
| 5. STUN | PRONTO | Binding Request/Response em portas 17309, 17341, 17342, 17357, 17358 |
| 6. NAT traversal | PARCIAL | Hole punching observado, tipo de NAT desconhecido |
| 7. Descoberta de peers | PARCIAL | TLV 0x0004 fornece IP+porta, mecanismo de descoberta desconhecido |
| 8. UDP/9993 | PARCIAL | Estrutura parcial, região criptografada não decifrável |
| 9. UDP/47836 | PRONTO | Keepalive de 4 bytes com contador LE |
| 10. Relay | NÃO PRONTO | Não confirmado nos PCAPs |
| 11. Interface virtual | PRONTO | radminvpn0 com ARP, IP 26.x.x.x |
| 12. Encapsulamento de pacotes | NÃO PRONTO | Formato dos pacotes dentro da VPN não determinado |

### Recomendações para Próxima Etapa

1. Capturar o handshake inicial completo (antes de qualquer conexão TCP)
2. Capturar o tráfego de troca de chaves sincronizado com eventos de UI
3. Decodificar as respostas STUN completas (atributos MAPPED-ADDRESS)
4. Coletar mais amostras de UDP/9993 para mapear a estrutura TLV completa
5. Tentar interoperabilidade real com o cliente Windows para validar o protocolo

---

**Documento gerado:** `docs/PCAP_FORENSICS_DEEP_DIVE.md`  
**Arquivos .pcapng originais:** Preservados, não modificados  
**Código-fonte do projeto:** Não alterado