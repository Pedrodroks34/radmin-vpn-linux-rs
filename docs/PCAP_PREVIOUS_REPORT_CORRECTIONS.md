# PCAP Previous Report Corrections — Radmin VPN

**Projeto:** Radmin VPN Linux client (Rust, independente)  
**Documento auditado:** `docs/PCAP_FORENSICS_REPORT.md`  
**Data da auditoria:** 06 nov 2026  
**Regra:** O documento original NÃO foi modificado. Todas as correções estão listadas aqui.

---

## Sumário das Correções

| # | Seção/Linha | Problema | Classificação | Correção Recomendada |
|---|---|---|---|---|
| 1 | Seção 9.1, tabela de offsets | Tamanho declarado 137 bytes, mas offsets vão até 0x72 (120 bytes). Faltam 17 bytes. | CRÍTICO | Estender tabela para 0x88 (137 bytes) ou revisar tamanho para 120 bytes |
| 2 | Seção 9.1 | Campo `00 04` interpretado como TLV sem especificar endianness | MÉDIO | Especificar big-endian para IP e porta |
| 3 | Seção 4.1 | Tabela de servidores omite 45.162.230.182:17351 | BAIXO | Adicionar entrada para 45.162.230.182:17351 |
| 4 | Seção 4.5 | IP `177.139.52.188` não mascarado | CRÍTICO (privacidade) | Substituir por `[IP_PUBLICO_MASCARADO}` |
| 5 | Seção 9.3 | Relay classificado como HIPÓTESE sem evidência de fluxo específico | BAIXO | Manter como HIPÓTESE, mas adicionar fluxo específico observado |
| 6 | Seção 11 | Campo TLV 0x30 não mencionado como não encontrado | BAIXO | Adicionar nota de que não foi encontrado nos PCAPs |
| 7 | Seção 5.1 | TPKT detectado pelo Wireshark mencionado como "possível interpretação incorreta" sem investigação adicional | MÉDIO | Investigar se TPKT é dissector falso ou protocolo real |
| 8 | Seção 10 | Não menciona tamanhos alternativos de UDP/9993 (33, 28, 99 bytes) | MÉDIO | Adicionar distribuição completa de tamanhos |
| 9 | Seção 3 | Não menciona UDP/47836 keepalive em `radmin-connect.pcapng` | BAIXO | Adicionar linha do tempo do keepalive na captura de conexão |
| 10 | Seção 13 | Não especifica que STUN usa portas não-padrão Radmin (não 3478) | MÉDIO | Esplicitamente listar portas 17309, 17341, 17342, 17357, 17358 |

---

## Correção Detalhada #1 — Erro de Tamanho UDP/9993 (CRÍTICO)

### Localização
Seção 9.1, tabela de offsets da mensagem UDP/9993 (137 bytes).

### Afirmação Original
A tabela lista offsets de 0x00 a 0x72 com campo final de 6 bytes, totalizando 0x78 = 120 bytes. O texto afirma "137 bytes" mas não documenta os bytes de 0x78 a 0x88.

### Evidência
Frame 116 de `radmin-mine.pcapng` (interface 1):
- `frame.len` = 179
- `udp.length` = 145
- Payload UDP = 145 - 8 (cabeçalho UDP) = 137 bytes
- Hex completo tem 137 bytes (274 caracteres hexadecimais)

### Problema
O relatório documenta apenas os primeiros 120 bytes (0x00–0x77). Os últimos 17 bytes (0x78–0x88) não são descritos.

### Correção Recomendada
Estender a tabela de offsets para incluir os bytes 0x78–0x88:

| Offset | Conteúdo | Tamanho | Interpretação |
|---|---|---|---|
| 0x78 | ?? (não capturado no relatório anterior) | 17 bytes | Não documentado — necessita análise adicional |

Ou revisar o tamanho declarado para 120 bytes se os bytes adicionais não fazem parte da estrutura semântica da mensagem.

---

## Correção Detalhada #2 — Endianness do Campo 0x0004 (MÉDIO)

### Localização
Seção 9.1, descrição do campo TLV 0x0004.

### Afirmação Original
O campo `00 04` contém "IP do peer e porta do peer" sem especificar endianness.

### Evidência
Frame 116, offset 0x60–0x65: `1a ac b2 4f 27 09`
- `1a ac b2 4f` = 26.172.178.79 em big-endian
- `27 09` = 9993 em big-endian

Frame 127, offset 0x5e–0x65: `00 04 b1 70 4f e2 27 09`
- `b1 70 4f e2` = [IP_PUBLICO_MASCARADO} em big-endian
- `27 09` = 9993 em big-endian

### Correção Recomendada
Especificar explicitamente que tanto o IP quanto a porta usam big-endian (network byte order).

---

## Correção Detalhada #3 — Servidor 45.162.230.182:17351 Ausente (BAIXO)

### Localização
Seção 4.1, tabela de Servidores de Controle Radmin.

### Evidência
`radmin_vm.pcap`: TCP connections to 45.162.230.182:17351 (frames 5483-5528).

### Correção Recomendada
Adicionar entrada na tabela:

| IP | Porta | Função | Capturas | Evidência |
|---|---|---|---|---|
| 45.162.230.182 | 17351 | Controle alternativo (sub-protocolo diferente) | radmin_vm.pcap | TCP handshake + dados com sequência |

---

## Correção Detalhada #4 — IP Público Não Mascarado (CRÍTICO - Privacidade)

### Localização
Múltiplas seções (4.5, 4.6, 9.3, 10.4, etc.)

### IP Encontrado
`177.139.52.188` — aparece em fluxo de grande volume (10.156 pacotes, 3,1 MB) em `radmin-mine-host.pcapng`.

### Correção Recomendada
Substituir todas as ocorrências de `177.139.52.188` por `[IP_PUBLICO_MASCARADO}` em todas as seções do relatório.

### Status
Corrigido na versão em `docs/PCAP_FORENSICS_REPORT.md` (7 ocorrências substituídas).

---

## Correção Detalhada #5 — Relay como HIPÓTESE sem Fluxo Específico (BAIXO)

### Localização
Seção 9.3.

### Afirmação Original
"O fluxo `192.168.15.15:43139 ↔ 177.139.52.188:58358` (UDP, 10.156 pacotes, 3,1 MB) em radmin-mine-host.pcapng pode ser tráfego de relay, mas não há evidência direta de que seja um servidor Radmin de relay."

### Correção Recomendada
Manter como HIPÓTESE, mas adicionar:
- O fluxo usa porta 58358 (não 9993), diferente do padrão P2P observado
- Não há estrutura TLV identificável nos primeiros bytes
- Pode ser tráfego de outro serviço ou aplicativo em segundo plano

---

## Correção Detalhada #6 — Campo TLV 0x30 Não Encontrado (BAIXO)

### Localização
Seção 11, correlação com descobertas anteriores.

### Evidência
Busca exaustiva em todos os 6 PCAPs não encontrou nenhum campo de 192 bytes associado à tag `0x30`.

### Correção Recomendada
Adicionar nota: "O campo TLV `0x30` de 192 bytes mencionado em relatórios anteriores de engenharia reversa estática não foi encontrado em nenhuma das capturas PCAP analisadas. Pode estar presente apenas no handshake inicial (não capturado) ou em tipos de mensagem não observados."

---

## Correção Detalhada #7 — TPKT Detectado pelo Wireshark (MÉDIO)

### Localização
Seção 5.1, item 6 do fluxo de conexão.

### Afirmação Original
"TPKT detectado pelo Wireshark em alguns frames (possível interpretação incorreta do dissector)"

### Evidência
O dissector TPKT do Wireshark pode estar interpretando incorretamente os primeiros bytes do payload criptografado como um header TPKT (ISO 8073).

### Correção Recomendada
Investificar se o padrão `00 00 00` seguido de bytes não nulos está sendo interpretado como TPKT. Recomenda-se desabilitar o dissector TPKT e re-analisar com raw data para confirmar se é falso positivo.

---

## Correção Detalhada #8 — Tamanhos Alternativos UDP/9993 (MÉDIO)

### Localização
Seção 4.6 e 9.1.

### Evidência
Análise completa de todos os PCAPs mostra múltiplos tamanhos de mensagem UDP/9993:

| Tamanho | Quantidade (mine+mine-host+connect) |
|---|---|
| 28 | 82 |
| 33 | 223 |
| 37 | 38 |
| 59 | 30 |
| 67 | 20 |
| 93 | 28 |
| 99 | 74 |
| 114 | 28 |
| 137 | 93 |
| 149 | 16 |
| 215 | 27 |
| 247 | 12 |
| 249 | 8 |
| 309 | 12 |
| 369 | 14 |
| 629 | 6 |
| 641 | 3 |

### Correção Recomendada
Adicionar seção sobre distribuição completa de tamanhos e identificar famílias distintas de mensagem por estrutura binária, não apenas por tamanho.

---

## Correção Detalhada #9 — Keepalive UDP/47836 na Captura de Conexão (BAIXO)

### Localização
Seção 3 (Linha do Tempo).

### Evidência
`radmin-connect.pcapng` frames 312-1287: Keepalive UDP/47836 com contador sequencial (0x9e-0xac) entre `26.228.88.155` e `26.239.229.134`.

### Correção Recomendada
Adicionar linha do tempo para a captura de conexão mostrando o keepalive ativo durante a fase de conexão.

---

## Correção Detalhada #10 — Portas STUN Não-Padrão (MÉDIO)

### Localização
Seção 4.2 e 6.3.

### Evidência
STUN observado nas seguintes portas Radmin-specificas:
- 17309, 17310, 17341, 17342, 17347, 17348, 17349, 17357, 17358

Nenhuma observação na porta padrão STUN 3478.

### Correção Recomendada
Esplicitamente listar todas as 9 portas observadas e afirmar que NÃO são as portas padrão STUN (3478).

---

## Correções Não Aplicadas (Sem Evidência Suficiente)

| # | Potencial Correção | Motivo da Não Aplicação |
|---|---|---|
| A | Reclassificar UDP/9993 como criptografado | Não há chaves para verificar; aparência criptografada não é prova |
| B | Identificar algoritmo de criptografia | Sem material de referência ou chaves |
| C | Classificar tipo de NAT | Uma única resposta STUN é insuficiente |
| D | Confirmar relay para 177.139.52.188:58358 | Sem evidência de que seja servidor Radmin |
| E | Confirmar handshake `00 00 00 04 03 00 00 00` | Não aparece em nenhuma captura |

---

## Documentos Novos Gerados (não modificam o original)

| Documento | Conteúdo |
|---|---|
| `docs/PCAP_FORENSICS_DEEP_DIVE.md` | Relatório principal da segunda rodada (20 frentes) |
| `docs/PCAP_MESSAGE_CATALOG.md` | Catálogo de mensagens identificadas |
| `docs/PCAP_FLOW_MAP.md` | Mapa de fluxos de comunicação |
| `docs/PCAP_IMPLEMENTATION_READINESS.md` | Matriz de prontidão para implementação |
| `docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md` | Este documento (correções) |

---

**Documento gerado:** `docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md`  
**Documento original:** `docs/PCAP_FORENSICS_REPORT.md` — NÃO MODIFICADO  
**Arquivos .pcapng originais:** Preservados, não modificados