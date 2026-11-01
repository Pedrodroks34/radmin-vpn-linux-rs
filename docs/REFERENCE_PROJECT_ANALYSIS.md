# Análise do Projeto de Referência — Radmin VPN para Linux (Wine)

**Alvo:** https://github.com/baptisterajaut/radmin-vpn-linux (clonado em `/home/pedrodroks/Downloads/radmin/references/radmin-vpn-linux/`)

**Licença:** GPL-3.0

**Objetivo desta análise:** extrair descobertas de engenharia reversa do projeto externo e cruzá-las com nossa engenharia reversa estática + tráfego capturado, para acelerar a construção de um cliente Rust independente — sem incorporar Wine, drivers Windows, DLLs ou hooks externos como dependência.

---

## 1. Arquitetura do Projeto Externo

O projeto roda o cliente oficial Windows (`RvControlSvc.exe` + `RvRvpnGui.exe`) sob **Wine**, substituindo componentes incompatíveis por implementações nativas Linux. O fluxo de dados é:

```
RvControlSvc.exe (Wine)
    ├─ DeviceIoControl \\.\RVPNNETMP (IOCTLs: VERSION, STATUS, CONNECT, SETUP, PEERMAC, ...)
    │     │
    │     ▼
    └─ rvpnnetmp.sys (driver shim PE, rodando sob Wine)
            │ TLV-encoded frames via named pipes (FIFOs)
            │   Z:\tmp\rvpn_b2d   (bridge→driver)
            │   Z:\tmp\rvpn_d2b_high (driver→bridge, alta prioridade)
            │   Z:\tmp\rvpn_d2b_low  (driver→bridge, baixa prioridade)
            ▼
    tap_bridge (nativo Linux)
            │ [u16 len][frame] sobre FIFO / raw frame sobre TAP
            ▼
    TAP device (radminvpn0) ←─ rede virtual L2 visível ao Linux
```

Componentes principais:

| Componente | Tipo | Papel |
|---|---|---|
| `rvpnnetmp.sys` | driver PE (mingw) | Emula o NDIS miniport `NetMP60.sys`. Cria `\Device\RVPNNETMP`. Aceita IOCTLs do serviço, enfileira frames em IRP queue, faz roteamento por MAC, envia/recebe via FIFOs. |
| `tap_bridge` | binário nativo C | Lê/grava frames entre TAP Linux e FIFOs. Duas threads (incoming/outgoing). ARP snoop + gratuitous ARP. Replicação de multicast Minecraft. Filtros JSON. |
| `adapter_hook.dll` | DLL PE injetada | IAT hooks no `RvControlSvc.exe` e `RvROLClient.dll`: renomeia adaptador, `RegSetKeySecurity` no-op, `GetProcAddress` hook para `GetNameInfoW`, perflib stubs, `LoadLibrary` watcher para `RvROLClient.dll`. |
| `rvpn_launcher.exe` | EXE PE injecor | Cria `RvControlSvc.exe` suspenso, injeta `adapter_hook.dll` via `CreateRemoteThread`+`LoadLibraryA`. |
| `drvinst.exe` | EXE PE stub | Substitui o instalador de driver NDIS da Famatech (causaria `abort()` no Wine). Retorna 0. |
| `netsh.exe/netsh64.exe` | EXE PE wrapper | Traduz comandos `netsh interface ip` do Radmin para `ip addr`/`ip link` no Linux via arquivo de relay. |
| `rvpn_dnsfix.so` | LD_PRELOAD (glibc) | Intercepta `getnameinfo`/`gethostbyaddr` para endereços privados → retorna numérico imediatamente (evita PTR bloqueado). |
| `rvpn_reuseport.so` | LD_PRELOAD (wineserver) | Força `SO_REUSEPORT` em todo socket TCP criado pelo wineserver, permitindo SO_REUSEADDR duplo no Windows (NAT traversal). |

---

## 2. Descobertas Técnicas Extraídas

### 2.1 Protocolo de Frame (TLV)

Extraído dos comentários e código de `rvpnnetmp.c`:

| Contexto | Formato | Campo 1 | Campo 2 | Campo 3 |
|---|---|---|---|---|
| Service Read (driver→serviço) | TLV, modo >= 2 | `u32 dest_mac_prefix` (host byte order, byte-swapado) | `u32 frame_len` | `frame_data` (mínimo 60 bytes, zero-padded) |
| Service Write (serviço→driver) | raw frame | Ethernet frame (14 + payload) | — | — |
| FIFO bridge (driver↔tap_bridge) | `[u16 len][frame]` | `u16 frame_len` (native byte order) | `frame_data` | — |

**Detalhe importante do TLV de leitura:** O `dest_mac_prefix` são os **primeiros 4 bytes do MAC de destino** do frame Ethernet, byte-swapados (`ntohl`). O serviço compara isso contra MACs de peers registrados via `IOCTL_RVPN_PEERMAC`. Sem o byte-swap, unicast não matcha nenhum peer → silenciosamente dropado.

**Padding:** Frames com menos de 60 bytes são zero-padded até 60 bytes (mínimo de frame Ethernet).

### 2.2 IOCTLs Identificados

Todos derivados da RE de `RvNetMP60.sys` e pontos de chamada de `RvControlSvc.exe`:

| IOCTL | Código | Entrada | Saída | Papel inferido |
|---|---|---|---|---|
| `IOCTL_RVPN_VERSION` | `0x0022C004` | 8B (versão + MAC) | 12B | Registro de versão. Se versão == 4: retorna `[status=0][MAC 6 bytes][pad 2]`. Senão: `[status=1]`. |
| `IOCTL_RVPN_STATUS` | `0x00224018` | 0 | 4B | Status do adaptador. Bit 0 = media presente/ativo. Serviço checa `status != 0 && (status & 1)`. |
| `IOCTL_RVPN_CONNECT` | `0x00224020` | 0 | 1B | Estado de conexão do NDIS. Retorna `0x20` (NdisMediaStateConnected). Se 0 bytes escritos, `DeviceIoControl` falha → `CDeviceRemoved`. |
| `IOCTL_RVPN_SETLINK` | `0x00224010` | 0xB8B | 0xB8 | Estatísticas/link. Responde bloco zeroado de 0xB8 bytes. |
| `IOCTL_RVPN_SETUP` | `0x0022801C` | 4B (modo) | 0 | Define modo de formato TLV. Modo >= 2 ativa `dest_mac_prefix` no TLV de leitura. |
| `IOCTL_RVPN_PEERMAC` | `0x00228014` | 6B (MAC) | 0 | Registra qual `FILE_OBJECT` (handle) responde a qual MAC de peer. Usado pelo RX thread para rotear unicast. |
| `IOCTL_RVPN_SETMAC` | `0x00228024` | variável | variável | ACK de propriedade por-peer. Retorna 1 byte. |

### 2.3 FIFOs (Named Pipes via Wine Z: drive)

| Caminho | Direção | Propósito |
|---|---|---|
| `Z:\tmp\rvpn_b2d` | bridge→driver | Frames do TAP chegando ao serviço (RX) |
| `Z:\tmp\rvpn_d2b_high` | driver→bridge | Alta prioridade: TCP, ICMP, unicast UDP, ARP |
| `Z:\tmp\rvpn_d2b_low` | driver→bridge | Baixa prioridade: broadcast, multicast, não-IP |
| `Z:\tmp\rvpn_d2b` | legião | Pipe único legado — não usado pelo código novo |

### 2.4 Roteamento por MAC (PeerMAC)

O driver mantém uma tabela de pares `(FILE_OBJECT, MAC[6])`, dinâmica (começa em 16 slots, dobra até 4096). Frames unicast são roteados para o `FILE_OBJECT` cujo MAC de destino bate. Frames de grupo (broadcast/multicast, bit 0 do primeiro byte do MAC setado) são entregues a **um IRP por `FILE_OBJECT` único**.

### 2.5 Detecção de Prioridade (Driver→Bridge)

| Protocolo | Prioridade |
|---|---|
| ARP (0x0806) | Alta |
| IPv4 TCP (6), ICMP (1) | Alta |
| IPv4 UDP unicast (17, bit 0 do dst MAC claro) | Alta |
| IPv6 TCP (6), ICMPv6 (58) | Alta |
| IPv6 UDP unicast (17, bit 0 do dst MAC claro) | Alta |
| Broadcast/Multicast, não-IP | Baixa |

### 2.6 Detecção de Endereço Uplink

O projeto determina qual interface é o "uplink" (caminho para a Internet) de duas formas:
1. `GetBestInterface(8.8.8.8)` — confia apenas se o IfIndex estiver na enumeração de adaptadores.
2. Fallback: o **único** adaptador UP que tem `FirstGatewayAddress` E um IPv4 roteável (não loopback, não link-local 169.254/16, não CGNAT 100.64/10).

Se for ambíguo (0 ou >1 candidato), retorna 0 e não filtra (comportamento seguro).

### 2.7 Filtragem de Interfaces (GetAdaptersAddresses / GetAdaptersInfo)

O hook `adapter_hook.dll` intercepta ambas as funções da `IPHLPAPI`:
- Renomeia o adaptador TAP para `Famatech Radmin VPN Ethernet Adapter` / `Radmin VPN`.
- Oculta todo adaptador que **não** é o TAP nem o default-route, zerando `FirstUnicastAddress` (GAA) ou `IpAddressList` (GAI).
- Isso impede que o conector ROL anuncie IPs de docker0/vmnet/tailscale como candidatos NAT.

### 2.8 Reverse-DNS Short-Circuit (`rvpn_dnsfix.so`)

Intercepta `getnameinfo`/`gethostbyaddr` no nível glibc (LD_PRELOAD no serviço). Para endereços privados (loopback 127/8, 10/8, 172.16/12, 192.168/16, APIPA 169.254/16, CGNAT 100.64/10), retorna imediatamente a forma numérica + porta numérica, sem consultar DNS. Endereços públicos passam para a função real.

Mesmo feito para IPv6 (loopback, link-local, site-local, ULA fc00::/7).

### 2.9 SO_REUSEPORT (`rvpn_reuseport.so`)

Intercepta `socket()` no `wineserver` (LD_PRELOAD). Para sockets TCP, força `SO_REUSEPORT` antes de `bind()`. Isso permite que o Radmin 2.1 faça **TCP port-reuse NAT traversal**: bind listener em `uplink:PORT`, adverte o mapping, depois bind sockets de saída na mesma porta local. Sem isso, o kernel Linux rejeita o segundo bind com `EADDRINUSE` que o wineserver relabela como `WSAEACCES`.

### 2.10 Perflib Stubs

Wine está faltando 4 exports da `advapi32`:
- `PerfIncrementULongCounterValue`
- `PerfIncrementULongLongCounterValue`
- `PerfDecrementULongCounterValue`
- `PerfDecrementULongLongCounterValue`

O Radmin 2.1 resolve 7 exports em cascata; se qualquer um falhar, o counterset não é criado, o per-peer counter object fica NULL, e o handshake de peer é descartado → `error: 0x700000000`. O projeto responde com stubs no-op (`ERROR_SUCCESS`) via hook de `GetProcAddress`.

### 2.11 Replicação de Multicast Minecraft

O `tap_bridge` detecta pacotes IPv4 UDP para `224.0.2.60` (Minecraft LAN) e os replica como broadcast para `26.255.255.255` e `255.255.255.255`, recalculando checksum IP e zerando checksum UDP.

---

## 3. Estruturas Binárias Identificadas

### 3.1 Estruturas Internas do Driver (`rvpnnetmp.c`)

```c
// Device extension (estado por instância do driver)
struct _DEVICE_EXTENSION {
    BOOLEAN Connected;
    UCHAR   MacAddress[6];
    LONG    IoctlCount;
    LONG    StatusCount;
    ULONG   SetupMode;       // setado por IOCTL_RVPN_SETUP (0x22801c)
    HANDLE  FifoB2D;         // bridge→driver (RX)
    HANDLE  FifoD2B_High;    // driver→bridge alta prioridade
    HANDLE  FifoD2B_Low;     // driver→bridge baixa prioridade
};

// Tabela de rotas por peer (MAC → FILE_OBJECT)
struct _PEER_ROUTE {
    PFILE_OBJECT fo;
    UCHAR mac[6];
};

// RX Ring (fallback quando não há IRP pendente)
struct _RX_RING {
    volatile ULONG write_idx;
    volatile ULONG read_idx;
    struct { USHORT len; UCHAR data[1600]; } frames[16];
};
```

### 3.2 Formato de Frame Ethernet

Campos padrão Ethernet II:
- Offset 0-5: Destination MAC
- Offset 6-11: Source MAC
- Offset 12-13: Ethertype (big-endian): `0x0800` = IPv4, `0x0806` = ARP, `0x86DD` = IPv6
- Offset 14+: payload

Para IPv4:
- Offset 14+9 (byte 23 do frame): IP protocol (1=ICMP, 6=TCP, 17=UDP)
- Offset 14+12 (byte 26 do frame): Source IP
- Offset 14+16 (byte 30 do frame): Destination IP

---

## 4. Cruzamento com Nossa Engenharia Reversa

### 4.1 Confirmações Independentes (nossa RE estática + tráfego)

| Descoberta do projeto externo | Nossa evidência | Status |
|---|---|---|
| `\Device\RVPNNETMP` | Strings do `NetMP60_1_1_64.sys` | **Confirmada** |
| Driver é NDIS 6 miniport, x86-64 | `file` + strings `.sys` | **Confirmada** |
| Serviço é `RvControlSvc.exe` | Imports PE (`StartServiceCtrlDispatcherW`, etc.) | **Confirmada** |
| GUI se conecta via named pipe `\\.\pipe\RadminVpnGuiChannel` | Strings do serviço | **Confirmada** |
| Porta de controle TCP **17301** | Captura Wireshark (porta não-HTTP com tráfego significativo) | **Confirmada** |
| Servidor `148.113.190.78:17301` | Captura Wireshark | **Confirmada** |
| Cabeçalho de frame: 4 bytes big-endian = tamanho do payload | Captura Wireshark (múltiplos exemplos) | **Confirmada** |
| Pacote de controle `00 00 00 04 03 00 00 00` | Captura Wireshark | **Confirmado (estrutura), significado não confirmado** |
| Reconexão abre nova conexão TCP (porta origem diferente) | Captura Wireshark (porta 49526 após 56923) | **Confirmada** |
| Driver assinado por Microsoft WHQL | `inspect_pe_certificates` | **Confirmada** |
| Driver versão `NetMP60_1_1` | Strings `.inf` + `.sys` | **Confirmada** |
| DNS-over-HTTPS `https://%hs/dns-query` | Strings `RvROLClient.dll` | **Confirmada** |
| Resolvers públicos hardcoded (1.1.1.1, 8.8.8.8, 9.9.9.9...) | Strings `RvROLClient.dll` | **Confirmada** |

### 4.2 Descobertas do Projeto Externo que Corroboram Nossa RE

| Descoberta | Evidência externa | Nossa evidência | Status |
|---|---|---|---|
| Driver NDIS emulado substitui `NetMP60.sys` | Código do `rvpnnetmp.sys` | Strings do `.sys` original | **Confirmada** |
| Frames Ethernet trafegam sobre o adaptador virtual | Código do `tap_bridge` + `rvpnnetmp.c` | Captura Wireshark (não vemos frames Ethernet, vemos TCP 17301) | **Provável** |
| Roteamento por MAC para multi-peer | Código do driver (`g_peer_routes`) | RTTI `VCUniqueConnectionId`, `VCConnection` | **Provável** |
| Prioridade de frames (TCP/ICMP acima de broadcast) | Código do driver (`classify_high_priority`) | Não observado diretamente | **Hipótese** |
| Per-peer NAT traversal com SO_REUSEADDR/TCP port reuse | Código `rvpn_reuseport.so` + docs | Strings `TcpNatChecker`, `Connections TCP/nat` no serviço | **Provável** |
| Handshake de peer falha sem perflib counters | Docs `wine-perflib.md` | RTTI `CAuthSessionId`, `CMsgAuth*` | **Provável** |

### 4.3 Diferenças Arquiteturais (Nosso Cliente Rust vs Projeto Externo)

| Aspecto | Projeto Externo | Nosso Projeto (Rust independente) |
|---|---|---|
| Execução do cliente | Wine + cliente Windows oficial | Código Rust nativo (não usamos Wine) |
| Driver de rede | `rvpnnetmp.sys` (PE) emulado sob Wine | TUN/TAP nativo Linux |
| Canal de serviço↔driver | FIFOs nomeados + IOCTL Windows | Não aplicável (sem driver Windows) |
| Canal de driver↔TAP | FIFOs + `tap_bridge` | TUN/TAP diretamente no Rust |
| Tradução netsh | `netsh_wrapper.exe` | `netlink`/`rtnetlink` no Rust |
| Reverse-DNS fix | `rvpn_dnsfix.so` (LD_PRELOAD glibc) | Não necessário (Rust controla seu próprio DNS) |
| SO_REUSEPORT fix | `rvpn_reuseport.so` (LD_PRELOAD wineserver) | Rust controla sockets diretamente |
| Perflib stubs | Hook IAT `advapi32` | Não aplicável (não usamos advapi32) |
| Filtragem de interfaces | Hook `GetAdaptersAddresses/Info` | Não necessário (controlamos quais IPs anunciar) |
| GUI | Qt do cliente Windows (Wine) | CLI Rust (opcional TUI futuramente) |

---

## 5. Componentes Reutilizáveis Conceitualmente (não código)

O código do projeto externo está sob **GPL-3.0**. Não podemos copiar código-fonte C/C++ para nosso projeto Rust sem respeitar a licença e documentar a proveniência. Entretanto, podemos **reutilizar conceitos e estruturas documentadas**:

| Conceito | Fonte | Aplicação no nosso cliente Rust |
|---|---|---|
| TLV framing: 4-byte length prefix | `rvpnnetmp.c` `tlv_encode_frame` | Parser de framing TCP no nosso módulo `transport` |
| TLV com dest MAC prefix (4 bytes) | `rvpnnetmp.c` | Estrutura de endereçamento de peer |
| Prioridade TCP/ICMP acima de broadcast | `classify_high_priority` | Fila de prioridade no nosso transporte |
| Roteamento unicast por MAC | `g_peer_routes` | Tabela de peers por endereço virtual |
| ARP snoop + gratuitous ARP | `tap_bridge.c` | Cache de endereçamento virtual no nosso módulo `network` |
| Reverse-DNS numérico para privados | `rvpn_dnsfix.c` | Não necessário (Rust não chama glibc getnameinfo indiretamente) |
| SO_REUSEPORT para NAT traversal | `rvpn_reuseport.c` | Rust define `SO_REUSEADDR`/`SO_REUSEPORT` diretamente nos sockets |
| Perflib counters para handshake de peer | `wine-perflib.md` | Estrutura de sessão/autenticação a ser descoberta via RE dinâmica |
| Minecraft multicast → broadcast | `replicate_mcast_to_bcast` | Não necessário (escopo limitado) |

---

## 6. Limitações e Incompatibilidades

| Item | Detalhe |
|---|---|
| **Licença GPL-3.0** | O código C/C++ do projeto externo não pode ser copiado diretamente para nosso projeto Rust sem torná-lo GPL-3.0 também e documentar a origem. Usamos apenas como referência conceitual. |
| **Não é um cliente nativo** | O projeto externo roda o cliente Windows oficial sob Wine. Não há código de protocolo de rede nativo — apenas adaptação de ambiente. |
| **Versão específica** | Validado contra Radmin VPN 2.1.4951.1 (mesma versão do nosso alvo). 2.0.4899.9 também funciona. 1.4 não é suportado. |
| **Não revela protocolo de pacote** | O projeto externo nunca decodificou o conteúdo dos frames Ethernet TCP entre peers — ele apenas os transporta. O protocolo de controle ROS e os pacotes de dados permanecem desconhecidos. |
| **Não revela handshake de autenticação** | O handshake entre peers e com o servidor ROS continua desconhecido. |
| **Não revela algoritmos de criptografia** | `CCryptoChannel` continua não analisado por nenhum dos dois projetos. |

---

## 7. Relação com Nossa Especificação (`docs/PROTOCOL_SPEC.md`)

### 7.1 O que o projeto externo confirma

| Nosso campo | Status anterior | Novo status | Base |
|---|---|---|---|
| Porta 17301 TCP | Confirmada (captura) | **Confirmada** | Projeto usa a mesma porta indiretamente (via serviço Windows) |
| Servidor `148.113.190.78` | Confirmado (captura) | **Confirmado** | Mesmo alvo |
| Cabeçalho 4 bytes BE = tamanho | Confirmado (captura) | **Confirmado** | O TLV do driver usa `u32 frame_len` (embora em contexto diferente) |
| `dest_mac_prefix` em TLV | Não conhecido | **Confirmado (conceito)** | `rvpnnetmp.c` linha 328-375 |
| Frame mínimo 60 bytes | Não conhecido | **Confirmado** | `ETH_FRAME_MIN 60` em `rvpnnetmp.c` |

### 7.2 O que permanece desconhecido (ambos os projetos)

- Estrutura binária dos pacotes ROS (`CRosPkt*`, `CMsg*`, `CLoginPacket`, etc.)
- Handshake de autenticação dispositivo↔servidor
- Algoritmos de criptografia (`CCryptoChannel`)
- Formato dos frames Ethernet entre peers (o que vai dentro do payload do TLV)
- Endereçamento IP virtual (faixa 26.x.x.x não confirmada em nenhum dos dois)
- Portas de peer-to-peer (NAT traversal usa porta 17301 para controle; portas de dados desconhecidas)

---

## 8. Próximas Etapas para Implementação Independente em Rust

Com base em tudo que foi levantado, estas são as etapas recomendadas em ordem:

### Fase I — Protocolo de Controle (alto valor, baixo custo)

1. **Parser de framing TCP** (módulo `transport`):
   - Ler `u32` big-endian = tamanho do payload
   - Ler payload completo
   - Lidar com frames fragmentados (múltiplas leituras TCP)
   - Lidar com múltiplos frames em uma leitura
   - Validar tamanho máximo (ex: 65535 bytes) para evitar alocação excessiva
   - Testes unitários com frames reais capturados nos PCAPs

2. **Análise de payload dos frames capturados**:
   - Agrupar frames por tamanho (36, 68, 100, 116, 148, 180, 244, 260, 308, 356, 388, 708, 1440, 1960, 3396 bytes)
   - Procurar bytes constantes (magic, tipo de mensagem, versão)
   - Procurar campos que variam com a ação (conectar, msg chat, desconectar, reconectar)

### Fase II — Decompilação (para preencher o que o tráfego não revela)

3. **Abrir o banco Ghidra** (`/tmp/opencode/ghidra_project/radmin_project.rep`) na GUI:
   - Analisar `ROLClient_Connect`, `ROLClient_Send`, `ROLClient_Receive`
   - Analisar `CCryptoChannel` (estrutura, métodos)
   - Analisar `CRosPktHeartbeat` e outros tipos de pacote ROS
   - Extrair funções de serialização/desserialização

4. **Mais capturas de tráfego direcionadas**:
   - Uma ação por vez (só conectar, só join network, só chat, só desconectar)
   - Correlacionar tipo de pacote com ação

### Fase III — Implementação Rust (após evidências suficientes)

5. Substituir `_raw: Vec<u8>` em `src/protocol/packets.rs` por estruturas reais
6. Implementar módulos `session`, `identity`, `authentication`, `crypto`
7. Implementar `tunnel` (TUN/TAP nativo)
8. Implementar `daemon` (serviço systemd)

---

## 9. Conclusão

O projeto de referência confirma nossa arquitetura de alto nível (serviço Windows + driver de rede virtual + interface TAP) e fornece detalhes valiosos sobre o **framing de baixo nível** (TLV com tamanho prefixado, roteamento por MAC, priorização de tráfego). No entanto, ele **não revela o protocolo de aplicação** (ROS, pacotes de controle, autenticação, criptografia) — isso continua sendo nossa principal fronteira desconhecida.

O caminho mais curto para um cliente Rust independente é:
1. Implementar o parser de framing TCP agora (baseado nas capturas);
2. Fazer mais capturas direcionadas para identificar tipos de mensagem;
3. Usar o banco Ghidra existente para decompilar as funções de serialização;
4. Só então implementar as estruturas de pacote e a lógica de sessão.

Não há atalho: o protocolo de controle e os algoritmos criptográficos só serão conhecidos por meio de análise dos binários oficiais + tráfego real.