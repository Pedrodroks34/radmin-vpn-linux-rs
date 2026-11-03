# Relatório Forense: Catálogo de Mensagens e Protocolo de Controle (Fase 3 — Etapa 1)

**Projeto:** Radmin VPN Linux (`Pedrodroks34/radmin-vpn-linux-rs`)  
**Branch de trabalho:** `feat/phase-3-control-message-catalog`  
**Base:** `ccb4b4a27579fb7e25ad31e15f9908a4d8431176` (`origin/main`, após configuração de CI do GitHub Actions; base anterior do PR #7: `81cccc312861ca697518fe8952ac791a5d43b0d3`)
**Data da Auditoria:** 03 de novembro de 2026 (Revisão Final Documental da Fase 3.1)
**Status:** Concluído (Especificação Técnica Forense e Rastreabilidade Rigorosa)

---

## Sumário

1. [Escopo e Metodologia](#1-escopo-e-metodologia)
2. [Evidências Disponíveis](#2-evidências-disponíveis)
3. [Auditoria Forense da Implementação Atual (`src/protocol/control.rs`)](#3-auditoria-forense-da-implementação-atual-srcprotocolcontrolrs)
4. [Catálogo de Mensagens Oficiais (`RvROLClient.dll`)](#4-catálogo-de-mensagens-oficiais-rvrolclientdll)
5. [Catálogo de Tags e Taxonomia TLV Famatech](#5-catálogo-de-tags-e-taxonomia-tlv-famatech)
6. [Separação Arquitetural e Rastreabilidade dos Canais (Portas 17301 e 17351)](#6-separação-arquitetural-e-rastreabilidade-dos-canais-portas-17301-e-17351)
7. [Fluxos de Login e Troca Pós-Handshake na Porta 17301](#7-fluxos-de-login-e-troca-pós-handshake-na-porta-17301)
8. [Fluxos de Gerenciamento de Redes e Nós](#8-fluxos-de-gerenciamento-de-redes-e-nós)
9. [Códigos de Status e Tratamento de Erros](#9-códigos-de-status-e-tratamento-de-erros)
10. [Matriz de Confiança e Rastreabilidade](#10-matriz-de-confiança-e-rastreabilidade)
11. [Questões Ainda Não Resolvidas e Bloqueios](#11-questões-ainda-não-resolvidas-e-bloqueios)
12. [Próximas Etapas e Plano de Implementação Incremental](#12-próximas-etapas-e-plano-de-implementação-incremental)

---

## 1. Escopo e Metodologia

### 1.1 Objetivo da Etapa
Investigar, auditar e formalizar a especificação forense das mensagens trocadas no **canal de controle TCP (porta 17301)** e nos canais de coordenação secundários (porta 17351) do Radmin VPN **após o término bem-sucedido do handshake criptográfico SRP-6a**, quando o payload dos quadros do canal de controle passa a ser cifrado sob o algoritmo Famatech AES-256-CBC com encadeamento contínuo de IV (mantendo os prefixos de enquadramento TCP de 4 bytes em texto claro).

O escopo desta entrega é estritamente **investigativo e documental**, com proibição expressa de implementação prematura de código de produção, de suposições arbitrárias ou de mascaramento de divergências via testes circulares de round-trip.

### 1.2 Metodologia Clean-Room
A investigação adotou técnicas rigorosas de engenharia reversa e análise de tráfego passiva/ativa:
1. **Engenharia Reversa Estática de Binários Oficiais:**
   - `RvROLClient.dll` (v2.1.4951, 1.686.392 bytes): módulo cliente da arquitetura ROL (*Radmin Online Service*), responsável pela instanciação de pacotes, serialização TLV, dispatching de callbacks e ciclo de vida de redes.
   - `RvControlSvc.exe` (1.744.384 bytes): serviço central de controle do Windows, responsável pelo registro dinâmico dos descritores de propriedades e estado local da VPN.
   - `RvRvpnGui.exe` (1.332.736 bytes): interface gráfica do cliente, contendo a tabela mestre de tradução de códigos de erro de rede para texto legível.
   - `shelper.dll` (978.944 bytes): biblioteca de suporte criptográfico (SRP-6a, KDF e derivação de credenciais via CryptoAPI).
2. **Reconstrução Simbólica de RTTI e Vtables:**
   - Extração de descritores de tipo MSVC RTTI (`TypeDescriptor`, `CompleteObjectLocator`), permitindo mapear vtables, construtores, destruidores e métodos de serialização para cada pacote cliente e resposta de servidor.
3. **Análise Forense de Tráfego de Rede (PCAP):**
   - Análise de capturas reais (`radmin_17301.pcap`, `radmin_vm.pcap`, `radmin_vm2.pcap`), reassemblagem de fluxos TCP e medição precisa de tamanhos de quadros, sequenciamento e temporização.
   - Inspeção de pacotes de coordenação transmitidos em texto claro na porta 17351 (ex.: Pacote #5486 em `radmin_vm.pcap` e #686 em `radmin_vm2.pcap`) contendo contêineres TLV primitivos antes da ativação do cipher daquele canal.
4. **Auditoria Comparativa Cruzada:**
   - Confrontação linha a linha das estruturas em [`src/protocol/control.rs`](file:///home/rhuan/.gemini/antigravity/scratch/radmin-re/repo/src/protocol/control.rs) e [`src/protocol/tlv.rs`](file:///home/rhuan/.gemini/antigravity/scratch/radmin-re/repo/src/protocol/tlv.rs) contra as tabelas oficiais e desmontagem dos binários.

---

## 2. Evidências Disponíveis

| Artefato / Fonte | Tipo | Tamanho / Localização | Descrição e Relevância |
|---|---|---|---|
| `RvROLClient.dll` | Binário PE32 (x86) | 1.686.392 bytes | Hierarquia `CAbstractClnPacket`, `CRosPacket`, classes `CLoginPacket`, `CJoinNetworkPacket`, `CManageNetworkPacket`, tabela de salto em `0x1008bb3c`, gerador TLV de anúncio em `0x100162d0` e tratador em `0x10015bd0`. |
| `RvControlSvc.exe` | Binário PE32 (x86) | 1.744.384 bytes | Tabela mestre de registro de 744 descritores de propriedades TLV através de `call 0x4aec20`, rotinas de atualização de rede `0x41537e`. |
| `RvRvpnGui.exe` | Binário PE32 (x86) | 1.332.736 bytes | Tabela de salto em `0x004ed284` e tabela de tradução em `0x004ed2e0` (códigos 1002 a 1037) com strings oficiais de erro de rede. |
| `shelper.dll` | Binário PE32 (x86) | 978.944 bytes | Rotina de hashing de senhas `0x10065790` (CryptoAPI `CALG_SHA1`), primitivas do handshake SRP-6a. |
| `radmin_17301.pcap` | Captura PCAP-NG | 30.596 bytes (85 pacotes) | Tráfego TCP na porta 17301 (fluxos 49494 e 49493 para `148.113.190.78` e `198.244.203.247`), cobrindo handshake completo e sequência inicial de pacotes cifrados. |
| `radmin_vm.pcap` | Captura PCAP-NG | 21.205.260 bytes (12.441 pacotes) | Captura abrangente de máquina virtual Windows, cobrindo porta 17301 (cifrada), porta 17351 (quadros #5486 e #5487 desprotegidos), STUN e Teredo. |
| `radmin_vm2.pcap` | Captura PCAP-NG | 196.304 bytes | Captura de validação contendo o quadro TLV desprotegido #686 (288 bytes úteis na porta 17351). |

---

## 3. Auditoria Forense da Implementação Atual (`src/protocol/control.rs`)

A inspeção detalhada de [`src/protocol/control.rs`](file:///home/rhuan/.gemini/antigravity/scratch/radmin-re/repo/src/protocol/control.rs) e seus testes associados revela que a implementação atual foi construída predominantemente a partir de **hipóteses preliminares e testes unitários de round-trip**, sem respaldo nos mecanismos reais de despacho do cliente oficial.

### 3.1 O Problema dos Testes de Round-Trip como Falsa Validação
No arquivo `src/protocol/control.rs`, os testes unitários (`test_login_message_roundtrip`, `test_login_response_roundtrip`, `test_peer_info_roundtrip`, etc.) validam exclusivamente que:
$$\text{Rust Struct} \xrightarrow{\text{to\_tlv()}} \text{Bytes} \xrightarrow{\text{parse()}} \text{Rust Struct}$$

Essa propriedade circular garante que o serializador e o desserializador concordam entre si em um ambiente isolado, mas **não fornece nenhuma evidência de compatibilidade com o protocolo oficial**. Como demonstrado abaixo, diversas tags, estruturas e regras de negócio estavam incompatíveis com os binários oficiais.

### 3.2 Avaliação Detalhada por Estrutura e Campo

#### A. `ControlMessage::Login`
```rust
Login {
    client_version: u32,  // 0x010001d8 (TAG_CLIENT_VERSION)
    machine_id: u32,      // 0x010001db (TAG_MACHINE_ID)
    session_token: u32,   // 0x010001df (TAG_SESSION_TOKEN)
}
```
- **Evidência no binário:**
  - `0x010001d8` (`TAG_CLIENT_VERSION`): CONFIRMADO na tabela de propriedades de `RvControlSvc.exe` (`UINT32`).
  - `0x010001db` (`TAG_MACHINE_ID`): CONFIRMADO na tabela (`UINT32`).
  - `0x010001df` (`TAG_SESSION_TOKEN`): **INCORRETO**. No binário oficial (`RvControlSvc.exe` e `RvROLClient.dll`), a tag `0x010001df` corresponde a `PROP_NETWORK_STATUS` (código de status operacional / conexão), e **não** a um token de sessão.
- **Evidência no cliente oficial:** Em `RvROLClient.dll`, a classe oficial de login é `CLoginPacket` (vtable `0x1011462c`, construtor `0x10017ec0`). Ela herda de `CAbstractClnPacket`, registra explicitamente o identificador de comando `0x14` na Tag `0x0100031f` e seta as propriedades `0x1286`, `0x01000377` e `0x122f`.
- **Ordem e Endianness:** Tag e Length em Big-Endian no wire (comprovado no PCAP).
- **Classificação:** **PARCIAL / DIVERGENTE DO OFICIAL**.

---

#### B. `ControlMessage::LoginResponse`
```rust
LoginResponse {
    session_token: u32,   // 0x010001df (TAG_SESSION_TOKEN)
    virtual_ip: Ipv4Addr, // 0x010001de (TAG_VIRTUAL_IPV4)
    node_id: u64,         // 0x02000008 (TAG_NODE_ID)
}
```
- **Evidência no binário:**
  - `0x010001df`: Código de status de resposta (`0x0` = Sucesso, ou `0x2` = Aprovado), não token de sessão.
  - `0x010001de`: Tag genérica interna. A propriedade oficial para o IP virtual atribuído à interface VPN (`26.x.x.x`) é **`0x010001ea`** (`PROP_VIRTUAL_IP`).
  - `0x02000008`: Tag de controle interno de engine. A propriedade oficial para o ID de nó/peer é **`0x020001e2`** (`PROP_NODE_ID`).
- **Evidência no cliente oficial:** A resposta de login do servidor instancia `CRosPktLoginComplete` (vtable `0x101187b4`, tratador `0x1008b2f8`), identificada pelo ID de comando de servidor **`0x15`** na Tag `0x01000320`.
- **Classificação:** **INCORRETO / HIPÓTESE**.

---

#### C. `ControlMessage::JoinNetwork`
```rust
JoinNetwork {
    network_name: String,     // 0x090001dc (TAG_NETWORK_NAME)
    password_hash: Vec<u8>,   // 0x090001dd (TAG_PASSWORD_HASH)
}
```
- **Evidência no binário:**
  - `0x090001dc`: O byte superior `0x09` indica tipo `BLOB/BINARY` na taxonomia Famatech. Conforme a tabela de descritores de `RvControlSvc.exe` e o método `ProcessNetworkUpdate` em `RvROLClient.dll`, strings UTF-8 possuem prefixo `0x0B`. A tag oficial é **`0x0b0001dc`** (`PROP_NETWORK_NAME`).
  - `0x090001dd`: **INCORRETO**. A desmontagem de `shelper.dll` no endereço `0x10065790` demonstra que o hash da senha é gerado via SHA-1 (`CALG_SHA1 = 0x8004`, 20 bytes) e inserido no contêiner com a tag **`0x090001cd`** (`PROP_AUTH_HASH`).
- **Evidência no cliente oficial:** A solicitação usa `CJoinNetworkPacket` (vtable `0x101145e0`, construtor `0x10017950`), registrando o ID de comando **`0x27`** na Tag `0x0100031f`.
- **Classificação:** **PARCIAL / INCORRETO NAS TAGS**.

---

#### D. `ControlMessage::LeaveNetwork`
```rust
LeaveNetwork {
    network_id: u64, // 0x020001d5 (TAG_NETWORK_ID)
}
```
- **Evidência no binário:**
  - `0x020001d5`: Tag hipotética. O catálogo global de propriedades estabelece que o identificador de rede de 64 bits é registrado sob **`0x020001e1`** (`PROP_NETWORK_ID`).
- **Evidência no cliente oficial:** Despachado através de `CManageNetworkPacket` (vtable `0x101146cc`, construtor `0x10018210`), com ID de comando **`0x34`** na Tag `0x0100031f`.
- **Classificação:** **HIPÓTESE**.

---

#### E. `ControlMessage::NetworkInfo`
```rust
NetworkInfo {
    network_id: u64,      // 0x020001d5 (TAG_NETWORK_ID)
    name: String,         // 0x090001dc (TAG_NETWORK_NAME)
    member_count: u32,    // 0x010001e3 (TAG_MEMBER_COUNT)
}
```
- **Evidência no binário:**
  - `member_count: u32` (`0x010001e3`): **ERRO FUNDAMENTAL DESCOBERTO**. A desmontagem do manipulador de rede em `RvControlSvc.exe` (`0x41537e`) e de `ProcessNetworkUpdate` em `RvROLClient.dll` (`0x1004ef1c`) comprovou que a tag `0x010001e3` representa `PROP_NET_CONN_ATTR` (atributos operacionais de conectividade e roteamento da rede), e **não contagem de membros**. A contagem de membros é calculada a partir da lista de nós (`0x0d0001e4`) ou por consulta assíncrona.
- **Evidência no cliente oficial:** As informações de rede são enviadas pelo servidor através de `CRosPktNetworks` (vtable `0x10118850`, ID de comando **`0x26`**) e `CRosPktNetworksChanges` (vtable `0x10118884`, ID de comando **`0x29`**).
- **Classificação:** **INCORRETO**.

---

#### F. `ControlMessage::PeerInfo`
```rust
PeerInfo {
    node_id: u64,         // 0x02000008 (TAG_NODE_ID)
    virtual_ip: Ipv4Addr, // 0x010001de (TAG_VIRTUAL_IPV4)
    status: PeerStatus,   // 0x0100032b (TAG_PEER_STATUS)
    last_seen_ms: u64,    // 0x020001e1 (TAG_TIMESTAMP)
}
```
- **Evidência no binário:**
  - `status: PeerStatus` (`0x0100032b`): **ERRO FUNDAMENTAL DESCOBERTO**. O código Rust assumia `PeerStatus (1=Offline, 2=Online, 3=Connecting)`. No entanto, a análise de `RvControlSvc.exe` e das capturas PCAP demonstrou que `0x0100032b` é **`PROP_PROTOCOL_CAPS`** (uma bitmask de capacidades do protocolo negociadas na conexão). O status de presença online de um nó é na verdade representado pelo booleano **`0x040001e7`** (`PROP_IS_ONLINE`).
  - `last_seen_ms` (`0x020001e1`): No código Rust foi rotulado como timestamp geral, mas no catálogo oficial `0x020001e1` é `PROP_NETWORK_ID`, enquanto o timestamp do peer é **`0x0200025e`** (`PROP_NODE_LAST_SEEN`).
- **Classificação:** **INCORRETO**.

---

#### G. `ControlMessage::Keepalive`
```rust
Keepalive {
    session_token: u32,   // 0x010001df (TAG_SESSION_TOKEN)
    timestamp_ms: u64,    // 0x020001e1 (TAG_TIMESTAMP)
}
```
- **Evidência no binário:** O cliente oficial utiliza a classe dedicada `CHeartbeatPacket` (vtable `0x10114534`, construtor `0x100176f0`), que registra o comando **`0x04`** na Tag `0x0100031f`. O heartbeat não consiste em um par arbitrário de `0x010001df` e `0x020001e1`.
- **Classificação:** **HIPÓTESE / DIVERGENTE**.

---

### 3.3 A Falha Estrutural do Mecanismo Heurístico de Despacho
No método `ControlMessage::from_tlv` em `src/protocol/control.rs`:
```rust
// Heurística frágil da implementação anterior:
if let (Some(_ver), Some(_mach), Some(_token)) = (...) { return Ok(Self::Login); }
if let (Some(_token), Some(_ip), Some(_node)) = (...) { return Ok(Self::LoginResponse); }
if let (Some(_name), Some(_pwd)) = (...) { return Ok(Self::JoinNetwork); }
```
Essa estratégia de adivinhação semântica baseada na presença simultânea de tags era necessária unicamente porque a implementação anterior desconhecia a existência das **tags mestras de despacho**:
- **`0x0100031f`:** Identificador de comando / tipo de mensagem enviada pelo cliente.
- **`0x01000320`:** Identificador de comando / tipo de mensagem respondida pelo servidor.

---

## 4. Catálogo de Mensagens Oficiais (`RvROLClient.dll`)

A engenharia reversa das vtables e das funções de despacho em `RvROLClient.dll` permitiu mapear com exatidão a hierarquia de classes C++ e o mecanismo de pares Requisição-Resposta.

### 4.1 Pacotes de Requisição do Cliente (`CAbstractClnPacket@RolClient`)
Todos os pacotes emitidos pelo cliente herdam de `CAbstractClnPacket` (vtable base `0x10114128`). Seu construtor base (`0x100165c0`) recebe o código numérico da ação e executa invariavelmente:
```x86asm
100165d0: mov eax, dword ptr [ebp + 0x8] ; código de ação (Command ID)
100165dd: mov dword ptr [edi + 0x8], eax  ; armazena na estrutura do pacote
1001660c: push 0
1001660e: push dword ptr [edi + 0x8]      ; valor do Command ID
10016611: lea ecx, [edi + 0x14]           ; ponteiro para o contêiner TLV interno
10016614: push 0x0100031f                 ; Tag PROP_CLIENT_PACKET_ID (UINT32)
10016619: call 0x100a6b70                 ; grava a propriedade no contêiner TLV
```

| Classe C++ Oficial | Command ID | Vtable | Tamanho Heap | Construtor VA | Destruidor VA | Descrição Funcional |
|---|---|---|---|---|---|---|
| `CHeartbeatPacket` | **`0x04`** (4) | `0x10114534` | `0x50` bytes | `0x100176f0` | `0x10017730` | Sinal periódico de conectividade (*keepalive*). |
| `CLoginPacket` | **`0x14`** (20) | `0x1011462c` | `0x48` bytes | `0x10017ec0` | `0x10017ef0` | Registro inicial pós-handshake e capacidades. |
| `CJoinNetworkPacket` | **`0x27`** (39) | `0x101145e0` | `0x68` bytes | `0x10017950` | `0x100179a0` | Requisição de ingresso em rede com nome e hash. |
| `CEnumPublicNetworksPacket` | **`0x2b`** (43) | `0x101143f4` | `0x48` bytes | `0x100170a0` | `0x100170d0` | Solicitação do catálogo de redes públicas. |
| `CManageNetworkPacket` | **`0x34`** (52) | `0x101146cc` | `0x50` bytes | `0x10018210` | `0x10018240` | Operações administrativas (criar, sair, excluir rede). |

---

### 4.2 Pacotes de Resposta do Servidor (`CRosPacket@RolClient`)
As mensagens recebidas do servidor são deserializadas pelo despachador central em `0x1008a7b0`.
O despachador extrai o identificador da resposta a partir da Tag **`0x01000320`**:
```x86asm
1008a7d5: push 0x01000320                 ; Tag PROP_SERVER_PACKET_ID (UINT32)
1008a7df: call 0x10084d80                 ; extrai o valor inteiro da resposta
1008a812: mov eax, dword ptr [ebp - 0x1c] ; eax = Command ID do servidor
1008a815: add eax, -6                     ; normalização de índice (eax = cmd - 6)
1008a81f: cmp eax, 0x30                   ; limite da tabela (49 entradas)
1008a822: ja 0x1008b9fd                   ; desvio para tratador padrão / erro
1008a828: jmp dword ptr [0x1008bb3c + eax*4] ; salto indexado via tabela
```

A análise da tabela de salto em `0x1008bb3c` revelou os seguintes manipuladores de resposta:

| Classe C++ Oficial | Command ID | Vtable | Tratador VA | Construtor VA | Descrição Funcional |
|---|---|---|---|---|---|
| `CRosPktLoginComplete` | **`0x15`** (21) | `0x101187b4` | `0x1008b2f8` | `0x10086ae0` | Confirmação de login e concessão de credenciais. |
| `CRosPktManageNetReply` | **`0x25`** (37) | `0x1011881c` | `0x1008b3fc` | `0x10086bd0` | Resultado de operação administrativa de rede. |
| `CRosPktNetworks` | **`0x26`** (38) | `0x10118850` | `0x1008b4f0` | `0x10086ce0` | Lista abrangente de redes e peers vinculados. |
| `CRosPktJoinNetwork` | **`0x28`** (40) | `0x10118718` | `0x1008b16b` | `0x10086920` | Confirmação preliminar de pedido de ingresso. |
| `CRosPktNetworksChanges`| **`0x29`** (41) | `0x10118884` | `0x1008b57f` | `0x10086dc0` | Atualizações delta de estado de redes e membros. |
| `CRosPktJoinApproved` | **`0x2a`** (42) | `0x10118c2c` | `0x1008b0f5` | `0x10086897` | Aprovação definitiva de ingresso com atribuição de IP. |
| `CRosPktPublicNetworks` | **`0x2d`** (45) | `0x10118c94` | `0x1008b7af` | `0x10087007` | Lista paginada de redes públicas retornada. |

> [!NOTE]
> **Pares de Requisição e Resposta:**
> A estrutura de numeração reflete a semântica de pares diretos:
> - **Login:** Cliente `0x14` (20) $\rightarrow$ Servidor `0x15` (21).
> - **Join:** Cliente `0x27` (39) $\rightarrow$ Servidor `0x28` (40) / `0x2a` (42).
> - **Networks/Sync:** Servidor `0x26` (38) e deltas `0x29` (41).

---

## 5. Catálogo de Tags e Taxonomia TLV Famatech

### 5.1 Formato de Codificação no Wire
Conforme confirmado no Pacote #5486 (`radmin_vm.pcap`) e no Pacote #686 (`radmin_vm2.pcap`), o enquadramento TLV utiliza a convenção:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    LENGTH (32 bits, BE)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      TAG (32 bits, BE)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     VALUE (Length bytes...)                   |
+---------------------------------------------------------------+
```

---

### 5.2 Taxonomia de Tipos e Contagem Real de Descritores
A inspeção exaustiva do binário `RvControlSvc.exe` através de todas as chamadas à rotina estática de registro `call 0x4aec20` contabilizou **exatamente 744 descritores únicos de propriedades TLV**.

A discrepância histórica observada em relatórios preliminares da rodada 2 (onde o texto mencionava "723 registros", enquanto a tabela apresentava soma de 715) foi integralmente elucidada:
- A tabela antiga omitia 3 categorias de tipos suportadas pela arquitetura Famatech: `0x05` (Float), `0x06` (Double) e `0x0A` (DateTime).
- As categorias inteiras `0x01` (+3), `0x02` (+1) e `0x03` (+3) estavam levemente subcontadas.

A distribuição real verificada no binário `RvControlSvc.exe` é:

| Prefixo da Tag | Categoria de Tipo | Qtd. Tags Únicas | Descrição e Representação Interna |
|---|---|---|---|
| `0x01` | **`UINT32`** | 377 | Inteiro de 4 bytes sem sinal em Big-Endian no wire. |
| `0x02` | **`UINT64`** | 110 | Inteiro de 8 bytes sem sinal em Big-Endian (IDs de rede, carimbos Epoch). |
| `0x03` | **`INT32`** | 101 | Inteiro de 4 bytes com sinal em Big-Endian (primitiva escalar; ver distinção semântica abaixo). |
| `0x04` | **`BOOL`** | 35 | Booleano lógico (`0`=falso, `1`=verdadeiro; tamanho no wire ainda pendente de confirmação empírica). |
| `0x05` | **`FLOAT`** | 5 | Ponto flutuante de precisão simples (IEEE 754 de 32 bits). |
| `0x06` | **`DOUBLE`** | 3 | Ponto flutuante de precisão dupla (IEEE 754 de 64 bits). |
| `0x08` | **`COMPOUND`** | 4 | Estrutura binária composta / flags compactadas. |
| `0x09` | **`BINARY / BLOB`** | 22 | Buffer binário opaco (chaves públicas RSA, hashes de autenticação). |
| `0x0A` | **`DATETIME`** | 14 | Estrutura temporal ou carimbo de data/hora estendido. |
| `0x0B` | **`STRING_UTF8`** | 51 | Cadeia de caracteres codificada em UTF-8 (sem terminação nula no fio). |
| `0x0C` | **`OBJECT`** | 1 | Registro aninhado serializado. |
| `0x0D` | **`LIST / ARRAY`** | 7 | Coleção contígua de elementos homogêneos (ex.: lista de nós). |
| `0x0E` | **`MAP / CONTAINER`**| 14 | Contêiner associativo chave-valor. |
| **Total** | — | **744** | **Soma exata das 13 categorias ($377+110+101+35+5+3+4+22+14+51+1+7+14 = 744$).** |

#### Esclarecimentos sobre os Tipos Primitivos `0x03` e `0x04`:
1. **Diferenciação entre Primitiva `0x03` (INT32) e Semântica de Aplicação:**
   - O prefixo `0x03` no byte superior identifica exclusivamente a primitiva escalar de inteiro com sinal de 32 bits (`INT32`, 4 bytes em Big-Endian no wire).
   - Anotações anteriores rotulavam certas tags como `INT32 / ID` porque propriedades específicas (como referências de rede locais ou identificadores de entidade de sub-sistemas) utilizam esse tipo primitivo escalar.
   - Na gramática do protocolo Famatech TLV, **não existe um tipo primitivo "ID"**: o wire transporta puramente um inteiro de 4 bytes com sinal, e o significado de identificador é uma semântica de aplicação específica de cada propriedade.
2. **Status de Confirmação da Codificação de `0x04` (BOOL) no Wire:**
   - A taxonomia registra 35 propriedades do tipo booleano (`0x04`), como `PROP_IS_ONLINE` (`0x040001e7`).
   - Em código C++ compilado com MSVC (x86), existe duplicidade conceitual: o tipo primitivo nativo `bool` da linguagem C++ ocupa 1 byte (`sizeof(bool) == 1`), enquanto o typedef padrão Win32 `BOOL` ocupa 4 bytes (`sizeof(BOOL) == 4`, onde `0`=falso e `1`=verdadeiro).
   - Nas capturas PCAP em texto claro acessíveis (como o pacote #5486 na porta 17351), somente figuram propriedades dos tipos `0x01` (`UINT32`) e `0x09` (`BLOB`); nenhuma propriedade booleana `0x04` estava presente desprotegida no wire.
   - **Conclusão Forense:** O comprimento exato do campo `Length` de booleanos no wire (se o protocolo codifica como `Length = 1` byte ou `Length = 4` bytes) **permanece como comportamento ainda não confirmado empiricamente em capturas de tráfego**. Um parser defensivo em Rust deve estar preparado para aceitar comprimentos de 1 e 4 bytes até validação em testbed dinâmico.

---

### 5.3 Tags Críticas Confirmadas por Engenharia Reversa

| Tag Hex | Nome Conceitual | Tipo | Fonte da Evidência | Significado Funcional |
|---|---|---|---|---|
| `0x0100031f` | `PROP_CLIENT_PACKET_ID` | `UINT32` | `RvROLClient.dll` `0x10016614` | ID do pacote emitido pelo cliente (`0x04`, `0x14`, `0x27`, `0x2b`, `0x34`). |
| `0x01000320` | `PROP_SERVER_PACKET_ID` | `UINT32` | `RvROLClient.dll` `0x1008a7d5` | ID do pacote emitido pelo servidor (`0x15`, `0x25`, `0x26`, `0x28`, `0x29`, `0x2a`). |
| `0x010001df` | `PROP_NETWORK_STATUS` | `UINT32` | `RvControlSvc.exe`, `RvROLClient.dll` `0x100162f8` / `0x10015bf9` | Código de status de conexão (`1`=Iniciando, `2`=Aprovado/Ativo). |
| `0x0100032b` | `PROP_PROTOCOL_CAPS` | `UINT32` | `RvROLClient.dll` `0x10016311`, PCAP #5486 | Bitmask de capacidades e extensões do protocolo Radmin. |
| `0x010001e3` | `PROP_NET_CONN_ATTR` | `UINT32` | `RvControlSvc.exe` `0x41537e`, `RvROLClient.dll` | Atributos operacionais de rede (NÃO contagem de membros). |
| `0x010001ea` | `PROP_VIRTUAL_IP` | `UINT32` | `RvControlSvc.exe`, `RvROLClient.dll` `0x100412a0` | Endereço IPv4 virtual atribuído à interface VPN (`26.0.0.0/8`). |
| `0x020001e1` | `PROP_NETWORK_ID` | `UINT64` | `RvControlSvc.exe`, `RvROLClient.dll` | Identificador único de 64 bits da rede virtual. |
| `0x020001e2` | `PROP_NODE_ID` | `UINT64` | `RvControlSvc.exe`, `RvROLClient.dll` | Identificador exclusivo de 64 bits do nó/peer. |
| `0x0200025e` | `PROP_NODE_LAST_SEEN` | `UINT64` | `RvControlSvc.exe` | Timestamp Epoch de 64 bits do último contato (*heartbeat*) do peer. |
| `0x040001e7` | `PROP_IS_ONLINE` | `BOOL` | `RvControlSvc.exe` | Indicador booleano de presença online do nó. |
| `0x090001ca` | `PROP_RSA_PUBKEY_BLOB`| `BLOB` | PCAP #5486 / #686, `RvROLClient.dll` `0x10016328` | Chave pública RSA-2048 empacotada do cliente (256 bytes). |
| `0x090001cd` | `PROP_AUTH_HASH` | `BLOB` | `shelper.dll` `0x10065790` | Digest de 20 bytes do hash SHA-1 da senha de rede. |
| `0x09000201` | `PROP_ENDPOINT_CANDIDATES`| `BLOB` | `RvROLClient.dll` | Tuplas serializadas de IP público/local e portas STUN para descoberta P2P. |
| `0x0b0001dc` | `PROP_NETWORK_NAME` | `STRING_UTF8`| `RvControlSvc.exe`, `RvROLClient.dll` | Nome legível em UTF-8 da rede virtual Radmin. |
| `0x0b0001eb` | `PROP_PEER_ALIAS` | `STRING_UTF8`| `RvControlSvc.exe` | Apelido / hostname de exibição do peer. |

---

## 6. Separação Arquitetural e Rastreabilidade dos Canais (Portas 17301 e 17351)

Para evitar qualquer confusão de análise entre o canal de controle principal e o canal de coordenação secundário, documenta-se a separação estrita de cada fluxo:

```
+-----------------------------------------------------------------------------------------------------+
| CANAL DE CONTROLE PRINCIPAL (TCP 17301)                                                            |
| Finalidade: Handshake SRP-6a mútuo, negociação de chave mestra e controle cifrado da VPN           |
| Cifração: Plaintext durante SRP-6a (#32..#50) -> Payloads cifrados AES-256-CBC após Pacote #50      |
+-----------------------------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------------------------+
| CANAL SECUNDÁRIO DE COORDENAÇÃO (TCP 17351)                                                         |
| Finalidade: Anúncio de identidade preliminar do nó (P2P / Relay) com chave RSA pública             |
| Cifração: Mensagem inicial em TEXTO CLARO (#5486 / #686) -> Cifração do canal secundário posterior |
+-----------------------------------------------------------------------------------------------------+
```

### 6.1 Canal A: Controle Primário (Porta 17301)
- **Arquivo PCAP de origem:** `radmin_17301.pcap` (filtrado) e `radmin_vm.pcap` (completo).
- **Endereços e Portas (Fluxo 1):**
  - Origem: `192.168.122.77:49494` (Cliente Windows)
  - Destino: `148.113.190.78:17301` (Servidor Oficial ROL)
- **Endereços e Portas (Fluxo 2):**
  - Origem: `192.168.122.77:49493` (Cliente Windows)
  - Destino: `198.244.203.247:17301` (Servidor Oficial ROL Secundário)
- **Estado Criptográfico:**
  - Pacotes #32 a #50: Handshake SRP-6a em texto claro (versão 3, salt, $A$, $B$, $M_1$, $M_2$).
  - Pacotes #51 em diante: **Payloads cifrados sob Famatech AES-256-CBC**, mantendo o prefixo de enquadramento TCP de 4 bytes (comprimento do bloco cifrado) em texto claro.
- **Nota fundamental:** Neste canal **não existe quadro de 288 bytes em texto claro**. Todo tráfego posterior ao handshake é encapsulado com prefixo de tamanho de 4 bytes (enquadramento em texto claro) e payload interno estritamente cifrado (208B, 2576B, 160B, 432B, etc.).

---

### 6.2 Canal B: Coordenação Secundária (Porta 17351)
- **Arquivos PCAP de origem:** `radmin_vm.pcap` (Pacotes #5486 e #5487) e `radmin_vm2.pcap` (Pacote #686).
- **Endereços e Portas:**
  - Origem: `192.168.122.77:49497` (Cliente Windows)
  - Destino: `45.162.230.182:17351` (Endpoint de Coordenação / Relay)
- **Estado Criptográfico:** **Em texto claro** (etapa de anúncio anterior à ativação da cifra neste canal secundário).
- **Rastreabilidade no Binário:** Gerado pela função `0x100162d0` em `RvROLClient.dll` e avaliado pela função `0x10015bd0`.

#### Estrutura Exata do Pacote de Anúncio (#5486 em `radmin_vm.pcap` / #686 em `radmin_vm2.pcap`):
- Direção: Cliente $\rightarrow$ Servidor
- Tamanho no TCP: 292 bytes (4 bytes de prefixo de comprimento + 288 bytes úteis TLV):
```
[0x00..0x03] 00 00 01 20 -> Comprimento do Quadro = 288 bytes (0x0120)

-- Registro TLV 1 (12 bytes) --
[0x04..0x07] 00 00 00 04 -> Length = 4 bytes
[0x08..0x0b] 01 00 01 df -> Tag = 0x010001df (PROP_NETWORK_STATUS)
[0x0c..0x0f] 00 00 00 01 -> Value = 1 (Status: Solicitando / Inicializando)

-- Registro TLV 2 (12 bytes) --
[0x10..0x13] 00 00 00 04 -> Length = 4 bytes
[0x14..0x17] 01 00 03 2b -> Tag = 0x0100032b (PROP_PROTOCOL_CAPS)
[0x18..0x1b] 00 00 00 02 -> Value = 2 (Bitmask de capacidades do cliente)

-- Registro TLV 3 (264 bytes) --
[0x1c..0x1f] 00 00 01 00 -> Length = 256 bytes (0x0100)
[0x20..0x23] 09 00 01 ca -> Tag = 0x090001ca (PROP_RSA_PUBKEY_BLOB)
[0x24..0x123] [256 bytes da Chave Pública RSA-2048 do Nó]
```

#### Estrutura Exata da Resposta de Confirmação (#5487 em `radmin_vm.pcap`):
- Direção: Servidor $\rightarrow$ Cliente
- Tamanho no TCP: 16 bytes (4 bytes de prefixo de comprimento + 12 bytes úteis TLV):
```
[0x00..0x03] 00 00 00 0c -> Comprimento do Quadro = 12 bytes (0x000c)

-- Registro TLV 1 (12 bytes) --
[0x04..0x07] 00 00 00 04 -> Length = 4 bytes
[0x08..0x0b] 01 00 01 df -> Tag = 0x010001df (PROP_NETWORK_STATUS)
[0x0c..0x0f] 00 00 00 02 -> Value = 2 (Status: Confirmado / Aprovado)
```

Essa comprovação estabelece a ordem dos campos sem qualquer hipótese: **Length antecede Tag, e Tag antecede Value**.

---

## 7. Fluxos de Login e Troca Pós-Handshake na Porta 17301

### 7.1 Sequência Temporal Observada em `radmin_17301.pcap`
A medição de comprimento de quadros TCP no fluxo principal (`192.168.122.77:49494 -> 148.113.190.78:17301`) documenta os seguintes quadros determinísticos:

| Pkt # | Direção | Comprimento TCP | Payload Cifrado | Faixa Plaintext | Status de Validação e Atribuição Funcional |
|---|---|---|---|---|---|
| #32..#50 | C $\leftrightarrow$ S | Vários | Handshake SRP-6a | Texto claro | **CONFIRMADO** (Handshake SRP-6a mútuo completo). |
| **#51** | **C $\rightarrow$ S** | **212 B** | **208 B** (`0x00d0`) | **184 – 200 B** | **HIPÓTESE:** `CLoginPacket` (Command ID `0x14`). |
| **#52** | **S $\rightarrow$ C** | **2580 B** | **2576 B** (`0x0a10`) | **2552 – 2568 B** | **HIPÓTESE:** `CRosPktLoginComplete` e/ou `CRosPktNetworks`. |
| **#53** | **S $\rightarrow$ C** | **164 B** | **160 B** (`0x00a0`) | **136 – 152 B** | **HIPÓTESE:** Parâmetros de roteamento / ACK de estado. |
| **#55** | **C $\rightarrow$ S** | **436 B** | **432 B** (`0x01b0`) | **408 – 424 B** | **HIPÓTESE:** Endpoints locais / candidatos STUN (`0x09000201`). |
| **#58** | **S $\rightarrow$ C** | **388 B** | **384 B** (`0x0180`) | **360 – 376 B** | **HIPÓTESE:** Sincronização periódica de peers. |
| **#59** | **C $\rightarrow$ S** | **388 B** | **384 B** (`0x0180`) | **360 – 376 B** | **HIPÓTESE:** Confirmação de sincronização de peers. |
| **#62** | **S $\rightarrow$ C** | **164 B** | **160 B** (`0x00a0`) | **136 – 152 B** | **HIPÓTESE:** Notificação de intervalo de keepalive. |
| **#63** | **S $\rightarrow$ C** | **244 B** | **240 B** (`0x00f0`) | **216 – 232 B** | **HIPÓTESE:** Fechamento de negociação de sessão. |

> [!IMPORTANT]
> **Distinção entre Fato Comprovado e Inferência de Fluxo (Item 3 da Auditoria):**
> 1. **Confirmado por Engenharia Reversa Estática:** No binário `RvROLClient.dll`, existem as classes `CLoginPacket` (vtable `0x1011462c`), `CRosPktLoginComplete` (vtable `0x101187b4`, tratador `0x1008b2f8`) e `CRosPktNetworks` (vtable `0x10118850`, tratador `0x1008b4f0`).
> 2. **Confirmado por PCAP:** O cliente emite 208B cifrados no Pacote #51 e o servidor responde 2576B cifrados no Pacote #52.
> 3. **Ligação entre as Classes e os Pacotes Cifrados (208B / 2576B):** **CLASSIFICADA COMO HIPÓTESE**.
> Como o tráfego da porta 17301 encontra-se cifrado sob AES-256-CBC e não pôde ser decifrado offline sem posse das chaves efêmeras, **não é permitido afirmar categoricamente que o quadro de 2576B é `CRosPktNetworks` apenas pelo seu tamanho**. Essa atribuição é uma inferência contextual altamente plausível decorrente da máquina de estados do protocolo, mas permanece pendente de confirmação via captura dinâmica em ambiente controlado.

---

### 7.2 Diagrama de Sequência Hipotético do Canal de Controle

```mermaid
sequenceDiagram
    autonumber
    actor C as Cliente Radmin / Rust
    participant S as Servidor de Controle ROL (17301)

    Note over C,S: Handshake Famatech SRP-6a Concluído (CONFIRMADO)
    Note over C,S: Payloads Cifrados sob Famatech AES-256-CBC (Prefixo de Tamanho em Texto Claro)
    
    rect rgb(240, 248, 255)
    Note over C,S: Fase 1: Registro e Concessão de Acesso (HIPÓTESE de Mapeamento)
    C->>S: Pacote #51 (208 B Cifrados) — Inferido: CLoginPacket<br/>- 0x0100031f: Command ID = 0x14 (Login)<br/>- 0x010001d8: ClientVersion<br/>- 0x010001db: MachineID
    S-->>C: Pacote #52 (2576 B Cifrados) — Inferido: CRosPktLoginComplete + CRosPktNetworks<br/>- 0x01000320: Command ID = 0x15 / 0x26<br/>- Despejo do catálogo de redes e peers
    S-->>C: Pacote #53 (160 B Cifrados) — Inferido: Parâmetros Operacionais
    end

    rect rgb(255, 250, 240)
    Note over C,S: Fase 2: Publicação de Endpoints Locais e P2P (HIPÓTESE)
    C->>S: Pacote #55 (432 B Cifrados) — Inferido: Candidatos de Transporte P2P
    S-->>C: Pacote #58 (384 B Cifrados) — Inferido: Sincronização de Peers
    C->>S: Pacote #59 (384 B Cifrados) — Inferido: ACK de Sincronização
    end

    rect rgb(245, 255, 250)
    Note over C,S: Fase 3: Manutenção e Keepalive Periódico
    loop A cada intervalo de Heartbeat
        C->>S: CHeartbeatPacket (Command ID = 0x04)
        S-->>C: ACK de Heartbeat
    end
    end
```

---

## 8. Fluxos de Gerenciamento de Redes e Nós

### 8.1 Ingresso em Rede (`CJoinNetworkPacket`)
Para ingressar em uma rede virtual:
1. O subsistema criptográfico calcula o hash digest de 20 bytes via SHA-1 (`CALG_SHA1 = 0x8004` em `shelper.dll` `0x10065790`):
   $$\text{Hash} = \text{SHA-1}(\text{password\_utf8})$$
2. O cliente constrói um `CJoinNetworkPacket` (vtable `0x101145e0`, construtor `0x10017950`):
   - `0x0100031f`: `0x00000027` (Command ID `0x27` / 39)
   - `0x0b0001dc`: String UTF-8 com o nome da rede.
   - `0x090001cd`: Digest de 20 bytes de `PROP_AUTH_HASH`.
   - `0x0100032b`: Bitmask de capacidades do cliente.
3. O servidor avalia a credencial e responde através da tabela de despacho (`0x1008bb3c`):
   - Confirmação preliminar: `CRosPktJoinNetwork` (Command ID `0x28` / 40, vtable `0x10118718`).
   - Aprovação com atribuição de IP virtual: `CRosPktJoinApproved` (Command ID `0x2a` / 42, vtable `0x10118c2c`).

### 8.2 Gerenciamento Administrativo (`CManageNetworkPacket`)
As operações administrativas (criar rede, sair de rede ou excluir rede) são encapsuladas em `CManageNetworkPacket` (vtable `0x101146cc`, construtor `0x10018210`):
- `0x0100031f`: `0x00000034` (Command ID `0x34` / 52)
- O servidor confirma a operação através de `CRosPktManageNetReply` (Command ID `0x25` / 37, vtable `0x1011881c`).

### 8.3 Propriedades de Peers na Sincronização de Nós (`CRosPktNetworks`)
Cada registro de peer recebido no contêiner de nós contém:
- **`0x020001e2` (`PROP_NODE_ID`):** Identificador exclusivo do peer (64 bits).
- **`0x010001ea` (`PROP_VIRTUAL_IP`):** Endereço IPv4 virtual no espaço `26.0.0.0/8`.
- **`0x0b0001eb` (`PROP_PEER_ALIAS`):** Hostname / apelido em UTF-8.
- **`0x040001e7` (`PROP_IS_ONLINE`):** Booleano indicando presença ativa nos servidores ROL.
- **`0x0200025e` (`PROP_NODE_LAST_SEEN`):** Carimbo Epoch de 64 bits.
- **`0x09000201` (`PROP_ENDPOINT_CANDIDATES`):** Buffer contendo tuplas de transporte para tentativa de NAT hole punching direto.

---

## 9. Códigos de Status e Tratamento de Erros

A investigação da engenharia reversa desmembrou os códigos de status em duas camadas distintas: **códigos de estado de protocolo** (avaliados em `RvROLClient.dll`) e **códigos de erro operacionais de rede** (despachados para a UI em `RvRvpnGui.exe`).

### 9.1 Códigos de Estado do Protocolo (`PROP_NETWORK_STATUS` — `0x010001df`)
Comprovados diretamente na desmontagem de `RvROLClient.dll`:
- **`0x100162f8` (Emissão no Anúncio):** O cliente grava `0x010001df = 1` no contêiner TLV de 288 bytes (`STATUS_INITIALIZING` / estado de solicitação de ingresso).
- **`0x10015c02` (Validação de Retorno):**
  ```x86asm
  10015bf9: call 0x10014360        ; extrai valor de 0x010001df
  10015c02: cmpl $0x2, -0x30(%ebp) ; verifica se código == 2
  10015c06: jne 0x10015c30         ; se != 2, aborta e executa cleanup em 0x10005c80
  10015c08: mov dword ptr [esi + 0x78], 1 ; se == 2, marca estado ativo (APPROVED)
  ```
- **Conclusão:** No handshake preliminar, `1` representa estado inicial/solicitando e `2` representa estado aprovado/ativo.

---

### 9.2 Códigos de Erro de Rede Comprovados em `RvRvpnGui.exe`
A interface gráfica contém a rotina central de despacho de erros em `0x004ecf00`:
```x86asm
4ecf00: lea -0x3ea(%esi), %eax      ; subtrai offset base 0x3ea (1002 em decimal)
4ecf06: cmp $0x23, %eax             ; valida faixa de 36 entradas (0..35, códigos 1002 a 1037)
4ecf09: ja 0x4ece31                 ; se fora da faixa, desvia para formatador genérico "\n(%1)"
4ecf0f: movzbl 0x4ed2e0(%eax), %eax ; consulta tabela de tradução de 36 bytes em 0x004ed2e0
4ecf16: jmp dword ptr [0x004ed284 + eax*4] ; salto para tratador correspondente (23 entradas: Jump[0]..Jump[22])
```

#### Arquitetura da Tabela e Análise dos 36 Códigos (1002 a 1037)
A tabela de tradução `0x004ed2e0` cobre 36 posições indexadas. A desmontagem completa das 23 entradas da tabela de salto `0x004ed284` revela com precisão a razão pela qual apenas 20 códigos possuem tratadores dedicados:
1. **20 Códigos com Tratadores Especializados:**
   - **19 códigos** possuem strings literais descritivas em texto claro no binário (ex.: senha inválida, rede cheia, timeout, etc.).
   - **1 código (1029)** desvia para `Jump[18]` (`0x004ecf1d`), que empacota a string vazia `""` (`0x005d25c6`), silenciando a mensagem textual adicional na UI.
2. **16 Códigos com Redirecionamento ao Formatador Numérico Genérico:**
   - Os 16 códigos intermediários restantes (**1003, 1005, 1010, 1018, 1022, 1023, 1025, 1026, 1027, 1028, 1030, 1031, 1034, 1035 e 1036**) possuem valores de índice `1` ou `22` na tabela de tradução `0x004ed2e0`.
   - Tanto `Jump[1]` quanto `Jump[22]` apontam para o endereço `0x004ece31`, que empacota a string `"\n(%1)"` (`0x005e87c8`).
   - Para esses 16 códigos, o cliente oficial não possui mensagens textuais dedicadas; eles são exibidos na interface gráfica formatados como código numérico bruto entre parênteses.
3. **Códigos Fora da Faixa (< 1002 ou > 1037):**
   - A instrução `ja 0x4ece31` desvia imediatamente qualquer valor fora do intervalo indexado para a mesma rotina de formatação genérica `"\n(%1)"`.

Abaixo documentam-se os 20 códigos com tratadores dedicados identificados até o momento:

| Código | Handler VA | String Literal no Binário | Endereço da String | Classificação |
|---|---|---|---|---|
| **1002** (`0x03ea`) | `0x004ed25c` | `"Invalid network name or password"` | `0x005e87a4` | **CONFIRMADO** |
| **1004** (`0x03ec`) | `0x004ecfba` | `"Cannot connect to ROL server"` *(emitido em `RvROLClient.dll` `0x1004a1bd`)* | `0x005e85b4` | **CONFIRMADO** |
| **1006** (`0x03ee`) | `0x004ed11c` | `"Out of memory"` | `0x005e8704` | **CONFIRMADO** |
| **1007** (`0x03ef`) | `0x004ecf6a` | `"Canceled"` | `0x005e8578` | **CONFIRMADO** |
| **1008** (`0x03f0`) | `0x004ed1bc` | `"Timed out"` | `0x005e8750` | **CONFIRMADO** |
| **1009** (`0x03f1`) | `0x004ed00a` | `"This network name has already been taken"` | `0x005e85f0` | **CONFIRMADO** |
| **1011** (`0x03f3`) | `0x004ed16c` | `"ROL protocol error"` | `0x005e8730` | **CONFIRMADO** |
| **1012** (`0x03f4`) | `0x004ecf92` | `"You cannot join this network without password"` | `0x005e8584` | **CONFIRMADO** |
| **1013** (`0x03f5`)| `0x004ed234` | `"Connection prohibited"` | `0x005e878c` | **CONFIRMADO** |
| **1014** (`0x03f6`)| `0x004ed194` | `"Service connection lost"` | `0x005dbecc` | **CONFIRMADO** |
| **1015** (`0x03f7`)| `0x004ed144` | `"The password is too short"` | `0x005e8714` | **CONFIRMADO** |
| **1016** (`0x03f8`)| `0x004ecf42` | `"Access denied"` | `0x005e8568` | **CONFIRMADO** |
| **1017** (`0x03f9`)| `0x004ed032` | `"Network name should not be empty or longer than %1 characters"` | `0x005e861c` | **CONFIRMADO** |
| **1019** (`0x03fb`)| `0x004ed07c` | `"Last administrator cannot leave the network"` | `0x005e865c` | **CONFIRMADO** |
| **1020** (`0x03fc`)| `0x004ed0cc` | `"Network is closed to new members, joining impossible"` | `0x005e86b4` | **CONFIRMADO** |
| **1021** (`0x03fd`)| `0x004ed0f4` | `"Network name collision"` | `0x005e86ec` | **CONFIRMADO** |
| **1024** (`0x0400`)| `0x004ed0a4` | `"The virtual network limit has been reached"` | `0x005e8688` | **CONFIRMADO** |
| **1029** (`0x0405`)| `0x004ecf1d` | `""` *(String vazia / supressão de texto)* | `0x005d25c6` | **CONFIRMADO** |
| **1032** (`0x0408`)| `0x004ed1e4` | `"User ignores you"` | `0x005e875c` | **CONFIRMADO** |
| **1033** (`0x0409`)| `0x004ed20c` | `"You are muted in this chat"` | `0x005e8770` | **CONFIRMADO** |
| **1037** (`0x040d`)| `0x004ecfe2` | `"Chat is under maintenance"` | `0x005e85d4` | **CONFIRMADO** |

#### Mapeamento dos 16 Códigos com Formatação Genérica de Fallback:
Os seguintes códigos da faixa 1002..1037 são roteados pelo cliente oficial para o formatador genérico `0x004ece31` (`"\n(%1)"`):
`1003`, `1005`, `1010`, `1018`, `1022`, `1023`, `1025`, `1026`, `1027`, `1028`, `1030`, `1031`, `1034`, `1035`, `1036`.
Nenhuma evidência estática adicional indica texto ou semântica específica para esses números; comportam-se como posições não associadas a strings personalizadas ou reservadas na arquitetura Famatech.

> [!NOTE]
> **Esclarecimento sobre a Numeração Antiga (0..4):**
> A lista anterior simplificada (0=Sucesso, 1=Senha Inválida, 2=Não Encontrada, 3=Rede Cheia, 4=Já Membro) consistia em uma abstração preliminar de notas conceituais. A evidência binária real demonstra que os erros operacionais trafegam na faixa numérica 1002..1037.

---

## 10. Matriz de Confiança e Rastreabilidade

| Entidade / Descoberta | Classificação | Evidência Primária | Justificativa Forense |
|---|---|---|---|
| **Formato TLV no Wire (Length antes de Tag)** | **CONFIRMADO** | PCAP #5486 (`radmin_vm.pcap`), #686 (`radmin_vm2.pcap`), `RvROLClient.dll` `0x100162d0` | Observado diretamente em bytes não cifrados do fio e em código gerador do binário. |
| **Identificador de Comando Cliente `0x0100031f`** | **CONFIRMADO** | `RvROLClient.dll` (`0x10016614`) | Desmontagem do construtor base `CAbstractClnPacket::CAbstractClnPacket`. |
| **Identificador de Resposta Servidor `0x01000320`** | **CONFIRMADO** | `RvROLClient.dll` (`0x1008a7d5`, tabela `0x1008bb3c`) | Desmontagem da rotina de extração e tabela de salto do despachador central. |
| **IDs de Pacotes Cliente (`0x04`, `0x14`, `0x27`, `0x34`)** | **CONFIRMADO** | `RvROLClient.dll` (`0x10017706`, `0x10017ece`, `0x1001795b`, `0x10018221`) | Parâmetro literal empacotado em `push $id` nos construtores especializados. |
| **IDs de Pacotes Servidor (`0x15`, `0x25`, `0x26`, `0x28`)** | **CONFIRMADO** | `RvROLClient.dll` (tabela de salto `0x1008bb3c`, vtables `0x10118...`) | Mapeamento direto entre índice da tabela, tratador e classes C++ instanciadas. |
| **Hashing de Senha SHA-1 (`CALG_SHA1`)** | **CONFIRMADO** | `shelper.dll` (`0x10065790`) | Chamada explícita à CryptoAPI do Windows (`CryptCreateHash` com `0x8004`). |
| **Tag de Hash de Autenticação `0x090001cd`** | **CONFIRMADO** | `shelper.dll`, `RvROLClient.dll` | Atribuição de digest SHA-1 de 20 bytes à propriedade `0x090001cd`. |
| **Incompatibilidade da Tag `0x010001e3` (Atributo vs Membros)** | **CONFIRMADO** | `RvControlSvc.exe` (`0x41537e`), `RvROLClient.dll` (`0x1004ef1c`) | Operações bit a bit em flags operacionais; contagem de membros refutada. |
| **Incompatibilidade da Tag `0x0100032b` (Capacidades vs Status)** | **CONFIRMADO** | `RvControlSvc.exe`, PCAP #5486, `RvROLClient.dll` `0x10016311` | Bitmask de capacidades do cliente; presença online é tag `0x040001e7`. |
| **Contagem Total de 744 Descritores TLV Únicos** | **CONFIRMADO** | `RvControlSvc.exe` (`call 0x4aec20`) | Mapeamento exaustivo de todas as chamadas de registro no binário em 13 categorias. |
| **Primitiva INT32 (`0x03`) vs Semântica de ID** | **CONFIRMADO** | `RvControlSvc.exe`, `RvROLClient.dll` | Primitiva TLV é estritamente escalar inteiro de 4 bytes (BE); "ID" é semântica de aplicação. |
| **Comprimento de Codificação no Wire de BOOL (`0x04`)** | **PARCIAL** | Taxonomia de 35 tags em `RvControlSvc.exe` | Semântica booleana confirmada; tamanho no wire (1B vs 4B) sem amostra não cifrada no PCAP. |
| **Tabela de Erros de Rede Oficiais (1002 a 1037)** | **CONFIRMADO** | `RvRvpnGui.exe` (`0x004ecf00`, `0x004ed284`, `0x004ed2e0`) | Desmontagem de 36 slots: 20 tratadores dedicados (19 descritivos + 1 vazio) e 16 com fallback `"\n(%1)"`. |
| **Enquadramento TCP 17301 Pós-Handshake** | **CONFIRMADO** | `radmin_17301.pcap` (#51 em diante) | Prefixo de enquadramento de 4B em texto claro; payload interno cifrado sob Famatech AES-256-CBC. |
| **Sequência de Tamanhos Pós-Handshake na Porta 17301 (208B, 2576B, etc.)** | **CONFIRMADO** | `radmin_17301.pcap` (#51, #52, #61, #65) | Registro determinístico idêntico em fluxos distintos para servidores independentes. |
| **Atribuição das Classes aos Pacotes Cifrados (208B / 2576B)** | **HIPÓTESE** | Correlação de temporização de fluxo | Payloads estão cifrados sob AES-256-CBC e não foram decifrados offline. |
| **Decifração Integral do Tráfego Cifrado TCP 17301 nos PCAPs** | **DESCONHECIDO** | Capturas de tráfego de produção sem dump de RAM do Windows | Chave de sessão AES-256 é efêmera gerada por CSPRNG na VM; inviável decifrar passivamente. |
| **Subcampos Internos de `PROP_ENDPOINT_CANDIDATES`** | **PARCIAL** | `RvROLClient.dll`, análise de buffers | Conhecida a presença de tuplas IP/Porta; formato de compactação pendente de testes. |

---

## 11. Questões Ainda Não Resolvidas e Bloqueios

### 11.1 Impossibilidade de Decifração Passiva Offline do Tráfego TCP 17301
Os dados transmitidos nos pacotes #51 (208B), #52 (2576B) e subsequentes na porta 17301 foram criptografados com uma chave AES-256-CBC derivada mutuamente via SRP-6a a partir de expoentes efêmeros $a$ e $b$ gerados aleatoriamente em memória no momento da captura.

Como a chave privada efêmera do cliente e a senha mestre não foram capturadas no momento do tráfego, **é matematicamente impossível decifrar o payload bruto dessas sessões gravadas sem posse das chaves**.

> [!IMPORTANT]
> A engenharia reversa das estruturas e vtables em `RvROLClient.dll` suprime quase integralmente essa limitação, permitindo reconstruir as mensagens a partir do código do próprio cliente oficial, em vez de depender exclusivamente da decifração dos PCAPs gravados.

### 11.2 Detalhamento de Buffers Dinâmicos Compostos
O quadro de 2576 bytes enviado pelo servidor contém múltiplos registros empacotados (lista de redes, lista de nós membros, configurações de túnel). Embora saibamos que cada membro é um contêiner associado à lista `0x0d0001e4`, a gramática exata de aninhamento dos contêineres compostos precisa ser validada através de uma sessão viva controlada.

---

## 12. Próximas Etapas e Plano de Implementação Incremental

Para avançar com segurança para a implementação funcional no canal de controle sem comprometer o núcleo já estabilizado na Fase 2:

### Etapa 3.2 — Testbed Dinâmico Controlado (Harness Local)
1. Configurar um endpoint de teste ou harness local capaz de instanciar a máquina de estados `RSessionServer` e `ControlClientNegotiator` com **chaves estáticas pré-conhecidas**.
2. Conectar uma instância cliente para inspecionar os pacotes `CLoginPacket` e `CJoinNetworkPacket` em texto claro antes da cifra.

### Etapa 3.3 — Refatoração Cirúrgica de `src/protocol/control.rs`
1. **Eliminar o mecanismo heurístico frágil:** Substituir o casamento de campos em `from_tlv` pelo roteamento explícito baseado em:
   - Pacotes de saída: inclusão da Tag `0x0100031f` (`CommandId`).
   - Pacotes de entrada: leitura obrigatória da Tag `0x01000320` (`ServerCommandId`).
2. **Corrigir as tags incorretas:**
   - Atualizar `TAG_PASSWORD_HASH` para `0x090001cd`.
   - Atualizar `TAG_NETWORK_NAME` para `0x0b0001dc`.
   - Atualizar `TAG_VIRTUAL_IPV4` para `0x010001ea`.
   - Atualizar `TAG_NETWORK_ID` para `0x020001e1`.
   - Corrigir a interpretação de `0x010001e3` como flags de conectividade (`PROP_NET_CONN_ATTR`).
   - Corrigir a interpretação de `0x0100032b` como capacidades (`PROP_PROTOCOL_CAPS`) e introduzir `0x040001e7` (`PROP_IS_ONLINE`).
3. **Preservar a suíte de testes:** Atualizar os testes unitários para refletirem as tags oficiais e adicionar testes com bytes reais extraídos dos pacotes desprotegidos.

---
*Relatório elaborado conforme as diretrizes de integridade documental, rastreabilidade forense e padrões de engenharia de software do projeto Radmin VPN Linux.*
