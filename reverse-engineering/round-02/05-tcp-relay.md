# Frente 5: Protocolo TcpRelay e Conexão Mediada

**Classificação de Certeza:** CONFIRMADO (desmontagem do enum de conexão em `RvControlSvc.exe` em `0x43fb60`, correlacionada com a análise de fluxo de pacotes na porta TCP 17351 em `radmin_17301.pcap`)

---

## 1. Visão Geral do TcpRelay

Quando dois peers não conseguem estabelecer uma conexão direta ponto-a-ponto (P2P via TCP Simultaneous Open ou UDP STUN) devido a firewalls restritivos ou NATs simétricos, o cliente recorre à rota de retransmissão centralizada (**TcpRelay**) operando na **porta TCP 17351**.

### 1.1 Enumeração dos Tipos de Transporte (`RvControlSvc.exe` em `0x43fb60`)
A função em `0x43fb60` mapeia o código do tipo de conexão para uma representação textual explícita:

```x86asm
0x43fb60: mov eax, dword ptr [esp + 4] ; código do enum
0x43fb64: test eax, eax
0x43fb66: je 0x43fb80                 ; 0 -> "TCP" (P2P Direto)
0x43fb68: dec eax
0x43fb69: je 0x43fb88                 ; 1 -> "UDP" (P2P Direto)
0x43fb6b: dec eax
0x43fb6c: je 0x43fb90                 ; 2 -> "TcpRelay" (Relay na porta 17351)
0x43fb6e: mov eax, 0x51d2a0           ; default -> "Unknown"
0x43fb73: ret
0x43fb80: mov eax, 0x51d2a8           ; "TCP"
0x43fb85: ret
0x43fb88: mov eax, 0x51d2ac           ; "UDP"
0x43fb8d: ret
0x43fb90: mov eax, 0x51d2b0           ; "TcpRelay"
0x43fb95: ret
```

---

## 2. Análise do Fluxo TcpRelay na Captura `radmin_17301.pcap`

Na captura `radmin_17301.pcap`, após tentativas frustradas de conexão direta, o cliente inicia uma conexão TCP em direção a `198.244.203.247:17351` (pacotes #688 a #710):

```mermaid
sequenceDiagram
    autonumber
    actor C1 as Peer Local (192.168.122.77)
    participant R as Servidor TcpRelay (:17351)
    actor C2 as Peer Remoto

    C1->>R: TCP SYN (:49502 -> :17351)
    R-->>C1: TCP SYN-ACK (:17351 -> :49502)
    C1->>R: TCP ACK
    C1->>R: Pkt #695: Magic Framing + Relay Binding Request<br/>- Tag 0x10000004: Peer Target Node ID<br/>- Tag 0x50000020: Session Cookie / Auth Token
    R-->>C1: Pkt #701: Relay Binding Response<br/>- Tag 0x40000001: Relay Channel Status (0x01 = Pronto)
    Note over C1,R,C2: O Servidor Relay atua como roteador transparente
    C1->>R: Pkt #705: Tag 0x300000c0 (Payload Cifrado E2E destinado ao Peer C2)
    R-->>C2: Repassa pacote #705 intacto
```

### 2.1 Tags de Controle e Encapsulamento do Protocolo TcpRelay
O framing no canal 17351 utiliza prefixos de 4 bytes big-endian, seguidos por registros TLV dedicados à mediação de canal:

| Tag Hex | Descrição e Finalidade | Tamanho Típico |
|---|---|---|
| `0x10000004` | **Target Node ID:** Identificador numérico do peer de destino solicitado | 4 bytes |
| `0x20000008` | **Relay Routing ID:** Identificador de sessão de relay atribuído pelo servidor | 8 bytes |
| `0x300000c0` | **Encapsulated Data:** Quadro de dados do túnel Ethernet VPN (cifrado E2E) | Variável (alinhado a 16 bytes) |
| `0x40000001` | **Channel Status:** Flag de controle de fluxo / canal estabelecido | 1 byte |
| `0x50000020` | **Session Cookie:** Token criptográfico efêmero gerado pelo servidor ROL | 32 bytes |
| `0x600000c0` | **Multiplexed Frame:** Quadro multiplexado contendo múltiplos sub-pacotes | Variável |
| `0x70000014` | **Relay Keepalive:** Batimento cardíaco do túnel TcpRelay | 20 bytes |

---

## 3. Criptografia Ponta-a-Ponta (E2E) no TcpRelay

Um aspecto crítico revelado pela desmontagem de `RvROLClient.dll` e `RvControlSvc.exe`:
* O servidor TcpRelay **não possui as chaves de decifragem dos quadros de dados**.
* O payload transmitido sob a tag `0x300000c0` é previamente cifrado com a chave de sessão negociada diretamente entre os dois peers (via handshake RSA-2048 / AES-256 peer-to-peer).
* O servidor TcpRelay apenas inspeciona o cabeçalho de roteamento (`0x10000004` / `0x20000008`) para reencaminhar o fluxo ao socket TCP do peer correspondente, preservando a confidencialidade e a integridade ponta-a-ponta dos dados trafegados na VPN.
