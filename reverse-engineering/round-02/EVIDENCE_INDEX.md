# Índice Geral de Evidências de Engenharia Reversa (Round 02)

Este documento cataloga de forma estruturada todos os endereços de memória virtual (VA), deslocamentos de arquivo, símbolos, identificadores de pacotes em capturas PCAP e referências cruzadas que sustentam as conclusões técnicas das dez frentes de investigação.

---

## 1. Tabela de Binários e Artefatos Analisados

| Arquivo | Tamanho (Bytes) | Arquitetura | SHA-256 Resumido | Função no Sistema |
|---|---|---|---|---|
| `RvControlSvc.exe` | 1.835.008 | x86 (32-bit PE) | `...` | Serviço de sistema principal, orquestrador e tabelas TLV |
| `RvRvpnGui.exe` | 2.502.656 | x86 (32-bit PE) | `...` | Interface de usuário oficial e cliente do Named Pipe IPC |
| `RvROLClient.dll` | 983.040 | x86 (32-bit PE) | `...` | Cliente do serviço de rede e coordenação Famatech ROL |
| `RvUESClient.dll` | 417.792 | x86 (32-bit PE) | `...` | Subsistema de mensageria assíncrona interna |
| `shelper.dll` | 806.912 | x86 (32-bit PE) | `...` | Motor criptográfico OpenSSL + CryptoAPI |
| `NetMP60_1_1_64.sys` | 67.584 | x64 (64-bit PE) | `...` | Driver miniport NDIS 6.0 virtual adapter |
| `radmin_17301.pcap` | 1.258.496 | pcapng | N/A | Captura de tráfego TCP na porta 17301 e 17351 (Relay) |
| `radmin_vm2.pcap` | 3.489.792 | pcapng | N/A | Captura de tráfego STUN (UDP 17309-17349) e Teredo (UDP 3544) |
| `radmin_vm.pcap` | 2.150.400 | pcapng | N/A | Captura de sessão completa em ambiente de máquina virtual |

---

## 2. Índice de Funções e Endereços Virtuais por Frente

### Frente 1: Handshake e Troca de Chaves
* `shelper.dll!0x1006b860` (`SHelper_RSession_CreateClient`): Construtor da sessão de handshake RSA do cliente.
* `shelper.dll!0x1006a2b0` (`SHelper_RSession_GetNextBuffer`): Despachante da máquina de estados do handshake (Estados 0, 1, 2, 3).
* `shelper.dll!0x1006a512`: Estado 0 — Geração de 64 bytes de chave via `RAND_bytes`, cabeçalho de 12 bytes e cifragem RSA de 76 bytes.
* `shelper.dll!0x1006a4cc`: Estado 2 — Validação e leitura do token de sessão de 4 bytes recebido do servidor (`cmp eax, 4`).
* `shelper.dll!0x1006ba80` (`SHelper_RSession_GetKey`): Extração dos primeiros 32 bytes de material de chave para derivar a chave AES-256.

### Frente 2: Criptografia e Formato dos Quadros
* `shelper.dll!0x10065de8`: Chamada a `RSA_public_encrypt` com `push 1` (`RSA_PKCS1_PADDING`).
* `shelper.dll!0x10062ca9`: Inicialização com zeros (`xorps xmm0, xmm0`) dos IVs de cifragem (`esi+0x1ec`) e decifragem (`esi+0x1fc`).
* `shelper.dll!0x10062e00` / `0x10062d60`: Rotinas de cifragem e decifragem chamando OpenSSL `AES_cbc_encrypt` (`0x10003b30`), mantendo encadeamento contínuo de IV.
* `shelper.dll!0x10069c20`: Rotina de cálculo de tamanho alinhado: `((payload_len + 24) / 16) * 16`.
* `shelper.dll!0x1006a0c0`: Algoritmo de soma aditiva de 64 bits little-endian sobre a faixa `[0 .. total_len - 9]`.
* `shelper.dll!0x10069f90`: Rotina de validação e desempacotamento de quadros (valida `9 <= pad_len <= 24` e verifica checksum).

### Frente 3: Catálogo TLV
* `RvControlSvc.exe!0x00498fe0`: Tabela global contendo os 723 descritores de propriedades TLV.
* `RvControlSvc.exe!0x41537e`: Manipulador da propriedade `0x010001e3` como atributo operacional de rede (`UINT32`).
* `RvROLClient.dll!0x1004ef1c`: Processamento da tag `0x010001e3` ao lado de `0x040001e7` (booleano) e `0x0200025e` (timestamp uint64).
* `RvControlSvc.exe!0x488ae0`: Motor de serialização genérico TLV (Tag de 32 bits BE + Comprimento de 32 bits BE + Valor).

### Frente 4: Autenticação e Redes
* `shelper.dll!0x10065790`: Hashing de senha de rede via CryptoAPI usando `CALG_SHA1` (`0x8004`), gerando digest de 20 bytes para a tag `0x090001cd`.
* `RvROLClient.dll!0x100412a0`: Ponto de entrada de `ROLClient_JoinNetwork`.
* `RvROLClient.dll!0x1004a090`: Construção da mensagem TLV `JoinNetworkRequest`.
* `RvROLClient.dll!0x1004a115`: Verificação dos códigos de status de retorno na tag `0x010001df`.

### Frente 5: TcpRelay
* `RvControlSvc.exe!0x43fb60`: Função de conversão do enum de transporte: `0 -> "TCP"`, `1 -> "UDP"`, `2 -> "TcpRelay"`.
* `RvROLClient.dll!0x1004d220`: Estabelecimento do túnel de relay na porta 17351.

### Frente 6: NAT e STUN
* `RvROLClient.dll!0x10051180`: Rotina de envio de Binding Request STUN RFC 3489.
* `RvROLClient.dll!0x10051640`: Decodificação dos atributos `0x0001` (MAPPED-ADDRESS), `0x0004` (SOURCE-ADDRESS) e `0x0005` (CHANGED-ADDRESS).

### Frente 7: Teredo
* `RvROLClient.dll!0x10052310`: Desobfuscação de porta (`XOR 0xFFFF`) e endereço IPv4 (`XOR 0xFFFFFFFF`) do cliente Teredo (`CTeredoThread`).

### Frente 8: Windows IPC
* `RvControlSvc.exe!0x519e74`: String UTF-16 `\\.\pipe\RadminVpnGuiChannel`.
* `RvControlSvc.exe!0x40f052` / `0x47de40`: Criação do Named Pipe com limite de 200 instâncias.
* `RvRvpnGui.exe!0x4e8eb0`: Função `FUN_004e8eb0`, conexão ao pipe via `0x5352d0` e emissão do comando inicial `0x3f6` em `0x4e8f78`.
* `RvRvpnGui.exe!0x4e2ac0`: Despachante central de mensagens IPC e tratamento dos comandos `0x3ec`, `0x3ed`, `0x3ee`, `0x3ef`, `0x3f6`.

### Frente 9: Driver NDIS
* `NetMP60_1_1_64.sys!0x14000c05c`: Configuração de `NDIS_DEVICE_OBJECT_ATTRIBUTES` com nome `\Device\RVPNNETMP` e registro via `NdisRegisterDeviceEx` (`0x14000c08f`).
* `NetMP60_1_1_64.sys!0x1400030cc`: Rotina assíncrona de enfileiramento de IRPs retornando `STATUS_PENDING` (`0x103` em `0x140003222`).
* `RvControlSvc.exe!0x4aff8a`: IOCTL `0x224020` (Media Status, 1 byte out).
* `RvControlSvc.exe!0x4b003a`: IOCTL `0x224018` (Link speed/MTU, 4 bytes out).
* `RvControlSvc.exe!0x4b00a4`: IOCTL `0x22801c` (Set state/MTU, 4 bytes in).
* `RvControlSvc.exe!0x4b0123`: IOCTL `0x228014` (Set MAC Address, 6 bytes in).
* `RvControlSvc.exe!0x4b017f`: IOCTL `0x22c004` (Adapter Control & Event Exchange, 8 bytes in, 12 bytes out).

---

## 3. Índice de Pacotes em Capturas de Rede (PCAP)

| Captura | Número do Pacote | Endereço Origem / Destino | Protocolo / Porta | Dados / Significado Identificado |
|---|---|---|---|---|
| `radmin_17301.pcap` | #35 | `192.168.122.77:49493 -> 198.244.203.247:17301` | TCP (8 bytes) | Magic Framing `00 00 00 04` + Magic Payload `03 00 00 00` |
| `radmin_17301.pcap` | #44 | `198.244.203.247:17301 -> 192.168.122.77:49493` | TCP (8 bytes) | Server Echo do Magic: `00 00 00 04 03 00 00 00` |
| `radmin_17301.pcap` | #46 | `192.168.122.77:49493 -> 198.244.203.247:17301` | TCP (260 bytes) | Client Hello RSA-2048 (Payload de 76 bytes criptografado) |
| `radmin_17301.pcap` | #48 | `198.244.203.247:17301 -> 192.168.122.77:49493` | TCP (8 bytes) | Server Hello com token de sessão de 4 bytes |
| `radmin_17301.pcap` | #50 | `192.168.122.77:49493 -> 198.244.203.247:17301` | TCP | Primeiro quadro cifrado AES-256-CBC com trailer 0xCC |
| `radmin_17301.pcap` | #688..#710 | `192.168.122.77:49502 <-> 198.244.203.247:17351` | TCP Relay | Estabelecimento de túnel de retransmissão TcpRelay e troca de dados cifrados E2E |
| `radmin_vm2.pcap` | #10 | `192.168.122.77 -> 20.201.205.4:3544` | UDP Teredo | Pacote de inicialização do túnel Teredo IPv6 sobre UDP |
| `radmin_vm2.pcap` | #796 | `192.168.122.77:54536 -> 198.244.203.247:17348` | UDP STUN | STUN RFC 3489 Binding Request (`0x0001`) |
| `radmin_vm2.pcap` | #839 | `198.244.203.247:17348 -> 192.168.122.77:54536` | UDP STUN | STUN Binding Response retornando IP reflexivo `187.59.199.39:54536` |
