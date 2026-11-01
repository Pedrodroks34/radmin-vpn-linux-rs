# Relatório de Engenharia Reversa — Radmin VPN 2.1.4951.1

## Resumo executivo

O instalador `Radmin_VPN_2.1.4951.1.exe` (54,3 MB, Inno Setup + MSI) contém:
- `RvRvpnGui.exe` — GUI Qt 5.15/QML
- `RvControlSvc.exe` — serviço Windows, motor FamRT/C++ com IOCP
- `RvROLClient.dll` — cliente ROL (47 exports: conectar, registrar, juntar rede, enviar, receber, NAT, etc.)
- `RvUESClient.dll` — detecção de tipo de NAT
- `NetMP60.sys` — driver NDIS virtual (`\Device\RVPNNETMP`, L2 Ethernet)
- Componentes legacy do Radmin Server 3 (`Radmin.exe`, `rchatx.dll`, `voicex.dll`, etc.)

## Arquitetura (confirmada via REA)

```
GUI (Qt) ── named pipe \\.\pipe\RadminVpnGuiChannel ──> Serviço RvControlSvc.exe
                                                        │
                          ├─ RvROLClient.dll ─────────► ROS (servidor de sinalização)
                          ├─ RvUESClient.dll ──────────► Detecção de tipo de NAT
                          ├─ WFP (fwpuclnt) ───────────► Regras de firewall
                          ├─ IPHLPAPI ─────────────────► Rotas e IPNet
                          └─ DeviceIoControl ──────────► NetMP60.sys (adapter virtual L2)
```

## Componentes e papéis (tabela detalhada)

Ver `README.md`.

## Tipos de pacote identificados via RTTI (RvROLClient.dll)

Os seguintes tipos de pacote foram extraídos dos nomes de classes C++ nos binários
(strings `?AV*Packet@RolClient@@`). Suas estruturas binárias são **desconhecidas**.

| Pacote | Inferência de papel |
|---|---|
| `CAbstractClnPacket` / `VIClnPacket` | Pacote cliente abstrato / interface |
| `CAbstractConnectionPacket` | Pacote de conexão abstrato |
| `CCancelJoinPacket` | Cancelar entrada em rede |
| `CChatCommandPacket` | Comando de chat |
| `CChatGetNodesPacket` | Obter nós via chat |
| `CClientVersionInfo` | Informação de versão do cliente |
| `CConflictedIpAddressPacket` | Detecção de conflito de IP |
| `CConnectResultPacket` | Resultado de conexão |
| `CDirectEnetInfoPacket` | Info de rede Enet direta |
| `CEnetInfoPacket` | Info de rede Enet |
| `CEnumPublicNetworksPacket` | Enumerar redes públicas |
| `CGenericPacket` | Pacote genérico |
| `CGetNodeRegionSupportPacket` | Suporte de região do nó |
| `CGuiLanguagePacket` | Idioma da GUI |
| `CHeartbeatPacket` | Heartbeat / keep-alive |
| `CIsAlivePacket` | Verificar se está vivo |
| `CJoinNetworkPacket` | Entrar em rede virtual |
| `CLoginPacket` | Login / autenticação |
| `CLogPacket` | Pacote de log |
| `CManageNetworkPacket` | Gerenciar rede virtual |
| `CMsgAuthFailed` | Autenticação falhou |
| `CMsgAuthFinished` | Autenticação finalizada |
| `CMsgBadServerPacket` | Servidor ruim / inválido |
| `CMsgNetPacket` | Pacote de rede |
| `CMsgRosIgnored` | ROS ignorado |
| `CNatPenPackets` / `CNatPenStatusPacket` | Pacotes de penetração de NAT |
| `CPacketConnection` (FamRT) | Conexão de pacote |
| `CRequestTrsPacket` | Requisição TRS |
| `CRosConnectionPacket` | Conexão ROS |
| `CRosPacket` / `IRosPacket` | Pacote ROS (interface) |
| `CRosPktChatCommandReply` | Resposta de comando de chat ROS |
| `CRosPktCollectTcpNatInfo` | Coletar info NAT TCP |
| `CRosPktLicInfo` | Info de licença |
| `CRosPktPushInfo` | Push de info (notificação) |
| `CRServerInfoPacket` | Info do servidor R |
| `CSessionSummaryPacket` | Resumo de sessão |
| `CStartEnetPacket` | Iniciar Enet |
| `CTcpInfoPacket` | Info TCP |
| `CTcpNatInfoPacket` | Info NAT TCP |
| `ReplyPacket` (ControlSvc) | Pacote de resposta do serviço |

Classes de suporte identificadas: `CPenSocket`, `USNatPenPacket`, `USNatPenWave`,
`USPenGroup`, `USPortPara`, `CAuthSessionId`, `CRosAddress`, `CRosSessionId`,
`CCryptoChannel`, `VCRosSessionId`, `VCConnector`, `VCConnection`, `CConnectionPool`,
`CEnetScheduler`, `CChatRegionSupportCache`, `CNodeMapEntry`, `CVNetWorker`,
`CConContainer`, `NTcpConnect`, `NTrsConnect`, `ENETConnect`.

## Classificação das descobertas

| Item | Status | Base |
|---|---|---|
| Instalador Inno Setup + MSI | Confirmada | Recursos PE, strings |
| Serviço Windows + named pipe | Confirmada | Imports + strings |
| GUI Qt 5.15/QML | Confirmada | Imports Qt5* |
| Driver NDIS virtual L2 | Confirmada | .inf + strings do .sys |
| DNS-over-HTTPS + resolvers públicos | Confirmada | String `https://%hs/dns-query` + IPs hardcoded |
| Servidores ROS não hardcoded | Confirmada | Nenhum IP de servidor encontrado nos binários |
| Canais criptografados + compressão | Confirmada (existem) | Exports `SetCompression`, `DisableEncryption` |
| NAT traversal (hole punching) | Confirmada (existe) | Classes `CPenSocket`, `USNatPenPacket`, etc. |
| Tipos de pacote ROS | Confirmada (nomes) | RTTI strings `?AV*Packet@RolClient@@` |
| Estrutura binária dos pacotes | Desconhecida | Requer REA dinâmica |
| Algoritmos de criptografia | Desconhecido | Sem strings identificáveis |
| Portas de rede | Desconhecido | Nenhuma porta fixa encontrada |
| Handshake de autenticação | Desconhecido | Requer REA dinâmica |

## Descobertas de Tráfego (Captura Wireshark)

### Setup de captura
- Interface: `virbr0` (Libvirt Bridge)
- VM IP: `192.168.122.77`
- Arquivo 1: `/tmp/radmin_vm.pcap` (~21 MB, ~6360 pacotes)
- Arquivo 2: `/tmp/radmin_vm2.pcap` (~196 KB, ~69 frames TCP para porta 17301)
- Sub-extração porta 17301: `/tmp/radmin_17301.pcap` (~30 KB, 3 fluxos TCP distintos)

### Porta de controle e servidor
- **Porta 17301 TCP** — confirmada como porta de controle do Radmin
- **Servidor principal:** `148.113.190.78` (alternantes: `198.244.203.247`, `45.162.230.182`)

### Formato do frame (CONFIRMADO via captura)
- **Cabeçalho:** 4 bytes, big-endian, `uint32_t` = tamanho do payload (NÃO inclui os 4 bytes do cabeçalho)
- **Endianness:** Big-endian (confirmado via `00 00 00 20` = 32)
- **Validação:** 54 frames extraídos de 3 fluxos TCP, 22824 bytes consumidos, 0 bytes restantes, sem truncamento

### Validação do parser
- Extração por fluxo TCP: Stream 0 (19 frames, 11260 bytes), Stream 1 (18 frames, 5920 bytes), Stream 2 (17 frames, 5644 bytes)
- Todos os fluxos consumidos completamente sem truncamento
- Parser implementado em `src/protocol/framing.rs` com 8 testes passando
- Integração com `src/transport/mod.rs` concluída com 5 testes de integração

### Pacote de controle
- `00 00 00 04 03 00 00 00` — cabeçalho (tamanho=4) + payload `03 00 00 00`
- Significado não confirmado (keepalive, ACK ou handshake)

### Reconexão
- Nova conexão TCP na porta de origem diferente após desconexão
- Reconexão observada ~30 segundos após a primeira conexão

## Próximos passos obrigatórios

1. Executar cliente Windows em VM isolada com Wireshark para capturar tráfego real.
2. Decompilar `RvROLClient.dll` e `RvControlSvc.exe` (Ghidra/IDA/Kuna) para extrair:
   - Estruturas binárias dos pacotes (offsets, tamanhos, tipos).
   - Funções de serialização/desserialização.
   - Algoritmos criptográficos.
   - Endereços e portas dos servidores ROS/relay.
3. Preencher todas as células marcadas `desconhecido` nesta especificação.
4. Somente então substituir `_raw: Vec<u8>` pelas estruturas Rust reais em `src/protocol/packets.rs`.

## Diretório de extração

Os binários foram extraídos para `/tmp/opencode/radmin_ext/` (fora deste repositório).

## Limitações

- Nenhum motor de decompilação (Ghidra/IDA/Hopper) disponível neste host.
- Nenhuma execução observada (não há depuração, emulação ou replay).
- Declarações sobre pacotes exatos, handshake e criptografia são inferências de símbolos.
- Não foram capturados pacotes de rede reais de peers (apenas servidor de controle).
- A estrutura interna do payload (campos, tipos, ordem) permanece desconhecida.