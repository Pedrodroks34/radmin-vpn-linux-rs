# Radmin VPN — Cliente Linux Nativo (Rust)

Cliente independente do Radmin VPN para Linux, desenvolvido com base em
engenharia reversa do instalador oficial `Radmin_VPN_2.1.4951.1.exe`.

**Status:** Em desenvolvimento — apenas esboço de módulos. Nenhuma funcionalidade
de rede está implementada ainda.

## Aviso legal

Este projeto é para fins de interoperabilidade e estudo. Não usa código da
Famatech Corp. Não depende de ZeroTier, Tailscale, Hamachi, Wine ou qualquer
outra VPN. Não implementa criptografia própria.

## Estrutura dos módulos (baseada na REA)

| Módulo | Papel | Status |
|---|---|---|
| `protocol` | Protocolo ROS (sinalização) | Esboço |
| `discovery` | Descoberta de servidores via DNS/DoH | Esboço |
| `identity` | Identidade do dispositivo | Esboço |
| `authentication` | Handshake de autenticação | Esboço |
| `crypto` | Canais criptografados (ring/rustls) | Esboço |
| `transport` | Canais UDP/TCP/relay | Esboço |
| `session` | Gerenciamento de sessões | Esboço |
| `network` | Redes virtuais e membros | Esboço |
| `routing` | Tabelas de rotas | Esboço |
| `peer` | Descoberta de peers | Esboço |
| `nat` | Detecção de NAT e hole punching | Esboço |
| `relay` | Servidores de retransmissão | Esboço |
| `tunnel` | Interface TUN/TAP Linux | Esboço |
| `daemon` | Serviço systemd | Esboço |
| `cli` | Interface de linha de comando | Esboço |
| `config` | Configuração persistente | Esboço |

## Evidências coletadas (REA)

- Instalador: Inno Setup + MSI aninhado, SHA-256
  `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7`
- Serviço: `RvControlSvc.exe` (pipe `\\.\pipe\RadminVpnGuiChannel`)
- Cliente ROL: `RvROLClient.dll` (47 exportações `ROLClient_*`)
- NAT client: `RvUESClient.dll` (`UESC_GetTcpNatType`, etc.)
- Driver: `NetMP60.sys` (NDIS virtual, `\Device\RVPNNETMP`)
- Assinatura: DigiCert → Famatech Corp. (Road Town, VG)

## Próximos passos (obrigatório antes de implementar rede)

1. Análise dinâmica do cliente Windows (Wireshark + depurador) para extrair:
   - Endereços e portas dos servidores ROS
   - Estrutura binária dos pacotes
   - Handshake de autenticação
   - Algoritmos de criptografia
2. Decompilação de `RvROLClient.dll` e `RvControlSvc.exe`
3. Especificar o protocolo em `docs/PROTOCOL_SPEC.md`
4. Implementar módulos gradualmente

## Compilar

```bash
cargo build
cargo run -- --help
```

## Licença

MIT