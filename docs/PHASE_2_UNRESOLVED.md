# Questões Não Resolvidas e Próximos Passos — Fase 2 (`PHASE_2_UNRESOLVED.md`)

> **Projeto**: Radmin VPN Linux (Interoperabilidade com Cliente Oficial)  
> **Fase**: Fase 2 — Handshake SHelper da Conexão de Controle  
> **Data**: 2026-11-02  

---

## 1. Escopo Efetivamente Resolvido na Fase 2

1. **Identificação e Formalização da Família B (`SHelper_*`)**:
   - Resolução definitiva de que `SHelper_*` (`0x1006ab90`) implementa **SRP-6a** (Thomas J. Wu) e constitui o protocolo da conexão de controle na porta `17301`, dissociando-o de `SHelper_RSession_*` (RSA-2048, Fase 1).
2. **Matemática do SRP-6a**:
   - Parâmetros comprovados por engenharia reversa de `shelper.dll`: Primo $N$ de 1536 bits (`0x100ac280`), $g = 5$, $k = 3$, hash SHA-1 e KDF de 40 bytes (`0x10061790`).
3. **Framing TLV dos Payloads**:
   - Framing de cabeçalho de 4 bytes (`tag` em 5 bits, `length` em 27 bits) em network byte order.
4. **Implementação em Rust e Canal Criptográfico**:
   - `ControlClientNegotiator`, `ControlServerSession` e `ControlConnection` operando com `FamatechCipherState` (AES-256-CBC) e testados ponta a ponta com 101 testes passando.

---

## 2. Questões Pendentes para a Fase 3 (Fora do Escopo da Fase 2)

### 2.1 Catálogo TLV de Login e Gerenciamento de Rede (Pós-Handshake)
- **Descrição**: Uma vez estabelecido o canal cifrado AES-256 da conexão de controle, o cliente oficial troca mensagens binárias para autenticação de conta, obtenção de lista de redes e gerenciamento de membros.
- **Evidências Necessárias**:
  - Mapeamento das estruturas internas de mensagens TLV decifradas em `radmin_17301.pcap` (pacotes pós-handshake a partir de #51, como o frame de 208 bytes do cliente e 2576 bytes do servidor).
  - Desmontagem das tabelas de despacho de mensagens em `RvROLClient.dll!RolClient::CRosProtocol_SRP_ManageNetwork` e `CRosProtocol_ClientLogin`.
- **Impacto**: Não bloqueia a conectividade e segurança do canal de controle, mas é necessário para login de conta e adesão a redes virtuais.

### 2.2 Descoberta de Peers e Sinalização P2P
- **Descrição**: Mecanismos de troca de endpoints (IP/Porta) públicos e locais entre nós para estabelecimento de túneis diretos (STUN / Teredo / UDP Hole Punching).
- **Evidências Disponíveis**: Módulos preliminares em `src/nat/` e capturas em `radmin_vm.pcap`.
- **Próximo Passo**: Conectar a sinalização de endpoints recebida pelo canal de controle da Fase 2 ao orquestrador de túnel.

### 2.3 Resiliência e Reconexão com Cluster de Múltiplos Nós
- **Descrição**: As capturas demonstram conexões concorrentes para múltiplos servidores de borda (`148.113.190.78:17301` e `198.244.203.247:17301`).
- **Comportamento Atual**: O cliente conecta a um endpoint especificado.
- **Evolução Futura**: Implementar pool de conexões de controle redundantes com reconexão automática e failover.
