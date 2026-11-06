# PCAP Implementation Readiness — Radmin VPN Linux Client

**Projeto:** Radmin VPN Linux client (Rust, independente)  
**Base:** Análise de 6 capturas PCAP/PCAPNG em `claude-handoff/pcaps/`  
**Data:** 06 nov 2026  
**Commit-base:** 9eecbfe  

---

## Sumário da Matriz de Prontidão

| # | Item | Prontidão | Evidência Necessária para Avançar |
|---|---|---|---|
| 1 | Framing de controle | PRONTO | — |
| 2 | Handshake inicial | NÃO PRONTO | Capturar handshake antes de qualquer conexão TCP |
| 3 | Autenticação | NÃO PRONTO | Material de chave + tráfego de autenticação |
| 4 | Criptografia | NÃO PRONTO | Chaves AES + algoritmo + modo de operação |
| 5 | STUN | PRONTO | Portas e formato de mensagem confirmados |
| 6 | NAT traversal | PARCIAL | Tipo de NAT + hole punching bem-sucedido |
| 7 | Descoberta de peers | PARCIAL | Mecanismo de descoberta + TLV completo |
| 8 | UDP/9993 | PARCIAL | Estrutura completa + região criptografada |
| 9 | UDP/47836 | PRONTO | Formato confirmado |
| 10 | Relay | NÃO PRONTO | Confirmação de servidor de relay |
| 11 | Interface virtual | PRONTO | ARP + IP 26.x.x.x confirmados |
| 12 | Encapsulamento de pacotes | NÃO PRONTO | Formato interno dos pacotes VPN |

---

## Detalhamento por Item

### 1. Framing de Controle — PRONTO

**Evidência nos PCAPs:**
- TCP/17301: `[4-byte big-endian length][payload]` validado em 8 frames (frames 77, 80, 81, 82, 87, 88, 93, 94 de `radmin-connect.pcapng`)
- TCP/17351: Mesmo framing validado em frames 5487, 5493, 5494, 5501 de `radmin_vm.pcap`
- O campo de length exclui os 4 bytes do próprio header

**O que pode ser implementado:**
- Parser de framing TCP para controle
- Reassembly de mensagens fragmentadas (ex: 2592 bytes em 2 segmentos TCP)

**O que ainda precisa:**
- Nenhum — o framing está completamente caracterizado

---

### 2. Handshake Inicial — NÃO PRONTO

**Evidência nos PCAPs:**
- O handshake `00 00 00 04 03 00 00 00` mencionado em relatórios anteriores NÃO aparece no início de nenhuma conexão TCP capturada
- As capturas TCP/17301 começam com dados PSH+ACK, não com o handshake de 8 bytes
- Possível explicação: o handshake ocorre antes do início da captura ou é filtrado

**Evidência necessária:**
- Capturar rede ANTES de iniciar o cliente Radmin
- Capturar os primeiros bytes de cada conexão TCP/17301
- Verificar se o handshake `00 00 00 04 03 00 00 00` é enviado antes do handshake TCP ou após o estabelecimento TCP

**Bloqueador:** Sem o handshake, não é possível iniciar a conexão de controle.

---

### 3. Autenticação — NÃO PRONTO

**Evidência nos PCAPs:**
- Todo o tráfego TCP/17301 e TCP/17351 está criptografado
- Não há campos identificáveis como credenciais, tokens ou material de autenticação em plaintext
- Não há evidência de SRP ou outro protocolo de autenticação no tráfego capturado

**Evidência necessária:**
- Capturar tráfego durante o login do cliente (sincronizado com eventos de UI)
- Identificar onde são enviados usuário/senha ou material de autenticação
- Verificar se a autenticação ocorre dentro do canal criptografado ou antes

**Bloqueador:** Sem entender a autenticação, não é possível estabelecer uma conexão válida.

---

### 4. Criptografia — NÃO PRONTO

**Evidência nos PCAPs:**
- Região criptografada de 48 bytes (0x2E–0x5D) nas mensagens UDP/9993 Família A
- Todo o payload TCP/17301 e TCP/17351 parece criptografado (alta entropia)
- Não há nonce, IV ou chave visíveis em nenhum pacote

**Evidência necessária:**
- Chaves AES-256-CBC (32 bytes) usadas pelo CCryptoChannel
- IV usado (fixo ou variável)
- Modo de operação (CBC confirmado em análise estática, mas não verificado no tráfego)
- Padding scheme (0xcc fill + checksum + size indicator, conforme análise estática)

**Bloqueador:** Sem as chaves, não é possível criptografar/descriptografar o tráfego.

---

### 5. STUN — PRONTO

**Evidência nos PCAPs:**
- Binding Request (20 bytes) e Binding Response (56 bytes) observados em 9 portas
- Portas: 17309, 17310, 17341, 17342, 17347, 17348, 17349, 17357, 17358
- Formato RFC 5389 padrão: Message Type 0x0001, Message Length 0x0000, Transaction ID 16 bytes
- Retry automático após ~100ms

**O que pode ser implementado:**
- Cliente STUN Binding Request nas portas Radmin-specificas
- Parsing de Binding Response para extrair endereço mapeado

**O que ainda precisa:**
- Decodificar atributos STUN nas respostas (MAPPED-ADDRESS, XOR-MAPPED-ADDRESS)
- Verificar se o magic cookie padrão (0x2112A442) é usado

---

### 6. NAT Traversal — PARCIAL

**Evidência nos PCAPs:**
- Hole punching observado: mesma mensagem UDP/9993 enviada de portas 9993, 48318, 48870
- STUN Binding Request/Response em múltiplos servidores
- Não há confirmação de hole punching bem-sucedido (não há pares de request/response verificados)

**Evidência necessária:**
- Determinar tipo de NAT (Full Cone, Restricted, Symmetric)
- Verificar se hole punching resulta em comunicação bidirecional estabelecida
- Capturar tráfego após hole punching bem-sucedido

**Bloqueador parcial:** Não é possível implementar NAT traversal confiável sem saber o tipo de NAT.

---

### 7. Descoberta de Peers — PARCIAL

**Evidência nos PCAPs:**
- TLV 0x0004 contém IP + porta do peer (big-endian)
- Identificador de sessão de 10 bytes: `e5 d4 c1 c5 bc 21 59 16 c8 0f`
- Não há evidência de como a lista de peers é obtida (servidor de descoberta? broadcast?)

**Evidência necessária:**
- Identificar como os peers são descobertos (servidor central? lista estática? broadcast?)
- Especificar completamente o TLV 0x0004 e outros campos TLV
- Verificar se existem outros tipos de TLV além do 0x0004

**Bloqueador parcial:** Sem mecanismo de descoberta, o cliente não sabe com quais peers comunicar.

---

### 8. UDP/9993 — PARCIAL

**Evidência nos PCAPs:**
- 5 famílias de mensagem identificadas por tamanho (28, 33, 99, 137, 247-641 bytes)
- Estrutura parcialmente mapeada para a Família A (137 bytes)
- Região criptografada de 48 bytes não decifrável sem chaves
- TLV 0x0004 com IP/porta do peer confirmado

**Evidência necessária:**
- Especificar completamente todos os campos de todas as famílias
- Identificar o algoritmo de criptografia usado na região de 48 bytes
- Determinar se há nonce ou IV nas mensagens UDP/9993
- Especificar os 17 bytes não documentados no offset 0x78–0x88 da Família A

**Bloqueador parcial:** Não é possível implementar a comunicação P2P completa sem entender a criptografia e todos os campos.

---

### 9. UDP/47836 — PRONTO

**Evidência nos PCAPs:**
- 4 bytes de payload, formato `XX 02 00 00` (contador sequencial little-endian uint16)
- Contador incrementa +1 a cada mensagem
- Interval ~1 segundo entre keepalives
- Apenas uma direção observada (26.228.88.155 → 26.239.229.134)

**O que pode ser implementado:**
- Envio de keepalive periódico com contador sequencial
- Recebimento e validação de keepalives

**O que ainda precisa:**
- Verificar se há resposta esperada ao keepalive
- Determinar timeout para detecção de peer morto

---

### 10. Relay — NÃO PRONTO

**Evidência nos PCAPs:**
- Fluxo de grande volume (3,1 MB) entre 192.168.15.15:43139 e [IP_PUBLICO_MASCARADO}:58358 (UDP)
- Não há evidência de que seja um servidor Radmin de relay
- Pode ser tráfego de outro serviço ou P2P direto com outro peer

**Evidência necessária:**
- Confirmar se existe um servidor de relay dedicado no protocolo Radmin
- Identificar o protocolo usado no canal de relay
- Verificar se o tráfego de grande volume é Radmin ou outro serviço

**Bloqueador:** Não há evidência de relay no protocolo Radmin nas capturas.

---

### 11. Interface Virtual — PRONTO

**Evidência nos PCAPs:**
- Interface `radminvpn0` com IP `26.239.229.134/8`
- ARP para resolução de endereços virtuais
- MACs locais (prefixo 02:xx)
- IGMPv3, SSDP, MDNS como tráfego auxiliar

**O que pode ser implementado:**
- Interface TUN/TAP com endereço 26.x.x.x
- Resposta ARP para IPs virtuais
- Roteamento de pacotes entre interface virtual e sockets UDP

**O que ainda precisa:**
- Determinar o driver de interface virtual (tun/tap vs outro)
- Especificar o formato de encapsulamento entre interface virtual e rede física

---

### 12. Encapsulamento de Pacotes — NÃO PRONTO

**Evidência nos PCAPs:**
- Não há evidência de como os pacotes da interface virtual são encapsulados para transmissão na rede física
- Não há correlação direta entre pacotes Ethernet na interface virtual e pacotes UDP na interface física (além do nível de mensagem UDP/9993)
- Não há evidência de cabeçalho adicional entre a camada virtual e o transporte UDP

**Evidência necessária:**
- Capturar tráfego na interface virtual e física simultaneamente com correlação pacote-a-pacote
- Determinar se há encapsulamento adicional (GRE, UDP-in-UDP, etc.)
- Verificar se o formato dos pacotes na interface virtual é o mesmo do UDP/9993

**Bloqueador:** Sem entender o encapsulamento, não é possível implementar a interface virtual funcionando.

---

## Recomendações de Prioridade para Implementação

### Alta Prioridade (bloqueadores)

1. **Capturar handshake inicial** — Sem o handshake, não há conexão de controle
2. **Obter chaves de criptografia** — Sem chaves, não há comunicação segura
3. **Entender encapsulamento** — Sem encapsulamento, a interface virtual não funciona

### Média Prioridade (parciais)

4. **Especificar completamente UDP/9993** — Incluindo os 17 bytes não documentados e a região criptografada
5. **Identificar mecanismo de descoberta de peers** — Como a lista de peers é obtida
6. **Determinar tipo de NAT** — Para implementar NAT traversal confiável

### Baixa Prioridade (não-bloqueantes)

7. **Implementar keepalive UDP/47836** — Simples, formato confirmado
8. **Implementar cliente STUN** — Formato confirmado, portas conhecidas
9. **Implementar interface virtual TUN/TAP** — Formato de IP conhecido

---

## Experimentos Recomendados (Próxima Etapa)

1. **Captura do handshake:** Iniciar captura de rede antes de lançar o cliente Radmin, capturar os primeiros bytes de cada conexão TCP/17301
2. **Captura sincronizada com UI:** Sincronizar captura de rede com eventos de login/conexão do cliente para identificar autenticação e troca de chaves
3. **Decodificação STUN:** Usar dissector STUN adequado para decodificar atributos nas respostas de 98 bytes
4. **Correlacionar pacotes:** Capturar interface virtual e física simultaneamente, correlacionar pacote-a-pacote por tamanho e timestamp
5. **Interoperabilidade real:** Testar com o cliente Windows oficial para validar o protocolo (apenas observação, sem modificação)

---

**Documento gerado:** `docs/PCAP_IMPLEMENTATION_READINESS.md`  
**Arquivos .pcapng originais:** Preservados, não modificados  
**Código-fonte do projeto:** Não alterado