# Frente 7: Mecanismo de Tunelamento Teredo

**Classificação de Certeza:** CONFIRMADO (identificação da classe `CTeredoThread` em `RvROLClient.dll` e captura de tráfego UDP na porta 3544 em `radmin_vm2.pcap`)

---

## 1. Visão Geral do Uso de Teredo no Radmin VPN

O Radmin VPN inclui um subsistema completo de tunelamento baseado no padrão **Teredo (RFC 4380)**, implementado na classe interna `CTeredoThread` da biblioteca `RvROLClient.dll`. O objetivo principal deste mecanismo é fornecer um caminho alternativo de conectividade ponto-a-ponto através de IPv6 encapsulado em pacotes UDP quando a infraestrutura de rede intermediária bloqueia protocolos P2P clássicos em IPv4 ou implementa NATs agressivos.

---

## 2. Evidência em Tráfego de Rede (`radmin_vm2.pcap`)

Na captura de rede `radmin_vm2.pcap`, no pacote #10:
* **Protocolo de Transporte:** UDP
* **Porta de Destino:** `3544` (Porta padrão atribuída pela IANA para o serviço Teredo)
* **IP do Servidor de Retransmissão:** `20.201.205.4:3544` (Infraestrutura pública oficial de Teredo da Microsoft)

O cliente emite solicitações de roteamento e pacotes de teste Teredo com cabeçalho de autenticação nula para qualificar a viabilidade do túnel IPv6.

---

## 3. Estrutura do Endereço Teredo e Desobfuscação

O endereço IPv6 Teredo gerado e processado pelo cliente possui 128 bits estruturados conforme a RFC 4380:

```
+----------------+----------------+----------------+----------------+
| Prefix 32 bits | Server IPv4    | Flags 16 bits  | Obfuscated Port|
| (2001:0000::)  | 32 bits        |                | 16 bits        |
+----------------+----------------+----------------+----------------+
| Obfuscated IPv4 Address (32 bits)                                 |
+-------------------------------------------------------------------+
```

### 3.1 Rotina de Desobfuscação em `RvROLClient.dll`
No código desmontado de `CTeredoThread`:
Para contornar dispositivos NAT que inspecionam o payload à procura de endereços IP locais para tradução incorreta (*ALG - Application Layer Gateway*), o Teredo ofusca a porta e o IP reflexivo aplicando uma operação `XOR` bit a bit:

$$\text{PortaReal} = \text{ObfuscatedPort} \oplus \text{0xFFFF}$$

$$\text{IPv4Real} = \text{ObfuscatedIPv4} \oplus \text{0xFFFFFFFF}$$

A desmontagem em `RvROLClient.dll` implementa diretamente essa desobfuscação:
```x86asm
0x10052310: movzx eax, word ptr [esi + 0x28] ; lê porta ofuscada
0x10052314: xor eax, 0xffff                  ; desofusca porta via XOR 0xFFFF
0x10052319: mov dword ptr [esi + 0x30], eax  ; armazena porta real do peer
0x1005231c: mov eax, dword ptr [esi + 0x2a]  ; lê IPv4 ofuscado
0x1005231f: xor eax, 0xffffffff              ; desofusca IPv4 via XOR 0xFFFFFFFF
0x10052324: mov dword ptr [esi + 0x34], eax  ; armazena IP reflexivo decodificado
```

---

## 4. Prioridade de Seleção na Arquitetura do Cliente

Na árvore de decisão de transporte do Radmin VPN, o mecanismo Teredo opera como uma **estratégia de fallback secundária**:
1. Se o P2P direto IPv4 (UDP/TCP) falhar;
2. Se o cliente possuir suporte ou adaptador Teredo ativo;
3. O cliente tenta a comunicação via encapsulamento IPv6 Teredo através da porta UDP 3544 antes de recorrer em definitivo ao servidor centralizado de `TcpRelay` (porta 17351).
