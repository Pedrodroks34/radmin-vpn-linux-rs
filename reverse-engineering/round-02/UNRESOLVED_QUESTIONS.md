# Questões em Aberto e Classificação de Certeza (Round 02)

Este documento classifica rigorosamente todas as descobertas entre fatos **CONFIRMADOS**, evidências **CORROBORADAS**, **HIPÓTESES** plausíveis e lacunas técnicas **DESCONHECIDAS**, priorizando o que ainda depende de testes de interoperabilidade reais.

---

## 1. Classificação Geral das Descobertas

| Componente / Funcionalidade | Status | Nível de Confiança | Justificativa / Prova |
|---|---|---|---|
| **Magic de Framing (4B BE + `03 00 00 00`)** | **CONFIRMADO** | 100% | Validado em `shelper.dll` e pacote #35/#44 em `radmin_17301.pcap` |
| **Formato do Client Hello (RSA-2048 PKCS#1 v1.5 com bloco de 76B)** | **CONFIRMADO** | 100% | Desmontagem de `SHelper_RSession_GetNextBuffer` (`0x1006a512`) |
| **Server Hello Token (4 bytes)** | **CONFIRMADO** | 100% | Desmontagem do Estado 2 (`0x1006a4cc`) e pacote #48 |
| **Derivação de Chave AES-256 (primeiros 32B da chave efêmera)** | **CONFIRMADO** | 100% | Desmontagem de `SHelper_RSession_GetKey` e `SetKeyEnc` (`0x1006ab00`) |
| **Inicialização do IV com 16 zeros e encadeamento contínuo** | **CONFIRMADO** | 100% | Desmontagem do construtor (`0x10062ca9`) e chamadas a `AES_cbc_encrypt` |
| **Trailer Proprietário (Alinhamento 16B, Padding 0xCC, Soma 64-bit, PadLen 9..24)** | **CONFIRMADO** | 100% | Desmontagem de `FUN_10069c20`, `FUN_1006a0c0` e `FUN_10069f90` |
| **Semântica da Tag TLV `0x010001e3` como Atributo Operacional de Rede** | **CONFIRMADO** | 100% | Desmontagem em `RvControlSvc.exe` (`0x41537e`) e `RvROLClient.dll` (`0x1004ef1c`) |
| **Hashing de Senha de Rede via SHA-1 (`0x090001cd`)** | **CONFIRMADO** | 100% | Desmontagem de `0x10065790` chamando CryptoAPI com `CALG_SHA1` (`0x8004`) |
| **Protocolo STUN RFC 3489 na Porta UDP 17309..17349** | **CONFIRMADO** | 100% | Atributos 0x0001, 0x0004 e 0x0005 decodificados em `radmin_vm2.pcap` |
| **Desobfuscação Teredo (XOR 0xFFFF e XOR 0xFFFFFFFF)** | **CONFIRMADO** | 100% | Desmontagem de `CTeredoThread` em `RvROLClient.dll` (`0x10052310`) |
| **Códigos IOCTL do Driver (`0x22c004`, `0x228014`, `0x22801c`, `0x224018`, `0x224020`)** | **CONFIRMADO** | 100% | Desmontagem de chamadas a `DeviceIoControl` em `RvControlSvc.exe` |
| **Named Pipe IPC (`\\.\pipe\RadminVpnGuiChannel`) e Comandos `0x3ec..0x3f6`** | **CONFIRMADO** | 100% | Desmontagem em `RvRvpnGui.exe` (`0x4e8eb0`) e `RvControlSvc.exe` (`0x40f052`) |
| **Mecanismo de Obtenção da Chave Pública RSA do Servidor** | **CORROBORADO** | 80% | Chave RSA embutida no binário/configuração, mas com mecanismo de atualização dinâmica não totalmente mapeado |
| **Política de Renovação de Chaves (Rekeying Period)** | **HIPÓTESE** | 50% | Indícios de rekeying após expiração de timer de inatividade ou volume limite, sem gatilho explícito no PCAP |
| **Mapeamento de Todos os 723 Descritores de Propriedade TLV** | **CORROBORADO** | 75% | Tabela de tipos e tags extraída integralmente de `0x00498fe0`; semântica detalhada de 45 tags prioritárias identificada |

---

## 2. Questões Prioritárias em Aberto

### Questão 1 (Prioridade ALTA): Provisão e Ancoragem da Chave Pública RSA do Servidor
* **Situação Atual:** No handshake do cliente (`shelper.dll!0x1006a540`), a chave pública RSA do servidor é passada como parâmetro no ponteiro `[esi + 0x18]`.
* **Lacuna Técnica:** O cliente oficial carrega a chave RSA de coordenação diretamente de uma tabela de chaves confiáveis embutida em `.rdata` do executável ou aceita chaves dinâmicas negociadas previamente?
* **Estratégia de Validação:** Localizar a tabela de certificados/chaves públicas em `.rdata` de `RvROLClient.dll` e verificar se há verificação de assinatura digital estrita (Certificate Pinning) ou se qualquer chave RSA-2048 padrão é aceita em servidores privados.

### Questão 2 (Prioridade MÉDIA): Frequência de Rekeying e Keepalive
* **Situação Atual:** No fluxo `radmin_17301.pcap`, a sessão de controle permanece aberta por minutos trocando pacotes pequenos de telemetria sem renovar a chave AES negociada inicialmente.
* **Lacuna Técnica:** O protocolo exige rekeying periódico por tempo (ex.: a cada 1 hora) ou por bytes transmitidos? Ou a sessão é puramente persistente até a desconexão do socket?
* **Estratégia de Validação:** Executar uma sessão longa com transferência de tráfego de alta volumetria (ex.: transferência contínua de arquivo iperf de 5 GB pela VPN) para observar se o servidor emite uma mensagem TLV de solicitação de novo handshake.

### Questão 3 (Prioridade BAIXA): Bitmask Completo dos Atributos em `0x010001e3`
* **Situação Atual:** Confirmamos que `0x010001e3` é um atributo de rede de 32 bits utilizado no controle de roteamento e permissões.
* **Lacuna Técnica:** Quais são exatamente todos os bits de flag mapeados nos 32 bits (ex.: bit 0 = Broadcast habilitado, bit 1 = Isolamento de clientes, bit 2 = Acesso a sub-redes locais)?
* **Estratégia de Validação:** Comparar capturas de configuração de redes com diferentes configurações administrativas marcadas no painel da GUI oficial.
