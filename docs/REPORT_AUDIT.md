# Auditoria Crítica do Relatório de Engenharia Reversa do Radmin VPN
**Arquivo:** `docs/REPORT_AUDIT.md`  
**Autor:** Antigravity (Google DeepMind - Advanced Agentic Coding)  
**Data:** 01 de Novembro de 2026  
**Binários Auditados:** `RvControlSvc.exe`, `RvROLClient.dll`, `RvUESClient.dll`, `shelper.dll`, `NetMP60_1_1_64.sys`  
**PCAPs Auditados:** `radmin_17301.pcap`, `radmin_vm2.pcap`, `radmin_vm.pcap`  

---

## 1. Introdução e Metodologia

Esta auditoria técnica independente foi realizada para verificar de forma rigorosa as conclusões anteriormente documentadas no relatório `RELATORIO_ENGENHARIA_REVERSA_RADMIN.md`. 

Nenhuma afirmação anterior foi aceita a priori. Todas as conclusões foram submetidas a verificação cruzada:
1. **Inspeção de pacotes brutos** nos PCAPs originais (`dpkt`, `scapy`).
2. **Desmontagem e descompilação instrução por instrução** dos binários em assembly x86/x64 (`capstone`, Ghidra 12.2).
3. **Desenvolvimento e execução de testes independentes** de codificação/decodificação com dados sintéticos.

---

## 2. Validação do Formato TLV

### 2.1 Confirmação da Estrutura Wire
- **Estrutura Declarada:** `[uint32 length][uint32 tag][value]`
- **Status da Validação:** **CONFIRMADA COM PRECISÃO.**
- **Evidência no Tráfego:**
  - No arquivo **`radmin_vm2.pcap`**, **Pacote #686** (e correlatos #5486 e #5631 no `radmin_vm.pcap`):
    - Framing externo TCP: `00 00 01 20` (Big-Endian `0x0120` = 288 bytes).
    - **Registro 1:**
      - Comprimento: `00 00 00 04` (4 bytes)
      - Tag: `01 00 01 df` (`Tipo 1`, Campo `0x1df`)
      - Valor: `00 00 00 01` (uint32 = 1)
    - **Registro 2:**
      - Comprimento: `00 00 00 04` (4 bytes)
      - Tag: `01 00 03 2b` (`Tipo 1`, Campo `0x32b`)
      - Valor: `00 00 00 02` (uint32 = 2)
    - **Registro 3:**
      - Comprimento: `00 00 01 00` (256 bytes)
      - Tag: `09 00 01 ca` (`Tipo 9`, Campo `0x1ca`)
      - Valor: 256 bytes de chave pública RSA-2048.
    - **Soma Exata:** `(4 + 4 + 4) + (4 + 4 + 4) + (4 + 4 + 256) = 12 + 12 + 264 = 288 bytes`. O tamanho corresponde exatamente ao framing externo `0x0120`.

### 2.2 Descoberta do Catálogo Global de Schemas (Binário)
- **Função:** `FUN_00498fe0` em `RvControlSvc.exe` (`0x00498fe0`).
- **Descoberta Crítica:** Esta função é um inicializador estático massivo que registra **744 descritores de campos** na tabela global `0x5a52b4` através de chamadas à função `0x004aec20`.
- **Mapeamento dos Campos Auditados:**
  - **`0x010001df`:** Registrado em `0x0049fccd` com a chamada `call 0x4aec20` (Objeto BSS em `0x59cb2c`).
  - **`0x0100032b`:** Registrado em `0x0049fd18` com a chamada `call 0x4aec20` (Objeto BSS em `0x59cb5c`).
  - **`0x090001ca`:** Registrado em `0x0049f46d` com a chamada `call 0x4aec20` (Objeto BSS em `0x59c618`).
- **Codificadores Wire em `RvControlSvc.exe`:**
  - `FUN_00488ae0`: Serializador base que executa `_byteswap_ulong` no comprimento e na tag (garantindo Big-Endian em rede).
  - `FUN_00472ef0`: Valida `tag & 0xFF000000 == 0x01000000` (inteiro 32-bit).
  - `FUN_00472f60`: Valida `tag & 0xFF000000 == 0x02000000` (inteiro 64-bit).
  - `FUN_004795d0`: Valida `tag & 0xFF000000 == 0x09000000` (buffer arbitrário).

### 2.3 Separação de Framing
- O framing de nível de transporte é **separado** do framing TLV:
  - Todo quadro TCP na rede começa com um cabeçalho fixo de 4 bytes: `[uint32 Big-Endian Length]`.
  - Antes do estabelecimento do canal cifrado, o payload é uma sequência concatenada de registros TLV.
  - Após a ativação da cifragem, o cabeçalho de 4 bytes passa a indicar o comprimento do bloco criptográfico (sempre múltiplo de 16 bytes). O conteúdo TLV viaja dentro do bloco decifrado.

---

## 3. Validação da Criptografia (`shelper.dll`)

### 3.1 Pseudocódigo Reconstituído e Verificado

#### Preparação de Padding e Trailer (Antes da Cifragem - `FUN_10069c20`)
```python
def famatech_pad_and_sign(payload: bytes, block_size: int = 16) -> bytes:
    payload_len = len(payload)
    if payload_len == 0 or block_size >= 256:
        raise ValueError("Tamanho inválido")
        
    # 1. Cálculo do tamanho total alinhado:
    # No assembly: eax = block_size + 8 + payload_len; eax /= block_size; eax *= block_size;
    total_len = ((payload_len + 24) // block_size) * block_size
    pad_len = total_len - payload_len  # 9 <= pad_len <= 24 (para block_size=16)

    buf = bytearray(total_len)
    buf[:payload_len] = payload

    # 2. Preenchimento de bytes 0xCC até total_len - 9
    for i in range(payload_len, total_len - 9):
        buf[i] = 0xCC

    # 3. Checksum Aditivo de 64 bits (FUN_1006a0c0) sobre os primeiros (total_len - 9) bytes
    sum_64 = 0
    num_u64 = (total_len - 9) // 8
    for i in range(num_u64):
        word = int.from_bytes(buf[i * 8 : (i + 1) * 8], 'little')
        sum_64 = (sum_64 + word) & 0xFFFFFFFFFFFFFFFF
        
    rem = (total_len - 9) % 8
    if rem > 0:
        tail = bytes(buf[num_u64 * 8 : total_len - 9]) + b'\x00' * (8 - rem)
        word = int.from_bytes(tail, 'little')
        sum_64 = (sum_64 + word) & 0xFFFFFFFFFFFFFFFF

    # 4. Hash MD5 dos 8 bytes do Checksum (FUN_100638f0)
    sum_bytes = sum_64.to_bytes(8, 'little')
    md5_digest = bytearray(hashlib.md5(sum_bytes).digest()) # 16 bytes

    # 5. Dobra o MD5 em 8 bytes (linhas 0x10069ce0 a 0x10069d15)
    trailer_mac = bytearray(8)
    for i in range(8):
        trailer_mac[i] = (md5_digest[i] + md5_digest[i + 8]) & 0xFF

    # 6. Gravação do Trailer: 8 bytes do MAC + 1 byte de pad_len
    buf[total_len - 9 : total_len - 1] = trailer_mac
    buf[total_len - 1] = pad_len

    return bytes(buf)
```

#### Verificação e Descarte de Padding (Após a Decifragem - `FUN_10069f90`)
1. Decifra o bloco com AES-256-CBC.
2. Lê `pad_len = buf[total_len - 1]`.
3. Valida: `9 <= pad_len <= (block_size + 9)`. Se inválido, rejeita.
4. Valida se os bytes em `buf[total_len - pad_len .. total_len - 10]` são todos `0xCC`.
5. Recalcula o checksum de 64 bits sobre `buf[0 .. total_len - 9]`.
6. Recalcula o MD5 dobrado e compara com os 8 bytes em `buf[total_len - 9 .. total_len - 1]`.
7. Se idêntico, retorna o payload autêntico de `buf[0 .. total_len - pad_len]`.

### 3.2 Inicialização de Chave e IV
- **Tamanho da Chave:** 32 bytes (256 bits), verificado em `SHelper_CChannel_SetKeyEnc` (`0x1006ab00: cmp param_3, 0x20`).
- **Inicialização do IV:**
  - Na função de inicialização do canal AES (`0x10062c16` e `0x10062cac`):
    ```asm
    0x10062c16: xorps  xmm0, xmm0
    0x10062c1c: movdqu xmmword ptr [esi + 0x1ec], xmm0   ; Encrypt IV = 16 zeros
    0x10062c24: movdqu xmmword ptr [esi + 0x1fc], xmm0   ; Decrypt IV = 16 zeros
    ```
  - **O IV inicial é exatamente 16 bytes nulos (`0x00`).**
  - O IV subsequente é atualizado in-place pelo modo CBC do OpenSSL (`FUN_10003b30` / `AES_cbc_encrypt`), encadeando os blocos finais de cada pacote enviado/recebido.
- **Ordem de Aplicação:** O trailer e o padding são calculados e anexados **ANTES** da cifragem. O receptor executa AES-CBC decrypt **ANTES** de verificar e remover o trailer.

### 3.3 Teste Independente Executado
Foi executado um teste de regressão em Python utilizando a biblioteca `cryptography` e vetores de dados artificiais cobrindo todas as classes de equivalência de tamanho:
- Payloads testados: 4, 5, 7, 8, 15, 16, 23, 24 e 100 bytes.
- Todos os testes resultaram em sucesso total: 100% de integridade verificada, remoção correta de padding e recomposição idêntica dos dados originais.

---

## 4. Validação da Comunicação P2P e NAT Traversal

### 4.1 Evidência Irrefutável de Comunicação Direta Peer-to-Peer
- **Endpoints Identificados:**
  - Cliente Local: `192.168.122.77`
  - Peer Remoto: `179.34.172.136:62565` (IP público residencial - Vivo Brasil).
- **Evidências no PCAP `radmin_vm2.pcap`:**
  1. **Sessão P2P Ativa:** Entre os pacotes #65 e #599, os dois nós mantêm conexão TCP estabelecida transmitindo quadros regulares de keepalive/dados (`00 00 00 10 ...`, 16 bytes de payload cifrado) em intervalos de aproximadamente 10 segundos.
  2. **Fechamento Limpo:** Nos pacotes #600 e #607, a sessão é encerrada bilateralmente com flags `FIN-ACK` (`0x11`).
  3. **Reconexão via TCP Simultaneous-Open:**
     - Pacote #696 (`t=1793481039.325`): Local envia SYN seq=3817256890 para `179.34.172.136:62565` a partir da porta `49527`.
     - Pacote #703 (`t=1793481039.342`): Peer remoto envia SYN seq=2399116486 para `192.168.122.77:49527`.
     - Pacote #704 (`t=1793481039.342`): Local responde com SYN-ACK (`flags 0x12`).
     - Pacote #714 (`t=1793481039.388`): Peer remoto responde com ACK (`flags 0x10`).
     - **Conclusão:** O handshake TCP de 4 vias por abertura simultânea foi concluído com sucesso e a conexão P2P direta foi reestabelecida.

### 4.2 Papel da Porta 17351 (`TcpRelay`)
- **Auditoria Crítica:** A porta 17351 **não é um canal de controle puro**, mas sim o serviço formal **`TcpRelay`**.
- **Evidência no Binário (`RvControlSvc.exe`):**
  - Em `0x0043fb60`, existe a função de conversão do enum de canal:
    ```
    Tipo 0 -> "TCP"
    Tipo 1 -> "UDP"
    Tipo 2 -> "TcpRelay" (string em 0x0051df00)
    ```
  - Em `0x0043fb81`, a string de formatação registra no log: `'%ls' via %hs/%hs` (ex: `'NodeName' via TcpRelay/outgoing`).
- **Comportamento na Rede:** Cada conexão para `45.162.230.182:17351` negocia uma sessão RSA independente e, a partir de então, transporta os mesmos pacotes cifrados e framed que seriam enviados diretamente entre peers.

### 4.3 Demonstração da Correlação do Teredo com os Peers do Radmin
A auditoria comprovou estaticamente e em rede que o tráfego Teredo é diretamente associado ao Radmin VPN:
1. **Evidência em Binário:** Em `RvROLClient.dll`, foi localizada a classe C++ RTTI:
   `RolClient::teredo::CTeredoThread` (strings em `0x10103608` e `0x10103620`).
2. **Decodificação RFC 4380 dos Pacotes no PCAP:**
   Os pacotes IPv6 encapsulados em UDP 54778 foram decodificados matematicamente:
   - `2001:0:14c9:cd04:2c09:2a05:44c4:38d8`:
     - Servidor: `20.201.205.4` (Microsoft Teredo Relay)
     - **IP Público do Cliente:** `187.59.199.39` (IP externo da máquina local `192.168.122.77`)
     - Porta Mapeada: `54778`
   - `2001:0:14c9:cd04:28ed:3718:4cdd:5377`:
     - **IP Público do Peer:** `179.34.172.136` (o exato nó remoto com o qual o Radmin estabeleceu TCP direto!).
     - Porta Mapeada: `51431`
   - `2001:0:14c9:cd04:4d7:1ce6:4e8f:b01d`:
     - **IP Público do Peer:** `177.112.79.226` (o segundo nó remoto para o qual o cliente disparou o SYN do pacote #784).
3. **Payloads Internos:** Os pacotes encapsulados transportam bolhas de travessia NAT (NextHeader 59) e pacotes TCP SYN direcionados às portas de serviço do nó remoto.

---

## 5. Validação do Driver TAP (`NetMP60_1_1_64.sys`)

### 5.1 Transporte de Quadros Ethernet
- **Status:** **CONFIRMADO.**
- O driver `NetMP60_1_1_64.sys` registra-se como miniport NDIS 6.0 virtual com mídia Ethernet (`NdisMedium802_3`).
- As rotinas `FUN_00476b60` (`ReadFile`) e `FUN_00476c10` (`WriteFile`) em `RvControlSvc.exe` transferem buffers que contêm o cabeçalho Ethernet completo de 14 bytes (`DMAC + SMAC + EtherType`) seguido do payload IP.

### 5.2 Sincronização Assíncrona
- Em `FUN_0047d5c0` (leitura) e `FUN_0047d8a0` (escrita), as operações são disparadas com estruturas `OVERLAPPED` (`this + 0x5c` e `this + 0x7c`).
- O serviço trata explicitamente o retorno `GetLastError() == 0x3e5` (`ERROR_IO_PENDING`), marcando as flags de pendência em `this + 0x78` e `this + 0x98`.
- A sincronização e o desbloqueio ocorrem via `GetOverlappedResult` (`0x5171c0`) associado a loops com `CancelIoEx` (`0x5171bc`) para cancelamento gracioso.

### 5.3 Correção Crítica: Descoberta de IOCTLs de Configuração
O relatório preliminar afirmava erroneamente que nenhum IOCTL era utilizado. A auditoria localizou **5 chamadas a `DeviceIoControl` (`0x517170`)** direcionadas ao handle do driver em `RvControlSvc.exe`:
- **`0x228014` (em `0x4b011d`):** Envia buffer de 6 bytes. Trata-se da configuração do **endereço MAC** da interface virtual (`NetVRadminMacAddress`).
- **`0x224018` (em `0x4b0034`):** Consulta status e atributos da interface.
- **`0x224020` (em `0x4aff84`):** Leitura de estatísticas de transmissão.
- **`0x22801c` (em `0x4b009e`):** Configuração de parâmetros de rede / estado de link (Up/Down).
- **`0x22c004` (em `0x4b0179`):** Handshake de registro e sincronização do serviço com o miniport.

### 5.4 Equivalência no Linux
A equivalência com `IFF_TAP | IFF_NO_PI` é **plenamente funcional e suficiente**, com o seguinte mapeamento de arquitetura:
1. **I/O de Pacotes:** `ReadFile` e `WriteFile` assíncronos no Windows mapeiam diretamente para `read()` e `write()` (ou I/O assíncrono com `tokio::io::AsyncReadExt` / `AsyncWriteExt`) no descritor de arquivo `/dev/net/tun`.
2. **Substituição dos IOCTLs:**
   - IOCTL `0x228014` (MAC) -> `SIOCSIFHWADDR` (ou Netlink via `rtnetlink`).
   - IOCTL `0x22801c` (Link Up) -> `SIOCSIFFLAGS` com `IFF_UP | IFF_RUNNING`.
   - Configuração de MTU -> `SIOCSIFMTU`.

---

## 6. Quadro Comparativo: Conclusões Auditadas

| Item Analisado | Conclusão Anterior | Veredito da Auditoria | Justificativa Técnica |
| :--- | :--- | :--- | :--- |
| **Referência do Pkt #686** | "Pacote #686 no `radmin_vm.pcap`" | **CORRIGIDA** | O pacote #686 no `radmin_vm.pcap` é TLS/Akamai. O pacote com registros TLV é o **#686 no `radmin_vm2.pcap`** (e #5486 no `radmin_vm.pcap`). |
| **Estrutura TLV Big-Endian** | `[Len:4][Tag:4][Val:N]` | **CONFIRMADA** | Verificada matematicamente nos pacotes e confirmada no catálogo de 744 campos em `FUN_00498fe0`. |
| **Campos 0x1df, 0x32b, 0x1ca** | Handshake / RSA key | **CONFIRMADA** | Localizados nos pontos de registro de schema `0x49fccd`, `0x49fd18` e `0x49f46d`. |
| **Cifra Simétrica** | AES-256-CBC | **CONFIRMADA** | Confirmada em `FUN_10062fb0`, `FUN_10062e00` e wrappers OpenSSL. |
| **IV Inicial** | Não detalhado | **CONFIRMADA / EXPANDIDA** | O IV inicial é de **16 bytes zerados (`0x00`)**, conforme demonstrado em `0x10062c16`. |
| **Posição do Trailer** | Não especificada | **CONFIRMADA / ESPECIFICADA** | O trailer é adicionado **antes** da cifragem e validado **após** a decifragem. |
| **IOCTLs do Driver** | "Nenhum IOCTL necessário" | **REJEITADA / CORRIGIDA** | Existem 5 IOCTLs no Windows (`0x228014`, etc.) para MAC e status; no Linux, mapeiam para Netlink / `ioctl` de socket padrão. |
| **Porta 17351** | Relay genérico | **CONFIRMADA / ESPECIFICADA** | Enum oficial `TcpRelay` (`0x51df00`), precedido por handshake RSA formal. |
| **Teredo como Transporte** | Hipótese baseada em portas | **CONFIRMADA COM PROVAS** | Descoberta da classe `RolClient::teredo::CTeredoThread` e decodificação dos endereços RFC 4380 mapeando para os mesmos IPs dos peers. |
| **Comunicação P2P Direta** | Suposição de P2P | **CONFIRMADA COM PROVAS** | Pacotes #65..#599 e handshake simultaneous-open nos pacotes #696/#703/#704 comprovam tráfego peer direto real. |

---

## 7. Questões Pendentes para Futuras Capturas

1. **Comutação Dinâmica para UDP Puro entre Peers:**
   - Embora o enum `UDP` exista (`0x51defc`) e os testes STUN sejam feitos em UDP, os PCAPs disponíveis documentam a transferência contínua de dados P2P em TCP direto e em túneis Teredo/Relay. Uma captura contendo transferência intensiva de arquivos em redes sem bloqueio de UDP é recomendada para auditar se há um protocolo UDP customizado ou se UDP é restrito a STUN/Teredo.
2. **Algoritmo de Compressão:**
   - O export `ROLClient_SetCompression` está presente em `RvROLClient.dll`, mas todas as sessões capturadas operaram com compressão desativada. O algoritmo exato (provavelmente zlib ou lzo) aguarda captura com tráfego comprimido.

