# Questões Pendentes e Limitações Conhecidas — Pós-Fase 1 (`PHASE_1_UNRESOLVED.md`)

> **Nota sobre item resolvido nesta Fase 1:**  
> A questão levantada na auditoria anterior sobre como os **64 bytes (`0x40`)** retornados por `SHelper_RSession_GetKey` (`shelper.dll!0x1006ba80` -> `0x1006a270`) são convertidos na chave AES-256 de **32 bytes (`0x20`)** do `SHelper_CChannel` foi **100% resolvida** por desmontagem de `RvROLClient.dll!0x100df250` (`CChannelWrapper::Create`), `0x100df470` (`CChannelWrapper::SetKey`), `0x10096f0d..0x10096f21` e `0x100969de..0x10096a16`: o cliente oficial valida `key_len >= 0x20` e passa `&key_buf[0..32]` tanto para `SHelper_CChannel_SetKeyEnc` (`0x10062e00`) quanto para `SHelper_CChannel_SetKeyDec` (`0x10062d60`).

---

## 1. Máquina de Estados `SHelper_*` da Conexão Central na Porta `17301` (`radmin_17301.pcap` #32..#50)

- **O que está indefinido**:
  - O formato interno exato e as operações criptográficas de cada um dos pacotes intermediários (`192B`, `32B`, `256B`, `224B`, `224B`, `48B`, `48B`) trocados após o frame de versão `[03 00 00 00]` na porta TCP `17301`.
- **O que já foi investigado**:
  - Identificamos em `RvROLClient.dll!0x100dc6e0` e `0x1003dd40..0x1003f530` que `shelper.dll` exporta duas famílias distintas:
    1. `SHelper_RSession_*` (`0x1006b860` / `0x1006a2b0`: `256B` `C->S` RSA PKCS#1 v1.5 com `76B` plaintext -> `4B` `S->C` token), usada por `RvROLClient.dll!0x10096660..0x10096ff2` e implementada integralmente nesta Fase 1.
    2. `SHelper_*` (`0x1006ab90` `SHelper_CreateClient`, `0x1006ad20` `SHelper_CreateServer`, `0x1006b1e0` `SHelper_GetNextBuffer`, `0x1006b010` `SHelper_GetKey`, `0x1006b1d0` `SHelper_GetNetworkProtocolVersion = 3`), usada por `RvROLClient.dll!0x1003eb30` na porta `17301`.
  - Correlacionamos os pacotes de `radmin_17301.pcap` separando os dois fluxos TCP concorrentes (`49494` e `49493`), demonstrando que o pacote #44 (`S->C`, `4B` `03000000` em `49493`), #35/#46 (`S->C`, `192B`) e #39/#48 (`S->C`, `256B`) pertencem à máquina `SHelper_*` (`0x1006b1e0`) e não à máquina `SHelper_RSession_*` (`0x1006a2b0`).
- **Qual evidência está faltando**:
  - A desmontagem completa das sub-rotinas internas chamadas por `shelper.dll!0x1006b1e0` (no intervalo `0x10066800..0x10069b00`) e a extração dos parâmetros de chave pública do servidor central passados a `SHelper_CreateClient` (`0x1006ab90`).
- **Qual análise adicional resolveria a dúvida**:
  - Desmontar estaticamente `shelper.dll!0x10066800..0x10069b00` e `RvROLClient.dll!0x1003eb30..0x1003f530` para documentar cada estado de `SHelper_GetNextBuffer` (`0x1006b1e0`) e extrair do segmento `.rdata` de `RvROLClient.dll` / `RvControlSvc.exe` o módulo RSA do servidor central.

---

## 2. Semântica dos 3 DWORDs de Cabeçalho (`client_params: [u32; 3]`) e do `server_token` (`u32`) em `SHelper_RSession`

- **O que está indefinido**:
  - O significado semântico de camada superior dos 3 DWORDs (`[esi+0x04..+0x0c]`, bytes `0..12` do plaintext RSA de 76 bytes) passados a `SHelper_RSession_CreateClient` e do `server_token` de 4 bytes passado a `SHelper_RSession_CreateServer`.
- **O que já foi investigado**:
  - Em `shelper.dll!0x1006b860` (`0x1006a690`), `0x1006a512`, `0x1006a30c`, `0x1006a4cc`, `0x1006bbb0` e `0x1006bc30`, confirmamos que `shelper.dll` trata esses valores como inteiros opacos de 32 bits transportados dentro do handshake e disponibilizados ao par remoto após `is_established == 1`.
  - Em `RvROLClient.dll!0x10096bf0..0x10097060`, verificamos que após `RSession::GetNextBuffer` concluir, o servidor chama `0x100dd090` (`GetClientDataOnServer`) e valida o valor em `0x100dc890`.
- **Qual evidência está faltando**:
  - Identificar os valores exatos passados pelos chamadores de `RvROLClient.dll!0x10096660` e validados em `0x100dc890`.
- **Qual análise adicional resolveria a dúvida**:
  - Desmontar `RvROLClient.dll!0x10096660..0x10096800` e `0x100dc890` para mapear os campos do objeto chamador que alimentam `d0, d1, d2` e `server_token`.

---

## 3. Conteúdo Decifrado dos Pacotes de Controle Pós-Handshake (Fases 2 e 3)

- **O que está indefinido**:
  - Os payloads em texto claro dos pacotes cifrados trocados após a ativação do `SHelper_CChannel` nas capturas `radmin_17301.pcap`, `radmin_vm.pcap` e `radmin_vm2.pcap`.
- **O que já foi investigado**:
  - Comprovamos que a chave AES-256 de cada sessão é gerada dinamicamente via `RAND_bytes` (`0x10063530`) no momento do handshake e cifrada com RSA-2048 PKCS#1 v1.5.
- **Qual evidência está faltando**:
  - Como os PCAPs históricos não vieram acompanhados de dump de memória das chaves efêmeras daquelas sessões, os pacotes pós-handshake dos PCAPs não podem ser decifrados offline sem a chave privada do servidor ou o buffer de `SHelper_GetKey` / `SHelper_RSession_GetKey`.
- **Qual análise adicional resolveria a dúvida**:
  - Para a Fase 2 e Fase 3, combinar a análise estática dos serializadores/parsers TLV em `RvROLClient.dll` (`0x10029aa0`, `0x1002b2c0`) com instrumentação dinâmica (Frida/x64dbg em `shelper.dll!0x10063000` `CChannel_Encrypt` e `0x100630f0` `CChannel_Decrypt`) caso uma VM Windows com o cliente oficial esteja disponível.
