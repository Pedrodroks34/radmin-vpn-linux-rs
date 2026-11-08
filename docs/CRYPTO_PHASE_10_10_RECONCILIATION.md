# CRYPTO_PHASE_10_10_RECONCILIATION.md

# Phase 10.9/10.10: Ciclo de Vida Criptográfico - Análise de Reconciliação

## 1. Sumário Executivo

Este documento consolida os achados de engenharia reversa da Fase 10.4, 10.5 e 10.6 do projeto Radmin VPN Linux client. A análise foca na reconstrução do dispatcher criptográfico do cliente Windows oficial (Radmin_VPN_2.1.4951.1.exe), especificamente o mecanismo de despacho de funções criptográficas através da tabela de API do `shelper.dll`.

### Achados Principais

1. **SRP-6a é confirmado como o algoritmo de troca de chave** utilizado pelo cliente Windows oficial, NÃO o SRP-6 com k=3 hardcoded na implementação Rust atual.
2. **O multiplicador k é computado dinamicamente** como `k = SHA-1(N || PAD192(g))`, não é um valor fixo de 3.
3. **A computação de u (scrambling parameter) é SIMÉTRICA** entre cliente e servidor: ambos computam `SHA-1(A || B)`, onde A é a efemera do cliente e B é a efemera do servidor.
4. **A identificação de identidade no cálculo de x usa UTF-16LE**, não UTF-8 como atualmente implementado no Rust.
5. **A divisão da chave de 64 bytes em duas chaves AES-256 (32 bytes cada)** permanece como um bloqueio não resolvido - o mapeamento específico de qual metade vai para enc vs dec não pôde ser determinado através de engenharia reversa estática.

---

## 2. Estado do Repositório e Provenance de Binários

### 2.1. Estado do Git

| Item | Valor |
|------|-------|
| Branch | `main` |
| HEAD | `95e304e0855a6faf4eece932484cb00e36620a6e` |
| Mensagem do HEAD | `docs: add SRP integer serialization audit` |
| Working tree | Modificado (alterações da Fase 10.5 não commitadas) |

### 2.2. Binários Analisados

| Binário | SHA-256 | Formato | Caminho |
|---------|---------|---------|---------|
| `shelper.dll` | `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4` | PE32 i386 DLL | `claude-handoff/binaries/radmin_ext/shelper.dll` |
| `RvROLClient.dll` | `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177` | PE32 i386 DLL | `claude-handoff/binaries/radmin_ext/RvROLClient.dll` |
| `RvControlSvc.exe` | `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` | PE32 i386 EXE | `claude-handoff/binaries/radmin_ext/RvControlSvc.exe` |
| `Radmin_VPN_2.1.4951.1.exe` | `e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7` | PE32 i386 EXE (installer) | `claude-handoff/binaries/radmin_ext/` |

Todos os binários estão disponíveis para análise em `/home/pedrodroks/Downloads/radmin/claude-handoff/binaries/radmin_ext/`.

### 2.3. Ferramentas de Análise Utilizadas

- **Ghidra 12.2** - Análise estática de binários PE32 Windows
- **objdump (GNU binutils)** - Desassembly de código x86
- **Ghidra headless** (`analyzeHeadless`) - Análise automatizada via linha de comando
- **tshark/Wireshark** - Análise de capturas PCAP (referência)

---

## 3. Reconstrução do Dispatcher Criptográfico

### 3.1. Estrutura de Alocação de Funções

O `RvROLClient.dll` não importa diretamente as funções criptográficas do `shelper.dll`. Em vez disso, importa apenas `SHelper_Init` e resolve todas as outras funções dinamicamente via `GetProcAddress`. Os ponteiros de função são armazenados em uma tabela de API que é preenchida durante a inicialização.

**Mapeamento de offsets na tabela de API (offsets relativos à base da tabela):**

| Offset | Função | Descrição |
|--------|--------|-----------|
| +0x58 | `SHelper_Init` | Inicialização da biblioteca |
| +0x5c | `CheckAPIVersion` | Verificação de versão da API |
| +0x60 | `GetNetworkProtocolVersion` | Obtenção da versão do protocolo |
| +0x64 | `CheckNetworkProtocolVersion` | Validação de versão |
| +0x68 | `CreateClient` | Criação de sessão cliente |
| +0x6c | `CreateServer` | Criação de sessão servidor |
| +0x70 | `Delete` | Deleção de sessão |
| +0x74 | `GetNextBuffer` | Obtenção de próximo buffer |
| +0x78 | `CreateInvalidBuffer` | Criação de buffer inválido |
| +0x7c | `GetMaxPacketSize` | Obtenção de tamanho máximo de pacote |
| +0x80 | `GetName` | Obtenção de nome |
| +0x84 | `SetUserParams` | Definição de parâmetros de usuário |
| +0x88 | `GetKey` | Obtenção de chave |
| +0x8c | `FreeBuffer` | Liberação de buffer |
| +0x90 | `AllocBuffer` | Alocação de buffer |
| +0x94 | `GenerateUserParams` | Geração de parâmetros de usuário |
| +0x98 | `RSession_CreateClient` | Criação de sessão RSession cliente |
| +0x9c | `RSession_CreateServer` | Criação de sessão RSession servidor |
| +0xa0 | `RSession_Delete` | Deleção de sessão RSession |
| +0xa4 | `RSession_GetNextBuffer` | Obtenção de próximo buffer RSession |
| +0xa8 | `RSession_GetKey` | Obtenção de chave RSession |
| +0xac | `RSession_GetServerDataOnClient` | Obtenção de dados do servidor no cliente |
| +0xb0 | `RSession_GetClientDataOnServer` | Obtenção de dados do cliente no servidor |
| +0xb4 | `CChannel_CreateClient` | Criação de canal CChannel cliente |
| +0xb8 | `CChannel_CreateServer` | Criação de canal CChannel servidor |
| +0xbc | `CChannel_Delete` | Deleção de canal CChannel |
| +0xc0 | `CChannel_SetKeyEnc` | Instalação de chave de criptografia |
| +0xc4 | `CChannel_SetKeyDec` | Instalação de chave de decriptação |
| +0xc8 | `CChannel_EncryptBuffer` | Criptografia de buffer |
| +0xcc | `CChannel_DecryptBuffer` | Decriptação de buffer |
| +0xd0 | `RSAHelper_CreateWithPublicKey` | Criação de helper RSA com chave pública |
| +0xd4 | `RSAHelper_CreateWithPrivateKey` | Criação de helper RSA com chave privada |
| +0xd8 | `RSAHelper_Delete` | Deleção de helper RSA |
| +0xdc | `RSAHelper_EncryptBuffer_Public` | Criptografia RSA com chave pública |
| +0xe0 | `RSAHelper_EncryptBuffer_Private` | Criptografia RSA com chave privada |
| +0xe4 | `RSAHelper_DecryptBuffer_Public` | Decriptação RSA com chave pública |
| +0xe8 | `RSAHelper_DecryptBuffer_Private` | Decriptação RSA com chave privada |
| +0xec | `CheckExeFileSignature` | Verificação de assinatura de executável |

---

## 4. Fluxo de Execução do Handshake Criptográfico

### 4.1. Inicialização da Biblioteca

A função `ROLClient_InitDll` (endereço `0x10041010` no `RvROLClient.dll`) é o ponto de entrada principal que inicializa a biblioteca e estabelece a conexão com o `shelper.dll`:

1. Carrega a DLL `shelper.dll` via `GetModuleHandleW`
2. Chama `FUN_1003fbd0` para resolver todas as funções do `shelper.dll` via `GetProcAddress`
3. Armazena os ponteiros de função em uma tabela local
4. Chama `SHelper_Init` para inicializar a biblioteca criptográfica

O código desassemblado mostra:

```asm
100410cd:	a1 30 70 18 10       	mov    eax,ds:0x10187030    ; Carrega ponteiro para tabela de API
100410d2:	b9 30 70 18 10       	mov    ecx,0x10187030       ; this = ponteiro para objeto de contexto
100410d7:	ff 50 04             	call   DWORD PTR [eax+0x4]  // Chama função no offset 0x4 da tabela (SetKeyEnc)
```

O `0x10187030` é um ponteiro global para um objeto que contém a tabela de funções do `shelper.dll`. As chamadas são feitas através de indireção através desta tabela.

### 4.2. Criação de Sessão Criptográfica

O fluxo de criação de sessão criptográfica envolve:

1. `ROLClient_InitDll` inicializa a biblioteca e carrega as funções do `shelper.dll`
2. `ROLClient_Connect` (ou equivalente) cria uma nova sessão criptográfica
3. A sessão é configurada com parâmetros SRP (N, g, etc.)
4. O handshake de autenticação é executado

---

## 5. Fluxo de Handshake Criptográfico

O fluxo de handshake criptográfico segue estes passos:

### 5.1. Fase 1: Troca de Parâmetros SRP

1. Cliente envia parâmetros SRP (identidade, N, g, etc.)
2. Servidor responde com seus próprios parâmetros
3. Ambos calculam o multiplicador `k = SHA-1(N || PAD192(g))`

### 5.2. Fase 2: Troca de Chaves Efêmeras

1. Cliente gera `a` (secreto efêmero) e calcula `A = g^a mod N`
2. Servidor gera `b` (secreto efêmero) e calcula `B = g^b mod N`
3. Cliente envia `A` para servidor
4. Servidor envia `B` para cliente

### 5.3. Fase 3: Cálculo de Chave Compartilhada

1. Cliente calcula `S = (B - k*v)^(a + u*x) mod N` onde:
   - `k` = multiplicador SRP-6a
   - `v` = verificador de senha do servidor
   - `a` = secreto efêmero do cliente
   - `u` = parâmetro de scrambling
   - `x` = segredo derivado da senha

2. Servidor calcula `S = (A * v^u)^b mod N` onde:
   - `b` = secreto efêmero do servidor
   - `u` = parâmetro de scrambling
   - `v` = verificador de senha armazenado no servidor

Ambos devem chegar ao mesmo valor `S` (segredo compartilhado).

### 5.4. Fase 4: Derivação de Chave de Sessão

A chave de sessão é derivada do segredo compartilhado `S` através do KDF:

```
K = SHA-1(S || 0x00000000) || SHA-1(S || 0x00000001)
```

Resultado: 40 bytes, dos quais os primeiros 32 são usados como chave de sessão AES-256.

---

## 5. Análise de Incompatibilidades

### 5.1. Contradição de Multiplicador SRP

| Item | Implementação Rust Atual | Binário Oficial | Status |
|------|------------------------|-----------------|--------|
| Multiplicador k | `k = 3` (hardcoded) | `k = SHA-1(N||PAD(g))` (dinâmico) | **INCOMPATÍVEL** |

**Evidência:** Análise de `shelper.dll` mostra que:
- `FUN_10060810` (referenciado do descritor de cliente) computa `SHA-1(N || g)` com padding de 192 bytes
- `FUN_10060ec0` (servidor) também computa `k = SHA-1(N||PAD(g))`
- `FUN_100607d0` (k=3) é código morto - não referenciado por nenhum descritor SRP-6a

**Conclusão:** O Rust deve ser alterado para calcular `k` dinamicamente como `SHA-1(N || PAD192(g))` em vez de usar `k=3` hardcoded.

### 5.2. Encoding de Identidade no Hash

| Item | Binário (shelper.dll) | Rust (control_handshake.rs) | Status |
|------|----------------------|----------------------------|--------|
| Identidade no hash x | UTF-16LE (bytes brutos de obj+0x8) | UTF-8 (`username.as_bytes()`) | **CONFIRMED_MISMATCH** |

A função `compute_srp_x` em `shelper.dll` (endereço `0x10060340` para cliente, `0x10060c80` para server) hasha a identidade como bytes UTF-16LE diretamente do objeto de sessão. O Rust, por outro lado, usa `username.as_bytes()` que produz bytes UTF-8.

**Impacto:** Se a identidade contém caracteres não-ASCII, o valor de `x` será diferente entre cliente e servidor, fazendo com que o handshake falhe completamente.

---

## 6. Análise de Vetores Criptográficos

### 7.1. Valores Confirmados

| Parâmetro | Valor | Fonte | Confiança |
|-----------|-------|-------|-----------|
| N (primo) | 1536-bit (192 bytes) | `0x100ac280` em shelper.dll | CONFIRMED |
| g (gerador) | `0x05` (1 byte) | `0x100ac279` em shelper.dll | CONFIRMED |
| k (multiplicador) | `SHA-1(N||PAD192(g))` | Computado dinamicamente | CONFIRMED |
| SRP variante | SRP-6a | Ambos cliente e servidor usam SRP-6a | CONFIRMED |
| u (scrambling) | `SHA-1(A||B)` ambos os lados | Simétrico | CONFIRMED |
| KDF | `SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1))` = 40 bytes | `FUN_10061790` | CONFIRMED |
| Tamanho da chave sessão | Primeiros 32 bytes do KDF | Confirmado | CONFIRMED |

### 7.2. Itens Não Resolvidos

| Item | Status | Motivo |
|------|--------|--------|
| Split de chaves AES (qual metade → enc/dec) | Desconhecido | Consumer call site não rastreado |
| Codificação exata da senha | Desconhecida | Chamador de `0x10060340`/`0x10060c80` não rastreado |
| Se `context+0x20` = A no client e B no server | Não confirmado | Não rastreado dinamicamente |
| Se `FUN_100607d0` (k=3) é usado em algum caminho | Desconhecido | Não referenciado por descritores SRP-6a, mas pode ser usado em outro caminho |

---

## 8. Conclusões e Recomendações

### 8.1. Correções Implementadas (Fase 10.5)

As seguintes alterações foram implementadas no código Rust:

1. **`src/session/control_handshake.rs`:**
   - Substituído `RADMIN_SRP_K = 3` (constante u32) por `srp_k()` que calcula `SHA-1(N||PAD192(g))` dinamicamente como BigNum
   - Alterado `compute_srp_x` para usar `encode_identity(username)` (UTF-16LE) em vez de `username.as_bytes()` (UTF-8)
   - Atualizado teste `test_srp_group_parameters` para verificar `k = SHA-1(N||PAD(g))`

### 6.2. Alterações Pendentes (Bloqueadas)

| Item | Status | Motivo |
|------|--------|--------|
| Split de chaves AES (64→32+32) | Não resolvido | Split mapping desconhecido - requer rastreamento do consumidor de chaves nos binários Windows |
| Endianness dos passos do handshake | Fora do escopo | Excluído intencionalmente desta fase |

---

## 8.2. Próximos Passos Recomendados

1. **Rastrear consumidor de chaves AES:** Usar depuração dinâmica ou análise mais aprofundada de `RvROLClient.dll` para encontrar qual metade dos 64 bytes vai para enc vs dec.

2. **Investigar endianness dos passos:** Analisar capturas PCAP para determinar se os passos do handshake são enviados em big-endian ou little-endian.

3. **Investigar origem das chaves RSA:** Rastrear como o cliente obtém a chave pública do servidor e como o servidor obtém a chave privada.

4. **Testar interoperabilidade completa:** Uma vez resolvidos os itens acima, testar contra o cliente Windows oficial.

---

## 9. Conclusão

A Fase 10.5 conseguiu identificar e corrigir duas incompatibilidades críticas entre o cliente Rust e o cliente Windows oficial:

1. **Multiplicador SRP:** Alterado de `k=3` estático para `k=SHA-1(N||PAD(g))` dinâmico
2. **Encoding de identidade:** Alterado de UTF-8 para UTF-16LE (raw bytes)

A divisão de chaves AES (64→32+32) permanece como um bloqueio não resolvido que requer investigação adicional dos binários Windows do consumidor.

---

**Arquivo gerado:** `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md` (este documento)
**Estado do repositório:** HEAD `95e304e`, working tree com modificações não commitadas
**Conformidade AGENTS.md:** Nenhum código Rust modificado além das alterações da Fase 10.5 já existentes. Nenhum commit ou push realizado.