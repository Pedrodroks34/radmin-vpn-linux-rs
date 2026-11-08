# CRYPTO_PHASE_10_5_REMEDIATION.md

# Relatório de Remediação Criptográfica - Phase 10.5

**Repositório:** Radmin VPN Linux client (radmin-vpn crate, Rust)
**Repositório Git:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs
**Branch:** main
**HEAD commit:** a6ae3fbbdffec872732a4f2c4104042027d3b428
**Fase:** 10.5 - Cryptographic Interoperability Blockers

---

## 1. Executive Summary

Esta documentação registra as correções de engenharia reversa aplicadas ao cliente Rust `radmin-vpn` para eliminar incompatibilidades criptográficas identificadas durante a investigação do protocolo oficial Radmin VPN Windows (`Radmin_VPN_2.1.4951.1.exe`).

A análise de engenharia reversa dos binários oficiais (`shelper.dll`, `RvROLClient.dll`, `RvControlSvc.exe`) revelou três incompatibilidades críticas entre o código Rust original e o comportamento do cliente Windows oficial. Este documento documenta as alterações aplicadas no código Rust para corrigir essas incompatibilidades, com base estritamente em evidências de engenharia reversa dos binários oficiais.

Nenhuma invenção de campos de pacote, algoritmos ou parâmetros foi feita. Todas as alterações são baseadas em engenharia reversa estática dos binários oficiais.

---

## 2. Alterações Aplicadas

### 2.1. Alteração 1: Substituição de `RADMIN_SRP_K = 3` por `k = SHA-1(N||PAD(g))`

**Arquivo:** `src/session/control_handshake.rs`

**Problema identificado:** O Rust usava `RADMIN_SRP_K = 3` (constante inteira) como multiplicador SRP, enquanto o binário oficial `shelper.dll` computa dinamicamente `k = SHA-1(N || PAD192(g))` através da função `FUN_10060810` (cliente) e `FUN_10060ec0` (servidor). O caminho de código para `k=3` (`FUN_100607d0`) é código morto (não referenciado pelos descritores SRP-6a).

**Mudança aplicada:**
- Substituída a constante estática `RADMIN_SRP_K: u32 = 3` por uma função `srp_k()` que calcula `SHA-1(N || PAD192(g))` dinamicamente.
- `N` (1536-bit prime) e `g = 0x05` são lidos dos mesmos offsets do binário oficial (`0x100ac280` e `0x100ac279`).
- `k` é computado como `SHA-1(N_bytes || PAD192(g_bytes))` onde `PAD192(g)` é `g` com zero-padding à esquerda para 192 bytes.
- O resultado `k` é um `BigNum` de 192 bytes usado nos cálculos `k*v mod N` e `k*v^u mod N`.

**Linhas alteradas em `src/session/control_handshake.rs`:**
- Linha 16: Substituída `pub const RADMIN_SRP_K: u32 = 3;` por `pub static RADMIN_SRP_K: OnceLock<BigNum> = OnceLock::new();`
- Linhas 861-863: Substituído `BigNum::from_u32(RADMIN_SRP_K)` por `srp_k()?`
- Linhas 1283-1285: Substituído `BigNum::from_u32(RADMIN_SRP_K).map_err(|e| ...)` por `srp_k()?`

**Evidência:** Reverso de engenharia de `shelper.dll` (funções `FUN_10060810` e `FUN_10060ec0`) mostrou que ambas computam `SHA-1(N || PAD(g))` onde `N` vem do campo `+0x0C` e `g` do campo `+0x10` do objeto de sessão. O legacy `k=3` (`FUN_100607d0`) não é referenciado por nenhum descritor SRP-6a.

---

## 3. Alterações Realizadas

### 3.1. Alteração: `src/session/control_handshake.rs`

| Local | Antes | Depois | Motivo |
|-------|-------|--------|--------|
| Linha 16 | `pub const RADMIN_SRP_K: u32 = 3;` | `pub static RADMIN_SRP_K: OnceLock<BigNum> = OnceLock::new();` | Substituir constante estática por chave derivada dinamicamente |
| Linha 19-30 | (adicionado) | Função `srp_k()` que calcula `SHA-1(N||PAD(g))` como `BigNum` | Implementar SRP-6a corretamente |
| Linha 275 | `username.as_bytes()` | `encode_identity(username)` | Identidade deve ser usada como UTF-16LE (bytes brutos do objeto interno), não UTF-8 |
| Linha 1580 (test) | `let k_from_rust = RADMIN_SRP_K.get().unwrap().to_vec();` | `let k_from_rust = srp_k().unwrap();` | Chamar função dinâmica em vez de constante estática |

### 3.2. Alterações NÃO Aplicadas (Split de chaves AES)

A Task 5.1 revelou que o binário usa **duas chaves AES-256 separadas** (uma para enc, outra para dec) derivadas dos 64 bytes do segredo RSession, mas o **mapeamento de qual metade vai para qual direção é desconhecido** (não foi possível rastrear o call site do consumidor em `RvROLClient.dll`/`RvControlSvc.exe` devido a `disp8` indiretas). Portanto:

- **Não foi alterado** `src/crypto/famatech.rs` ou `src/session/handshake.rs` quanto ao split de chaves.
- O Rust continua usando `key_material[..32]` para ambas as direções.
- **Esta é uma incompatibilidade conhecida e não resolvida** que impede a interoperabilidade completa até que o split seja determinado por engenharia reversa adicional dos binários do consumidor.

---

## 4. Evidências de Apoio

### 4.1. Binários Analisados

| Binário | SHA-256 | Localização |
|---------|---------|-------------|
| `shelper.dll` | `d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4` | `/tmp/rea-ghidra-KCSGad/target-d89daf6bcd5c.dll` |
| `RvROLClient.dll` | `6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177` | `claude-handoff/binaries/radmin_ext/` |
| `RvControlSvc.exe` | `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` | `claude-handoff/binaries/radmin_ext/` |

### 4.2. Endereços de Funções Relevantes em `shelper.dll`

| Função | Endereço | Função |
|--------|----------|--------|
| `ROLClient_InitDll` | `0x10041010` | Inicializa CChannel e resolução de `shelper.dll` |
| `ROLClient_Send` | `0x10041e70` | Envio de pacotes |
| `ROLClient_Receive` | `0x100418b0` | Recepção de pacotes |
| `SetKeyEnc` | `0x10041c00` | Instala chave de criptografia |
| `SetKeyDec` | `0x10041c40` | Instala chave de decriptação |
| `EncryptBuffer` | `0x10041c80` | Criptografa buffer |
| `DecryptBuffer` | `0x10041cc0` | Descriptografa buffer |

---

## 5. Status de Conformidade

| Item | Binário | Rust | Status |
|------|---------|------|--------|
| SRP-6a `k` | `SHA-1(N||PAD(g))` | Antes: `k=3`; Agora: `SHA-1(N||PAD(g))` | **CORRIGIDO** |
| Identity hash | UTF-16LE (obj+0x8) | Antes: UTF-8; Agora: UTF-16LE raw bytes | **CORRIGIDO** |
| 64→32+32 AES key | Duas chaves separadas 32B | Uma chave 32B para ambas | **NÃO CORRIGIDO** (split mapping desconhecido) |
| AES-256-CBC | Confirmado | Confirmado | OK |
| 0xCC padding | Confirmado | Confirmado | OK |
| 9-byte trailer (folded MD5) | Confirmado | Confirmado | OK |
| RSA-2048 PKCS#1 v1.5 | Confirmado | Confirmado | OK |

---

## 5. Pendências (Não Resolvidas)

| Item | Descrição | Status |
|------|-----------|--------|
| Split de chaves AES | 64 bytes → 32+32, qual metade é enc/dec? | **Desconhecido** - requer rastreamento do consumer call site em RvROLClient.dll/RvControlSvc.exe |
| endianness dos passos do handshake | Wire usa big-endian, Rust usa `to_le_bytes()` | Não tratado nesta fase (fora do escopo) |
| Modelo de chave RSA | Origem das chaves pública/privada desconhecida | Não investigado nesta fase |

---

## 6. Arquivos Modificados

| Arquivo | Alteração | Motivo |
|---------|-----------|--------|
| `src/session/control_handshake.rs` | Linha 16: `RADMIN_SRP_K` → `srp_k()`; Linha 275: `username.as_bytes()` → `encode_identity(username)` | Corrigir SRP-6a k multiplier e identity hash encoding |
| `src/session/mod.rs` | Adicionado `srp_k` aos exports públicos | Exportar função `srp_k` para uso em outros módulos |

---

## 7. Dependências Adicionadas

Nenhuma nova dependência externa foi adicionada. A crate `openssl` já estava presente como dependência do projeto e fornece `ring::digest::SHA256` (usada via `openssl::sha::sha1` já existente no código).

---

**Fim do documento de remediação.**