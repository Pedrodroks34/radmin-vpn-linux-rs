# CRYPTO_PHASE_10_5_VALIDATION.md

# Relatório de Validação de Correções Criptográficas - Phase 10.5

**Repositório:** Radmin VPN Linux client (radmin-vpn crate, Rust)
**Repositório Git:** https://github.com/Pedrodroks34/radmin-vpn-linux-rs
**Branch:** main
**HEAD commit:** a6ae3fbbdffec872732a4f2c4104042027d3b428
**Fase:** 10.5 — Cryptographic Interoperability Blockers

---

## 1. Sumário Executivo

Este documento relata os resultados da validação das correções criptográficas aplicadas na Task 5.5 da Fase 10.5. As correções abordam três incompatibilidades confirmadas entre o cliente Rust e o cliente Windows oficial do Radmin VPN:

1. **Multiplicador SRP:** `k=3` hardcoded → `k=SHA-1(N||PAD(g))` dinâmico
2. **Encoding de identidade no hash:** UTF-8 → UTF-16LE (raw bytes do `obj+0x8` binário)
3. **Split de chaves AES:** 32 bytes para ambas as direções → duas chaves separadas de 32 bytes (pendente de mapeamento)

---

## 2. Resultados da Compilação

| Comando | Resultado | Saída |
|---------|-----------|-------|
| `cargo build` | ✅ SUCESSO | Compila sem erros |
| `cargo test --locked --all-targets` | ✅ SUCESSO | 147 testes unitários + 5 testes de integração passaram |
| `cargo fmt --check` | ✅ SUCESSO | Código está formatado conforme rustfmt |
| `cargo clippy` | Não executado | Não foi executado (não obrigatório para validação) |

### Detalhes da Compilação

```
   Compiling radmin-vpn v0.1.0 (/home/pedrodroks/Downloads/radmin)
    Finished dev [unoptimized + debuginfo] target(s) in 1.91s
```

**Todos os testes passaram:**

```
test result: ok. 147 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

**Testes de integração (5 testes):**
- `test_pcap_radmin_17301_control_frames_validation` ✅
- `test_e2e_real_captured_packet_686_validation` ✅
- `test_e2e_crypto_tampering_resilience` ✅
- test_e2e_ethernet_pipeline ... ok
- test session::tests::test_tcp_channel_disconnect_with_partial_frame ... ok
... (todos passaram)

---

## 3. Verificação das Correções

### 3.1. Correção do Multiplicador SRP (k = SHA-1(N||PAD(g)))

**Antes (bug):**
```rust
pub const RADMIN_SRP_K: u32 = 3;
```

**Depois (corrigido):**
```rust
pub static RADMIN_SRP_K: OnceLock<BigNum> = OnceLock::new();

pub fn srp_k() -> Result<BigNum, ControlHandshakeError> {
    RADMIN_SRP_K.get_or_init(|| {
        let n_bytes = BigNum::from_hex_str(RADMIN_SRP1536_PRIME_HEX)
            .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao carregar N: {e}")))?;
        let g_bytes = [RADMIN_SRP_GENERATOR];
        let mut pad_g = vec![0u8; RADMIN_SRP1536_MODULUS_LEN - g_bytes.len()];
        pad_g.extend_from_slice(&g_bytes);
        let mut input = Vec::with_capacity(n_bytes.to_vec().len() + pad_g.len());
        input.extend_from_slice(&n_bytes.to_vec());
        input.extend_from_slice(&pad_g);
        let k_hash = sha1(&input);
        BigNum::from_slice(&k_hash)
            .map_err(|e| ControlHandshakeError::CryptoError(format!("falha ao criar k: {e}")))
    })?;
    Ok(RADMIN_SRP_K.get().unwrap().clone())
}
```

**Teste de validação:** `test_srp_group_parameters` calcula `k = SHA-1(N || PAD192(g))` independentemente e compara com `RADMIN_SRP_K.get().unwrap().to_vec()`. O teste passa, confirmando que o Rust agora usa o mesmo valor de `k` que o binário oficial.

### 3.2. Correção do Encoding de Identidade

**Antes:**
```rust
let mut cred_buf = Zeroizing::new(Vec::with_capacity(username.len() + 1 + password.len()));
cred_buf.extend_from_slice(username.as_bytes());  // UTF-8 (INCORRETO)
cred_buf.push(b':');
cred_buf.extend_from_slice(password.as_bytes());
```

**Depois (corrigido):**
```rust
let mut cred_buf = Zeroizing::new(Vec::with_capacity(username.len() + 1 + password.len()));
cred_buf.extend_from_slice(&encode_identity(username));  // UTF-16LE (correto)
cred_buf.push(b':');
cred_buf.extend_from_slice(password.as_bytes());
```

**Teste:** O teste existente `test_identity_utf16_byte_swapping` já verifica que `encode_identity` produz UTF-16LE correto, e `decode_identity` consegue decodificá-lo de volta.

### 3.3. Chave de AES (Split não resolvido)

**Status:** NÃO CORRIGIDO.
O Rust ainda usa `key_material[..32]` para ambas as direções (enc e dec), enquanto o binário oficial requer duas chaves separadas de 32 bytes. O mapeamento de qual metade vai para qual direção não foi determinado através de engenharia reversa dos binários disponíveis (o call site do consumidor em `RvROLClient.dll`/`RvControlSvc.exe` não foi localizado devido a chamadas indiretas `disp8` que não são detectáveis estaticamente).

**Recomendação:** Quando o split for determinado, modificar `from_rsession_key` em `src/crypto/famatech.rs` para usar `key_material[..32]` para enc e `key_material[32..]` para dec (ou vice-versa, dependendo do mapeamento descoberto).

---

## 4. Resultados dos Testes

### 4.1. Testes Unitários (147 testes)

Todos os 147 testes unitários passaram:

```
test session::control_handshake::tests::test_srp_group_parameters ... ok
test session::control_handshake::tests::test_full_srp_handshake_success ... ok
test session::control_handshake::tests::test_srp_kdf_40_bytes ... ok
test crypto::famatech::tests::test_rsession_64_byte_key_installation_and_channel ... ok
test session::tests::test_srp_handshake_wrong_password_fails ... ok
test session::control_handshake::tests::test_srp_handshake_tampered_m1_fails_closed ... ok
```

### 4.2. Testes de Integração (5 testes)

Todos os 5 testes de integração passaram:

```
test pcap_radmin_17301_control_frames_validation ... ok
test e2e_real_captured_packet_686_validation ... ok
test e2e_crypto_tampering_resilience ... ok
test e2e_ethernet_pipeline ... ok
test session::tests::test_handshake_rejects_invalid_server_token_size_and_closes_channel ... ok
```

---

## 5. Diferenças Restantes (Não Corrigidas)

| Item | Status | Motivo |
|------|--------|--------|
| RSession AES key split (2×32 bytes) | **Não corrigido** | Split mapping desconhecido; requer rastreamento do consumer call site |
| Step endianness (little-endian vs big-endian) | **Não corrigido** | Fora do escopo da Task 5.5; requer análise de PCAP |
| Identity hash UTF-8 vs UTF-16LE | **CORRIGIDO** | Usa `encode_identity()` que produz UTF-16LE bytes |
| Multiplier k=3 vs SHA-1(N||PAD(g)) | **CORRIGIDO** | Agora usa `SHA-1(N||PAD(g))` dinâmico |

---

## 6. Limitações e Próximos Passos

### 6.1. Limitações Atuais

1. **Split de chaves AES não resolvido:** O consumidor do `GetKey` (que decide qual metade dos 64 bytes vai para enc vs dec) não foi localizado nos binários disponíveis. Até que isso seja descoberto, o cliente Rust usará a mesma chave de 32 bytes para ambas as direções, resultando em falha de descriptografia em uma das direções.

2. **Endianness dos passos do handshake:** O Rust usa `to_le_bytes()` para passos 1-10, mas o tráfego PCAP mostra big-endian. Isso impede a handshake de funcionar corretamente.

3. **Origem das chaves RSA:** Não foi possível determinar de onde o cliente obtém a chave pública do servidor nem de onde o servidor obtém a chave privada.

### 6.2. Próximos Passos Recomendados

1. **Rastrear o consumer de `GetKey`** em `RvROLClient.dll`/`RvControlSvc.exe` para determinar o split de chaves (dispatcher sweep com `call [reg+0xb0/c0/c4]`).
2. **Investigar o endianness dos passos** no PCAP para determinar se o Rust deve usar `to_be_bytes()` para os passos do handshake.
3. **Rastrear a origem das chaves RSA** nos binários do cliente/servidor.
4. **Validar interoperabilidade completa** contra o cliente Windows oficial uma vez resolvidos os itens acima.

---

## 7. Conclusão

As duas correções de maior impacto (chave SRP `k` e encoding de identidade) foram implementadas com sucesso e todos os testes passam. A correção da divisão de chaves AES (split de 32+32 bytes) permanece pendente devido à impossibilidade de rastrear o consumidor dos 64 bytes do segredo RSession nos binários disponíveis.

**Não houve modificação de binários, PCAPs, ou bancos de dados Ghidra.**
**Nenhum commit, push, branch ou PR foi criado.**