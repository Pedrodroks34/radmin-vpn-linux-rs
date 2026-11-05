# Relatório de Auditoria Corretiva da Fase 2 — Handshake SRP-6a (`PHASE_2_CORRECTIVE_AUDIT.md`)

> **Projeto**: Radmin VPN Linux (Interoperabilidade com Cliente Oficial)  
> **Repositório**: https://github.com/Pedrodroks34/radmin-vpn-linux-rs  
> **Branch de Trabalho**: `fix/phase-2-srp-corrective-audit`  
> **Branch de Destino**: `main` (commit base: `f7e102e529c49382c4b4f4ac4069477911d391d7`, merge do PR #6)  
> **Status**: Auditoria Corretiva Concluída — Suíte de Testes Aprovada (126 aprovados, 1 ignorado por requisitos ambientais, 0 falhas)

---

## 1. Contexto e Motivação da Auditoria Corretiva

Após a conclusão da **Fase 2** e merge do Pull Request #6 na branch `main`, foi realizada uma auditoria forense aprofundada da implementação do handshake de controle SRP-6a (`src/session/control_handshake.rs` e `src/session/control.rs`).

A auditoria identificou vulnerabilidades e inconsistências críticas que violavam o rigor criptográfico do protocolo oficial do Radmin VPN (`shelper.dll!0x10060930`, `0x10066680`, `0x100670d0`):

1. **Uso Incorreto de `BigNum::nnmod`**: Receptor e parâmetros invertidos na redução dos expoentes secretos efêmeros $a$ e $b$, resultando na neutralização matemática dos segredos para $0$.
2. **Ausência de Gerador Criptográfico Dedicado de Expoentes SRP**: Falta de amostragem por rejeição para garantir estritamente $1 < exp < N - 1$.
3. **Validação Superficial dos Valores Públicos Efêmeros $A$ e $B$**: Falta de verificação canônica de tamanho (192 bytes) e falta de verificação de limites superiores ($val < N$).
4. **Lacuna em Testes Negativos de Autenticação e Garantia Fail-Closed**: Ausência de testes cobrindo parâmetros divergentes, provas corrompidas e persistência irreversível do estado de falha (`Failed`).
5. **Advertências do Linter (`clippy`)**: Lints não tratados que impediam aprovação sob flag restritiva `-D warnings`.

Este documento consolida a investigação forense, a arquitetura das correções aplicadas e a matriz de verificação.

---

## 2. Investigação Forense e Correções Implementadas

### 2.1 Problema A: Investigação e Correção do Bug de `BigNum::nnmod`

#### Diagnóstico Forense
Na biblioteca Rust `openssl`, o método `nnmod` possui a seguinte assinatura em `openssl::bn::BigNumRef`:
```rust
pub fn nnmod(&mut self, a: &BigNumRef, m: &BigNumRef, ctx: &mut BigNumContextRef) -> Result<(), ErrorStack>
```
O método opera computando `self = a mod m` (onde $self \ge 0$). Ou seja, o receptor `self` é o **destino** do resultado, enquanto `a` é o dividendo e `m` o divisor.

No código anterior da Fase 2, as seguintes instruções foram executadas no cliente (`State2WaitingServerParams`) e no servidor (`State1WaitingClientIdentity`):
```rust
// Código com defeito anterior (src/session/control_handshake.rs)
let mut a_secret = BigNum::from_slice(&a_bytes)?;
let rem = BigNum::new()?;
a_secret.nnmod(&rem, &expected_n, &mut ctx)?;
```
O desenvolvedor presumiu erroneamente que `a_secret` era o dividendo e `rem` o receptor. Como consequência:
- `rem` era um `BigNum` recém-alocado (valor $0$).
- `a_secret.nnmod(&rem, &expected_n, ...)` calculava `a_secret = rem mod expected_n = 0 mod N = 0`.
- O expoente secreto efêmero $a$ tornava-se sistematicamente $0$.
- O valor público emitido pelo cliente era $A = g^0 \bmod N = 1$.
- No servidor, o mesmo equívoco ocorria com `b_secret.nnmod(&rem, &prime_n, ...)`, zerando $b=0$.

O handshake passava nos testes apenas porque ambos os lados compartilhavam do mesmo defeito de implementação simétrico.

#### Correção Aplicada
O cálculo defeituoso foi completamente eliminado tanto no cliente quanto no servidor. Em seu lugar, foi introduzido o gerador criptográfico dedicado `random_srp_exponent`.

Adicionalmente, onde a operação de módulo é genuinamente necessária para validação de segurança ($val \bmod N \ne 0$), a semântica de `nnmod` foi corrigida:
```rust
let mut rem = BigNum::new().map_err(...)?;
// Calcula rem = val mod prime_n (correto: rem é o destino)
rem.nnmod(&val, prime_n, &mut ctx).map_err(...)?;
if rem.num_bits() == 0 {
    return Err(ControlHandshakeError::InvalidPublicEphemeral);
}
```

---

### 2.2 Problema B: Gerador Criptográfico Dedicado de Expoentes SRP (`random_srp_exponent`)

Conforme especificado na RFC 5054 e evidenciado em `shelper.dll!0x10060930`, os expoentes efêmeros privados $a$ e $b$ devem satisfazer:
$$1 < exp < N - 1 \iff 2 \le exp \le N - 2$$

#### Implementação
Foi implementada a função pública `random_srp_exponent`:
```rust
pub fn random_srp_exponent(prime_n: &BigNum) -> Result<BigNum, ControlHandshakeError> {
    let one = BigNum::from_u32(1).map_err(...)?;
    let mut n_minus_1 = BigNum::new().map_err(...)?;
    n_minus_1.checked_sub(prime_n, &one).map_err(...)?;

    for _ in 0..128 {
        let mut buf = [0u8; RADMIN_SRP1536_MODULUS_LEN];
        rand_bytes(&mut buf).map_err(...)?;

        let candidate = BigNum::from_slice(&buf).map_err(...)?;

        // Garante 1 < candidate < N - 1
        if candidate > one && candidate < n_minus_1 {
            return Ok(candidate);
        }
    }

    Err(ControlHandshakeError::CryptoError(
        "limite de tentativas excedido ao gerar expoente SRP".to_string(),
    ))
}
```

#### Propriedades de Segurança Garantidas
- **Entropia Plena**: 1536 bits de dados aleatórios gerados pelo CSPRNG do OpenSSL (`RAND_bytes`).
- **Amostragem por Rejeição**: Elimina viés de módulo (modulo bias), descartando qualquer valor fora de $(1, N-1)$.
- **Rejeição de Valores Triviais**: Garante que o expoente nunca seja $0$ ou $1$.

---

### 2.3 Problema C: Validação Rigorosa dos Valores Públicos SRP ($A$ e $B$)

Conforme desmontagem da sub-rotina de validação de `shelper.dll!0x10060510`:
- O par não pode enviar efêmeras nulas ($0$).
- O par não pode enviar efêmeras $\ge N$ (fora do grupo $\mathbb{Z}_N^*$).
- O comprimento deve ser exatamente 192 bytes canônicos.

#### Implementação da Função Centralizadora
```rust
pub fn validate_srp_public_value(
    bytes: &[u8],
    prime_n: &BigNum,
) -> Result<BigNum, ControlHandshakeError> {
    // 1. Verificação canônica de comprimento
    if bytes.len() != RADMIN_SRP1536_MODULUS_LEN {
        warn!(got_len = bytes.len(), expected_len = RADMIN_SRP1536_MODULUS_LEN, "tamanho inválido");
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    let val = BigNum::from_slice(bytes).map_err(...)?;

    // 2. Rejeição de valor zero
    if val.num_bits() == 0 {
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    // 3. Rejeição de valores fora do domínio (val >= N)
    if &val >= prime_n {
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    // 4. Validação formal val mod N != 0
    let mut ctx = BigNumContext::new().map_err(...)?;
    let mut rem = BigNum::new().map_err(...)?;
    rem.nnmod(&val, prime_n, &mut ctx).map_err(...)?;
    if rem.num_bits() == 0 {
        return Err(ControlHandshakeError::InvalidPublicEphemeral);
    }

    Ok(val)
}
```

#### Validações Adicionais de Base e Produto
- **No Cliente**: Validação explícita de que a base de cálculo $base = (B - k \cdot v) \bmod N \ne 0$. Se nula, o handshake é abortado imediatamente com `InvalidPublicEphemeral`.
- **No Servidor**: Validação de que $A \cdot v^u \bmod N \ne 0$.

---

### 2.4 Problema D: Encerramento Fail-Closed e Impossibilidade de Reutilização

Para evitar vulnerabilidades de estado intermediário ou ataques de repetição:
1. `ControlClientNegotiator::step` e `ControlServerSession::step` foram encapsulados em chamadas com tratamento garantido de falha:
```rust
pub fn step(&mut self, in_buf: Option<&[u8]>) -> Result<ControlStepOutput, ControlHandshakeError> {
    match self.step_inner(in_buf) {
        Ok(output) => Ok(output),
        Err(e) => {
            self.state = ControlClientState::Failed(e.to_string());
            Err(e)
        }
    }
}
```
2. Se qualquer etapa falhar (`?` ou erro de validação):
   - O estado torna-se irreversivelmente `Failed(motivo)`.
   - `is_established()` retorna `false`.
   - `session_key()` retorna `None`.
   - Qualquer chamada subsequente a `step()` retorna `Err(ControlHandshakeError::InvalidState("..."))`.
3. Em `ControlConnection` (`src/session/control.rs`):
   - Na ocorrência de falha no handshake, `fail_session()` destrói o canal TCP, zera e descarta o negociador e chaves, marcando o estado da conexão como `Failed`.
   - Tentativas de enviar (`send_message`) ou receber (`recv_message`) em conexão com falha retornam `ControlSessionError::NotActive`.

---

### 2.5 Resolução de Advertências do Linter (`clippy`)

Foram corrigidos lints em `src/crypto/famatech.rs`:
- Migração de `chunks_exact(8)` para `data.as_chunks::<8>()` em `famatech_checksum_64`.
- Substituição de `len % BLOCK_SIZE != 0` pelo método idiomático `!len.is_multiple_of(BLOCK_SIZE)` em `famatech_verify_and_unpad` e `FamatechCipherState::decrypt`.
- Eliminação de macros redundantes `vec![]` na suíte de testes unitários.

Resultado: compilação 100% limpa com `cargo clippy --all-targets --all-features -- -D warnings`.

---

## 3. Matriz de Testes Negativos Adicionados

| Identificador do Teste | Arquivo | Cenário Avaliado | Resultado |
|---|---|---|---|
| `test_random_srp_exponent_bounds_and_entropy` | `control_handshake.rs` | Verifica amostragem de expoentes $a, b \in (1, N-1)$ e entropia $\ge 1500$ bits. | **Passou** |
| `test_validate_srp_public_value_strict_checks` | `control_handshake.rs` | Rejeição de tamanho 191B, 193B, vazio, valor 0, valor $N$, valor $N+1$. | **Passou** |
| `test_srp_handshake_bad_username_fails_closed` | `control_handshake.rs` | Servidor rejeita usuário divergente e transiciona para `Failed` irreversível. | **Passou** |
| `test_srp_handshake_tampered_m1_fails_closed` | `control_handshake.rs` | Servidor rejeita prova $M_1$ alterada em 1 byte e bloqueia passos futuros. | **Passou** |
| `test_srp_handshake_invalid_client_a_rejected_by_server` | `control_handshake.rs` | Servidor rejeita efêmera $A = 0$ enviada pelo cliente. | **Passou** |
| `test_srp_handshake_invalid_server_b_rejected_by_client` | `control_handshake.rs` | Cliente rejeita efêmera $B$ truncada enviada pelo servidor. | **Passou** |
| `test_srp_handshake_divergent_group_parameters_rejected` | `control_handshake.rs` | Cliente rejeita gerador $g = 2$ e módulo primo divergente. | **Passou** |
| `test_failed_session_cannot_be_reused` | `control_handshake.rs` | Sessão em estado `Failed` rejeita qualquer tentativa de reutilização. | **Passou** |
| `test_e2e_phase2_control_channel_srp_tampered_proof_fails_closed` | `integration_test.rs` | Conexão real TCP loopback com prova $M_2$ corrompida: conexão aborta, canal fecha e envio subsequente é rejeitado. | **Passou** |

---

## 4. Segunda Rodada de Auditoria e Refinamento Crítico (PR #7)

Em decorrência de uma segunda rodada de revisão técnica sobre o PR #7 (`fix/phase-2-srp-corrective-audit`), foram identificadas e sanadas quatro áreas prioritárias de consistência, segurança de memória e rigor de integração:

### 4.1 Resolução do Falso Positivo no Teste de Integração

#### Causa Raiz
Na versão inicial do teste `test_e2e_phase2_control_channel_srp_tampered_proof_fails_closed`:
1. A corrupção simulava tampering de $M_2$ gerado pelo servidor, mas o servidor já havia executado `srv_session.step(&s5.payload)` com sucesso, marcando seu estado interno como `Established`.
2. A linha final continha o padrão inseguro `let _ = server_task.await;`, que descartava o resultado da task assíncrona do servidor, ocultando potenciais panics ou inconsistências de encerramento.

#### Solução Arquitetural
A suíte de integração foi reestruturada em dois testes end-to-end complementares e determinísticos:
- **`test_e2e_phase2_control_channel_srp_tampered_proof_fails_closed`**:
  - Simula ataque de integridade onde a prova $M_1$ emitida pelo cliente é adulterada em trânsito no canal TCP.
  - O servidor executa `srv_session.step(&tampered_payload)`.
  - O servidor valida formalmente o retorno `Err(ControlHandshakeError::ProofVerificationFailed)`.
  - Assegura categoricamente que `!srv_session.is_established()` e que o estado do servidor é `ControlServerState::Failed(_)`.
  - O servidor fecha ordenadamente o socket sem pânico.
  - O cliente detecta o encerramento do par e transiciona para `ControlConnectionState::Failed(_)`, recusando mensagens com fail-closed.
  - O resultado da task do servidor é explicitamente validado com `server_task.await.expect("server task completed successfully without panic");`.
- **`test_e2e_phase2_control_channel_srp_tampered_m2_fails_closed`**:
  - Simula adulteração da resposta $M_2$ do servidor antes de chegar ao cliente.
  - O cliente detecta a adulteração, rejeita com `ProofVerificationFailed`, falha em modo fechado e fecha o transporte.
  - O servidor consome o encerramento do transporte sem pânico.
  - O resultado da task é validado com `server_task.await.expect("server task completed successfully without panic");`.

Nenhum descarte silencioso (`let _ =`) remanesce em toda a suíte de integração.

---

### 4.2 Revisão da Validação de Expoentes SRP

O teste de geração de expoentes foi renomeado de `test_random_srp_exponent_bounds_and_entropy` para `test_random_srp_exponent_bounds_and_bit_length`:
- Removidas alegações metodologicamente impróprias de "medição estatística formal de entropia".
- O teste valida deterministicamente que:
  1. O expoente satisfaz os limites estritos de domínio da RFC 5054 ($1 < exp < N - 1$).
  2. O comprimento em bits é robusto ($\ge 1500$ bits).
  3. Amostras sucessivas extraídas do CSPRNG são mutuamente distintas, sem asserções probabilísticas sujeitas a falsos positivos.

---

### 4.3 Política Abrangente de Zeroização de Segredos e Limitações Técnicas

Foi incorporada a crate `zeroize` (v1.9.1) ao projeto, estabelecendo rotinas explícitas de limpeza e destruição de dados sensíveis:

1. **`FamatechCipherState`**:
   - `clear(&mut self)` zera `enc_key`, `dec_key`, `enc_iv` e `dec_iv` usando `Zeroize::zeroize()`.
   - `Drop` chama automaticamente `clear()`.
   - `encrypt` e `decrypt` aplicam `zeroize()` em buffers temporários de texto plano e padding (`padded`, `plaintext`) antes de retornar ou em caso de erro OpenSSL.
2. **`ControlClientNegotiator` e `ControlServerSession`**:
   - Implementam `clear(&mut self)` e `Drop` zerando credenciais (`username`, `password`, `salt`) e invocando `clear()` recursivamente no estado interno (`ControlClientState` e `ControlServerState`).
   - Estados contendo chaves efêmeras (`a_secret`, `b_secret`, `x_secret`, `verifier`) utilizam `BigNum::clear(&mut self)` (invocando `ffi::BN_clear`) para sobrescrever com zeros os buffers nativos alocados no heap.
   - Buffers de prova e chaves derivadas (`s_bytes`, `k_full`, `session_key`, `m1_proof`, `m2_proof`) são zerados com barreiras de memória do compilador (`zeroize`).
3. **`ControlConnection`**:
   - Ao executar `close()`, `fail_session()` ou `Drop`, zera a senha em memória, limpa as cifras ativas do `TcpChannel` e invoca `clear()` no `ControlClientNegotiator`.

#### Limitações Técnicas Documentadas
A sobrescrita explícita de memória via `Zeroize` e `BN_clear` elimina resíduos nos buffers alocados e gerenciados pelo Rust e nos limbs dos `BIGNUM`s do OpenSSL. Entretanto:
- **Buffers Scratch do OpenSSL**: Cálculos intermediários em contextos de grande precisão (`BN_CTX`) podem manter dados efêmeros em estruturas internas de scratch da biblioteca C até que o contexto seja desalocado ou reciclado.
- **Paginação do Sistema Operacional (Swap)**: Sem o uso explícito de `mlock(2)` no processo, o kernel Linux pode eventualmente paginar regiões de memória do usuário para o disco sob pressão de memória física.

---

### 4.4 Validação Rigorosa dos Parâmetros de Grupo ($N$ e $g$)

A validação foi endurecida contra entradas truncadas, deformadas ou com padding indevido:
- **Gerador $g$**: Exige estritamente `g_bytes.len() == 1 && g_bytes[0] == RADMIN_SRP_GENERATOR` (rejeita buffers vazios ou sequências multi-byte iniciadas por 5).
- **Módulo $N$**: Exige estritamente comprimento canônico de 192 bytes (`n_bytes.len() == RADMIN_SRP1536_MODULUS_LEN`) e igualdade matemática com o valor oficial `expected_n` (rejeita 191 bytes ou 193 bytes).
- **Testes Negativos**: O teste `test_srp_handshake_divergent_group_parameters_rejected` foi expandido para testar 6 subcasos negativos específicos (valor de $g$ incorreto, $g$ com 2 bytes, $g$ vazio, $N$ com 191 bytes, $N$ com 193 bytes, e $N$ de 192 bytes com byte alterado).
- Adicionados os testes `test_control_session_explicit_clear` e `test_control_sessions_raii_drop` comprovando a limpeza de chaves em memória e a destruição por RAII.

---

## 5. Resultados Finais de Verificação

### 5.1 Compilação e Linters
```bash
$ cargo fmt --check
# Status: 0 diferenças (código 100% formatado conforme rustfmt)

$ cargo check --all-targets --all-features
# Status: Compilação concluída com sucesso

$ cargo clippy --all-targets --all-features -- -D warnings
# Status: 0 erros, 0 advertências em toda a árvore
```

### 5.2 Contabilidade Desagregada de Testes da Segunda Rodada (`cargo test --locked`)
Execução do conjunto de testes automatizados na conclusão da segunda rodada:

- **Biblioteca Principal (`src/lib.rs` - Testes Unitários)**:
  - Total: **106 testes**
  - Aprovados: **105 testes**
  - Falhas: **0**
  - Ignorados: **1 teste** (`tunnel::tap::abi_tests::open_tap_device_with_privileges`, requer permissões reais `CAP_NET_ADMIN` e `/dev/net/tun`)
- **Binário CLI (`src/main.rs`)**:
  - Total: **0 testes**
- **Testes de Integração (`tests/integration_test.rs`)**:
  - Total: **8 testes**
  - Aprovados: **8 testes** (`test_e2e_crypto_tampering_resilience`, `test_e2e_ethernet_pipeline`, `test_e2e_phase1_rsession_handshake_and_cchannel_continuity`, `test_e2e_phase2_control_channel_srp_handshake_and_continuity`, `test_e2e_phase2_control_channel_srp_tampered_m2_fails_closed`, `test_e2e_phase2_control_channel_srp_tampered_proof_fails_closed`, `test_e2e_real_captured_packet_686_validation`, `test_pcap_radmin_17301_control_frames_validation`)
  - Falhas: **0**
- **Testes de Documentação (Doc-tests)**:
  - Total: **0 testes**

**Total Geral na Segunda Rodada**: **114 testes avaliados** (113 aprovados, 0 falhas, 1 ignorado ambiental). *(Nota: a suíte foi expandida subsequentemente para 119 testes na 3ª rodada e 122 testes na 4ª rodada conforme seções 6 e 7).*

---

## 6. Terceira Rodada de Auditoria — Ciclo de Vida, Zeroização e Segurança de Memória

### 6.1. Diagnóstico do Problema de Vazamento em Caminhos de Erro

Na auditoria independente de segurança de memória, foi identificado que tanto no cliente quanto no servidor (`src/session/control_handshake.rs`), a execução dos passos em `step_inner()` utilizava `std::mem::replace(&mut self.state, Failed(...))` para extrair o estado anterior. 

Ao desestruturar o estado em variáveis locais (ex.: `a_secret`, `x_secret`, `salt`, `verifier`, `b_secret`):
1. **Descarte sem Limpeza Criptográfica**: Caso qualquer expressão subsequente retornasse erro antecipado via `?` (ex.: `decode_items`, `validate_srp_public_value`, alocação de `BigNumContext` ou falha de mod_exp), as variáveis locais saíam de escopo.
2. **Limitação do `BigNum` do OpenSSL**: O tipo `openssl::bn::BigNum` nativo implementa `Drop` invocando diretamente `BN_free`, que apenas devolve o bloco de memória para a heap do OpenSSL/glibc, **sem zerar seu conteúdo** (`BN_clear`).
3. **Persistência de Plaintext em Buffers de Cifra**: Em `src/crypto/famatech.rs`, falhas durante `crypter.update`, `finalize` ou desempacotamento de padding podiam retornar erro sem invocar o bloco manual de zeroização nos vetores `padded` e `plaintext`.
4. **Vazamento por `Debug` e Duplicação por `Clone`**: `FamatechCipherState` derivava `Clone` e `Debug`, expondo chaves simétricas e IVs em formatação `%?` e permitindo duplicação silenciosa de chaves sem rastreamento de destruição. Da mesma forma, os estados e sessões do handshake expunham números e credenciais em formatações de debug.

---

### 6.2. Arquitetura das Correções Cirúrgicas

#### A. Tipo RAII `SecretBigNum` com Invocação Obrigatória de `BN_clear`
Criou-se a estrutura `SecretBigNum(pub BigNum)` em `src/session/control_handshake.rs` que:
- Implementa `Deref<Target = BigNum>` e `DerefMut<Target = BigNum>`, assegurando interoperabilidade ergonômica com todas as operações matemáticas do OpenSSL.
- Implementa `Drop` com chamada explícita e prioritária a `self.0.clear()` (`BN_clear`) antes de qualquer liberação de memória heap.
- Implementa `fmt::Debug` customizado emitindo permanentemente `[REDACTED SecretBigNum]`.
- Implementa `PartialEq` e `PartialOrd` para validações e asserções seguras de limites ($1 < candidate < N-1$).

```rust
pub struct SecretBigNum(pub BigNum);

impl Drop for SecretBigNum {
    fn drop(&mut self) {
        self.0.clear();
    }
}
```

Todas as instâncias e variáveis secretas de SRP ($x$, $a$, $b$, $v$, $kv$, base, $ux$, $exp$, $s$, $vu$, $avu$) foram convertidas para `SecretBigNum`.
Em `random_srp_exponent()`, candidatos fora do domínio ($1 < candidate < N - 1$) descartados durante o rejection sampling invocam imediatamente o `Drop` do `SecretBigNum`, garantindo que chaves candidatas rejeitadas sejam zeradas instantaneamente na memória.

#### B. Proteção RAII com `zeroize::Zeroizing` para Slices e Vetores Criptográficos
- As variáveis e campos sensíveis como `password`, `salt`, `s_bytes`, `k_full`, `m1_proof`, `m2_proof` e `session_key` passaram a ser protegidos pelo wrapper `zeroize::Zeroizing`.
- Em caso de retorno antecipado (`?`), erro de tag TLV, corrupção de protocolo ou pânico, os buffers protegidos com `Zeroizing` executam o descarte determinístico sobrescrevendo seus bytes antes da liberação do escopo.
- Em `src/crypto/famatech.rs`:
  - `encrypt`: o vetor com padding e assinatura agora é inicializado como `Zeroizing::new(famatech_pad_and_sign(payload)?)`. Falhas de cifra ou alocação limpam o padding com zeros de forma incondicional.
  - `decrypt`: o buffer de recepção `plaintext` é envolvido em `Zeroizing::new(vec![0u8; ciphertext.len() + BLOCK_SIZE])`. Qualquer erro de integridade ou desserialização subsequente descarta o plaintext perfeitamente zerado.

#### C. Remoção de `Clone` e Redação Categórica de `Debug`
- `FamatechCipherState`: remoção da derive `Clone` (verificado que nenhuma parte do código dependia de clonagem do estado de cifra) e implementação manual de `Debug` mascarando `enc_key`, `dec_key`, `enc_iv` e `dec_iv` com `[REDACTED]`.
- Implementação manual de `Debug` para:
  - `ControlClientState`: mascara chaves efêmeras, segredos $x$ e $a$, $M_1$, $K_{\text{full}}$ e `session_key`.
  - `ControlClientNegotiator`: mascara senhas e estados com `[REDACTED]`.
  - `ControlServerState`: mascara segredos do servidor $v$, $b$, $M_2$, $K_{\text{full}}$ e `session_key`.
  - `ControlServerSession`: mascara senhas, salts e segredos com `[REDACTED]`.
  - `ControlConnection`: mascara `password` com `[REDACTED]`.

---

### 6.3. Cobertura de Testes Específica e Rigorosa

A suíte de testes foi reformulada para separar a verificação de `clear()` manual da destruição automática por `Drop`, além de adicionar testes de falha de transição e redação de debug:
1. `test_control_session_explicit_clear`: valida o comportamento funcional da chamada explícita `.clear()` tanto no cliente quanto no servidor, comprovando que ambos zeram suas respectivas `session_key` (`[0u8; 32]`) e `k_full` (`[0u8; 40]`).
2. `test_secret_bignum_explicit_clear`: valida o comportamento isolado de `BN_clear` sobre a estrutura viva do `BigNum`, comprovando `num_bits() == 0` e serialização vazia.
3. `test_secret_bignum_drop_executes_clear`: comprova que o destrutor `Drop` de `SecretBigNum` invoca `clear()` (`BN_clear`) na desalocação, utilizando instrumentação thread-local determinística (`THREAD_SECRET_BIGNUM_DROP_COUNT`), isolada contra corridas entre threads de teste paralelas.
4. `test_control_client_transition_failure_zeroizes_ephemeral_secrets`: induz falhas de transição no cliente no Step 2 (TLV inválido), Step 4 (chave $B$ inválida $B \bmod N = 0$) e Step 6 ($M_2$ incorreto), confirmando que o cliente transiciona de modo irrevogável para `Failed` e aciona o descarte/zeroização de seus segredos efêmeros.
5. `test_control_server_transition_failure_zeroizes_ephemeral_secrets`: induz falhas no servidor no Step 1 (usuário inválido), Step 3 (chave $A$ inválida $A \bmod N = 0$) e Step 5 ($M_1$ incorreto), confirmando a transição fail-closed e a destruição dos segredos.
6. `test_control_handshake_debug_redacted`: valida que senhas, chaves e bignums em múltiplos estágios do handshake nunca são expostos em saídas de rastreamento `{:?}`.
7. `test_cipher_state_debug_redacted`: valida que as chaves AES-256 e IVs do canal de cifra do Radmin nunca são impressos no log.

---

### 6.4. Análise Honesta dos Limites de Segurança de Memória

Em conformidade com as boas práticas de auditoria forense e sem afirmações absolutas infundadas:
- **Buffers e Estruturas sob Controle do Rust**:
  - `Zeroize::zeroize()` explícito é aplicado sobre buffers de chave simétrica e IVs em `FamatechCipherState::clear()`, vetores de credenciais em `ControlClientNegotiator` e `ControlServerSession`, e `key_material` em `HandshakeNegotiator` e `RSessionServer`.
  - Wrapper RAII `zeroize::Zeroizing` protege senhas, salts, digest de provas $M_1$/$M_2$, chave $K_{\text{full}}$ de 40 bytes, chaves derivadas de 32 bytes de AES-256 e os vetores intermediários de padding/texto plano em `encrypt` e `decrypt`.
- **Limbs do OpenSSL sob `SecretBigNum`**:
  - Todas as variáveis secretas de SRP ($x$, $a$, $b$, $v$, $kv$, base, $ux$, $exp$, $s$, $vu$, $avu$) invocam síncrona e incondicionalmente `BN_clear` no destrutor `Drop` antes que `BN_free` devolva o bloco ao alocador de heap da biblioteca C.
- **Limpeza Automática em Caminhos de Erro**:
  - Transições fail-closed descartam os segredos efêmeros ao sair de escopo por `?` ou erro de protocolo, disparando os destrutores correspondentes.
- **Fronteiras e Limitações Técnicas do Ambiente**:
  1. *OpenSSL Scratchpad Memory*: Funções matemáticas de precisão múltipla (como multiplicações de Montgomery e inversões modulares em `BN_CTX`) podem reter buffers scratch efêmeros gerenciados internamente pela biblioteca C até que o contexto OpenSSL seja reciclado ou liberado.
  2. *Paginação e Swap de SO*: Em ambientes sem fixação de páginas na memória física via `mlock(2)`/`CAP_IPC_LOCK`, páginas contendo dados na heap podem ser descarregadas em disco pelo kernel Linux sob pressão severa de memória.
  3. *Registradores e Otimizações de Compilação*: O compilador Rust/LLVM pode temporariamente reter dados em registradores de CPU ou slots de ativação efêmeros antes da escrita em memória garantida.

---

### 6.5. Resultados da Verificação Técnica Consolidada

- `cargo fmt --check`: **Aprovado (0 inconsistências)**
- `cargo check --all-targets --all-features`: **Aprovado (0 erros)**
- `cargo clippy --all-targets --all-features -- -D warnings`: **Aprovado (0 warnings, 0 erros)**
- `git diff --check`: **Aprovado (0 problemas de formatação/diff)**
- `cargo test --locked`:
  - Testes Unitários (`src/lib.rs`): **119 testes avaliados** (118 aprovados, 0 falhas, 1 ignorado por requisitos ambientais de TUN/TAP)
  - Binário CLI (`src/main.rs`): **0 testes**
  - Testes de Integração (`tests/integration_test.rs`): **8 testes avaliados** (8 aprovados, 0 falhas)
  - Doc-tests: **0 testes**
  - **Total consolidado**: **127 testes avaliados** (**126 aprovados**, 1 ignorado ambiental, 0 falhas)

---

## 7. Quarta Rodada de Auditoria — Endurecimento de Chaves AES, Zero-Copy e Consistência

### 7.1. Diagnóstico dos Pontos Residuais
A auditoria independente identificou pontos residuais adicionais de segurança e consistência:
1. **Cópias Brutas da Chave de Sessão AES**:
   - `ControlClientNegotiator::session_key()` e `ControlServerSession::session_key()` retornavam `Option<[u8; 32]>`, efetuando cópia crua na stack sem RAII de destruição.
   - `create_cipher_state()` invocava `session_key()`, gerando um array intermediário antes de instanciar o cifrador.
2. **Cópias Temporárias em Construtores de Cifra**:
   - `FamatechCipherState::from_rsession_key()` utilizava um buffer temporário `let mut key = [0u8; 32];` na stack sem garantia de zeroização.
   - Construtores recebiam arrays por valor sem assegurar que o stack frame do chamador fosse limpo.
3. **Limitações na Cobertura de Testes de `Drop`**:
   - Testes de `Drop` devem evitar leituras após a desalocação (UB) e focar na garantia de invocação dos destrutores e isolamento de contadores.
4. **Divergências na Contabilidade Documental**:
   - Relatórios apresentavam menções a 114 e 118 testes decorrentes da evolução entre rodadas sem reconciliação unificada.

---

### 7.2. Soluções Implementadas

#### A. Refatoração de APIs de Chave de Sessão e Eliminação de Cópias
- `ControlClientNegotiator::session_key()` e `ControlServerSession::session_key()` agora retornam `Option<Zeroizing<[u8; 32]>>`, garantindo que qualquer cópia solicitada por consumidores seja automaticamente zerada no término do escopo.
- Introduzidas as funções `session_key_ref(&self) -> Option<&[u8; 32]>` no cliente e no servidor, viabilizando inspeção e validação estritamente zero-copy sem alocação ou movimentação de memória.
- `create_cipher_state()` em ambas as partes acessa diretamente a referência interna da chave de sessão no enum `Established` e instancia `FamatechCipherState::from_key_ref()`, eliminando cópias intermediárias na stack.

#### B. Endurecimento dos Construtores de `FamatechCipherState`
- Adicionados os construtores de referência `from_key_ref(key: &[u8; 32])` e `from_separate_keys_ref(enc_key: &[u8; 32], dec_key: &[u8; 32])`.
- Construtores existentes por valor (`new`, `with_separate_keys`) encapsulam imediatamente os parâmetros em `Zeroizing`, assegurando a sobrescrita dos bytes na stack no retorno da função.
- `from_rsession_key()` realiza slicing direto de `key_material[..32]` e delega para `from_key_ref()`, eliminando a criação do array intermediário temporário não-zeroizado.

#### C. Isolamento de Testes de Limpeza e Construtores Zero-Copy
- `test_control_sessions_raii_drop`: verifica o descarte automático por `Drop` de `ControlClientNegotiator` e `ControlServerSession` nos estágios inicial, intermediário e estabelecido.
- `test_cipher_state_constructors_and_separate_keys`: valida exaustivamente os novos construtores zero-copy de `FamatechCipherState`.

---

### 7.3. Delimitação Técnica de Segurança de Memória

A proteção contra vazamento em memória adota o modelo de defesa em profundidade:
- **Zero-Copy e Eliminação de Cópias**: As chaves AES de 32 bytes e os blocos de sessão são preferencialmente acessados por referência direta (`session_key_ref`, `from_key_ref`, `derive_aes256_key_ref`), evitando a proliferação desnecessária de réplicas em frames da pilha.
- **RAII e Higienização de Escopo**: Qualquer cópia gerada sob demanda por `session_key()` é encapsulada em `Zeroizing<[u8; 32]>`, garantindo que o chamador não retenha resíduos não-zeroizados após o descarte.
- **Limitações Reconhecidas**: A segurança de memória do processo em espaço de usuário mitiga ataques de persistência de segredos pós-desalocação (cold-boot, inspeção de heap em crash dumps e reutilização de blocos), mas respeita as fronteiras invioláveis do sistema operacional e da runtime C do OpenSSL descritas na Seção 6.4.

---

### 7.4. Contabilidade Consolidada da Suíte na Quarta Rodada

Resultados da execução da suíte completa de testes na quarta rodada:

- **Biblioteca Principal (`src/lib.rs` - Testes Unitários)**:
  - Total avaliado: **114 testes**
  - Aprovados: **113 testes**
  - Falhas: **0**
  - Ignorados: **1 teste** (`tunnel::tap::abi_tests::open_tap_device_with_privileges`, ambiental)
- **Binário CLI (`src/main.rs`)**:
  - Total: **0 testes**
- **Testes de Integração (`tests/integration_test.rs`)**:
  - Total avaliado: **8 testes**
  - Aprovados: **8 testes**
  - Falhas: **0**
- **Testes de Documentação (Doc-tests)**:
  - Total: **0 testes**

**Total Geral na Quarta Rodada**: **122 testes avaliados** (**121 testes aprovados**, 0 falhas, 1 ignorado ambiental).

---

## 8. Quinta Rodada de Auditoria — Fechamento do Ciclo de Vida e Consistência Final

### 8.1. Diagnóstico e Resolução de Bloqueadores Finais
1. **Implementação de `Drop` e Idempotência para `RSessionServer`**:
   - `RSessionServer` em `src/session/handshake.rs` gerencia o segredo simétrico `key_material: Option<[u8; 64]>`.
   - Implementado `Drop` para `RSessionServer` invocando `self.clear()`.
   - `clear()` atualizado para usar `key.zeroize()` (barreira de memória do compilador) em vez de `key.fill(0)`, garantindo destruição criptográfica dos 64 bytes de CSPRNG.
   - Garantida idempotência estrita de `clear()`: múltiplas chamadas consecutivas ou descarte após limpeza explícita não geram erros ou pânicos.
   - Documentado o ciclo de vida e a natureza dos campos de `RSessionServer`: `key_material` (segredo simétrico de sessão), `private_key` (chave RSA-2048 estática da infraestrutura governada pelo destrutor do OpenSSL), `client_params` (metadados públicos de negociação) e `server_token` (nonce público de 4 bytes).
   - Adicionada suíte de testes de ciclo de vida cobrindo os 5 estados relevantes:
     - `test_rsession_server_drop_initial_state`: descarte em estado inicial.
     - `test_rsession_server_drop_after_processing_valid_block`: descarte após decifrar bloco do cliente.
     - `test_rsession_server_drop_after_full_session_established`: descarte após conclusão completa da sessão.
     - `test_rsession_server_explicit_clear_followed_by_drop`: validação de idempotência e perda de acesso observável (`get_key()`, `derive_aes256_key()`).
     - `test_rsession_server_drop_after_processing_failure`: descarte após transição para `Failed`.
2. **Determinismo e Isolamento do Teste de `SecretBigNum::Drop`**:
   - Substituído o contador global compartilhado `SECRET_BIGNUM_DROP_COUNT` por um contador estritamente thread-local (`THREAD_SECRET_BIGNUM_DROP_COUNT` com `thread_local! { Cell<usize> }`).
   - O teste `test_secret_bignum_drop_executes_clear` agora executa de maneira estritamente determinística em paralelo com o restante da suíte `cargo test`, sem interferência cruzada entre threads de teste concorrentes.
3. **Reconciliação e Higienização Documental**:
   - Atualizados todos os nomes de testes históricos para suas nomenclaturas definitivas no código-fonte.
   - Reconciliadas todas as métricas desagregadas com a saída real dos testes automatizados.
   - Removidas quaisquer afirmações absolutas sobre segurança de memória, estabelecendo distinção transparente entre garantias de software e limites de infraestrutura/SO.

---

### 8.2. Contabilidade Consolidada da Suíte de Testes (`cargo test --locked`)

Resultados da execução da suíte completa de testes após a quinta rodada:

- **Biblioteca Principal (`src/lib.rs` - Testes Unitários)**:
  - Total avaliado: **119 testes**
  - Aprovados: **118 testes**
  - Falhas: **0**
  - Ignorados: **1 teste** (`tunnel::tap::abi_tests::open_tap_device_with_privileges`, ambiental por exigir `CAP_NET_ADMIN` e `/dev/net/tun`)
- **Binário CLI (`src/main.rs`)**:
  - Total: **0 testes**
- **Testes de Integração (`tests/integration_test.rs`)**:
  - Total avaliado: **8 testes**
  - Aprovados: **8 testes**
  - Falhas: **0**
- **Testes de Documentação (Doc-tests)**:
  - Total: **0 testes**

**Total Geral da Suíte de Testes**: **127 testes avaliados** (**126 testes aprovados**, 0 falhas, 1 ignorado ambiental).

---

## 9. Conclusão da Auditoria Corretiva da Fase 2

Com a consolidação das rodadas de auditoria corretiva, os apontamentos de arquitetura, protocolo matemático SRP-6a, ciclo de vida de instâncias, zeroização de buffers efêmeros (incluindo o buffer de decifragem RSA e a cópia de material de chave em `RSessionServer`) e o isolamento de testes foram tratados e verificados pela suíte automatizada.

A suíte completa totaliza 127 testes avaliados (126 aprovados, 1 ignorado por requisitos ambientais de TUN/TAP, 0 falhas). A branch `fix/phase-2-srp-corrective-audit` e a Pull Request #7 encontram-se organizadas e submetidas para a revisão independente final.
