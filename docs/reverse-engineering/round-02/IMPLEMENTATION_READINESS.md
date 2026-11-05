# Matriz de Prontidão para Implementação no Cliente Rust (Round 02)

Este documento avalia a viabilidade e prontidão técnica para a implementação de cada subsistema no cliente nativo Linux em Rust (`radmin-vpn-linux-rs`), baseando-se estritamente nas evidências confirmadas durante esta rodada de engenharia reversa.

---

## 1. Matriz de Prontidão Técnica

| Módulo / Subsistema | Status de Prontidão | Dependência Externa / Bloqueios | Arquivos Rust de Destino |
|---|---|---|---|
| **Framing TCP & Magic (0x03000000)** | **PRONTO (READY)** | Nenhuma | `src/transport/framing.rs` |
| **Handshake RSA-2048 / AES-256 (`HandshakeNegotiator`)** | **PRONTO (READY)** | Chave pública do servidor | `src/session/handshake.rs` |
| **Cifra Simétrica & Trailer Proprietário (`CryptoChannel`)** | **PRONTO (READY)** | Crate `aes`, `cbc` | `src/crypto/famatech.rs` |
| **Serialização e Parser TLV Famatech** | **PRONTO (READY)** | Nenhuma | `src/protocol/tlv.rs` |
| **Autenticação de Rede e Hashing SHA-1** | **PRONTO (READY)** | Crate `sha1` | `src/session/auth.rs` |
| **Camada TAP Linux (`/dev/net/tun`) & Packet Pump** | **PRONTO (READY)** | Privilégio `CAP_NET_ADMIN` | `src/adapter/tap.rs` |
| **Cliente STUN RFC 3489 (Descoberta de NAT)** | **PRONTO (READY)** | Sockets UDP assíncronos | `src/p2p/stun.rs` |
| **Cliente de Retransmissão TcpRelay (Porta 17351)** | **PRONTO (READY)** | Nenhuma | `src/transport/relay.rs` |
| **Camada IPC (UNIX Domain Socket)** | **PRONTO (READY)** | Nenhuma | `src/ipc/server.rs` |
| **Tunelamento Teredo (RFC 4380)** | **OPCIONAL (NEEDS RESEARCH)** | Suporte IPv6 local | `src/p2p/teredo.rs` |

---

## 2. Especificações de Implementação Prontas para o Rust

### 2.1 Cifra Simétrica e Trailer (`src/crypto/famatech.rs`)
A implementação do trailer e validação de padding deve seguir rigorosamente a especificação extraída de `shelper.dll`:

```rust
// Regras obrigatórias de codificação do trailer:
// 1. total_len = ((payload_len + 24) / 16) * 16;
// 2. pad_len = total_len - payload_len; // 9 <= pad_len <= 24
// 3. buffer[payload_len .. total_len - 9].fill(0xCC);
// 4. checksum = sum_64bit_additive_little_endian(&buffer[0 .. total_len - 9]);
// 5. buffer[total_len - 9 .. total_len - 1].copy_from_slice(&checksum.to_le_bytes());
// 6. buffer[total_len - 1] = pad_len as u8;
// 7. aes_256_cbc_encrypt(key, &mut iv, buffer); // IV é persistente e atualizado in-place
```

### 2.2 Máquina de Estados do Handshake (`src/session/handshake.rs`)
A integração em `src/session/` deve eliminar qualquer transição imediata para `SessionActive` sem validação de rede:

```rust
pub enum HandshakeState {
    /// 1. Envia magic framing [00 00 00 04] + [03 00 00 00], aguarda resposta idêntica
    WaitingMagicEcho,
    /// 2. Gera 64 bytes randômicos, monta bloco de 76 bytes, cifra com RSA-2048 PKCS#1 v1.5,
    ///    envia 256 bytes e aguarda 4 bytes do servidor
    WaitingServerHello {
        client_key_material: [u8; 64],
    },
    /// 3. Recebe token de 4 bytes, deriva chave AES-256 dos primeiros 32 bytes de
    ///    `client_key_material`, inicializa IV com zeros e ativa canal simétrico
    SessionActive {
        session_token: u32,
        crypto: CryptoChannel,
    },
    Failed(HandshakeError),
}
```

### 2.3 Interface do Dispositivo de Rede Local (`src/adapter/tap.rs`)
Substituição direta do driver NDIS Windows (`NetMP60_1_1_64.sys`) no Linux:
1. Abrir `/dev/net/tun` com `O_RDWR | O_NONBLOCK`.
2. Emitir `ioctl(fd, TUNSETIFF, &ifr)` com flags `IFF_TAP | IFF_NO_PI`.
3. Configurar MTU para 1500 bytes com `SIOCSIFMTU`.
4. Configurar endereço MAC virtual com `SIOCSIFHWADDR`.
5. Acoplar a um `tokio::io::unix::AsyncFd` para leitura e escrita assíncrona não-bloqueante de quadros Ethernet de 1514 bytes.

---

## 3. Plano de Testes Automatizados com Vetores Extraídos

Para assegurar conformidade sem regressões na futura etapa de implementação:
1. **Teste de Checksum 64-bit:** Vetor extraído diretamente de `shelper.dll` validando a soma little-endian de palavras de 8 bytes e o tratamento de bytes excedentes.
2. **Teste de Padding / Unpadding:** Verificação de que payloads de comprimentos variados (ex.: 1 a 1500 bytes) sempre resultam em múltiplos estritos de 16 bytes e que `pad_len` se mantém entre 9 e 24 bytes com preenchimento `0xCC`.
3. **Teste de Encadeamento de IV:** Validação de que dois blocos consecutivos cifrados com CBC utilizam os últimos 16 bytes do bloco anterior como IV subsequente.
4. **Teste de Deserialização TLV:** Parsing dos blocos de Login, JoinNetwork e respostas de erro usando as tags catalogadas em `03-tlv-catalog.md`.
5. **Teste de STUN Binding:** Simulação de resposta STUN com atributos `0x0001`, `0x0004` e `0x0005` conforme capturado no pacote #839 de `radmin_vm2.pcap`.
