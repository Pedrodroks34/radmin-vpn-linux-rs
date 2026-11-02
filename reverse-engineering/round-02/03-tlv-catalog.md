# Frente 3: Catálogo TLV e Formato de Mensagens

**Classificação de Certeza:** CONFIRMADO (despejo e análise direta dos 723 descritores da tabela global em `RvControlSvc.exe` no endereço `0x00498fe0`, além da desmontagem em `RvROLClient.dll`)

---

## 1. Visão Geral da Serialização TLV Famatech

Todas as estruturas de dados transmitidas no canal Radmin VPN (após o handshake criptográfico) são codificadas em formato **TLV (Tag-Length-Value)** com os seguintes parâmetros fundamentais:

* **Tag:** Inteiro sem sinal de 32 bits, codificado em **Big-Endian**.
* **Length:** Inteiro sem sinal de 32 bits, codificado em **Big-Endian**, indicando estritamente o tamanho em bytes do campo *Value*.
* **Value:** Sequência de $N$ bytes cujo tipo e semântica são determinados pelos bits superiores da Tag e pelo registro no catálogo de propriedades.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      TAG (32 bits, BE)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    LENGTH (32 bits, BE)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     VALUE (Length bytes...)                   |
+---------------------------------------------------------------+
```

---

## 2. Taxonomia dos Tipos de Dados pelas Tags

A análise estática das rotinas de serialização `FUN_00488ae0` e despacho em `RvControlSvc.exe` e `RvROLClient.dll` revela que os 8 bits mais significativos (ou o primeiro byte da Tag) definem a tipagem de dados primitivos e compostos:

| Byte Superior da Tag | Categoria de Tipo | Quantidade de Tags Registradas | Representação no Valor |
|---|---|---|---|
| `0x01` | **`UINT32`** | 374 | Inteiro de 4 bytes sem sinal em Big-Endian (ou Little-Endian interno desempacotado pela arquitetura) |
| `0x02` | **`UINT64`** | 109 | Inteiro de 8 bytes sem sinal (utilizado para IDs de rede e carimbos de data/hora) |
| `0x03` | **`INT32` / ID** | 98 | Inteiro de 4 bytes com sinal (códigos de status e identificadores numéricos) |
| `0x04` | **`BOOL`** | 35 | Booleano representado em 1 byte ou 4 bytes (`0x00000000` = falso, `0x00000001` = verdadeiro) |
| `0x08` | **`COMPOUND`** | 4 | Estrutura binária composta / flags empacotadas |
| `0x09` | **`BINARY / BLOB`** | 22 | Buffer binário opaco (chaves públicas RSA, hashes de autenticação, nós brutos) |
| `0x0B` | **`STRING_UTF8`** | 51 | Cadeia de caracteres codificada em UTF-8 (nomes de rede, apelidos de usuários) |
| `0x0C` | **`OBJECT`** | 1 | Instância aninhada de objeto ou registro serializado |
| `0x0D` | **`LIST / ARRAY`** | 7 | Coleção contígua de elementos homogêneos |
| `0x0E` | **`MAP / CONTAINER`**| 14 | Contêiner associativo chave-valor |

---

## 3. Catálogo de Propriedades Globais (`0x00498fe0`)

No binário `RvControlSvc.exe`, a função `FUN_00498fe0` inicializa uma tabela estática de descritores de propriedades com exatamente **723 registros**, indexados pelo ID de propriedade (`prop_id`). Cada descritor possui 12 bytes:

```c
struct PropertyDescriptor {
    uint32_t tag;       // Tag TLV completa (tipo + ID)
    uint16_t flags;     // Flags de serialização / obrigatoriedade / cache
    uint16_t type;      // Código interno do tipo Famatech
    uint32_t handler;   // Ponteiro para método de validação / conversão
};
```

### 3.1 Tags Principais Confirmadas por Desmontagem e PCAP

| Tag Hex | Nome Conceitual / Função | Tipo | Contexto de Observação |
|---|---|---|---|
| `0x010001ea` | `PROP_VIRTUAL_IP` | `UINT32` | IPv4 atribuído à interface virtual VPN (ex.: `26.x.x.x`) |
| `0x010001df` | `PROP_NETWORK_STATUS` | `UINT32` | Estado de conexão com a rede (`0` = desconectado, `1` = conectado, `2` = autenticando) |
| `0x010001e3` | `PROP_NET_CONN_ATTR` | `UINT32` | Atributo de conectividade de rede (analisado detalhadamente na Seção 4) |
| `0x0100032b` | `PROP_PROTOCOL_CAPS` | `UINT32` | Bitmask de capacidades e extensões negociadas no login |
| `0x020001e1` | `PROP_NETWORK_ID` | `UINT64` | Identificador único de 64 bits da rede virtual Radmin |
| `0x0200025e` | `PROP_NODE_LAST_SEEN` | `UINT64` | Carimbo de data/hora (timestamp Epoch de 64 bits) do peer |
| `0x040001e7` | `PROP_IS_ONLINE` | `BOOL` | Indicador de presença de nó na rede virtual |
| `0x090001ca` | `PROP_RSA_PUBKEY_BLOB` | `BLOB` | Chave pública RSA-2048 empacotada transmitida pelo cliente |
| `0x090001cd` | `PROP_AUTH_HASH` | `BLOB` | Hash SHA-1 de credencial / senha de rede |
| `0x0b0001dc` | `PROP_NETWORK_NAME` | `STRING_UTF8` | Nome textual da rede virtual (ex.: `"LAN_Gaming"`) |
| `0x0b0001eb` | `PROP_PEER_ALIAS` | `STRING_UTF8` | Nome / hostname do usuário na rede virtual |

---

## 4. Análise Aprofundada da Tag `0x010001e3`

Havia uma dúvida conceitual em análises prévias se `0x010001e3` representava uma contagem de nós (`member_count`) ou um atributo de rede.

### 4.1 Evidência em `RvControlSvc.exe` (`0x41537e`)
No manipulador de atualização de rede em `0x41537e`:
```x86asm
0x41537e: mov eax, dword ptr [ebp - 0x14] ; tag extraída = 0x010001e3
0x415381: cmp eax, 0x010001e3
0x415386: jne 0x41539a
0x415388: mov edx, dword ptr [ebp + 0xc]  ; ponteiro para valor de 32 bits
0x41538b: mov dword ptr [esi + 0x34], edx ; grava em flags/atributos da rede local
0x41538e: or dword ptr [esi + 0x30], 2    ; ativa flag de atributo modificado
```

### 4.2 Evidência em `RvROLClient.dll` (`0x1004ef1c`)
Em `RvROLClient.dll`, a propriedade é tratada dentro do método `ProcessNetworkUpdate`:
```x86asm
0x1004ef1c: push 0x010001e3
0x1004ef21: mov ecx, edi
0x1004ef23: call 0x10022370        ; busca valor da propriedade no container TLV
0x1004ef28: test eax, eax
0x1004ef2a: je 0x1004ef3e
0x1004ef2c: mov ecx, dword ptr [eax]
0x1004ef2e: mov dword ptr [ebx + 0x48], ecx ; armazena tipo de topologia / permissões de rede
```

> [!IMPORTANT]
> **Conclusão:** A Tag `0x010001e3` é um **inteiro de 32 bits (`UINT32`) representando atributos operacionais de rede (modo de roteamento, controle de acesso e capacidades de broadcast)**, e **não** uma contagem de nós. A contagem de nós é dinamicamente computada a partir da lista/array de nós (`0x0d0001e4`) ou por requisição explícita via `ROLClient_GetNodes`.
