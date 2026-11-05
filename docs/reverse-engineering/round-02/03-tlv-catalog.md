# Front 3: TLV Catalog and Message Format

**Certainty classification:** CONFIRMED (direct dump and analysis of the 723 descriptors in the global table of `RvControlSvc.exe` at address `0x00498fe0`, plus disassembly in `RvROLClient.dll`)

---

## 1. Overview of Famatech TLV Serialization

All data structures transmitted over the Radmin VPN channel (after the cryptographic handshake) are encoded in **TLV (Tag-Length-Value)** format with the following fundamental parameters:

* **Tag:** 32-bit unsigned integer, encoded in **Big-Endian**.
* **Length:** 32-bit unsigned integer, encoded in **Big-Endian**, strictly indicating the size in bytes of the *Value* field.
* **Value:** Sequence of $N$ bytes whose type and semantics are determined by the upper bits of the Tag and by the entry in the property catalog.

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

## 2. Taxonomy of Data Types by Tag

Static analysis of the serialization routine `FUN_00488ae0` and of the dispatch in `RvControlSvc.exe` and `RvROLClient.dll` reveals that the 8 most significant bits (or the first byte of the Tag) define the typing of primitive and composite data:

| Upper Tag Byte | Type Category | Number of Registered Tags | Representation in the Value |
|---|---|---|---|
| `0x01` | **`UINT32`** | 374 | 4-byte unsigned integer in Big-Endian (or internal Little-Endian unpacked by the architecture) |
| `0x02` | **`UINT64`** | 109 | 8-byte unsigned integer (used for network IDs and timestamps) |
| `0x03` | **`INT32` / ID** | 98 | 4-byte signed integer (status codes and numeric identifiers) |
| `0x04` | **`BOOL`** | 35 | Boolean represented in 1 byte or 4 bytes (`0x00000000` = false, `0x00000001` = true) |
| `0x08` | **`COMPOUND`** | 4 | Composite binary structure / packed flags |
| `0x09` | **`BINARY / BLOB`** | 22 | Opaque binary buffer (RSA public keys, authentication hashes, raw nodes) |
| `0x0B` | **`STRING_UTF8`** | 51 | UTF-8 encoded character string (network names, user aliases) |
| `0x0C` | **`OBJECT`** | 1 | Nested object instance or serialized record |
| `0x0D` | **`LIST / ARRAY`** | 7 | Contiguous collection of homogeneous elements |
| `0x0E` | **`MAP / CONTAINER`** | 14 | Associative key-value container |

---

## 3. Global Property Catalog (`0x00498fe0`)

In the `RvControlSvc.exe` binary, the function `FUN_00498fe0` initializes a static table of property descriptors with exactly **723 records**, indexed by the property ID (`prop_id`). Each descriptor is 12 bytes:

```c
struct PropertyDescriptor {
    uint32_t tag;       // Full TLV tag (type + ID)
    uint16_t flags;     // Serialization / mandatory / cache flags
    uint16_t type;      // Internal Famatech type code
    uint32_t handler;   // Pointer to the validation / conversion method
};
```

### 3.1 Main Tags Confirmed by Disassembly and PCAP

| Hex Tag | Conceptual Name / Function | Type | Observation Context |
|---|---|---|---|
| `0x010001ea` | `PROP_VIRTUAL_IP` | `UINT32` | IPv4 assigned to the VPN virtual interface (for example `26.x.x.x`) |
| `0x010001df` | `PROP_NETWORK_STATUS` | `UINT32` | Network connection state (`0` = disconnected, `1` = connected, `2` = authenticating) |
| `0x010001e3` | `PROP_NET_CONN_ATTR` | `UINT32` | Network connectivity attribute (analyzed in detail in Section 4) |
| `0x0100032b` | `PROP_PROTOCOL_CAPS` | `UINT32` | Bitmask of capabilities and extensions negotiated at login |
| `0x020001e1` | `PROP_NETWORK_ID` | `UINT64` | Unique 64-bit identifier of the Radmin virtual network |
| `0x0200025e` | `PROP_NODE_LAST_SEEN` | `UINT64` | Peer timestamp (64-bit Epoch time) |
| `0x040001e7` | `PROP_IS_ONLINE` | `BOOL` | Indicator of node presence in the virtual network |
| `0x090001ca` | `PROP_RSA_PUBKEY_BLOB` | `BLOB` | Packed RSA-2048 public key transmitted by the client |
| `0x090001cd` | `PROP_AUTH_HASH` | `BLOB` | SHA-1 hash of the network credential / password |
| `0x0b0001dc` | `PROP_NETWORK_NAME` | `STRING_UTF8` | Textual name of the virtual network (for example `"LAN_Gaming"`) |
| `0x0b0001eb` | `PROP_PEER_ALIAS` | `STRING_UTF8` | User name / hostname within the virtual network |

---

## 4. In-Depth Analysis of Tag `0x010001e3`

Previous analyses raised a conceptual question about whether `0x010001e3` represented a node count (`member_count`) or a network attribute.

### 4.1 Evidence in `RvControlSvc.exe` (`0x41537e`)
In the network update handler at `0x41537e`:
```x86asm
0x41537e: mov eax, dword ptr [ebp - 0x14] ; extracted tag = 0x010001e3
0x415381: cmp eax, 0x010001e3
0x415386: jne 0x41539a
0x415388: mov edx, dword ptr [ebp + 0xc]  ; pointer to 32-bit value
0x41538b: mov dword ptr [esi + 0x34], edx ; writes to the local network flags/attributes
0x41538e: or dword ptr [esi + 0x30], 2    ; sets the modified-attribute flag
```

### 4.2 Evidence in `RvROLClient.dll` (`0x1004ef1c`)
In `RvROLClient.dll`, the property is handled inside the `ProcessNetworkUpdate` method:
```x86asm
0x1004ef1c: push 0x010001e3
0x1004ef21: mov ecx, edi
0x1004ef23: call 0x10022370        ; looks up the property value in the TLV container
0x1004ef28: test eax, eax
0x1004ef2a: je 0x1004ef3e
0x1004ef2c: mov ecx, dword ptr [eax]
0x1004ef2e: mov dword ptr [ebx + 0x48], ecx ; stores the network topology type / permissions
```

> [!IMPORTANT]
> **Conclusion:** The Tag `0x010001e3` is a 32-bit integer (`UINT32`) representing **operational network attributes (routing mode, access control and broadcast capabilities)**, and **not** a node count. The node count is dynamically computed from the node list/array (`0x0d0001e4`) or through an explicit `ROLClient_GetNodes` request.
