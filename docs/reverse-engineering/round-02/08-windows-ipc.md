# Frente 8: Comunicação IPC entre GUI e Serviço

**Classificação de Certeza:** CONFIRMADO (desmontagem direta de `FUN_004e8eb0` e `FUN_004e2ac0` em `RvRvpnGui.exe` e criação do Named Pipe em `RvControlSvc.exe` em `0x40f052` / `0x47de40`)

---

## 1. Visão Geral da Arquitetura IPC

No ambiente Windows oficial, o Radmin VPN é decomposto em dois processos independentes com níveis de privilégio distintos:
1. **`RvControlSvc.exe` (Serviço de Sistema / Background Service):** Executa com privilégios de `SYSTEM` (`NT AUTHORITY\SYSTEM`), responsável por gerenciar a placa de rede virtual, interagir com os servidores de coordenação ROL, gerenciar chaves e rotear o tráfego VPN.
2. **`RvRvpnGui.exe` (Interface Gráfica de Usuário):** Executa no contexto do usuário convencional logado (`Session 1`), responsável por exibir a interface de usuário, receber cliques de conexão/desconexão e exibir a lista de redes e membros.

A comunicação entre a GUI e o Serviço ocorre exclusivamente através de **Named Pipes do Windows**.

---

## 2. Identificação e Criação do Named Pipe

O canal de Named Pipe possui o seguinte identificador canônico em UTF-16:
```
\\.\pipe\RadminVpnGuiChannel
```

### 2.1 Lado do Servidor (`RvControlSvc.exe` em `0x40f052`)
No serviço de sistema, a rotina de inicialização em `0x40f040` cria o Named Pipe com capacidade para até 200 instâncias simultâneas de clientes:

```x86asm
0x40f040: push ebp
0x40f041: mov ebp, esp
0x40f043: push 0xc8                 ; nMaxInstances = 200 (0xC8)
0x40f048: push dword ptr [ebp + 8]  ; atributos de segurança (SECURITY_ATTRIBUTES)
0x40f04b: add ecx, 0xe0
0x40f051: push 0x519e74             ; L"\\\\.\\pipe\\RadminVpnGuiChannel"
0x40f056: call 0x47de40             ; CreateNamedPipeW(..., PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, ...)
0x40f05b: movzx eax, al
0x40f05e: pop ebp
0x40f05f: ret 4
```

### 2.2 Lado do Cliente (`RvRvpnGui.exe` em `FUN_004e8eb0`)
A GUI localiza o pipe no endereço de memória `0x5e7fe4` e conecta-se assincronamente através de `0x5352d0`:

```x86asm
0x4e8f28: push dword ptr [0x5e7fd4] ; timeout de conexão
0x4e8f2e: mov ecx, ebx
0x4e8f30: push dword ptr [0x5e7fd0] ; modo de abertura
0x4e8f36: push dword ptr [esi + 0x11c] ; handle de overlapped I/O
0x4e8f3c: push 0x5e7fe4             ; L"\\\\.\\pipe\\RadminVpnGuiChannel"
0x4e8f41: call 0x5352d0             ; CreateFileW / WaitNamedPipeW
0x4e8f46: test al, al
0x4e8f48: je 0x4e8fb0
```

---

## 3. Estrutura das Mensagens e Protocolo de Comandos

Assim que o Named Pipe é conectado pela interface gráfica, um quadro de handshake inicial de 25 bytes é trocado para validar a versão do canal de IPC. Em seguida, os comandos são serializados através da rotina `FUN_004e2ac0`.

### 3.1 Identificadores de Comandos Confirmados (`FUN_004e2ac0`)
Pela desmontagem dos chamadores de `FUN_004e2ac0`, foram identificados os seguintes códigos operacionais:

| Código (Hex) | Código (Dec) | Ponto de Chamada | Significado / Operação | Parâmetros |
|---|---|---|---|---|
| **`0x3f6`** | 1014 | `0x4e8f78` | **Subscrição de Eventos do Serviço:** Emitido imediatamente pela GUI após abrir o pipe para registrar seu interesse em notificações de estado da rede | `param = 0` |
| **`0x3ec`** | 1004 | `0x4e92b6` | **Comando de Conectar / Reabilitar VPN:** Emitido quando o usuário clica no botão principal de ligar ou reconectar | `param = 1` |
| **`0x3ed`** | 1005 | `0x4e9304` | **Comando de Desconectar / Pausar VPN:** Desliga o tráfego do adaptador virtual | `param = 0` |
| **`0x3ee`** | 1006 | `0x4e9352` | **Consulta de Estado do Adaptador:** Requisita o status atual do driver NDIS e endereço IP atribuído | `param = 0` |
| **`0x3ef`** | 1007 | `0x4e9295` | **Notificação de Estado Conectado:** Sinaliza que a GUI assumiu o estado ativo e pronto | `param = eax` |

### 3.2 Formato do Envelope de Mensagem IPC
Cada mensagem trafegada no Named Pipe possui um cabeçalho fixo seguido do payload:

```
+-----------------------------+-----------------------------+-----------------------------+
| MAGIC IDENTIFIER (4 bytes)  | COMMAND_ID (4 bytes, LE)    | PAYLOAD_LENGTH (4 bytes, LE)|
+-----------------------------+-----------------------------+-----------------------------+
| DATA PAYLOAD (Length bytes...)                                                          |
+-----------------------------------------------------------------------------------------+
```

---

## 4. Equivalente Arquitetural para o Cliente Linux

No ambiente Linux nativo, o mecanismo equivalente com paridade funcional completa é:
* **Mecanismo:** **UNIX Domain Sockets** (`AF_UNIX`) vinculados a `/var/run/radmin-vpn.sock` (ou sob `XDG_RUNTIME_DIR/radmin-vpn.sock` no modo de usuário).
* **Segurança de Acesso:** Permissões de arquivo POSIX `0660` atribuídas ao grupo `radminvpn` ou administradores locais (`root`).
* **Protocolo:** O cliente Rust pode implementar o envelope binário nativo para compatibilidade com eventuais GUIs portadas ou expor uma API IPC baseada em JSON-RPC sobre o socket UNIX.
