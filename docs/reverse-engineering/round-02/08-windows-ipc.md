# Front 8: IPC Communication Between the GUI and the Service

**Certainty classification:** CONFIRMED (direct disassembly of `FUN_004e8eb0` and `FUN_004e2ac0` in `RvRvpnGui.exe`, and creation of the Named Pipe in `RvControlSvc.exe` at `0x40f052` / `0x47de40`)

---

## 1. Overview of the IPC Architecture

In the official Windows environment, Radmin VPN is split into two independent processes with different privilege levels:
1. **`RvControlSvc.exe` (System service / background service):** Runs with `SYSTEM` privileges (`NT AUTHORITY\SYSTEM`). It manages the virtual network adapter, interacts with the ROL coordination servers, manages keys and routes VPN traffic.
2. **`RvRvpnGui.exe` (graphical user interface):** Runs in the context of the logged-in user (`Session 1`). It displays the user interface, receives connect/disconnect clicks, and shows the list of networks and members.

Communication between the GUI and the service happens exclusively through **Windows Named Pipes**.

---

## 2. Identification and Creation of the Named Pipe

The Named Pipe channel has the following canonical identifier in UTF-16:
```
\\.\pipe\RadminVpnGuiChannel
```

### 2.1 Server Side (`RvControlSvc.exe` at `0x40f052`)
In the system service, the initialization routine at `0x40f040` creates the Named Pipe with capacity for up to 200 simultaneous client instances:

```x86asm
0x40f040: push ebp
0x40f041: mov ebp, esp
0x40f043: push 0xc8                 ; nMaxInstances = 200 (0xC8)
0x40f048: push dword ptr [ebp + 8]  ; security attributes (SECURITY_ATTRIBUTES)
0x40f04b: add ecx, 0xe0
0x40f051: push 0x519e74             ; L"\\\\.\\pipe\\RadminVpnGuiChannel"
0x40f056: call 0x47de40             ; CreateNamedPipeW(..., PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, ...)
0x40f05b: movzx eax, al
0x40f05e: pop ebp
0x40f05f: ret 4
```

### 2.2 Client Side (`RvRvpnGui.exe` in `FUN_004e8eb0`)
The GUI locates the pipe at the memory address `0x5e7fe4` and connects asynchronously through `0x5352d0`:

```x86asm
0x4e8f28: push dword ptr [0x5e7fd4] ; connection timeout
0x4e8f2e: mov ecx, ebx
0x4e8f30: push dword ptr [0x5e7fd0] ; open mode
0x4e8f36: push dword ptr [esi + 0x11c] ; overlapped I/O handle
0x4e8f3c: push 0x5e7fe4             ; L"\\\\.\\pipe\\RadminVpnGuiChannel"
0x4e8f41: call 0x5352d0             ; CreateFileW / WaitNamedPipeW
0x4e8f46: test al, al
0x4e8f48: je 0x4e8fb0
```

---

## 3. Message Structure and Command Protocol

As soon as the GUI connects to the Named Pipe, an initial 25-byte handshake frame is exchanged to validate the IPC channel version. The commands are then serialized through the routine `FUN_004e2ac0`.

### 3.1 Confirmed Command Identifiers (`FUN_004e2ac0`)
From the disassembly of the callers of `FUN_004e2ac0`, the following operation codes were identified:

| Code (Hex) | Code (Dec) | Call Site | Meaning / Operation | Parameters |
|---|---|---|---|---|
| **`0x3f6`** | 1014 | `0x4e8f78` | **Service event subscription:** Sent immediately by the GUI after opening the pipe to register its interest in network state notifications | `param = 0` |
| **`0x3ec`** | 1004 | `0x4e92b6` | **Connect / re-enable VPN command:** Sent when the user clicks the main connect or reconnect button | `param = 1` |
| **`0x3ed`** | 1005 | `0x4e9304` | **Disconnect / pause VPN command:** Turns off traffic on the virtual adapter | `param = 0` |
| **`0x3ee`** | 1006 | `0x4e9352` | **Adapter status query:** Requests the current status of the NDIS driver and the assigned IP address | `param = 0` |
| **`0x3ef`** | 1007 | `0x4e9295` | **Connected-state notification:** Signals that the GUI has assumed the active, ready state | `param = eax` |

### 3.2 IPC Message Envelope Format
Each message sent over the Named Pipe has a fixed header followed by the payload:

```
+-----------------------------+-----------------------------+-----------------------------+
| MAGIC IDENTIFIER (4 bytes)  | COMMAND_ID (4 bytes, LE)    | PAYLOAD_LENGTH (4 bytes, LE)|
+-----------------------------+-----------------------------+-----------------------------+
| DATA PAYLOAD (Length bytes...)                                                          |
+-----------------------------------------------------------------------------------------+
```

---

## 4. Architectural Equivalent for the Linux Client

On native Linux, the equivalent mechanism with full functional parity is:
* **Mechanism:** **UNIX Domain Sockets** (`AF_UNIX`) bound to `/var/run/radmin-vpn.sock` (or under `XDG_RUNTIME_DIR/radmin-vpn.sock` in user mode).
* **Access security:** POSIX file permissions `0660`, assigned to the `radminvpn` group or to local administrators (`root`).
* **Protocol:** The Rust client can implement the native binary envelope for compatibility with any ported GUI, or expose an IPC API based on JSON-RPC over the UNIX socket.
