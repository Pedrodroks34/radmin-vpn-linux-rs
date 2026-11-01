//! # Radmin VPN — Cliente Linux Nativo (Rust)
//!
//! Implementação independente do cliente Radmin VPN para Linux,
//! interoperável com a infraestrutura oficial do Radmin VPN (Famatech Corp.).
//!
//! ## Base da engenharia reversa
//!
//! Esta implementação se baseia na análise estática do instalador
//! `Radmin_VPN_2.1.4951.1.exe` (Inno Setup + MSI) e seus componentes:
//! `RvControlSvc.exe`, `RvROLClient.dll`, `RvUESClient.dll`,
//! `RvDownloader.dll`, `NetMP60.sys`, etc.
//!
//! ## Mapeamento de componentes (Windows → Linux)
//
//! | Componente Windows | Papel identificado | Módulo Linux (este crate) |
//! |---|---|---|
//! | `RvControlSvc.exe` | Serviço Windows, motor FamRT/C++ (IOCP), IPC via pipe | `daemon` + `session` + `transport` |
//! | `RvRvpnGui.exe` | GUI Qt 5.15 / QML | `cli` (futuro TUI) |
//! | `RvROLClient.dll` | Protocolo ROS, canais, NAT, redes (47 exports) | `protocol` + `discovery` + `peer` + `nat` |
//! | `RvUESClient.dll` | Detecção de tipo de NAT | `nat` |
//! | `RvDownloader.dll` / `RvRolUpdater.dll` | Atualização | (fora do escopo inicial) |
//! | `NetMP60.sys` | Driver NDIS virtual (L2/Ethernet) | `tunnel` + `network` (TUN/TAP Linux) |
//! | `imrsdk.dll` | SDK legado de acesso remoto | (não reutilizado) |
//!
//! ## Avisos importantes
//!
//! - **Não usar ZeroTier, Tailscale, Hamachi ou qualquer outra VPN como base.**
//! - **Não implementar criptografia própria.** Usar `ring` / `rustls`.
//! - **Não presumir endpoints ou pacotes.** Os detalhes do protocolo binário
//!   (handshake, estrutura de pacotes, algoritmos, portas) requerem análise
//!   dinâmica e decompilação antes de serem implementados.
//!
//! Cada módulo abaixo documenta o que foi **confirmado**, o que é
//! **fortemente provável** e o que permanece **desconhecido**.

pub mod authentication;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod daemon;
pub mod discovery;
pub mod identity;
pub mod nat;
pub mod network;
pub mod peer;
pub mod protocol;
pub mod relay;
pub mod routing;
pub mod session;
pub mod transport;
pub mod tunnel;

pub use anyhow::Result;
pub use tracing::{error, info, warn, debug};

/// Versão do cliente (espelha o FileVersion do instalador: 2.1.4951.1)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Nome do serviço/daemon (equivalente ao Registro `HKLM\SOFTWARE\Famatech\RadminVPN\1.0`)
pub const SERVICE_NAME: &str = "radmin-vpn";

/// Pipe nomeado usado pelo Windows entre GUI e serviço
/// `\\.\pipe\RadminVpnGuiChannel` — no Linux usamos socket Unix ou canal interno
pub const GUI_CHANNEL_PATH: &str = "/run/radmin-vpn/gui.sock";
