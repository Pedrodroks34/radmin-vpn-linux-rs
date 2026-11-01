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
pub use tracing::{debug, error, info, warn};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const SERVICE_NAME: &str = "radmin-vpn";

pub const GUI_CHANNEL_PATH: &str = "/run/radmin-vpn/gui.sock";
