//! Ponto de entrada do cliente Radmin VPN para Linux.

use clap::Parser;
use radmin_vpn::cli::{run, Cli};
use radmin_vpn::info;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Inicializa logging
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    info!("Iniciando Radmin VPN Linux v{}", radmin_vpn::VERSION);

    let cli = Cli::parse();
    run(cli).await?;

    Ok(())
}
