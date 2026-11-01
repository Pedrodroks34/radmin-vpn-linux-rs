//! # Módulo `cli` — Interface de linha de comando
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - GUI Windows: `RvRvpnGui.exe` (Qt 5.15/QML) com widgets `node_widget`,
//!   `networkwidget`, `StatusIndicator`, `UnsupportedRegionBar`, `ReportReason`.
//! - Status visuais: `node_applicant.svg`, `node_connecting.svg`,
//!   `ping_disconnected.svg`, `disconnected.svg`.
//! - Comandos de rede inferidos: join, leave, create, delete, enable, update.
//!
//! **Mapeamento Linux:**
//! - CLI substitui a GUI Qt.
//! - Comunica com o daemon via socket Unix (`/run/radmin-vpn/gui.sock`).

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "radmin-vpn", about = "Cliente Radmin VPN para Linux")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Entrar em uma rede virtual
    Join {
        #[arg(short, long)]
        network: String,
    },
    /// Sair de uma rede virtual
    Leave {
        #[arg(short, long)]
        network: String,
    },
    /// Listar redes e peers
    List,
    /// Mostrar status da conexão
    Status,
    /// Iniciar o daemon
    Start,
    /// Parar o daemon
    Stop,
    /// Configurar o cliente
    Config,
}

pub async fn run(cli: Cli) -> crate::Result<()> {
    match cli.command {
        Commands::Join { network } => {
            println!("Juntando-se à rede: {}", network);
            Err(anyhow::anyhow!("Join não implementado (aguardando protocolo)"))
        }
        Commands::Leave { network } => {
            println!("Saindo da rede: {}", network);
            Err(anyhow::anyhow!("Leave não implementado"))
        }
        Commands::List => {
            println!("Listando redes...");
            Err(anyhow::anyhow!("List não implementado"))
        }
        Commands::Status => {
            println!("Status: desconectado");
            Ok(())
        }
        Commands::Start => {
            println!("Iniciando daemon...");
            Err(anyhow::anyhow!("Start não implementado"))
        }
        Commands::Stop => {
            println!("Parando daemon...");
            Ok(())
        }
        Commands::Config => {
            println!("Configuração...");
            Ok(())
        }
    }
}
