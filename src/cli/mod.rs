use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "radmin-vpn", about = "Cliente Radmin VPN para Linux")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {

    Join {
        #[arg(short, long)]
        network: String,
    },

    Leave {
        #[arg(short, long)]
        network: String,
    },

    List,

    Status,

    Start,

    Stop,

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
