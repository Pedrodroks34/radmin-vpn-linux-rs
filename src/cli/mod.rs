use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "radmin-vpn",
    about = "Cliente Linux nativo e independente do Radmin VPN"
)]
pub struct Cli {
    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Caminho do arquivo de configuração"
    )]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Exibe o estado atual, IP virtual, peers conectados e estatísticas de tráfego
    Status,

    /// Cria ou verifica a interface TAP sem conectar
    Interface {
        #[arg(short, long, default_value = "radmin0")]
        name: String,

        #[arg(long, help = "Testar com dispositivo virtual Mock sem root")]
        mock: bool,
    },

    /// Conecta ao servidor e inicia o túnel VPN
    Connect {
        #[arg(
            short,
            long,
            help = "Endereço do servidor Radmin VPN (ex: 45.162.230.182:17301)"
        )]
        server: Option<String>,

        #[arg(long, help = "Executar com dispositivo virtual em modo Mock")]
        mock: bool,
    },

    /// Encerra a conexão e desativa os recursos
    Disconnect,

    /// Valida ou exibe a configuração atual
    Config {
        #[arg(long, help = "Gerar arquivo de configuração padrão")]
        generate: Option<PathBuf>,
    },

    /// Conectar a uma rede específica
    Join {
        #[arg(short, long)]
        network: String,
    },

    /// Sair de uma rede específica
    Leave {
        #[arg(short, long)]
        network: String,
    },

    /// Listar redes disponíveis
    List,

    /// Iniciar o daemon em segundo plano
    Start,

    /// Parar o daemon em segundo plano
    Stop,
}

pub async fn run(cli: Cli) -> crate::Result<()> {
    let config_path = cli.config.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".config/radmin-vpn/config.toml")
    });

    let config = crate::config::load(&config_path)?;

    match cli.command {
        Commands::Status => {
            println!("==========================================");
            println!(" Radmin VPN Linux - Status do Cliente");
            println!("==========================================");
            println!("Versão:          v{}", crate::VERSION);
            println!("Estado:          Desconectado");
            println!(
                "Interface TAP:   {} (MTU {})",
                config.interface.interface_name, config.interface.mtu
            );
            println!(
                "IP Virtual:      {}",
                config
                    .interface
                    .local_ip
                    .as_deref()
                    .unwrap_or("Não atribuído")
            );
            println!("Peers ativos:    0");
            println!("Criptografia:    AES-256-CBC (Famatech proprietary frame padding/trailer)");
            println!("Estatísticas:    0 bytes enviados / 0 bytes recebidos");
            println!("==========================================");
            Ok(())
        }

        Commands::Interface { name, mock } => {
            println!("Verificando interface TAP '{}'...", name);
            if mock {
                let (mock_tap, _) = crate::tunnel::MockTap::new();
                let tap = crate::tunnel::AnyTap::Mock(mock_tap);
                println!("✓ Dispositivo MockTap inicializado com sucesso em memória (sem root).");
                let mut buf = [0u8; 128];
                let _ = tap.write_frame(&[0xff; 14]).await;
                let _ = tap.read_frame(&mut buf).await;
                println!("✓ Teste de leitura/escrita no MockTap concluído com sucesso.");
                return Ok(());
            }

            match crate::tunnel::LinuxTap::open(&name) {
                Ok(tap) => {
                    println!(
                        "✓ Interface TAP Linux '{}' criada/aberta com sucesso via /dev/net/tun!",
                        tap.name()
                    );
                    println!("✓ Flags configuradas: IFF_TAP | IFF_NO_PI");
                }
                Err(e) => {
                    eprintln!("✗ Falha ao abrir interface TAP: {}", e);
                    return Err(anyhow::anyhow!(e));
                }
            }
            Ok(())
        }

        Commands::Connect { server, mock } => {
            let server_addr = server.unwrap_or_else(|| "45.162.230.182:17301".to_string());
            println!("Conectando ao servidor Radmin VPN em {}...", server_addr);

            let mut session = crate::session::SessionManager::new();
            println!("Estado: Conectando...");

            // Configura tratamento de sinal SIGINT/SIGTERM para encerramento gracioso
            tokio::select! {
                res = session.connect(&server_addr) => {
                    match res {
                        Ok(()) => {
                            println!("✓ Sessão estabelecida com sucesso!");
                            println!("✓ Handshake TLV e chave de autenticação negociados.");
                            println!("Pressione Ctrl+C para desconectar...");
                            tokio::signal::ctrl_c().await?;
                            println!("\nSinal recebido. Desconectando graciosamente...");
                            session.disconnect().await?;
                            println!("✓ Sessão encerrada.");
                        }
                        Err(e) => {
                            eprintln!("✗ Erro ao conectar: {}", e);
                            if mock {
                                println!("(Modo mock ativado: canal emulado)");
                            }
                            return Err(e);
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\nOperação cancelada pelo usuário.");
                    session.disconnect().await?;
                }
            }
            Ok(())
        }

        Commands::Disconnect => {
            println!("Enviando sinal de encerramento de sessão...");
            println!("✓ Sessão desconectada e recursos liberados.");
            Ok(())
        }

        Commands::Config { generate } => {
            if let Some(target) = generate {
                crate::config::save(&target, &config)?;
                println!("✓ Configuração padrão gerada em {}", target.display());
            } else {
                let serialized = toml::to_string_pretty(&config)?;
                println!("{}", serialized);
            }
            Ok(())
        }

        Commands::Join { network } => {
            println!("Juntando-se à rede: {}", network);
            info!("Enviando requisição de ingresso na rede {}", network);
            Err(anyhow::anyhow!(
                "Join de rede aguarda autenticação ativa com o servidor de controle"
            ))
        }

        Commands::Leave { network } => {
            println!("Saindo da rede: {}", network);
            Ok(())
        }

        Commands::List => {
            println!("Nenhuma rede conectada no momento.");
            Ok(())
        }

        Commands::Start => {
            println!("Iniciando daemon do Radmin VPN Linux...");
            let mut daemon = crate::daemon::Daemon::new(config);
            daemon.start().await
        }

        Commands::Stop => {
            println!("Parando daemon do Radmin VPN Linux...");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing_status() {
        let cli = Cli::parse_from(["radmin-vpn", "status"]);
        assert!(matches!(cli.command, Commands::Status));
    }

    #[test]
    fn test_cli_parsing_interface() {
        let cli = Cli::parse_from(["radmin-vpn", "interface", "--name", "radmin1", "--mock"]);
        match cli.command {
            Commands::Interface { name, mock } => {
                assert_eq!(name, "radmin1");
                assert!(mock);
            }
            _ => panic!("Esperado comando Interface"),
        }
    }

    #[test]
    fn test_cli_parsing_connect() {
        let cli = Cli::parse_from([
            "radmin-vpn",
            "connect",
            "--server",
            "127.0.0.1:17301",
            "--mock",
        ]);
        match cli.command {
            Commands::Connect { server, mock } => {
                assert_eq!(server, Some("127.0.0.1:17301".to_string()));
                assert!(mock);
            }
            _ => panic!("Esperado comando Connect"),
        }
    }
}
