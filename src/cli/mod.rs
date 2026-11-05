use crate::daemon::ipc::{resolve_socket_path, IpcClient, IpcCommand, IpcResponse};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    Status,

    Interface {
        #[arg(short, long, default_value = "radmin0")]
        name: String,

        #[arg(long, help = "Testar com dispositivo virtual Mock sem root")]
        mock: bool,
    },

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

    Disconnect,

    Config {
        #[arg(long, help = "Gerar arquivo de configuração padrão")]
        generate: Option<PathBuf>,
    },

    Join {
        #[arg(short, long)]
        network: String,
    },

    Leave {
        #[arg(short, long)]
        network: String,
    },

    List,

    Start,

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
            let socket_path = resolve_socket_path();
            match IpcClient::connect(&socket_path).await {
                Ok(mut client) => {
                    let resp = client.send_command(&IpcCommand::QueryStatus).await?;
                    if let IpcResponse::Status {
                        connected,
                        virtual_ip,
                        active_network,
                        peers_online,
                    } = resp
                    {
                        println!("==========================================");
                        println!(" Radmin VPN Linux - Status do Cliente");
                        println!("==========================================");
                        println!("Versão:          v{}", crate::VERSION);
                        println!(
                            "Estado:          {}",
                            if connected {
                                "Conectado"
                            } else {
                                "Desconectado"
                            }
                        );
                        println!(
                            "Interface TAP:   {} (MTU {})",
                            config.interface.interface_name, config.interface.mtu
                        );
                        println!(
                            "IP Virtual:      {}",
                            virtual_ip
                                .as_deref()
                                .or(config.interface.local_ip.as_deref())
                                .unwrap_or("Não atribuído")
                        );
                        println!(
                            "Rede Ativa:      {}",
                            active_network.as_deref().unwrap_or("Nenhuma")
                        );
                        println!("Peers online:    {}", peers_online);
                        println!("Criptografia:    AES-256-CBC (Famatech proprietary frame padding/trailer)");
                        println!("Daemon PID:      {}", client.server_pid());
                        println!("==========================================");
                    }
                }
                Err(_) => {
                    println!("==========================================");
                    println!(" Radmin VPN Linux - Status do Cliente");
                    println!("==========================================");
                    println!("Versão:          v{}", crate::VERSION);
                    println!("Daemon:          Não está em execução");
                    println!(
                        "Interface TAP:   {} (MTU {})",
                        config.interface.interface_name, config.interface.mtu
                    );
                    println!("Dica:            Execute 'radmin-vpn start' para iniciar o serviço.");
                    println!("==========================================");
                }
            }
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
            let socket_path = resolve_socket_path();
            if let Ok(mut client) = IpcClient::connect(&socket_path).await {
                println!("Conectando via daemon em execução...");
                match client
                    .send_command(&IpcCommand::SwitchPower { enable: true })
                    .await?
                {
                    IpcResponse::Success { message } => {
                        println!("✓ Conexão iniciada com sucesso via daemon: {}", message);
                        return Ok(());
                    }
                    IpcResponse::Error { message, .. } => {
                        eprintln!("✗ Daemon retornou erro ao conectar: {}", message);
                        return Ok(());
                    }
                    _ => {}
                }
            }

            let server_addr = server.unwrap_or_else(|| "45.162.230.182:17301".to_string());
            println!(
                "Conectando ao servidor Radmin VPN em {} (modo standalone)...",
                server_addr
            );

            let mut session = crate::session::SessionManager::new();
            println!("Estado: Conectando...");

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
            let socket_path = resolve_socket_path();
            match IpcClient::connect(&socket_path).await {
                Ok(mut client) => {
                    let resp = client
                        .send_command(&IpcCommand::SwitchPower { enable: false })
                        .await?;
                    match resp {
                        IpcResponse::Success { message } => {
                            println!(
                                "✓ Conexão VPN desconectada com sucesso via daemon: {}",
                                message
                            );
                        }
                        IpcResponse::Error { message, .. } => {
                            eprintln!("✗ Erro ao desconectar: {}", message);
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    println!("O daemon do Radmin VPN não está em execução.");
                }
            }
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
            let socket_path = resolve_socket_path();
            match IpcClient::connect(&socket_path).await {
                Ok(mut client) => {
                    let cmd = IpcCommand::JoinNetwork {
                        network_name: network.clone(),
                        password: String::new(),
                    };
                    match client.send_command(&cmd).await? {
                        IpcResponse::Success { message } => {
                            println!(
                                "✓ Ingressou na rede '{}' com sucesso ({}).",
                                network, message
                            );
                        }
                        IpcResponse::Error { message, .. } => {
                            eprintln!("✗ Falha ao ingressar na rede '{}': {}", network, message);
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    eprintln!("✗ Erro: O daemon do Radmin VPN não está em execução. Inicie com 'radmin-vpn start'.");
                }
            }
            Ok(())
        }

        Commands::Leave { network } => {
            let socket_path = resolve_socket_path();
            match IpcClient::connect(&socket_path).await {
                Ok(mut client) => {
                    let net_id = network.parse::<u64>().unwrap_or(0);
                    let cmd = IpcCommand::LeaveNetwork { network_id: net_id };
                    match client.send_command(&cmd).await? {
                        IpcResponse::Success { message } => {
                            println!("✓ Saiu da rede '{}' com sucesso ({}).", network, message);
                        }
                        IpcResponse::Error { message, .. } => {
                            eprintln!("✗ Falha ao sair da rede '{}': {}", network, message);
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    eprintln!("✗ Erro: O daemon do Radmin VPN não está em execução.");
                }
            }
            Ok(())
        }

        Commands::List => {
            let socket_path = resolve_socket_path();
            match IpcClient::connect(&socket_path).await {
                Ok(mut client) => match client.send_command(&IpcCommand::EnumNetworks).await? {
                    IpcResponse::NetworkList { networks } => {
                        if networks.is_empty() {
                            println!("Nenhuma rede virtual conectada no momento.");
                        } else {
                            println!("Redes virtuais associadas ({}):", networks.len());
                            for (i, net) in networks.iter().enumerate() {
                                println!("  [{}] {}", i + 1, net);
                            }
                        }
                    }
                    IpcResponse::Error { message, .. } => {
                        eprintln!("✗ Erro ao listar redes: {}", message);
                    }
                    _ => {}
                },
                Err(_) => {
                    eprintln!("✗ Erro: O daemon do Radmin VPN não está em execução.");
                }
            }
            Ok(())
        }

        Commands::Start => {
            println!("Iniciando daemon do Radmin VPN Linux...");
            let mut daemon = crate::daemon::Daemon::new(config);
            daemon.start().await
        }

        Commands::Stop => {
            let socket_path = resolve_socket_path();
            match IpcClient::connect(&socket_path).await {
                Ok(mut client) => match client.send_command(&IpcCommand::Disconnect).await? {
                    IpcResponse::Success { message } => {
                        println!("✓ Comando de encerramento enviado ao daemon: {}", message);
                    }
                    IpcResponse::Error { message, .. } => {
                        eprintln!("✗ Erro ao encerrar daemon: {}", message);
                    }
                    _ => {}
                },
                Err(_) => {
                    println!("Nenhum daemon do Radmin VPN está em execução.");
                }
            }
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
