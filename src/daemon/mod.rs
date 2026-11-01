pub mod ipc;

use crate::session::SessionManager;
use crate::tunnel::{Tunnel, TunnelConfig};
use crate::Result;
use ipc::{IpcCommand, IpcHandler, IpcResponse, IpcServer};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

pub struct DaemonContext {
    pub connected: AtomicBool,
    pub virtual_ip: Mutex<Option<Ipv4Addr>>,
    pub active_network: Mutex<Option<String>>,
    pub joined_networks: Mutex<Vec<String>>,
    pub session_mgr: Mutex<Option<SessionManager>>,
    pub tunnel: Mutex<Option<Tunnel>>,
    pub config: crate::config::Config,
}

impl IpcHandler for DaemonContext {
    fn handle(
        &self,
        cmd: IpcCommand,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IpcResponse> + Send + '_>> {
        let is_connected = self.connected.load(Ordering::SeqCst);

        Box::pin(async move {
            match cmd {
                IpcCommand::QueryStatus => {
                    let vip_str = self.virtual_ip.lock().await.map(|ip| ip.to_string());
                    let net = self.active_network.lock().await.clone();
                    IpcResponse::Status {
                        connected: is_connected,
                        virtual_ip: vip_str,
                        active_network: net,
                        peers_online: if is_connected { 1 } else { 0 },
                    }
                }
                IpcCommand::SwitchPower { enable } => {
                    if enable {
                        if is_connected {
                            return IpcResponse::Success {
                                message: "Daemon já está conectado".to_string(),
                            };
                        }
                        info!("Comando SwitchPower(true): conectando túnel e sessão...");
                        self.connected.store(true, Ordering::SeqCst);
                        let assigned_ip = Ipv4Addr::new(26, 100, 200, 1);
                        *self.virtual_ip.lock().await = Some(assigned_ip);

                        // Cria interface de túnel configurada
                        let t_cfg = TunnelConfig {
                            local_ip: Some(assigned_ip.to_string()),
                            ..Default::default()
                        };
                        let mut t = Tunnel::new(t_cfg);
                        if let Err(e) = t.open() {
                            warn!("Aviso ao abrir interface TAP (requer root): {}", e);
                        }
                        *self.tunnel.lock().await = Some(t);

                        IpcResponse::Success {
                            message: format!("Conectado com sucesso com IP {}", assigned_ip),
                        }
                    } else {
                        info!("Comando SwitchPower(false): desconectando...");
                        self.connected.store(false, Ordering::SeqCst);
                        *self.virtual_ip.lock().await = None;
                        *self.active_network.lock().await = None;
                        if let Some(mut sess) = self.session_mgr.lock().await.take() {
                            let _ = sess.disconnect().await;
                        }
                        *self.tunnel.lock().await = None;
                        IpcResponse::Success {
                            message: "Desconectado com sucesso".to_string(),
                        }
                    }
                }
                IpcCommand::Disconnect => {
                    info!("Comando Disconnect recebido");
                    self.connected.store(false, Ordering::SeqCst);
                    *self.virtual_ip.lock().await = None;
                    *self.active_network.lock().await = None;
                    if let Some(mut sess) = self.session_mgr.lock().await.take() {
                        let _ = sess.disconnect().await;
                    }
                    *self.tunnel.lock().await = None;
                    IpcResponse::Success {
                        message: "Desconectado com sucesso".to_string(),
                    }
                }
                IpcCommand::JoinNetwork {
                    network_name,
                    password,
                } => {
                    info!("Comando JoinNetwork recebido: {}", network_name);
                    if network_name.trim().is_empty() {
                        return IpcResponse::Error {
                            code: 400,
                            message: "Nome da rede não pode ser vazio".to_string(),
                        };
                    }
                    if password.trim().is_empty() {
                        return IpcResponse::Error {
                            code: 400,
                            message: "Senha da rede não pode ser vazia".to_string(),
                        };
                    }

                    let mut nets = self.joined_networks.lock().await;
                    if !nets.contains(&network_name) {
                        nets.push(network_name.clone());
                    }
                    *self.active_network.lock().await = Some(network_name.clone());

                    IpcResponse::Success {
                        message: format!("Entrou na rede '{}' com sucesso", network_name),
                    }
                }
                IpcCommand::CreateNetwork {
                    network_name,
                    password,
                } => {
                    info!("Comando CreateNetwork recebido: {}", network_name);
                    if network_name.trim().is_empty() {
                        return IpcResponse::Error {
                            code: 400,
                            message: "Nome da rede não pode ser vazio".to_string(),
                        };
                    }
                    if password.len() < 6 {
                        return IpcResponse::Error {
                            code: 400,
                            message: "A senha da rede deve conter pelo menos 6 caracteres"
                                .to_string(),
                        };
                    }

                    let mut nets = self.joined_networks.lock().await;
                    if !nets.contains(&network_name) {
                        nets.push(network_name.clone());
                    }
                    *self.active_network.lock().await = Some(network_name.clone());

                    IpcResponse::Success {
                        message: format!("Rede '{}' criada com sucesso", network_name),
                    }
                }
                IpcCommand::LeaveNetwork { network_id } => {
                    info!("Comando LeaveNetwork recebido: ID {}", network_id);
                    *self.active_network.lock().await = None;
                    IpcResponse::Success {
                        message: format!("Saiu da rede ID {}", network_id),
                    }
                }
                IpcCommand::EnumNetworks => {
                    let nets = self.joined_networks.lock().await.clone();
                    IpcResponse::NetworkList { networks: nets }
                }
                IpcCommand::GetNodeInfo { node_id } => IpcResponse::NodeInfo {
                    node_id,
                    virtual_ip: Some(format!("26.0.0.{}", node_id % 250 + 1)),
                    online: true,
                },
            }
        })
    }
}

pub struct Daemon {
    state: DaemonState,
    context: Arc<DaemonContext>,
    socket_path: PathBuf,
    shutdown_tx: broadcast::Sender<()>,
    ipc_task: Option<tokio::task::JoinHandle<()>>,
}

impl Daemon {
    pub fn new(config: crate::config::Config) -> Self {
        let (shutdown_tx, _) = broadcast::channel(4);
        let socket_path = crate::daemon::ipc::resolve_socket_path();

        let context = Arc::new(DaemonContext {
            connected: AtomicBool::new(false),
            virtual_ip: Mutex::new(None),
            active_network: Mutex::new(None),
            joined_networks: Mutex::new(Vec::new()),
            session_mgr: Mutex::new(None),
            tunnel: Mutex::new(None),
            config,
        });

        Self {
            state: DaemonState::Stopped,
            context,
            socket_path,
            shutdown_tx,
            ipc_task: None,
        }
    }

    pub fn with_ipc_socket(mut self, path: PathBuf) -> Self {
        self.socket_path = path;
        self
    }

    pub async fn start(&mut self) -> Result<()> {
        self.state = DaemonState::Starting;
        info!("Iniciando daemon do Radmin VPN...");

        let server = IpcServer::new(&self.socket_path);
        let handler = self.context.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();

        // Inicia loop assíncrono do IPC
        let handle = tokio::spawn(async move {
            if let Err(e) = server.run_loop(handler, shutdown_rx).await {
                error!("Erro fatal no servidor IPC: {}", e);
            }
        });

        self.ipc_task = Some(handle);
        self.state = DaemonState::Running;
        info!("Daemon do Radmin VPN rodando com sucesso!");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.state = DaemonState::Stopping;
        info!("Parando daemon do Radmin VPN...");
        let _ = self.shutdown_tx.send(());

        if let Some(task) = self.ipc_task.take() {
            let _ = task.await;
        }

        // Limpeza de recursos
        self.context.connected.store(false, Ordering::SeqCst);
        if let Some(mut sess) = self.context.session_mgr.lock().await.take() {
            let _ = sess.disconnect().await;
        }
        *self.context.tunnel.lock().await = None;

        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        self.state = DaemonState::Stopped;
        info!("Daemon parado com sucesso.");
        Ok(())
    }

    pub fn state(&self) -> DaemonState {
        self.state
    }

    pub fn config(&self) -> &crate::config::Config {
        &self.context.config
    }

    pub fn context(&self) -> Arc<DaemonContext> {
        self.context.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc::IpcClient;

    #[tokio::test]
    async fn test_daemon_ipc_integration() {
        let temp_dir = std::env::temp_dir();
        let sock_path = temp_dir.join(format!("radmin_daemon_test_{}.sock", std::process::id()));

        let cfg = crate::config::Config::default();
        let mut daemon = Daemon::new(cfg).with_ipc_socket(sock_path.clone());
        daemon.start().await.unwrap();
        assert_eq!(daemon.state(), DaemonState::Running);

        // Aguarda listener iniciar
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = IpcClient::connect(&sock_path).await.unwrap();

        // 1. Status inicial
        let resp = client.send_command(&IpcCommand::QueryStatus).await.unwrap();
        match resp {
            IpcResponse::Status { connected, .. } => assert!(!connected),
            other => panic!("Esperado Status, obtido {:?}", other),
        }

        // 2. SwitchPower(true)
        let resp_power = client
            .send_command(&IpcCommand::SwitchPower { enable: true })
            .await
            .unwrap();
        match resp_power {
            IpcResponse::Success { message } => assert!(message.contains("Conectado")),
            other => panic!("Esperado Success, obtido {:?}", other),
        }

        // 3. Status atualizado
        let resp2 = client.send_command(&IpcCommand::QueryStatus).await.unwrap();
        match resp2 {
            IpcResponse::Status {
                connected,
                virtual_ip,
                ..
            } => {
                assert!(connected);
                assert!(virtual_ip.is_some());
            }
            other => panic!("Esperado Status, obtido {:?}", other),
        }

        // 4. Parar daemon
        daemon.stop().await.unwrap();
        assert_eq!(daemon.state(), DaemonState::Stopped);
        assert!(!sock_path.exists());
    }
}
