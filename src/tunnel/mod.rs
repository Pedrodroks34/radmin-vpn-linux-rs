pub mod tap;

pub use tap::{AnyTap, LinuxTap, MockTap, MockTapEndpoint, TapError};

use crate::crypto::CryptoChannel;
use crate::transport::TcpChannel;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelType {
    Tun,
    Tap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub tunnel_type: TunnelType,
    pub interface_name: String,
    pub mtu: u16,
    pub local_ip: Option<String>,
    pub remote_ip: Option<String>,
    pub subnet: Option<String>,
    pub mock_mode: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            tunnel_type: TunnelType::Tap,
            interface_name: "radmin0".to_string(),
            mtu: 1500,
            local_ip: None,
            remote_ip: None,
            subnet: None,
            mock_mode: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct TunnelMetrics {
    pub tx_frames: AtomicU64,
    pub rx_frames: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub dropped_frames: AtomicU64,
    pub crypto_errors: AtomicU64,
}

pub struct Tunnel {
    config: TunnelConfig,
    device: Option<AnyTap>,
    metrics: Arc<TunnelMetrics>,
}

impl Tunnel {
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            device: None,
            metrics: Arc::new(TunnelMetrics::default()),
        }
    }

    pub fn metrics(&self) -> Arc<TunnelMetrics> {
        self.metrics.clone()
    }

    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }

    pub fn open(&mut self) -> Result<()> {
        if self.config.mock_mode {
            let (mock, _) = MockTap::new();
            self.device = Some(AnyTap::Mock(mock));
            info!("Dispositivo TAP aberto em modo de simulação (MockTap)");
            return Ok(());
        }

        match LinuxTap::open(&self.config.interface_name) {
            Ok(tap) => {
                info!("Interface TAP Linux aberta: {}", tap.name());
                self.device = Some(AnyTap::Linux(tap));
                Ok(())
            }
            Err(e) => {
                error!("Falha ao abrir interface TAP: {}", e);
                Err(anyhow::anyhow!(e))
            }
        }
    }

    pub fn with_mock_tap(&mut self, mock: MockTap) {
        self.device = Some(AnyTap::Mock(mock));
    }

    pub async fn read_frame(&self) -> Result<Vec<u8>> {
        let dev = self
            .device
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispositivo TAP não inicializado"))?;

        let mut buf = vec![0u8; self.config.mtu as usize + 14 + 4]; // MTU + Ethernet header + VLAN
        let n = dev.read_frame(&mut buf).await?;
        buf.truncate(n);
        self.metrics.rx_frames.fetch_add(1, Ordering::Relaxed);
        self.metrics.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(buf)
    }

    pub async fn write_frame(&self, frame: &[u8]) -> Result<()> {
        let dev = self
            .device
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispositivo TAP não inicializado"))?;

        let n = dev.write_frame(frame).await?;
        self.metrics.tx_frames.fetch_add(1, Ordering::Relaxed);
        self.metrics.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(())
    }
}

/// Loop bidirecional de encaminhamento de quadros (Forwarding Pump)
pub struct ForwardingPump {
    running: Arc<AtomicBool>,
    metrics: Arc<TunnelMetrics>,
}

impl Default for ForwardingPump {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardingPump {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(TunnelMetrics::default()),
        }
    }

    pub fn metrics(&self) -> Arc<TunnelMetrics> {
        self.metrics.clone()
    }

    /// Executa o loop bidirecional entre o dispositivo TAP e o canal TCP de transporte seguro.
    pub async fn run(
        &self,
        tap: Arc<AnyTap>,
        mut transport: TcpChannel,
        crypto: Arc<CryptoChannel>,
    ) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);
        let running_tx = self.running.clone();
        let metrics_tx = self.metrics.clone();
        let metrics_rx = self.metrics.clone();

        let tap_in = tap.clone();
        let crypto_in = crypto.clone();

        // Canal intermediário entre o leitor do TAP e o transmissor do TCP
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(128);

        // Tarefa 1: Lê quadros Ethernet do TAP -> cifra -> fila de envio
        let tap_reader_handle = tokio::spawn(async move {
            let mut read_buf = vec![0u8; 2048];
            while running_tx.load(Ordering::Relaxed) {
                match tap_in.read_frame(&mut read_buf).await {
                    Ok(n) if n > 0 => {
                        let raw_frame = &read_buf[..n];
                        match crypto_in.encrypt(raw_frame).await {
                            Ok(ct) => {
                                if outbound_tx.send(ct).await.is_err() {
                                    break;
                                }
                                metrics_tx.tx_frames.fetch_add(1, Ordering::Relaxed);
                                metrics_tx.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                metrics_tx.crypto_errors.fetch_add(1, Ordering::Relaxed);
                                metrics_tx.dropped_frames.fetch_add(1, Ordering::Relaxed);
                                debug!("Erro ao cifrar quadro Ethernet: {}", e);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Erro ao ler do TAP: {}", e);
                        break;
                    }
                }
            }
        });

        // Tarefa 2: Consome pacotes cifrados e envia pelo canal TCP
        let running_pump = self.running.clone();
        let tap_writer = tap.clone();
        let crypto_out = crypto.clone();
        let mut crypto_failure: Option<String> = None;

        loop {
            tokio::select! {
                // Outbound: TAP -> TCP
                Some(encrypted_frame) = outbound_rx.recv() => {
                    if let Err(e) = transport.send(encrypted_frame).await {
                        error!("Erro ao enviar quadro pelo transporte TCP: {}", e);
                        break;
                    }
                }
                // Inbound: TCP -> decifra -> TAP
                result = transport.receive() => {
                    match result {
                        Ok(framed_packet) => {
                            match crypto_out.decrypt(&framed_packet.payload).await {
                                Ok(eth_frame) => {
                                    if let Err(e) = tap_writer.write_frame(&eth_frame).await {
                                        warn!("Erro ao injetar quadro Ethernet no TAP: {}", e);
                                        metrics_rx.dropped_frames.fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        metrics_rx.rx_frames.fetch_add(1, Ordering::Relaxed);
                                        metrics_rx.rx_bytes.fetch_add(eth_frame.len() as u64, Ordering::Relaxed);
                                    }
                                }
                                Err(e) => {
                                    metrics_rx.crypto_errors.fetch_add(1, Ordering::Relaxed);
                                    metrics_rx.dropped_frames.fetch_add(1, Ordering::Relaxed);
                                    error!("Falha de integridade no quadro recebido, encerrando o canal: {}", e);
                                    crypto_failure = Some(e.to_string());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            info!("Canal de transporte fechado: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        running_pump.store(false, Ordering::SeqCst);
        let _ = tap_reader_handle.abort();
        match crypto_failure {
            Some(reason) => Err(anyhow::anyhow!("falha criptográfica no canal: {}", reason)),
            None => Ok(()),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoChannelConfig;
    use crate::transport::{ChannelConfig, TcpChannelListener};
    use std::time::Duration;

    #[tokio::test]
    async fn pump_stops_on_crypto_failure_instead_of_forwarding() {
        let (mock_tap, _endpoint) = MockTap::new();
        let tap = Arc::new(AnyTap::Mock(mock_tap));

        let mut crypto_cfg = CryptoChannelConfig::default();
        crypto_cfg.enabled = true;
        let crypto = Arc::new(CryptoChannel::with_key(crypto_cfg, [0x33u8; 32]));

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client_transport = TcpChannel::connect(&addr.to_string(), ChannelConfig::default())
            .await
            .unwrap();
        let mut server_transport = listener.accept().await.unwrap();

        let pump = Arc::new(ForwardingPump::new());
        let handle = tokio::spawn({
            let pump = pump.clone();
            let tap = tap.clone();
            let crypto = crypto.clone();
            async move { pump.run(tap, client_transport, crypto).await }
        });

        server_transport.send(vec![0u8; 32]).await.unwrap();

        let outcome = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("o pump deve encerrar após falha criptográfica");
        assert!(outcome.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_forwarding_pump_pipeline() {
        let (mock_tap, endpoint) = MockTap::new();
        let tap = Arc::new(AnyTap::Mock(mock_tap));

        let shared_key = [0x33u8; 32];
        let mut crypto_cfg = CryptoChannelConfig::default();
        crypto_cfg.enabled = true;
        let crypto = Arc::new(CryptoChannel::with_key(crypto_cfg, shared_key));

        let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let client_transport = TcpChannel::connect(&addr.to_string(), ChannelConfig::default())
            .await
            .unwrap();
        let mut server_transport = listener.accept().await.unwrap();

        let pump = Arc::new(ForwardingPump::new());
        let pump_clone = pump.clone();
        let tap_clone = tap.clone();
        let crypto_clone = crypto.clone();

        tokio::spawn(async move {
            let _ = pump_clone
                .run(tap_clone, client_transport, crypto_clone)
                .await;
        });

        // Simula frame Ethernet gerado pelo kernel no TAP
        let eth_frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x20, 0x01, 0x02, 0x03, 0x04,
        ];

        endpoint.inject_frame(eth_frame.clone()).await.unwrap();

        // Servidor TCP deve receber o pacote cifrado no frame
        let received_net_frame = server_transport.receive().await.unwrap();
        // Decifra com a mesma chave do servidor
        let mut server_cipher = crate::crypto::FamatechCipherState::new(shared_key);
        let decrypted_eth = server_cipher.decrypt(&received_net_frame.payload).unwrap();
        assert_eq!(decrypted_eth, eth_frame);

        // Servidor envia frame de resposta
        let reply_frame = vec![0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc, 0x08, 0x00, 0x42];
        let encrypted_reply = server_cipher.encrypt(&reply_frame).unwrap();
        server_transport.send(encrypted_reply).await.unwrap();

        // TAP deve receber de volta o frame original após o pump decifrar
        match &*tap {
            AnyTap::Mock(m) => {
                let outbound = m.recv_outbound().await.unwrap();
                assert_eq!(outbound, reply_frame);
            }
            _ => panic!("Esperado MockTap"),
        }

        pump.stop();
    }
}
