use crate::Result;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::info;

const TUNSETIFF: u64 = 0x400454ca;

type IfReq = libc::ifreq;

#[derive(Debug, Error)]
pub enum TapError {
    #[error("permissão insuficiente para criar/acessar a interface TAP: requer sudo ou a capability CAP_NET_ADMIN (detalhes: {0})")]
    PermissionDenied(String),
    #[error("arquivo do dispositivo /dev/net/tun não encontrado no sistema: {0}")]
    DeviceNotFound(String),
    #[error("falha na chamada ioctl TUNSETIFF: {0}")]
    IoctlFailed(String),
    #[error("erro de E/S no dispositivo TAP: {0}")]
    Io(#[from] std::io::Error),
    #[error("canal de TAP mock desconectado")]
    MockDisconnected,
}

pub struct LinuxTap {
    name: String,
    async_fd: AsyncFd<File>,
}

impl LinuxTap {
    pub fn open(dev_name: &str) -> std::result::Result<Self, TapError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::PermissionDenied => TapError::PermissionDenied(e.to_string()),
                std::io::ErrorKind::NotFound => TapError::DeviceNotFound(e.to_string()),
                _ => TapError::Io(e),
            })?;

        let fd = file.as_raw_fd();

        let mut ifr: IfReq = unsafe { std::mem::zeroed() };
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;

        let name_bytes = dev_name.as_bytes();
        let max_len = ifr.ifr_name.len() - 1;
        let len = name_bytes.len().min(max_len);

        for (i, &b) in name_bytes[..len].iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }

        let res = unsafe { libc::ioctl(fd, TUNSETIFF as _, &ifr) };
        if res < 0 {
            let last_err = std::io::Error::last_os_error();
            if last_err.raw_os_error() == Some(libc::EPERM)
                || last_err.raw_os_error() == Some(libc::EACCES)
            {
                return Err(TapError::PermissionDenied(last_err.to_string()));
            }
            return Err(TapError::IoctlFailed(last_err.to_string()));
        }

        let assigned_name = unsafe {
            std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        info!("Interface TAP Linux criada com sucesso: {}", assigned_name);

        let async_fd = unsafe { AsyncFd::register(file) }
            .map_err(|e| TapError::Io(std::io::Error::other(e.to_string())))?;
        Ok(Self {
            name: assigned_name,
            async_fd,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn read_frame(&self, buf: &mut [u8]) -> std::result::Result<usize, TapError> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            let fd = self.async_fd.get_ref().as_raw_fd();
            let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Err(TapError::Io(err));
            }

            return Ok(ret as usize);
        }
    }

    pub async fn write_frame(&self, frame: &[u8]) -> std::result::Result<usize, TapError> {
        loop {
            let mut guard = self.async_fd.writable().await?;
            let fd = self.async_fd.get_ref().as_raw_fd();
            let ret =
                unsafe { libc::write(fd, frame.as_ptr() as *const libc::c_void, frame.len()) };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Err(TapError::Io(err));
            }

            return Ok(ret as usize);
        }
    }
}

pub struct MockTap {
    tx: mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    injected_tx: mpsc::Sender<Vec<u8>>,
    outbound_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl MockTap {
    pub fn new() -> (Self, Arc<MockTapEndpoint>) {
        let (to_kernel_tx, to_kernel_rx) = mpsc::channel(128);
        let (from_kernel_tx, from_kernel_rx) = mpsc::channel(128);

        let device = Self {
            tx: from_kernel_tx.clone(),
            rx: tokio::sync::Mutex::new(to_kernel_rx),
            injected_tx: to_kernel_tx,
            outbound_rx: tokio::sync::Mutex::new(from_kernel_rx),
        };

        let endpoint = Arc::new(MockTapEndpoint {
            send_to_tap: device.injected_tx.clone(),
        });

        (device, endpoint)
    }

    pub async fn read_frame(&self, buf: &mut [u8]) -> std::result::Result<usize, TapError> {
        let mut rx = self.rx.lock().await;
        let frame = rx.recv().await.ok_or(TapError::MockDisconnected)?;
        let len = frame.len().min(buf.len());
        buf[..len].copy_from_slice(&frame[..len]);
        Ok(len)
    }

    pub async fn write_frame(&self, frame: &[u8]) -> std::result::Result<usize, TapError> {
        self.tx
            .send(frame.to_vec())
            .await
            .map_err(|_| TapError::MockDisconnected)?;
        Ok(frame.len())
    }

    pub async fn recv_outbound(&self) -> Option<Vec<u8>> {
        let mut rx = self.outbound_rx.lock().await;
        rx.recv().await
    }

    pub async fn inject_inbound(&self, frame: Vec<u8>) -> Result<()> {
        self.injected_tx
            .send(frame)
            .await
            .map_err(|_| anyhow::anyhow!("Mock TAP channel closed"))?;
        Ok(())
    }
}

pub struct MockTapEndpoint {
    send_to_tap: mpsc::Sender<Vec<u8>>,
}

impl MockTapEndpoint {
    pub async fn inject_frame(&self, frame: Vec<u8>) -> Result<()> {
        self.send_to_tap
            .send(frame)
            .await
            .map_err(|_| anyhow::anyhow!("Mock TAP closed"))?;
        Ok(())
    }
}

pub enum AnyTap {
    Linux(LinuxTap),
    Mock(MockTap),
}

impl AnyTap {
    pub async fn read_frame(&self, buf: &mut [u8]) -> std::result::Result<usize, TapError> {
        match self {
            AnyTap::Linux(t) => t.read_frame(buf).await,
            AnyTap::Mock(m) => m.read_frame(buf).await,
        }
    }

    pub async fn write_frame(&self, frame: &[u8]) -> std::result::Result<usize, TapError> {
        match self {
            AnyTap::Linux(t) => t.write_frame(frame).await,
            AnyTap::Mock(m) => m.write_frame(frame).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_tap_read_write() {
        let (tap, endpoint) = MockTap::new();

        let test_eth_frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x28,
        ];

        endpoint.inject_frame(test_eth_frame.clone()).await.unwrap();

        let mut read_buf = [0u8; 1514];
        let n = tap.read_frame(&mut read_buf).await.unwrap();
        assert_eq!(&read_buf[..n], &test_eth_frame[..]);

        let reply = vec![0x00, 0x01, 0x02, 0x03];
        tap.write_frame(&reply).await.unwrap();
        let outbound = tap.recv_outbound().await.unwrap();
        assert_eq!(outbound, reply);
    }
}

#[cfg(test)]
mod abi_tests {
    use super::*;

    #[test]
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn ifreq_has_kernel_size_and_flags_offset() {
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
        assert_eq!(std::mem::offset_of!(IfReq, ifr_name), 0);
        assert_eq!(std::mem::offset_of!(IfReq, ifr_ifru), 16);
    }

    #[tokio::test]
    #[ignore = "requer /dev/net/tun e CAP_NET_ADMIN"]
    async fn open_tap_device_with_privileges() {
        let tap = LinuxTap::open("radtst0").expect("TAP deve abrir com privilégios");
        assert_eq!(tap.name(), "radtst0");
    }
}
