//! Configuração programática de interfaces de rede Linux via ioctl / Netlink.
//!
//! Equivalente no Linux às operações de inicialização e parametrização do
//! driver Windows NetMP60_1_1_64.sys (atribuição de IP virtual 26.x.x.x,
//! máscara de sub-rede /8, MTU 1500 e ativação IFF_UP).

use std::net::Ipv4Addr;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum NetlinkError {
    #[error("permissão insuficiente (CAP_NET_ADMIN ou sudo requerido): {0}")]
    PermissionDenied(String),
    #[error("interface de rede '{0}' não encontrada")]
    InterfaceNotFound(String),
    #[error("falha na chamada de configuração da interface: {0}")]
    IoctlFailed(String),
    #[error("erro de E/S na configuração da rede: {0}")]
    Io(#[from] std::io::Error),
}

/// Configurador de interfaces de rede de baixo nível no Linux.
pub struct InterfaceConfigurator;

impl InterfaceConfigurator {
    /// Configura o endereço IPv4 e máscara de rede na interface especificada.
    pub fn set_ip_and_netmask(
        ifname: &str,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> std::result::Result<(), NetlinkError> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(NetlinkError::Io(std::io::Error::last_os_error()));
        }

        struct SockCloser(libc::c_int);
        impl Drop for SockCloser {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = SockCloser(sock);

        // 1. Configurar IP (SIOCSIFADDR)
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        Self::copy_ifname(ifname, &mut ifr.ifr_name)?;

        let sockaddr_in = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sockaddr_in as *const _ as *const u8,
                &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
        }

        let res = unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as _, &ifr) };
        if res < 0 {
            let last_err = std::io::Error::last_os_error();
            if last_err.raw_os_error() == Some(libc::EPERM)
                || last_err.raw_os_error() == Some(libc::EACCES)
            {
                return Err(NetlinkError::PermissionDenied(last_err.to_string()));
            }
            if last_err.raw_os_error() == Some(libc::ENODEV) {
                return Err(NetlinkError::InterfaceNotFound(ifname.to_string()));
            }
            return Err(NetlinkError::IoctlFailed(format!(
                "SIOCSIFADDR falhou: {}",
                last_err
            )));
        }

        // 2. Configurar Máscara de Sub-rede (SIOCSIFNETMASK)
        let mut ifr_mask: libc::ifreq = unsafe { std::mem::zeroed() };
        Self::copy_ifname(ifname, &mut ifr_mask.ifr_name)?;

        let sockaddr_mask = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(netmask.octets()),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sockaddr_mask as *const _ as *const u8,
                &mut ifr_mask.ifr_ifru.ifru_netmask as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
        }

        let res_mask = unsafe { libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &ifr_mask) };
        if res_mask < 0 {
            let last_err = std::io::Error::last_os_error();
            return Err(NetlinkError::IoctlFailed(format!(
                "SIOCSIFNETMASK falhou: {}",
                last_err
            )));
        }

        info!(
            "Interface '{}' configurada com IP {} e máscara {}",
            ifname, ip, netmask
        );
        Ok(())
    }

    /// Configura o MTU da interface.
    pub fn set_mtu(ifname: &str, mtu: u16) -> std::result::Result<(), NetlinkError> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(NetlinkError::Io(std::io::Error::last_os_error()));
        }

        struct SockCloser(libc::c_int);
        impl Drop for SockCloser {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = SockCloser(sock);

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        Self::copy_ifname(ifname, &mut ifr.ifr_name)?;
        ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;

        let res = unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifr) };
        if res < 0 {
            let last_err = std::io::Error::last_os_error();
            if last_err.raw_os_error() == Some(libc::EPERM)
                || last_err.raw_os_error() == Some(libc::EACCES)
            {
                return Err(NetlinkError::PermissionDenied(last_err.to_string()));
            }
            if last_err.raw_os_error() == Some(libc::ENODEV) {
                return Err(NetlinkError::InterfaceNotFound(ifname.to_string()));
            }
            return Err(NetlinkError::IoctlFailed(format!(
                "SIOCSIFMTU falhou: {}",
                last_err
            )));
        }

        debug!("MTU da interface '{}' configurado para {}", ifname, mtu);
        Ok(())
    }

    /// Ativa o estado da interface (equivalente a `ip link set <ifname> up`).
    pub fn set_up(ifname: &str) -> std::result::Result<(), NetlinkError> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(NetlinkError::Io(std::io::Error::last_os_error()));
        }

        struct SockCloser(libc::c_int);
        impl Drop for SockCloser {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = SockCloser(sock);

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        Self::copy_ifname(ifname, &mut ifr.ifr_name)?;

        // Lê flags atuais
        let res = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &ifr) };
        if res < 0 {
            let last_err = std::io::Error::last_os_error();
            return Err(NetlinkError::IoctlFailed(format!(
                "SIOCGIFFLAGS falhou: {}",
                last_err
            )));
        }

        let current_flags = unsafe { ifr.ifr_ifru.ifru_flags };
        let new_flags = current_flags | (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        ifr.ifr_ifru.ifru_flags = new_flags;

        let res_set = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
        if res_set < 0 {
            let last_err = std::io::Error::last_os_error();
            if last_err.raw_os_error() == Some(libc::EPERM)
                || last_err.raw_os_error() == Some(libc::EACCES)
            {
                return Err(NetlinkError::PermissionDenied(last_err.to_string()));
            }
            return Err(NetlinkError::IoctlFailed(format!(
                "SIOCSIFFLAGS falhou: {}",
                last_err
            )));
        }

        info!("Interface '{}' ativada (IFF_UP | IFF_RUNNING)", ifname);
        Ok(())
    }

    /// Configura o endereço MAC físico da interface (SIOCSIFHWADDR).
    pub fn set_mac_address(ifname: &str, mac: [u8; 6]) -> std::result::Result<(), NetlinkError> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(NetlinkError::Io(std::io::Error::last_os_error()));
        }

        struct SockCloser(libc::c_int);
        impl Drop for SockCloser {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = SockCloser(sock);

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        Self::copy_ifname(ifname, &mut ifr.ifr_name)?;

        unsafe {
            ifr.ifr_ifru.ifru_hwaddr.sa_family = libc::ARPHRD_ETHER;
            for (i, &b) in mac.iter().enumerate() {
                ifr.ifr_ifru.ifru_hwaddr.sa_data[i] = b as libc::c_char;
            }
        }

        let res = unsafe { libc::ioctl(sock, libc::SIOCSIFHWADDR as _, &ifr) };
        if res < 0 {
            let last_err = std::io::Error::last_os_error();
            if last_err.raw_os_error() == Some(libc::EPERM)
                || last_err.raw_os_error() == Some(libc::EACCES)
            {
                return Err(NetlinkError::PermissionDenied(last_err.to_string()));
            }
            if last_err.raw_os_error() == Some(libc::ENODEV) {
                return Err(NetlinkError::InterfaceNotFound(ifname.to_string()));
            }
            return Err(NetlinkError::IoctlFailed(format!(
                "SIOCSIFHWADDR falhou: {}",
                last_err
            )));
        }

        info!(
            "Endereço MAC da interface '{}' configurado para {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            ifname, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        Ok(())
    }

    fn copy_ifname(
        ifname: &str,
        dest: &mut [libc::c_char; libc::IFNAMSIZ],
    ) -> std::result::Result<(), NetlinkError> {
        let bytes = ifname.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(NetlinkError::IoctlFailed(format!(
                "Nome da interface '{}' excede o limite IFNAMSIZ",
                ifname
            )));
        }
        for (i, &b) in bytes.iter().enumerate() {
            dest[i] = b as libc::c_char;
        }
        dest[bytes.len()] = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonexistent_interface_error_classification() {
        // Tentar configurar interface que não existe no sistema de teste
        let res = InterfaceConfigurator::set_ip_and_netmask(
            "nonexistent999",
            Ipv4Addr::new(26, 0, 0, 1),
            Ipv4Addr::new(255, 0, 0, 0),
        );

        // Deve retornar erro de permissão ou interface não encontrada
        assert!(res.is_err());
        match res.unwrap_err() {
            NetlinkError::PermissionDenied(_) | NetlinkError::InterfaceNotFound(_) => {}
            other => panic!("Tipo de erro inesperado: {:?}", other),
        }
    }

    #[test]
    fn test_ifname_overflow_check() {
        let long_name = "a".repeat(libc::IFNAMSIZ + 1);
        let res = InterfaceConfigurator::set_up(&long_name);
        assert!(res.is_err());
    }
}
