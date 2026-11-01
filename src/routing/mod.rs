//! # Módulo `routing` — Tabelas de rotas para a rede virtual
//
//! ## Evidências da engenharia reversa (REA)
//
//! **Confirmado:**
//! - O serviço Windows usa IPHLPAPI para gerenciar rotas e entradas de ARP/IPNet.
//! - `Driver Read Buffer Size`, `Driver Reads in progress` — leitura de pacotes do driver.
//!
//! **Desconhecido:**
//! - Tabela de roteamento interna do cliente.
//! - Como pacotes são encaminhados para peers específicos (next-hop virtual).

use crate::Result;

/// Entrada de rota na rede virtual
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: String, // CIDR (a confirmar via REA dinâmica)
    pub gateway: std::net::Ipv4Addr,
    pub interface: String,
    pub metric: u32,
}

/// Gerenciador de rotas (placeholder — usar rtnetlink no Linux)
pub struct RouteTable {
    pub routes: Vec<RouteEntry>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn add_route(&mut self, route: RouteEntry) {
        self.routes.push(route);
    }

    pub async fn apply_to_system(&self) -> Result<()> {
        Err(anyhow::anyhow!("Aplicação de rotas via netlink não implementada"))
    }
}
