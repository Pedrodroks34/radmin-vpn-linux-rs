use crate::Result;

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: std::net::Ipv4Addr,
    pub interface: String,
    pub metric: u32,
}

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
