use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: String,
    pub interface: crate::tunnel::TunnelConfig,
    pub discovery: crate::discovery::DiscoveryConfig,
    pub crypto: crate::crypto::CryptoChannelConfig,
    pub transport: crate::transport::ChannelConfig,
    pub auto_connect: bool,
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            interface: crate::tunnel::TunnelConfig::default(),
            discovery: crate::discovery::DiscoveryConfig {
                doh_endpoint: None,
                resolvers: vec![
                    "1.1.1.1".parse().unwrap(),
                    "8.8.8.8".parse().unwrap(),
                    "9.9.9.9".parse().unwrap(),
                ],
                ros_hostname: None,
            },
            crypto: crate::crypto::CryptoChannelConfig {
                enabled: true,
                compression: false,
            },
            transport: crate::transport::ChannelConfig::default(),
            auto_connect: false,
            log_level: "info".to_string(),
        }
    }
}

pub fn load(path: &std::path::Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

pub fn save(path: &std::path::Path, config: &Config) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}
