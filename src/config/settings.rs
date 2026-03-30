use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub cache_url: String,
    pub result_url: String,
    pub cache_pool_size: usize,
    pub result_pool_size: usize,
    pub cache_ttl_secs: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DohServer {
    pub ip: String,
    pub port: u16,
    pub domain: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsConfig {
    #[serde(default)]
    pub udp_servers: Vec<String>,
    #[serde(default)]
    pub doh_servers: Vec<DohServer>,
    pub timeout_secs: u64,
    #[serde(default = "default_node_timeout_ms")]
    pub node_timeout_ms: u64,
}

fn default_node_timeout_ms() -> u64 {
    1000 // Default 1 second timeout per DNS node
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KafkaConfig {
    pub brokers: String,
    pub group_id: String,
    pub topic: String,
    pub concurrency_limit: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub redis: RedisConfig,
    pub dns: DnsConfig,
    pub tls: TlsConfig,
    pub kafka: KafkaConfig,
}

impl Settings {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let settings: Settings = toml::from_str(&contents)?;
        Ok(settings)
    }
}
