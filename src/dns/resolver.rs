use crate::config::settings::DnsConfig;
use anyhow::{Context, Result};
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::time::{timeout, Duration};

#[derive(Clone)]
pub struct DnsResolver {
    resolvers: Vec<Arc<TokioAsyncResolver>>,
    node_timeout_ms: u64,
}

impl DnsResolver {
    pub fn new(config: &DnsConfig) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_millis(config.node_timeout_ms);
        opts.attempts = 1; // Single attempt per resolver, let concurrency handle retries essentially
        opts.try_tcp_on_error = true;

        let mut resolvers = Vec::new();

        // Initialize UDP Resolvers
        for server in &config.udp_servers {
            let mut r_config = ResolverConfig::new();
            let socket_addr: SocketAddr = server.parse().with_context(|| format!("Invalid UDP server address: {}", server))?;
            let name_server = NameServerConfig::new(socket_addr, Protocol::Udp);
            r_config.add_name_server(name_server);
            resolvers.push(Arc::new(TokioAsyncResolver::tokio(r_config, opts.clone())));
        }

        // Initialize DoH Resolvers
        for doh in &config.doh_servers {
            let mut r_config = ResolverConfig::new();
            let socket_addr: SocketAddr = format!("{}:{}", doh.ip, doh.port).parse().with_context(|| format!("Invalid DoH IP/Port: {}:{}", doh.ip, doh.port))?;
            let mut name_server = NameServerConfig::new(socket_addr, Protocol::Https);
            name_server.tls_dns_name = Some(doh.domain.clone());
            r_config.add_name_server(name_server);
            resolvers.push(Arc::new(TokioAsyncResolver::tokio(r_config, opts.clone())));
        }

        if resolvers.is_empty() {
            anyhow::bail!("No DNS servers configured");
        }

        Ok(Self {
            resolvers,
            node_timeout_ms: config.node_timeout_ms,
        })
    }

    pub async fn resolve_sni(&self, sni: &str) -> Result<Vec<IpAddr>> {
        let mut futures = vec![];

        for resolver in &self.resolvers {
            let sni_clone = sni.to_string();
            let r = resolver.clone();
            let node_timeout_ms = self.node_timeout_ms;

            futures.push(tokio::spawn(async move {
                let resolve_future = r.lookup_ip(sni_clone);
                match timeout(Duration::from_millis(node_timeout_ms), resolve_future).await {
                    Ok(Ok(response)) => {
                        let ips: Vec<IpAddr> = response.iter().collect();
                        Ok(ips)
                    }
                    Ok(Err(e)) => Err(anyhow::anyhow!("Lookup failed: {}", e)),
                    Err(_) => Err(anyhow::anyhow!("Timeout")),
                }
            }));
        }

        let results = futures::future::join_all(futures).await;
        let mut all_ips = std::collections::HashSet::new();

        for res in results {
            if let Ok(Ok(ips)) = res {
                all_ips.extend(ips);
            }
        }

        if all_ips.is_empty() {
            anyhow::bail!("All parallel DNS lookups failed or timed out");
        }

        Ok(all_ips.into_iter().collect())
    }
}
