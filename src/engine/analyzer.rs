use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tracing::debug;

use crate::dns::resolver::DnsResolver;
use crate::models::message::{AlertRecord, RawKafkaMessage};
use crate::models::state::TlsState;
use crate::parser::extract::extract_sni;
use crate::redis::mgr::RedisManager;
use crate::tls::prober::TlsProber;

#[derive(Clone)]
pub struct AnalyzerEngine {
    redis_mgr: Arc<RedisManager>,
    dns_resolver: Arc<DnsResolver>,
    tls_prober: Arc<TlsProber>,
}

fn is_valid_sni(sni: &str) -> bool {
    if sni.is_empty() || sni.len() > 253 {
        return false;
    }
    for c in sni.chars() {
        // Simple validation: SNI should only contain alphanumeric characters, hyphens, and dots.
        // It shouldn't contain brackets, spaces, or raw IP structures generally (though IPs are technically parseable, usually SNI is a hostname).
        if !c.is_ascii_alphanumeric() && c != '-' && c != '.' {
            return false;
        }
    }
    true
}

impl AnalyzerEngine {
    pub fn new(
        redis_mgr: Arc<RedisManager>,
        dns_resolver: Arc<DnsResolver>,
        tls_prober: Arc<TlsProber>,
    ) -> Self {
        Self {
            redis_mgr,
            dns_resolver,
            tls_prober,
        }
    }

    pub async fn process_message(&self, msg: RawKafkaMessage) -> Result<()> {
        let sni = match extract_sni(&msg.payload) {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to extract SNI: {}", e);
                return Ok(());
            }
        };

        if !is_valid_sni(&sni) {
            debug!("Skipping invalid SNI: {}", sni);
            return Ok(());
        }

        self.process_task(msg.ori_ip, msg.dst_ip, sni).await
    }

    pub async fn process_task(&self, ori_ip: std::net::IpAddr, dst_ip: std::net::IpAddr, sni: String) -> Result<()> {
        debug!("Extracted/Provided SNI: {} for Dst IP: {}", sni, dst_ip);

        // 1. Check cache
        if let Some(cached_state) = self.redis_mgr.get_cache(dst_ip, &sni).await? {
            debug!("Cache hit: state {} for {}:{}", cached_state.as_u8(), dst_ip, sni);
            if cached_state.is_alert() {
                self.push_alert_direct(ori_ip, dst_ip, &sni, cached_state).await?;
            }
            return Ok(());
        }

        debug!("Cache miss for {}:{}", dst_ip, sni);

        // 2. DNS/DoH Resolution
        let resolved_ips = match self.dns_resolver.resolve_sni(&sni).await {
            Ok(ips) => ips,
            Err(_) => {
                self.record_state(ori_ip, dst_ip, &sni, TlsState::DnsResolutionFailed).await?;
                return Ok(());
            }
        };

        if resolved_ips.is_empty() {
            self.record_state(ori_ip, dst_ip, &sni, TlsState::DnsResolutionFailed).await?;
            return Ok(());
        }

        // Cache all resolved IPs as valid DNS matches
        for ip in &resolved_ips {
            let _ = self.redis_mgr.set_cache(*ip, &sni, TlsState::DnsMatch).await;
        }

        // If target IP is in resolved IPs, we are done
        if resolved_ips.contains(&dst_ip) {
            return Ok(());
        }

        // 3. Dynamic TLS PubKey Probing
        let dst_pubkey = match self.tls_prober.probe(dst_ip, &sni).await {
            Ok(key) => key,
            Err(_) => {
                self.record_state(ori_ip, dst_ip, &sni, TlsState::IpConnectionFailed).await?;
                return Ok(());
            }
        };

        let mut base_pubkey = None;
        for ip in resolved_ips {
            if let Ok(key) = self.tls_prober.probe(ip, &sni).await {
                base_pubkey = Some(key);
                break;
            }
        }

        match base_pubkey {
            Some(base_key) => {
                if dst_pubkey == base_key {
                    self.record_state(ori_ip, dst_ip, &sni, TlsState::TlsMatch).await?;
                } else {
                    self.record_state(ori_ip, dst_ip, &sni, TlsState::Mismatch).await?;
                }
            }
            None => {
                self.record_state(ori_ip, dst_ip, &sni, TlsState::IpConnectionFailed).await?;
            }
        }

        Ok(())
    }

    async fn record_state(&self, ori_ip: std::net::IpAddr, dst_ip: std::net::IpAddr, sni: &str, state: TlsState) -> Result<()> {
        self.redis_mgr.set_cache(dst_ip, sni, state).await?;
        if state.is_alert() {
            self.push_alert_direct(ori_ip, dst_ip, sni, state).await?;
        }
        Ok(())
    }

    async fn push_alert_direct(&self, ori_ip: std::net::IpAddr, dst_ip: std::net::IpAddr, sni: &str, state: TlsState) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let alert = AlertRecord::new(ori_ip, dst_ip, sni.to_string(), state, timestamp);
        self.redis_mgr.push_alert(&alert).await
    }
}
