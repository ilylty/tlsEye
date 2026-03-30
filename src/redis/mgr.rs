use std::net::IpAddr;
use anyhow::{Context, Result};
use deadpool_redis::{Config, Pool, Runtime};
use redis::AsyncCommands;
use serde_json;
use tracing::debug;

use crate::models::message::AlertRecord;
use crate::models::state::TlsState;

#[derive(Clone)]
pub struct RedisManager {
    cache_pool: Pool,
    result_pool: Pool,
    cache_ttl_secs: usize,
}

impl RedisManager {
    pub fn new(
        cache_url: &str,
        result_url: &str,
        cache_pool_size: usize,
        result_pool_size: usize,
        cache_ttl_secs: usize,
    ) -> Result<Self> {
        let mut cache_cfg = Config::from_url(cache_url);
        cache_cfg.pool = Some(deadpool_redis::PoolConfig::new(cache_pool_size));
        let cache_pool = cache_cfg
            .create_pool(Some(Runtime::Tokio1))
            .context("Failed to create Redis cache pool")?;

        let mut result_cfg = Config::from_url(result_url);
        result_cfg.pool = Some(deadpool_redis::PoolConfig::new(result_pool_size));
        let result_pool = result_cfg
            .create_pool(Some(Runtime::Tokio1))
            .context("Failed to create Redis result pool")?;

        Ok(Self {
            cache_pool,
            result_pool,
            cache_ttl_secs,
        })
    }

    /// 查询缓存：组合键 cache:ip_sni:{ip}:{sni}
    pub async fn get_cache(&self, ip: IpAddr, sni: &str) -> Result<Option<TlsState>> {
        let key = format!("cache:ip_sni:{}:{}", ip, sni);
        let mut conn = self.cache_pool.get().await?;
        let result: Option<u8> = conn.get(&key).await?;

        Ok(result.and_then(|val| match val {
            0 => Some(TlsState::Mismatch),
            1 => Some(TlsState::DnsMatch),
            2 => Some(TlsState::TlsMatch),
            8 => Some(TlsState::IpConnectionFailed),
            9 => Some(TlsState::DnsResolutionFailed),
            _ => None,
        }))
    }

    /// 写入缓存
    pub async fn set_cache(&self, ip: IpAddr, sni: &str, state: TlsState) -> Result<()> {
        let key = format!("cache:ip_sni:{}:{}", ip, sni);
        let mut conn = self.cache_pool.get().await?;
        conn.set_ex::<_, _, ()>(&key, state.as_u8(), self.cache_ttl_secs as u64)
            .await?;
        debug!("Cached state {} for key {}", state.as_u8(), key);
        Ok(())
    }

    /// 写入结果库
    pub async fn push_alert(&self, record: &AlertRecord) -> Result<()> {
        let payload = serde_json::to_string(record)?;
        let mut conn = self.result_pool.get().await?;
        conn.rpush::<_, _, ()>("result:alerts", payload).await?;
        debug!("Pushed alert for SNI {}", record.sni);
        Ok(())
    }
}
