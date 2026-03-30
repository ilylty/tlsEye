use std::sync::Arc;
use tokio;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

use tlseye::config::settings::Settings;
use tlseye::dns::resolver::DnsResolver;
use tlseye::engine::analyzer::AnalyzerEngine;
use tlseye::kafka::consumer::KafkaConsumerWorker;
use tlseye::redis::mgr::RedisManager;
use tlseye::tls::prober::TlsProber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(Level::INFO.into())
                .parse_lossy("info,hickory_proto=error")
        )
        .init();

    // Initialize rustls crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    info!("Starting tlseye analyzer");

    let config_path = std::env::var("TLSEYE_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let settings = Settings::load(&config_path)?;
    info!("Loaded configuration from {}", config_path);

    // 1. Initialize Redis Manager
    let redis_mgr = Arc::new(RedisManager::new(
        &settings.redis.cache_url,
        &settings.redis.result_url,
        settings.redis.cache_pool_size,
        settings.redis.result_pool_size,
        settings.redis.cache_ttl_secs,
    )?);

    // 2. Initialize DNS Resolver
    let dns_resolver = Arc::new(DnsResolver::new(&settings.dns)?);

    // 3. Initialize TLS Prober
    let tls_prober = Arc::new(TlsProber::new(settings.tls.timeout_secs));

    // 4. Initialize Analyzer Engine
    let engine = Arc::new(AnalyzerEngine::new(
        redis_mgr.clone(),
        dns_resolver.clone(),
        tls_prober.clone(),
    ));

    // 5. Initialize & Run Kafka Consumer
    let consumer = KafkaConsumerWorker::new(
        &settings.kafka.brokers,
        &settings.kafka.group_id,
        &settings.kafka.topic,
        engine,
        settings.kafka.concurrency_limit,
    )?;

    consumer.run().await;

    Ok(())
}