use anyhow::{Context, Result};
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::Message;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::engine::analyzer::AnalyzerEngine;
use crate::models::message::RawKafkaMessage;

pub struct KafkaConsumerWorker {
    consumer: StreamConsumer,
    engine: Arc<AnalyzerEngine>,
    concurrency_limit: usize,
}

impl KafkaConsumerWorker {
    pub fn new(
        brokers: &str,
        group_id: &str,
        topic: &str,
        engine: Arc<AnalyzerEngine>,
        concurrency_limit: usize,
    ) -> Result<Self> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("group.id", group_id)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "true")
            .create()
            .context("Consumer creation failed")?;

        consumer
            .subscribe(&[topic])
            .context("Can't subscribe to specified topic")?;

        Ok(Self {
            consumer,
            engine,
            concurrency_limit,
        })
    }

    pub async fn run(&self) {
        info!("Starting Kafka Consumer");
        let semaphore = Arc::new(Semaphore::new(self.concurrency_limit));

        loop {
            match self.consumer.recv().await {
                Ok(msg) => {
                    if let Some(payload) = msg.payload() {
                        match serde_json::from_slice::<RawKafkaMessage>(payload) {
                            Ok(raw_msg) => {
                                let engine = self.engine.clone();
                                let permit = semaphore.clone().acquire_owned().await.unwrap();

                                tokio::spawn(async move {
                                    if let Err(e) = engine.process_message(raw_msg).await {
                                        error!("Error processing message: {:?}", e);
                                    }
                                    drop(permit);
                                });
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to deserialize Kafka message: {}. Payload preview: {:?}",
                                    e,
                                    String::from_utf8_lossy(payload)
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Kafka error: {}", e);
                }
            }
        }
    }
}
