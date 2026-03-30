# TLSEye

> **⚠️ DEMO NOTICE**: This project is a proof-of-concept / demo application. It is primarily intended for educational, experimental, and demonstration purposes. It may require further hardening before being used in a production environment.

TLSEye is a high-performance, asynchronous Rust-based analysis engine designed to consume TLS `ClientHello` payloads from network metadata streams, extract Server Name Indications (SNIs), and perform multi-dimensional validation to detect domain spoofing and infrastructure anomalies.

## Core Features

- **Kafka Ingestion**: High-throughput Kafka consumer utilizing bounded semaphores to prevent memory starvation while maxing out network I/O.
- **Parallel DNS/DoH Resolution**: Concurrently queries an array of UDP and DoH (DNS over HTTPS) servers. Implements soft-timeouts per node to ensure single slow resolvers don't bottleneck the analysis pipeline.
- **Dynamic TLS Probing**: Connects to target IPs to fetch and compare TLS certificates (PubKey/Subject) against baseline certificates fetched via validated DNS IPs.
- **Redis Caching & Alerting**: Efficiently caches domain-to-IP validation states and pushes malicious/mismatched alerts to a separate Redis DB.
- **SNI Sanitization**: Safely decodes Base64 payloads, parses TLS ClientHello extensions, and filters out malformed or artificially injected SNI strings.

## Architecture

1. **Packet Capture**: `pcap_to_kafka.py` parses PCAP files using `tshark` and publishes `ClientHello` payloads to Kafka.
2. **Analysis Engine (Rust)**:
   - Fetches payloads from Kafka.
   - Extracts SNI.
   - Looks up SNI cache in Redis.
   - Resolves SNI simultaneously across multiple DNS nodes.
   - Verifies target IP certificate vs. baseline certificate.
   - Caches results and generates alerts for mismatches.

## Prerequisites

- **Rust**: 1.75+
- **Kafka**: KRaft mode recommended (e.g., v3.5+)
- **Redis**: 6.0+

## Getting Started

1. **Configure Environment**
   Update `config.toml` with your Kafka brokers, Redis URIs, and DNS arrays.

2. **Build & Run**
   ```cmd
   cargo build --release
   target\release\tlseye.exe
   ```


## State Definitions

- `1` (`DnsMatch`): Target IP was successfully resolved via DNS.
- `2` (`TlsMatch`): Target IP was not in DNS, but TLS certificate matched the baseline.
- `0` (`Mismatch`): Target IP responded with a completely different certificate. (Alert generated)
- `8` (`IpConnectionFailed`): Target IP could not be connected on port 443. (Alert generated)
- `9` (`DnsResolutionFailed`): SNI could not be resolved via any DNS node. (Alert generated)
