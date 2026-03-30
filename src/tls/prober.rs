use anyhow::{anyhow, Result};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, Error, SignatureScheme};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;
use tracing::debug;
use ring::digest::{digest, SHA256};

#[derive(Debug)]
pub struct ShortCircuitError;

impl std::fmt::Display for ShortCircuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ShortCircuitError")
    }
}

impl std::error::Error for ShortCircuitError {}

#[derive(Debug)]
struct ExtractPubKeyVerifier {
    pubkey_hash: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ServerCertVerifier for ExtractPubKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Compute SHA256 of the DER certificate (which includes the pubkey)
        // Or if we specifically need only the SPKI, we can parse it, but hashing the full DER
        // of the leaf cert is equally valid for identifying if the certificates are the same.
        let hash = digest(&SHA256, end_entity.as_ref()).as_ref().to_vec();
        
        if let Ok(mut lock) = self.pubkey_hash.lock() {
            *lock = Some(hash);
        }

        // Return a custom error to short-circuit the handshake
        Err(Error::General("ShortCircuit".into()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Err(Error::General("ShortCircuit".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Err(Error::General("ShortCircuit".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

#[derive(Clone)]
pub struct TlsProber {
    timeout_secs: u64,
}

impl TlsProber {
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }

    pub async fn probe(&self, ip: IpAddr, sni: &str) -> Result<Vec<u8>> {
        let addr = SocketAddr::new(ip, 443);
        let pubkey_hash = Arc::new(Mutex::new(None));

        let verifier = Arc::new(ExtractPubKeyVerifier {
            pubkey_hash: pubkey_hash.clone(),
        });

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|_| anyhow!("Invalid SNI: {}", sni))?;

        let connect_fut = async {
            let stream = TcpStream::connect(&addr).await?;
            let res = connector.connect(server_name, stream).await;
            
            // We expect an error because of our short-circuit
            if let Err(e) = res {
                debug!("Handshake failed as expected: {}", e);
            }
            Ok::<_, anyhow::Error>(())
        };

        let _ = timeout(Duration::from_secs(self.timeout_secs), connect_fut).await;

        let hash = {
            let lock = pubkey_hash.lock().unwrap();
            lock.clone()
        };

        match hash {
            Some(h) => Ok(h),
            None => Err(anyhow!("Failed to extract public key hash from {}", ip)),
        }
    }
}
