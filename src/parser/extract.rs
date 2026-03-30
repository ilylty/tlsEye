use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use tls_parser::{parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake};

pub fn extract_sni(base64_payload: &str) -> Result<String> {
    let payload = general_purpose::STANDARD
        .decode(base64_payload)
        .map_err(|e| anyhow!("Base64 decode error: {}", e))?;

    let (_, record) =
        parse_tls_plaintext(&payload).map_err(|e| anyhow!("TLS parse error: {:?}", e))?;

    for msg in record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg {
            if let Some(exts) = client_hello.ext {
                let parsed_exts = tls_parser::parse_tls_extensions(exts)
                    .map_err(|e| anyhow!("TLS extensions parse error: {:?}", e))?;

                for ext in parsed_exts.1 {
                    if let TlsExtension::SNI(sni_ext) = ext {
                        for sni in sni_ext {
                            if let Ok(s) = std::str::from_utf8(sni.1) {
                                return Ok(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    Err(anyhow!("No SNI found in TLS payload"))
}
