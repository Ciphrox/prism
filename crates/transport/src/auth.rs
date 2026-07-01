use std::sync::Arc;
use std::time::Duration;

use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{IdleTimeout, TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

#[derive(Debug)]
struct InsecureVerifier;
impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[derive(Debug)]
struct PinningVerifier {
    expected_cert: Vec<u8>,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected_cert {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Certificate mismatch".to_string()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[derive(Debug)]
struct TrustedClientVerifier {
    trusted_certs: Vec<Vec<u8>>,
}

impl ClientCertVerifier for TrustedClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self
            .trusted_certs
            .iter()
            .any(|cert| cert.as_slice() == end_entity.as_ref())
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Invalid Client".to_string()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

fn transport_config() -> TransportConfig {
    let mut transport_cfg = TransportConfig::default();
    transport_cfg.keep_alive_interval(Some(Duration::from_secs(5)));
    transport_cfg.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(15_000))));

    transport_cfg.receive_window(VarInt::from_u32(8 * 1024 * 1024));
    transport_cfg.send_window(8 * 1024 * 1024);

    transport_cfg.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    transport_cfg.datagram_send_buffer_size(4 * 1024 * 1024);

    transport_cfg.congestion_controller_factory(Arc::new(BbrConfig::default()));
    transport_cfg
}

pub fn create_insecure_client_config(
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
) -> anyhow::Result<quinn::ClientConfig> {
    let cert = CertificateDer::from(client_cert);
    let key = PrivateKeyDer::try_from(client_key)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    let mut rustls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_client_auth_cert(vec![cert], key)?;
    rustls_config.alpn_protocols = vec![b"prism".to_vec()];

    let quic_config = QuicClientConfig::try_from(rustls_config)?;

    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_config));
    client_cfg.transport_config(Arc::new(transport_config()));

    Ok(client_cfg)
}

pub fn create_insecure_server_config(
    server_cert: Vec<u8>,
    server_key: Vec<u8>,
) -> anyhow::Result<quinn::ServerConfig> {
    let cert = CertificateDer::from(server_cert);
    let key = PrivateKeyDer::try_from(server_key)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    let mut rustls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    rustls_config.alpn_protocols = vec![b"prism".to_vec()];

    let quic_config = QuicServerConfig::try_from(rustls_config)?;

    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    server_cfg.transport_config(Arc::new(transport_config()));

    Ok(server_cfg)
}

pub fn create_client_config(
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
    server_cert: Vec<u8>,
) -> anyhow::Result<quinn::ClientConfig> {
    let cert = CertificateDer::from(client_cert);
    let key = PrivateKeyDer::try_from(client_key)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    let mut rustls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinningVerifier {
            expected_cert: server_cert,
        }))
        .with_client_auth_cert(vec![cert], key)?;
    rustls_config.alpn_protocols = vec![b"prism".to_vec()];

    let quic_config = QuicClientConfig::try_from(rustls_config)?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_config));
    client_cfg.transport_config(Arc::new(transport_config()));

    Ok(client_cfg)
}

pub fn create_server_config(
    server_cert: Vec<u8>,
    server_key: Vec<u8>,
    trusted_client_certs: Vec<Vec<u8>>,
) -> anyhow::Result<quinn::ServerConfig> {
    let cert = CertificateDer::from(server_cert);
    let key = PrivateKeyDer::try_from(server_key)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    let mut rustls_config = ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(TrustedClientVerifier {
            trusted_certs: trusted_client_certs,
        }))
        .with_single_cert(vec![cert], key)?;
    rustls_config.alpn_protocols = vec![b"prism".to_vec()];

    let quic_config = QuicServerConfig::try_from(rustls_config)?;

    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    server_cfg.transport_config(Arc::new(transport_config()));

    Ok(server_cfg)
}
