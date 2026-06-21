use lowprint_tcp_proxy::{config::ServerConfig, tls, trojan};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use sha2::{Digest, Sha224};
use std::sync::Arc;
use std::{fs, time::Duration};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        ClientConfig, DigitallySignedStruct, SignatureScheme,
    },
    TlsAcceptor, TlsConnector,
};

#[tokio::test]
async fn trojan_roundtrip_over_tls() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let dir = tempdir().unwrap();
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(&key_path, key_pair.serialize_pem()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let cfg = ServerConfig {
        listen: server_addr,
        domain: "localhost".into(),
        password: "secret".into(),
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        node_name: None,
        log_level: "info".into(),
        tcp_nodelay: true,
    };
    let acceptor = TlsAcceptor::from(tls::load_server_config(&cfg.cert_path, &cfg.key_path).unwrap());
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = trojan::serve_tls_connection(stream, acceptor, cfg).await;
    });

    let tcp = TcpStream::connect(server_addr).await.unwrap();
    let connector = TlsConnector::from(insecure_client_config());
    let mut stream = connector
        .connect(ServerName::try_from("localhost".to_string()).unwrap(), tcp)
        .await
        .unwrap();

    let hash = hex::encode(Sha224::digest(b"secret"));
    stream.write_all(hash.as_bytes()).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream
        .write_all(&[
            0x01,
            0x01,
            127,
            0,
            0,
            1,
            (echo_addr.port() >> 8) as u8,
            echo_addr.port() as u8,
            b'\r',
            b'\n',
        ])
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut body = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&body, b"ping");
}

fn insecure_client_config() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth(),
    )
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}
