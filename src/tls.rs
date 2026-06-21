use anyhow::{Context, Result};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::{fs::File, io::BufReader, path::Path, sync::Arc};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};

pub fn load_server_config(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building rustls server config")?;
    Ok(Arc::new(config))
}

fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(&path).with_context(|| format!("opening cert {}", path.as_ref().display()))?;
    let mut reader = BufReader::new(file);
    certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("reading PEM certificates")
}

fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(&path).with_context(|| format!("opening key {}", path.as_ref().display()))?;
    let mut reader = BufReader::new(file);
    if let Some(key) = pkcs8_private_keys(&mut reader).next() {
        let key: PrivatePkcs8KeyDer<'static> = key.context("reading PKCS#8 private key")?;
        return Ok(key.into());
    }
    let file = File::open(&path).with_context(|| format!("opening key {}", path.as_ref().display()))?;
    let mut reader = BufReader::new(file);
    if let Some(key) = rsa_private_keys(&mut reader).next() {
        let key: PrivatePkcs1KeyDer<'static> = key.context("reading RSA private key")?;
        return Ok(key.into());
    }
    anyhow::bail!("no private key found in {}", path.as_ref().display());
}
