use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{fs, net::SocketAddr, path::Path};

fn default_listen() -> SocketAddr {
    "0.0.0.0:443".parse().expect("valid default listen")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_tcp_nodelay() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub domain: String,
    pub password: String,
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub node_name: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_tcp_nodelay")]
    pub tcp_nodelay: bool,
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.as_ref().display()))?;
        toml::from_str(&text).context("parsing server config")
    }

    pub fn validate(&self) -> Result<()> {
        if self.domain.trim().is_empty() {
            bail!("domain must not be empty");
        }
        if self.password.is_empty() {
            bail!("password must not be empty");
        }
        if self.cert_path.trim().is_empty() {
            bail!("cert_path must not be empty");
        }
        if self.key_path.trim().is_empty() {
            bail!("key_path must not be empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_required_fields() {
        let cfg = ServerConfig {
            listen: "0.0.0.0:443".parse().unwrap(),
            domain: "example.com".into(),
            password: "secret".into(),
            cert_path: "/cert.pem".into(),
            key_path: "/key.pem".into(),
            node_name: None,
            log_level: "info".into(),
            tcp_nodelay: true,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_missing_password() {
        let cfg = ServerConfig {
            listen: "0.0.0.0:443".parse().unwrap(),
            domain: "example.com".into(),
            password: String::new(),
            cert_path: "/cert.pem".into(),
            key_path: "/key.pem".into(),
            node_name: None,
            log_level: "info".into(),
            tcp_nodelay: true,
        };
        assert!(cfg.validate().is_err());
    }
}
