use crate::config::ServerConfig;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha224, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::{debug, info, warn};

const MAX_AUTH_LINE: usize = 128;
const HTTPS_FALLBACK: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nBad Request\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanRequest {
    pub target: TargetAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Domain(String, u16),
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
}

impl TargetAddr {
    fn to_connect_string(&self) -> String {
        match self {
            Self::Domain(name, port) => format!("{name}:{port}"),
            Self::Ipv4(addr, port) => format!("{addr}:{port}"),
            Self::Ipv6(addr, port) => format!("[{addr}]:{port}"),
        }
    }
}

pub fn sha224_password_hash(password: &str) -> String {
    hex::encode(Sha224::digest(password.as_bytes()))
}

pub fn sha256_password_hash(password: &str) -> String {
    hex::encode(Sha256::digest(password.as_bytes()))
}

pub fn verify_password_hash(password: &str, presented: &str) -> bool {
    let normalized = presented.trim().to_ascii_lowercase();
    let sha224 = sha224_password_hash(password);
    let sha256 = sha256_password_hash(password);
    constant_time_eq(normalized.as_bytes(), sha224.as_bytes())
        || constant_time_eq(normalized.as_bytes(), sha256.as_bytes())
}

pub fn shadowrocket_uri(config: &ServerConfig) -> String {
    let name = config
        .node_name
        .clone()
        .unwrap_or_else(|| format!("lowprint-{}", config.domain));
    format!(
        "trojan://{}@{}:{}?sni={}#{}",
        urlencoding::encode(&config.password),
        config.domain,
        config.listen.port(),
        urlencoding::encode(&config.domain),
        urlencoding::encode(&name)
    )
}

pub async fn serve_tls_connection(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    config: ServerConfig,
) -> Result<()> {
    tcp.set_nodelay(config.tcp_nodelay).ok();
    let mut tls = acceptor.accept(tcp).await.context("TLS accept")?;
    let mut upstream = match authenticate_and_connect(&mut tls, &config).await {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(kind = "trojan_handshake_error", %err);
            let _ = tls.write_all(HTTPS_FALLBACK).await;
            let _ = tls.shutdown().await;
            return Err(err);
        }
    };

    info!(kind = "trojan_stream_open");
    match tokio::io::copy_bidirectional(&mut tls, &mut upstream).await {
        Ok((from_client, from_upstream)) => {
            info!(
                kind = "trojan_stream_close",
                bytes_from_client = from_client,
                bytes_from_upstream = from_upstream
            );
            Ok(())
        }
        Err(err) => {
            warn!(kind = "trojan_proxy_error", %err);
            Err(err).context("proxying trojan stream")
        }
    }
}

async fn authenticate_and_connect(
    tls: &mut TlsStream<TcpStream>,
    config: &ServerConfig,
) -> Result<TcpStream> {
    let line = read_crlf_line(tls, MAX_AUTH_LINE).await?;
    if !verify_password_hash(&config.password, &line) {
        bail!("trojan authentication failed");
    }
    let request = read_request(tls).await.context("reading trojan request")?;
    let target = request.target.to_connect_string();
    let upstream = match TcpStream::connect(target).await {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(kind = "trojan_upstream_connect_error", %err);
            return Err(err).context("connecting upstream");
        }
    };
    upstream.set_nodelay(config.tcp_nodelay).ok();
    Ok(upstream)
}

async fn read_crlf_line<R>(reader: &mut R, max_len: usize) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    loop {
        if buf.len() >= max_len {
            bail!("line too long");
        }
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await.context("reading CRLF line")?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            buf.truncate(buf.len() - 2);
            return String::from_utf8(buf).context("line is not utf-8");
        }
    }
}

pub async fn read_request<R>(reader: &mut R) -> Result<TrojanRequest>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; 2];
    reader.read_exact(&mut head).await.context("reading command")?;
    if head[0] != 0x01 {
        bail!("only CONNECT command is supported");
    }
    let target = match head[1] {
        0x01 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await.context("reading IPv4 address")?;
            let port = read_port(reader).await?;
            TargetAddr::Ipv4(Ipv4Addr::from(ip), port)
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await.context("reading domain length")?;
            if len[0] == 0 {
                bail!("empty domain target");
            }
            let mut domain = vec![0u8; len[0] as usize];
            reader.read_exact(&mut domain).await.context("reading domain")?;
            let port = read_port(reader).await?;
            TargetAddr::Domain(String::from_utf8(domain).context("domain is not utf-8")?, port)
        }
        0x04 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await.context("reading IPv6 address")?;
            let port = read_port(reader).await?;
            TargetAddr::Ipv6(Ipv6Addr::from(ip), port)
        }
        atyp => bail!("unsupported address type {atyp:#x}"),
    };
    let mut crlf = [0u8; 2];
    reader
        .read_exact(&mut crlf)
        .await
        .context("reading request terminator")?;
    if crlf != *b"\r\n" {
        bail!("invalid request terminator");
    }
    debug!(kind = "trojan_request_parsed");
    Ok(TrojanRequest { target })
}

async fn read_port<R>(reader: &mut R) -> Result<u16>
where
    R: AsyncRead + Unpin,
{
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await.context("reading port")?;
    Ok(u16::from_be_bytes(port))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.ct_eq(right).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn verifies_password_hashes() {
        let sha224 = sha224_password_hash("secret");
        let sha256 = sha256_password_hash("secret");
        assert!(verify_password_hash("secret", &sha224));
        assert!(verify_password_hash("secret", &sha256));
        assert!(!verify_password_hash("secret", &sha224_password_hash("wrong")));
    }

    #[test]
    fn builds_shadowrocket_uri() {
        let cfg = ServerConfig {
            listen: "0.0.0.0:443".parse().unwrap(),
            domain: "example.com".into(),
            password: "p@ss word".into(),
            cert_path: "/cert.pem".into(),
            key_path: "/key.pem".into(),
            node_name: Some("node one".into()),
            log_level: "info".into(),
            tcp_nodelay: true,
        };
        assert_eq!(
            shadowrocket_uri(&cfg),
            "trojan://p%40ss%20word@example.com:443?sni=example.com#node%20one"
        );
    }

    #[tokio::test]
    async fn parses_domain_request() {
        let (mut a, mut b) = duplex(128);
        tokio::spawn(async move {
            a.write_all(&[
                0x01, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                b'm', 0x01, 0xbb, b'\r', b'\n',
            ])
            .await
            .unwrap();
        });
        let req = read_request(&mut b).await.unwrap();
        assert_eq!(req.target, TargetAddr::Domain("example.com".into(), 443));
    }

    #[tokio::test]
    async fn parses_ipv4_request() {
        let (mut a, mut b) = duplex(128);
        tokio::spawn(async move {
            a.write_all(&[0x01, 0x01, 127, 0, 0, 1, 0x1f, 0x90, b'\r', b'\n'])
                .await
                .unwrap();
        });
        let req = read_request(&mut b).await.unwrap();
        assert_eq!(req.target, TargetAddr::Ipv4("127.0.0.1".parse().unwrap(), 8080));
    }
}
