use anyhow::Result;
use clap::{Parser, Subcommand};
use lowprint_tcp_proxy::{config::ServerConfig, tls, trojan};
use std::path::PathBuf;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    CheckConfig,
    Uri,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = ServerConfig::load(&cli.config)?;
    tracing_subscriber::fmt()
        .with_env_filter(config.log_level.clone())
        .with_target(false)
        .init();

    match cli.command {
        Some(Command::CheckConfig) => {
            config.validate()?;
            info!("server config is valid");
            Ok(())
        }
        Some(Command::Uri) => {
            config.validate()?;
            println!("{}", trojan::shadowrocket_uri(&config));
            Ok(())
        }
        None => run(config).await,
    }
}

async fn run(config: ServerConfig) -> Result<()> {
    config.validate()?;
    let tls_config = tls::load_server_config(&config.cert_path, &config.key_path)?;
    let listener = TcpListener::bind(config.listen).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    info!(listen = %config.listen, "trojan server started");
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(err) = trojan::serve_tls_connection(stream, acceptor, config).await {
                warn!(%peer, %err, "trojan connection ended");
            }
        });
    }
}
