use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use tgram_server::config::ServerConfig;
use tgram_server::run_with_listener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tgram_server=debug"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let config = match ServerConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!(error = %e, "Server configuration initialization failed");
            return Err(std::io::Error::other(e).into());
        }
    };
    let listener = TcpListener::bind(config.bind_addr).await?;

    run_with_listener(listener, config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;

    Ok(())
}
