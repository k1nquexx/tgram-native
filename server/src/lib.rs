pub mod auth;
pub mod config;
pub mod connection;
pub mod error;
pub mod hub;
pub mod media;
pub mod store;

use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{error, info};

use crate::config::ServerConfig;
use crate::connection::serve_connection;
use crate::error::{ServerError, ServerResult};
use crate::hub::RealtimeHub;
use crate::media::MediaManager;
use crate::store::StorageEngine;

/// Initializes storage + media subsystems and runs the async TCP accept loop until `shutdown` resolves.
pub async fn run_with_listener<F>(
    listener: TcpListener,
    config: ServerConfig,
    shutdown: F,
) -> ServerResult<()>
where
    F: Future<Output = ()>,
{
    let store = if let Some(ref db_url) = config.database_url {
        info!("Connecting to PostgreSQL persistence backend...");
        StorageEngine::new_postgres(db_url, config.redis_url.as_deref()).await?
    } else {
        info!(
            seed_demo = config.seed_demo_data,
            "Using high-speed In-Memory store (set DATABASE_URL / REDIS_URL for PostgreSQL+Redis)"
        );
        StorageEngine::new_memory(config.seed_demo_data)
    };

    let media = Arc::new(MediaManager::new(config.media_dir.clone()).await?);
    let hub = RealtimeHub::new(store, media);
    let config = Arc::new(config);

    let local_addr = listener
        .local_addr()
        .map_err(|e| ServerError::Internal(format!("local_addr failed: {e}")))?;
    let pub_key_hex = hex::encode(config.signing_key.verifying_key().to_bytes());

    info!(
        %local_addr,
        ed25519_pubkey = %pub_key_hex,
        max_connections = config.max_connections,
        "TGram Native MTWire v1 TCP server listening"
    );

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!(
                    active_sockets = hub.active_socket_count(),
                    "Shutdown signal received; stopping TCP listener"
                );
                break;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, peer_addr)) => {
                        let cfg = Arc::clone(&config);
                        let hub_clone = Arc::clone(&hub);
                        tokio::spawn(async move {
                            serve_connection(stream, peer_addr, cfg, hub_clone).await;
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "TCP accept error");
                    }
                }
            }
        }
    }

    Ok(())
}
