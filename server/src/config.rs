use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tgram_proto::default_server_signing_key;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub signing_key: SigningKey,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub media_dir: PathBuf,
    pub handshake_timeout: Duration,
    pub unauth_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_connections: usize,
    pub seed_demo_data: bool,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, String> {
        let bind_raw = env::var("TGRAM_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:4430".to_owned());
        let bind_addr: SocketAddr = bind_raw
            .parse()
            .map_err(|e| format!("invalid TGRAM_BIND_ADDR '{bind_raw}': {e}"))?;

        let signing_key = match env::var("TGRAM_SERVER_KEY_HEX") {
            Ok(hex_str) if !hex_str.trim().is_empty() => {
                let bytes = hex::decode(hex_str.trim())
                    .map_err(|e| format!("invalid TGRAM_SERVER_KEY_HEX: {e}"))?;
                let seed: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "TGRAM_SERVER_KEY_HEX must be exactly 32 bytes (64 hex chars)")?;
                SigningKey::from_bytes(&seed)
            }
            _ => default_server_signing_key(),
        };

        let database_url = env::var("DATABASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let redis_url = env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let media_dir = env::var("TGRAM_MEDIA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/media"));

        let max_connections = env::var("TGRAM_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(65_536);

        let seed_demo_data = env::var("TGRAM_SEED_DEMO")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);

        Ok(Self {
            bind_addr,
            signing_key,
            database_url,
            redis_url,
            media_dir,
            handshake_timeout: Duration::from_secs(5),
            unauth_timeout: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(75),
            max_connections,
            seed_demo_data,
        })
    }
}
