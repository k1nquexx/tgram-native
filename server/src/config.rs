use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use zeroize::Zeroize;

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
    pub max_uploads_per_user: usize,
    pub max_total_uploads: usize,
    pub upload_session_ttl: Duration,
    pub seed_demo_data: bool,
}

pub const DEFAULT_SERVER_SEED_HEX: &str =
    "3c4d5e6f8091a2b3c4d5e6f70d1e2f405162738495a6b7c8d9ea001122334455";

/// Loads the server's static Ed25519 identity key from `TGRAM_SERVER_KEY_HEX`,
/// or falls back to the default server key when running without custom configuration.
pub fn load_production_signing_key() -> Result<SigningKey, String> {
    let env_val = env::var("TGRAM_SERVER_KEY_HEX")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SERVER_SEED_HEX.to_owned());
    parse_production_signing_key(Some(&env_val))
}

/// Validates and constructs the server's Ed25519 `SigningKey` from an optional hex string, zeroizing seed bytes.
pub fn parse_production_signing_key(raw_hex: Option<&str>) -> Result<SigningKey, String> {
    let Some(raw_hex) = raw_hex else {
        return Err(
            "CRITICAL: TGRAM_SERVER_KEY_HEX environment variable is required (64 hex chars / 32-byte Ed25519 seed). \
             Generate one via: openssl rand -hex 32"
                .to_owned(),
        );
    };

    let trimmed = raw_hex.trim();
    if trimmed.is_empty() {
        return Err(
            "CRITICAL: TGRAM_SERVER_KEY_HEX must not be empty (expected 64 hex chars)".to_owned(),
        );
    }

    let mut raw_bytes =
        hex::decode(trimmed).map_err(|e| format!("CRITICAL: invalid TGRAM_SERVER_KEY_HEX: {e}"))?;
    if raw_bytes.len() != 32 {
        let len = raw_bytes.len();
        raw_bytes.zeroize();
        return Err(format!(
            "CRITICAL: TGRAM_SERVER_KEY_HEX must be exactly 32 bytes (64 hex chars), got {len} bytes"
        ));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw_bytes);
    raw_bytes.zeroize();

    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, String> {
        let bind_raw = env::var("TGRAM_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:4430".to_owned());
        let bind_addr: SocketAddr = bind_raw
            .parse()
            .map_err(|e| format!("invalid TGRAM_BIND_ADDR '{bind_raw}': {e}"))?;

        let signing_key = load_production_signing_key()?;

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
            .filter(|&v| v > 0)
            .unwrap_or(65_536);

        let max_uploads_per_user = env::var("TGRAM_MAX_UPLOADS_PER_USER")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(4);

        let max_total_uploads = env::var("TGRAM_MAX_TOTAL_UPLOADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(1_024);

        let upload_ttl_secs = env::var("TGRAM_UPLOAD_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(30 * 60);

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
            max_uploads_per_user,
            max_total_uploads,
            upload_session_ttl: Duration::from_secs(upload_ttl_secs),
            seed_demo_data,
        })
    }
}
