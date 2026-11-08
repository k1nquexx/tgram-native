use argon2::{
    password_hash::{
        rand_core::OsRng as PwOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{ServerError, ServerResult};

/// Telegram Desktop Night Blue official 7-color peer avatar palette (`0xRRGGBB`).
pub const AVATAR_PALETTE_RGB: [u32; 7] = [
    0xE17076, // Coral Red
    0x7BC862, // Emerald Green
    0x65AADD, // Sky Blue
    0xA695E7, // Soft Violet
    0xEE7AAE, // Rose Pink
    0x6EC9CB, // Cyan Teal
    0xFAA774, // Warm Amber
];

#[inline]
pub fn avatar_color_for_id(id: u64) -> u32 {
    AVATAR_PALETTE_RGB[(id as usize) % AVATAR_PALETTE_RGB.len()]
}

/// Validates and normalizes `@username` (3..=32 ASCII alphanumeric or `_`).
pub fn normalize_username(raw: &str) -> ServerResult<String> {
    let trimmed = raw.trim().trim_start_matches('@').to_ascii_lowercase();
    if trimmed.len() < 3 || trimmed.len() > 32 {
        return Err(ServerError::BadRequest(
            "Username must be 3..32 characters long".to_owned(),
        ));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(ServerError::BadRequest(
            "Username may only contain ASCII letters, digits, and '_'".to_owned(),
        ));
    }
    Ok(trimmed)
}

pub fn validate_password(password: &str) -> ServerResult<()> {
    if password.len() < 4 || password.len() > 256 {
        return Err(ServerError::BadRequest(
            "Password must be between 4 and 256 characters".to_owned(),
        ));
    }
    Ok(())
}

/// Offloads memory-hard Argon2id hashing to Tokio's blocking thread pool so async I/O workers never stall.
pub async fn hash_password_async(password: String) -> ServerResult<String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut PwOsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| ServerError::Internal(format!("argon2 hash failed: {e}")))
    })
    .await
    .map_err(|e| ServerError::Internal(format!("blocking pool join error: {e}")))?
}

/// Offloads constant-time Argon2id verification to Tokio's blocking thread pool.
pub async fn verify_password_async(password: String, phc_hash: String) -> ServerResult<bool> {
    tokio::task::spawn_blocking(move || {
        let Ok(parsed) = PasswordHash::new(&phc_hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
    .await
    .map_err(|e| ServerError::Internal(format!("blocking pool join error: {e}")))
}

/// Generates a 32-byte CSPRNG session token `(raw_token_for_client, sha256_digest_for_db)`.
pub fn generate_session_token() -> ([u8; 32], [u8; 32]) {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let digest = hash_session_token(&raw);
    (raw, digest)
}

/// Computes `SHA-256(raw_token)` for safe persistent indexing.
#[inline]
pub fn hash_session_token(raw_token: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(raw_token);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}
