use std::fs;
use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use keyring::Entry as KeyringEntry;
use prost::Message;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zeroize::Zeroize;

const KEYRING_SERVICE: &str = "org.tgram.native.desktop";
const KDF_SALT_LEN: usize = 16;

/// Local AEAD ChaCha20-Poly1305 cipher encrypting all SQLite WAL records & session tokens at rest.
///
/// Key Hierarchy:
/// 1. `TGRAM_DB_KEY` (Passcode Lock): Memory-hard **Argon2id** key derivation with a per-profile 128-bit salt.
/// 2. **OS Native Keychain** (`keyring`): Windows Credential Manager (DPAPI), macOS Keychain, or Linux Secret Service.
///    Automatically migrates and deletes any legacy `.vault.key` file if present.
/// 3. **Headless Fallback** (`.vault.key` with `0600` permissions on Unix): Used only if `TGRAM_VAULT_BACKEND=file`
///    or if running in a headless environment without an active OS credential service.
pub struct LocalVaultCipher {
    cipher: ChaCha20Poly1305,
}

impl LocalVaultCipher {
    pub fn load_or_create(db_path: &Path) -> Result<Self, String> {
        ensure_parent_dir(db_path)?;

        let mut key_bytes = resolve_master_key(db_path)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        key_bytes.zeroize();

        Ok(Self { cipher })
    }

    pub fn from_raw_key(mut key_bytes: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        key_bytes.zeroize();
        Self { cipher }
    }

    pub fn seal_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| "local vault AEAD encryption failed".to_owned())?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn open_bytes(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() < 12 + 16 {
            return Err("corrupted vault blob (too short)".to_owned());
        }
        let nonce = Nonce::from_slice(&blob[0..12]);
        self.cipher
            .decrypt(nonce, &blob[12..])
            .map_err(|_| "local vault AEAD authentication tag mismatch".to_owned())
    }

    pub fn seal_proto<M: Message>(&self, msg: &M) -> Result<Vec<u8>, String> {
        let mut buf = Vec::with_capacity(msg.encoded_len());
        msg.encode(&mut buf)
            .map_err(|e| format!("proto encode failed: {e}"))?;
        self.seal_bytes(&buf)
    }

    pub fn open_proto<M: Message + Default>(&self, blob: &[u8]) -> Result<M, String> {
        let plain = self.open_bytes(blob)?;
        M::decode(plain.as_slice()).map_err(|e| format!("proto decode failed: {e}"))
    }
}

fn ensure_parent_dir(db_path: &Path) -> Result<(), String> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create data directory '{}': {e}", parent.display()))?;
        }
    }
    Ok(())
}

fn resolve_master_key(db_path: &Path) -> Result<[u8; 32], String> {
    if let Ok(pass) = std::env::var("TGRAM_DB_KEY") {
        let trimmed = pass.trim();
        if !trimmed.is_empty() {
            let salt = load_or_create_kdf_salt(db_path)?;
            let key = derive_key_from_passcode(trimmed.as_bytes(), &salt)?;
            info!("LocalVaultCipher unlocked via Argon2id master passcode (TGRAM_DB_KEY)");
            return Ok(key);
        }
    }

    let force_file = std::env::var("TGRAM_VAULT_BACKEND")
        .map(|v| v.eq_ignore_ascii_case("file"))
        .unwrap_or(false);

    if !force_file {
        match load_or_create_os_keychain(db_path) {
            Ok(key) => return Ok(key),
            Err(err) => {
                warn!(
                    reason = %err,
                    "OS native keychain unavailable; falling back to local .vault.key file"
                );
            }
        }
    }

    load_or_generate_keyfile(db_path)
}

pub fn derive_key_from_passcode(
    passcode: &[u8],
    salt: &[u8; KDF_SALT_LEN],
) -> Result<[u8; 32], String> {
    let mut derived = [0u8; 32];
    Argon2::default()
        .hash_password_into(passcode, salt, &mut derived)
        .map_err(|e| format!("Argon2id passcode key derivation failed: {e}"))?;
    Ok(derived)
}

fn load_or_create_kdf_salt(db_path: &Path) -> Result<[u8; KDF_SALT_LEN], String> {
    let salt_path = vault_sidecar_path(db_path, "vault.salt");
    if salt_path.exists() {
        let raw = fs::read(&salt_path).map_err(|e| format!("read vault salt failed: {e}"))?;
        if let Ok(arr) = <[u8; KDF_SALT_LEN]>::try_from(raw.as_slice()) {
            return Ok(arr);
        }
    }

    let mut salt = [0u8; KDF_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    write_restricted_file(&salt_path, &salt)
        .map_err(|e| format!("write vault salt failed: {e}"))?;
    Ok(salt)
}

fn keyring_account_for_db(db_path: &Path) -> String {
    let stem = db_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "client_default".to_owned());

    let canonical_dir = db_path
        .parent()
        .and_then(|p| fs::canonicalize(p).ok())
        .unwrap_or_else(|| db_path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf());

    let mut hasher = Sha256::new();
    hasher.update(b"TGram-Keyring-Scope-v1:");
    hasher.update(canonical_dir.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let dir_tag = hex::encode(&digest[..4]);

    format!("vault:{stem}:{dir_tag}")
}

fn load_or_create_os_keychain(db_path: &Path) -> Result<[u8; 32], String> {
    let account = keyring_account_for_db(db_path);
    let entry = KeyringEntry::new(KEYRING_SERVICE, &account)
        .map_err(|e| format!("keyring init error: {e}"))?;
    let legacy_key_path = vault_sidecar_path(db_path, "vault.key");

    match entry.get_password() {
        Ok(mut secret_hex) => {
            let decoded = hex::decode(secret_hex.trim());
            secret_hex.zeroize();

            if let Ok(mut bytes) = decoded {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    bytes.zeroize();
                    if legacy_key_path.exists() {
                        let _ = fs::remove_file(&legacy_key_path);
                    }
                    info!(account = %account, "LocalVaultCipher key loaded from OS native keychain");
                    return Ok(arr);
                }
                bytes.zeroize();
            }
            warn!(account = %account, "Invalid secret format in OS keychain; rotating vault key");
        }
        Err(keyring::Error::NoEntry) => {
            // Seamless upgrade path: migrate existing local `.vault.key` into OS Keychain and shred file
            if legacy_key_path.exists() {
                if let Ok(mut raw) = fs::read(&legacy_key_path) {
                    if let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) {
                        let mut encoded = hex::encode(arr);
                        let store_res = entry.set_password(&encoded);
                        encoded.zeroize();
                        raw.zeroize();

                        store_res.map_err(|e| format!("keyring migration store failed: {e}"))?;
                        let _ = fs::remove_file(&legacy_key_path);
                        info!(
                            account = %account,
                            "Migrated legacy .vault.key into OS native keychain and removed plaintext keyfile"
                        );
                        return Ok(arr);
                    }
                    raw.zeroize();
                }
            }
        }
        Err(err) => {
            return Err(format!("keyring read failed: {err}"));
        }
    }

    let mut fresh_key = [0u8; 32];
    OsRng.fill_bytes(&mut fresh_key);
    let mut encoded = hex::encode(fresh_key);
    let store_res = entry.set_password(&encoded);
    encoded.zeroize();

    if let Err(err) = store_res {
        fresh_key.zeroize();
        return Err(format!("keyring write failed: {err}"));
    }

    info!(account = %account, "Generated new 256-bit vault key in OS native keychain");
    Ok(fresh_key)
}

fn load_or_generate_keyfile(db_path: &Path) -> Result<[u8; 32], String> {
    let key_path = vault_sidecar_path(db_path, "vault.key");
    if key_path.exists() {
        let mut raw = fs::read(&key_path).map_err(|e| format!("read vault key failed: {e}"))?;
        if let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) {
            raw.zeroize();
            return Ok(arr);
        }
        raw.zeroize();
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    write_restricted_file(&key_path, &key).map_err(|e| format!("write vault key failed: {e}"))?;
    Ok(key)
}

fn vault_sidecar_path(db_path: &Path, ext: &str) -> PathBuf {
    db_path.with_extension(ext)
}

fn write_restricted_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
        f.sync_all()
    }

    #[cfg(not(unix))]
    {
        fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_passcode_kdf_and_aead_roundtrip() {
        let salt_a = [0x11_u8; KDF_SALT_LEN];
        let salt_b = [0x22_u8; KDF_SALT_LEN];

        let k1 = derive_key_from_passcode(b"correct-horse-battery-staple", &salt_a).unwrap();
        let k2 = derive_key_from_passcode(b"correct-horse-battery-staple", &salt_a).unwrap();
        let k3 = derive_key_from_passcode(b"correct-horse-battery-staple", &salt_b).unwrap();
        let k4 = derive_key_from_passcode(b"wrong-passcode", &salt_a).unwrap();

        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);

        let vault = LocalVaultCipher::from_raw_key(k1);
        let secret_payload = b"Telegram Desktop SQLite WAL AEAD record";
        let mut sealed = vault.seal_bytes(secret_payload).unwrap();

        let opened = vault.open_bytes(&sealed).unwrap();
        assert_eq!(opened, secret_payload);

        // Tamper with ciphertext byte -> Poly1305 MAC must reject
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(vault.open_bytes(&sealed).is_err());
    }
}
