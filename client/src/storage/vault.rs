use std::fs;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use prost::Message;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Local AEAD ChaCha20-Poly1305 cipher encrypting all SQLite WAL records & session tokens at rest.
pub struct LocalVaultCipher {
    cipher: ChaCha20Poly1305,
}

impl LocalVaultCipher {
    pub fn load_or_create(db_path: &Path) -> Result<Self, String> {
        let key_bytes: [u8; 32] = if let Ok(pass) = std::env::var("TGRAM_DB_KEY") {
            if !pass.trim().is_empty() {
                let mut hasher = Sha256::new();
                hasher.update(b"TGram-LocalVault-v1:");
                hasher.update(pass.as_bytes());
                let out = hasher.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&out);
                arr
            } else {
                load_or_generate_keyfile(db_path)?
            }
        } else {
            load_or_generate_keyfile(db_path)?
        };

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        Ok(Self { cipher })
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

fn load_or_generate_keyfile(db_path: &Path) -> Result<[u8; 32], String> {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create data directory: {e}"))?;
    }
    let key_path = db_path.with_extension("vault.key");
    if key_path.exists() {
        let raw = fs::read(&key_path).map_err(|e| format!("read vault key failed: {e}"))?;
        if let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) {
            return Ok(arr);
        }
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    fs::write(&key_path, key).map_err(|e| format!("write vault key failed: {e}"))?;
    Ok(key)
}
