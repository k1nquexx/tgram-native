use std::fs;
use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use keyring::Entry as KeyringEntry;
use prost::Message;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zeroize::Zeroize;

const KEYRING_SERVICE: &str = "org.tgram.native.desktop";
const KDF_SALT_LEN: usize = 16;
const PROFILE_GUID_META_KEY: &str = "profile_guid";
const KDF_SALT_META_KEY: &str = "kdf_salt";

#[cfg(windows)]
const DPAPI_FILE_MAGIC: &[u8; 8] = b"TGDPAPI1";

/// Local AEAD ChaCha20-Poly1305 cipher encrypting all SQLite WAL records & session tokens at rest.
///
/// Key Hierarchy:
/// 1. `TGRAM_DB_KEY` (Passcode Lock): Memory-hard **Argon2id** key derivation with a per-profile 128-bit salt
///    stored inside the SQLite `vault_header` metadata table.
/// 2. **OS Native Keychain** (`keyring`): Windows Credential Manager (DPAPI), macOS Keychain, or Linux Secret Service,
///    indexed by a persistent 128-bit random `profile_guid` stored inside `vault_header` so moving or renaming
///    the data directory never invalidates encrypted database access (`M-03`).
/// 3. **Headless Fallback** (`.vault.key` protected with `0600` mode on Unix and user-SID **DPAPI**
///    `CryptProtectData` encryption on Windows, `L-03`): Used only when `TGRAM_VAULT_BACKEND=file`
///    or in headless environments without an active OS credential service.
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

fn open_vault_header_conn(db_path: &Path) -> Result<Connection, String> {
    ensure_parent_dir(db_path)?;
    let conn = Connection::open(db_path)
        .map_err(|e| format!("open sqlite vault header '{}' failed: {e}", db_path.display()))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         CREATE TABLE IF NOT EXISTS vault_header (
             meta_key TEXT PRIMARY KEY,
             meta_val BLOB NOT NULL
         );",
    )
    .map_err(|e| format!("init sqlite vault_header failed: {e}"))?;
    Ok(conn)
}

/// Loads or initializes a persistent 128-bit random profile GUID inside the SQLite `vault_header`
/// table so moving the database directory never breaks OS Keychain key lookup (`M-03`).
pub fn load_or_create_profile_guid(db_path: &Path) -> Result<String, String> {
    let conn = open_vault_header_conn(db_path)?;
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT meta_val FROM vault_header WHERE meta_key = ?1",
            params![PROFILE_GUID_META_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| format!("query profile_guid failed: {e}"))?;

    if let Some(raw) = existing {
        if let Ok(s) = std::str::from_utf8(&raw) {
            let trimmed = s.trim();
            if trimmed.len() == 32 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Ok(trimmed.to_ascii_lowercase());
            }
        }
    }

    let mut guid_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut guid_bytes);
    let guid_hex = hex::encode(guid_bytes);

    conn.execute(
        "INSERT OR REPLACE INTO vault_header (meta_key, meta_val) VALUES (?1, ?2)",
        params![PROFILE_GUID_META_KEY, guid_hex.as_bytes()],
    )
    .map_err(|e| format!("persist profile_guid failed: {e}"))?;

    Ok(guid_hex)
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
    let conn = open_vault_header_conn(db_path)?;
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT meta_val FROM vault_header WHERE meta_key = ?1",
            params![KDF_SALT_META_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| format!("query kdf_salt failed: {e}"))?;

    if let Some(raw) = existing {
        if let Ok(arr) = <[u8; KDF_SALT_LEN]>::try_from(raw.as_slice()) {
            return Ok(arr);
        }
    }

    // Seamless migration from legacy `.vault.salt` sidecar file if present
    let legacy_salt_path = vault_sidecar_path(db_path, "vault.salt");
    if legacy_salt_path.exists() {
        if let Ok(raw) = fs::read(&legacy_salt_path) {
            if let Ok(arr) = <[u8; KDF_SALT_LEN]>::try_from(raw.as_slice()) {
                conn.execute(
                    "INSERT OR REPLACE INTO vault_header (meta_key, meta_val) VALUES (?1, ?2)",
                    params![KDF_SALT_META_KEY, &arr[..]],
                )
                .map_err(|e| format!("migrate kdf_salt into sqlite failed: {e}"))?;
                let _ = fs::remove_file(&legacy_salt_path);
                return Ok(arr);
            }
        }
    }

    let mut salt = [0u8; KDF_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    conn.execute(
        "INSERT OR REPLACE INTO vault_header (meta_key, meta_val) VALUES (?1, ?2)",
        params![KDF_SALT_META_KEY, &salt[..]],
    )
    .map_err(|e| format!("persist kdf_salt into sqlite failed: {e}"))?;
    Ok(salt)
}

#[inline]
fn keyring_account_for_guid(guid_hex: &str) -> String {
    format!("vault:guid:{guid_hex}")
}

fn legacy_keyring_account_for_db(db_path: &Path) -> String {
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

fn decode_hex_key32(mut secret_hex: String) -> Option<[u8; 32]> {
    let decoded = hex::decode(secret_hex.trim());
    secret_hex.zeroize();
    let mut bytes = decoded.ok()?;
    let arr = <[u8; 32]>::try_from(bytes.as_slice()).ok();
    bytes.zeroize();
    arr
}

fn store_key_in_keyring_entry(entry: &KeyringEntry, key: &[u8; 32]) -> Result<(), String> {
    let mut encoded = hex::encode(key);
    let res = entry.set_password(&encoded);
    encoded.zeroize();
    res.map_err(|e| format!("keyring write failed: {e}"))
}

fn load_or_create_os_keychain(db_path: &Path) -> Result<[u8; 32], String> {
    let guid = load_or_create_profile_guid(db_path)?;
    let account = keyring_account_for_guid(&guid);
    let entry = KeyringEntry::new(KEYRING_SERVICE, &account)
        .map_err(|e| format!("keyring init error: {e}"))?;
    let legacy_key_path = vault_sidecar_path(db_path, "vault.key");

    match entry.get_password() {
        Ok(secret_hex) => {
            if let Some(arr) = decode_hex_key32(secret_hex) {
                if legacy_key_path.exists() {
                    let _ = fs::remove_file(&legacy_key_path);
                }
                info!(account = %account, "LocalVaultCipher key loaded from OS native keychain");
                return Ok(arr);
            }
            warn!(account = %account, "Invalid secret format in OS keychain; rotating vault key");
        }
        Err(keyring::Error::NoEntry) => {
            // 1. Seamless upgrade from legacy path-hashed OS Keychain entry (`vault:{stem}:{dir_tag}`)
            let legacy_account = legacy_keyring_account_for_db(db_path);
            if let Ok(legacy_entry) = KeyringEntry::new(KEYRING_SERVICE, &legacy_account) {
                if let Ok(legacy_hex) = legacy_entry.get_password() {
                    if let Some(arr) = decode_hex_key32(legacy_hex) {
                        store_key_in_keyring_entry(&entry, &arr)?;
                        let _ = legacy_entry.delete_credential();
                        info!(
                            from = %legacy_account,
                            to = %account,
                            "Migrated path-scoped keychain entry to portable GUID keychain entry"
                        );
                        return Ok(arr);
                    }
                }
            }

            // 2. Seamless upgrade from local `.vault.key` (raw or DPAPI-sealed) into OS Keychain
            if legacy_key_path.exists() {
                if let Ok(mut raw) = fs::read(&legacy_key_path) {
                    let parsed = open_keyfile_payload(&raw);
                    raw.zeroize();
                    if let Ok((arr, _)) = parsed {
                        store_key_in_keyring_entry(&entry, &arr)?;
                        let _ = fs::remove_file(&legacy_key_path);
                        info!(
                            account = %account,
                            "Migrated local .vault.key into OS native keychain and removed keyfile"
                        );
                        return Ok(arr);
                    }
                }
            }
        }
        Err(err) => {
            return Err(format!("keyring read failed: {err}"));
        }
    }

    let mut fresh_key = [0u8; 32];
    OsRng.fill_bytes(&mut fresh_key);
    if let Err(err) = store_key_in_keyring_entry(&entry, &fresh_key) {
        fresh_key.zeroize();
        return Err(err);
    }

    info!(account = %account, "Generated new 256-bit vault key in OS native keychain");
    Ok(fresh_key)
}

fn load_or_generate_keyfile(db_path: &Path) -> Result<[u8; 32], String> {
    let key_path = vault_sidecar_path(db_path, "vault.key");
    if key_path.exists() {
        let mut raw = fs::read(&key_path).map_err(|e| format!("read vault key failed: {e}"))?;
        let opened = open_keyfile_payload(&raw);
        raw.zeroize();
        if let Ok((arr, needs_dpapi_upgrade)) = opened {
            if needs_dpapi_upgrade {
                if let Ok(sealed) = seal_keyfile_payload(&arr) {
                    let _ = write_restricted_file(&key_path, &sealed);
                    info!("Upgraded legacy plaintext .vault.key to Windows DPAPI-sealed blob");
                }
            }
            return Ok(arr);
        }
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let sealed = match seal_keyfile_payload(&key) {
        Ok(s) => s,
        Err(e) => {
            key.zeroize();
            return Err(e);
        }
    };
    if let Err(e) = write_restricted_file(&key_path, &sealed) {
        key.zeroize();
        return Err(format!("write vault key failed: {e}"));
    }
    Ok(key)
}

fn seal_keyfile_payload(raw_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        let dpapi_blob = win_dpapi::protect(raw_key)?;
        let mut out = Vec::with_capacity(DPAPI_FILE_MAGIC.len() + dpapi_blob.len());
        out.extend_from_slice(DPAPI_FILE_MAGIC);
        out.extend_from_slice(&dpapi_blob);
        Ok(out)
    }

    #[cfg(not(windows))]
    {
        Ok(raw_key.to_vec())
    }
}

fn open_keyfile_payload(file_bytes: &[u8]) -> Result<([u8; 32], bool), String> {
    #[cfg(windows)]
    {
        if file_bytes.starts_with(DPAPI_FILE_MAGIC) {
            let mut plain = win_dpapi::unprotect(&file_bytes[DPAPI_FILE_MAGIC.len()..])?;
            let res = <[u8; 32]>::try_from(plain.as_slice())
                .map(|arr| (arr, false))
                .map_err(|_| "decrypted DPAPI vault key has invalid length".to_owned());
            plain.zeroize();
            return res;
        }
        if let Ok(arr) = <[u8; 32]>::try_from(file_bytes) {
            return Ok((arr, true));
        }
        Err("invalid .vault.key format".to_owned())
    }

    #[cfg(not(windows))]
    {
        <[u8; 32]>::try_from(file_bytes)
            .map(|arr| (arr, false))
            .map_err(|_| "invalid .vault.key length".to_owned())
    }
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

#[cfg(windows)]
mod win_dpapi {
    use std::ptr;
    use zeroize::Zeroize;

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x0000_0001;
    const DPAPI_ENTROPY: &[u8] = b"TGram-Native-VaultKey-DPAPI-v1";

    #[repr(C)]
    struct CryptoApiBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const CryptoApiBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const CryptoApiBlob,
            pv_reserved: *mut core::ffi::c_void,
            p_prompt_struct: *const core::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut CryptoApiBlob,
        ) -> i32;

        fn CryptUnprotectData(
            p_data_in: *const CryptoApiBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const CryptoApiBlob,
            pv_reserved: *mut core::ffi::c_void,
            p_prompt_struct: *const core::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut CryptoApiBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        fn GetLastError() -> u32;
    }

    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if plaintext.is_empty() {
            return Err("cannot DPAPI-protect empty buffer".to_owned());
        }
        let in_blob = CryptoApiBlob {
            cb_data: plaintext.len() as u32,
            pb_data: plaintext.as_ptr() as *mut u8,
        };
        let entropy_blob = CryptoApiBlob {
            cb_data: DPAPI_ENTROPY.len() as u32,
            pb_data: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut out_blob = CryptoApiBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                ptr::null(),
                &entropy_blob,
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 || out_blob.pb_data.is_null() {
            let err = unsafe { GetLastError() };
            return Err(format!("Win32 CryptProtectData failed (error 0x{err:08X})"));
        }

        let sealed =
            unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize) }
                .to_vec();
        unsafe {
            let _ = LocalFree(out_blob.pb_data as *mut core::ffi::c_void);
        }
        Ok(sealed)
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.is_empty() {
            return Err("cannot DPAPI-unprotect empty blob".to_owned());
        }
        let in_blob = CryptoApiBlob {
            cb_data: ciphertext.len() as u32,
            pb_data: ciphertext.as_ptr() as *mut u8,
        };
        let entropy_blob = CryptoApiBlob {
            cb_data: DPAPI_ENTROPY.len() as u32,
            pb_data: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut out_blob = CryptoApiBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                ptr::null_mut(),
                &entropy_blob,
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 || out_blob.pb_data.is_null() {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "Win32 CryptUnprotectData failed (error 0x{err:08X})"
            ));
        }

        let plain = unsafe {
            let slice =
                std::slice::from_raw_parts_mut(out_blob.pb_data, out_blob.cb_data as usize);
            let copied = slice.to_vec();
            slice.zeroize();
            let _ = LocalFree(out_blob.pb_data as *mut core::ffi::c_void);
            copied
        };
        Ok(plain)
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

    #[test]
    fn test_profile_guid_and_salt_persist_across_directory_move() {
        let base = std::env::temp_dir().join(format!(
            "tgram_vault_move_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let dir_a = base.join("location_alpha");
        let dir_b = base.join("location_beta_renamed");
        let db_a = dir_a.join("client_portable.sqlite3");
        let db_b = dir_b.join("client_portable.sqlite3");

        let guid_before = load_or_create_profile_guid(&db_a).unwrap();
        let salt_before = load_or_create_kdf_salt(&db_a).unwrap();
        assert_eq!(guid_before.len(), 32);

        // Relocate the entire profile directory to a different path (`M-03` regression scenario)
        fs::rename(&dir_a, &dir_b).expect("rename profile directory failed");

        let guid_after = load_or_create_profile_guid(&db_b).unwrap();
        let salt_after = load_or_create_kdf_salt(&db_b).unwrap();

        assert_eq!(guid_before, guid_after);
        assert_eq!(
            keyring_account_for_guid(&guid_before),
            keyring_account_for_guid(&guid_after)
        );
        assert_eq!(salt_before, salt_after);

        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_dpapi_keyfile_roundtrip_and_tamper_rejection() {
        let raw_key = [0x5A_u8; 32];
        let mut sealed = seal_keyfile_payload(&raw_key).expect("DPAPI seal failed");
        assert!(sealed.starts_with(DPAPI_FILE_MAGIC));
        assert!(sealed.len() > DPAPI_FILE_MAGIC.len() + 32);
        assert!(
            !sealed.windows(32).any(|w| w == raw_key),
            "DPAPI blob must not expose raw 256-bit key in plaintext"
        );

        let (opened, needs_upgrade) = open_keyfile_payload(&sealed).expect("DPAPI open failed");
        assert_eq!(opened, raw_key);
        assert!(!needs_upgrade);

        // Legacy 32-byte raw file triggers seamless upgrade flag
        let (legacy_opened, legacy_upgrade) =
            open_keyfile_payload(&raw_key).expect("legacy raw key open failed");
        assert_eq!(legacy_opened, raw_key);
        assert!(legacy_upgrade);

        // Corrupted DPAPI payload must fail decryption
        let tail = sealed.len() - 1;
        sealed[tail] ^= 0xFF;
        assert!(open_keyfile_payload(&sealed).is_err());
    }
}
