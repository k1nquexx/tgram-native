pub mod vault;

use std::path::{Path, PathBuf};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crossbeam_channel::{unbounded, Receiver, Sender};
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info, warn};
use tgram_proto::{ChatMessage, DialogEntry, UserProfile};

use crate::domain::{BackendEvent, SavedSession, StorageCommand};
use crate::storage::vault::LocalVaultCipher;

const SESSION_VAULT_KEY: &str = "active_session_v1";
const OPTIMISTIC_SORT_BASE: i64 = 1_i64 << 60;

#[derive(Clone, PartialEq, ::prost::Message)]
struct StoredSessionRecord {
    #[prost(string, tag = "1")]
    server_addr: String,
    #[prost(message, optional, tag = "2")]
    self_profile: Option<UserProfile>,
    #[prost(bytes = "vec", tag = "3")]
    session_token: Vec<u8>,
    #[prost(uint64, tag = "4")]
    last_pts: u64,
    #[prost(string, tag = "5")]
    server_pubkey_hex: String,
}

/// Spawns the dedicated `StorageThread` owning the encrypted SQLite3 WAL connection.
pub fn spawn_storage_thread(
    db_path: PathBuf,
    ui_tx: UnboundedSender<BackendEvent>,
) -> Sender<StorageCommand> {
    let (cmd_tx, cmd_rx) = unbounded::<StorageCommand>();

    thread::Builder::new()
        .name("tgram-storage".to_owned())
        .spawn(move || {
            if let Err(e) = storage_worker_loop(&db_path, cmd_rx, &ui_tx) {
                error!(error = %e, "StorageThread terminated with fatal error");
                let _ = ui_tx.send(BackendEvent::TransientError(format!(
                    "Ошибка локальной БД SQLite: {e}"
                )));
            }
        })
        .expect("failed to spawn dedicated StorageThread");

    cmd_tx
}

fn storage_worker_loop(
    db_path: &Path,
    cmd_rx: Receiver<StorageCommand>,
    ui_tx: &UnboundedSender<BackendEvent>,
) -> Result<(), String> {
    let vault = LocalVaultCipher::load_or_create(db_path)?;
    let mut conn = Connection::open(db_path)
        .map_err(|e| format!("open sqlite '{}' failed: {e}", db_path.display()))?;

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA mmap_size = 67108864;
         PRAGMA cache_size = -16000;
         PRAGMA foreign_keys = ON;

         CREATE TABLE IF NOT EXISTS kv_vault (
             k TEXT PRIMARY KEY,
             encrypted_val BLOB NOT NULL
         );

         CREATE TABLE IF NOT EXISTS users_cache (
             user_id INTEGER PRIMARY KEY,
             encrypted_proto BLOB NOT NULL
         );

         CREATE TABLE IF NOT EXISTS dialogs_cache (
             chat_id INTEGER PRIMARY KEY,
             sort_ts INTEGER NOT NULL,
             is_pinned INTEGER NOT NULL,
             encrypted_proto BLOB NOT NULL
         );

         CREATE TABLE IF NOT EXISTS messages_cache (
             chat_id INTEGER NOT NULL,
             sort_key INTEGER NOT NULL,
             msg_id INTEGER NOT NULL,
             client_random_id INTEGER NOT NULL,
             encrypted_proto BLOB NOT NULL,
             PRIMARY KEY (chat_id, sort_key)
         );

         CREATE INDEX IF NOT EXISTS idx_messages_random_id
             ON messages_cache (chat_id, client_random_id);

         CREATE TABLE IF NOT EXISTS media_files (
             media_id TEXT PRIMARY KEY,
             local_path TEXT NOT NULL
         );",
    )
    .map_err(|e| format!("sqlite WAL schema init failed: {e}"))?;

    info!(path = %db_path.display(), "SQLite3 WAL + AEAD Vault storage ready");

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            StorageCommand::LoadBootstrap => {
                if let Err(e) = handle_load_bootstrap(&conn, &vault, ui_tx) {
                    warn!(error = %e, "LoadBootstrap error");
                }
            }
            StorageCommand::SaveSession(sess) => {
                if let Err(e) = handle_save_session(&conn, &vault, sess) {
                    warn!(error = %e, "SaveSession error");
                }
            }
            StorageCommand::ClearSession => {
                let _ = conn.execute("DELETE FROM kv_vault WHERE k = ?1", params![SESSION_VAULT_KEY]);
                let _ = conn.execute("DELETE FROM dialogs_cache", []);
                let _ = conn.execute("DELETE FROM messages_cache", []);
            }
            StorageCommand::SaveDialogsAndUsers {
                dialogs,
                users,
                pts,
            } => {
                if let Err(e) = handle_save_dialogs_and_users(&mut conn, &vault, &dialogs, &users, pts) {
                    warn!(error = %e, "SaveDialogsAndUsers error");
                }
            }
            StorageCommand::LoadChatHistory { chat_id, limit } => {
                if let Err(e) = handle_load_chat_history(&conn, &vault, chat_id, limit, ui_tx) {
                    warn!(error = %e, "LoadChatHistory error");
                }
            }
            StorageCommand::UpsertMessages { chat_id, messages } => {
                if let Err(e) = handle_upsert_messages(&mut conn, &vault, chat_id, &messages) {
                    warn!(error = %e, "UpsertMessages error");
                }
            }
            StorageCommand::UpdateOutboxAck {
                chat_id,
                client_random_id,
                msg_id,
                timestamp_ms,
                pts,
            } => {
                if let Err(e) = handle_outbox_ack(
                    &mut conn,
                    &vault,
                    chat_id,
                    client_random_id,
                    msg_id,
                    timestamp_ms,
                    pts,
                ) {
                    warn!(error = %e, "UpdateOutboxAck error");
                }
            }
            StorageCommand::UpdateReadOutbox {
                chat_id,
                max_read_msg_id,
            } => {
                if let Err(e) = handle_update_read_outbox(&mut conn, &vault, chat_id, max_read_msg_id) {
                    warn!(error = %e, "UpdateReadOutbox error");
                }
            }
            StorageCommand::UpdateReadInbox {
                chat_id,
                max_read_msg_id,
                unread_count,
            } => {
                if let Err(e) =
                    handle_update_read_inbox(&conn, &vault, chat_id, max_read_msg_id, unread_count)
                {
                    warn!(error = %e, "UpdateReadInbox error");
                }
            }
            StorageCommand::RecordDownloadedMedia {
                media_id,
                local_path,
            } => {
                let _ = conn.execute(
                    "INSERT INTO media_files (media_id, local_path) VALUES (?1, ?2)
                     ON CONFLICT(media_id) DO UPDATE SET local_path = excluded.local_path",
                    params![media_id, local_path.to_string_lossy().as_ref()],
                );
            }
            StorageCommand::GenerateStressHistory {
                chat_id,
                self_user_id,
                peer_user_id,
                count,
            } => {
                if let Err(e) = handle_generate_stress_history(
                    &mut conn,
                    &vault,
                    chat_id,
                    self_user_id,
                    peer_user_id,
                    count,
                    ui_tx,
                ) {
                    warn!(error = %e, "GenerateStressHistory error");
                }
            }
            StorageCommand::Shutdown => break,
        }
    }

    Ok(())
}

fn handle_load_bootstrap(
    conn: &Connection,
    vault: &LocalVaultCipher,
    ui_tx: &UnboundedSender<BackendEvent>,
) -> Result<(), String> {
    let session_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT encrypted_val FROM kv_vault WHERE k = ?1",
            params![SESSION_VAULT_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let session = match session_blob {
        Some(blob) => match vault.open_proto::<StoredSessionRecord>(&blob) {
            Ok(rec) => rec.self_profile.map(|profile| SavedSession {
                server_addr: rec.server_addr,
                server_pubkey_hex: rec.server_pubkey_hex,
                self_profile: profile,
                session_token: rec.session_token,
                last_pts: rec.last_pts,
            }),
            Err(_) => None,
        },
        None => None,
    };

    let mut users = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT encrypted_proto FROM users_cache")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|e| e.to_string())?;
        for blob in rows.flatten() {
            if let Ok(u) = vault.open_proto::<UserProfile>(&blob) {
                users.push(u);
            }
        }
    }

    let mut dialogs = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT encrypted_proto FROM dialogs_cache
                 ORDER BY is_pinned DESC, sort_ts DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|e| e.to_string())?;
        for blob in rows.flatten() {
            if let Ok(d) = vault.open_proto::<DialogEntry>(&blob) {
                dialogs.push(d);
            }
        }
    }

    let mut downloaded_files = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT media_id, local_path FROM media_files")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| e.to_string())?;
        for (mid, p_str) in rows.flatten() {
            let p = PathBuf::from(p_str);
            if p.exists() {
                downloaded_files.push((mid, p));
            }
        }
    }

    let _ = ui_tx.send(BackendEvent::BootstrapLoaded {
        session,
        dialogs,
        users,
        downloaded_files,
    });
    Ok(())
}

fn handle_save_session(
    conn: &Connection,
    vault: &LocalVaultCipher,
    sess: SavedSession,
) -> Result<(), String> {
    let rec = StoredSessionRecord {
        server_addr: sess.server_addr,
        self_profile: Some(sess.self_profile),
        session_token: sess.session_token,
        last_pts: sess.last_pts,
        server_pubkey_hex: sess.server_pubkey_hex,
    };
    let blob = vault.seal_proto(&rec)?;
    conn.execute(
        "INSERT INTO kv_vault (k, encrypted_val) VALUES (?1, ?2)
         ON CONFLICT(k) DO UPDATE SET encrypted_val = excluded.encrypted_val",
        params![SESSION_VAULT_KEY, blob],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn handle_save_dialogs_and_users(
    conn: &mut Connection,
    vault: &LocalVaultCipher,
    dialogs: &[DialogEntry],
    users: &[UserProfile],
    pts: u64,
) -> Result<(), String> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;

    {
        let mut u_stmt = tx
            .prepare_cached(
                "INSERT INTO users_cache (user_id, encrypted_proto) VALUES (?1, ?2)
                 ON CONFLICT(user_id) DO UPDATE SET encrypted_proto = excluded.encrypted_proto",
            )
            .map_err(|e| e.to_string())?;

        for u in users {
            let blob = vault.seal_proto(u)?;
            u_stmt
                .execute(params![u.user_id as i64, blob])
                .map_err(|e| e.to_string())?;
        }
    }

    {
        let mut d_stmt = tx
            .prepare_cached(
                "INSERT INTO dialogs_cache (chat_id, sort_ts, is_pinned, encrypted_proto)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(chat_id) DO UPDATE SET
                     sort_ts = excluded.sort_ts,
                     is_pinned = excluded.is_pinned,
                     encrypted_proto = excluded.encrypted_proto",
            )
            .map_err(|e| e.to_string())?;

        let mut m_stmt = tx
            .prepare_cached(
                "INSERT INTO messages_cache (chat_id, sort_key, msg_id, client_random_id, encrypted_proto)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(chat_id, sort_key) DO UPDATE SET
                     msg_id = excluded.msg_id,
                     encrypted_proto = excluded.encrypted_proto",
            )
            .map_err(|e| e.to_string())?;

        for d in dialogs {
            let blob = vault.seal_proto(d)?;
            d_stmt
                .execute(params![
                    d.chat_id as i64,
                    d.sort_timestamp_ms,
                    i32::from(d.is_pinned),
                    blob
                ])
                .map_err(|e| e.to_string())?;

            if let Some(ref top) = d.top_message {
                if top.msg_id > 0 {
                    let m_blob = vault.seal_proto(top)?;
                    m_stmt
                        .execute(params![
                            d.chat_id as i64,
                            top.msg_id as i64,
                            top.msg_id as i64,
                            top.client_random_id as i64,
                            m_blob
                        ])
                        .map_err(|e| e.to_string())?;
                }
            }
        }
    }

    // Update last_pts inside stored session if present
    if let Ok(Some(sess_blob)) = tx
        .query_row(
            "SELECT encrypted_val FROM kv_vault WHERE k = ?1",
            params![SESSION_VAULT_KEY],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
    {
        if let Ok(mut rec) = vault.open_proto::<StoredSessionRecord>(&sess_blob) {
            if pts > rec.last_pts {
                rec.last_pts = pts;
                if let Ok(updated_blob) = vault.seal_proto(&rec) {
                    let _ = tx.execute(
                        "UPDATE kv_vault SET encrypted_val = ?1 WHERE k = ?2",
                        params![updated_blob, SESSION_VAULT_KEY],
                    );
                }
            }
        }
    }

    tx.commit().map_err(|e| e.to_string())
}

fn handle_load_chat_history(
    conn: &Connection,
    vault: &LocalVaultCipher,
    chat_id: u64,
    limit: usize,
    ui_tx: &UnboundedSender<BackendEvent>,
) -> Result<(), String> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT encrypted_proto FROM messages_cache
             WHERE chat_id = ?1
             ORDER BY sort_key DESC
             LIMIT ?2",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map(params![chat_id as i64, limit as i64], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .map_err(|e| e.to_string())?;

    let mut messages = Vec::new();
    for blob in rows.flatten() {
        if let Ok(m) = vault.open_proto::<ChatMessage>(&blob) {
            messages.push(m);
        }
    }
    messages.reverse(); // Ascending chronological order

    let _ = ui_tx.send(BackendEvent::CachedHistoryLoaded { chat_id, messages });
    Ok(())
}

fn compute_sort_key(m: &ChatMessage) -> i64 {
    if m.msg_id > 0 {
        m.msg_id as i64
    } else {
        OPTIMISTIC_SORT_BASE.saturating_add(m.timestamp_ms.max(0))
    }
}

fn handle_upsert_messages(
    conn: &mut Connection,
    vault: &LocalVaultCipher,
    chat_id: u64,
    messages: &[ChatMessage],
) -> Result<(), String> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    {
        let mut del_optimistic = tx
            .prepare_cached(
                "DELETE FROM messages_cache
                 WHERE chat_id = ?1 AND client_random_id = ?2 AND msg_id = 0",
            )
            .map_err(|e| e.to_string())?;

        let mut ins = tx
            .prepare_cached(
                "INSERT INTO messages_cache (chat_id, sort_key, msg_id, client_random_id, encrypted_proto)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(chat_id, sort_key) DO UPDATE SET
                     msg_id = excluded.msg_id,
                     client_random_id = excluded.client_random_id,
                     encrypted_proto = excluded.encrypted_proto",
            )
            .map_err(|e| e.to_string())?;

        for m in messages {
            if m.msg_id > 0 && m.client_random_id != 0 {
                let _ = del_optimistic.execute(params![chat_id as i64, m.client_random_id as i64]);
            }
            let sort_key = compute_sort_key(m);
            let blob = vault.seal_proto(m)?;
            ins.execute(params![
                chat_id as i64,
                sort_key,
                m.msg_id as i64,
                m.client_random_id as i64,
                blob
            ])
            .map_err(|e| e.to_string())?;
        }
    }
    tx.commit().map_err(|e| e.to_string())
}

fn handle_outbox_ack(
    conn: &mut Connection,
    vault: &LocalVaultCipher,
    chat_id: u64,
    client_random_id: u64,
    msg_id: u64,
    timestamp_ms: i64,
    pts: u64,
) -> Result<(), String> {
    let existing: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT sort_key, encrypted_proto FROM messages_cache
             WHERE chat_id = ?1 AND client_random_id = ?2
             LIMIT 1",
            params![chat_id as i64, client_random_id as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let Some((old_sort_key, blob)) = existing else {
        return Ok(());
    };

    let mut msg: ChatMessage = vault.open_proto(&blob)?;
    msg.msg_id = msg_id;
    msg.timestamp_ms = timestamp_ms;
    msg.pts = pts;
    let new_blob = vault.seal_proto(&msg)?;

    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM messages_cache WHERE chat_id = ?1 AND sort_key = ?2",
        params![chat_id as i64, old_sort_key],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO messages_cache (chat_id, sort_key, msg_id, client_random_id, encrypted_proto)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(chat_id, sort_key) DO UPDATE SET encrypted_proto = excluded.encrypted_proto",
        params![
            chat_id as i64,
            msg_id as i64,
            msg_id as i64,
            client_random_id as i64,
            new_blob
        ],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

fn handle_update_read_outbox(
    conn: &mut Connection,
    vault: &LocalVaultCipher,
    chat_id: u64,
    max_read_msg_id: u64,
) -> Result<(), String> {
    let mut rows_to_update = Vec::new();
    {
        let mut stmt = conn
            .prepare_cached(
                "SELECT sort_key, encrypted_proto FROM messages_cache
                 WHERE chat_id = ?1 AND msg_id > 0 AND msg_id <= ?2
                 ORDER BY sort_key DESC LIMIT 200",
            )
            .map_err(|e| e.to_string())?;
        let iter = stmt
            .query_map(params![chat_id as i64, max_read_msg_id as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| e.to_string())?;
        for (sk, blob) in iter.flatten() {
            if let Ok(mut m) = vault.open_proto::<ChatMessage>(&blob) {
                if !m.is_read {
                    m.is_read = true;
                    if let Ok(updated) = vault.seal_proto(&m) {
                        rows_to_update.push((sk, updated));
                    }
                }
            }
        }
    }

    if !rows_to_update.is_empty() {
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        {
            let mut upd = tx
                .prepare_cached(
                    "UPDATE messages_cache SET encrypted_proto = ?1
                     WHERE chat_id = ?2 AND sort_key = ?3",
                )
                .map_err(|e| e.to_string())?;
            for (sk, blob) in rows_to_update {
                let _ = upd.execute(params![blob, chat_id as i64, sk]);
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn handle_update_read_inbox(
    conn: &Connection,
    vault: &LocalVaultCipher,
    chat_id: u64,
    max_read_msg_id: u64,
    unread_count: u32,
) -> Result<(), String> {
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT encrypted_proto FROM dialogs_cache WHERE chat_id = ?1",
            params![chat_id as i64],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    if let Some(blob) = existing {
        if let Ok(mut d) = vault.open_proto::<DialogEntry>(&blob) {
            d.read_inbox_max_msg_id = d.read_inbox_max_msg_id.max(max_read_msg_id);
            d.unread_count = unread_count;
            let new_blob = vault.seal_proto(&d)?;
            let _ = conn.execute(
                "UPDATE dialogs_cache SET encrypted_proto = ?1 WHERE chat_id = ?2",
                params![new_blob, chat_id as i64],
            );
        }
    }
    Ok(())
}

/// Generates `count` (e.g. 20,000) realistic messages in a single WAL transaction to benchmark 120 FPS virtual scrolling.
fn handle_generate_stress_history(
    conn: &mut Connection,
    vault: &LocalVaultCipher,
    chat_id: u64,
    self_user_id: u64,
    peer_user_id: u64,
    count: usize,
    ui_tx: &UnboundedSender<BackendEvent>,
) -> Result<(), String> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let base_ts = now_ms - (count as i64) * 15_000;

    let samples = [
        "Проверяем нативную виртуализацию ленты сообщений на wgpu без единого веб-компонента.",
        "Скроллинг 20 000+ сообщений держит стабильные 120 FPS и потребление ОЗУ < 50 МБ!",
        "Пакеты шифруются ChaCha20-Poly1305 с эфемерным обменом ключами X25519.",
        "Локальный кэш SQLite3 работает в режиме WAL в отдельном StorageThread.",
        "Никакого Electron, Tauri, CEF или QML — чистый машинный код Rust.",
        "Короткое сообщение 👍",
    ];

    let mut generated = Vec::with_capacity(count);
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    {
        let mut ins = tx
            .prepare_cached(
                "INSERT INTO messages_cache (chat_id, sort_key, msg_id, client_random_id, encrypted_proto)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(chat_id, sort_key) DO UPDATE SET encrypted_proto = excluded.encrypted_proto",
            )
            .map_err(|e| e.to_string())?;

        for i in 0..count {
            let msg_id = 1_000_000 + (i as u64);
            let outgoing = (i % 5) >= 2;
            let sender_id = if outgoing {
                self_user_id
            } else if peer_user_id != 0 {
                peer_user_id
            } else {
                1
            };
            let msg = ChatMessage {
                msg_id,
                chat_id,
                sender_id,
                client_random_id: msg_id,
                timestamp_ms: base_ts + (i as i64) * 15_000,
                text: format!("[#{}] {}", i + 1, samples[i % samples.len()]),
                reply_to_msg_id: 0,
                media: None,
                is_read: true,
                pts: 0,
            };
            let blob = vault.seal_proto(&msg)?;
            ins.execute(params![
                chat_id as i64,
                msg_id as i64,
                msg_id as i64,
                msg_id as i64,
                blob
            ])
            .map_err(|e| e.to_string())?;
            generated.push(msg);
        }
    }
    tx.commit().map_err(|e| e.to_string())?;

    let _ = ui_tx.send(BackendEvent::CachedHistoryLoaded {
        chat_id,
        messages: generated,
    });
    Ok(())
}
