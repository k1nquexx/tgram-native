use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info};
use tgram_proto::{
    MediaAttachment, MediaDownloadChunkRequest, MediaDownloadChunkResponse, MediaUploadChunkAck,
    MediaUploadChunkRequest, MediaUploadInitRequest, MediaUploadInitResponse,
};

use crate::error::{ServerError, ServerResult};

pub const RECOMMENDED_CHUNK_SIZE: u32 = 64 * 1024; // 64 KiB
pub const MAX_DOWNLOAD_CHUNK_SIZE: u32 = 256 * 1024; // 256 KiB
pub const MAX_MEDIA_SIZE_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB
pub const DEFAULT_MAX_UPLOADS_PER_USER: usize = 4;
pub const DEFAULT_MAX_TOTAL_UPLOADS: usize = 1_024;
pub const DEFAULT_UPLOAD_SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_CACHED_ATTACHMENTS: usize = 10_000;

#[derive(Default)]
struct UploadQuotaTracker {
    per_user: HashMap<u64, usize>,
    total_active: usize,
}

/// RAII slot reservation guard ensuring per-user and global upload counters never leak on drop, abort, or panic.
struct UploadSlotGuard {
    user_id: u64,
    tracker: Arc<StdMutex<UploadQuotaTracker>>,
}

impl Drop for UploadSlotGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.tracker.lock() {
            guard.total_active = guard.total_active.saturating_sub(1);
            if let Some(cnt) = guard.per_user.get_mut(&self.user_id) {
                *cnt = cnt.saturating_sub(1);
                if *cnt == 0 {
                    guard.per_user.remove(&self.user_id);
                }
            }
        }
    }
}

struct UploadSession {
    owner_user_id: u64,
    file_name: String,
    mime_type: String,
    declared_size: u64,
    expected_sha256: [u8; 32],
    width: u32,
    height: u32,
    temp_path: PathBuf,
    last_active_elapsed_ms: AtomicU64,
    _quota_guard: UploadSlotGuard,
    state: Mutex<UploadProgressState>,
}

struct UploadProgressState {
    file: File,
    hasher: Sha256,
    next_chunk_index: u32,
    bytes_received: u64,
}

pub struct MediaManager {
    root_dir: PathBuf,
    started_at: Instant,
    max_uploads_per_user: usize,
    max_total_uploads: usize,
    session_ttl: Duration,
    quota_tracker: Arc<StdMutex<UploadQuotaTracker>>,
    in_flight: DashMap<String, UploadSession>,
    by_id: DashMap<String, MediaAttachment>,
}

impl MediaManager {
    pub async fn new(root_dir: PathBuf) -> ServerResult<Self> {
        Self::with_limits(
            root_dir,
            DEFAULT_MAX_UPLOADS_PER_USER,
            DEFAULT_MAX_TOTAL_UPLOADS,
            DEFAULT_UPLOAD_SESSION_TTL,
        )
        .await
    }

    pub async fn with_limits(
        root_dir: PathBuf,
        max_uploads_per_user: usize,
        max_total_uploads: usize,
        session_ttl: Duration,
    ) -> ServerResult<Self> {
        fs::create_dir_all(&root_dir)
            .await
            .map_err(|e| ServerError::Internal(format!("failed to create media dir: {e}")))?;

        sweep_orphan_part_files(&root_dir).await;

        Ok(Self {
            root_dir,
            started_at: Instant::now(),
            max_uploads_per_user: max_uploads_per_user.max(1),
            max_total_uploads: max_total_uploads.max(1),
            session_ttl,
            quota_tracker: Arc::new(StdMutex::new(UploadQuotaTracker::default())),
            in_flight: DashMap::new(),
            by_id: DashMap::new(),
        })
    }

    /// Spawns the periodic background worker that evicts abandoned `.part` upload sessions and closes open FDs.
    pub fn start_cleanup_worker(manager: Arc<Self>) -> JoinHandle<()> {
        let check_period = (manager.session_ttl / 2)
            .clamp(Duration::from_millis(50), Duration::from_secs(60));

        tokio::spawn(async move {
            let mut ticker = interval(check_period);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            ticker.tick().await; // Skip immediate tick

            loop {
                ticker.tick().await;
                let evicted = manager.cleanup_expired_sessions().await;
                if evicted > 0 {
                    info!(
                        evicted_sessions = evicted,
                        remaining_in_flight = manager.in_flight.len(),
                        "Cleaned up expired zombie upload sessions"
                    );
                }
            }
        })
    }

    /// Evicts any in-flight upload sessions inactive for at least `self.session_ttl`, closing FDs and deleting `.part` files.
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let now_ms = self.elapsed_ms();
        let ttl_ms = (self.session_ttl.as_millis() as u64).max(1);

        let candidates: Vec<String> = self
            .in_flight
            .iter()
            .filter_map(|entry| {
                let last_ms = entry.value().last_active_elapsed_ms.load(Ordering::Acquire);
                if now_ms.saturating_sub(last_ms) >= ttl_ms {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        let mut evicted = 0usize;
        for upload_id in candidates {
            let removed = self.in_flight.remove_if(&upload_id, |_, s| {
                let last_ms = s.last_active_elapsed_ms.load(Ordering::Acquire);
                now_ms.saturating_sub(last_ms) >= ttl_ms
            });

            if let Some((_, session)) = removed {
                let temp_path = session.temp_path.clone();
                // Drop `session` FIRST so `File` handle closes on Windows before `remove_file`
                drop(session);
                let _ = fs::remove_file(&temp_path).await;
                debug!(%upload_id, "Evicted expired upload session");
                evicted += 1;
            }
        }

        evicted
    }

    /// Aborts all remaining in-flight upload sessions cleanly on server shutdown.
    pub async fn abort_all_uploads(&self) {
        let keys: Vec<String> = self.in_flight.iter().map(|e| e.key().clone()).collect();
        for key in keys {
            if let Some((_, session)) = self.in_flight.remove(&key) {
                let temp_path = session.temp_path.clone();
                drop(session);
                let _ = fs::remove_file(&temp_path).await;
            }
        }
    }

    #[inline]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    #[inline]
    pub fn validate_media_id(media_id: &str) -> ServerResult<()> {
        validate_safe_id(media_id, "media_id")
    }

    pub fn get_attachment(&self, media_id: &str) -> Option<MediaAttachment> {
        if validate_safe_id(media_id, "media_id").is_err() {
            return None;
        }
        self.by_id.get(media_id).map(|entry| entry.value().clone())
    }

    pub fn register_existing(&self, attachment: MediaAttachment) {
        if validate_safe_id(&attachment.media_id, "media_id").is_ok() {
            if self.by_id.len() >= MAX_CACHED_ATTACHMENTS {
                if let Some(evict_key) = self.by_id.iter().next().map(|e| e.key().clone()) {
                    self.by_id.remove(&evict_key);
                }
            }
            self.by_id.insert(attachment.media_id.clone(), attachment);
        }
    }

    /// Removes an orphaned media file from disk and memory cache if database metadata persistence fails (`HIGH-04`).
    pub async fn remove_orphaned_media(&self, media_id: &str) {
        if validate_safe_id(media_id, "media_id").is_ok() {
            self.by_id.remove(media_id);
            let path = self.media_path(media_id);
            let _ = fs::remove_file(&path).await;
        }
    }

    pub async fn init_upload(
        &self,
        user_id: u64,
        req: MediaUploadInitRequest,
    ) -> ServerResult<MediaUploadInitResponse> {
        if req.file_name.trim().is_empty() || req.file_name.len() > 255 {
            return Err(ServerError::BadRequest(
                "file_name must be 1..255 bytes".to_owned(),
            ));
        }
        if req.size_bytes == 0 || req.size_bytes > MAX_MEDIA_SIZE_BYTES {
            return Err(ServerError::PayloadTooLarge(format!(
                "file size {} must be between 1B and {}B",
                req.size_bytes, MAX_MEDIA_SIZE_BYTES
            )));
        }
        let expected_sha256: [u8; 32] = req
            .sha256_hash
            .as_slice()
            .try_into()
            .map_err(|_| ServerError::BadRequest("sha256_hash must be 32 bytes".to_owned()))?;

        // Enforce strict per-user & global active upload caps BEFORE opening any OS file descriptor.
        // Note: Unauthenticated hash-only CAS deduplication is intentionally disabled to prevent
        // side-channel file-existence probing and unauthorized media_id disclosure (CWE-639/CWE-345).
        let quota_guard = self.reserve_upload_slot(user_id)?;

        let upload_id = random_hex_id("upl");
        let temp_path = self.root_dir.join(format!("{upload_id}.part"));
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)
            .await
            .map_err(|e| ServerError::Internal(format!("open temp upload failed: {e}")))?;

        let now_elapsed = self.elapsed_ms();
        let session = UploadSession {
            owner_user_id: user_id,
            file_name: sanitize_filename(&req.file_name),
            mime_type: if req.mime_type.trim().is_empty() {
                "application/octet-stream".to_owned()
            } else {
                req.mime_type
            },
            declared_size: req.size_bytes,
            expected_sha256,
            width: req.width,
            height: req.height,
            temp_path,
            last_active_elapsed_ms: AtomicU64::new(now_elapsed),
            _quota_guard: quota_guard,
            state: Mutex::new(UploadProgressState {
                file,
                hasher: Sha256::new(),
                next_chunk_index: 0,
                bytes_received: 0,
            }),
        };

        self.in_flight.insert(upload_id.clone(), session);

        Ok(MediaUploadInitResponse {
            upload_id,
            chunk_size: RECOMMENDED_CHUNK_SIZE,
            already_deduped: false,
            ready_media_id: String::new(),
        })
    }

    pub async fn append_chunk(
        &self,
        user_id: u64,
        req: MediaUploadChunkRequest,
    ) -> ServerResult<(MediaUploadChunkAck, Option<MediaAttachment>)> {
        validate_safe_id(&req.upload_id, "upload_id")?;

        if req.data.len() > MAX_DOWNLOAD_CHUNK_SIZE as usize {
            return Err(ServerError::PayloadTooLarge(
                "upload chunk exceeds 256 KiB".to_owned(),
            ));
        }

        // Verify ownership BEFORE mutating or removing any session state
        {
            let session_ref = self
                .in_flight
                .get(&req.upload_id)
                .ok_or_else(|| ServerError::BadRequest("unknown upload_id".to_owned()))?;
            if session_ref.owner_user_id != user_id {
                return Err(ServerError::Unauthorized);
            }
        }

        if !req.is_last_chunk {
            let chunk_outcome: ServerResult<u64> = {
                let session_ref = self
                    .in_flight
                    .get(&req.upload_id)
                    .ok_or_else(|| ServerError::BadRequest("unknown upload_id".to_owned()))?;

                if session_ref.owner_user_id != user_id {
                    return Err(ServerError::Unauthorized);
                }

                session_ref
                    .last_active_elapsed_ms
                    .store(self.elapsed_ms(), Ordering::Release);

                let mut guard = session_ref.state.lock().await;
                if req.chunk_index != guard.next_chunk_index {
                    Err(ServerError::BadRequest(format!(
                        "out-of-order chunk: expected {}, got {}",
                        guard.next_chunk_index, req.chunk_index
                    )))
                } else {
                    let next_total = guard.bytes_received + req.data.len() as u64;
                    if next_total > session_ref.declared_size {
                        Err(ServerError::BadRequest(
                            "received bytes exceed declared size".to_owned(),
                        ))
                    } else if let Err(e) = guard.file.write_all(&req.data).await {
                        Err(ServerError::Internal(format!("chunk write error: {e}")))
                    } else {
                        guard.hasher.update(&req.data);
                        guard.bytes_received = next_total;
                        guard.next_chunk_index += 1;
                        Ok(next_total)
                    }
                }
            };

            match chunk_outcome {
                Ok(next_total) => {
                    return Ok((
                        MediaUploadChunkAck {
                            upload_id: req.upload_id,
                            chunk_index: req.chunk_index,
                            bytes_received: next_total,
                            media_id: String::new(),
                        },
                        None,
                    ));
                }
                Err(err) => {
                    // Immediately abort broken session & clean up its `.part` file and FD
                    self.abort_single_upload(&req.upload_id, user_id).await;
                    return Err(err);
                }
            }
        }

        // Final chunk: atomically remove owned session, verify SHA-256, and promote file
        let removed = self
            .in_flight
            .remove_if(&req.upload_id, |_, s| s.owner_user_id == user_id)
            .ok_or_else(|| ServerError::BadRequest("unknown upload_id".to_owned()))?;
        let (_, session) = removed;

        let temp_path = session.temp_path.clone();
        let declared_size = session.declared_size;
        let expected_sha256 = session.expected_sha256;
        let file_name = session.file_name;
        let mime_type = session.mime_type;
        let width = session.width;
        let height = session.height;
        let _quota_guard = session._quota_guard;
        let mut state = session.state.into_inner();

        if req.chunk_index != state.next_chunk_index {
            drop(state.file);
            let _ = fs::remove_file(&temp_path).await;
            return Err(ServerError::BadRequest(format!(
                "out-of-order final chunk: expected {}, got {}",
                state.next_chunk_index, req.chunk_index
            )));
        }

        let final_total = state.bytes_received + req.data.len() as u64;
        if final_total != declared_size {
            drop(state.file);
            let _ = fs::remove_file(&temp_path).await;
            return Err(ServerError::BadRequest(format!(
                "final byte size mismatch: declared {}, got {}",
                declared_size, final_total
            )));
        }

        if let Err(e) = state.file.write_all(&req.data).await {
            drop(state.file);
            let _ = fs::remove_file(&temp_path).await;
            return Err(ServerError::Internal(format!("final chunk write error: {e}")));
        }
        if let Err(e) = state.file.flush().await {
            drop(state.file);
            let _ = fs::remove_file(&temp_path).await;
            return Err(ServerError::Internal(format!("flush error: {e}")));
        }
        drop(state.file); // Close file handle on Windows before atomic rename

        state.hasher.update(&req.data);
        let actual_digest = state.hasher.finalize();
        if actual_digest.as_slice() != expected_sha256 {
            let _ = fs::remove_file(&temp_path).await;
            return Err(ServerError::BadRequest(
                "SHA-256 integrity verification failed".to_owned(),
            ));
        }

        let media_id = random_hex_id("med");
        let final_path = self.media_path(&media_id);
        if let Err(e) = fs::rename(&temp_path, &final_path).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(ServerError::Internal(format!(
                "atomic media commit failed: {e}"
            )));
        }

        let attachment = MediaAttachment {
            media_id: media_id.clone(),
            file_name,
            mime_type,
            size_bytes: final_total,
            sha256_hash: expected_sha256.to_vec(),
            width,
            height,
        };

        self.register_existing(attachment.clone());

        Ok((
            MediaUploadChunkAck {
                upload_id: req.upload_id,
                chunk_index: req.chunk_index,
                bytes_received: final_total,
                media_id,
            },
            Some(attachment),
        ))
    }

    pub async fn read_chunk(
        &self,
        req: MediaDownloadChunkRequest,
    ) -> ServerResult<MediaDownloadChunkResponse> {
        validate_safe_id(&req.media_id, "media_id")?;
        let meta = self
            .get_attachment(&req.media_id)
            .ok_or_else(|| ServerError::BadRequest("media_id not found".to_owned()))?;
        self.read_chunk_with_meta(req, &meta).await
    }

    pub async fn read_chunk_with_meta(
        &self,
        req: MediaDownloadChunkRequest,
        meta: &MediaAttachment,
    ) -> ServerResult<MediaDownloadChunkResponse> {
        validate_safe_id(&req.media_id, "media_id")?;

        let read_len = req.length.clamp(1024, MAX_DOWNLOAD_CHUNK_SIZE) as usize;
        if req.offset >= meta.size_bytes {
            return Ok(MediaDownloadChunkResponse {
                media_id: req.media_id,
                offset: req.offset,
                total_size: meta.size_bytes,
                data: Vec::new(),
                eof: true,
            });
        }

        let path = self.media_path(&req.media_id);
        let mut file = File::open(&path)
            .await
            .map_err(|e| ServerError::Internal(format!("open media file failed: {e}")))?;

        file.seek(SeekFrom::Start(req.offset))
            .await
            .map_err(|e| ServerError::Internal(format!("seek media file failed: {e}")))?;

        let remaining = (meta.size_bytes - req.offset) as usize;
        let to_read = remaining.min(read_len);
        let mut buf = vec![0u8; to_read];
        file.read_exact(&mut buf)
            .await
            .map_err(|e| ServerError::Internal(format!("read media chunk failed: {e}")))?;

        let eof = req.offset + (to_read as u64) >= meta.size_bytes;
        Ok(MediaDownloadChunkResponse {
            media_id: req.media_id,
            offset: req.offset,
            total_size: meta.size_bytes,
            data: buf,
            eof,
        })
    }

    fn reserve_upload_slot(&self, user_id: u64) -> ServerResult<UploadSlotGuard> {
        let mut guard = self
            .quota_tracker
            .lock()
            .map_err(|_| ServerError::Internal("upload quota lock poisoned".to_owned()))?;

        if guard.total_active >= self.max_total_uploads {
            return Err(ServerError::RateLimited(5_000));
        }
        let user_active = guard.per_user.get(&user_id).copied().unwrap_or(0);
        if user_active >= self.max_uploads_per_user {
            return Err(ServerError::RateLimited(5_000));
        }

        guard.total_active += 1;
        guard.per_user.insert(user_id, user_active + 1);
        drop(guard);

        Ok(UploadSlotGuard {
            user_id,
            tracker: Arc::clone(&self.quota_tracker),
        })
    }

    async fn abort_single_upload(&self, upload_id: &str, user_id: u64) {
        if let Some((_, session)) = self
            .in_flight
            .remove_if(upload_id, |_, s| s.owner_user_id == user_id)
        {
            let temp_path = session.temp_path.clone();
            drop(session);
            let _ = fs::remove_file(&temp_path).await;
        }
    }

    #[inline]
    fn elapsed_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }

    fn media_path(&self, media_id: &str) -> PathBuf {
        self.root_dir.join(format!("{media_id}.bin"))
    }
}

fn validate_safe_id(id: &str, label: &str) -> ServerResult<()> {
    if id.is_empty()
        || id.len() > 64
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(ServerError::BadRequest(format!("invalid {label} format")));
    }
    Ok(())
}

async fn sweep_orphan_part_files(root_dir: &Path) {
    let Ok(mut entries) = fs::read_dir(root_dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("part") {
            let _ = fs::remove_file(&path).await;
        }
    }
}

fn random_hex_id(prefix: &str) -> String {
    let mut rnd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{prefix}_{ts:x}_{}", hex::encode(rnd))
}

fn sanitize_filename(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|&c| {
            !c.is_control()
                && !matches!(
                    c,
                    '/' | '\\'
                        | '\0'
                        | ':'
                        | '*'
                        | '?'
                        | '"'
                        | '<'
                        | '>'
                        | '|'
                        | '\u{200E}'
                        | '\u{200F}'
                        | '\u{061C}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
        .take(180)
        .collect();
    let trimmed = cleaned.trim().trim_matches('.').trim();
    if trimmed.is_empty() {
        "attachment.bin".to_owned()
    } else {
        trimmed.to_owned()
    }
}
