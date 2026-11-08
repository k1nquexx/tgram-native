use std::io::SeekFrom;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tgram_proto::{
    MediaAttachment, MediaDownloadChunkRequest, MediaDownloadChunkResponse, MediaUploadChunkAck,
    MediaUploadChunkRequest, MediaUploadInitRequest, MediaUploadInitResponse,
};

use crate::error::{ServerError, ServerResult};

pub const RECOMMENDED_CHUNK_SIZE: u32 = 64 * 1024; // 64 KiB
pub const MAX_DOWNLOAD_CHUNK_SIZE: u32 = 256 * 1024; // 256 KiB
pub const MAX_MEDIA_SIZE_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB

struct UploadSession {
    owner_user_id: u64,
    file_name: String,
    mime_type: String,
    declared_size: u64,
    expected_sha256: [u8; 32],
    width: u32,
    height: u32,
    temp_path: PathBuf,
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
    in_flight: DashMap<String, UploadSession>,
    by_id: DashMap<String, MediaAttachment>,
    by_sha256: DashMap<[u8; 32], String>,
}

impl MediaManager {
    pub async fn new(root_dir: PathBuf) -> ServerResult<Self> {
        fs::create_dir_all(&root_dir)
            .await
            .map_err(|e| ServerError::Internal(format!("failed to create media dir: {e}")))?;
        Ok(Self {
            root_dir,
            in_flight: DashMap::new(),
            by_id: DashMap::new(),
            by_sha256: DashMap::new(),
        })
    }

    pub fn get_attachment(&self, media_id: &str) -> Option<MediaAttachment> {
        self.by_id.get(media_id).map(|entry| entry.value().clone())
    }

    pub fn register_existing(&self, attachment: MediaAttachment) {
        if let Ok(hash) = <[u8; 32]>::try_from(attachment.sha256_hash.as_slice()) {
            self.by_sha256.insert(hash, attachment.media_id.clone());
        }
        self.by_id.insert(attachment.media_id.clone(), attachment);
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

        // Instant Content-Addressed Deduplication (CAS)
        if let Some(existing_id) = self.by_sha256.get(&expected_sha256) {
            let media_id = existing_id.value().clone();
            if self.media_path(&media_id).exists() {
                return Ok(MediaUploadInitResponse {
                    upload_id: String::new(),
                    chunk_size: RECOMMENDED_CHUNK_SIZE,
                    already_deduped: true,
                    ready_media_id: media_id,
                });
            }
        }

        let upload_id = random_hex_id("upl");
        let temp_path = self.root_dir.join(format!("{upload_id}.part"));
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)
            .await
            .map_err(|e| ServerError::Internal(format!("open temp upload failed: {e}")))?;

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
        if req.data.len() > MAX_DOWNLOAD_CHUNK_SIZE as usize {
            return Err(ServerError::PayloadTooLarge(
                "upload chunk exceeds 256 KiB".to_owned(),
            ));
        }

        if !req.is_last_chunk {
            let session_ref = self
                .in_flight
                .get(&req.upload_id)
                .ok_or_else(|| ServerError::BadRequest("unknown upload_id".to_owned()))?;

            if session_ref.owner_user_id != user_id {
                return Err(ServerError::Unauthorized);
            }

            let mut guard = session_ref.state.lock().await;
            if req.chunk_index != guard.next_chunk_index {
                return Err(ServerError::BadRequest(format!(
                    "out-of-order chunk: expected {}, got {}",
                    guard.next_chunk_index, req.chunk_index
                )));
            }
            let next_total = guard.bytes_received + req.data.len() as u64;
            if next_total > session_ref.declared_size {
                return Err(ServerError::BadRequest(
                    "received bytes exceed declared size".to_owned(),
                ));
            }

            guard
                .file
                .write_all(&req.data)
                .await
                .map_err(|e| ServerError::Internal(format!("chunk write error: {e}")))?;
            guard.hasher.update(&req.data);
            guard.bytes_received = next_total;
            guard.next_chunk_index += 1;

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

        // Final chunk: atomically remove in-flight session, verify SHA-256, promote file
        let (_, session) = self
            .in_flight
            .remove(&req.upload_id)
            .ok_or_else(|| ServerError::BadRequest("unknown upload_id".to_owned()))?;

        if session.owner_user_id != user_id {
            let _ = fs::remove_file(&session.temp_path).await;
            return Err(ServerError::Unauthorized);
        }

        let mut state = session.state.into_inner();
        if req.chunk_index != state.next_chunk_index {
            drop(state.file);
            let _ = fs::remove_file(&session.temp_path).await;
            return Err(ServerError::BadRequest(format!(
                "out-of-order final chunk: expected {}, got {}",
                state.next_chunk_index, req.chunk_index
            )));
        }

        let final_total = state.bytes_received + req.data.len() as u64;
        if final_total != session.declared_size {
            drop(state.file);
            let _ = fs::remove_file(&session.temp_path).await;
            return Err(ServerError::BadRequest(format!(
                "final byte size mismatch: declared {}, got {}",
                session.declared_size, final_total
            )));
        }

        state
            .file
            .write_all(&req.data)
            .await
            .map_err(|e| ServerError::Internal(format!("final chunk write error: {e}")))?;
        state
            .file
            .flush()
            .await
            .map_err(|e| ServerError::Internal(format!("flush error: {e}")))?;
        drop(state.file); // Close file handle on Windows before atomic rename

        state.hasher.update(&req.data);
        let actual_digest = state.hasher.finalize();
        if actual_digest.as_slice() != session.expected_sha256 {
            let _ = fs::remove_file(&session.temp_path).await;
            return Err(ServerError::BadRequest(
                "SHA-256 integrity verification failed".to_owned(),
            ));
        }

        let media_id = random_hex_id("med");
        let final_path = self.media_path(&media_id);
        fs::rename(&session.temp_path, &final_path)
            .await
            .map_err(|e| ServerError::Internal(format!("atomic media commit failed: {e}")))?;

        let attachment = MediaAttachment {
            media_id: media_id.clone(),
            file_name: session.file_name,
            mime_type: session.mime_type,
            size_bytes: final_total,
            sha256_hash: session.expected_sha256.to_vec(),
            width: session.width,
            height: session.height,
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
        let meta = self
            .get_attachment(&req.media_id)
            .ok_or_else(|| ServerError::BadRequest("media_id not found".to_owned()))?;

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

    fn media_path(&self, media_id: &str) -> PathBuf {
        self.root_dir.join(format!("{media_id}.bin"))
    }
}

fn random_hex_id(prefix: &str) -> String {
    let mut rnd = [0u8; 12];
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
        .filter(|c| !matches!(c, '/' | '\\' | '\0' | ':'))
        .take(180)
        .collect();
    if cleaned.trim().is_empty() {
        "attachment.bin".to_owned()
    } else {
        cleaned
    }
}
