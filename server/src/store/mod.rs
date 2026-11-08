pub mod memory;
pub mod postgres;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tgram_proto::{
    AuthRequest, ChatMessage, CreateDirectChatResponse, GetHistoryResponse, MediaAttachment,
    SearchPeersResponse, SendMessageRequest, SyncDialogsResponse, UserProfile,
};

use crate::error::ServerResult;
use crate::store::memory::MemoryStore;
use crate::store::postgres::PostgresStore;

#[derive(Debug, Clone)]
pub struct AuthSessionOutcome {
    pub profile: UserProfile,
    pub raw_session_token: [u8; 32],
    pub token_sha256: [u8; 32],
    pub current_pts: u64,
}

#[derive(Debug, Clone)]
pub struct RecipientDeliveryTarget {
    pub user_id: u64,
    pub unread_count: u32,
    pub pts: u64,
}

#[derive(Debug, Clone)]
pub struct PersistMessageOutcome {
    pub message: ChatMessage,
    pub sender_profile: UserProfile,
    pub sender_pts: u64,
    pub recipients: Vec<RecipientDeliveryTarget>,
    pub was_duplicate: bool,
}

#[derive(Debug, Clone)]
pub struct MarkReadOutcome {
    pub chat_id: u64,
    pub max_read_msg_id: u64,
    pub unread_count: u32,
    pub reader_pts: u64,
    pub notify_peers: Vec<(u64, u64)>, // (peer_user_id, peer_pts)
}

#[derive(Clone)]
pub enum StorageEngine {
    Memory(Arc<MemoryStore>),
    Postgres(Arc<PostgresStore>),
}

impl StorageEngine {
    pub fn new_memory(seed_demo: bool) -> Self {
        Self::Memory(Arc::new(MemoryStore::new(seed_demo)))
    }

    pub async fn new_postgres(
        database_url: &str,
        redis_url: Option<&str>,
    ) -> ServerResult<Self> {
        let pg = PostgresStore::connect(database_url, redis_url).await?;
        Ok(Self::Postgres(Arc::new(pg)))
    }

    pub async fn authenticate(&self, req: AuthRequest) -> ServerResult<AuthSessionOutcome> {
        match self {
            Self::Memory(s) => s.authenticate(req).await,
            Self::Postgres(s) => s.authenticate(req).await,
        }
    }

    pub async fn revoke_session(&self, token_sha256: &[u8; 32]) -> ServerResult<bool> {
        match self {
            Self::Memory(s) => s.revoke_session(token_sha256).await,
            Self::Postgres(s) => s.revoke_session(token_sha256).await,
        }
    }

    pub async fn set_presence(
        &self,
        user_id: u64,
        online: bool,
        now_ms: i64,
    ) -> ServerResult<Vec<u64>> {
        match self {
            Self::Memory(s) => s.set_presence(user_id, online, now_ms).await,
            Self::Postgres(s) => s.set_presence(user_id, online, now_ms).await,
        }
    }

    pub async fn sync_dialogs(
        &self,
        user_id: u64,
        limit: u32,
        online_checker: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> ServerResult<SyncDialogsResponse> {
        match self {
            Self::Memory(s) => s.sync_dialogs(user_id, limit, online_checker).await,
            Self::Postgres(s) => s.sync_dialogs(user_id, limit, online_checker).await,
        }
    }

    pub async fn get_history(
        &self,
        user_id: u64,
        chat_id: u64,
        before_msg_id: u64,
        limit: u32,
    ) -> ServerResult<GetHistoryResponse> {
        match self {
            Self::Memory(s) => s.get_history(user_id, chat_id, before_msg_id, limit).await,
            Self::Postgres(s) => s.get_history(user_id, chat_id, before_msg_id, limit).await,
        }
    }

    pub async fn search_peers(
        &self,
        user_id: u64,
        query: &str,
        limit: u32,
        online_checker: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> ServerResult<SearchPeersResponse> {
        match self {
            Self::Memory(s) => s.search_peers(user_id, query, limit, online_checker).await,
            Self::Postgres(s) => s.search_peers(user_id, query, limit, online_checker).await,
        }
    }

    pub async fn get_or_create_direct_chat(
        &self,
        user_id: u64,
        target_user_id: u64,
        online_checker: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> ServerResult<CreateDirectChatResponse> {
        match self {
            Self::Memory(s) => {
                s.get_or_create_direct_chat(user_id, target_user_id, online_checker)
                    .await
            }
            Self::Postgres(s) => {
                s.get_or_create_direct_chat(user_id, target_user_id, online_checker)
                    .await
            }
        }
    }

    pub async fn persist_message(
        &self,
        sender_id: u64,
        req: SendMessageRequest,
        media: Option<MediaAttachment>,
        now_ms: i64,
    ) -> ServerResult<PersistMessageOutcome> {
        match self {
            Self::Memory(s) => s.persist_message(sender_id, req, media, now_ms).await,
            Self::Postgres(s) => s.persist_message(sender_id, req, media, now_ms).await,
        }
    }

    pub async fn mark_read(
        &self,
        reader_id: u64,
        chat_id: u64,
        max_read_msg_id: u64,
        now_ms: i64,
    ) -> ServerResult<MarkReadOutcome> {
        match self {
            Self::Memory(s) => s.mark_read(reader_id, chat_id, max_read_msg_id, now_ms).await,
            Self::Postgres(s) => s.mark_read(reader_id, chat_id, max_read_msg_id, now_ms).await,
        }
    }

    pub async fn chat_member_ids(&self, user_id: u64, chat_id: u64) -> ServerResult<Vec<u64>> {
        match self {
            Self::Memory(s) => s.chat_member_ids(user_id, chat_id).await,
            Self::Postgres(s) => s.chat_member_ids(user_id, chat_id).await,
        }
    }

    pub async fn save_media_metadata(
        &self,
        uploader_user_id: u64,
        media: &MediaAttachment,
        now_ms: i64,
    ) -> ServerResult<()> {
        match self {
            Self::Memory(s) => s.save_media_metadata(uploader_user_id, media, now_ms).await,
            Self::Postgres(s) => s.save_media_metadata(uploader_user_id, media, now_ms).await,
        }
    }

    pub async fn get_media_attachment(&self, media_id: &str) -> ServerResult<Option<MediaAttachment>> {
        match self {
            Self::Memory(s) => s.get_media_attachment(media_id).await,
            Self::Postgres(s) => s.get_media_attachment(media_id).await,
        }
    }

    pub async fn user_has_access_to_media(
        &self,
        user_id: u64,
        media_id: &str,
    ) -> ServerResult<bool> {
        match self {
            Self::Memory(s) => s.user_has_access_to_media(user_id, media_id).await,
            Self::Postgres(s) => s.user_has_access_to_media(user_id, media_id).await,
        }
    }
}

#[inline]
pub fn unix_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Escapes PostgreSQL `LIKE` pattern metacharacters (`\`, `%`, `_`) so untrusted peer search
/// queries cannot inject arbitrary wildcard expansions (`ESCAPE '\'`).
pub fn escape_sql_like(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len() + 4);
    for ch in raw.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '%' => escaped.push_str("\\%"),
            '_' => escaped.push_str("\\_"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::escape_sql_like;

    #[test]
    fn escapes_postgres_like_wildcards_and_backslashes() {
        assert_eq!(escape_sql_like("alice"), "alice");
        assert_eq!(escape_sql_like("100%_admin\\test"), "100\\%\\_admin\\\\test");
        assert_eq!(escape_sql_like("___%%%"), "\\_\\_\\_\\%\\%\\%");
    }
}
