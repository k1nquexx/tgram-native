use std::collections::HashSet;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tgram_proto::{
    AuthMethod, AuthRequest, ChatMessage, CreateDirectChatResponse, DialogEntry,
    GetHistoryResponse, MediaAttachment, PeerType, SearchPeersResponse, SendMessageRequest,
    SyncDialogsResponse, UserOnlineState, UserProfile,
};

use crate::auth::{
    avatar_color_for_id, dummy_password_phc, generate_session_token, hash_password_async,
    hash_session_token, normalize_username, validate_password, verify_password_constant_time,
};
use crate::error::{ServerError, ServerResult};
use crate::store::{
    escape_sql_like, unix_millis_now, AuthSessionOutcome, MarkReadOutcome, PersistMessageOutcome,
    RecipientDeliveryTarget,
};

const SCHEMA_SQL: &str = include_str!("../../migrations/001_init.sql");
const SESSION_CACHE_TTL_SECS: u64 = 15 * 60;
const PRESENCE_TTL_SECS: u64 = 90;

pub struct PostgresStore {
    pool: PgPool,
    redis: Option<ConnectionManager>,
}

impl PostgresStore {
    pub async fn connect(database_url: &str, redis_url: Option<&str>) -> ServerResult<Self> {
        let _ = dummy_password_phc();
        let pool = PgPoolOptions::new()
            .max_connections(32)
            .connect(database_url)
            .await
            .map_err(|e| ServerError::Database(format!("PostgreSQL connect failed: {e}")))?;

        sqlx::raw_sql(SCHEMA_SQL)
            .execute(&pool)
            .await
            .map_err(|e| ServerError::Database(format!("PostgreSQL migration failed: {e}")))?;

        let redis = if let Some(r_url) = redis_url {
            let client = redis::Client::open(r_url)
                .map_err(|e| ServerError::Database(format!("Redis URL invalid: {e}")))?;
            let mgr = ConnectionManager::new(client)
                .await
                .map_err(|e| ServerError::Database(format!("Redis connect failed: {e}")))?;
            Some(mgr)
        } else {
            None
        };

        Ok(Self { pool, redis })
    }

    pub async fn authenticate(&self, req: AuthRequest) -> ServerResult<AuthSessionOutcome> {
        let now = unix_millis_now();
        let method = AuthMethod::try_from(req.method).unwrap_or(AuthMethod::Unspecified);

        match method {
            AuthMethod::Register => {
                let uname = normalize_username(&req.username)?;
                validate_password(&req.password)?;

                let exists: Option<i64> =
                    sqlx::query_scalar("SELECT user_id FROM users WHERE LOWER(username) = $1")
                        .bind(&uname)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(db_err)?;
                if exists.is_some() {
                    return Err(ServerError::UsernameTaken(uname));
                }

                let password_phc = hash_password_async(req.password).await?;
                let display_name: String = if req.display_name.trim().is_empty() {
                    uname.clone()
                } else {
                    req.display_name.trim().chars().take(64).collect()
                };
                let provisional_color = avatar_color_for_id(now as u64) as i64;

                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let row = sqlx::query(
                    "INSERT INTO users (username, display_name, password_phc, avatar_color_rgb, last_seen_ms, current_pts, created_at_ms)
                     VALUES ($1, $2, $3, $4, $5, 1, $5)
                     RETURNING user_id",
                )
                .bind(&uname)
                .bind(&display_name)
                .bind(&password_phc)
                .bind(provisional_color)
                .bind(now)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| {
                    if e.to_string().contains("unique") {
                        ServerError::UsernameTaken(uname.clone())
                    } else {
                        db_err(e)
                    }
                })?;

                let user_id = row.try_get::<i64, _>("user_id").map_err(db_err)? as u64;
                let final_color = avatar_color_for_id(user_id);
                sqlx::query("UPDATE users SET avatar_color_rgb = $1 WHERE user_id = $2")
                    .bind(final_color as i64)
                    .bind(user_id as i64)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;

                // Create Saved Messages ("Избранное") direct chat
                let self_pair = format!("{user_id}:{user_id}");
                let chat_row = sqlx::query(
                    "INSERT INTO chats (peer_type, title, avatar_color_rgb, direct_pair_key, created_at_ms)
                     VALUES ($1, 'Избранное', $2, $3, $4)
                     RETURNING chat_id",
                )
                .bind(PeerType::Direct as i32)
                .bind(0x65AADD_i64)
                .bind(&self_pair)
                .bind(now)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
                let self_chat_id: i64 = chat_row.try_get("chat_id").map_err(db_err)?;

                sqlx::query(
                    "INSERT INTO chat_members (chat_id, user_id, joined_at_ms) VALUES ($1, $2, $3)",
                )
                .bind(self_chat_id)
                .bind(user_id as i64)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;

                let (raw_token, token_sha256) = generate_session_token();
                sqlx::query(
                    "INSERT INTO user_sessions (token_sha256, user_id, device_name, created_at_ms, last_active_ms)
                     VALUES ($1, $2, $3, $4, $4)",
                )
                .bind(&token_sha256[..])
                .bind(user_id as i64)
                .bind(&req.device_name)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;

                tx.commit().await.map_err(db_err)?;
                self.cache_session_in_redis(&token_sha256, user_id).await;

                Ok(AuthSessionOutcome {
                    profile: UserProfile {
                        user_id,
                        username: uname,
                        display_name,
                        avatar_color_rgb: final_color,
                        avatar_media_id: String::new(),
                        status: UserOnlineState::Online as i32,
                        last_seen_ms: now,
                    },
                    raw_session_token: raw_token,
                    token_sha256,
                    current_pts: 1,
                })
            }

            AuthMethod::Login => {
                let uname = normalize_username(&req.username)?;
                if req.password.len() > 256 {
                    return Err(ServerError::InvalidCredentials);
                }
                let maybe_row = sqlx::query(
                    "SELECT user_id, username, display_name, password_phc, avatar_color_rgb, avatar_media_id, current_pts
                     FROM users WHERE LOWER(username) = $1",
                )
                .bind(&uname)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;

                let maybe_phc = match maybe_row.as_ref() {
                    Some(r) => Some(r.try_get::<String, _>("password_phc").map_err(db_err)?),
                    None => None,
                };

                if !verify_password_constant_time(req.password, maybe_phc).await? {
                    return Err(ServerError::InvalidCredentials);
                }

                let row = maybe_row.ok_or(ServerError::InvalidCredentials)?;
                let user_id = row.try_get::<i64, _>("user_id").map_err(db_err)? as u64;
                let current_pts = row.try_get::<i64, _>("current_pts").map_err(db_err)? as u64;

                let (raw_token, token_sha256) = generate_session_token();
                sqlx::query(
                    "INSERT INTO user_sessions (token_sha256, user_id, device_name, created_at_ms, last_active_ms)
                     VALUES ($1, $2, $3, $4, $4)",
                )
                .bind(&token_sha256[..])
                .bind(user_id as i64)
                .bind(&req.device_name)
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(db_err)?;

                sqlx::query("UPDATE users SET last_seen_ms = $1 WHERE user_id = $2")
                    .bind(now)
                    .bind(user_id as i64)
                    .execute(&self.pool)
                    .await
                    .map_err(db_err)?;

                self.cache_session_in_redis(&token_sha256, user_id).await;

                Ok(AuthSessionOutcome {
                    profile: UserProfile {
                        user_id,
                        username: row.try_get("username").map_err(db_err)?,
                        display_name: row.try_get("display_name").map_err(db_err)?,
                        avatar_color_rgb: row.try_get::<i64, _>("avatar_color_rgb").map_err(db_err)?
                            as u32,
                        avatar_media_id: row.try_get("avatar_media_id").map_err(db_err)?,
                        status: UserOnlineState::Online as i32,
                        last_seen_ms: now,
                    },
                    raw_session_token: raw_token,
                    token_sha256,
                    current_pts,
                })
            }

            AuthMethod::TokenResume => {
                let raw_token: [u8; 32] = req
                    .session_token
                    .as_slice()
                    .try_into()
                    .map_err(|_| ServerError::Unauthorized)?;
                let token_sha256 = hash_session_token(&raw_token);

                // Always validate session liveness against PostgreSQL so a stale Redis cache
                // entry can never resurrect a logged-out session (CWE-613).
                let maybe_session = sqlx::query(
                    "UPDATE user_sessions SET last_active_ms = $1 WHERE token_sha256 = $2 RETURNING user_id",
                )
                .bind(now)
                .bind(&token_sha256[..])
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;

                let Some(srow) = maybe_session else {
                    if let Some(mut r) = self.redis.clone() {
                        let key = format!("tgram:sess:{}", hex::encode(token_sha256));
                        let _: Result<(), _> = r.del(key).await;
                    }
                    return Err(ServerError::Unauthorized);
                };

                let user_id = srow.try_get::<i64, _>("user_id").map_err(db_err)? as u64;
                self.cache_session_in_redis(&token_sha256, user_id).await;

                let urow = sqlx::query(
                    "UPDATE users SET last_seen_ms = $1 WHERE user_id = $2
                     RETURNING username, display_name, avatar_color_rgb, avatar_media_id, current_pts",
                )
                .bind(now)
                .bind(user_id as i64)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?
                .ok_or(ServerError::Unauthorized)?;

                let current_pts = urow.try_get::<i64, _>("current_pts").map_err(db_err)? as u64;
                Ok(AuthSessionOutcome {
                    profile: UserProfile {
                        user_id,
                        username: urow.try_get("username").map_err(db_err)?,
                        display_name: urow.try_get("display_name").map_err(db_err)?,
                        avatar_color_rgb: urow
                            .try_get::<i64, _>("avatar_color_rgb")
                            .map_err(db_err)? as u32,
                        avatar_media_id: urow.try_get("avatar_media_id").map_err(db_err)?,
                        status: UserOnlineState::Online as i32,
                        last_seen_ms: now,
                    },
                    raw_session_token: raw_token,
                    token_sha256,
                    current_pts,
                })
            }

            AuthMethod::Unspecified => Err(ServerError::BadRequest(
                "auth method must be specified".to_owned(),
            )),
        }
    }

    pub async fn revoke_session(&self, token_sha256: &[u8; 32]) -> ServerResult<bool> {
        let res = sqlx::query("DELETE FROM user_sessions WHERE token_sha256 = $1")
            .bind(&token_sha256[..])
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        if let Some(mut r) = self.redis.clone() {
            let key = format!("tgram:sess:{}", hex::encode(token_sha256));
            r.del::<_, ()>(&key).await.map_err(|e| {
                tracing::error!(error = %e, "Redis session cache invalidation failed during logout");
                ServerError::Database(format!("Redis session cache invalidation failed: {e}"))
            })?;
        }
        Ok(res.rows_affected() > 0)
    }

    pub async fn set_presence(
        &self,
        user_id: u64,
        online: bool,
        now_ms: i64,
    ) -> ServerResult<Vec<u64>> {
        if let Some(mut r) = self.redis.clone() {
            let key = format!("tgram:online:{user_id}");
            if online {
                let _: Result<(), _> = r.set_ex(key, 1_u8, PRESENCE_TTL_SECS).await;
            } else {
                let _: Result<(), _> = r.del(key).await;
            }
        }
        sqlx::query("UPDATE users SET last_seen_ms = $1 WHERE user_id = $2")
            .bind(now_ms)
            .bind(user_id as i64)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        let rows = sqlx::query(
            "SELECT DISTINCT cm2.user_id
             FROM chat_members cm1
             JOIN chat_members cm2 ON cm1.chat_id = cm2.chat_id
             WHERE cm1.user_id = $1 AND cm2.user_id <> $1",
        )
        .bind(user_id as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(rows
            .into_iter()
            .filter_map(|r| r.try_get::<i64, _>("user_id").ok().map(|v| v as u64))
            .collect())
    }

    pub async fn sync_dialogs(
        &self,
        user_id: u64,
        limit: u32,
        online_checker: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> ServerResult<SyncDialogsResponse> {
        let max_items = limit.clamp(1, 500) as i64;
        let current_pts: i64 =
            sqlx::query_scalar("SELECT current_pts FROM users WHERE user_id = $1")
                .bind(user_id as i64)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?
                .unwrap_or(1);

        let rows = sqlx::query(
            "SELECT uc.chat_id,
                    uc.peer_type,
                    uc.title,
                    uc.avatar_color_rgb,
                    uc.created_at_ms,
                    uc.read_inbox_max_msg_id,
                    uc.read_outbox_max_msg_id,
                    uc.is_pinned,
                    p.peer_user_id,
                    p.peer_name,
                    p.peer_avatar_color,
                    m.msg_id,
                    m.sender_id AS msg_sender_id,
                    m.client_random_id AS msg_client_random_id,
                    m.timestamp_ms AS msg_timestamp_ms,
                    m.body_text AS msg_body_text,
                    m.reply_to_msg_id AS msg_reply_to_msg_id,
                    m.media_id,
                    m.file_name,
                    m.mime_type,
                    m.size_bytes,
                    m.sha256_hash,
                    m.width,
                    m.height,
                    COALESCE(u_cnt.cnt, 0)::BIGINT AS unread_count
             FROM (
                 SELECT c.chat_id,
                        c.peer_type,
                        c.title,
                        c.avatar_color_rgb,
                        c.created_at_ms,
                        cm.read_inbox_max_msg_id,
                        cm.read_outbox_max_msg_id,
                        cm.is_pinned
                 FROM chat_members cm
                 JOIN chats c ON c.chat_id = cm.chat_id
                 WHERE cm.user_id = $1
                 ORDER BY cm.is_pinned DESC, cm.joined_at_ms DESC
                 LIMIT $2
             ) uc
             LEFT JOIN LATERAL (
                 SELECT u.user_id AS peer_user_id,
                        u.display_name AS peer_name,
                        u.avatar_color_rgb AS peer_avatar_color
                 FROM chat_members cm2
                 JOIN users u ON u.user_id = cm2.user_id
                 WHERE cm2.chat_id = uc.chat_id AND cm2.user_id <> $1
                 LIMIT 1
             ) p ON uc.peer_type = 1
             LEFT JOIN LATERAL (
                 SELECT m1.msg_id,
                        m1.sender_id,
                        m1.client_random_id,
                        m1.timestamp_ms,
                        m1.body_text,
                        m1.reply_to_msg_id,
                        mo.media_id,
                        mo.file_name,
                        mo.mime_type,
                        mo.size_bytes,
                        mo.sha256_hash,
                        mo.width,
                        mo.height
                 FROM messages m1
                 LEFT JOIN media_objects mo ON mo.media_id = m1.media_id
                 WHERE m1.chat_id = uc.chat_id
                 ORDER BY m1.msg_id DESC
                 LIMIT 1
             ) m ON TRUE
             LEFT JOIN LATERAL (
                 SELECT COUNT(*)::BIGINT AS cnt
                 FROM messages m2
                 WHERE m2.chat_id = uc.chat_id
                   AND m2.msg_id > uc.read_inbox_max_msg_id
                   AND m2.sender_id <> $1
             ) u_cnt ON TRUE",
        )
        .bind(user_id as i64)
        .bind(max_items)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let mut dialogs = Vec::with_capacity(rows.len());
        let mut referenced_uids = HashSet::new();
        referenced_uids.insert(user_id);

        for row in rows {
            let chat_id = row.try_get::<i64, _>("chat_id").map_err(db_err)? as u64;
            let peer_type = row.try_get::<i32, _>("peer_type").map_err(db_err)?;
            let mut title: String = row.try_get("title").map_err(db_err)?;
            let mut avatar_color_rgb =
                row.try_get::<i64, _>("avatar_color_rgb").map_err(db_err)? as u32;
            let created_at_ms: i64 = row.try_get("created_at_ms").map_err(db_err)?;
            let read_inbox = row
                .try_get::<i64, _>("read_inbox_max_msg_id")
                .map_err(db_err)? as u64;
            let read_outbox = row
                .try_get::<i64, _>("read_outbox_max_msg_id")
                .map_err(db_err)? as u64;
            let is_pinned: bool = row.try_get("is_pinned").map_err(db_err)?;

            let mut peer_user_id = 0_u64;
            if peer_type == PeerType::Direct as i32 {
                let peer_uid_opt: Option<i64> = row.try_get("peer_user_id").map_err(db_err)?;
                if let Some(puid) = peer_uid_opt {
                    peer_user_id = puid as u64;
                    if let Some(pname) = row
                        .try_get::<Option<String>, _>("peer_name")
                        .map_err(db_err)?
                    {
                        title = pname;
                    }
                    if let Some(pcol) = row
                        .try_get::<Option<i64>, _>("peer_avatar_color")
                        .map_err(db_err)?
                    {
                        avatar_color_rgb = pcol as u32;
                    }
                    referenced_uids.insert(peer_user_id);
                } else {
                    peer_user_id = user_id;
                    if title.is_empty() {
                        title = "Избранное".to_owned();
                    }
                }
            }

            let msg_id_opt: Option<i64> = row.try_get("msg_id").map_err(db_err)?;
            let top_message = if let Some(raw_mid) = msg_id_opt {
                let msg_id = raw_mid as u64;
                let sender_id = row.try_get::<i64, _>("msg_sender_id").map_err(db_err)? as u64;
                let client_random_id = row
                    .try_get::<i64, _>("msg_client_random_id")
                    .map_err(db_err)? as u64;
                let timestamp_ms: i64 = row.try_get("msg_timestamp_ms").map_err(db_err)?;
                let text: String = row.try_get("msg_body_text").map_err(db_err)?;
                let reply_to_msg_id = row
                    .try_get::<i64, _>("msg_reply_to_msg_id")
                    .map_err(db_err)? as u64;

                let media_id_opt: Option<String> = row.try_get("media_id").map_err(db_err)?;
                let media = if let Some(mid) = media_id_opt {
                    Some(MediaAttachment {
                        media_id: mid,
                        file_name: row.try_get("file_name").map_err(db_err)?,
                        mime_type: row.try_get("mime_type").map_err(db_err)?,
                        size_bytes: row.try_get::<i64, _>("size_bytes").map_err(db_err)? as u64,
                        sha256_hash: row.try_get("sha256_hash").map_err(db_err)?,
                        width: row.try_get::<i32, _>("width").map_err(db_err)? as u32,
                        height: row.try_get::<i32, _>("height").map_err(db_err)? as u32,
                    })
                } else {
                    None
                };

                let is_read = if sender_id == user_id {
                    msg_id <= read_outbox
                } else {
                    msg_id <= read_inbox
                };
                referenced_uids.insert(sender_id);

                Some(ChatMessage {
                    msg_id,
                    chat_id,
                    sender_id,
                    client_random_id,
                    timestamp_ms,
                    text,
                    reply_to_msg_id,
                    media,
                    is_read,
                    pts: 0,
                })
            } else {
                None
            };

            let unread_count: i64 = row.try_get("unread_count").map_err(db_err)?;
            let sort_timestamp_ms = top_message
                .as_ref()
                .map(|m| m.timestamp_ms)
                .unwrap_or(created_at_ms);

            dialogs.push(DialogEntry {
                chat_id,
                peer_type,
                title,
                peer_user_id,
                avatar_color_rgb,
                top_message,
                unread_count: unread_count.max(0) as u32,
                read_inbox_max_msg_id: read_inbox,
                read_outbox_max_msg_id: read_outbox,
                is_pinned,
                sort_timestamp_ms,
            });
        }

        dialogs.sort_by(|a, b| {
            b.is_pinned
                .cmp(&a.is_pinned)
                .then_with(|| b.sort_timestamp_ms.cmp(&a.sort_timestamp_ms))
        });

        let uid_vec: Vec<i64> = referenced_uids.into_iter().map(|u| u as i64).collect();
        let user_rows = sqlx::query(
            "SELECT user_id, username, display_name, avatar_color_rgb, avatar_media_id, last_seen_ms
             FROM users WHERE user_id = ANY($1)",
        )
        .bind(&uid_vec)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let mut users = Vec::with_capacity(user_rows.len());
        for ur in user_rows {
            let uid = ur.try_get::<i64, _>("user_id").map_err(db_err)? as u64;
            users.push(UserProfile {
                user_id: uid,
                username: ur.try_get("username").map_err(db_err)?,
                display_name: ur.try_get("display_name").map_err(db_err)?,
                avatar_color_rgb: ur.try_get::<i64, _>("avatar_color_rgb").map_err(db_err)? as u32,
                avatar_media_id: ur.try_get("avatar_media_id").map_err(db_err)?,
                status: if online_checker(uid) {
                    UserOnlineState::Online as i32
                } else {
                    UserOnlineState::Offline as i32
                },
                last_seen_ms: ur.try_get("last_seen_ms").map_err(db_err)?,
            });
        }

        Ok(SyncDialogsResponse {
            dialogs,
            users,
            current_pts: current_pts as u64,
        })
    }

    pub async fn get_history(
        &self,
        user_id: u64,
        chat_id: u64,
        before_msg_id: u64,
        limit: u32,
    ) -> ServerResult<GetHistoryResponse> {
        let page_size = limit.clamp(1, 200) as i64;
        let member_row = sqlx::query(
            "SELECT read_inbox_max_msg_id, read_outbox_max_msg_id
             FROM chat_members WHERE chat_id = $1 AND user_id = $2",
        )
        .bind(chat_id as i64)
        .bind(user_id as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or(ServerError::ChatNotFound(chat_id))?;

        let read_inbox = member_row
            .try_get::<i64, _>("read_inbox_max_msg_id")
            .map_err(db_err)? as u64;
        let read_outbox = member_row
            .try_get::<i64, _>("read_outbox_max_msg_id")
            .map_err(db_err)? as u64;

        let cursor = if before_msg_id == 0 {
            i64::MAX
        } else {
            before_msg_id as i64
        };

        let rows = sqlx::query(
            "SELECT m.msg_id, m.chat_id, m.sender_id, m.client_random_id, m.timestamp_ms,
                    m.body_text, m.reply_to_msg_id,
                    mo.media_id, mo.file_name, mo.mime_type, mo.size_bytes, mo.sha256_hash, mo.width, mo.height
             FROM messages m
             LEFT JOIN media_objects mo ON mo.media_id = m.media_id
             WHERE m.chat_id = $1 AND m.msg_id < $2
             ORDER BY m.msg_id DESC
             LIMIT $3",
        )
        .bind(chat_id as i64)
        .bind(cursor)
        .bind(page_size + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let has_more = rows.len() > page_size as usize;
        let mut messages: Vec<ChatMessage> = rows
            .into_iter()
            .take(page_size as usize)
            .map(|r| decode_message_row(&r, user_id, read_inbox, read_outbox))
            .collect::<ServerResult<Vec<_>>>()?;

        messages.reverse(); // Ascending msg_id order

        Ok(GetHistoryResponse {
            chat_id,
            messages,
            has_more,
        })
    }

    pub async fn search_peers(
        &self,
        _user_id: u64,
        query: &str,
        limit: u32,
        online_checker: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> ServerResult<SearchPeersResponse> {
        let q = query.trim().trim_start_matches('@').to_lowercase();
        if q.is_empty() {
            return Ok(SearchPeersResponse {
                users: Vec::new(),
                dialogs: Vec::new(),
            });
        }
        let escaped_q = escape_sql_like(&q);
        let pattern = format!("%{escaped_q}%");
        let rows = sqlx::query(
            "SELECT user_id, username, display_name, avatar_color_rgb, avatar_media_id, last_seen_ms
             FROM users
             WHERE LOWER(username) LIKE $1 ESCAPE '\\'
                OR LOWER(display_name) LIKE $1 ESCAPE '\\'
             LIMIT $2",
        )
        .bind(&pattern)
        .bind(limit.clamp(1, 50) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let mut users = Vec::with_capacity(rows.len());
        for ur in rows {
            let uid = ur.try_get::<i64, _>("user_id").map_err(db_err)? as u64;
            users.push(UserProfile {
                user_id: uid,
                username: ur.try_get("username").map_err(db_err)?,
                display_name: ur.try_get("display_name").map_err(db_err)?,
                avatar_color_rgb: ur.try_get::<i64, _>("avatar_color_rgb").map_err(db_err)? as u32,
                avatar_media_id: ur.try_get("avatar_media_id").map_err(db_err)?,
                status: if online_checker(uid) {
                    UserOnlineState::Online as i32
                } else {
                    UserOnlineState::Offline as i32
                },
                last_seen_ms: ur.try_get("last_seen_ms").map_err(db_err)?,
            });
        }

        Ok(SearchPeersResponse {
            users,
            dialogs: Vec::new(),
        })
    }

    pub async fn get_or_create_direct_chat(
        &self,
        user_id: u64,
        target_user_id: u64,
        online_checker: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> ServerResult<CreateDirectChatResponse> {
        let now = unix_millis_now();
        let peer_row = sqlx::query(
            "SELECT user_id, username, display_name, avatar_color_rgb, avatar_media_id, last_seen_ms
             FROM users WHERE user_id = $1",
        )
        .bind(target_user_id as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or_else(|| ServerError::BadRequest("target user not found".to_owned()))?;

        let peer = UserProfile {
            user_id: target_user_id,
            username: peer_row.try_get("username").map_err(db_err)?,
            display_name: peer_row.try_get("display_name").map_err(db_err)?,
            avatar_color_rgb: peer_row
                .try_get::<i64, _>("avatar_color_rgb")
                .map_err(db_err)? as u32,
            avatar_media_id: peer_row.try_get("avatar_media_id").map_err(db_err)?,
            status: if online_checker(target_user_id) {
                UserOnlineState::Online as i32
            } else {
                UserOnlineState::Offline as i32
            },
            last_seen_ms: peer_row.try_get("last_seen_ms").map_err(db_err)?,
        };

        let pair_key = format!(
            "{}:{}",
            user_id.min(target_user_id),
            user_id.max(target_user_id)
        );

        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let chat_row = sqlx::query(
            "INSERT INTO chats (peer_type, title, avatar_color_rgb, direct_pair_key, created_at_ms)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (direct_pair_key) DO UPDATE SET peer_type = EXCLUDED.peer_type
             RETURNING chat_id",
        )
        .bind(PeerType::Direct as i32)
        .bind(if user_id == target_user_id {
            "Избранное"
        } else {
            ""
        })
        .bind(peer.avatar_color_rgb as i64)
        .bind(&pair_key)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;

        let chat_id = chat_row.try_get::<i64, _>("chat_id").map_err(db_err)? as u64;

        for uid in [user_id, target_user_id] {
            sqlx::query(
                "INSERT INTO chat_members (chat_id, user_id, joined_at_ms)
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            )
            .bind(chat_id as i64)
            .bind(uid as i64)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;

        let dialog = DialogEntry {
            chat_id,
            peer_type: PeerType::Direct as i32,
            title: if user_id == target_user_id {
                "Избранное".to_owned()
            } else {
                peer.display_name.clone()
            },
            peer_user_id: target_user_id,
            avatar_color_rgb: peer.avatar_color_rgb,
            top_message: None,
            unread_count: 0,
            read_inbox_max_msg_id: 0,
            read_outbox_max_msg_id: 0,
            is_pinned: false,
            sort_timestamp_ms: now,
        };

        Ok(CreateDirectChatResponse {
            dialog: Some(dialog),
            peer: Some(peer),
        })
    }

    pub async fn persist_message(
        &self,
        sender_id: u64,
        req: SendMessageRequest,
        media: Option<MediaAttachment>,
        now_ms: i64,
    ) -> ServerResult<PersistMessageOutcome> {
        if req.text.trim().is_empty() && media.is_none() {
            return Err(ServerError::BadRequest(
                "message must contain text or media".to_owned(),
            ));
        }
        if req.client_random_id == 0 {
            return Err(ServerError::BadRequest(
                "client_random_id must be non-zero".to_owned(),
            ));
        }

        let sender_row = sqlx::query(
            "SELECT username, display_name, avatar_color_rgb, avatar_media_id, current_pts
             FROM users WHERE user_id = $1",
        )
        .bind(sender_id as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or(ServerError::Unauthorized)?;

        let sender_profile = UserProfile {
            user_id: sender_id,
            username: sender_row.try_get("username").map_err(db_err)?,
            display_name: sender_row.try_get("display_name").map_err(db_err)?,
            avatar_color_rgb: sender_row
                .try_get::<i64, _>("avatar_color_rgb")
                .map_err(db_err)? as u32,
            avatar_media_id: sender_row.try_get("avatar_media_id").map_err(db_err)?,
            status: UserOnlineState::Online as i32,
            last_seen_ms: now_ms,
        };

        let chat_id = if req.chat_id != 0 {
            req.chat_id
        } else if req.target_user_id != 0 {
            let dm = self
                .get_or_create_direct_chat(sender_id, req.target_user_id, &|_| false)
                .await?;
            dm.dialog.map(|d| d.chat_id).unwrap_or(0)
        } else {
            return Err(ServerError::BadRequest("chat_id required".to_owned()));
        };

        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1::BIGINT FROM chat_members WHERE chat_id = $1 AND user_id = $2",
        )
        .bind(chat_id as i64)
        .bind(sender_id as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        if is_member.is_none() {
            return Err(ServerError::ChatNotFound(chat_id));
        }

        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let media_id_opt = media.as_ref().map(|m| m.media_id.as_str());

        let inserted = sqlx::query(
            "INSERT INTO messages (chat_id, sender_id, client_random_id, timestamp_ms, body_text, reply_to_msg_id, media_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (chat_id, sender_id, client_random_id) DO NOTHING
             RETURNING msg_id",
        )
        .bind(chat_id as i64)
        .bind(sender_id as i64)
        .bind(req.client_random_id as i64)
        .bind(now_ms)
        .bind(&req.text)
        .bind(req.reply_to_msg_id as i64)
        .bind(media_id_opt)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let Some(ins_row) = inserted else {
            tx.rollback().await.ok();
            let dup = sqlx::query(
                "SELECT msg_id, chat_id, timestamp_ms, body_text, reply_to_msg_id
                 FROM messages WHERE chat_id = $1 AND sender_id = $2 AND client_random_id = $3",
            )
            .bind(chat_id as i64)
            .bind(sender_id as i64)
            .bind(req.client_random_id as i64)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
            let sender_pts = sender_row.try_get::<i64, _>("current_pts").map_err(db_err)? as u64;
            return Ok(PersistMessageOutcome {
                message: ChatMessage {
                    msg_id: dup.try_get::<i64, _>("msg_id").map_err(db_err)? as u64,
                    chat_id: dup.try_get::<i64, _>("chat_id").map_err(db_err)? as u64,
                    sender_id,
                    client_random_id: req.client_random_id,
                    timestamp_ms: dup.try_get("timestamp_ms").map_err(db_err)?,
                    text: dup.try_get("body_text").map_err(db_err)?,
                    reply_to_msg_id: dup.try_get::<i64, _>("reply_to_msg_id").map_err(db_err)?
                        as u64,
                    media,
                    is_read: false,
                    pts: sender_pts,
                },
                sender_profile,
                sender_pts,
                recipients: Vec::new(),
                was_duplicate: true,
            });
        };

        let msg_id = ins_row.try_get::<i64, _>("msg_id").map_err(db_err)? as u64;

        sqlx::query(
            "UPDATE chat_members SET read_inbox_max_msg_id = GREATEST(read_inbox_max_msg_id, $1)
             WHERE chat_id = $2 AND user_id = $3",
        )
        .bind(msg_id as i64)
        .bind(chat_id as i64)
        .bind(sender_id as i64)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        let member_rows = sqlx::query(
            "UPDATE users u SET current_pts = u.current_pts + 1
             FROM chat_members cm
             WHERE cm.chat_id = $1 AND cm.user_id = u.user_id
             RETURNING u.user_id, u.current_pts, cm.read_inbox_max_msg_id",
        )
        .bind(chat_id as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;

        let mut sender_pts = 1_u64;
        let mut recipients = Vec::with_capacity(member_rows.len());
        for mr in member_rows {
            let uid = mr.try_get::<i64, _>("user_id").map_err(db_err)? as u64;
            let pts = mr.try_get::<i64, _>("current_pts").map_err(db_err)? as u64;
            let read_inbox = mr
                .try_get::<i64, _>("read_inbox_max_msg_id")
                .map_err(db_err)? as u64;
            if uid == sender_id {
                sender_pts = pts;
            }
            let unread_count = if uid == sender_id {
                0
            } else {
                let cnt: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM messages WHERE chat_id = $1 AND msg_id > $2 AND sender_id <> $3",
                )
                .bind(chat_id as i64)
                .bind(read_inbox as i64)
                .bind(uid as i64)
                .fetch_one(&self.pool)
                .await
                .map_err(db_err)?;
                cnt as u32
            };
            recipients.push(RecipientDeliveryTarget {
                user_id: uid,
                unread_count,
                pts,
            });
        }

        let message = ChatMessage {
            msg_id,
            chat_id,
            sender_id,
            client_random_id: req.client_random_id,
            timestamp_ms: now_ms,
            text: req.text,
            reply_to_msg_id: req.reply_to_msg_id,
            media,
            is_read: false,
            pts: sender_pts,
        };

        Ok(PersistMessageOutcome {
            message,
            sender_profile,
            sender_pts,
            recipients,
            was_duplicate: false,
        })
    }

    pub async fn mark_read(
        &self,
        reader_id: u64,
        chat_id: u64,
        max_read_msg_id: u64,
        _now_ms: i64,
    ) -> ServerResult<MarkReadOutcome> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let updated = sqlx::query(
            "UPDATE chat_members
             SET read_inbox_max_msg_id = GREATEST(read_inbox_max_msg_id, $1)
             WHERE chat_id = $2 AND user_id = $3
             RETURNING read_inbox_max_msg_id",
        )
        .bind(max_read_msg_id as i64)
        .bind(chat_id as i64)
        .bind(reader_id as i64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or(ServerError::ChatNotFound(chat_id))?;

        let effective = updated
            .try_get::<i64, _>("read_inbox_max_msg_id")
            .map_err(db_err)? as u64;

        let peer_rows = sqlx::query(
            "UPDATE chat_members
             SET read_outbox_max_msg_id = GREATEST(read_outbox_max_msg_id, $1)
             WHERE chat_id = $2 AND user_id <> $3
             RETURNING user_id",
        )
        .bind(effective as i64)
        .bind(chat_id as i64)
        .bind(reader_id as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;

        let reader_pts: i64 = sqlx::query_scalar(
            "UPDATE users SET current_pts = current_pts + 1 WHERE user_id = $1 RETURNING current_pts",
        )
        .bind(reader_id as i64)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;

        let mut notify_peers = Vec::with_capacity(peer_rows.len());
        for pr in peer_rows {
            let pid = pr.try_get::<i64, _>("user_id").map_err(db_err)? as u64;
            let p_pts: i64 = sqlx::query_scalar(
                "UPDATE users SET current_pts = current_pts + 1 WHERE user_id = $1 RETURNING current_pts",
            )
            .bind(pid as i64)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
            notify_peers.push((pid, p_pts as u64));
        }

        tx.commit().await.map_err(db_err)?;

        let unread_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM messages WHERE chat_id = $1 AND msg_id > $2 AND sender_id <> $3",
        )
        .bind(chat_id as i64)
        .bind(effective as i64)
        .bind(reader_id as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(MarkReadOutcome {
            chat_id,
            max_read_msg_id: effective,
            unread_count: unread_count as u32,
            reader_pts: reader_pts as u64,
            notify_peers,
        })
    }

    pub async fn chat_member_ids(&self, user_id: u64, chat_id: u64) -> ServerResult<Vec<u64>> {
        let rows = sqlx::query("SELECT user_id FROM chat_members WHERE chat_id = $1")
            .bind(chat_id as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;

        let ids: Vec<u64> = rows
            .into_iter()
            .filter_map(|r| r.try_get::<i64, _>("user_id").ok().map(|v| v as u64))
            .collect();
        if !ids.contains(&user_id) {
            return Err(ServerError::ChatNotFound(chat_id));
        }
        Ok(ids)
    }

    pub async fn save_media_metadata(
        &self,
        uploader_user_id: u64,
        media: &MediaAttachment,
        now_ms: i64,
    ) -> ServerResult<()> {
        sqlx::query(
            "INSERT INTO media_objects (
                 media_id, uploader_user_id, file_name, mime_type, size_bytes, sha256_hash, width, height, created_at_ms
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (media_id) DO NOTHING",
        )
        .bind(&media.media_id)
        .bind(uploader_user_id as i64)
        .bind(&media.file_name)
        .bind(&media.mime_type)
        .bind(media.size_bytes as i64)
        .bind(&media.sha256_hash)
        .bind(media.width as i32)
        .bind(media.height as i32)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    pub async fn get_media_attachment(&self, media_id: &str) -> ServerResult<Option<MediaAttachment>> {
        let row = sqlx::query(
            "SELECT media_id, file_name, mime_type, size_bytes, sha256_hash, width, height
             FROM media_objects
             WHERE media_id = $1",
        )
        .bind(media_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let Some(r) = row else {
            return Ok(None);
        };

        Ok(Some(MediaAttachment {
            media_id: r.try_get("media_id").map_err(db_err)?,
            file_name: r.try_get("file_name").map_err(db_err)?,
            mime_type: r.try_get("mime_type").map_err(db_err)?,
            size_bytes: r.try_get::<i64, _>("size_bytes").map_err(db_err)? as u64,
            sha256_hash: r.try_get("sha256_hash").map_err(db_err)?,
            width: r.try_get::<i32, _>("width").map_err(db_err)? as u32,
            height: r.try_get::<i32, _>("height").map_err(db_err)? as u32,
        }))
    }

    pub async fn user_has_access_to_media(
        &self,
        user_id: u64,
        media_id: &str,
    ) -> ServerResult<bool> {
        let allowed: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                 FROM media_objects mo
                 WHERE mo.media_id = $1 AND mo.uploader_user_id = $2
             ) OR EXISTS (
                 SELECT 1
                 FROM messages m
                 INNER JOIN chat_members cm ON cm.chat_id = m.chat_id
                 WHERE m.media_id = $1 AND cm.user_id = $2
             )",
        )
        .bind(media_id)
        .bind(user_id as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(allowed)
    }

    async fn cache_session_in_redis(&self, token_sha256: &[u8; 32], user_id: u64) {
        if let Some(mut r) = self.redis.clone() {
            let key = format!("tgram:sess:{}", hex::encode(token_sha256));
            let _: Result<(), _> = r.set_ex(key, user_id, SESSION_CACHE_TTL_SECS).await;
        }
    }
}

fn decode_message_row(
    r: &sqlx::postgres::PgRow,
    viewer_id: u64,
    read_inbox: u64,
    read_outbox: u64,
) -> ServerResult<ChatMessage> {
    let msg_id = r.try_get::<i64, _>("msg_id").map_err(db_err)? as u64;
    let chat_id = r.try_get::<i64, _>("chat_id").map_err(db_err)? as u64;
    let sender_id = r.try_get::<i64, _>("sender_id").map_err(db_err)? as u64;
    let client_random_id = r.try_get::<i64, _>("client_random_id").map_err(db_err)? as u64;
    let timestamp_ms: i64 = r.try_get("timestamp_ms").map_err(db_err)?;
    let text: String = r.try_get("body_text").map_err(db_err)?;
    let reply_to_msg_id = r.try_get::<i64, _>("reply_to_msg_id").map_err(db_err)? as u64;

    let media_id_opt: Option<String> = r.try_get("media_id").map_err(db_err)?;
    let media = if let Some(mid) = media_id_opt {
        Some(MediaAttachment {
            media_id: mid,
            file_name: r.try_get("file_name").map_err(db_err)?,
            mime_type: r.try_get("mime_type").map_err(db_err)?,
            size_bytes: r.try_get::<i64, _>("size_bytes").map_err(db_err)? as u64,
            sha256_hash: r.try_get("sha256_hash").map_err(db_err)?,
            width: r.try_get::<i32, _>("width").map_err(db_err)? as u32,
            height: r.try_get::<i32, _>("height").map_err(db_err)? as u32,
        })
    } else {
        None
    };

    let is_read = if sender_id == viewer_id {
        msg_id <= read_outbox
    } else {
        msg_id <= read_inbox
    };

    Ok(ChatMessage {
        msg_id,
        chat_id,
        sender_id,
        client_random_id,
        timestamp_ms,
        text,
        reply_to_msg_id,
        media,
        is_read,
        pts: 0,
    })
}

fn db_err(e: sqlx::Error) -> ServerError {
    ServerError::Database(e.to_string())
}
