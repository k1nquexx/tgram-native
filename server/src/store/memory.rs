use std::collections::{HashMap, HashSet};

use tokio::sync::RwLock;
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
    unix_millis_now, AuthSessionOutcome, MarkReadOutcome, PersistMessageOutcome,
    RecipientDeliveryTarget,
};

const GLOBAL_GENERAL_CHAT_ID: u64 = 1;
const SYSTEM_USER_ID: u64 = 1;

#[derive(Clone)]
struct UserRecord {
    user_id: u64,
    username: String,
    display_name: String,
    password_phc: String,
    avatar_color_rgb: u32,
    avatar_media_id: String,
    last_seen_ms: i64,
    current_pts: u64,
}

impl UserRecord {
    fn to_profile(&self, is_online: bool) -> UserProfile {
        UserProfile {
            user_id: self.user_id,
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            avatar_color_rgb: self.avatar_color_rgb,
            avatar_media_id: self.avatar_media_id.clone(),
            status: if is_online {
                UserOnlineState::Online as i32
            } else {
                UserOnlineState::Offline as i32
            },
            last_seen_ms: self.last_seen_ms,
        }
    }
}

#[derive(Clone)]
struct MemberState {
    read_inbox_max_msg_id: u64,
    read_outbox_max_msg_id: u64,
    is_pinned: bool,
}

struct ChatRecord {
    chat_id: u64,
    peer_type: PeerType,
    title: String,
    avatar_color_rgb: u32,
    members: HashMap<u64, MemberState>,
    messages: Vec<ChatMessage>,
    created_at_ms: i64,
}

struct StoredMediaObject {
    uploader_user_id: u64,
    attachment: MediaAttachment,
}

struct MemoryState {
    next_user_id: u64,
    next_chat_id: u64,
    next_msg_id: u64,
    users: HashMap<u64, UserRecord>,
    usernames: HashMap<String, u64>,
    sessions: HashMap<[u8; 32], u64>,
    chats: HashMap<u64, ChatRecord>,
    direct_pairs: HashMap<(u64, u64), u64>,
    idempotency: HashMap<(u64, u64, u64), u64>, // (chat_id, sender_id, client_random_id) -> msg_id
    media: HashMap<String, StoredMediaObject>,
}

pub struct MemoryStore {
    state: RwLock<MemoryState>,
    seed_demo: bool,
}

impl MemoryStore {
    pub fn new(seed_demo: bool) -> Self {
        let _ = dummy_password_phc();
        let now = unix_millis_now();
        let mut users = HashMap::new();
        let mut usernames = HashMap::new();
        let mut chats = HashMap::new();

        if seed_demo {
            let sys_user = UserRecord {
                user_id: SYSTEM_USER_ID,
                username: "telegram".to_owned(),
                display_name: "TGram System".to_owned(),
                password_phc: String::new(),
                avatar_color_rgb: 0x65AADD,
                avatar_media_id: String::new(),
                last_seen_ms: now,
                current_pts: 1,
            };
            usernames.insert(sys_user.username.clone(), SYSTEM_USER_ID);
            users.insert(SYSTEM_USER_ID, sys_user);

            let welcome_msg = ChatMessage {
                msg_id: 1,
                chat_id: GLOBAL_GENERAL_CHAT_ID,
                sender_id: SYSTEM_USER_ID,
                client_random_id: 1,
                timestamp_ms: now,
                text: "Добро пожаловать в TGram Native! Запустите второй экземпляр клиента, зарегистрируйте аккаунт и проверьте мгновенный обмен сообщениями по бинарному протоколу MTWire v1.".to_owned(),
                reply_to_msg_id: 0,
                media: None,
                is_read: false,
                pts: 1,
            };

            let mut members = HashMap::new();
            members.insert(
                SYSTEM_USER_ID,
                MemberState {
                    read_inbox_max_msg_id: 1,
                    read_outbox_max_msg_id: 0,
                    is_pinned: true,
                },
            );

            chats.insert(
                GLOBAL_GENERAL_CHAT_ID,
                ChatRecord {
                    chat_id: GLOBAL_GENERAL_CHAT_ID,
                    peer_type: PeerType::Group,
                    title: "TGram Native — Общий чат".to_owned(),
                    avatar_color_rgb: 0x5288C1,
                    members,
                    messages: vec![welcome_msg],
                    created_at_ms: now,
                },
            );
        }

        Self {
            state: RwLock::new(MemoryState {
                next_user_id: if seed_demo { 2 } else { 1 },
                next_chat_id: if seed_demo { 2 } else { 1 },
                next_msg_id: if seed_demo { 2 } else { 1 },
                users,
                usernames,
                sessions: HashMap::new(),
                chats,
                direct_pairs: HashMap::new(),
                idempotency: HashMap::new(),
                media: HashMap::new(),
            }),
            seed_demo,
        }
    }

    pub async fn authenticate(&self, req: AuthRequest) -> ServerResult<AuthSessionOutcome> {
        let now = unix_millis_now();
        let method = AuthMethod::try_from(req.method).unwrap_or(AuthMethod::Unspecified);

        match method {
            AuthMethod::Register => {
                let uname = normalize_username(&req.username)?;
                validate_password(&req.password)?;
                {
                    let guard = self.state.read().await;
                    if guard.usernames.contains_key(&uname) {
                        return Err(ServerError::UsernameTaken(uname));
                    }
                }

                let password_phc = hash_password_async(req.password).await?;
                let display_name = if req.display_name.trim().is_empty() {
                    uname.clone()
                } else {
                    req.display_name.trim().chars().take(64).collect()
                };

                let mut guard = self.state.write().await;
                if guard.usernames.contains_key(&uname) {
                    return Err(ServerError::UsernameTaken(uname));
                }

                let user_id = guard.next_user_id;
                guard.next_user_id += 1;

                let user = UserRecord {
                    user_id,
                    username: uname.clone(),
                    display_name,
                    password_phc,
                    avatar_color_rgb: avatar_color_for_id(user_id),
                    avatar_media_id: String::new(),
                    last_seen_ms: now,
                    current_pts: 1,
                };
                let profile = user.to_profile(true);

                guard.usernames.insert(uname, user_id);
                guard.users.insert(user_id, user);

                // Auto-join global group chat if enabled
                if self.seed_demo {
                    if let Some(general) = guard.chats.get_mut(&GLOBAL_GENERAL_CHAT_ID) {
                        general.members.insert(
                            user_id,
                            MemberState {
                                read_inbox_max_msg_id: 0,
                                read_outbox_max_msg_id: 0,
                                is_pinned: true,
                            },
                        );
                    }
                }

                // Also create "Избранное" (Saved Messages) self-chat automatically
                let saved_chat_id = guard.next_chat_id;
                guard.next_chat_id += 1;
                let mut saved_members = HashMap::new();
                saved_members.insert(
                    user_id,
                    MemberState {
                        read_inbox_max_msg_id: 0,
                        read_outbox_max_msg_id: 0,
                        is_pinned: false,
                    },
                );
                guard.chats.insert(
                    saved_chat_id,
                    ChatRecord {
                        chat_id: saved_chat_id,
                        peer_type: PeerType::Direct,
                        title: "Избранное".to_owned(),
                        avatar_color_rgb: 0x65AADD,
                        members: saved_members,
                        messages: Vec::new(),
                        created_at_ms: now,
                    },
                );
                guard.direct_pairs.insert((user_id, user_id), saved_chat_id);

                let (raw_token, token_sha256) = generate_session_token();
                guard.sessions.insert(token_sha256, user_id);

                Ok(AuthSessionOutcome {
                    profile,
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
                let (maybe_uid, maybe_phc) = {
                    let guard = self.state.read().await;
                    if let Some(&uid) = guard.usernames.get(&uname) {
                        if let Some(rec) = guard.users.get(&uid) {
                            (Some(uid), Some(rec.password_phc.clone()))
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    }
                };

                if !verify_password_constant_time(req.password, maybe_phc).await? {
                    return Err(ServerError::InvalidCredentials);
                }
                let user_id = maybe_uid.ok_or(ServerError::InvalidCredentials)?;

                let mut guard = self.state.write().await;
                let rec = guard
                    .users
                    .get_mut(&user_id)
                    .ok_or(ServerError::InvalidCredentials)?;
                rec.last_seen_ms = now;
                let pts = rec.current_pts;
                let profile = rec.to_profile(true);

                let (raw_token, token_sha256) = generate_session_token();
                guard.sessions.insert(token_sha256, user_id);

                Ok(AuthSessionOutcome {
                    profile,
                    raw_session_token: raw_token,
                    token_sha256,
                    current_pts: pts,
                })
            }

            AuthMethod::TokenResume => {
                let raw_token: [u8; 32] = req
                    .session_token
                    .as_slice()
                    .try_into()
                    .map_err(|_| ServerError::Unauthorized)?;
                let token_sha256 = hash_session_token(&raw_token);

                let mut guard = self.state.write().await;
                let user_id = guard
                    .sessions
                    .get(&token_sha256)
                    .copied()
                    .ok_or(ServerError::Unauthorized)?;
                let rec = guard
                    .users
                    .get_mut(&user_id)
                    .ok_or(ServerError::Unauthorized)?;
                rec.last_seen_ms = now;
                let pts = rec.current_pts;
                let profile = rec.to_profile(true);

                Ok(AuthSessionOutcome {
                    profile,
                    raw_session_token: raw_token,
                    token_sha256,
                    current_pts: pts,
                })
            }

            AuthMethod::Unspecified => Err(ServerError::BadRequest(
                "auth method must be specified".to_owned(),
            )),
        }
    }

    pub async fn revoke_session(&self, token_sha256: &[u8; 32]) -> ServerResult<bool> {
        let mut guard = self.state.write().await;
        Ok(guard.sessions.remove(token_sha256).is_some())
    }

    pub async fn set_presence(
        &self,
        user_id: u64,
        _online: bool,
        now_ms: i64,
    ) -> ServerResult<Vec<u64>> {
        let mut guard = self.state.write().await;
        if let Some(u) = guard.users.get_mut(&user_id) {
            u.last_seen_ms = now_ms;
        }
        let mut peers = HashSet::new();
        for chat in guard.chats.values() {
            if chat.members.contains_key(&user_id) {
                for &member_id in chat.members.keys() {
                    if member_id != user_id && member_id != SYSTEM_USER_ID {
                        peers.insert(member_id);
                    }
                }
            }
        }
        Ok(peers.into_iter().collect())
    }

    pub async fn sync_dialogs(
        &self,
        user_id: u64,
        limit: u32,
        online_checker: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> ServerResult<SyncDialogsResponse> {
        let max_items = limit.clamp(1, 500) as usize;
        let guard = self.state.read().await;

        let current_pts = guard
            .users
            .get(&user_id)
            .map(|u| u.current_pts)
            .unwrap_or(1);

        let mut dialogs = Vec::new();
        let mut referenced_uids = HashSet::new();
        referenced_uids.insert(user_id);

        for chat in guard.chats.values() {
            let Some(member) = chat.members.get(&user_id) else {
                continue;
            };
            let entry = build_dialog_entry(&guard, chat, user_id, member, &mut referenced_uids);
            dialogs.push(entry);
        }

        dialogs.sort_by(|a, b| {
            b.is_pinned
                .cmp(&a.is_pinned)
                .then_with(|| b.sort_timestamp_ms.cmp(&a.sort_timestamp_ms))
                .then_with(|| b.chat_id.cmp(&a.chat_id))
        });
        dialogs.truncate(max_items);

        let mut users = Vec::with_capacity(referenced_uids.len());
        for uid in referenced_uids {
            if let Some(u) = guard.users.get(&uid) {
                users.push(u.to_profile(online_checker(uid)));
            }
        }

        Ok(SyncDialogsResponse {
            dialogs,
            users,
            current_pts,
        })
    }

    pub async fn get_history(
        &self,
        user_id: u64,
        chat_id: u64,
        before_msg_id: u64,
        limit: u32,
    ) -> ServerResult<GetHistoryResponse> {
        let page_size = limit.clamp(1, 200) as usize;
        let guard = self.state.read().await;

        let chat = guard
            .chats
            .get(&chat_id)
            .ok_or(ServerError::ChatNotFound(chat_id))?;
        let my_member = chat
            .members
            .get(&user_id)
            .ok_or(ServerError::ChatNotFound(chat_id))?;

        let end_idx = if before_msg_id == 0 {
            chat.messages.len()
        } else {
            chat.messages
                .partition_point(|m| m.msg_id < before_msg_id)
        };

        let start_idx = end_idx.saturating_sub(page_size);
        let has_more = start_idx > 0;

        let mut messages: Vec<ChatMessage> = chat.messages[start_idx..end_idx].to_vec();
        for msg in &mut messages {
            if msg.sender_id == user_id {
                msg.is_read = msg.msg_id <= my_member.read_outbox_max_msg_id;
            } else {
                msg.is_read = msg.msg_id <= my_member.read_inbox_max_msg_id;
            }
        }

        Ok(GetHistoryResponse {
            chat_id,
            messages,
            has_more,
        })
    }

    pub async fn search_peers(
        &self,
        user_id: u64,
        query: &str,
        limit: u32,
        online_checker: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> ServerResult<SearchPeersResponse> {
        let max_items = limit.clamp(1, 50) as usize;
        let q = query.trim().trim_start_matches('@').to_lowercase();
        if q.is_empty() {
            return Ok(SearchPeersResponse {
                users: Vec::new(),
                dialogs: Vec::new(),
            });
        }

        let guard = self.state.read().await;
        let mut users = Vec::new();
        for u in guard.users.values() {
            if u.user_id == SYSTEM_USER_ID {
                continue;
            }
            if u.username.contains(&q) || u.display_name.to_lowercase().contains(&q) {
                users.push(u.to_profile(online_checker(u.user_id)));
                if users.len() >= max_items {
                    break;
                }
            }
        }

        let mut dialogs = Vec::new();
        let mut dummy_refs = HashSet::new();
        for chat in guard.chats.values() {
            let Some(member) = chat.members.get(&user_id) else {
                continue;
            };
            let entry = build_dialog_entry(&guard, chat, user_id, member, &mut dummy_refs);
            if entry.title.to_lowercase().contains(&q) {
                dialogs.push(entry);
                if dialogs.len() >= max_items {
                    break;
                }
            }
        }

        Ok(SearchPeersResponse { users, dialogs })
    }

    pub async fn get_or_create_direct_chat(
        &self,
        user_id: u64,
        target_user_id: u64,
        online_checker: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> ServerResult<CreateDirectChatResponse> {
        let now = unix_millis_now();
        let mut guard = self.state.write().await;

        let target_rec = guard
            .users
            .get(&target_user_id)
            .ok_or_else(|| ServerError::BadRequest("target user does not exist".to_owned()))?
            .clone();

        let pair = ordered_pair(user_id, target_user_id);
        let chat_id = if let Some(&existing_id) = guard.direct_pairs.get(&pair) {
            existing_id
        } else {
            let cid = guard.next_chat_id;
            guard.next_chat_id += 1;

            let mut members = HashMap::new();
            members.insert(
                user_id,
                MemberState {
                    read_inbox_max_msg_id: 0,
                    read_outbox_max_msg_id: 0,
                    is_pinned: false,
                },
            );
            members.insert(
                target_user_id,
                MemberState {
                    read_inbox_max_msg_id: 0,
                    read_outbox_max_msg_id: 0,
                    is_pinned: false,
                },
            );

            let title = if user_id == target_user_id {
                "Избранное".to_owned()
            } else {
                String::new()
            };

            guard.chats.insert(
                cid,
                ChatRecord {
                    chat_id: cid,
                    peer_type: PeerType::Direct,
                    title,
                    avatar_color_rgb: target_rec.avatar_color_rgb,
                    members,
                    messages: Vec::new(),
                    created_at_ms: now,
                },
            );
            guard.direct_pairs.insert(pair, cid);
            cid
        };

        let state_ref: &MemoryState = &guard;
        let chat = state_ref.chats.get(&chat_id).unwrap();
        let member = chat.members.get(&user_id).unwrap();
        let mut refs = HashSet::new();
        let dialog = build_dialog_entry(state_ref, chat, user_id, member, &mut refs);
        let peer = target_rec.to_profile(online_checker(target_user_id));

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
        let trimmed_text = req.text.trim();
        if trimmed_text.is_empty() && media.is_none() {
            return Err(ServerError::BadRequest(
                "message must contain text or media attachment".to_owned(),
            ));
        }
        if req.text.chars().count() > 4096 {
            return Err(ServerError::PayloadTooLarge(
                "message text exceeds 4096 characters".to_owned(),
            ));
        }
        if req.client_random_id == 0 {
            return Err(ServerError::BadRequest(
                "client_random_id must be non-zero".to_owned(),
            ));
        }

        let mut guard = self.state.write().await;

        let sender_profile = guard
            .users
            .get(&sender_id)
            .ok_or(ServerError::Unauthorized)?
            .to_profile(true);

        // Resolve chat_id (or auto-create direct chat if target_user_id provided)
        let chat_id = if req.chat_id != 0 {
            req.chat_id
        } else if req.target_user_id != 0 {
            if !guard.users.contains_key(&req.target_user_id) {
                return Err(ServerError::BadRequest(
                    "target_user_id not found".to_owned(),
                ));
            }
            let pair = ordered_pair(sender_id, req.target_user_id);
            if let Some(&cid) = guard.direct_pairs.get(&pair) {
                cid
            } else {
                let cid = guard.next_chat_id;
                guard.next_chat_id += 1;
                let mut members = HashMap::new();
                members.insert(
                    sender_id,
                    MemberState {
                        read_inbox_max_msg_id: 0,
                        read_outbox_max_msg_id: 0,
                        is_pinned: false,
                    },
                );
                members.insert(
                    req.target_user_id,
                    MemberState {
                        read_inbox_max_msg_id: 0,
                        read_outbox_max_msg_id: 0,
                        is_pinned: false,
                    },
                );
                guard.chats.insert(
                    cid,
                    ChatRecord {
                        chat_id: cid,
                        peer_type: PeerType::Direct,
                        title: if sender_id == req.target_user_id {
                            "Избранное".to_owned()
                        } else {
                            String::new()
                        },
                        avatar_color_rgb: avatar_color_for_id(req.target_user_id),
                        members,
                        messages: Vec::new(),
                        created_at_ms: now_ms,
                    },
                );
                guard.direct_pairs.insert(pair, cid);
                cid
            }
        } else {
            return Err(ServerError::BadRequest(
                "chat_id or target_user_id is required".to_owned(),
            ));
        };

        // Verify membership before mutating state or returning idempotent cache
        {
            let chat = guard
                .chats
                .get(&chat_id)
                .ok_or(ServerError::ChatNotFound(chat_id))?;
            if !chat.members.contains_key(&sender_id) {
                return Err(ServerError::ChatNotFound(chat_id));
            }
        }

        // Per-chat idempotency check scoped to (chat_id, sender_id, client_random_id)
        if let Some(&existing_msg_id) =
            guard.idempotency.get(&(chat_id, sender_id, req.client_random_id))
        {
            if let Some(chat) = guard.chats.get(&chat_id) {
                if let Ok(idx) = chat
                    .messages
                    .binary_search_by_key(&existing_msg_id, |m| m.msg_id)
                {
                    let msg = chat.messages[idx].clone();
                    let sender_pts = guard
                        .users
                        .get(&sender_id)
                        .map(|u| u.current_pts)
                        .unwrap_or(msg.pts);
                    return Ok(PersistMessageOutcome {
                        message: msg,
                        sender_profile,
                        sender_pts,
                        recipients: Vec::new(),
                        was_duplicate: true,
                    });
                }
            }
        }

        let msg_id = guard.next_msg_id;
        guard.next_msg_id += 1;

        let member_ids: Vec<u64> = guard
            .chats
            .get(&chat_id)
            .unwrap()
            .members
            .keys()
            .copied()
            .collect();

        // Advance pts for all participants
        let mut member_pts = HashMap::with_capacity(member_ids.len());
        for &uid in &member_ids {
            if let Some(u) = guard.users.get_mut(&uid) {
                u.current_pts += 1;
                member_pts.insert(uid, u.current_pts);
            }
        }
        let sender_pts = member_pts.get(&sender_id).copied().unwrap_or(1);

        let is_self_chat = member_ids.len() == 1 && member_ids[0] == sender_id;
        let message = ChatMessage {
            msg_id,
            chat_id,
            sender_id,
            client_random_id: req.client_random_id,
            timestamp_ms: now_ms,
            text: req.text,
            reply_to_msg_id: req.reply_to_msg_id,
            media,
            is_read: is_self_chat,
            pts: sender_pts,
        };

        let mut recipients = Vec::with_capacity(member_ids.len());
        {
            let chat = guard.chats.get_mut(&chat_id).unwrap();
            if let Some(sender_member) = chat.members.get_mut(&sender_id) {
                sender_member.read_inbox_max_msg_id =
                    sender_member.read_inbox_max_msg_id.max(msg_id);
                if is_self_chat {
                    sender_member.read_outbox_max_msg_id = msg_id;
                }
            }
            chat.messages.push(message.clone());

            for (&uid, m_state) in &chat.members {
                if uid == SYSTEM_USER_ID {
                    continue;
                }
                let unread_count = if uid == sender_id {
                    0
                } else {
                    count_unread_for_member(&chat.messages, uid, m_state.read_inbox_max_msg_id)
                };
                recipients.push(RecipientDeliveryTarget {
                    user_id: uid,
                    unread_count,
                    pts: member_pts.get(&uid).copied().unwrap_or(1),
                });
            }
        }

        guard
            .idempotency
            .insert((chat_id, sender_id, req.client_random_id), msg_id);

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
        let mut guard = self.state.write().await;

        let (effective_max, unread_count, peer_ids) = {
            let chat = guard
                .chats
                .get_mut(&chat_id)
                .ok_or(ServerError::ChatNotFound(chat_id))?;
            if !chat.members.contains_key(&reader_id) {
                return Err(ServerError::ChatNotFound(chat_id));
            }

            let highest_in_chat = chat.messages.last().map(|m| m.msg_id).unwrap_or(0);
            let clamped = max_read_msg_id.min(highest_in_chat);

            let prev_inbox = chat.members[&reader_id].read_inbox_max_msg_id;
            let effective = prev_inbox.max(clamped);

            if let Some(m) = chat.members.get_mut(&reader_id) {
                m.read_inbox_max_msg_id = effective;
            }

            let mut peers = Vec::new();
            if effective > prev_inbox {
                for (&uid, m) in chat.members.iter_mut() {
                    if uid != reader_id && uid != SYSTEM_USER_ID {
                        if effective > m.read_outbox_max_msg_id {
                            m.read_outbox_max_msg_id = effective;
                        }
                        peers.push(uid);
                    }
                }
            }

            let remaining = count_unread_for_member(&chat.messages, reader_id, effective);
            (effective, remaining, peers)
        };

        let reader_pts = if let Some(u) = guard.users.get_mut(&reader_id) {
            u.current_pts += 1;
            u.current_pts
        } else {
            1
        };

        let mut notify_peers = Vec::with_capacity(peer_ids.len());
        for pid in peer_ids {
            let p_pts = if let Some(pu) = guard.users.get_mut(&pid) {
                pu.current_pts += 1;
                pu.current_pts
            } else {
                1
            };
            notify_peers.push((pid, p_pts));
        }

        Ok(MarkReadOutcome {
            chat_id,
            max_read_msg_id: effective_max,
            unread_count,
            reader_pts,
            notify_peers,
        })
    }

    pub async fn chat_member_ids(&self, user_id: u64, chat_id: u64) -> ServerResult<Vec<u64>> {
        let guard = self.state.read().await;
        let chat = guard
            .chats
            .get(&chat_id)
            .ok_or(ServerError::ChatNotFound(chat_id))?;
        if !chat.members.contains_key(&user_id) {
            return Err(ServerError::ChatNotFound(chat_id));
        }
        Ok(chat
            .members
            .keys()
            .copied()
            .filter(|&uid| uid != SYSTEM_USER_ID)
            .collect())
    }

    pub async fn save_media_metadata(
        &self,
        uploader_user_id: u64,
        media: &MediaAttachment,
        _now_ms: i64,
    ) -> ServerResult<()> {
        let mut guard = self.state.write().await;
        guard.media.insert(
            media.media_id.clone(),
            StoredMediaObject {
                uploader_user_id,
                attachment: media.clone(),
            },
        );
        Ok(())
    }

    pub async fn get_media_attachment(&self, media_id: &str) -> ServerResult<Option<MediaAttachment>> {
        let guard = self.state.read().await;
        Ok(guard.media.get(media_id).map(|m| m.attachment.clone()))
    }

    pub async fn user_has_access_to_media(
        &self,
        user_id: u64,
        media_id: &str,
    ) -> ServerResult<bool> {
        let guard = self.state.read().await;
        if let Some(stored) = guard.media.get(media_id) {
            if stored.uploader_user_id == user_id {
                return Ok(true);
            }
        }

        for chat in guard.chats.values() {
            if chat.members.contains_key(&user_id)
                && chat
                    .messages
                    .iter()
                    .any(|m| m.media.as_ref().map(|a| a.media_id.as_str()) == Some(media_id))
            {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

fn ordered_pair(a: u64, b: u64) -> (u64, u64) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

fn count_unread_for_member(
    messages: &[ChatMessage],
    user_id: u64,
    read_inbox_max_msg_id: u64,
) -> u32 {
    let start = messages.partition_point(|m| m.msg_id <= read_inbox_max_msg_id);
    messages[start..]
        .iter()
        .filter(|m| m.sender_id != user_id)
        .count() as u32
}

fn build_dialog_entry(
    state: &MemoryState,
    chat: &ChatRecord,
    viewer_id: u64,
    member: &MemberState,
    referenced_uids: &mut HashSet<u64>,
) -> DialogEntry {
    let mut peer_user_id = 0;
    let mut title = chat.title.clone();
    let mut avatar_color_rgb = chat.avatar_color_rgb;

    if chat.peer_type == PeerType::Direct {
        if chat.members.len() == 1 {
            peer_user_id = viewer_id;
            if title.is_empty() {
                title = "Избранное".to_owned();
            }
        } else if let Some(&other_uid) = chat.members.keys().find(|&&uid| uid != viewer_id) {
            peer_user_id = other_uid;
            referenced_uids.insert(other_uid);
            if let Some(peer_rec) = state.users.get(&other_uid) {
                title = peer_rec.display_name.clone();
                avatar_color_rgb = peer_rec.avatar_color_rgb;
            }
        }
    }

    let top_message = chat.messages.last().map(|m| {
        referenced_uids.insert(m.sender_id);
        let mut copy = m.clone();
        if copy.sender_id == viewer_id {
            copy.is_read = copy.msg_id <= member.read_outbox_max_msg_id;
        } else {
            copy.is_read = copy.msg_id <= member.read_inbox_max_msg_id;
        }
        copy
    });

    let sort_timestamp_ms = top_message
        .as_ref()
        .map(|m| m.timestamp_ms)
        .unwrap_or(chat.created_at_ms);

    let unread_count =
        count_unread_for_member(&chat.messages, viewer_id, member.read_inbox_max_msg_id);

    DialogEntry {
        chat_id: chat.chat_id,
        peer_type: chat.peer_type as i32,
        title,
        peer_user_id,
        avatar_color_rgb,
        top_message,
        unread_count,
        read_inbox_max_msg_id: member.read_inbox_max_msg_id,
        read_outbox_max_msg_id: member.read_outbox_max_msg_id,
        is_pinned: member.is_pinned,
        sort_timestamp_ms,
    }
}
