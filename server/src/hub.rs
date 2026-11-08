use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use prost::Message;
use tokio::sync::mpsc;
use tgram_proto::{
    flags, ChatMessage, NewMessageUpdate, Opcode, PresenceUpdate, ReadAckRequest, ReadAckResponse,
    ReadHistoryUpdate, SendMessageAck, SendMessageRequest, TypingEventRequest, TypingUpdate,
    UserOnlineState,
};

use crate::error::{ServerError, ServerResult};
use crate::media::MediaManager;
use crate::store::{unix_millis_now, StorageEngine};

pub const SESSION_OUTBOX_CAPACITY: usize = 1024;
const TYPING_TTL_MS: u32 = 6_000;

/// Pre-serialized wire packet ready to be AEAD-sealed by a connection's writer task.
#[derive(Clone, Debug)]
pub struct OutboundPacket {
    pub opcode: Opcode,
    pub flags: u16,
    pub req_id: u64,
    pub payload: Bytes,
}

impl OutboundPacket {
    pub fn from_proto<M: Message>(opcode: Opcode, pkt_flags: u16, req_id: u64, msg: &M) -> Self {
        let mut buf = BytesMut::with_capacity(msg.encoded_len());
        msg.encode(&mut buf)
            .expect("prost encoding into growable BytesMut is infallible");
        Self {
            opcode,
            flags: pkt_flags,
            req_id,
            payload: buf.freeze(),
        }
    }
}

#[derive(Clone)]
struct SessionHandle {
    conn_id: u64,
    tx: mpsc::Sender<OutboundPacket>,
}

/// Sharded real-time message router and multi-device session registry.
pub struct RealtimeHub {
    next_conn_id: AtomicU64,
    active_sockets: AtomicUsize,
    sessions_by_user: DashMap<u64, Vec<SessionHandle>>,
    pub store: StorageEngine,
    pub media: Arc<MediaManager>,
}

impl RealtimeHub {
    pub fn new(store: StorageEngine, media: Arc<MediaManager>) -> Arc<Self> {
        Arc::new(Self {
            next_conn_id: AtomicU64::new(1),
            active_sockets: AtomicUsize::new(0),
            sessions_by_user: DashMap::with_capacity_and_shard_amount(4096, 64),
            store,
            media,
        })
    }

    #[inline]
    pub fn allocate_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    #[inline]
    pub fn increment_sockets(&self) -> usize {
        self.active_sockets.fetch_add(1, Ordering::AcqRel) + 1
    }

    #[inline]
    pub fn decrement_sockets(&self) {
        self.active_sockets.fetch_sub(1, Ordering::AcqRel);
    }

    #[inline]
    pub fn active_socket_count(&self) -> usize {
        self.active_sockets.load(Ordering::Acquire)
    }

    #[inline]
    pub fn is_user_online(&self, user_id: u64) -> bool {
        self.sessions_by_user
            .get(&user_id)
            .map(|list| !list.is_empty())
            .unwrap_or(false)
    }

    /// Binds an authenticated TCP session to `user_id` and broadcasts `ONLINE` if transitioning `0 -> 1`.
    pub async fn bind_user_session(
        &self,
        user_id: u64,
        conn_id: u64,
        tx: mpsc::Sender<OutboundPacket>,
    ) {
        let became_online = {
            let mut list = self.sessions_by_user.entry(user_id).or_default();
            list.retain(|s| !s.tx.is_closed() && s.conn_id != conn_id);
            let was_offline = list.is_empty();
            list.push(SessionHandle { conn_id, tx });
            was_offline
        };

        if became_online {
            let now = unix_millis_now();
            if let Ok(peers) = self.store.set_presence(user_id, true, now).await {
                let pkt = OutboundPacket::from_proto(
                    Opcode::PresenceUpdate,
                    flags::SERVER_PUSH,
                    0,
                    &PresenceUpdate {
                        user_id,
                        status: UserOnlineState::Online as i32,
                        last_seen_ms: now,
                    },
                );
                for peer_uid in peers {
                    self.push_to_user(peer_uid, pkt.clone(), None);
                }
            }
        }
    }

    /// Unbinds a TCP session on disconnect/logout and broadcasts `OFFLINE` if transitioning `1 -> 0`.
    pub async fn unbind_user_session(&self, user_id: u64, conn_id: u64) {
        let became_offline = {
            match self.sessions_by_user.entry(user_id) {
                Entry::Occupied(mut occ) => {
                    occ.get_mut()
                        .retain(|s| s.conn_id != conn_id && !s.tx.is_closed());
                    if occ.get().is_empty() {
                        occ.remove();
                        true
                    } else {
                        false
                    }
                }
                Entry::Vacant(_) => false,
            }
        };

        if became_offline {
            let now = unix_millis_now();
            if let Ok(peers) = self.store.set_presence(user_id, false, now).await {
                let pkt = OutboundPacket::from_proto(
                    Opcode::PresenceUpdate,
                    flags::SERVER_PUSH,
                    0,
                    &PresenceUpdate {
                        user_id,
                        status: UserOnlineState::Offline as i32,
                        last_seen_ms: now,
                    },
                );
                for peer_uid in peers {
                    self.push_to_user(peer_uid, pkt.clone(), None);
                }
            }
        }
    }

    /// Non-blocking fanout to all active sessions of `user_id`.
    /// Evicts dead/backpressured channels automatically without stalling the caller.
    pub fn push_to_user(
        &self,
        user_id: u64,
        packet: OutboundPacket,
        exclude_conn_id: Option<u64>,
    ) {
        let handles: Vec<SessionHandle> = match self.sessions_by_user.get(&user_id) {
            Some(list) => list.value().clone(),
            None => return,
        };

        let mut has_closed = false;
        for h in handles {
            if Some(h.conn_id) == exclude_conn_id {
                continue;
            }
            if h.tx.try_send(packet.clone()).is_err() && h.tx.is_closed() {
                has_closed = true;
            }
        }

        if has_closed {
            if let Entry::Occupied(mut occ) = self.sessions_by_user.entry(user_id) {
                occ.get_mut().retain(|s| !s.tx.is_closed());
                if occ.get().is_empty() {
                    occ.remove();
                }
            }
        }
    }

    /// Persists a message idempotently and routes real-time `NewMessageUpdate` pushes to all chat members.
    pub async fn route_send_message(
        &self,
        sender_id: u64,
        origin_conn_id: u64,
        req: SendMessageRequest,
    ) -> ServerResult<SendMessageAck> {
        let media = if req.media_id.trim().is_empty() {
            None
        } else {
            let attachment = self
                .media
                .get_attachment(req.media_id.trim())
                .ok_or_else(|| {
                    ServerError::BadRequest(format!("unknown media_id '{}'", req.media_id))
                })?;
            Some(attachment)
        };

        let now = unix_millis_now();
        let outcome = self
            .store
            .persist_message(sender_id, req, media, now)
            .await?;

        if !outcome.was_duplicate {
            for target in &outcome.recipients {
                let mut delivered_msg: ChatMessage = outcome.message.clone();
                delivered_msg.pts = target.pts;

                let update = NewMessageUpdate {
                    message: Some(delivered_msg),
                    sender_brief: Some(outcome.sender_profile.clone()),
                    unread_count: target.unread_count,
                };
                let pkt = OutboundPacket::from_proto(
                    Opcode::NewMessageUpdate,
                    flags::SERVER_PUSH,
                    0,
                    &update,
                );

                // Originating socket gets compact `SendMessageAck`; sender's other devices & all peers get Push
                let exclude = if target.user_id == sender_id {
                    Some(origin_conn_id)
                } else {
                    None
                };
                self.push_to_user(target.user_id, pkt, exclude);
            }
        }

        Ok(SendMessageAck {
            chat_id: outcome.message.chat_id,
            client_random_id: outcome.message.client_random_id,
            msg_id: outcome.message.msg_id,
            server_timestamp_ms: outcome.message.timestamp_ms,
            pts: outcome.sender_pts,
        })
    }

    /// Marks incoming messages as read and pushes `ReadHistoryUpdate` (`✓` -> `✓✓`) to message authors.
    pub async fn route_read_ack(
        &self,
        reader_id: u64,
        origin_conn_id: u64,
        req: ReadAckRequest,
    ) -> ServerResult<ReadAckResponse> {
        let now = unix_millis_now();
        let outcome = self
            .store
            .mark_read(reader_id, req.chat_id, req.max_read_msg_id, now)
            .await?;

        for (peer_uid, peer_pts) in outcome.notify_peers {
            let push = ReadHistoryUpdate {
                chat_id: outcome.chat_id,
                reader_user_id: reader_id,
                max_read_msg_id: outcome.max_read_msg_id,
                read_at_ms: now,
                pts: peer_pts,
            };
            let pkt = OutboundPacket::from_proto(
                Opcode::ReadHistoryUpdate,
                flags::SERVER_PUSH,
                0,
                &push,
            );
            self.push_to_user(peer_uid, pkt, None);
        }

        // Sync read position across reader's own secondary devices
        let self_sync = ReadHistoryUpdate {
            chat_id: outcome.chat_id,
            reader_user_id: reader_id,
            max_read_msg_id: outcome.max_read_msg_id,
            read_at_ms: now,
            pts: outcome.reader_pts,
        };
        let self_pkt = OutboundPacket::from_proto(
            Opcode::ReadHistoryUpdate,
            flags::SERVER_PUSH,
            0,
            &self_sync,
        );
        self.push_to_user(reader_id, self_pkt, Some(origin_conn_id));

        Ok(ReadAckResponse {
            chat_id: outcome.chat_id,
            max_read_msg_id: outcome.max_read_msg_id,
            unread_count: outcome.unread_count,
            pts: outcome.reader_pts,
        })
    }

    /// Broadcasts ephemeral typing/uploading status (`ttl_ms = 6000`) to online participants in `chat_id`.
    pub async fn route_typing_event(
        &self,
        sender_id: u64,
        origin_conn_id: u64,
        req: TypingEventRequest,
    ) -> ServerResult<()> {
        let member_ids = self.store.chat_member_ids(sender_id, req.chat_id).await?;

        let update = TypingUpdate {
            chat_id: req.chat_id,
            user_id: sender_id,
            action: req.action,
            ttl_ms: TYPING_TTL_MS,
        };
        let pkt = OutboundPacket::from_proto(Opcode::TypingUpdate, flags::SERVER_PUSH, 0, &update);

        for uid in member_ids {
            if uid != sender_id {
                self.push_to_user(uid, pkt.clone(), Some(origin_conn_id));
            }
        }
        Ok(())
    }
}
