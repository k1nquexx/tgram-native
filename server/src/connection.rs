use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tracing::{debug, error, trace, warn};
use tgram_proto::{
    flags, perform_server_handshake, AuthRequest, AuthResponse, CreateDirectChatRequest,
    DecodedFrame, FrameOpener, FrameSealer, GetHistoryRequest, LogoutRequest, LogoutResponse,
    MediaDownloadChunkRequest, MediaUploadChunkRequest, MediaUploadInitRequest, Opcode,
    PingRequest, PongResponse, ReadAckRequest, SearchPeersRequest, SendMessageRequest,
    SyncDialogsRequest, TypingEventRequest,
};

use crate::config::ServerConfig;
use crate::error::{ServerError, ServerResult};
use crate::hub::{OutboundPacket, RealtimeHub, SESSION_OUTBOX_CAPACITY};
use crate::media::MediaManager;
use crate::store::unix_millis_now;

struct AuthenticatedContext {
    user_id: u64,
    token_sha256: [u8; 32],
}

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, cost: f64) -> Result<(), u32> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);

        if self.tokens >= cost {
            self.tokens -= cost;
            Ok(())
        } else {
            let deficit = cost - self.tokens;
            let wait_ms = ((deficit / self.refill_per_sec) * 1000.0).ceil() as u32;
            Err(wait_ms.max(50))
        }
    }
}

/// Entrypoint for a single accepted TCP client socket.
pub async fn serve_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<ServerConfig>,
    hub: Arc<RealtimeHub>,
) {
    let conn_id = hub.allocate_conn_id();
    let total_sockets = hub.increment_sockets();

    if total_sockets > config.max_connections {
        warn!(conn_id, %peer_addr, total_sockets, "rejecting connection: max_connections reached");
        hub.decrement_sockets();
        return;
    }

    // Disable Nagle's algorithm for sub-millisecond interactive chat & typing responsiveness
    let _ = stream.set_nodelay(true);

    let handshake_res = timeout(
        config.handshake_timeout,
        perform_server_handshake(&mut stream, &config.signing_key),
    )
    .await;

    let (sealer, opener) = match handshake_res {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            debug!(conn_id, %peer_addr, error = %e, "MTWire handshake failed");
            hub.decrement_sockets();
            return;
        }
        Err(_) => {
            debug!(conn_id, %peer_addr, "MTWire handshake timed out");
            hub.decrement_sockets();
            return;
        }
    };

    trace!(conn_id, %peer_addr, "AEAD tunnel established");

    let (read_half, write_half) = stream.into_split();
    let (outbound_tx, outbound_rx) = mpsc::channel::<OutboundPacket>(SESSION_OUTBOX_CAPACITY);
    let (disconnect_tx, disconnect_rx) = watch::channel(false);

    let writer_handle = tokio::spawn(writer_loop(
        conn_id,
        write_half,
        sealer,
        outbound_rx,
        disconnect_rx.clone(),
    ));

    reader_loop(
        conn_id,
        peer_addr,
        read_half,
        opener,
        outbound_tx,
        disconnect_tx,
        disconnect_rx,
        config,
        &hub,
    )
    .await;

    let _ = writer_handle.await;
    hub.decrement_sockets();
    trace!(conn_id, %peer_addr, "TCP session closed");
}

async fn wait_for_force_disconnect(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow_and_update() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow_and_update() {
            return;
        }
    }
    std::future::pending::<()>().await
}

/// Dedicated write half: batches queued frames into a single reusable `BytesMut` for minimal syscalls.
async fn writer_loop(
    conn_id: u64,
    mut write_half: OwnedWriteHalf,
    mut sealer: FrameSealer,
    mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    mut disconnect_rx: watch::Receiver<bool>,
) {
    let mut tx_wire = BytesMut::with_capacity(16 * 1024);
    let mut forced_abort = false;

    'writer: loop {
        let first_pkt = tokio::select! {
            biased;
            _ = wait_for_force_disconnect(&mut disconnect_rx) => {
                forced_abort = true;
                break 'writer;
            }
            maybe_pkt = outbound_rx.recv() => {
                match maybe_pkt {
                    Some(pkt) => pkt,
                    None => break 'writer,
                }
            }
        };

        tx_wire.clear();
        if let Err(e) = sealer.seal_raw(
            first_pkt.opcode,
            first_pkt.flags,
            first_pkt.req_id,
            &first_pkt.payload,
            &mut tx_wire,
        ) {
            error!(conn_id, error = %e, "fatal AEAD seal error in writer_loop; terminating session");
            forced_abort = true;
            break 'writer;
        }

        // Coalesce up to 64 already-queued packets into one write_all syscall under burst load
        for _ in 0..64 {
            let Ok(next_pkt) = outbound_rx.try_recv() else {
                break;
            };
            if let Err(e) = sealer.seal_raw(
                next_pkt.opcode,
                next_pkt.flags,
                next_pkt.req_id,
                &next_pkt.payload,
                &mut tx_wire,
            ) {
                error!(
                    conn_id,
                    error = %e,
                    "fatal AEAD seal error during packet coalescing; terminating session to prevent silent drop"
                );
                forced_abort = true;
                break 'writer;
            }
        }

        tokio::select! {
            biased;
            _ = wait_for_force_disconnect(&mut disconnect_rx) => {
                forced_abort = true;
                break 'writer;
            }
            write_res = write_half.write_all(&tx_wire) => {
                if let Err(e) = write_res {
                    trace!(conn_id, error = %e, "socket write closed");
                    break 'writer;
                }
            }
        }
    }

    if !forced_abort {
        let _ = write_half.shutdown().await;
    }
}

/// Dedicated read half: authenticates AEAD frames and dispatches RPC opcodes.
#[allow(clippy::too_many_arguments)]
async fn reader_loop(
    conn_id: u64,
    peer_addr: SocketAddr,
    mut read_half: OwnedReadHalf,
    mut opener: FrameOpener,
    outbound_tx: mpsc::Sender<OutboundPacket>,
    disconnect_tx: watch::Sender<bool>,
    mut disconnect_rx: watch::Receiver<bool>,
    config: Arc<ServerConfig>,
    hub: &Arc<RealtimeHub>,
) {
    let mut rx_buf = BytesMut::with_capacity(16 * 1024);
    let mut auth_ctx: Option<AuthenticatedContext> = None;
    let mut limiter = TokenBucket::new(160.0, 80.0);

    loop {
        if rx_buf.capacity() - rx_buf.len() < 4096 {
            rx_buf.reserve(8192);
        }

        let wait_limit = if auth_ctx.is_some() {
            config.idle_timeout
        } else {
            config.unauth_timeout
        };

        let read_outcome = tokio::select! {
            biased;
            _ = wait_for_force_disconnect(&mut disconnect_rx) => {
                debug!(conn_id, %peer_addr, "session forcibly terminated due to outbound backpressure");
                break;
            }
            res = timeout(wait_limit, read_half.read_buf(&mut rx_buf)) => res,
        };

        let bytes_read = match read_outcome {
            Ok(Ok(0)) => break, // Clean TCP FIN
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                trace!(conn_id, %peer_addr, error = %e, "socket read error");
                break;
            }
            Err(_) => {
                debug!(conn_id, %peer_addr, authenticated = auth_ctx.is_some(), "idle watchdog expired");
                break;
            }
        };
        let _ = bytes_read;

        loop {
            let frame = match opener.try_open_next(&mut rx_buf) {
                Ok(Some(f)) => f,
                Ok(None) => break, // Need more bytes from TCP stream
                Err(e) => {
                    warn!(conn_id, %peer_addr, error = %e, "AEAD verification/framing error; dropping client");
                    if let Some(ctx) = auth_ctx.take() {
                        hub.unbind_user_session(ctx.user_id, conn_id).await;
                    }
                    return;
                }
            };

            let req_id = frame.header.req_id;
            if let Err(err) = dispatch_frame(
                conn_id,
                &mut auth_ctx,
                &mut limiter,
                frame,
                &outbound_tx,
                &disconnect_tx,
                hub,
            )
            .await
            {
                let err_pkt = OutboundPacket::from_proto(
                    Opcode::Error,
                    flags::NONE,
                    req_id,
                    &err.to_rpc_error(),
                );
                if outbound_tx.send(err_pkt).await.is_err() {
                    break;
                }
            }
        }
    }

    if let Some(ctx) = auth_ctx.take() {
        hub.unbind_user_session(ctx.user_id, conn_id).await;
    }
}

async fn dispatch_frame(
    conn_id: u64,
    auth_ctx: &mut Option<AuthenticatedContext>,
    limiter: &mut TokenBucket,
    frame: DecodedFrame,
    outbound_tx: &mpsc::Sender<OutboundPacket>,
    disconnect_tx: &watch::Sender<bool>,
    hub: &Arc<RealtimeHub>,
) -> ServerResult<()> {
    let opcode = frame.header.opcode;
    let req_id = frame.header.req_id;

    // Rate-limit cost weighted by operation type
    let cost = match opcode {
        Opcode::Ping => 0.1,
        Opcode::UploadChunkReq | Opcode::DownloadChunkReq => 0.15,
        Opcode::AuthReq => 5.0,
        _ => 1.0,
    };
    if let Err(retry_ms) = limiter.try_consume(cost) {
        return Err(ServerError::RateLimited(retry_ms));
    }

    match opcode {
        Opcode::Ping => {
            let req: PingRequest = frame.decode_proto()?;
            let pong = PongResponse {
                client_timestamp_ms: req.client_timestamp_ms,
                server_timestamp_ms: unix_millis_now(),
            };
            enqueue_reply(outbound_tx, Opcode::Pong, req_id, &pong).await
        }

        Opcode::AuthReq => {
            let req: AuthRequest = frame.decode_proto()?;
            let outcome = hub.store.authenticate(req).await?;

            if let Some(prev) = auth_ctx.take() {
                if prev.user_id != outcome.profile.user_id {
                    hub.unbind_user_session(prev.user_id, conn_id).await;
                }
            }

            let user_id = outcome.profile.user_id;
            *auth_ctx = Some(AuthenticatedContext {
                user_id,
                token_sha256: outcome.token_sha256,
            });
            hub.bind_user_session(
                user_id,
                conn_id,
                outbound_tx.clone(),
                disconnect_tx.clone(),
            )
            .await;

            let res = AuthResponse {
                self_profile: Some(outcome.profile),
                session_token: outcome.raw_session_token.to_vec(),
                server_time_ms: unix_millis_now(),
                current_pts: outcome.current_pts,
            };
            enqueue_reply(outbound_tx, Opcode::AuthRes, req_id, &res).await
        }

        Opcode::LogoutReq => {
            let _: LogoutRequest = frame.decode_proto()?;
            let ctx = auth_ctx.take().ok_or(ServerError::Unauthorized)?;
            let revoked = hub.store.revoke_session(&ctx.token_sha256).await?;
            hub.unbind_user_session(ctx.user_id, conn_id).await;
            enqueue_reply(outbound_tx, Opcode::LogoutRes, req_id, &LogoutResponse { revoked })
                .await
        }

        Opcode::SyncDialogsReq => {
            let uid = require_uid(auth_ctx)?;
            let req: SyncDialogsRequest = frame.decode_proto()?;
            let hub_ref = Arc::clone(hub);
            let res = hub
                .store
                .sync_dialogs(uid, req.limit, &move |u| hub_ref.is_user_online(u))
                .await?;
            enqueue_reply(outbound_tx, Opcode::SyncDialogsRes, req_id, &res).await
        }

        Opcode::GetHistoryReq => {
            let uid = require_uid(auth_ctx)?;
            let req: GetHistoryRequest = frame.decode_proto()?;
            let res = hub
                .store
                .get_history(uid, req.chat_id, req.before_msg_id, req.limit)
                .await?;
            enqueue_reply(outbound_tx, Opcode::GetHistoryRes, req_id, &res).await
        }

        Opcode::SearchPeersReq => {
            let uid = require_uid(auth_ctx)?;
            let req: SearchPeersRequest = frame.decode_proto()?;
            let hub_ref = Arc::clone(hub);
            let res = hub
                .store
                .search_peers(uid, &req.query, req.limit, &move |u| {
                    hub_ref.is_user_online(u)
                })
                .await?;
            enqueue_reply(outbound_tx, Opcode::SearchPeersRes, req_id, &res).await
        }

        Opcode::CreateDirectChatReq => {
            let uid = require_uid(auth_ctx)?;
            let req: CreateDirectChatRequest = frame.decode_proto()?;
            let hub_ref = Arc::clone(hub);
            let res = hub
                .store
                .get_or_create_direct_chat(uid, req.target_user_id, &move |u| {
                    hub_ref.is_user_online(u)
                })
                .await?;
            enqueue_reply(outbound_tx, Opcode::CreateDirectChatRes, req_id, &res).await
        }

        Opcode::SendMessageReq => {
            let uid = require_uid(auth_ctx)?;
            let req: SendMessageRequest = frame.decode_proto()?;
            let ack = hub.route_send_message(uid, conn_id, req).await?;
            enqueue_reply(outbound_tx, Opcode::SendMessageAck, req_id, &ack).await
        }

        Opcode::ReadAckReq => {
            let uid = require_uid(auth_ctx)?;
            let req: ReadAckRequest = frame.decode_proto()?;
            let res = hub.route_read_ack(uid, conn_id, req).await?;
            enqueue_reply(outbound_tx, Opcode::ReadAckRes, req_id, &res).await
        }

        Opcode::TypingEventReq => {
            let uid = require_uid(auth_ctx)?;
            let req: TypingEventRequest = frame.decode_proto()?;
            hub.route_typing_event(uid, conn_id, req).await
        }

        Opcode::UploadInitReq => {
            let uid = require_uid(auth_ctx)?;
            let req: MediaUploadInitRequest = frame.decode_proto()?;
            let res = hub.media.init_upload(uid, req).await?;
            enqueue_reply(outbound_tx, Opcode::UploadInitRes, req_id, &res).await
        }

        Opcode::UploadChunkReq => {
            let uid = require_uid(auth_ctx)?;
            let req: MediaUploadChunkRequest = frame.decode_proto()?;
            let (ack, completed) = hub.media.append_chunk(uid, req).await?;
            if let Some(ref attachment) = completed {
                hub.store
                    .save_media_metadata(uid, attachment, unix_millis_now())
                    .await?;
            }
            enqueue_reply(outbound_tx, Opcode::UploadChunkAck, req_id, &ack).await
        }

        Opcode::DownloadChunkReq => {
            let uid = require_uid(auth_ctx)?;
            let req: MediaDownloadChunkRequest = frame.decode_proto()?;
            MediaManager::validate_media_id(&req.media_id)?;
            if !hub.store.user_has_access_to_media(uid, &req.media_id).await? {
                return Err(ServerError::Unauthorized);
            }
            let meta = match hub.media.get_attachment(&req.media_id) {
                Some(m) => m,
                None => {
                    let loaded = hub
                        .store
                        .get_media_attachment(&req.media_id)
                        .await?
                        .ok_or_else(|| ServerError::BadRequest("media_id not found".to_owned()))?;
                    hub.media.register_existing(loaded.clone());
                    loaded
                }
            };
            let res = hub.media.read_chunk_with_meta(req, &meta).await?;
            enqueue_reply(outbound_tx, Opcode::DownloadChunkRes, req_id, &res).await
        }

        other => Err(ServerError::BadRequest(format!(
            "unexpected client->server opcode: {other:?}"
        ))),
    }
}

#[inline]
fn require_uid(auth_ctx: &Option<AuthenticatedContext>) -> ServerResult<u64> {
    auth_ctx
        .as_ref()
        .map(|c| c.user_id)
        .ok_or(ServerError::Unauthorized)
}

async fn enqueue_reply<M: prost::Message>(
    tx: &mpsc::Sender<OutboundPacket>,
    opcode: Opcode,
    req_id: u64,
    msg: &M,
) -> ServerResult<()> {
    let pkt = OutboundPacket::from_proto(opcode, flags::NONE, req_id, msg);
    tx.send(pkt)
        .await
        .map_err(|_| ServerError::Internal("session outbound channel closed".to_owned()))
}
