use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use crossbeam_channel::Sender as CrossbeamSender;
use ed25519_dalek::VerifyingKey;
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex};
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};
use tracing::{debug, info, warn};
use tgram_proto::{
    flags, parse_verifying_key_hex, perform_client_handshake, AuthMethod, AuthRequest,
    AuthResponse, CreateDirectChatRequest, CreateDirectChatResponse, DecodedFrame,
    GetHistoryRequest, GetHistoryResponse, LogoutRequest, MediaAttachment,
    MediaDownloadChunkRequest, MediaDownloadChunkResponse, MediaUploadChunkAck,
    MediaUploadChunkRequest, MediaUploadInitRequest, MediaUploadInitResponse, NewMessageUpdate,
    Opcode, PingRequest, PresenceUpdate, ReadAckRequest, ReadAckResponse, ReadHistoryUpdate,
    RpcError, SearchPeersRequest, SearchPeersResponse, SendMessageAck, SendMessageRequest,
    SyncDialogsRequest, SyncDialogsResponse, TypingEventRequest, TypingUpdate,
};

use crate::domain::{
    BackendEvent, ConnectionState, NetCommand, SavedSession, StorageCommand,
};

const PING_INTERVAL: Duration = Duration::from_secs(25);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(6);
const RPC_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
struct RawWireOutbound {
    opcode: Opcode,
    req_id: u64,
    payload: Bytes,
}

impl RawWireOutbound {
    fn encode_proto<M: Message>(opcode: Opcode, req_id: u64, msg: &M) -> Self {
        let mut buf = BytesMut::with_capacity(msg.encoded_len());
        msg.encode(&mut buf).expect("prost encode infallible");
        Self {
            opcode,
            req_id,
            payload: buf.freeze(),
        }
    }
}

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<DecodedFrame, String>>>>>;

#[derive(Clone)]
struct SessionRpcClient {
    wire_tx: UnboundedSender<RawWireOutbound>,
    next_req_id: Arc<AtomicU64>,
    pending: PendingMap,
}

impl SessionRpcClient {
    fn next_id(&self) -> u64 {
        self.next_req_id.fetch_add(1, Ordering::Relaxed)
    }

    fn send_fire_and_forget<M: Message>(&self, opcode: Opcode, msg: &M) -> Result<u64, String> {
        let req_id = self.next_id();
        self.wire_tx
            .send(RawWireOutbound::encode_proto(opcode, req_id, msg))
            .map_err(|_| "соединение закрыто".to_owned())?;
        Ok(req_id)
    }

    async fn call<Req, Res>(&self, opcode: Opcode, expected_res: Opcode, req: &Req) -> Result<Res, String>
    where
        Req: Message,
        Res: Message + Default,
    {
        let req_id = self.next_id();
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().await;
            map.insert(req_id, tx);
        }

        if self
            .wire_tx
            .send(RawWireOutbound::encode_proto(opcode, req_id, req))
            .is_err()
        {
            let mut map = self.pending.lock().await;
            map.remove(&req_id);
            return Err("соединение разорвано".to_owned());
        }

        let frame = match timeout(RPC_TIMEOUT, rx).await {
            Ok(Ok(Ok(f))) => f,
            Ok(Ok(Err(rpc_err))) => return Err(rpc_err),
            Ok(Err(_)) => return Err("канал ответа закрыт".to_owned()),
            Err(_) => {
                let mut map = self.pending.lock().await;
                map.remove(&req_id);
                return Err("превышен таймаут ожидания ответа сервера".to_owned());
            }
        };

        if frame.header.opcode != expected_res {
            return Err(format!(
                "неожиданный опкод ответа: {:?}",
                frame.header.opcode
            ));
        }

        frame.decode_proto::<Res>().map_err(|e| e.to_string())
    }
}

#[derive(Clone)]
struct ActiveConnectionTarget {
    server_addr: String,
    server_pubkey_hex: String,
    pinned_key: VerifyingKey,
    auth_req: AuthRequest,
    is_interactive_auth: bool,
}

fn build_connection_target(
    server_addr: String,
    server_pubkey_hex: String,
    auth_req: AuthRequest,
) -> Result<ActiveConnectionTarget, String> {
    let clean_hex = server_pubkey_hex.trim().to_owned();
    let pinned_key = parse_verifying_key_hex(&clean_hex).map_err(|_| {
        "Некорректный публичный ключ сервера Ed25519 (ожидается 64 HEX-символа)".to_owned()
    })?;
    let is_interactive_auth = auth_req.method != AuthMethod::TokenResume as i32;
    Ok(ActiveConnectionTarget {
        server_addr,
        server_pubkey_hex: clean_hex,
        pinned_key,
        auth_req,
        is_interactive_auth,
    })
}

/// Spawns the dedicated `NetworkThread` running an isolated Tokio event loop (IOCP / epoll / kqueue).
pub fn spawn_network_thread(
    storage_tx: CrossbeamSender<StorageCommand>,
    ui_tx: UnboundedSender<BackendEvent>,
) -> UnboundedSender<NetCommand> {
    let (cmd_tx, cmd_rx) = unbounded_channel::<NetCommand>();

    thread::Builder::new()
        .name("tgram-network".to_owned())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to initialize Tokio I/O runtime on NetworkThread");

            rt.block_on(network_supervisor_loop(cmd_rx, storage_tx, ui_tx));
        })
        .expect("failed to spawn dedicated NetworkThread");

    cmd_tx
}

async fn network_supervisor_loop(
    mut cmd_rx: UnboundedReceiver<NetCommand>,
    storage_tx: CrossbeamSender<StorageCommand>,
    ui_tx: UnboundedSender<BackendEvent>,
) {
    let mut target: Option<ActiveConnectionTarget> = None;
    let mut outbox_queue: VecDeque<SendMessageRequest> = VecDeque::new();
    let mut reconnect_attempt: u32 = 0;

    loop {
        // If no active target session is configured yet, wait idly for UI commands (0% CPU)
        let Some(current_target) = target.clone() else {
            let Some(cmd) = cmd_rx.recv().await else {
                break;
            };
            if let NetCommand::ConnectAndAuth {
                server_addr,
                server_pubkey_hex,
                req,
            } = cmd
            {
                match build_connection_target(server_addr, server_pubkey_hex, req) {
                    Ok(new_target) => {
                        target = Some(new_target);
                        reconnect_attempt = 0;
                    }
                    Err(err_msg) => {
                        let _ = ui_tx.send(BackendEvent::AuthFailed(err_msg));
                        let _ = ui_tx.send(BackendEvent::ConnectionChanged(
                            ConnectionState::Disconnected,
                        ));
                    }
                }
            }
            continue;
        };

        if reconnect_attempt == 0 {
            let _ = ui_tx.send(BackendEvent::ConnectionChanged(ConnectionState::Connecting));
        } else {
            let _ = ui_tx.send(BackendEvent::ConnectionChanged(
                ConnectionState::Reconnecting {
                    attempt: reconnect_attempt,
                },
            ));
            let backoff_ms = (250_u64.saturating_mul(1_u64 << reconnect_attempt.min(5))).min(5_000);
            tokio::select! {
                _ = sleep(Duration::from_millis(backoff_ms)) => {}
                maybe_cmd = cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(NetCommand::ConnectAndAuth { server_addr, server_pubkey_hex, req }) => {
                            match build_connection_target(server_addr, server_pubkey_hex, req) {
                                Ok(new_target) => {
                                    target = Some(new_target);
                                    reconnect_attempt = 0;
                                }
                                Err(err_msg) => {
                                    target = None;
                                    reconnect_attempt = 0;
                                    let _ = ui_tx.send(BackendEvent::AuthFailed(err_msg));
                                    let _ = ui_tx.send(BackendEvent::ConnectionChanged(
                                        ConnectionState::Disconnected,
                                    ));
                                }
                            }
                            continue;
                        }
                        Some(NetCommand::LogoutAndDisconnect) => {
                            target = None;
                            outbox_queue.clear();
                            let _ = storage_tx.send(StorageCommand::ClearSession);
                            let _ = ui_tx.send(BackendEvent::ConnectionChanged(ConnectionState::Disconnected));
                            let _ = ui_tx.send(BackendEvent::LoggedOut);
                            continue;
                        }
                        Some(NetCommand::SendTextMessage { chat_id, target_user_id, client_random_id, text }) => {
                            outbox_queue.push_back(SendMessageRequest {
                                chat_id,
                                target_user_id,
                                client_random_id,
                                text,
                                reply_to_msg_id: 0,
                                media_id: String::new(),
                            });
                            continue;
                        }
                        Some(_) => continue,
                        None => break,
                    }
                }
            }
        }

        let outcome = run_single_connection_cycle(
            &current_target,
            &mut cmd_rx,
            &mut outbox_queue,
            &storage_tx,
            &ui_tx,
        )
        .await;

        match outcome {
            CycleExit::AuthRejected(reason) => {
                let _ = ui_tx.send(BackendEvent::AuthFailed(reason));
                let _ = ui_tx.send(BackendEvent::ConnectionChanged(
                    ConnectionState::Disconnected,
                ));
                if !current_target.is_interactive_auth {
                    // Stored token expired/revoked: clear local session so login form appears
                    let _ = storage_tx.send(StorageCommand::ClearSession);
                    let _ = ui_tx.send(BackendEvent::LoggedOut);
                }
                target = None;
                reconnect_attempt = 0;
            }
            CycleExit::SwitchTarget(new_target) => {
                target = Some(new_target);
                reconnect_attempt = 0;
            }
            CycleExit::LoggedOut => {
                target = None;
                outbox_queue.clear();
                reconnect_attempt = 0;
                let _ = storage_tx.send(StorageCommand::ClearSession);
                let _ = ui_tx.send(BackendEvent::ConnectionChanged(
                    ConnectionState::Disconnected,
                ));
                let _ = ui_tx.send(BackendEvent::LoggedOut);
            }
            CycleExit::DisconnectedWithToken {
                server_addr,
                session_token,
                last_pts,
            } => {
                // Promote target to seamless TokenResume for automatic reconnects
                target = Some(ActiveConnectionTarget {
                    server_addr,
                    server_pubkey_hex: current_target.server_pubkey_hex.clone(),
                    pinned_key: current_target.pinned_key,
                    auth_req: AuthRequest {
                        method: AuthMethod::TokenResume as i32,
                        username: String::new(),
                        password: String::new(),
                        display_name: String::new(),
                        session_token,
                        device_name: "TGram Desktop Rust".to_owned(),
                        last_known_pts: last_pts,
                    },
                    is_interactive_auth: false,
                });
                reconnect_attempt = reconnect_attempt.saturating_add(1);
            }
            CycleExit::NetworkFailedBeforeAuth(err_msg) => {
                if current_target.is_interactive_auth && reconnect_attempt >= 1 {
                    let _ = ui_tx.send(BackendEvent::AuthFailed(format!(
                        "Сервер {} недоступен: {err_msg}",
                        current_target.server_addr
                    )));
                    let _ = ui_tx.send(BackendEvent::ConnectionChanged(
                        ConnectionState::Disconnected,
                    ));
                    target = None;
                    reconnect_attempt = 0;
                } else {
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                }
            }
            CycleExit::ChannelClosed => break,
        }
    }
}

enum CycleExit {
    AuthRejected(String),
    SwitchTarget(ActiveConnectionTarget),
    LoggedOut,
    DisconnectedWithToken {
        server_addr: String,
        session_token: Vec<u8>,
        last_pts: u64,
    },
    NetworkFailedBeforeAuth(String),
    ChannelClosed,
}

async fn run_single_connection_cycle(
    target: &ActiveConnectionTarget,
    cmd_rx: &mut UnboundedReceiver<NetCommand>,
    outbox_queue: &mut VecDeque<SendMessageRequest>,
    storage_tx: &CrossbeamSender<StorageCommand>,
    ui_tx: &UnboundedSender<BackendEvent>,
) -> CycleExit {
    let mut stream = match timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(&target.server_addr)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return CycleExit::NetworkFailedBeforeAuth(e.to_string()),
        Err(_) => return CycleExit::NetworkFailedBeforeAuth("таймаут TCP подключения".to_owned()),
    };

    let _ = stream.set_nodelay(true);
    let _ = ui_tx.send(BackendEvent::ConnectionChanged(
        ConnectionState::Handshaking,
    ));

    let (mut sealer, mut opener) = match timeout(
        HANDSHAKE_TIMEOUT,
        perform_client_handshake(&mut stream, &target.pinned_key),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return CycleExit::NetworkFailedBeforeAuth(e.to_string()),
        Err(_) => {
            return CycleExit::NetworkFailedBeforeAuth(
                "таймаут криптографического рукопожатия".to_owned(),
            )
        }
    };

    let _ = ui_tx.send(BackendEvent::ConnectionChanged(
        ConnectionState::Authenticating,
    ));

    let (mut read_half, mut write_half) = stream.into_split();
    let (wire_tx, mut wire_rx) = unbounded_channel::<RawWireOutbound>();
    let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

    // Spawn dedicated socket writer task for this TCP session
    let writer_join = tokio::spawn(async move {
        let mut wire_buf = BytesMut::with_capacity(16 * 1024);
        while let Some(first) = wire_rx.recv().await {
            wire_buf.clear();
            if sealer
                .seal_raw(first.opcode, flags::NONE, first.req_id, &first.payload, &mut wire_buf)
                .is_err()
            {
                break;
            }
            while let Ok(more) = wire_rx.try_recv() {
                if sealer
                    .seal_raw(more.opcode, flags::NONE, more.req_id, &more.payload, &mut wire_buf)
                    .is_err()
                {
                    break;
                }
            }
            if write_half.write_all(&wire_buf).await.is_err() {
                break;
            }
        }
        let _ = write_half.shutdown().await;
    });

    let rpc = SessionRpcClient {
        wire_tx: wire_tx.clone(),
        next_req_id: Arc::new(AtomicU64::new(1)),
        pending: Arc::clone(&pending),
    };

    // Spawn dedicated socket reader task routing RPC replies & real-time Server Pushes
    let (reader_dead_tx, mut reader_dead_rx) = oneshot::channel::<()>();
    let pending_reader = Arc::clone(&pending);
    let storage_reader = storage_tx.clone();
    let ui_reader = ui_tx.clone();

    let reader_join = tokio::spawn(async move {
        let mut rx_buf = BytesMut::with_capacity(16 * 1024);
        loop {
            if rx_buf.capacity() - rx_buf.len() < 4096 {
                rx_buf.reserve(8192);
            }
            match read_half.read_buf(&mut rx_buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }

            loop {
                let frame = match opener.try_open_next(&mut rx_buf) {
                    Ok(Some(f)) => f,
                    Ok(None) => break,
                    Err(e) => {
                        warn!(error = %e, "client AEAD frame open failed");
                        let _ = reader_dead_tx.send(());
                        return;
                    }
                };

                handle_inbound_frame(frame, &pending_reader, &storage_reader, &ui_reader).await;
            }
        }
        // Fail any remaining in-flight RPCs immediately on socket disconnect
        let mut map = pending_reader.lock().await;
        for (_, tx) in map.drain() {
            let _ = tx.send(Err("соединение потеряно".to_owned()));
        }
        let _ = reader_dead_tx.send(());
    });

    // 1. Authenticate over the encrypted tunnel
    let auth_res: AuthResponse = match rpc
        .call(Opcode::AuthReq, Opcode::AuthRes, &target.auth_req)
        .await
    {
        Ok(res) => res,
        Err(err_msg) => {
            drop(wire_tx);
            let _ = writer_join.await;
            let _ = reader_join.await;
            return CycleExit::AuthRejected(err_msg);
        }
    };

    let Some(profile) = auth_res.self_profile else {
        drop(wire_tx);
        return CycleExit::AuthRejected("пустой профиль в ответе сервера".to_owned());
    };

    let session_token = auth_res.session_token.clone();
    let last_pts = auth_res.current_pts;

    let _ = storage_tx.send(StorageCommand::SaveSession(SavedSession {
        server_addr: target.server_addr.clone(),
        server_pubkey_hex: target.server_pubkey_hex.clone(),
        self_profile: profile.clone(),
        session_token: session_token.clone(),
        last_pts,
    }));

    let _ = ui_tx.send(BackendEvent::ConnectionChanged(ConnectionState::Online));
    let _ = ui_tx.send(BackendEvent::AuthSucceeded {
        server_addr: target.server_addr.clone(),
        server_pubkey_hex: target.server_pubkey_hex.clone(),
        profile: profile.clone(),
        session_token: session_token.clone(),
        current_pts: last_pts,
    });

    info!(
        username = %profile.username,
        user_id = profile.user_id,
        server = %target.server_addr,
        "MTWire v1 session authenticated"
    );

    // 2. Automatically sync dialogs & flush any pending offline outbox messages
    spawn_sync_dialogs(&rpc, storage_tx, ui_tx);

    while let Some(queued_msg) = outbox_queue.pop_front() {
        spawn_send_text(&rpc, queued_msg, storage_tx, ui_tx);
    }

    // 3. Steady-state multiplexed event loop (commands + 25s keep-alive Ping + disconnect watch)
    let mut ping_ticker = interval(PING_INTERVAL);
    ping_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ping_ticker.tick().await; // Skip immediate first tick

    let exit = loop {
        tokio::select! {
            _ = &mut reader_dead_rx => {
                debug!("TCP reader closed; entering auto-reconnect");
                break CycleExit::DisconnectedWithToken {
                    server_addr: target.server_addr.clone(),
                    session_token: session_token.clone(),
                    last_pts,
                };
            }

            _ = ping_ticker.tick() => {
                let now_ms = unix_ms();
                let rpc_ping = rpc.clone();
                tokio::spawn(async move {
                    let _ = rpc_ping
                        .call::<_, tgram_proto::PongResponse>(
                            Opcode::Ping,
                            Opcode::Pong,
                            &PingRequest { client_timestamp_ms: now_ms },
                        )
                        .await;
                });
            }

            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else {
                    break CycleExit::ChannelClosed;
                };

                match cmd {
                    NetCommand::ConnectAndAuth {
                        server_addr,
                        server_pubkey_hex,
                        req,
                    } => match build_connection_target(server_addr, server_pubkey_hex, req) {
                        Ok(new_target) => break CycleExit::SwitchTarget(new_target),
                        Err(err_msg) => {
                            let _ = ui_tx.send(BackendEvent::AuthFailed(err_msg));
                        }
                    },

                    NetCommand::LogoutAndDisconnect => {
                        let _ = rpc
                            .call::<_, tgram_proto::LogoutResponse>(
                                Opcode::LogoutReq,
                                Opcode::LogoutRes,
                                &LogoutRequest {},
                            )
                            .await;
                        break CycleExit::LoggedOut;
                    }

                    NetCommand::SyncDialogs => {
                        spawn_sync_dialogs(&rpc, storage_tx, ui_tx);
                    }

                    NetCommand::FetchHistory { chat_id, before_msg_id, limit } => {
                        let rpc_c = rpc.clone();
                        let st_c = storage_tx.clone();
                        let ui_c = ui_tx.clone();
                        tokio::spawn(async move {
                            match rpc_c
                                .call::<_, GetHistoryResponse>(
                                    Opcode::GetHistoryReq,
                                    Opcode::GetHistoryRes,
                                    &GetHistoryRequest { chat_id, before_msg_id, limit },
                                )
                                .await
                            {
                                Ok(res) => {
                                    let _ = st_c.send(StorageCommand::UpsertMessages {
                                        chat_id: res.chat_id,
                                        messages: res.messages.clone(),
                                    });
                                    let _ = ui_c.send(BackendEvent::HistoryFetched {
                                        chat_id: res.chat_id,
                                        messages: res.messages,
                                        has_more: res.has_more,
                                    });
                                }
                                Err(e) => {
                                    let _ = ui_c.send(BackendEvent::TransientError(e));
                                }
                            }
                        });
                    }

                    NetCommand::SearchPeers { query } => {
                        let rpc_c = rpc.clone();
                        let ui_c = ui_tx.clone();
                        tokio::spawn(async move {
                            if let Ok(res) = rpc_c
                                .call::<_, SearchPeersResponse>(
                                    Opcode::SearchPeersReq,
                                    Opcode::SearchPeersRes,
                                    &SearchPeersRequest { query, limit: 25 },
                                )
                                .await
                            {
                                let _ = ui_c.send(BackendEvent::SearchResults {
                                    users: res.users,
                                    dialogs: res.dialogs,
                                });
                            }
                        });
                    }

                    NetCommand::OpenDirectChat { target_user_id } => {
                        let rpc_c = rpc.clone();
                        let ui_c = ui_tx.clone();
                        tokio::spawn(async move {
                            match rpc_c
                                .call::<_, CreateDirectChatResponse>(
                                    Opcode::CreateDirectChatReq,
                                    Opcode::CreateDirectChatRes,
                                    &CreateDirectChatRequest { target_user_id },
                                )
                                .await
                            {
                                Ok(res) => {
                                    if let (Some(dialog), Some(peer)) = (res.dialog, res.peer) {
                                        let _ = ui_c.send(BackendEvent::DirectChatOpened { dialog, peer });
                                    }
                                }
                                Err(e) => {
                                    let _ = ui_c.send(BackendEvent::TransientError(e));
                                }
                            }
                        });
                    }

                    NetCommand::SendTextMessage { chat_id, target_user_id, client_random_id, text } => {
                        let req = SendMessageRequest {
                            chat_id,
                            target_user_id,
                            client_random_id,
                            text,
                            reply_to_msg_id: 0,
                            media_id: String::new(),
                        };
                        spawn_send_text(&rpc, req, storage_tx, ui_tx);
                    }

                    NetCommand::SendFileAttachment { chat_id, client_random_id, file_path, caption } => {
                        let rpc_c = rpc.clone();
                        let self_uid = profile.user_id;
                        let st_c = storage_tx.clone();
                        let ui_c = ui_tx.clone();
                        tokio::spawn(async move {
                            if let Err(err) = upload_and_send_media_task(
                                rpc_c,
                                self_uid,
                                chat_id,
                                client_random_id,
                                file_path,
                                caption,
                                st_c,
                                ui_c.clone(),
                            )
                            .await
                            {
                                let _ = ui_c.send(BackendEvent::MediaTransferFailed {
                                    chat_id,
                                    client_random_id,
                                    msg_id: 0,
                                    error: err,
                                });
                            }
                        });
                    }

                    NetCommand::DownloadAttachment { chat_id, msg_id, attachment, dest_dir } => {
                        let rpc_c = rpc.clone();
                        let st_c = storage_tx.clone();
                        let ui_c = ui_tx.clone();
                        tokio::spawn(async move {
                            if let Err(err) = download_media_task(
                                rpc_c,
                                chat_id,
                                msg_id,
                                attachment,
                                dest_dir,
                                st_c,
                                ui_c.clone(),
                            )
                            .await
                            {
                                let _ = ui_c.send(BackendEvent::MediaTransferFailed {
                                    chat_id,
                                    client_random_id: 0,
                                    msg_id,
                                    error: err,
                                });
                            }
                        });
                    }

                    NetCommand::SendReadAck { chat_id, max_read_msg_id } => {
                        let rpc_c = rpc.clone();
                        let st_c = storage_tx.clone();
                        let ui_c = ui_tx.clone();
                        tokio::spawn(async move {
                            if let Ok(res) = rpc_c
                                .call::<_, ReadAckResponse>(
                                    Opcode::ReadAckReq,
                                    Opcode::ReadAckRes,
                                    &ReadAckRequest { chat_id, max_read_msg_id },
                                )
                                .await
                            {
                                let _ = st_c.send(StorageCommand::UpdateReadInbox {
                                    chat_id: res.chat_id,
                                    max_read_msg_id: res.max_read_msg_id,
                                    unread_count: res.unread_count,
                                });
                                let _ = ui_c.send(BackendEvent::ReadAckConfirmed(res));
                            }
                        });
                    }

                    NetCommand::SendTyping { chat_id, action } => {
                        let _ = rpc.send_fire_and_forget(
                            Opcode::TypingEventReq,
                            &TypingEventRequest {
                                chat_id,
                                action: action as i32,
                            },
                        );
                    }
                }
            }
        }
    };

    drop(rpc);
    drop(wire_tx);
    let _ = writer_join.await;
    reader_join.abort();
    let _ = last_pts;
    exit
}

async fn handle_inbound_frame(
    frame: DecodedFrame,
    pending: &PendingMap,
    storage_tx: &CrossbeamSender<StorageCommand>,
    ui_tx: &UnboundedSender<BackendEvent>,
) {
    let req_id = frame.header.req_id;
    let opcode = frame.header.opcode;

    // 1. Correlated RPC response or RPC error
    if req_id != 0 {
        let waiter = {
            let mut map = pending.lock().await;
            map.remove(&req_id)
        };
        if let Some(tx) = waiter {
            if opcode == Opcode::Error {
                let msg = frame
                    .decode_proto::<RpcError>()
                    .map(|e| e.message)
                    .unwrap_or_else(|_| "ошибка запроса".to_owned());
                let _ = tx.send(Err(msg));
            } else {
                let _ = tx.send(Ok(frame));
            }
            return;
        }
    }

    // 2. Asynchronous real-time Server Push frames
    match opcode {
        Opcode::NewMessageUpdate => {
            if let Ok(upd) = frame.decode_proto::<NewMessageUpdate>() {
                if let Some(ref msg) = upd.message {
                    let _ = storage_tx.send(StorageCommand::UpsertMessages {
                        chat_id: msg.chat_id,
                        messages: vec![msg.clone()],
                    });
                }
                let _ = ui_tx.send(BackendEvent::IncomingMessage(upd));
            }
        }
        Opcode::ReadHistoryUpdate => {
            if let Ok(upd) = frame.decode_proto::<ReadHistoryUpdate>() {
                let _ = storage_tx.send(StorageCommand::UpdateReadOutbox {
                    chat_id: upd.chat_id,
                    max_read_msg_id: upd.max_read_msg_id,
                });
                let _ = ui_tx.send(BackendEvent::PeerReadHistory(upd));
            }
        }
        Opcode::TypingUpdate => {
            if let Ok(upd) = frame.decode_proto::<TypingUpdate>() {
                let _ = ui_tx.send(BackendEvent::PeerTyping(upd));
            }
        }
        Opcode::PresenceUpdate => {
            if let Ok(upd) = frame.decode_proto::<PresenceUpdate>() {
                let _ = ui_tx.send(BackendEvent::PeerPresence(upd));
            }
        }
        Opcode::Error => {
            if let Ok(err) = frame.decode_proto::<RpcError>() {
                let _ = ui_tx.send(BackendEvent::TransientError(err.message));
            }
        }
        _ => {}
    }
}

fn spawn_sync_dialogs(
    rpc: &SessionRpcClient,
    storage_tx: &CrossbeamSender<StorageCommand>,
    ui_tx: &UnboundedSender<BackendEvent>,
) {
    let rpc_c = rpc.clone();
    let st_c = storage_tx.clone();
    let ui_c = ui_tx.clone();
    tokio::spawn(async move {
        if let Ok(res) = rpc_c
            .call::<_, SyncDialogsResponse>(
                Opcode::SyncDialogsReq,
                Opcode::SyncDialogsRes,
                &SyncDialogsRequest { limit: 150 },
            )
            .await
        {
            let _ = st_c.send(StorageCommand::SaveDialogsAndUsers {
                dialogs: res.dialogs.clone(),
                users: res.users.clone(),
                pts: res.current_pts,
            });
            let _ = ui_c.send(BackendEvent::DialogsSynced {
                dialogs: res.dialogs,
                users: res.users,
                current_pts: res.current_pts,
            });
        }
    });
}

fn spawn_send_text(
    rpc: &SessionRpcClient,
    req: SendMessageRequest,
    storage_tx: &CrossbeamSender<StorageCommand>,
    ui_tx: &UnboundedSender<BackendEvent>,
) {
    let rpc_c = rpc.clone();
    let st_c = storage_tx.clone();
    let ui_c = ui_tx.clone();
    tokio::spawn(async move {
        match rpc_c
            .call::<_, SendMessageAck>(Opcode::SendMessageReq, Opcode::SendMessageAck, &req)
            .await
        {
            Ok(ack) => {
                let _ = st_c.send(StorageCommand::UpdateOutboxAck {
                    chat_id: ack.chat_id,
                    client_random_id: ack.client_random_id,
                    msg_id: ack.msg_id,
                    timestamp_ms: ack.server_timestamp_ms,
                    pts: ack.pts,
                });
                let _ = ui_c.send(BackendEvent::MessageAcked(ack));
            }
            Err(e) => {
                let _ = ui_c.send(BackendEvent::TransientError(format!(
                    "Ошибка отправки сообщения: {e}"
                )));
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn upload_and_send_media_task(
    rpc: SessionRpcClient,
    self_user_id: u64,
    chat_id: u64,
    client_random_id: u64,
    file_path: PathBuf,
    caption: String,
    storage_tx: CrossbeamSender<StorageCommand>,
    ui_tx: UnboundedSender<BackendEvent>,
) -> Result<(), String> {
    let file_name = file_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_owned());
    let mime_type = guess_mime(&file_name);

    // Compute full-file SHA-256 asynchronously in streaming chunks
    let meta = tokio::fs::metadata(&file_path)
        .await
        .map_err(|e| format!("не удалось прочитать файл: {e}"))?;
    let total_size = meta.len();
    if total_size == 0 {
        return Err("нельзя отправить пустой файл (0 байт)".to_owned());
    }

    let mut hash_file = File::open(&file_path)
        .await
        .map_err(|e| format!("ошибка открытия файла: {e}"))?;
    let mut hasher = Sha256::new();
    let mut hash_buf = vec![0u8; 64 * 1024];
    loop {
        let n = hash_file
            .read(&mut hash_buf)
            .await
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&hash_buf[..n]);
    }
    let sha256_bytes = hasher.finalize().to_vec();

    let mut preview_attachment = MediaAttachment {
        media_id: String::new(),
        file_name: file_name.clone(),
        mime_type: mime_type.clone(),
        size_bytes: total_size,
        sha256_hash: sha256_bytes.clone(),
        width: 0,
        height: 0,
    };

    let _ = ui_tx.send(BackendEvent::MediaUploadProgress {
        chat_id,
        client_random_id,
        attachment: preview_attachment.clone(),
        progress: 0.02,
    });

    let init_res: MediaUploadInitResponse = rpc
        .call(
            Opcode::UploadInitReq,
            Opcode::UploadInitRes,
            &MediaUploadInitRequest {
                file_name: file_name.clone(),
                mime_type,
                size_bytes: total_size,
                sha256_hash: sha256_bytes,
                width: 0,
                height: 0,
            },
        )
        .await?;

    if init_res.upload_id.trim().is_empty() {
        return Err("сервер не выдал идентификатор загрузки upload_id".to_owned());
    }

    let final_media_id = {
        let chunk_sz = init_res.chunk_size.clamp(16 * 1024, 128 * 1024) as usize;
        let mut reader = File::open(&file_path).await.map_err(|e| e.to_string())?;
        let mut chunk_buf = vec![0u8; chunk_sz];
        let mut sent_bytes: u64 = 0;
        let mut chunk_index: u32 = 0;
        let mut assigned_id = String::new();

        loop {
            let n = reader
                .read(&mut chunk_buf)
                .await
                .map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            sent_bytes += n as u64;
            let is_last = sent_bytes >= total_size;

            let ack: MediaUploadChunkAck = rpc
                .call(
                    Opcode::UploadChunkReq,
                    Opcode::UploadChunkAck,
                    &MediaUploadChunkRequest {
                        upload_id: init_res.upload_id.clone(),
                        chunk_index,
                        data: chunk_buf[..n].to_vec(),
                        is_last_chunk: is_last,
                    },
                )
                .await?;

            let progress = (ack.bytes_received as f32 / total_size as f32).clamp(0.0, 1.0);
            let _ = ui_tx.send(BackendEvent::MediaUploadProgress {
                chat_id,
                client_random_id,
                attachment: preview_attachment.clone(),
                progress,
            });

            if is_last {
                assigned_id = ack.media_id;
                break;
            }
            chunk_index += 1;
        }
        assigned_id
    };

    preview_attachment.media_id = final_media_id.clone();
    let _ = storage_tx.send(StorageCommand::RecordDownloadedMedia {
        media_id: final_media_id.clone(),
        local_path: file_path.clone(),
    });

    // Send the chat message referencing the uploaded media_id
    let msg_ack: SendMessageAck = rpc
        .call(
            Opcode::SendMessageReq,
            Opcode::SendMessageAck,
            &SendMessageRequest {
                chat_id,
                target_user_id: 0,
                client_random_id,
                text: caption.clone(),
                reply_to_msg_id: 0,
                media_id: final_media_id.clone(),
            },
        )
        .await?;

    let _ = storage_tx.send(StorageCommand::UpsertMessages {
        chat_id: msg_ack.chat_id,
        messages: vec![tgram_proto::ChatMessage {
            msg_id: msg_ack.msg_id,
            chat_id: msg_ack.chat_id,
            sender_id: self_user_id,
            client_random_id: msg_ack.client_random_id,
            timestamp_ms: msg_ack.server_timestamp_ms,
            text: caption,
            reply_to_msg_id: 0,
            media: Some(preview_attachment),
            is_read: false,
            pts: msg_ack.pts,
        }],
    });
    let ack_msg_id = msg_ack.msg_id;
    let _ = ui_tx.send(BackendEvent::MessageAcked(msg_ack));
    let _ = ui_tx.send(BackendEvent::MediaDownloadFinished {
        chat_id,
        msg_id: ack_msg_id,
        media_id: final_media_id,
        local_path: file_path,
    });

    Ok(())
}

async fn download_media_task(
    rpc: SessionRpcClient,
    chat_id: u64,
    msg_id: u64,
    attachment: MediaAttachment,
    dest_dir: PathBuf,
    storage_tx: CrossbeamSender<StorageCommand>,
    ui_tx: UnboundedSender<BackendEvent>,
) -> Result<(), String> {
    fs::create_dir_all(&dest_dir).map_err(|e| format!("не удалось создать папку загрузок: {e}"))?;

    let safe_name: String = attachment
        .file_name
        .chars()
        .filter(|c| !matches!(c, '/' | '\\' | ':' | '\0'))
        .collect();
    let final_name = if safe_name.trim().is_empty() {
        format!("{}.bin", attachment.media_id)
    } else {
        format!("{}_{}", msg_id, safe_name)
    };

    let temp_path = dest_dir.join(format!("{final_name}.part"));
    let final_path = dest_dir.join(&final_name);

    let mut out_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp_path)
        .await
        .map_err(|e| e.to_string())?;

    let mut hasher = Sha256::new();
    let mut offset: u64 = 0;
    let total = attachment.size_bytes.max(1);

    loop {
        let res: MediaDownloadChunkResponse = rpc
            .call(
                Opcode::DownloadChunkReq,
                Opcode::DownloadChunkRes,
                &MediaDownloadChunkRequest {
                    media_id: attachment.media_id.clone(),
                    offset,
                    length: 128 * 1024,
                },
            )
            .await?;

        if !res.data.is_empty() {
            out_file
                .write_all(&res.data)
                .await
                .map_err(|e| e.to_string())?;
            hasher.update(&res.data);
            offset += res.data.len() as u64;
        }

        let progress = (offset as f32 / total as f32).clamp(0.0, 1.0);
        let _ = ui_tx.send(BackendEvent::MediaDownloadProgress {
            chat_id,
            msg_id,
            media_id: attachment.media_id.clone(),
            progress,
        });

        if res.eof || res.data.is_empty() {
            break;
        }
    }

    out_file.flush().await.map_err(|e| e.to_string())?;
    drop(out_file);

    if attachment.sha256_hash.len() == 32 {
        let digest = hasher.finalize();
        if digest.as_slice() != attachment.sha256_hash.as_slice() {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err("контрольная сумма SHA-256 скачанного файла не совпала".to_owned());
        }
    }

    tokio::fs::rename(&temp_path, &final_path)
        .await
        .map_err(|e| e.to_string())?;

    let _ = storage_tx.send(StorageCommand::RecordDownloadedMedia {
        media_id: attachment.media_id.clone(),
        local_path: final_path.clone(),
    });
    let _ = ui_tx.send(BackendEvent::MediaDownloadFinished {
        chat_id,
        msg_id,
        media_id: attachment.media_id,
        local_path: final_path,
    });

    Ok(())
}

fn guess_mime(file_name: &str) -> String {
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with(".png") {
        "image/png".to_owned()
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg".to_owned()
    } else if lower.ends_with(".pdf") {
        "application/pdf".to_owned()
    } else if lower.ends_with(".zip") || lower.ends_with(".7z") {
        "application/zip".to_owned()
    } else if lower.ends_with(".txt") || lower.ends_with(".rs") || lower.ends_with(".md") {
        "text/plain".to_owned()
    } else {
        "application/octet-stream".to_owned()
    }
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
