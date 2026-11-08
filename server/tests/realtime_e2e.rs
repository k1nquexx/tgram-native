use std::path::Path;
use std::time::Duration;

use bytes::BytesMut;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tgram_proto::{
    flags, generate_server_signing_key, perform_client_handshake, AuthMethod, AuthRequest,
    AuthResponse, DecodedFrame, ErrorCode, FrameOpener, FrameSealer, MediaDownloadChunkRequest,
    MediaDownloadChunkResponse, MediaUploadChunkAck, MediaUploadChunkRequest,
    MediaUploadInitRequest, MediaUploadInitResponse, NewMessageUpdate, Opcode, ReadAckRequest,
    ReadAckResponse, ReadHistoryUpdate, RpcError, SendMessageAck, SendMessageRequest,
    TypingAction, TypingEventRequest, TypingUpdate,
};
use tgram_server::config::ServerConfig;
use tgram_server::run_with_listener;

struct TestWireClient {
    stream: TcpStream,
    sealer: FrameSealer,
    opener: FrameOpener,
    rx_buf: BytesMut,
}

impl TestWireClient {
    async fn connect(addr: std::net::SocketAddr, server_pubkey: &VerifyingKey) -> Self {
        let mut stream = TcpStream::connect(addr).await.expect("connect failed");
        stream.set_nodelay(true).unwrap();
        let (sealer, opener) = perform_client_handshake(&mut stream, server_pubkey)
            .await
            .expect("client handshake failed");
        Self {
            stream,
            sealer,
            opener,
            rx_buf: BytesMut::with_capacity(8192),
        }
    }

    async fn send_proto<M: prost::Message>(&mut self, opcode: Opcode, req_id: u64, msg: &M) {
        let mut wire = BytesMut::new();
        self.sealer
            .seal_proto(opcode, flags::NONE, req_id, msg, &mut wire)
            .expect("seal failed");
        self.stream.write_all(&wire).await.expect("write failed");
    }

    async fn recv_matching(&mut self, expected_opcode: Opcode) -> DecodedFrame {
        loop {
            if let Some(frame) = self
                .opener
                .try_open_next(&mut self.rx_buf)
                .expect("AEAD open failed")
            {
                if frame.header.opcode == expected_opcode {
                    return frame;
                }
                // Ignore unrelated presence broadcasts during test flow
                continue;
            }
            if self.rx_buf.capacity() - self.rx_buf.len() < 2048 {
                self.rx_buf.reserve(4096);
            }
            let n = tokio::time::timeout(
                Duration::from_secs(3),
                self.stream.read_buf(&mut self.rx_buf),
            )
            .await
            .expect("timed out waiting for packet")
            .expect("socket read error");
            assert!(n > 0, "unexpected EOF");
        }
    }

    async fn recv_rpc_reply(&mut self, req_id: u64) -> DecodedFrame {
        loop {
            if let Some(frame) = self
                .opener
                .try_open_next(&mut self.rx_buf)
                .expect("AEAD open failed")
            {
                if frame.header.req_id == req_id {
                    return frame;
                }
                continue;
            }
            if self.rx_buf.capacity() - self.rx_buf.len() < 2048 {
                self.rx_buf.reserve(4096);
            }
            let n = tokio::time::timeout(
                Duration::from_secs(3),
                self.stream.read_buf(&mut self.rx_buf),
            )
            .await
            .expect("timed out waiting for RPC reply")
            .expect("socket read error");
            assert!(n > 0, "unexpected EOF");
        }
    }

    async fn register_user(&mut self, req_id: u64, username: &str, display_name: &str) -> u64 {
        self.send_proto(
            Opcode::AuthReq,
            req_id,
            &AuthRequest {
                method: AuthMethod::Register as i32,
                username: username.to_owned(),
                password: "secret_password".to_owned(),
                display_name: display_name.to_owned(),
                session_token: Vec::new(),
                device_name: format!("Test {display_name}"),
                last_known_pts: 0,
            },
        )
        .await;

        let auth: AuthResponse = self
            .recv_matching(Opcode::AuthRes)
            .await
            .decode_proto()
            .expect("AuthResponse decode failed");
        auth.self_profile.expect("missing profile").user_id
    }
}

async fn count_part_files(dir: &Path) -> usize {
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else {
        return 0;
    };
    let mut cnt = 0usize;
    while let Ok(Some(entry)) = rd.next_entry().await {
        if entry.path().extension().and_then(|s| s.to_str()) == Some("part") {
            cnt += 1;
        }
    }
    cnt
}

#[tokio::test]
async fn realtime_auth_message_typing_and_read_receipt_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let temp_media = std::env::temp_dir().join(format!(
        "tgram_test_media_flow_{}",
        std::process::id()
    ));
    let _ = tokio::fs::remove_dir_all(&temp_media).await;

    let server_key = generate_server_signing_key();
    let server_pub = server_key.verifying_key();

    let cfg = ServerConfig {
        bind_addr: addr,
        signing_key: server_key,
        database_url: None,
        redis_url: None,
        media_dir: temp_media.clone(),
        handshake_timeout: Duration::from_secs(5),
        unauth_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(30),
        max_connections: 1024,
        max_uploads_per_user: 4,
        max_total_uploads: 64,
        upload_session_ttl: Duration::from_secs(60),
        seed_demo_data: true,
    };

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let srv_handle = tokio::spawn(async move {
        run_with_listener(listener, cfg, async move {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    });

    let mut alice = TestWireClient::connect(addr, &server_pub).await;
    let mut bob = TestWireClient::connect(addr, &server_pub).await;

    // 1. Register Alice & Bob
    let alice_uid = alice.register_user(1, "alice", "Alice").await;
    let bob_uid = bob.register_user(1, "bob", "Bob").await;

    // 2. Alice sends a direct message to Bob
    alice
        .send_proto(
            Opcode::SendMessageReq,
            2,
            &SendMessageRequest {
                chat_id: 0,
                target_user_id: bob_uid,
                client_random_id: 900_001,
                text: "Привет, Боб! Проверка MTWire v1.".to_owned(),
                reply_to_msg_id: 0,
                media_id: String::new(),
            },
        )
        .await;

    let ack: SendMessageAck = alice
        .recv_matching(Opcode::SendMessageAck)
        .await
        .decode_proto()
        .unwrap();
    assert_eq!(ack.client_random_id, 900_001);

    // Bob receives real-time server push NewMessageUpdate
    let push: NewMessageUpdate = bob
        .recv_matching(Opcode::NewMessageUpdate)
        .await
        .decode_proto()
        .unwrap();
    assert_eq!(push.unread_count, 1);
    let msg = push.message.unwrap();
    assert_eq!(msg.msg_id, ack.msg_id);
    assert_eq!(msg.sender_id, alice_uid);

    // 3. Bob starts typing -> Alice receives TypingUpdate push
    bob.send_proto(
        Opcode::TypingEventReq,
        3,
        &TypingEventRequest {
            chat_id: ack.chat_id,
            action: TypingAction::TypingText as i32,
        },
    )
    .await;

    let typing: TypingUpdate = alice
        .recv_matching(Opcode::TypingUpdate)
        .await
        .decode_proto()
        .unwrap();
    assert_eq!(typing.chat_id, ack.chat_id);
    assert_eq!(typing.user_id, bob_uid);
    assert_eq!(typing.ttl_ms, 6_000);

    // 4. Bob reads the message -> Alice receives ReadHistoryUpdate (✓ -> ✓✓)
    bob.send_proto(
        Opcode::ReadAckReq,
        4,
        &ReadAckRequest {
            chat_id: ack.chat_id,
            max_read_msg_id: ack.msg_id,
        },
    )
    .await;

    let read_res: ReadAckResponse = bob
        .recv_matching(Opcode::ReadAckRes)
        .await
        .decode_proto()
        .unwrap();
    assert_eq!(read_res.unread_count, 0);

    let read_push: ReadHistoryUpdate = alice
        .recv_matching(Opcode::ReadHistoryUpdate)
        .await
        .decode_proto()
        .unwrap();
    assert_eq!(read_push.chat_id, ack.chat_id);
    assert_eq!(read_push.reader_user_id, bob_uid);
    assert_eq!(read_push.max_read_msg_id, ack.msg_id);

    let _ = stop_tx.send(());
    let _ = srv_handle.await;
    let _ = tokio::fs::remove_dir_all(&temp_media).await;
}

#[tokio::test]
async fn media_idor_isolation_and_cas_dedup_disabled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let temp_media = std::env::temp_dir().join(format!(
        "tgram_test_media_idor_{}",
        std::process::id()
    ));
    let _ = tokio::fs::remove_dir_all(&temp_media).await;

    let server_key = generate_server_signing_key();
    let server_pub = server_key.verifying_key();

    let cfg = ServerConfig {
        bind_addr: addr,
        signing_key: server_key,
        database_url: None,
        redis_url: None,
        media_dir: temp_media.clone(),
        handshake_timeout: Duration::from_secs(5),
        unauth_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(30),
        max_connections: 1024,
        max_uploads_per_user: 4,
        max_total_uploads: 64,
        upload_session_ttl: Duration::from_secs(60),
        seed_demo_data: false,
    };

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let srv_handle = tokio::spawn(async move {
        run_with_listener(listener, cfg, async move {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    });

    let mut alice = TestWireClient::connect(addr, &server_pub).await;
    let mut bob = TestWireClient::connect(addr, &server_pub).await;
    let mut mallory = TestWireClient::connect(addr, &server_pub).await;

    let _alice_uid = alice.register_user(1, "alice_sec", "Alice").await;
    let bob_uid = bob.register_user(1, "bob_sec", "Bob").await;
    let mallory_uid = mallory.register_user(1, "mallory_sec", "Mallory").await;

    // 1. Alice uploads a confidential document
    let secret_bytes = b"CONFIDENTIAL_MERGER_CONTRACT_2026_ONLY_FOR_ALICE_AND_BOB".to_vec();
    let secret_sha256 = Sha256::digest(&secret_bytes).to_vec();

    alice
        .send_proto(
            Opcode::UploadInitReq,
            10,
            &MediaUploadInitRequest {
                file_name: "merger_contract.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                size_bytes: secret_bytes.len() as u64,
                sha256_hash: secret_sha256.clone(),
                width: 0,
                height: 0,
            },
        )
        .await;
    let init_res: MediaUploadInitResponse = alice
        .recv_rpc_reply(10)
        .await
        .decode_proto()
        .unwrap();
    assert!(!init_res.already_deduped);
    assert!(!init_res.upload_id.is_empty());

    alice
        .send_proto(
            Opcode::UploadChunkReq,
            11,
            &MediaUploadChunkRequest {
                upload_id: init_res.upload_id,
                chunk_index: 0,
                data: secret_bytes.clone(),
                is_last_chunk: true,
            },
        )
        .await;
    let chunk_ack: MediaUploadChunkAck = alice
        .recv_rpc_reply(11)
        .await
        .decode_proto()
        .unwrap();
    let alice_media_id = chunk_ack.media_id;
    assert!(!alice_media_id.is_empty());

    // 2. Alice sends the private attachment strictly to Bob (1-on-1 Direct Chat)
    alice
        .send_proto(
            Opcode::SendMessageReq,
            12,
            &SendMessageRequest {
                chat_id: 0,
                target_user_id: bob_uid,
                client_random_id: 777_001,
                text: "Секретный договор".to_owned(),
                reply_to_msg_id: 0,
                media_id: alice_media_id.clone(),
            },
        )
        .await;
    let _send_ack: SendMessageAck = alice.recv_rpc_reply(12).await.decode_proto().unwrap();
    let bob_push: NewMessageUpdate = bob
        .recv_matching(Opcode::NewMessageUpdate)
        .await
        .decode_proto()
        .unwrap();
    assert_eq!(
        bob_push.message.unwrap().media.unwrap().media_id,
        alice_media_id
    );

    // 3. Legitimate recipient Bob CAN download the attachment
    bob.send_proto(
        Opcode::DownloadChunkReq,
        20,
        &MediaDownloadChunkRequest {
            media_id: alice_media_id.clone(),
            offset: 0,
            length: 65_536,
        },
    )
    .await;
    let bob_dl: MediaDownloadChunkResponse = bob.recv_rpc_reply(20).await.decode_proto().unwrap();
    assert_eq!(bob_dl.data, secret_bytes);
    assert!(bob_dl.eof);

    // 4. Attack A (CAS Side-Channel Probe): Mallory sends UploadInitReq with Alice's file SHA-256
    mallory
        .send_proto(
            Opcode::UploadInitReq,
            30,
            &MediaUploadInitRequest {
                file_name: "probe.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                size_bytes: secret_bytes.len() as u64,
                sha256_hash: secret_sha256,
                width: 0,
                height: 0,
            },
        )
        .await;
    let mallory_init: MediaUploadInitResponse =
        mallory.recv_rpc_reply(30).await.decode_proto().unwrap();
    assert!(
        !mallory_init.already_deduped,
        "CAS deduplication must be disabled to prevent hash-probing side channels"
    );
    assert!(
        mallory_init.ready_media_id.is_empty(),
        "ready_media_id must never leak another user's media_id"
    );

    // 5. Attack B (Direct Media IDOR): Mallory tries to download Alice's media_id directly
    mallory
        .send_proto(
            Opcode::DownloadChunkReq,
            31,
            &MediaDownloadChunkRequest {
                media_id: alice_media_id.clone(),
                offset: 0,
                length: 65_536,
            },
        )
        .await;
    let dl_err_frame = mallory.recv_rpc_reply(31).await;
    assert_eq!(dl_err_frame.header.opcode, Opcode::Error);
    let dl_err: RpcError = dl_err_frame.decode_proto().unwrap();
    assert_eq!(dl_err.code, ErrorCode::Unauthorized as i32);

    // 6. Attack C (Attachment-Laundering IDOR): Mallory tries to attach Alice's media_id to Mallory's chat
    mallory
        .send_proto(
            Opcode::SendMessageReq,
            32,
            &SendMessageRequest {
                chat_id: 0,
                target_user_id: mallory_uid,
                client_random_id: 888_001,
                text: "Попытка прикрепить чужой media_id".to_owned(),
                reply_to_msg_id: 0,
                media_id: alice_media_id,
            },
        )
        .await;
    let attach_err_frame = mallory.recv_rpc_reply(32).await;
    assert_eq!(attach_err_frame.header.opcode, Opcode::Error);
    let attach_err: RpcError = attach_err_frame.decode_proto().unwrap();
    assert_eq!(attach_err.code, ErrorCode::Unauthorized as i32);

    // 7. Attack D (Path Traversal Probe): Mallory passes "../" in media_id
    mallory
        .send_proto(
            Opcode::DownloadChunkReq,
            33,
            &MediaDownloadChunkRequest {
                media_id: "../../etc/passwd".to_owned(),
                offset: 0,
                length: 4096,
            },
        )
        .await;
    let path_err_frame = mallory.recv_rpc_reply(33).await;
    assert_eq!(path_err_frame.header.opcode, Opcode::Error);
    let path_err: RpcError = path_err_frame.decode_proto().unwrap();
    assert_eq!(path_err.code, ErrorCode::BadRequest as i32);

    let _ = stop_tx.send(());
    let _ = srv_handle.await;
    let _ = tokio::fs::remove_dir_all(&temp_media).await;
}

#[tokio::test]
async fn zombie_upload_limit_and_ttl_cleanup_prevents_dos() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let temp_media = std::env::temp_dir().join(format!(
        "tgram_test_media_dos_{}",
        std::process::id()
    ));
    let _ = tokio::fs::remove_dir_all(&temp_media).await;

    let server_key = generate_server_signing_key();
    let server_pub = server_key.verifying_key();

    // Configure tight per-user quota (max 2 concurrent uploads) and fast 180ms TTL for deterministic E2E testing
    let cfg = ServerConfig {
        bind_addr: addr,
        signing_key: server_key,
        database_url: None,
        redis_url: None,
        media_dir: temp_media.clone(),
        handshake_timeout: Duration::from_secs(5),
        unauth_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(30),
        max_connections: 1024,
        max_uploads_per_user: 2,
        max_total_uploads: 16,
        upload_session_ttl: Duration::from_millis(180),
        seed_demo_data: false,
    };

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let srv_handle = tokio::spawn(async move {
        run_with_listener(listener, cfg, async move {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    });

    let mut mallory = TestWireClient::connect(addr, &server_pub).await;
    let _mallory_uid = mallory.register_user(1, "mallory_dos", "Mallory DoS").await;

    let dummy_hash = vec![0xAAu8; 32];

    // 1. Start 2 abandoned upload sessions (hitting max_uploads_per_user = 2)
    for req_id in [10u64, 11u64] {
        mallory
            .send_proto(
                Opcode::UploadInitReq,
                req_id,
                &MediaUploadInitRequest {
                    file_name: format!("zombie_{req_id}.bin"),
                    mime_type: "application/octet-stream".to_owned(),
                    size_bytes: 1024 * 1024,
                    sha256_hash: dummy_hash.clone(),
                    width: 0,
                    height: 0,
                },
            )
            .await;
        let reply = mallory.recv_rpc_reply(req_id).await;
        assert_eq!(reply.header.opcode, Opcode::UploadInitRes);
    }

    assert_eq!(count_part_files(&temp_media).await, 2);

    // 2. 3rd concurrent UploadInitReq MUST be rejected with RateLimited before opening a 3rd FD/file
    mallory
        .send_proto(
            Opcode::UploadInitReq,
            12,
            &MediaUploadInitRequest {
                file_name: "zombie_overflow.bin".to_owned(),
                mime_type: "application/octet-stream".to_owned(),
                size_bytes: 1024 * 1024,
                sha256_hash: dummy_hash.clone(),
                width: 0,
                height: 0,
            },
        )
        .await;
    let rejected = mallory.recv_rpc_reply(12).await;
    assert_eq!(rejected.header.opcode, Opcode::Error);
    let rpc_err: RpcError = rejected.decode_proto().unwrap();
    assert_eq!(rpc_err.code, ErrorCode::RateLimited as i32);
    assert_eq!(count_part_files(&temp_media).await, 2);

    // 3. Wait for background TTL cleanup worker to sweep expired zombie `.part` sessions
    tokio::time::sleep(Duration::from_millis(380)).await;
    assert_eq!(
        count_part_files(&temp_media).await,
        0,
        "expired .part files must be deleted by cleanup worker"
    );

    // 4. Verify quota slot was cleanly released by RAII UploadSlotGuard -> fresh upload now succeeds
    mallory
        .send_proto(
            Opcode::UploadInitReq,
            13,
            &MediaUploadInitRequest {
                file_name: "recovered.bin".to_owned(),
                mime_type: "application/octet-stream".to_owned(),
                size_bytes: 4096,
                sha256_hash: dummy_hash,
                width: 0,
                height: 0,
            },
        )
        .await;
    let recovered = mallory.recv_rpc_reply(13).await;
    assert_eq!(recovered.header.opcode, Opcode::UploadInitRes);

    let _ = stop_tx.send(());
    let _ = srv_handle.await;
    let _ = tokio::fs::remove_dir_all(&temp_media).await;
}

#[test]
fn production_signing_key_loader_fails_closed_without_valid_seed() {
    use tgram_server::config::parse_production_signing_key;

    let missing_err = parse_production_signing_key(None)
        .expect_err("server must refuse startup when TGRAM_SERVER_KEY_HEX is missing");
    assert!(missing_err.contains("TGRAM_SERVER_KEY_HEX"));

    assert!(parse_production_signing_key(Some("   ")).is_err());
    assert!(parse_production_signing_key(Some("deadbeef")).is_err());
    assert!(parse_production_signing_key(Some(&"zz".repeat(32))).is_err());

    let valid_hex = "42".repeat(32);
    let key = parse_production_signing_key(Some(&valid_hex)).expect("valid 64-char hex seed");
    assert_eq!(key.to_bytes(), [0x42u8; 32]);
}

#[tokio::test]
async fn cross_chat_same_client_random_id_delivers_independently() {
    // Static SQL schema regression check for H-04
    let schema_sql = include_str!("../migrations/001_init.sql");
    assert!(
        schema_sql.contains("uq_chat_sender_random_id UNIQUE (chat_id, sender_id, client_random_id)"),
        "001_init.sql must scope message idempotency uniqueness to (chat_id, sender_id, client_random_id)"
    );
    assert!(
        !schema_sql.contains("UNIQUE (sender_id, client_random_id)"),
        "legacy cross-chat uq_sender_random_id constraint must not remain in schema"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let temp_media = std::env::temp_dir().join(format!(
        "tgram_test_h04_random_id_{}",
        std::process::id()
    ));
    let _ = tokio::fs::remove_dir_all(&temp_media).await;

    let server_key = generate_server_signing_key();
    let server_pub = server_key.verifying_key();
    let cfg = ServerConfig {
        bind_addr: addr,
        signing_key: server_key,
        database_url: None,
        redis_url: None,
        media_dir: temp_media.clone(),
        handshake_timeout: Duration::from_secs(5),
        unauth_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(30),
        max_connections: 1024,
        max_uploads_per_user: 4,
        max_total_uploads: 64,
        upload_session_ttl: Duration::from_secs(60),
        seed_demo_data: false,
    };

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let srv_handle = tokio::spawn(async move {
        run_with_listener(listener, cfg, async move {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    });

    let mut alice = TestWireClient::connect(addr, &server_pub).await;
    let mut bob = TestWireClient::connect(addr, &server_pub).await;
    let mut charlie = TestWireClient::connect(addr, &server_pub).await;

    let _alice_uid = alice.register_user(1, "alice_h04", "Alice").await;
    let bob_uid = bob.register_user(1, "bob_h04", "Bob").await;
    let charlie_uid = charlie.register_user(1, "charlie_h04", "Charlie").await;

    let colliding_random_id = 424_242_u64;

    // 1. Alice sends message to Bob with client_random_id = 424_242
    alice
        .send_proto(
            Opcode::SendMessageReq,
            10,
            &SendMessageRequest {
                chat_id: 0,
                target_user_id: bob_uid,
                client_random_id: colliding_random_id,
                text: "Сообщение только для Боба".to_owned(),
                reply_to_msg_id: 0,
                media_id: String::new(),
            },
        )
        .await;
    let ack_bob: SendMessageAck = alice.recv_rpc_reply(10).await.decode_proto().unwrap();
    let push_bob: NewMessageUpdate = bob
        .recv_matching(Opcode::NewMessageUpdate)
        .await
        .decode_proto()
        .unwrap();
    assert_eq!(push_bob.message.unwrap().text, "Сообщение только для Боба");

    // 2. Alice sends message to Charlie reusing the EXACT SAME client_random_id = 424_242
    alice
        .send_proto(
            Opcode::SendMessageReq,
            11,
            &SendMessageRequest {
                chat_id: 0,
                target_user_id: charlie_uid,
                client_random_id: colliding_random_id,
                text: "Независимое сообщение для Чарли".to_owned(),
                reply_to_msg_id: 0,
                media_id: String::new(),
            },
        )
        .await;
    let ack_charlie: SendMessageAck = alice.recv_rpc_reply(11).await.decode_proto().unwrap();
    assert_ne!(
        ack_charlie.chat_id, ack_bob.chat_id,
        "colliding client_random_id across distinct chats must never misroute to first chat (H-04)"
    );
    assert_ne!(ack_charlie.msg_id, ack_bob.msg_id);

    let push_charlie: NewMessageUpdate = charlie
        .recv_matching(Opcode::NewMessageUpdate)
        .await
        .decode_proto()
        .unwrap();
    assert_eq!(
        push_charlie.message.unwrap().text,
        "Независимое сообщение для Чарли"
    );

    // 3. Genuine retry within the SAME chat (Bob's chat_id) STILL deduplicates idempotently
    alice
        .send_proto(
            Opcode::SendMessageReq,
            12,
            &SendMessageRequest {
                chat_id: ack_bob.chat_id,
                target_user_id: 0,
                client_random_id: colliding_random_id,
                text: "Сообщение только для Боба".to_owned(),
                reply_to_msg_id: 0,
                media_id: String::new(),
            },
        )
        .await;
    let ack_retry: SendMessageAck = alice.recv_rpc_reply(12).await.decode_proto().unwrap();
    assert_eq!(ack_retry.chat_id, ack_bob.chat_id);
    assert_eq!(ack_retry.msg_id, ack_bob.msg_id);

    let _ = stop_tx.send(());
    let _ = srv_handle.await;
    let _ = tokio::fs::remove_dir_all(&temp_media).await;
}

#[tokio::test]
async fn slow_consumer_backpressure_disconnects_stalled_session() {
    use std::sync::Arc;
    use tgram_proto::ChatMessage;
    use tgram_server::connection::serve_connection;
    use tgram_server::hub::{OutboundPacket, RealtimeHub, SESSION_OUTBOX_CAPACITY};
    use tgram_server::media::MediaManager;
    use tgram_server::store::StorageEngine;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let temp_media = std::env::temp_dir().join(format!(
        "tgram_test_m05_backpressure_{}",
        std::process::id()
    ));
    let _ = tokio::fs::remove_dir_all(&temp_media).await;

    let server_key = generate_server_signing_key();
    let server_pub = server_key.verifying_key();
    let cfg = Arc::new(ServerConfig {
        bind_addr: addr,
        signing_key: server_key,
        database_url: None,
        redis_url: None,
        media_dir: temp_media.clone(),
        handshake_timeout: Duration::from_secs(5),
        unauth_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(60),
        max_connections: 128,
        max_uploads_per_user: 4,
        max_total_uploads: 64,
        upload_session_ttl: Duration::from_secs(60),
        seed_demo_data: false,
    });

    let store = StorageEngine::new_memory(false);
    let media = Arc::new(MediaManager::new(temp_media.clone()).await.unwrap());
    let hub = RealtimeHub::new(store, media);

    let hub_srv = Arc::clone(&hub);
    let cfg_srv = Arc::clone(&cfg);
    let conn_join = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_connection(stream, peer_addr, cfg_srv, hub_srv).await;
    });

    // Connect SlowBob, register, and then STOP reading from `slow_bob.stream` completely
    let mut slow_bob = TestWireClient::connect(addr, &server_pub).await;
    let bob_uid = slow_bob.register_user(1, "slow_bob", "Slow Bob").await;
    assert!(hub.is_user_online(bob_uid));
    assert_eq!(hub.active_socket_count(), 1);

    // Flood SlowBob's session with 8,192 large push frames (~16 MiB) so OS TCP buffers saturate
    // AND `SESSION_OUTBOX_CAPACITY` (1,024) overflows with `TrySendError::Full`
    let big_text = "X".repeat(2048);
    let flood_pkt = OutboundPacket::from_proto(
        Opcode::NewMessageUpdate,
        flags::SERVER_PUSH,
        0,
        &NewMessageUpdate {
            message: Some(ChatMessage {
                msg_id: 99,
                chat_id: 1,
                sender_id: 1,
                client_random_id: 1,
                timestamp_ms: 1_000,
                text: big_text,
                reply_to_msg_id: 0,
                media: None,
                is_read: false,
                pts: 2,
            }),
            sender_brief: None,
            unread_count: 1,
        },
    );

    for _ in 0..(SESSION_OUTBOX_CAPACITY * 8) {
        hub.push_to_user(bob_uid, flood_pkt.clone(), None);
        if !hub.is_user_online(bob_uid) {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert!(
        !hub.is_user_online(bob_uid),
        "stalled slow consumer must be marked disconnected on outbound queue overflow (M-05)"
    );

    // Verify `serve_connection` aborts cleanly without hanging on zero-window `write_all`
    tokio::time::timeout(Duration::from_secs(2), conn_join)
        .await
        .expect("serve_connection hung instead of terminating slow consumer")
        .unwrap();
    assert_eq!(hub.active_socket_count(), 0);

    drop(slow_bob);
    let _ = tokio::fs::remove_dir_all(&temp_media).await;
}

#[tokio::test]
async fn login_timing_mitigation_executes_argon2id_for_unknown_user() {
    use std::time::Instant;
    use tgram_server::auth::verify_password_constant_time;
    use tgram_server::store::{escape_sql_like, StorageEngine};

    // Verify SQL LIKE wildcard escaping (L-01)
    assert_eq!(escape_sql_like("100%_raw\\q"), "100\\%\\_raw\\\\q");

    // Verify constant-work Argon2id equalizer runs full memory-hard verification on `None` / empty PHC (M-01)
    let t0 = Instant::now();
    let res_none = verify_password_constant_time("probe_password".to_owned(), None)
        .await
        .unwrap();
    let elapsed_none = t0.elapsed();
    assert!(!res_none);
    assert!(
        elapsed_none >= Duration::from_millis(2),
        "non-existent user login must execute full Argon2id work rather than returning in microseconds"
    );

    let store = StorageEngine::new_memory(false);
    store
        .authenticate(AuthRequest {
            method: AuthMethod::Register as i32,
            username: "real_alice".to_owned(),
            password: "correct_password_123".to_owned(),
            display_name: "Alice".to_owned(),
            session_token: Vec::new(),
            device_name: "Test".to_owned(),
            last_known_pts: 0,
        })
        .await
        .unwrap();

    let t_ghost = Instant::now();
    let err_ghost = store
        .authenticate(AuthRequest {
            method: AuthMethod::Login as i32,
            username: "ghost_nonexistent".to_owned(),
            password: "wrong_password_123".to_owned(),
            display_name: String::new(),
            session_token: Vec::new(),
            device_name: "Test".to_owned(),
            last_known_pts: 0,
        })
        .await
        .expect_err("ghost user must fail login");
    let d_ghost = t_ghost.elapsed();
    assert_eq!(err_ghost.to_rpc_error().code, ErrorCode::InvalidCredentials as i32);
    assert!(
        d_ghost >= Duration::from_millis(2),
        "MemoryStore::authenticate(Login) must run dummy Argon2id for unknown usernames (M-01)"
    );
}
