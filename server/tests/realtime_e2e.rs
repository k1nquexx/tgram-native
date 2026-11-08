use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tgram_proto::{
    default_server_signing_key, default_server_verifying_key, flags, perform_client_handshake,
    AuthMethod, AuthRequest, AuthResponse, DecodedFrame, FrameOpener, FrameSealer,
    NewMessageUpdate, Opcode, ReadAckRequest, ReadAckResponse, ReadHistoryUpdate, SendMessageAck,
    SendMessageRequest, TypingAction, TypingEventRequest, TypingUpdate,
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
    async fn connect(addr: std::net::SocketAddr) -> Self {
        let mut stream = TcpStream::connect(addr).await.expect("connect failed");
        stream.set_nodelay(true).unwrap();
        let pub_key = default_server_verifying_key();
        let (sealer, opener) = perform_client_handshake(&mut stream, &pub_key)
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
}

#[tokio::test]
async fn realtime_auth_message_typing_and_read_receipt_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let temp_media = std::env::temp_dir().join(format!(
        "tgram_test_media_{}",
        std::process::id()
    ));

    let cfg = ServerConfig {
        bind_addr: addr,
        signing_key: default_server_signing_key(),
        database_url: None,
        redis_url: None,
        media_dir: temp_media.clone(),
        handshake_timeout: Duration::from_secs(5),
        unauth_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(30),
        max_connections: 1024,
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

    let mut alice = TestWireClient::connect(addr).await;
    let mut bob = TestWireClient::connect(addr).await;

    // 1. Register Alice & Bob
    alice
        .send_proto(
            Opcode::AuthReq,
            1,
            &AuthRequest {
                method: AuthMethod::Register as i32,
                username: "alice".to_owned(),
                password: "secret_password".to_owned(),
                display_name: "Alice".to_owned(),
                session_token: Vec::new(),
                device_name: "Test Alice".to_owned(),
                last_known_pts: 0,
            },
        )
        .await;
    let alice_auth: AuthResponse = alice
        .recv_matching(Opcode::AuthRes)
        .await
        .decode_proto()
        .unwrap();
    let alice_uid = alice_auth.self_profile.unwrap().user_id;

    bob.send_proto(
        Opcode::AuthReq,
        1,
        &AuthRequest {
            method: AuthMethod::Register as i32,
            username: "bob".to_owned(),
            password: "secret_password".to_owned(),
            display_name: "Bob".to_owned(),
            session_token: Vec::new(),
            device_name: "Test Bob".to_owned(),
            last_known_pts: 0,
        },
    )
    .await;
    let bob_auth: AuthResponse = bob
        .recv_matching(Opcode::AuthRes)
        .await
        .decode_proto()
        .unwrap();
    let bob_uid = bob_auth.self_profile.unwrap().user_id;

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
