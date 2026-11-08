pub mod error;
pub mod frame;
pub mod handshake;
pub mod messages;
pub mod opcodes;

pub use error::{WireError, WireResult};
pub use frame::{DecodedFrame, FrameHeader, FrameOpener, FrameSealer};
pub use handshake::{
    default_server_signing_key, default_server_verifying_key, perform_client_handshake,
    perform_server_handshake, ClientHello, ServerHello, DEFAULT_SERVER_IDENTITY_SEED,
};
pub use messages::*;
pub use opcodes::{flags, Opcode, AEAD_TAG_LEN, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD_LEN};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use ed25519_dalek::SigningKey;

    #[tokio::test]
    async fn handshake_and_bidirectional_aead_roundtrip() {
        let server_key = default_server_signing_key();
        let server_pub = default_server_verifying_key();

        let (mut client_io, mut server_io) = tokio::io::duplex(8192);

        let server_task =
            tokio::spawn(async move { perform_server_handshake(&mut server_io, &server_key).await });
        let (mut c_sealer, mut c_opener) =
            perform_client_handshake(&mut client_io, &server_pub)
                .await
                .expect("client handshake failed");
        let (mut s_sealer, mut s_opener) = server_task
            .await
            .expect("join failed")
            .expect("server handshake failed");

        // Client -> Server RPC frame
        let req = SendMessageRequest {
            chat_id: 42,
            target_user_id: 0,
            client_random_id: 0xDEAD_BEEF_CAFE_0001,
            text: "Привет из нативного Rust клиента!".to_owned(),
            reply_to_msg_id: 0,
            media_id: String::new(),
        };
        let mut wire = BytesMut::new();
        c_sealer
            .seal_proto(Opcode::SendMessageReq, flags::NONE, 77, &req, &mut wire)
            .expect("seal failed");

        let opened = s_opener
            .try_open_next(&mut wire)
            .expect("open failed")
            .expect("complete frame expected");
        assert_eq!(opened.header.opcode, Opcode::SendMessageReq);
        assert_eq!(opened.header.req_id, 77);
        let decoded_req: SendMessageRequest = opened.decode_proto().expect("proto decode failed");
        assert_eq!(decoded_req, req);

        // Server -> Client Push frame
        let push = TypingUpdate {
            chat_id: 42,
            user_id: 1001,
            action: TypingAction::TypingText as i32,
            ttl_ms: 6000,
        };
        s_sealer
            .seal_proto(Opcode::TypingUpdate, flags::SERVER_PUSH, 0, &push, &mut wire)
            .expect("server seal failed");

        let c_opened = c_opener
            .try_open_next(&mut wire)
            .expect("client open failed")
            .expect("complete push frame expected");
        assert_eq!(c_opened.header.opcode, Opcode::TypingUpdate);
        assert_eq!(c_opened.header.req_id, 0);
        let decoded_push: TypingUpdate = c_opened.decode_proto().expect("push decode failed");
        assert_eq!(decoded_push, push);
    }

    #[tokio::test]
    async fn detects_header_aad_and_ciphertext_tampering() {
        let mut sealer = FrameSealer::new([0x11; 32], [0xAA, 0xBB, 0xCC, 0xDD]);
        let mut opener = FrameOpener::new([0x11; 32], [0xAA, 0xBB, 0xCC, 0xDD]);

        let ping = PingRequest {
            client_timestamp_ms: 1_730_000_000_000,
        };
        let mut wire = BytesMut::new();
        sealer
            .seal_proto(Opcode::Ping, flags::NONE, 1, &ping, &mut wire)
            .unwrap();

        // Tamper with req_id inside cleartext AAD header (byte offset 8)
        wire[8] ^= 0xFF;

        let err = opener.try_open_next(&mut wire).unwrap_err();
        assert!(matches!(err, WireError::AeadTampered));
    }

    #[tokio::test]
    async fn rejects_mitm_impostor_server_key() {
        let impostor_key = SigningKey::from_bytes(&[0x99; 32]);
        let pinned_pub = default_server_verifying_key();

        let (mut client_io, mut server_io) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = perform_server_handshake(&mut server_io, &impostor_key).await;
        });

        let res = perform_client_handshake(&mut client_io, &pinned_pub).await;
        assert!(matches!(res, Err(WireError::InvalidServerSignature)));
    }
}
