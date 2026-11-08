pub mod error;
pub mod frame;
pub mod handshake;
pub mod messages;
pub mod opcodes;

pub use error::{WireError, WireResult};
pub use frame::{DecodedFrame, FrameHeader, FrameOpener, FrameSealer};
pub use handshake::{
    generate_server_signing_key, parse_signing_key_hex, parse_verifying_key_hex,
    perform_client_handshake, perform_server_handshake, ClientHello, ServerHello,
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
        let server_key = generate_server_signing_key();
        let server_pub = server_key.verifying_key();

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
        assert_eq!(opener.sequence(), 0, "failed open must not advance sequence");
    }

    #[tokio::test]
    async fn rejects_mitm_impostor_server_key() {
        let impostor_key = SigningKey::from_bytes(&[0x99; 32]);
        let legitimate_key = generate_server_signing_key();
        let pinned_pub = legitimate_key.verifying_key();

        let (mut client_io, mut server_io) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = perform_server_handshake(&mut server_io, &impostor_key).await;
        });

        let res = perform_client_handshake(&mut client_io, &pinned_pub).await;
        assert!(matches!(res, Err(WireError::InvalidServerSignature)));
    }

    #[test]
    fn key_hex_parsers_validate_length_and_roundtrip() {
        let sk = generate_server_signing_key();
        let sk_hex = hex::encode(sk.to_bytes());
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());

        let parsed_sk = parse_signing_key_hex(&sk_hex).expect("valid signing key hex");
        let parsed_vk = parse_verifying_key_hex(&vk_hex).expect("valid verifying key hex");
        assert_eq!(parsed_sk.verifying_key(), parsed_vk);

        assert!(matches!(
            parse_signing_key_hex(""),
            Err(WireError::InvalidKeyMaterial(_))
        ));
        assert!(matches!(
            parse_signing_key_hex("deadbeef"),
            Err(WireError::InvalidKeyMaterial(_))
        ));
        assert!(matches!(
            parse_verifying_key_hex("zz"),
            Err(WireError::InvalidKeyMaterial(_))
        ));
    }

    #[test]
    fn sealer_error_does_not_desync_sequence_or_corrupt_buffer() {
        let mut sealer = FrameSealer::new([0x33; 32], [0x01, 0x02, 0x03, 0x04]);
        let mut opener = FrameOpener::new([0x33; 32], [0x01, 0x02, 0x03, 0x04]);
        let mut wire = BytesMut::new();

        // 1. Seal a valid first frame (seq 0 -> 1)
        let ping_1 = PingRequest {
            client_timestamp_ms: 100,
        };
        sealer
            .seal_proto(Opcode::Ping, flags::NONE, 1, &ping_1, &mut wire)
            .unwrap();
        assert_eq!(sealer.sequence(), 1);
        let len_after_first = wire.len();

        // 2. Attempt to seal an oversized frame into the SAME coalesced buffer -> must fail cleanly
        let oversized = vec![0xABu8; (MAX_FRAME_PAYLOAD_LEN as usize) + 64];
        let err = sealer
            .seal_raw(Opcode::Ping, flags::NONE, 2, &oversized, &mut wire)
            .unwrap_err();
        assert!(matches!(err, WireError::FrameTooLarge(_, _)));
        assert_eq!(sealer.sequence(), 1, "seq must NOT advance on FrameTooLarge");
        assert_eq!(wire.len(), len_after_first, "dst buffer must remain intact");

        // 3. Seal a valid frame right after the failed call (must use seq = 1, keeping opener in sync)
        let ping_2 = PingRequest {
            client_timestamp_ms: 200,
        };
        sealer
            .seal_proto(Opcode::Ping, flags::NONE, 3, &ping_2, &mut wire)
            .unwrap();
        assert_eq!(sealer.sequence(), 2);

        let f1 = opener.try_open_next(&mut wire).unwrap().unwrap();
        assert_eq!(f1.header.req_id, 1);
        assert_eq!(f1.decode_proto::<PingRequest>().unwrap(), ping_1);

        let f2 = opener.try_open_next(&mut wire).unwrap().unwrap();
        assert_eq!(f2.header.req_id, 3);
        assert_eq!(f2.decode_proto::<PingRequest>().unwrap(), ping_2);
        assert_eq!(opener.sequence(), 2);

        // 4. Verify u64::MAX SequenceOverflow leaves both sealer & opener unmutated
        sealer.set_sequence_for_test(u64::MAX);
        opener.set_sequence_for_test(u64::MAX);
        let overflow_err = sealer
            .seal_proto(Opcode::Ping, flags::NONE, 4, &ping_1, &mut wire)
            .unwrap_err();
        assert!(matches!(overflow_err, WireError::SequenceOverflow));
        assert_eq!(sealer.sequence(), u64::MAX);
        assert!(wire.is_empty());
    }

    #[test]
    fn fuzz_fragmented_stream_and_interleaved_frames() {
        let mut sealer = FrameSealer::new([0x77; 32], [0xDE, 0xAD, 0xBE, 0xEF]);
        let mut opener = FrameOpener::new([0x77; 32], [0xDE, 0xAD, 0xBE, 0xEF]);

        let mut full_stream = BytesMut::new();
        let mut expected_messages = Vec::with_capacity(128);
        let mut prng_state: u64 = 0x9E37_79B9_7F4A_7C15;

        let mut next_rand = || -> u64 {
            prng_state ^= prng_state << 13;
            prng_state ^= prng_state >> 7;
            prng_state ^= prng_state << 17;
            prng_state
        };

        for i in 0..128u64 {
            // Periodically inject an oversized seal attempt to verify zero state corruption
            if i % 19 == 0 {
                let huge = SendMessageRequest {
                    chat_id: 1,
                    target_user_id: 0,
                    client_random_id: i,
                    text: "X".repeat((MAX_FRAME_PAYLOAD_LEN as usize) + 1),
                    reply_to_msg_id: 0,
                    media_id: String::new(),
                };
                let before_seq = sealer.sequence();
                let before_len = full_stream.len();
                assert!(matches!(
                    sealer.seal_proto(Opcode::SendMessageReq, flags::NONE, i, &huge, &mut full_stream),
                    Err(WireError::FrameTooLarge(_, _))
                ));
                assert_eq!(sealer.sequence(), before_seq);
                assert_eq!(full_stream.len(), before_len);
            }

            let body_len = (next_rand() % 1500) as usize;
            let text: String = (0..body_len)
                .map(|k| char::from(b'a' + ((k as u8 + i as u8) % 26)))
                .collect();
            let msg = SendMessageRequest {
                chat_id: 100 + (i % 7),
                target_user_id: 0,
                client_random_id: 10_000 + i,
                text,
                reply_to_msg_id: 0,
                media_id: String::new(),
            };
            sealer
                .seal_proto(Opcode::SendMessageReq, flags::NONE, i + 1, &msg, &mut full_stream)
                .expect("valid frame must seal");
            expected_messages.push((i + 1, msg));
        }

        // Feed the stream into FrameOpener in randomized tiny TCP fragments (1..23 bytes)
        let mut rx_buf = BytesMut::new();
        let mut decoded = Vec::with_capacity(expected_messages.len());
        let mut cursor = 0usize;
        while cursor < full_stream.len() {
            let chunk_size = ((next_rand() % 23) as usize + 1).min(full_stream.len() - cursor);
            rx_buf.extend_from_slice(&full_stream[cursor..cursor + chunk_size]);
            cursor += chunk_size;

            while let Some(frame) = opener.try_open_next(&mut rx_buf).expect("valid stream") {
                let parsed: SendMessageRequest = frame.decode_proto().expect("valid protobuf");
                decoded.push((frame.header.req_id, parsed));
            }
        }

        assert!(rx_buf.is_empty());
        assert_eq!(decoded, expected_messages);
        assert_eq!(opener.sequence(), sealer.sequence());
    }
}
