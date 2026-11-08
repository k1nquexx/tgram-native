use crate::error::{WireError, WireResult};

/// Little-Endian magic `'T', 'G', 'N', 'V'` (`0x564E4754`).
pub const WIRE_MAGIC: u32 = 0x564E_4754;

/// MTWire protocol version 1.
pub const PROTO_VERSION_V1: u16 = 0x0001;

/// Cipher suite ID for `X25519 + Ed25519 + HKDF-SHA256 + ChaCha20-Poly1305`.
pub const CIPHER_SUITE_X25519_CHACHA20POLY1305: u16 = 0x0001;

/// Fixed byte sizes for handshake & encrypted packets.
pub const CLIENT_HELLO_LEN: usize = 44;
pub const SERVER_HELLO_LEN: usize = 108;
pub const FRAME_HEADER_LEN: usize = 16;
pub const AEAD_TAG_LEN: usize = 16;
pub const MAX_FRAME_PAYLOAD_LEN: u32 = 4 * 1024 * 1024; // 4 MiB hard cap

/// Frame header bitflags (`uint16_le` at offset 6..8).
pub mod flags {
    pub const NONE: u16 = 0x0000;
    pub const SERVER_PUSH: u16 = 0x0001;
    pub const NEEDS_ACK: u16 = 0x0002;
    pub const COMPRESSED_LZ4: u16 = 0x0004;
}

/// Canonical MTWire v1 packet opcode (`uint16_le` at offset 4..6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Opcode {
    // Transport & Error Control
    Ping = 0x0001,
    Pong = 0x0002,
    Error = 0x000F,

    // Authentication & Session
    AuthReq = 0x0010,
    AuthRes = 0x0011,
    LogoutReq = 0x0012,
    LogoutRes = 0x0013,
    RegisterPushTokenReq = 0x0014,
    RegisterPushTokenRes = 0x0015,

    // Dialogs, History & Peer Discovery
    SyncDialogsReq = 0x0020,
    SyncDialogsRes = 0x0021,
    GetHistoryReq = 0x0022,
    GetHistoryRes = 0x0023,
    SearchPeersReq = 0x0024,
    SearchPeersRes = 0x0025,
    CreateDirectChatReq = 0x0026,
    CreateDirectChatRes = 0x0027,

    // Real-Time Messaging
    SendMessageReq = 0x0030,
    SendMessageAck = 0x0031,
    NewMessageUpdate = 0x0032,

    // Read Receipts, Typing & Presence
    ReadAckReq = 0x0040,
    ReadAckRes = 0x0041,
    ReadHistoryUpdate = 0x0042,
    TypingEventReq = 0x0043,
    TypingUpdate = 0x0044,
    PresenceUpdate = 0x0045,

    // Chunked Media Transfer
    UploadInitReq = 0x0050,
    UploadInitRes = 0x0051,
    UploadChunkReq = 0x0052,
    UploadChunkAck = 0x0053,
    DownloadChunkReq = 0x0054,
    DownloadChunkRes = 0x0055,
}

impl Opcode {
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[inline]
    pub const fn is_server_push(self) -> bool {
        matches!(
            self,
            Self::NewMessageUpdate
                | Self::ReadHistoryUpdate
                | Self::TypingUpdate
                | Self::PresenceUpdate
        )
    }
}

impl TryFrom<u16> for Opcode {
    type Error = WireError;

    #[inline]
    fn try_from(raw: u16) -> WireResult<Self> {
        let op = match raw {
            0x0001 => Self::Ping,
            0x0002 => Self::Pong,
            0x000F => Self::Error,

            0x0010 => Self::AuthReq,
            0x0011 => Self::AuthRes,
            0x0012 => Self::LogoutReq,
            0x0013 => Self::LogoutRes,
            0x0014 => Self::RegisterPushTokenReq,
            0x0015 => Self::RegisterPushTokenRes,

            0x0020 => Self::SyncDialogsReq,
            0x0021 => Self::SyncDialogsRes,
            0x0022 => Self::GetHistoryReq,
            0x0023 => Self::GetHistoryRes,
            0x0024 => Self::SearchPeersReq,
            0x0025 => Self::SearchPeersRes,
            0x0026 => Self::CreateDirectChatReq,
            0x0027 => Self::CreateDirectChatRes,

            0x0030 => Self::SendMessageReq,
            0x0031 => Self::SendMessageAck,
            0x0032 => Self::NewMessageUpdate,

            0x0040 => Self::ReadAckReq,
            0x0041 => Self::ReadAckRes,
            0x0042 => Self::ReadHistoryUpdate,
            0x0043 => Self::TypingEventReq,
            0x0044 => Self::TypingUpdate,
            0x0045 => Self::PresenceUpdate,

            0x0050 => Self::UploadInitReq,
            0x0051 => Self::UploadInitRes,
            0x0052 => Self::UploadChunkReq,
            0x0053 => Self::UploadChunkAck,
            0x0054 => Self::DownloadChunkReq,
            0x0055 => Self::DownloadChunkRes,

            other => return Err(WireError::UnknownOpcode(other)),
        };
        Ok(op)
    }
}
