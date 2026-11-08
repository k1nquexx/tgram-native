//! Wire-compatible Protobuf v3 message structures matching `proto/mtwire.proto`.
//! Compiled directly via `prost` derive macros without requiring an external C++ `protoc` binary.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PeerType {
    Unspecified = 0,
    Direct = 1,
    Group = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum UserOnlineState {
    Unspecified = 0,
    Offline = 1,
    Online = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum MessageDeliveryState {
    Unspecified = 0,
    Sending = 1,
    Sent = 2,
    Read = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum TypingAction {
    Cancel = 0,
    TypingText = 1,
    Uploading = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ErrorCode {
    Unspecified = 0,
    BadRequest = 1,
    Unauthorized = 2,
    InvalidLogin = 3,
    UsernameTaken = 4,
    ChatNotFound = 5,
    RateLimited = 6,
    PayloadTooLarge = 7,
    Internal = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AuthMethod {
    Unspecified = 0,
    Login = 1,
    Register = 2,
    TokenResume = 3,
}

// ----------------------------------------------------------------------------
// Core Domain Entities
// ----------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserProfile {
    #[prost(uint64, tag = "1")]
    pub user_id: u64,
    #[prost(string, tag = "2")]
    pub username: String,
    #[prost(string, tag = "3")]
    pub display_name: String,
    #[prost(uint32, tag = "4")]
    pub avatar_color_rgb: u32,
    #[prost(string, tag = "5")]
    pub avatar_media_id: String,
    #[prost(enumeration = "UserOnlineState", tag = "6")]
    pub status: i32,
    #[prost(int64, tag = "7")]
    pub last_seen_ms: i64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MediaAttachment {
    #[prost(string, tag = "1")]
    pub media_id: String,
    #[prost(string, tag = "2")]
    pub file_name: String,
    #[prost(string, tag = "3")]
    pub mime_type: String,
    #[prost(uint64, tag = "4")]
    pub size_bytes: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub sha256_hash: Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub width: u32,
    #[prost(uint32, tag = "7")]
    pub height: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChatMessage {
    #[prost(uint64, tag = "1")]
    pub msg_id: u64,
    #[prost(uint64, tag = "2")]
    pub chat_id: u64,
    #[prost(uint64, tag = "3")]
    pub sender_id: u64,
    #[prost(uint64, tag = "4")]
    pub client_random_id: u64,
    #[prost(int64, tag = "5")]
    pub timestamp_ms: i64,
    #[prost(string, tag = "6")]
    pub text: String,
    #[prost(uint64, tag = "7")]
    pub reply_to_msg_id: u64,
    #[prost(message, optional, tag = "8")]
    pub media: Option<MediaAttachment>,
    #[prost(bool, tag = "9")]
    pub is_read: bool,
    #[prost(uint64, tag = "10")]
    pub pts: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DialogEntry {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(enumeration = "PeerType", tag = "2")]
    pub peer_type: i32,
    #[prost(string, tag = "3")]
    pub title: String,
    #[prost(uint64, tag = "4")]
    pub peer_user_id: u64,
    #[prost(uint32, tag = "5")]
    pub avatar_color_rgb: u32,
    #[prost(message, optional, tag = "6")]
    pub top_message: Option<ChatMessage>,
    #[prost(uint32, tag = "7")]
    pub unread_count: u32,
    #[prost(uint64, tag = "8")]
    pub read_inbox_max_msg_id: u64,
    #[prost(uint64, tag = "9")]
    pub read_outbox_max_msg_id: u64,
    #[prost(bool, tag = "10")]
    pub is_pinned: bool,
    #[prost(int64, tag = "11")]
    pub sort_timestamp_ms: i64,
}

// ----------------------------------------------------------------------------
// Transport & Error Control (0x0001 - 0x000F)
// ----------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PingRequest {
    #[prost(int64, tag = "1")]
    pub client_timestamp_ms: i64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PongResponse {
    #[prost(int64, tag = "1")]
    pub client_timestamp_ms: i64,
    #[prost(int64, tag = "2")]
    pub server_timestamp_ms: i64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RpcError {
    #[prost(enumeration = "ErrorCode", tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(uint32, tag = "3")]
    pub retry_after_ms: u32,
}

// ----------------------------------------------------------------------------
// Authentication & Session Lifecycle (0x0010 - 0x001F)
// ----------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthRequest {
    #[prost(enumeration = "AuthMethod", tag = "1")]
    pub method: i32,
    #[prost(string, tag = "2")]
    pub username: String,
    #[prost(string, tag = "3")]
    pub password: String,
    #[prost(string, tag = "4")]
    pub display_name: String,
    #[prost(bytes = "vec", tag = "5")]
    pub session_token: Vec<u8>,
    #[prost(string, tag = "6")]
    pub device_name: String,
    #[prost(uint64, tag = "7")]
    pub last_known_pts: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthResponse {
    #[prost(message, optional, tag = "1")]
    pub self_profile: Option<UserProfile>,
    #[prost(bytes = "vec", tag = "2")]
    pub session_token: Vec<u8>,
    #[prost(int64, tag = "3")]
    pub server_time_ms: i64,
    #[prost(uint64, tag = "4")]
    pub current_pts: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogoutRequest {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogoutResponse {
    #[prost(bool, tag = "1")]
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PushProvider {
    Unspecified = 0,
    Fcm = 1,
    Apns = 2,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterPushTokenRequest {
    #[prost(enumeration = "PushProvider", tag = "1")]
    pub provider: i32,
    #[prost(string, tag = "2")]
    pub device_token: String,
    #[prost(string, tag = "3")]
    pub app_bundle_id: String,
    #[prost(bool, tag = "4")]
    pub sandbox: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterPushTokenResponse {
    #[prost(bool, tag = "1")]
    pub registered: bool,
    #[prost(int64, tag = "2")]
    pub updated_at_ms: i64,
}

// ----------------------------------------------------------------------------
// Dialogs, History & Peer Discovery (0x0020 - 0x002F)
// ----------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncDialogsRequest {
    #[prost(uint32, tag = "1")]
    pub limit: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncDialogsResponse {
    #[prost(message, repeated, tag = "1")]
    pub dialogs: Vec<DialogEntry>,
    #[prost(message, repeated, tag = "2")]
    pub users: Vec<UserProfile>,
    #[prost(uint64, tag = "3")]
    pub current_pts: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetHistoryRequest {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(uint64, tag = "2")]
    pub before_msg_id: u64,
    #[prost(uint32, tag = "3")]
    pub limit: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetHistoryResponse {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(message, repeated, tag = "2")]
    pub messages: Vec<ChatMessage>,
    #[prost(bool, tag = "3")]
    pub has_more: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SearchPeersRequest {
    #[prost(string, tag = "1")]
    pub query: String,
    #[prost(uint32, tag = "2")]
    pub limit: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SearchPeersResponse {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<UserProfile>,
    #[prost(message, repeated, tag = "2")]
    pub dialogs: Vec<DialogEntry>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateDirectChatRequest {
    #[prost(uint64, tag = "1")]
    pub target_user_id: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateDirectChatResponse {
    #[prost(message, optional, tag = "1")]
    pub dialog: Option<DialogEntry>,
    #[prost(message, optional, tag = "2")]
    pub peer: Option<UserProfile>,
}

// ----------------------------------------------------------------------------
// Real-Time Messaging (0x0030 - 0x003F)
// ----------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendMessageRequest {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(uint64, tag = "2")]
    pub target_user_id: u64,
    #[prost(uint64, tag = "3")]
    pub client_random_id: u64,
    #[prost(string, tag = "4")]
    pub text: String,
    #[prost(uint64, tag = "5")]
    pub reply_to_msg_id: u64,
    #[prost(string, tag = "6")]
    pub media_id: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendMessageAck {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(uint64, tag = "2")]
    pub client_random_id: u64,
    #[prost(uint64, tag = "3")]
    pub msg_id: u64,
    #[prost(int64, tag = "4")]
    pub server_timestamp_ms: i64,
    #[prost(uint64, tag = "5")]
    pub pts: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewMessageUpdate {
    #[prost(message, optional, tag = "1")]
    pub message: Option<ChatMessage>,
    #[prost(message, optional, tag = "2")]
    pub sender_brief: Option<UserProfile>,
    #[prost(uint32, tag = "3")]
    pub unread_count: u32,
}

// ----------------------------------------------------------------------------
// Read Receipts, Typing & Presence (0x0040 - 0x004F)
// ----------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadAckRequest {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(uint64, tag = "2")]
    pub max_read_msg_id: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadAckResponse {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(uint64, tag = "2")]
    pub max_read_msg_id: u64,
    #[prost(uint32, tag = "3")]
    pub unread_count: u32,
    #[prost(uint64, tag = "4")]
    pub pts: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReadHistoryUpdate {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(uint64, tag = "2")]
    pub reader_user_id: u64,
    #[prost(uint64, tag = "3")]
    pub max_read_msg_id: u64,
    #[prost(int64, tag = "4")]
    pub read_at_ms: i64,
    #[prost(uint64, tag = "5")]
    pub pts: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TypingEventRequest {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(enumeration = "TypingAction", tag = "2")]
    pub action: i32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TypingUpdate {
    #[prost(uint64, tag = "1")]
    pub chat_id: u64,
    #[prost(uint64, tag = "2")]
    pub user_id: u64,
    #[prost(enumeration = "TypingAction", tag = "3")]
    pub action: i32,
    #[prost(uint32, tag = "4")]
    pub ttl_ms: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PresenceUpdate {
    #[prost(uint64, tag = "1")]
    pub user_id: u64,
    #[prost(enumeration = "UserOnlineState", tag = "2")]
    pub status: i32,
    #[prost(int64, tag = "3")]
    pub last_seen_ms: i64,
}

// ----------------------------------------------------------------------------
// Chunked Media Transfer (0x0050 - 0x005F)
// ----------------------------------------------------------------------------

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MediaUploadInitRequest {
    #[prost(string, tag = "1")]
    pub file_name: String,
    #[prost(string, tag = "2")]
    pub mime_type: String,
    #[prost(uint64, tag = "3")]
    pub size_bytes: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub sha256_hash: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub width: u32,
    #[prost(uint32, tag = "6")]
    pub height: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MediaUploadInitResponse {
    #[prost(string, tag = "1")]
    pub upload_id: String,
    #[prost(uint32, tag = "2")]
    pub chunk_size: u32,
    #[prost(bool, tag = "3")]
    pub already_deduped: bool,
    #[prost(string, tag = "4")]
    pub ready_media_id: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MediaUploadChunkRequest {
    #[prost(string, tag = "1")]
    pub upload_id: String,
    #[prost(uint32, tag = "2")]
    pub chunk_index: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub data: Vec<u8>,
    #[prost(bool, tag = "4")]
    pub is_last_chunk: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MediaUploadChunkAck {
    #[prost(string, tag = "1")]
    pub upload_id: String,
    #[prost(uint32, tag = "2")]
    pub chunk_index: u32,
    #[prost(uint64, tag = "3")]
    pub bytes_received: u64,
    #[prost(string, tag = "4")]
    pub media_id: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MediaDownloadChunkRequest {
    #[prost(string, tag = "1")]
    pub media_id: String,
    #[prost(uint64, tag = "2")]
    pub offset: u64,
    #[prost(uint32, tag = "3")]
    pub length: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MediaDownloadChunkResponse {
    #[prost(string, tag = "1")]
    pub media_id: String,
    #[prost(uint64, tag = "2")]
    pub offset: u64,
    #[prost(uint64, tag = "3")]
    pub total_size: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub data: Vec<u8>,
    #[prost(bool, tag = "5")]
    pub eof: bool,
}
