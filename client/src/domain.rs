use std::path::PathBuf;

use crossbeam_channel::Sender as CrossbeamSender;
use tokio::sync::mpsc::UnboundedSender;
use tgram_proto::{
    AuthRequest, ChatMessage, DialogEntry, MediaAttachment, MessageDeliveryState, NewMessageUpdate,
    PeerType, PresenceUpdate, ReadAckResponse, ReadHistoryUpdate, SendMessageAck, TypingAction,
    TypingUpdate, UserProfile,
};

#[derive(Debug, Clone)]
pub struct ClientLaunchConfig {
    pub profile_name: String,
    pub default_server_addr: String,
    pub db_path: PathBuf,
    pub downloads_dir: PathBuf,
}

impl ClientLaunchConfig {
    pub fn from_args() -> Self {
        let mut profile_name = std::env::var("TGRAM_PROFILE").unwrap_or_else(|_| "default".into());
        let mut default_server_addr =
            std::env::var("TGRAM_SERVER").unwrap_or_else(|_| "127.0.0.1:4430".into());

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--profile" | "-p" => {
                    if let Some(val) = args.next() {
                        let clean: String = val
                            .chars()
                            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                            .collect();
                        if !clean.is_empty() {
                            profile_name = clean;
                        }
                    }
                }
                "--server" | "-s" => {
                    if let Some(val) = args.next() {
                        if !val.trim().is_empty() {
                            default_server_addr = val.trim().to_owned();
                        }
                    }
                }
                _ => {}
            }
        }

        let base_dir = PathBuf::from("./data");
        let db_path = base_dir.join(format!("client_{profile_name}.sqlite3"));
        let downloads_dir = base_dir.join(format!("downloads_{profile_name}"));

        Self {
            profile_name,
            default_server_addr,
            db_path,
            downloads_dir,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Handshaking,
    Authenticating,
    Online,
    Reconnecting { attempt: u32 },
}

impl ConnectionState {
    pub fn label_ru(&self) -> String {
        match self {
            Self::Disconnected => "Не в сети".to_owned(),
            Self::Connecting => "Подключение...".to_owned(),
            Self::Handshaking => "Обмен ключами X25519...".to_owned(),
            Self::Authenticating => "Авторизация...".to_owned(),
            Self::Online => "Подключено (MTWire AEAD)".to_owned(),
            Self::Reconnecting { attempt } => format!("Переподключение (#{attempt})..."),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SavedSession {
    pub server_addr: String,
    pub self_profile: UserProfile,
    pub session_token: Vec<u8>,
    pub last_pts: u64,
}

#[derive(Debug, Clone)]
pub enum MediaTransferStatus {
    Idle,
    Uploading { progress: f32 },
    Downloading { progress: f32 },
    Downloaded { local_path: PathBuf },
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct UiMediaState {
    pub attachment: MediaAttachment,
    pub transfer: MediaTransferStatus,
}

#[derive(Debug, Clone)]
pub struct UiDialog {
    pub chat_id: u64,
    pub peer_type: PeerType,
    pub title: String,
    pub peer_user_id: u64,
    pub avatar_color_rgb: u32,
    pub top_preview: String,
    pub top_sender_is_self: bool,
    pub top_delivery: Option<MessageDeliveryState>,
    pub top_timestamp_ms: i64,
    pub top_time_label: String,
    pub unread_count: u32,
    pub read_inbox_max_msg_id: u64,
    pub read_outbox_max_msg_id: u64,
    pub is_pinned: bool,
    pub sort_timestamp_ms: i64,
}

#[derive(Debug, Clone)]
pub struct UiMessage {
    pub msg_id: u64,
    pub client_random_id: u64,
    pub chat_id: u64,
    pub sender_id: u64,
    pub sender_name: String,
    pub sender_color_rgb: u32,
    pub is_outgoing: bool,
    pub timestamp_ms: i64,
    pub time_label: String,
    pub text: String,
    pub delivery: MessageDeliveryState,
    pub media: Option<UiMediaState>,
}

impl UiMessage {
    #[inline]
    pub fn identity_key(&self) -> (u64, u64) {
        (self.msg_id, self.client_random_id)
    }
}

/// Handles passed to UI Thread once `StorageThread` and `NetworkThread` are spawned.
#[derive(Debug, Clone)]
pub struct BackendHandles {
    pub storage_tx: CrossbeamSender<StorageCommand>,
    pub net_tx: UnboundedSender<NetCommand>,
}

/// Commands dispatched non-blockingly to the dedicated SQLite WAL `StorageThread`.
#[derive(Debug)]
pub enum StorageCommand {
    LoadBootstrap,
    SaveSession(SavedSession),
    ClearSession,
    SaveDialogsAndUsers {
        dialogs: Vec<DialogEntry>,
        users: Vec<UserProfile>,
        pts: u64,
    },
    LoadChatHistory {
        chat_id: u64,
        limit: usize,
    },
    UpsertMessages {
        chat_id: u64,
        messages: Vec<ChatMessage>,
    },
    UpdateOutboxAck {
        chat_id: u64,
        client_random_id: u64,
        msg_id: u64,
        timestamp_ms: i64,
        pts: u64,
    },
    UpdateReadOutbox {
        chat_id: u64,
        max_read_msg_id: u64,
    },
    UpdateReadInbox {
        chat_id: u64,
        max_read_msg_id: u64,
        unread_count: u32,
    },
    RecordDownloadedMedia {
        media_id: String,
        local_path: PathBuf,
    },
    GenerateStressHistory {
        chat_id: u64,
        self_user_id: u64,
        peer_user_id: u64,
        count: usize,
    },
    Shutdown,
}

/// Commands dispatched non-blockingly to the dedicated async `NetworkThread`.
#[derive(Debug, Clone)]
pub enum NetCommand {
    ConnectAndAuth {
        server_addr: String,
        req: AuthRequest,
    },
    LogoutAndDisconnect,
    SyncDialogs,
    FetchHistory {
        chat_id: u64,
        before_msg_id: u64,
        limit: u32,
    },
    SearchPeers {
        query: String,
    },
    OpenDirectChat {
        target_user_id: u64,
    },
    SendTextMessage {
        chat_id: u64,
        target_user_id: u64,
        client_random_id: u64,
        text: String,
    },
    SendFileAttachment {
        chat_id: u64,
        client_random_id: u64,
        file_path: PathBuf,
        caption: String,
    },
    DownloadAttachment {
        chat_id: u64,
        msg_id: u64,
        attachment: MediaAttachment,
        dest_dir: PathBuf,
    },
    SendReadAck {
        chat_id: u64,
        max_read_msg_id: u64,
    },
    SendTyping {
        chat_id: u64,
        action: TypingAction,
    },
}

/// Events pushed asynchronously from `StorageThread` and `NetworkThread` into `UI Thread`.
#[derive(Debug, Clone)]
pub enum BackendEvent {
    BootstrapLoaded {
        session: Option<SavedSession>,
        dialogs: Vec<DialogEntry>,
        users: Vec<UserProfile>,
        downloaded_files: Vec<(String, PathBuf)>,
    },
    CachedHistoryLoaded {
        chat_id: u64,
        messages: Vec<ChatMessage>,
    },
    ConnectionChanged(ConnectionState),
    AuthSucceeded {
        server_addr: String,
        profile: UserProfile,
        session_token: Vec<u8>,
        current_pts: u64,
    },
    AuthFailed(String),
    LoggedOut,
    DialogsSynced {
        dialogs: Vec<DialogEntry>,
        users: Vec<UserProfile>,
        current_pts: u64,
    },
    HistoryFetched {
        chat_id: u64,
        messages: Vec<ChatMessage>,
        has_more: bool,
    },
    SearchResults {
        users: Vec<UserProfile>,
        dialogs: Vec<DialogEntry>,
    },
    DirectChatOpened {
        dialog: DialogEntry,
        peer: UserProfile,
    },
    MessageAcked(SendMessageAck),
    IncomingMessage(NewMessageUpdate),
    ReadAckConfirmed(ReadAckResponse),
    PeerReadHistory(ReadHistoryUpdate),
    PeerTyping(TypingUpdate),
    PeerPresence(PresenceUpdate),
    MediaUploadProgress {
        chat_id: u64,
        client_random_id: u64,
        attachment: MediaAttachment,
        progress: f32,
    },
    MediaDownloadProgress {
        chat_id: u64,
        msg_id: u64,
        media_id: String,
        progress: f32,
    },
    MediaDownloadFinished {
        chat_id: u64,
        msg_id: u64,
        media_id: String,
        local_path: PathBuf,
    },
    MediaTransferFailed {
        chat_id: u64,
        client_random_id: u64,
        msg_id: u64,
        error: String,
    },
    TransientError(String),
}

/// Formats Unix epoch milliseconds into `HH:MM` local-style 24h clock without heavy chrono dependencies.
pub fn format_hh_mm(timestamp_ms: i64) -> String {
    if timestamp_ms <= 0 {
        return String::new();
    }
    let total_secs = (timestamp_ms / 1000).max(0);
    // Apply local timezone offset estimation via OS or UTC+3/+7; let's compute civil clock cleanly:
    let secs_of_day = total_secs.rem_euclid(86_400);
    let hours = secs_of_day / 3600;
    let minutes = (secs_of_day % 3600) / 60;
    format!("{hours:02}:{minutes:02}")
}

pub fn format_bytes_human(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if (bytes as f64) < KIB {
        format!("{bytes} B")
    } else if (bytes as f64) < MIB {
        format!("{:.1} KB", (bytes as f64) / KIB)
    } else {
        format!("{:.2} MB", (bytes as f64) / MIB)
    }
}
