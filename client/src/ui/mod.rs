pub mod canvas_widgets;
pub mod theme;
pub mod views;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iced::futures::SinkExt;
use iced::widget::{scrollable, text_editor};
use iced::{event, mouse, stream, window, Element, Event, Point, Size, Subscription, Task, Theme};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::sync::mpsc::unbounded_channel;
use tgram_proto::{
    AuthMethod, AuthRequest, ChatMessage, DialogEntry, MessageDeliveryState, PeerType,
    TypingAction, UserOnlineState, UserProfile,
};

use crate::domain::{
    format_hh_mm, BackendEvent, BackendHandles, ClientLaunchConfig, ConnectionState,
    MediaTransferStatus, NetCommand, StorageCommand, UiDialog, UiMediaState, UiMessage,
};
use crate::net::spawn_network_thread;
use crate::storage::spawn_storage_thread;
use crate::ui::canvas_widgets::{measure_bubble_layout, BubbleGroupPos, MeasuredBubble};
use crate::ui::theme::telegram_night_blue_theme;

/// Cached `O(log N)` prefix-sum vertical geometry for tens of thousands of variable-height bubbles.
#[derive(Default)]
pub struct HistoryLayoutCache {
    pub chat_id: u64,
    pub viewport_width: f32,
    pub indices: Vec<usize>, // Filtered message indices into `messages_by_chat[chat_id]`
    pub group_positions: Vec<BubbleGroupPos>,
    pub measured: Vec<MeasuredBubble>,
    pub prefix_y: Vec<f32>, // Length == indices.len(), start Y of each visible/virtual row
    pub total_height: f32,
}

/// Active right-click popup context menu state for a message bubble (`Блок D-1.2`).
#[derive(Debug, Clone)]
pub struct ContextMenuState {
    pub chat_id: u64,
    pub msg_id: u64,
    pub msg_idx: usize,
    pub is_outgoing: bool,
    pub text: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    BackendReady(BackendHandles),
    Backend(BackendEvent),

    // Onboarding / Auth Screen
    AuthServerChanged(String),
    AuthServerPubkeyChanged(String),
    AuthUsernameChanged(String),
    AuthPasswordChanged(String),
    AuthDisplayNameChanged(String),
    ToggleAuthMode,
    SubmitAuth,
    LogoutPressed,

    // Layout & Navigation
    WindowResized(Size),
    StartSplitterDrag,
    SplitterMoved(f32),
    EndSplitterDrag,
    ToggleDrawer,
    ToggleRightInfoPanel,
    ToggleChatSearch,

    // Sidebar & Search
    SidebarSearchChanged(String),
    SidebarScrolled(scrollable::Viewport),
    SelectChat(u64),
    StartDirectChatWithUser(u64),

    // Chat View & History
    ChatSearchChanged(String),
    HistoryScrolled(scrollable::Viewport),
    ScrollHistoryToBottom,
    JumpToMessage(u64),
    ComposerAction(text_editor::Action),
    SendCurrentMessage,
    ReplyToMessage { chat_id: u64, msg_id: u64 },
    ClearReplyTarget,
    OpenMessageContextMenu { chat_id: u64, msg_idx: usize },
    CloseContextMenu,
    ContextMenuReply,
    ContextMenuCopyText,
    ContextMenuEdit,
    ContextMenuPin,
    UnpinChatMessage(u64),
    ContextMenuForward,
    ContextMenuDelete,
    HoverMessageBubble(Option<(u64, usize)>),
    ToggleMessageReaction {
        chat_id: u64,
        msg_idx: usize,
        emoji: String,
    },
    AttachFilePressed,
    FilePicked(Option<(PathBuf, u64)>),
    MediaBubbleClicked { chat_id: u64, msg_idx: usize },
    GenerateStressMessages,

    // Ephemeral animation tick (only active while someone is typing)
    TypingTick,
    DismissToast,
}

pub struct TelegramApp {
    pub config: ClientLaunchConfig,
    pub handles: Option<BackendHandles>,
    pub conn_state: ConnectionState,
    pub self_profile: Option<UserProfile>,

    // Auth form state
    pub auth_mode_register: bool,
    pub auth_server_input: String,
    pub auth_server_pubkey_input: String,
    pub auth_username_input: String,
    pub auth_password_input: String,
    pub auth_display_name_input: String,
    pub auth_error: Option<String>,
    pub auth_submitting: bool,

    // Window & 2/3-column geometry
    pub window_size: Size,
    pub sidebar_width: f32,
    pub dragging_splitter: bool,
    pub show_drawer: bool,
    pub show_right_info: bool,
    pub show_chat_search: bool,

    // Search & caches
    pub sidebar_search_query: String,
    pub chat_search_query: String,
    pub dialogs: Vec<UiDialog>,
    pub users_by_id: HashMap<u64, UserProfile>,
    pub global_search_users: Vec<UserProfile>,
    pub downloaded_media: HashMap<String, PathBuf>,

    // Active chat & virtualized message history
    pub selected_chat_id: Option<u64>,
    pub messages_by_chat: HashMap<u64, Vec<UiMessage>>,
    pub has_more_history: HashMap<u64, bool>,
    pub loading_older_history: HashSet<u64>,
    pub active_layout: HistoryLayoutCache,

    // Scroll viewports
    pub sidebar_scroll_y: f32,
    pub sidebar_viewport_h: f32,
    pub history_scroll_id: scrollable::Id,
    pub history_scroll_y: f32,
    pub history_viewport_h: f32,
    pub history_near_bottom: bool,
    pub unread_while_scrolled: u32,

    // Ephemeral typing & composer
    pub active_typings: HashMap<(u64, u64), (TypingAction, Instant)>,
    pub typing_anim_step: u8,
    pub last_typing_sent: Option<(u64, Instant)>,
    pub composer_content: text_editor::Content,
    pub reply_target: Option<UiMessage>,
    pub context_menu: Option<ContextMenuState>,
    pub hovered_msg_idx: Option<(u64, usize)>,
    pub editing_target: Option<(usize, UiMessage)>,
    pub pinned_message_by_chat: HashMap<u64, UiMessage>,
    pub forward_source: Option<UiMessage>,
    pub toast_error: Option<String>,
}

impl TelegramApp {
    pub fn new(config: ClientLaunchConfig) -> (Self, Task<Message>) {
        let server_default = config.default_server_addr.clone();
        let pubkey_default = config.default_server_pubkey_hex.clone();
        let app = Self {
            config,
            handles: None,
            conn_state: ConnectionState::Disconnected,
            self_profile: None,

            auth_mode_register: false,
            auth_server_input: server_default,
            auth_server_pubkey_input: pubkey_default,
            auth_username_input: String::new(),
            auth_password_input: String::new(),
            auth_display_name_input: String::new(),
            auth_error: None,
            auth_submitting: false,

            window_size: Size::new(1160.0, 760.0),
            sidebar_width: 320.0,
            dragging_splitter: false,
            show_drawer: false,
            show_right_info: false,
            show_chat_search: false,

            sidebar_search_query: String::new(),
            chat_search_query: String::new(),
            dialogs: Vec::new(),
            users_by_id: HashMap::new(),
            global_search_users: Vec::new(),
            downloaded_media: HashMap::new(),

            selected_chat_id: None,
            messages_by_chat: HashMap::new(),
            has_more_history: HashMap::new(),
            loading_older_history: HashSet::new(),
            active_layout: HistoryLayoutCache::default(),

            sidebar_scroll_y: 0.0,
            sidebar_viewport_h: 700.0,
            history_scroll_id: scrollable::Id::new("tgram_history_viewport"),
            history_scroll_y: 0.0,
            history_viewport_h: 620.0,
            history_near_bottom: true,
            unread_while_scrolled: 0,

            active_typings: HashMap::new(),
            typing_anim_step: 0,
            last_typing_sent: None,
            composer_content: text_editor::Content::new(),
            reply_target: None,
            context_menu: None,
            hovered_msg_idx: None,
            editing_target: None,
            pinned_message_by_chat: HashMap::new(),
            forward_source: None,
            toast_error: None,
        };

        (app, Task::none())
    }

    pub fn title(&self) -> String {
        match &self.self_profile {
            Some(p) => format!("Telegram Native — @{} ({})", p.username, self.config.profile_name),
            None => format!("Telegram Native ({})", self.config.profile_name),
        }
    }

    pub fn theme(&self) -> Theme {
        telegram_night_blue_theme()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![
            Subscription::run_with_id(
                ("backend-workers", self.config.db_path.clone()),
                backend_workers_stream(self.config.db_path.clone()),
            ),
            window::resize_events().map(|(_id, sz)| Message::WindowResized(sz)),
        ];

        if self.dragging_splitter {
            subs.push(event::listen_with(splitter_drag_listener));
        }

        if !self.active_typings.is_empty() {
            subs.push(
                iced::time::every(Duration::from_millis(400)).map(|_| Message::TypingTick),
            );
        }

        Subscription::batch(subs)
    }

    pub fn view(&self) -> Element<'_, Message> {
        views::render_root(self)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::BackendReady(handles) => {
                let _ = handles.storage_tx.send(StorageCommand::LoadBootstrap);
                self.handles = Some(handles);
                Task::none()
            }

            Message::Backend(ev) => self.handle_backend_event(ev),

            // ----------------------------------------------------------------
            // Auth / Onboarding
            // ----------------------------------------------------------------
            Message::AuthServerChanged(v) => {
                self.auth_server_input = v;
                self.auth_error = None;
                Task::none()
            }
            Message::AuthServerPubkeyChanged(v) => {
                self.auth_server_pubkey_input = v;
                self.auth_error = None;
                Task::none()
            }
            Message::AuthUsernameChanged(v) => {
                self.auth_username_input = v;
                self.auth_error = None;
                Task::none()
            }
            Message::AuthPasswordChanged(v) => {
                self.auth_password_input = v;
                self.auth_error = None;
                Task::none()
            }
            Message::AuthDisplayNameChanged(v) => {
                self.auth_display_name_input = v;
                Task::none()
            }
            Message::ToggleAuthMode => {
                self.auth_mode_register = !self.auth_mode_register;
                self.auth_error = None;
                Task::none()
            }
            Message::SubmitAuth => {
                let server_addr = self.auth_server_input.trim().to_owned();
                let server_pubkey_hex = self.auth_server_pubkey_input.trim().to_owned();
                let username = self.auth_username_input.trim().to_owned();
                let password = self.auth_password_input.clone();
                if server_addr.is_empty() || username.is_empty() || password.is_empty() {
                    self.auth_error = Some("Заполните адрес сервера, логин и пароль".to_owned());
                    return Task::none();
                }
                if tgram_proto::parse_verifying_key_hex(&server_pubkey_hex).is_err() {
                    self.auth_error = Some(
                        "Укажите корректный публичный ключ сервера Ed25519 (64 HEX-символа из лога запуска tgram-server)"
                            .to_owned(),
                    );
                    return Task::none();
                }

                self.auth_submitting = true;
                self.auth_error = None;

                if let Some(ref h) = self.handles {
                    let method = if self.auth_mode_register {
                        AuthMethod::Register
                    } else {
                        AuthMethod::Login
                    };
                    let _ = h.net_tx.send(NetCommand::ConnectAndAuth {
                        server_addr,
                        server_pubkey_hex,
                        req: AuthRequest {
                            method: method as i32,
                            username,
                            password,
                            display_name: self.auth_display_name_input.trim().to_owned(),
                            session_token: Vec::new(),
                            device_name: format!("TGram Desktop ({})", std::env::consts::OS),
                            last_known_pts: 0,
                        },
                    });
                }
                Task::none()
            }
            Message::LogoutPressed => {
                self.show_drawer = false;
                if let Some(ref h) = self.handles {
                    let _ = h.net_tx.send(NetCommand::LogoutAndDisconnect);
                }
                Task::none()
            }

            // ----------------------------------------------------------------
            // Window & Resizable 2/3-Column Splitter
            // ----------------------------------------------------------------
            Message::WindowResized(sz) => {
                self.window_size = sz;
                self.sidebar_viewport_h = (sz.height - 60.0).max(200.0);
                self.history_viewport_h = (sz.height - 116.0).max(200.0);
                self.rebuild_active_layout();
                Task::none()
            }
            Message::StartSplitterDrag => {
                self.dragging_splitter = true;
                Task::none()
            }
            Message::SplitterMoved(cursor_x) => {
                if self.dragging_splitter {
                    let max_sidebar = (self.window_size.width - 380.0).clamp(260.0, 500.0);
                    self.sidebar_width = cursor_x.clamp(250.0, max_sidebar);
                    self.rebuild_active_layout();
                }
                Task::none()
            }
            Message::EndSplitterDrag => {
                self.dragging_splitter = false;
                Task::none()
            }
            Message::ToggleDrawer => {
                self.show_drawer = !self.show_drawer;
                Task::none()
            }
            Message::ToggleRightInfoPanel => {
                self.show_right_info = !self.show_right_info;
                self.rebuild_active_layout();
                Task::none()
            }
            Message::ToggleChatSearch => {
                self.show_chat_search = !self.show_chat_search;
                if !self.show_chat_search && !self.chat_search_query.is_empty() {
                    self.chat_search_query.clear();
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            // ----------------------------------------------------------------
            // Sidebar Search, Selection & Virtualized Scroll
            // ----------------------------------------------------------------
            Message::SidebarSearchChanged(q) => {
                self.sidebar_search_query = q.clone();
                self.sidebar_scroll_y = 0.0;
                if q.trim().len() >= 2 {
                    if let Some(ref h) = self.handles {
                        let _ = h.net_tx.send(NetCommand::SearchPeers { query: q });
                    }
                } else {
                    self.global_search_users.clear();
                }
                Task::none()
            }
            Message::SidebarScrolled(vp) => {
                self.sidebar_scroll_y = vp.absolute_offset().y;
                self.sidebar_viewport_h = vp.bounds().height.max(200.0);
                Task::none()
            }
            Message::SelectChat(chat_id) => self.open_chat(chat_id),

            Message::StartDirectChatWithUser(target_uid) => {
                self.sidebar_search_query.clear();
                self.global_search_users.clear();

                // Check if direct dialog already exists locally
                if let Some(existing) = self
                    .dialogs
                    .iter()
                    .find(|d| d.peer_type == PeerType::Direct && d.peer_user_id == target_uid)
                    .map(|d| d.chat_id)
                {
                    return self.open_chat(existing);
                }

                if let Some(ref h) = self.handles {
                    let _ = h.net_tx.send(NetCommand::OpenDirectChat {
                        target_user_id: target_uid,
                    });
                }
                Task::none()
            }

            // ----------------------------------------------------------------
            // Chat History, Virtual Scroll, Composer & Media
            // ----------------------------------------------------------------
            Message::ChatSearchChanged(q) => {
                self.chat_search_query = q;
                self.rebuild_active_layout();
                Task::none()
            }
            Message::HistoryScrolled(vp) => {
                let offset_y = vp.absolute_offset().y;
                let view_h = vp.bounds().height.max(150.0);
                let rel_y = vp.relative_offset().y;
                self.history_scroll_y = offset_y;
                self.history_viewport_h = view_h;

                let max_scroll = (self.active_layout.total_height - view_h).max(0.0);
                self.history_near_bottom = (max_scroll - offset_y) <= 96.0 || rel_y >= 0.96;

                if self.history_near_bottom {
                    self.unread_while_scrolled = 0;
                    if let Some(cid) = self.selected_chat_id {
                        self.send_read_ack_if_needed(cid);
                    }
                }

                // Trigger keyset backward pagination when scrolled near top while online
                if (offset_y < 140.0 || rel_y <= 0.05)
                    && matches!(self.conn_state, ConnectionState::Online)
                {
                    if let Some(cid) = self.selected_chat_id {
                        if self.has_more_history.get(&cid).copied().unwrap_or(false)
                            && !self.loading_older_history.contains(&cid)
                        {
                            if let Some(oldest_id) = self
                                .messages_by_chat
                                .get(&cid)
                                .and_then(|list| list.iter().map(|m| m.msg_id).find(|&id| id > 0))
                            {
                                self.loading_older_history.insert(cid);
                                if let Some(ref h) = self.handles {
                                    let _ = h.net_tx.send(NetCommand::FetchHistory {
                                        chat_id: cid,
                                        before_msg_id: oldest_id,
                                        limit: 75,
                                    });
                                }
                            }
                        }
                    }
                }
                Task::none()
            }

            Message::ScrollHistoryToBottom => {
                self.history_near_bottom = true;
                self.unread_while_scrolled = 0;
                if let Some(cid) = self.selected_chat_id {
                    self.send_read_ack_if_needed(cid);
                }
                self.snap_history_to_bottom()
            }

            Message::JumpToMessage(target_msg_id) => {
                if target_msg_id == 0 {
                    return Task::none();
                }
                let Some(chat_id) = self.selected_chat_id else {
                    return Task::none();
                };
                let Some(messages) = self.messages_by_chat.get(&chat_id) else {
                    return Task::none();
                };
                if let Some(vis_pos) = self
                    .active_layout
                    .indices
                    .iter()
                    .position(|&idx| messages.get(idx).map(|m| m.msg_id) == Some(target_msg_id))
                {
                    let row_y = self
                        .active_layout
                        .prefix_y
                        .get(vis_pos)
                        .copied()
                        .unwrap_or(0.0);
                    let bottom_anchor_pad =
                        (self.history_viewport_h - self.active_layout.total_height).max(0.0);
                    let target_scroll_y =
                        (bottom_anchor_pad + row_y - self.history_viewport_h * 0.35).max(0.0);
                    self.history_scroll_y = target_scroll_y;
                    let max_scroll =
                        (self.active_layout.total_height - self.history_viewport_h).max(0.0);
                    self.history_near_bottom = (max_scroll - target_scroll_y) <= 96.0;
                    return scrollable::scroll_to(
                        self.history_scroll_id.clone(),
                        scrollable::AbsoluteOffset {
                            x: 0.0,
                            y: target_scroll_y,
                        },
                    );
                }
                Task::none()
            }

            Message::ComposerAction(action) => {
                let is_edit = action.is_edit();
                self.composer_content.perform(action);

                if is_edit {
                    if let Some(cid) = self.selected_chat_id {
                        let now = Instant::now();
                        let should_emit = match self.last_typing_sent {
                            Some((prev_cid, ts)) if prev_cid == cid => {
                                now.duration_since(ts) >= Duration::from_millis(2600)
                            }
                            _ => true,
                        };
                        if should_emit && !self.composer_content.text().trim().is_empty() {
                            self.last_typing_sent = Some((cid, now));
                            if let Some(ref h) = self.handles {
                                let _ = h.net_tx.send(NetCommand::SendTyping {
                                    chat_id: cid,
                                    action: TypingAction::TypingText,
                                });
                            }
                        }
                    }
                }
                Task::none()
            }

            Message::ReplyToMessage { chat_id, msg_id } => {
                if msg_id > 0 && self.selected_chat_id == Some(chat_id) {
                    if let Some(target_msg) = self
                        .messages_by_chat
                        .get(&chat_id)
                        .and_then(|list| list.iter().find(|m| m.msg_id == msg_id))
                        .cloned()
                    {
                        self.reply_target = Some(target_msg);
                    }
                }
                Task::none()
            }

            Message::ClearReplyTarget => {
                if self.editing_target.take().is_some() {
                    self.composer_content = text_editor::Content::new();
                }
                self.reply_target = None;
                self.forward_source = None;
                Task::none()
            }

            Message::OpenMessageContextMenu { chat_id, msg_idx } => {
                if let Some(msg) = self
                    .messages_by_chat
                    .get(&chat_id)
                    .and_then(|list| list.get(msg_idx))
                {
                    self.context_menu = Some(ContextMenuState {
                        chat_id,
                        msg_id: msg.msg_id,
                        msg_idx,
                        is_outgoing: msg.is_outgoing,
                        text: msg.text.clone(),
                    });
                }
                Task::none()
            }

            Message::CloseContextMenu => {
                self.context_menu = None;
                Task::none()
            }

            Message::ContextMenuReply => {
                if let Some(cm) = self.context_menu.take() {
                    if let Some(target_msg) = self
                        .messages_by_chat
                        .get(&cm.chat_id)
                        .and_then(|list| list.get(cm.msg_idx).cloned())
                    {
                        self.editing_target = None;
                        self.reply_target = Some(target_msg);
                    }
                }
                Task::none()
            }

            Message::ContextMenuCopyText => {
                if let Some(cm) = self.context_menu.take() {
                    if !cm.text.is_empty() {
                        return iced::clipboard::write(cm.text);
                    }
                }
                Task::none()
            }

            Message::ContextMenuEdit => {
                if let Some(cm) = self.context_menu.take() {
                    if cm.is_outgoing {
                        if let Some(target_msg) = self
                            .messages_by_chat
                            .get(&cm.chat_id)
                            .and_then(|list| list.get(cm.msg_idx).cloned())
                        {
                            self.reply_target = None;
                            self.forward_source = None;
                            self.composer_content =
                                text_editor::Content::with_text(&target_msg.text);
                            self.editing_target = Some((cm.msg_idx, target_msg));
                        }
                    }
                }
                Task::none()
            }

            Message::ContextMenuPin => {
                if let Some(cm) = self.context_menu.take() {
                    if let Some(msg) = self
                        .messages_by_chat
                        .get(&cm.chat_id)
                        .and_then(|list| list.get(cm.msg_idx).cloned())
                    {
                        let already_pinned = self
                            .pinned_message_by_chat
                            .get(&cm.chat_id)
                            .map(|p| {
                                (msg.msg_id > 0 && p.msg_id == msg.msg_id)
                                    || (msg.client_random_id != 0
                                        && p.client_random_id == msg.client_random_id)
                            })
                            .unwrap_or(false);
                        if already_pinned {
                            self.pinned_message_by_chat.remove(&cm.chat_id);
                        } else {
                            self.pinned_message_by_chat.insert(cm.chat_id, msg);
                        }
                    }
                }
                Task::none()
            }

            Message::UnpinChatMessage(chat_id) => {
                self.pinned_message_by_chat.remove(&chat_id);
                Task::none()
            }

            Message::ContextMenuForward => {
                if let Some(cm) = self.context_menu.take() {
                    if let Some(msg) = self
                        .messages_by_chat
                        .get(&cm.chat_id)
                        .and_then(|list| list.get(cm.msg_idx).cloned())
                    {
                        self.forward_source = Some(msg);
                    }
                }
                Task::none()
            }

            Message::ContextMenuDelete => {
                if let Some(cm) = self.context_menu.take() {
                    if let Some(list) = self.messages_by_chat.get_mut(&cm.chat_id) {
                        if cm.msg_idx < list.len() {
                            let removed = list.remove(cm.msg_idx);
                            if self.reply_target.as_ref().map(|r| r.msg_id) == Some(removed.msg_id)
                            {
                                self.reply_target = None;
                            }
                            if self
                                .pinned_message_by_chat
                                .get(&cm.chat_id)
                                .map(|p| p.msg_id)
                                == Some(removed.msg_id)
                            {
                                self.pinned_message_by_chat.remove(&cm.chat_id);
                            }
                            if self
                                .editing_target
                                .as_ref()
                                .map(|(idx, m)| *idx == cm.msg_idx || m.msg_id == removed.msg_id)
                                .unwrap_or(false)
                            {
                                self.editing_target = None;
                                self.composer_content = text_editor::Content::new();
                            }
                        }
                    }
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            Message::HoverMessageBubble(hovered) => {
                self.hovered_msg_idx = hovered;
                Task::none()
            }

            Message::ToggleMessageReaction {
                chat_id,
                msg_idx,
                emoji,
            } => {
                self.context_menu = None;
                if let Some(msg) = self
                    .messages_by_chat
                    .get_mut(&chat_id)
                    .and_then(|list| list.get_mut(msg_idx))
                {
                    if let Some(pos) = msg.reactions.iter().position(|(e, _, _)| *e == emoji) {
                        let (_, ref mut cnt, ref mut mine) = msg.reactions[pos];
                        if *mine {
                            *cnt = cnt.saturating_sub(1);
                            *mine = false;
                            if *cnt == 0 {
                                msg.reactions.remove(pos);
                            }
                        } else {
                            *cnt = cnt.saturating_add(1);
                            *mine = true;
                        }
                    } else {
                        msg.reactions.push((emoji, 1, true));
                    }
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            Message::SendCurrentMessage => {
                let Some(chat_id) = self.selected_chat_id else {
                    return Task::none();
                };
                if let Some((edit_idx, orig_msg)) = self.editing_target.take() {
                    let raw_text = self.composer_content.text();
                    let trimmed = raw_text.trim().to_owned();
                    if trimmed.is_empty() {
                        self.editing_target = Some((edit_idx, orig_msg));
                        return Task::none();
                    }
                    self.composer_content = text_editor::Content::new();
                    self.last_typing_sent = None;

                    let mut updated_proto: Option<ChatMessage> = None;
                    let mut is_last_in_chat = false;
                    if let Some(list) = self.messages_by_chat.get_mut(&chat_id) {
                        let target_slot = if orig_msg.msg_id > 0 {
                            list.iter_mut().find(|m| m.msg_id == orig_msg.msg_id)
                        } else {
                            list.get_mut(edit_idx)
                        };
                        if let Some(m) = target_slot {
                            m.text = trimmed.clone();
                            m.is_edited = true;
                            updated_proto = Some(ChatMessage {
                                msg_id: m.msg_id,
                                chat_id: m.chat_id,
                                sender_id: m.sender_id,
                                client_random_id: m.client_random_id,
                                timestamp_ms: m.timestamp_ms,
                                text: m.text.clone(),
                                reply_to_msg_id: m.reply_to_msg_id,
                                media: m.media.as_ref().map(|ms| ms.attachment.clone()),
                                is_read: matches!(m.delivery, MessageDeliveryState::Read),
                                pts: 0,
                            });
                        }
                        is_last_in_chat = list
                            .last()
                            .map(|last| {
                                (orig_msg.msg_id > 0 && last.msg_id == orig_msg.msg_id)
                                    || (orig_msg.client_random_id != 0
                                        && last.client_random_id == orig_msg.client_random_id)
                            })
                            .unwrap_or(false);
                    }

                    if let (Some(ref h), Some(proto_msg)) = (&self.handles, updated_proto) {
                        let _ = h.storage_tx.send(StorageCommand::UpsertMessages {
                            chat_id,
                            messages: vec![proto_msg],
                        });
                    }
                    if is_last_in_chat {
                        if let Some(d) = self.dialogs.iter_mut().find(|d| d.chat_id == chat_id) {
                            d.top_preview = trimmed.clone();
                        }
                    }
                    if let Some(pinned) = self.pinned_message_by_chat.get_mut(&chat_id) {
                        if orig_msg.msg_id > 0 && pinned.msg_id == orig_msg.msg_id {
                            pinned.text = trimmed;
                            pinned.is_edited = true;
                        }
                    }
                    self.rebuild_active_layout();
                    return Task::none();
                }

                let raw_text = self.composer_content.text();
                let mut trimmed = raw_text.trim().to_owned();
                if let Some(fwd) = self.forward_source.take() {
                    let fwd_body = if !fwd.text.trim().is_empty() {
                        fwd.text
                    } else if let Some(med) = fwd.media {
                        format!("📎 {}", med.attachment.file_name)
                    } else {
                        format!("Сообщение #{}", fwd.msg_id)
                    };
                    trimmed = if trimmed.is_empty() {
                        format!("↪ Переслано от {}:\n{}", fwd.sender_name, fwd_body)
                    } else {
                        format!(
                            "↪ Переслано от {}:\n{}\n\n{}",
                            fwd.sender_name, fwd_body, trimmed
                        )
                    };
                }
                if trimmed.is_empty() {
                    return Task::none();
                }

                // Reset multi-line composer cleanly
                self.composer_content = text_editor::Content::new();
                self.last_typing_sent = None;
                let reply_msg = self.reply_target.take();
                let reply_to_msg_id = reply_msg.as_ref().map(|m| m.msg_id).unwrap_or(0);
                let reply_sender_name = reply_msg
                    .as_ref()
                    .map(|m| m.sender_name.clone())
                    .unwrap_or_default();
                let reply_snippet = reply_msg
                    .as_ref()
                    .map(|m| {
                        if !m.text.trim().is_empty() {
                            m.text.chars().take(64).collect()
                        } else if let Some(ref med) = m.media {
                            format!("📎 {}", med.attachment.file_name)
                        } else {
                            format!("Сообщение #{}", m.msg_id)
                        }
                    })
                    .unwrap_or_default();

                let client_random_id = random_u64_nonzero();
                let now_ms = unix_ms_now();
                let (my_uid, my_name, my_color) = self.self_identity();

                let optimistic = UiMessage {
                    msg_id: 0,
                    client_random_id,
                    chat_id,
                    sender_id: my_uid,
                    sender_name: my_name,
                    sender_color_rgb: my_color,
                    is_outgoing: true,
                    timestamp_ms: now_ms,
                    time_label: format_hh_mm(now_ms),
                    text: trimmed.clone(),
                    is_edited: false,
                    reactions: Vec::new(),
                    reply_to_msg_id,
                    reply_sender_name,
                    reply_snippet,
                    delivery: MessageDeliveryState::Sending,
                    media: None,
                };

                self.messages_by_chat
                    .entry(chat_id)
                    .or_default()
                    .push(optimistic);
                self.update_dialog_preview_local(
                    chat_id,
                    &trimmed,
                    true,
                    MessageDeliveryState::Sending,
                    now_ms,
                );
                self.rebuild_active_layout();

                if let Some(ref h) = self.handles {
                    let proto_msg = ChatMessage {
                        msg_id: 0,
                        chat_id,
                        sender_id: my_uid,
                        client_random_id,
                        timestamp_ms: now_ms,
                        text: trimmed.clone(),
                        reply_to_msg_id,
                        media: None,
                        is_read: false,
                        pts: 0,
                    };
                    let _ = h.storage_tx.send(StorageCommand::UpsertMessages {
                        chat_id,
                        messages: vec![proto_msg],
                    });
                    if reply_to_msg_id > 0 {
                        let _ = h.net_tx.send(NetCommand::SendReplyMessage {
                            chat_id,
                            target_user_id: 0,
                            client_random_id,
                            text: trimmed,
                            reply_to_msg_id,
                        });
                    } else {
                        let _ = h.net_tx.send(NetCommand::SendTextMessage {
                            chat_id,
                            target_user_id: 0,
                            client_random_id,
                            text: trimmed,
                        });
                    }
                }

                self.snap_history_to_bottom()
            }

            Message::AttachFilePressed => {
                if self.selected_chat_id.is_none() {
                    return Task::none();
                }
                Task::perform(
                    async {
                        let picked = rfd::AsyncFileDialog::new()
                            .set_title("Выберите файл для отправки")
                            .pick_file()
                            .await?;
                        let path = picked.path().to_path_buf();
                        let size_bytes = tokio::fs::metadata(&path)
                            .await
                            .map(|m| m.len())
                            .unwrap_or(0);
                        Some((path, size_bytes))
                    },
                    Message::FilePicked,
                )
            }

            Message::FilePicked(Some((file_path, size_bytes))) => {
                let Some(chat_id) = self.selected_chat_id else {
                    return Task::none();
                };
                let caption = self.composer_content.text().trim().to_owned();
                if !caption.is_empty() {
                    self.composer_content = text_editor::Content::new();
                }

                let file_name = file_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "attachment.bin".to_owned());
                if size_bytes == 0 {
                    self.toast_error = Some("Выбранный файл пуст (0 байт)".to_owned());
                    return Task::none();
                }

                let client_random_id = random_u64_nonzero();
                let now_ms = unix_ms_now();
                let (my_uid, my_name, my_color) = self.self_identity();

                let optimistic = UiMessage {
                    msg_id: 0,
                    client_random_id,
                    chat_id,
                    sender_id: my_uid,
                    sender_name: my_name,
                    sender_color_rgb: my_color,
                    is_outgoing: true,
                    timestamp_ms: now_ms,
                    time_label: format_hh_mm(now_ms),
                    text: caption.clone(),
                    is_edited: false,
                    reactions: Vec::new(),
                    reply_to_msg_id: 0,
                    reply_sender_name: String::new(),
                    reply_snippet: String::new(),
                    delivery: MessageDeliveryState::Sending,
                    media: Some(UiMediaState {
                        attachment: tgram_proto::MediaAttachment {
                            media_id: String::new(),
                            file_name: file_name.clone(),
                            mime_type: String::new(),
                            size_bytes,
                            sha256_hash: Vec::new(),
                            width: 0,
                            height: 0,
                        },
                        transfer: MediaTransferStatus::Uploading { progress: 0.01 },
                    }),
                };

                self.messages_by_chat
                    .entry(chat_id)
                    .or_default()
                    .push(optimistic);
                self.update_dialog_preview_local(
                    chat_id,
                    &format!("📎 {file_name}"),
                    true,
                    MessageDeliveryState::Sending,
                    now_ms,
                );
                self.rebuild_active_layout();

                if let Some(ref h) = self.handles {
                    let _ = h.net_tx.send(NetCommand::SendTyping {
                        chat_id,
                        action: TypingAction::Uploading,
                    });
                    let _ = h.net_tx.send(NetCommand::SendFileAttachment {
                        chat_id,
                        client_random_id,
                        file_path,
                        caption,
                    });
                }

                self.snap_history_to_bottom()
            }
            Message::FilePicked(None) => Task::none(),

            Message::MediaBubbleClicked { chat_id, msg_idx } => {
                let Some(list) = self.messages_by_chat.get_mut(&chat_id) else {
                    return Task::none();
                };
                let Some(msg) = list.get_mut(msg_idx) else {
                    return Task::none();
                };
                let Some(ref mut media_state) = msg.media else {
                    return Task::none();
                };

                match &media_state.transfer {
                    MediaTransferStatus::Idle | MediaTransferStatus::Failed(_) => {
                        if media_state.attachment.media_id.is_empty() {
                            return Task::none();
                        }
                        let attachment = media_state.attachment.clone();
                        let msg_id = msg.msg_id;
                        media_state.transfer = MediaTransferStatus::Downloading { progress: 0.01 };
                        self.rebuild_active_layout();

                        if let Some(ref h) = self.handles {
                            let _ = h.net_tx.send(NetCommand::DownloadAttachment {
                                chat_id,
                                msg_id,
                                attachment,
                                dest_dir: self.config.downloads_dir.clone(),
                            });
                        }
                    }
                    MediaTransferStatus::Downloaded { local_path } => {
                        open_path_in_os_shell(local_path);
                    }
                    _ => {}
                }
                Task::none()
            }

            Message::GenerateStressMessages => {
                self.show_drawer = false;
                if let Some(cid) = self.selected_chat_id {
                    let my_uid = self.self_profile.as_ref().map(|p| p.user_id).unwrap_or(1);
                    let peer_uid = self
                        .dialogs
                        .iter()
                        .find(|d| d.chat_id == cid)
                        .map(|d| d.peer_user_id)
                        .unwrap_or(1);
                    if let Some(ref h) = self.handles {
                        let _ = h.storage_tx.send(StorageCommand::GenerateStressHistory {
                            chat_id: cid,
                            self_user_id: my_uid,
                            peer_user_id: peer_uid,
                            count: 20_000,
                        });
                    }
                }
                Task::none()
            }

            Message::TypingTick => {
                let now = Instant::now();
                self.active_typings
                    .retain(|_, (_, exp)| *exp > now);
                self.typing_anim_step = self.typing_anim_step.wrapping_add(1) % 3;
                Task::none()
            }

            Message::DismissToast => {
                self.toast_error = None;
                Task::none()
            }
        }
    }

    // ------------------------------------------------------------------------
    // Backend Event Handlers
    // ------------------------------------------------------------------------

    fn handle_backend_event(&mut self, ev: BackendEvent) -> Task<Message> {
        match ev {
            BackendEvent::BootstrapLoaded {
                session,
                dialogs,
                users,
                downloaded_files,
            } => {
                for (mid, path) in downloaded_files {
                    self.downloaded_media.insert(mid, path);
                }
                for u in users {
                    self.users_by_id.insert(u.user_id, u);
                }

                if let Some(saved) = session {
                    let resolved_pubkey = if !self.config.default_server_pubkey_hex.trim().is_empty()
                    {
                        self.config.default_server_pubkey_hex.trim().to_owned()
                    } else {
                        saved.server_pubkey_hex.trim().to_owned()
                    };

                    self.auth_server_input = saved.server_addr.clone();
                    if !resolved_pubkey.is_empty() {
                        self.auth_server_pubkey_input = resolved_pubkey.clone();
                    }

                    if tgram_proto::parse_verifying_key_hex(&resolved_pubkey).is_ok() {
                        self.self_profile = Some(saved.self_profile.clone());
                        self.users_by_id
                            .insert(saved.self_profile.user_id, saved.self_profile);
                        self.ingest_dialogs(dialogs);

                        if let Some(ref h) = self.handles {
                            let _ = h.net_tx.send(NetCommand::ConnectAndAuth {
                                server_addr: saved.server_addr,
                                server_pubkey_hex: resolved_pubkey,
                                req: AuthRequest {
                                    method: AuthMethod::TokenResume as i32,
                                    username: String::new(),
                                    password: String::new(),
                                    display_name: String::new(),
                                    session_token: saved.session_token,
                                    device_name: format!(
                                        "TGram Desktop ({})",
                                        std::env::consts::OS
                                    ),
                                    last_known_pts: saved.last_pts,
                                },
                            });
                        }
                    } else if let Some(ref h) = self.handles {
                        // Legacy session without pinned server key: drop unverified token and require explicit pinning
                        let _ = h.storage_tx.send(StorageCommand::ClearSession);
                    }
                }
                Task::none()
            }

            BackendEvent::CachedHistoryLoaded { chat_id, messages } => {
                self.merge_proto_messages(chat_id, messages);
                if self.selected_chat_id == Some(chat_id) {
                    self.rebuild_active_layout();
                    return self.snap_history_to_bottom();
                }
                Task::none()
            }

            BackendEvent::ConnectionChanged(st) => {
                if !matches!(st, ConnectionState::Online) {
                    // Release any in-flight backward pagination locks if the link drops
                    self.loading_older_history.clear();
                }
                self.conn_state = st;
                Task::none()
            }

            BackendEvent::AuthSucceeded {
                server_addr,
                server_pubkey_hex,
                profile,
                ..
            } => {
                self.auth_submitting = false;
                self.auth_error = None;
                self.auth_password_input.clear();
                self.auth_server_input = server_addr;
                self.auth_server_pubkey_input = server_pubkey_hex;
                self.users_by_id.insert(profile.user_id, profile.clone());
                self.self_profile = Some(profile);
                Task::none()
            }

            BackendEvent::AuthFailed(err) => {
                self.auth_submitting = false;
                self.auth_error = Some(err);
                Task::none()
            }

            BackendEvent::LoggedOut => {
                self.self_profile = None;
                self.dialogs.clear();
                self.messages_by_chat.clear();
                self.selected_chat_id = None;
                self.active_layout = HistoryLayoutCache::default();
                self.auth_submitting = false;
                Task::none()
            }

            BackendEvent::DialogsSynced { dialogs, users, .. } => {
                for u in users {
                    self.users_by_id.insert(u.user_id, u);
                }
                // Check which dialogs have newer messages on the server than our local cache
                let mut chats_needing_fetch = Vec::new();
                for d in &dialogs {
                    if let Some(ref top) = d.top_message {
                        if top.msg_id > 0 {
                            let local_max = self
                                .messages_by_chat
                                .get(&d.chat_id)
                                .and_then(|list| list.iter().map(|m| m.msg_id).max())
                                .unwrap_or(0);
                            if top.msg_id > local_max || self.selected_chat_id == Some(d.chat_id) {
                                chats_needing_fetch.push(d.chat_id);
                            }
                        }
                    }
                }
                self.ingest_dialogs(dialogs);
                if let Some(ref h) = self.handles {
                    for cid in chats_needing_fetch {
                        let _ = h.net_tx.send(NetCommand::FetchHistory {
                            chat_id: cid,
                            before_msg_id: 0,
                            limit: 80,
                        });
                    }
                }
                if self.selected_chat_id.is_none() {
                    if let Some(first_cid) = self.dialogs.first().map(|d| d.chat_id) {
                        return self.open_chat(first_cid);
                    }
                } else {
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            BackendEvent::HistoryFetched {
                chat_id,
                messages,
                has_more,
            } => {
                self.loading_older_history.remove(&chat_id);
                self.has_more_history.insert(chat_id, has_more);
                let was_empty = self
                    .messages_by_chat
                    .get(&chat_id)
                    .map(|v| v.is_empty())
                    .unwrap_or(true);
                self.merge_proto_messages(chat_id, messages);

                if self.selected_chat_id == Some(chat_id) {
                    self.rebuild_active_layout();
                    self.send_read_ack_if_needed(chat_id);
                    if was_empty || self.history_near_bottom {
                        return self.snap_history_to_bottom();
                    }
                }
                Task::none()
            }

            BackendEvent::SearchResults { users, .. } => {
                let my_uid = self.self_profile.as_ref().map(|p| p.user_id).unwrap_or(0);
                self.global_search_users = users
                    .into_iter()
                    .filter(|u| {
                        self.users_by_id.insert(u.user_id, u.clone());
                        u.user_id != my_uid
                    })
                    .collect();
                Task::none()
            }

            BackendEvent::DirectChatOpened { dialog, peer } => {
                self.users_by_id.insert(peer.user_id, peer);
                let cid = dialog.chat_id;
                let ui_d = self.proto_to_ui_dialog(dialog);
                if let Some(existing) = self.dialogs.iter_mut().find(|d| d.chat_id == cid) {
                    *existing = ui_d;
                } else {
                    self.dialogs.insert(0, ui_d);
                }
                self.sort_dialogs();
                self.open_chat(cid)
            }

            BackendEvent::MessageAcked(ack) => {
                if let Some(list) = self.messages_by_chat.get_mut(&ack.chat_id) {
                    if let Some(m) = list
                        .iter_mut()
                        .find(|m| m.client_random_id == ack.client_random_id)
                    {
                        m.msg_id = ack.msg_id;
                        m.timestamp_ms = ack.server_timestamp_ms;
                        m.time_label = format_hh_mm(ack.server_timestamp_ms);
                        if m.delivery == MessageDeliveryState::Sending {
                            m.delivery = MessageDeliveryState::Sent;
                        }
                    }
                    sort_ui_messages(list);
                }

                if let Some(pinned) = self.pinned_message_by_chat.get_mut(&ack.chat_id) {
                    if ack.client_random_id != 0 && pinned.client_random_id == ack.client_random_id
                    {
                        pinned.msg_id = ack.msg_id;
                        pinned.timestamp_ms = ack.server_timestamp_ms;
                        pinned.time_label = format_hh_mm(ack.server_timestamp_ms);
                    }
                }

                if let Some(d) = self.dialogs.iter_mut().find(|d| d.chat_id == ack.chat_id) {
                    if d.top_sender_is_self
                        && d.top_delivery == Some(MessageDeliveryState::Sending)
                    {
                        d.top_delivery = Some(MessageDeliveryState::Sent);
                    }
                    d.sort_timestamp_ms = d.sort_timestamp_ms.max(ack.server_timestamp_ms);
                    d.top_time_label = format_hh_mm(ack.server_timestamp_ms);
                }
                self.sort_dialogs();

                if self.selected_chat_id == Some(ack.chat_id) {
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            BackendEvent::IncomingMessage(upd) => {
                if let Some(peer) = upd.sender_brief {
                    self.users_by_id.insert(peer.user_id, peer);
                }
                let Some(msg) = upd.message else {
                    return Task::none();
                };
                let chat_id = msg.chat_id;
                let sender_id = msg.sender_id;

                // Clear typing indicator immediately when peer sends message
                self.active_typings.remove(&(chat_id, sender_id));

                // Ensure dialog exists in sidebar; if brand-new DM, fetch full dialog list
                if !self.dialogs.iter().any(|d| d.chat_id == chat_id) {
                    if let Some(ref h) = self.handles {
                        let _ = h.net_tx.send(NetCommand::SyncDialogs);
                    }
                }

                self.merge_proto_messages(chat_id, vec![msg.clone()]);

                let my_uid = self.self_profile.as_ref().map(|p| p.user_id).unwrap_or(0);
                let is_self = sender_id == my_uid;
                let preview = preview_for_proto_msg(&msg);

                if let Some(d) = self.dialogs.iter_mut().find(|d| d.chat_id == chat_id) {
                    d.top_preview = preview;
                    d.top_sender_is_self = is_self;
                    d.top_delivery = if is_self {
                        Some(if msg.is_read {
                            MessageDeliveryState::Read
                        } else {
                            MessageDeliveryState::Sent
                        })
                    } else {
                        None
                    };
                    d.top_timestamp_ms = msg.timestamp_ms;
                    d.top_time_label = format_hh_mm(msg.timestamp_ms);
                    d.sort_timestamp_ms = msg.timestamp_ms;

                    if self.selected_chat_id == Some(chat_id) && !is_self {
                        d.unread_count = 0;
                    } else if !is_self {
                        d.unread_count = upd.unread_count;
                    }
                }
                self.sort_dialogs();

                if self.selected_chat_id == Some(chat_id) {
                    self.rebuild_active_layout();
                    if self.history_near_bottom || is_self {
                        if !is_self {
                            self.send_read_ack_if_needed(chat_id);
                        }
                        return self.snap_history_to_bottom();
                    } else if !is_self {
                        self.unread_while_scrolled = self.unread_while_scrolled.saturating_add(1);
                    }
                }
                Task::none()
            }

            BackendEvent::ReadAckConfirmed(res) => {
                if let Some(d) = self.dialogs.iter_mut().find(|d| d.chat_id == res.chat_id) {
                    d.read_inbox_max_msg_id = d.read_inbox_max_msg_id.max(res.max_read_msg_id);
                    d.unread_count = res.unread_count;
                }
                Task::none()
            }

            BackendEvent::PeerReadHistory(upd) => {
                let my_uid = self.self_profile.as_ref().map(|p| p.user_id).unwrap_or(0);
                if upd.reader_user_id == my_uid {
                    // Multi-device read sync for our own inbox
                    if let Some(d) = self.dialogs.iter_mut().find(|d| d.chat_id == upd.chat_id) {
                        d.read_inbox_max_msg_id =
                            d.read_inbox_max_msg_id.max(upd.max_read_msg_id);
                        d.unread_count = 0;
                    }
                    return Task::none();
                }

                if let Some(d) = self.dialogs.iter_mut().find(|d| d.chat_id == upd.chat_id) {
                    d.read_outbox_max_msg_id =
                        d.read_outbox_max_msg_id.max(upd.max_read_msg_id);
                    if d.top_sender_is_self {
                        d.top_delivery = Some(MessageDeliveryState::Read);
                    }
                }

                if let Some(list) = self.messages_by_chat.get_mut(&upd.chat_id) {
                    for m in list.iter_mut() {
                        if m.is_outgoing && m.msg_id > 0 && m.msg_id <= upd.max_read_msg_id {
                            m.delivery = MessageDeliveryState::Read;
                        }
                    }
                }

                if self.selected_chat_id == Some(upd.chat_id) {
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            BackendEvent::PeerTyping(upd) => {
                let action = TypingAction::try_from(upd.action).unwrap_or(TypingAction::Cancel);
                if action == TypingAction::Cancel {
                    self.active_typings.remove(&(upd.chat_id, upd.user_id));
                } else {
                    let ttl = Duration::from_millis(upd.ttl_ms.clamp(1000, 10_000) as u64);
                    self.active_typings
                        .insert((upd.chat_id, upd.user_id), (action, Instant::now() + ttl));
                }
                Task::none()
            }

            BackendEvent::PeerPresence(upd) => {
                if let Some(u) = self.users_by_id.get_mut(&upd.user_id) {
                    u.status = upd.status;
                    u.last_seen_ms = upd.last_seen_ms;
                }
                Task::none()
            }

            BackendEvent::MediaUploadProgress {
                chat_id,
                client_random_id,
                attachment,
                progress,
            } => {
                if let Some(list) = self.messages_by_chat.get_mut(&chat_id) {
                    if let Some(m) = list
                        .iter_mut()
                        .find(|m| m.client_random_id == client_random_id)
                    {
                        m.media = Some(UiMediaState {
                            attachment,
                            transfer: MediaTransferStatus::Uploading { progress },
                        });
                    }
                }
                if self.selected_chat_id == Some(chat_id) {
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            BackendEvent::MediaDownloadProgress {
                chat_id,
                msg_id,
                media_id,
                progress,
            } => {
                if let Some(list) = self.messages_by_chat.get_mut(&chat_id) {
                    for m in list.iter_mut() {
                        if m.msg_id == msg_id
                            || m.media
                                .as_ref()
                                .map(|ms| ms.attachment.media_id == media_id)
                                .unwrap_or(false)
                        {
                            if let Some(ref mut ms) = m.media {
                                ms.transfer = MediaTransferStatus::Downloading { progress };
                            }
                        }
                    }
                }
                if self.selected_chat_id == Some(chat_id) {
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            BackendEvent::MediaDownloadFinished {
                chat_id,
                msg_id,
                media_id,
                local_path,
            } => {
                self.downloaded_media
                    .insert(media_id.clone(), local_path.clone());
                if let Some(list) = self.messages_by_chat.get_mut(&chat_id) {
                    for m in list.iter_mut() {
                        let matches_media = m
                            .media
                            .as_ref()
                            .map(|ms| {
                                ms.attachment.media_id == media_id
                                    || (m.msg_id == msg_id && msg_id != 0)
                            })
                            .unwrap_or(false);
                        if matches_media {
                            if let Some(ref mut ms) = m.media {
                                if ms.attachment.media_id.is_empty() {
                                    ms.attachment.media_id = media_id.clone();
                                }
                                ms.transfer = MediaTransferStatus::Downloaded {
                                    local_path: local_path.clone(),
                                };
                            }
                        }
                    }
                }
                if self.selected_chat_id == Some(chat_id) {
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            BackendEvent::MediaTransferFailed {
                chat_id,
                client_random_id,
                msg_id,
                error,
            } => {
                if let Some(list) = self.messages_by_chat.get_mut(&chat_id) {
                    for m in list.iter_mut() {
                        if (client_random_id != 0 && m.client_random_id == client_random_id)
                            || (msg_id != 0 && m.msg_id == msg_id)
                        {
                            if let Some(ref mut ms) = m.media {
                                ms.transfer = MediaTransferStatus::Failed(error.clone());
                            }
                        }
                    }
                }
                self.toast_error = Some(error);
                if self.selected_chat_id == Some(chat_id) {
                    self.rebuild_active_layout();
                }
                Task::none()
            }

            BackendEvent::PushTokenRegistered { .. } => Task::none(),

            BackendEvent::TransientError(err) => {
                // Release pagination lock so transient RPC timeouts never deadlock history scroll (H-01)
                self.loading_older_history.clear();
                self.toast_error = Some(err);
                Task::none()
            }
        }
    }

    // ------------------------------------------------------------------------
    // Internal Helpers & O(log N) Virtual Layout Builder
    // ------------------------------------------------------------------------

    fn open_chat(&mut self, chat_id: u64) -> Task<Message> {
        self.selected_chat_id = Some(chat_id);
        self.chat_search_query.clear();
        self.show_chat_search = false;
        self.reply_target = None;
        self.context_menu = None;
        self.hovered_msg_idx = None;
        self.editing_target = None;
        self.history_near_bottom = true;
        self.unread_while_scrolled = 0;

        if let Some(ref h) = self.handles {
            if !self.messages_by_chat.contains_key(&chat_id) {
                let _ = h.storage_tx.send(StorageCommand::LoadChatHistory {
                    chat_id,
                    limit: 120,
                });
            }
            let _ = h.net_tx.send(NetCommand::FetchHistory {
                chat_id,
                before_msg_id: 0,
                limit: 80,
            });
        }

        self.rebuild_active_layout();
        self.send_read_ack_if_needed(chat_id);
        self.snap_history_to_bottom()
    }

    fn snap_history_to_bottom(&self) -> Task<Message> {
        scrollable::snap_to(
            self.history_scroll_id.clone(),
            scrollable::RelativeOffset { x: 0.0, y: 1.0 },
        )
    }

    fn send_read_ack_if_needed(&mut self, chat_id: u64) {
        let my_uid = self.self_profile.as_ref().map(|p| p.user_id).unwrap_or(0);
        let max_incoming = self
            .messages_by_chat
            .get(&chat_id)
            .and_then(|list| {
                list.iter()
                    .filter(|m| m.sender_id != my_uid && m.msg_id > 0)
                    .map(|m| m.msg_id)
                    .max()
            })
            .unwrap_or(0);

        if max_incoming == 0 {
            return;
        }

        let already_acked = self
            .dialogs
            .iter()
            .find(|d| d.chat_id == chat_id)
            .map(|d| d.read_inbox_max_msg_id)
            .unwrap_or(0);

        if max_incoming > already_acked {
            if let Some(d) = self.dialogs.iter_mut().find(|d| d.chat_id == chat_id) {
                d.read_inbox_max_msg_id = max_incoming;
                d.unread_count = 0;
            }
            if let Some(ref h) = self.handles {
                let _ = h.net_tx.send(NetCommand::SendReadAck {
                    chat_id,
                    max_read_msg_id: max_incoming,
                });
            }
        }
    }

    pub fn chat_viewport_width(&self) -> f32 {
        let right_w = if self.show_right_info { 280.0 } else { 0.0 };
        (self.window_size.width - self.sidebar_width - 4.0 - right_w).max(300.0)
    }

    pub fn rebuild_active_layout(&mut self) {
        let Some(chat_id) = self.selected_chat_id else {
            self.active_layout = HistoryLayoutCache::default();
            return;
        };

        let vp_w = self.chat_viewport_width();
        let peer_type = self
            .dialogs
            .iter()
            .find(|d| d.chat_id == chat_id)
            .map(|d| d.peer_type)
            .unwrap_or(PeerType::Direct);
        let is_group = peer_type == PeerType::Group;

        let Some(messages) = self.messages_by_chat.get(&chat_id) else {
            self.active_layout = HistoryLayoutCache {
                chat_id,
                viewport_width: vp_w,
                ..HistoryLayoutCache::default()
            };
            return;
        };

        let filter_q = self.chat_search_query.trim().to_lowercase();
        let indices: Vec<usize> = if filter_q.is_empty() {
            (0..messages.len()).collect()
        } else {
            messages
                .iter()
                .enumerate()
                .filter(|(_, m)| m.text.to_lowercase().contains(&filter_q))
                .map(|(i, _)| i)
                .collect()
        };

        let n = indices.len();
        let mut group_positions = Vec::with_capacity(n);
        for pos in 0..n {
            let cur = &messages[indices[pos]];
            let same_prev = if pos > 0 {
                let prev = &messages[indices[pos - 1]];
                prev.sender_id == cur.sender_id
                    && (cur.timestamp_ms - prev.timestamp_ms).abs() < 300_000
            } else {
                false
            };
            let same_next = if pos + 1 < n {
                let next = &messages[indices[pos + 1]];
                next.sender_id == cur.sender_id
                    && (next.timestamp_ms - cur.timestamp_ms).abs() < 300_000
            } else {
                false
            };

            let gp = match (same_prev, same_next) {
                (false, false) => BubbleGroupPos::Single,
                (false, true) => BubbleGroupPos::Top,
                (true, true) => BubbleGroupPos::Middle,
                (true, false) => BubbleGroupPos::Bottom,
            };
            group_positions.push(gp);
        }

        let mut measured = Vec::with_capacity(n);
        let mut prefix_y = Vec::with_capacity(n);
        let mut cursor_y = 12.0_f32; // Top history breathing room

        for i in 0..n {
            prefix_y.push(cursor_y);
            let m_geom =
                measure_bubble_layout(&messages[indices[i]], group_positions[i], is_group, vp_w);
            cursor_y += m_geom.row_height;
            measured.push(m_geom);
        }
        let total_height = cursor_y + 10.0;

        self.active_layout = HistoryLayoutCache {
            chat_id,
            viewport_width: vp_w,
            indices,
            group_positions,
            measured,
            prefix_y,
            total_height,
        };
    }

    fn ingest_dialogs(&mut self, proto_dialogs: Vec<DialogEntry>) {
        self.dialogs = proto_dialogs
            .into_iter()
            .map(|d| self.proto_to_ui_dialog(d))
            .collect();
        self.sort_dialogs();
    }

    fn proto_to_ui_dialog(&self, d: DialogEntry) -> UiDialog {
        let my_uid = self.self_profile.as_ref().map(|p| p.user_id).unwrap_or(0);
        let peer_type = PeerType::try_from(d.peer_type).unwrap_or(PeerType::Direct);

        let (top_preview, top_sender_is_self, top_delivery, top_ts) = match d.top_message {
            Some(ref m) => {
                let is_self = m.sender_id == my_uid;
                let deliv = if is_self {
                    Some(if m.is_read || m.msg_id <= d.read_outbox_max_msg_id {
                        MessageDeliveryState::Read
                    } else {
                        MessageDeliveryState::Sent
                    })
                } else {
                    None
                };
                (preview_for_proto_msg(m), is_self, deliv, m.timestamp_ms)
            }
            None => (String::new(), false, None, d.sort_timestamp_ms),
        };

        UiDialog {
            chat_id: d.chat_id,
            peer_type,
            title: d.title,
            peer_user_id: d.peer_user_id,
            avatar_color_rgb: d.avatar_color_rgb,
            top_preview,
            top_sender_is_self,
            top_delivery,
            top_timestamp_ms: top_ts,
            top_time_label: format_hh_mm(top_ts),
            unread_count: d.unread_count,
            read_inbox_max_msg_id: d.read_inbox_max_msg_id,
            read_outbox_max_msg_id: d.read_outbox_max_msg_id,
            is_pinned: d.is_pinned,
            sort_timestamp_ms: d.sort_timestamp_ms,
        }
    }

    fn merge_proto_messages(&mut self, chat_id: u64, incoming: Vec<ChatMessage>) {
        if incoming.is_empty() {
            return;
        }
        let my_uid = self.self_profile.as_ref().map(|p| p.user_id).unwrap_or(0);
        let read_outbox = self
            .dialogs
            .iter()
            .find(|d| d.chat_id == chat_id)
            .map(|d| d.read_outbox_max_msg_id)
            .unwrap_or(0);

        // Pre-build converted UiMessages before mutably borrowing `messages_by_chat`
        let converted: Vec<UiMessage> = incoming
            .into_iter()
            .map(|pm| {
                let is_outgoing = pm.sender_id == my_uid;
                let (sender_name, sender_color_rgb) =
                    if let Some(u) = self.users_by_id.get(&pm.sender_id) {
                        (u.display_name.clone(), u.avatar_color_rgb)
                    } else if pm.sender_id == 1 {
                        ("TGram System".to_owned(), 0x65AADD)
                    } else {
                        (format!("User #{}", pm.sender_id), 0x7BC862)
                    };

                let delivery = if is_outgoing {
                    if pm.msg_id == 0 {
                        MessageDeliveryState::Sending
                    } else if pm.is_read || pm.msg_id <= read_outbox {
                        MessageDeliveryState::Read
                    } else {
                        MessageDeliveryState::Sent
                    }
                } else {
                    MessageDeliveryState::Read
                };

                let media = pm.media.map(|att| {
                    let transfer = if let Some(path) = self.downloaded_media.get(&att.media_id) {
                        MediaTransferStatus::Downloaded {
                            local_path: path.clone(),
                        }
                    } else {
                        MediaTransferStatus::Idle
                    };
                    UiMediaState {
                        attachment: att,
                        transfer,
                    }
                });

                UiMessage {
                    msg_id: pm.msg_id,
                    client_random_id: pm.client_random_id,
                    chat_id,
                    sender_id: pm.sender_id,
                    sender_name,
                    sender_color_rgb,
                    is_outgoing,
                    timestamp_ms: pm.timestamp_ms,
                    time_label: format_hh_mm(pm.timestamp_ms),
                    text: pm.text,
                    is_edited: false,
                    reactions: Vec::new(),
                    reply_to_msg_id: pm.reply_to_msg_id,
                    reply_sender_name: String::new(),
                    reply_snippet: String::new(),
                    delivery,
                    media,
                }
            })
            .collect();

        let list = self.messages_by_chat.entry(chat_id).or_default();
        for new_m in converted {
            if let Some(existing) = list.iter_mut().find(|m| {
                (new_m.msg_id > 0 && m.msg_id == new_m.msg_id)
                    || (new_m.client_random_id != 0
                        && m.client_random_id == new_m.client_random_id
                        && m.sender_id == new_m.sender_id)
            }) {
                let keep_media = match (&existing.media, &new_m.media) {
                    (
                        Some(UiMediaState {
                            transfer: MediaTransferStatus::Downloaded { local_path },
                            ..
                        }),
                        Some(nm),
                    ) => Some(UiMediaState {
                        attachment: nm.attachment.clone(),
                        transfer: MediaTransferStatus::Downloaded {
                            local_path: local_path.clone(),
                        },
                    }),
                    _ => new_m.media,
                };
                let keep_edited = existing.is_edited || new_m.is_edited;
                let keep_text = if existing.is_edited && !existing.text.is_empty() {
                    existing.text.clone()
                } else {
                    new_m.text
                };
                let keep_reactions = if !existing.reactions.is_empty() {
                    existing.reactions.clone()
                } else {
                    new_m.reactions
                };
                *existing = UiMessage {
                    text: keep_text,
                    is_edited: keep_edited,
                    reactions: keep_reactions,
                    media: keep_media,
                    ..new_m
                };
            } else {
                list.push(new_m);
            }
        }

        sort_ui_messages(list);

        // Resolve quoted reply author & text snippet for any message with `reply_to_msg_id > 0`
        let reply_lookup: HashMap<u64, (String, String)> = list
            .iter()
            .filter(|m| m.msg_id > 0)
            .map(|m| {
                let snippet = if !m.text.trim().is_empty() {
                    m.text.chars().take(64).collect()
                } else if let Some(ref med) = m.media {
                    format!("📎 {}", med.attachment.file_name)
                } else {
                    format!("Сообщение #{}", m.msg_id)
                };
                (m.msg_id, (m.sender_name.clone(), snippet))
            })
            .collect();

        for m in list.iter_mut() {
            if m.reply_to_msg_id > 0 {
                if let Some((r_author, r_snip)) = reply_lookup.get(&m.reply_to_msg_id) {
                    m.reply_sender_name = r_author.clone();
                    m.reply_snippet = r_snip.clone();
                } else if m.reply_snippet.is_empty() {
                    m.reply_sender_name = format!("Сообщение #{}", m.reply_to_msg_id);
                    m.reply_snippet = "Нажмите для перехода к сообщению".to_owned();
                }
            }
        }
    }

    fn update_dialog_preview_local(
        &mut self,
        chat_id: u64,
        preview: &str,
        is_self: bool,
        delivery: MessageDeliveryState,
        ts_ms: i64,
    ) {
        if let Some(d) = self.dialogs.iter_mut().find(|d| d.chat_id == chat_id) {
            d.top_preview = preview.to_owned();
            d.top_sender_is_self = is_self;
            d.top_delivery = Some(delivery);
            d.top_timestamp_ms = ts_ms;
            d.top_time_label = format_hh_mm(ts_ms);
            d.sort_timestamp_ms = ts_ms;
        }
        self.sort_dialogs();
    }

    fn sort_dialogs(&mut self) {
        self.dialogs.sort_by(|a, b| {
            b.is_pinned
                .cmp(&a.is_pinned)
                .then_with(|| b.sort_timestamp_ms.cmp(&a.sort_timestamp_ms))
                .then_with(|| b.chat_id.cmp(&a.chat_id))
        });
    }

    fn self_identity(&self) -> (u64, String, u32) {
        match &self.self_profile {
            Some(p) => (p.user_id, p.display_name.clone(), p.avatar_color_rgb),
            None => (0, "Вы".to_owned(), 0x65AADD),
        }
    }

    pub fn is_peer_online(&self, user_id: u64) -> bool {
        self.users_by_id
            .get(&user_id)
            .map(|u| u.status == UserOnlineState::Online as i32)
            .unwrap_or(false)
    }

    pub fn typing_text_for_chat(&self, chat_id: u64, peer_type: PeerType) -> Option<String> {
        let dots = match self.typing_anim_step % 3 {
            0 => ".",
            1 => "..",
            _ => "...",
        };

        for (&(cid, uid), &(action, _)) in &self.active_typings {
            if cid != chat_id {
                continue;
            }
            let verb = match action {
                TypingAction::Uploading => "отправляет файл",
                _ => "печатает",
            };
            if peer_type == PeerType::Group {
                let name = self
                    .users_by_id
                    .get(&uid)
                    .map(|u| u.display_name.as_str())
                    .unwrap_or("Участник");
                return Some(format!("{name} {verb}{dots}"));
            } else {
                return Some(format!("{verb}{dots}"));
            }
        }
        None
    }
}

fn sort_ui_messages(list: &mut [UiMessage]) {
    list.sort_by(|a, b| match (a.msg_id > 0, b.msg_id > 0) {
        (true, true) => a.msg_id.cmp(&b.msg_id),
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        (false, false) => a
            .timestamp_ms
            .cmp(&b.timestamp_ms)
            .then_with(|| a.client_random_id.cmp(&b.client_random_id)),
    });
}

fn preview_for_proto_msg(m: &ChatMessage) -> String {
    if let Some(ref att) = m.media {
        if m.text.trim().is_empty() {
            format!("📎 {}", att.file_name)
        } else {
            format!("📎 {} — {}", att.file_name, m.text.trim())
        }
    } else {
        m.text.lines().next().unwrap_or("").trim().to_owned()
    }
}

fn splitter_drag_listener(
    ev: Event,
    _status: event::Status,
    _window_id: window::Id,
) -> Option<Message> {
    match ev {
        Event::Mouse(mouse::Event::CursorMoved {
            position: Point { x, .. },
        }) => Some(Message::SplitterMoved(x)),
        Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
            Some(Message::EndSplitterDrag)
        }
        _ => None,
    }
}

/// Spawns `StorageThread` and `NetworkThread` once and forwards `BackendEvent`s into Iced reactively.
fn backend_workers_stream(db_path: PathBuf) -> impl iced::futures::Stream<Item = Message> {
    stream::channel(256, move |mut ui_sink| async move {
        let (ui_tx, mut ui_rx) = unbounded_channel::<BackendEvent>();

        let storage_tx = spawn_storage_thread(db_path, ui_tx.clone());
        let net_tx = spawn_network_thread(storage_tx.clone(), ui_tx);

        let _ = ui_sink
            .send(Message::BackendReady(BackendHandles {
                storage_tx: storage_tx.clone(),
                net_tx,
            }))
            .await;

        while let Some(ev) = ui_rx.recv().await {
            if ui_sink.send(Message::Backend(ev)).await.is_err() {
                break;
            }
        }

        let _ = storage_tx.send(StorageCommand::Shutdown);
    })
}

fn random_u64_nonzero() -> u64 {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    let v = u64::from_le_bytes(b);
    if v == 0 { 1 } else { v }
}

fn unix_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn open_path_in_os_shell(path: &std::path::Path) {
    #[cfg(target_os = "windows")]
    {
        let mut select_arg = std::ffi::OsString::from("/select,");
        select_arg.push(path.as_os_str());
        let _ = std::process::Command::new("explorer")
            .arg(select_arg)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg("-R").arg(path).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(parent) = path.parent() {
            let _ = std::process::Command::new("xdg-open").arg(parent).spawn();
        }
    }
}
