use iced::alignment::{Horizontal, Vertical};
use iced::mouse;
use iced::widget::text::Shaping;
use iced::widget::{
    button, canvas, column, container, mouse_area, row, scrollable, text, text_editor, text_input,
    Column, Text,
};
use iced::{Element, Length};
use tgram_proto::PeerType;

use crate::domain::{ConnectionState, UiDialog};
use crate::ui::canvas_widgets::{
    AvatarCircleCanvas, DialogRowCanvas, MessageBubbleCanvas, VectorIconCanvas, VectorIconKind,
    DIALOG_ROW_HEIGHT, FONT_BOLD,
};
use crate::ui::theme::{
    auth_input_style, card_container, chat_view_container, composer_editor_style, hairline_divider,
    pill_chip_container, primary_button_style, rgba8, search_input_style, sidebar_container,
    subtle_icon_button_style, thin_dark_scrollable_style, transparent_row_button_style, ACCENT,
    ACCENT_TEXT, BG_INPUT, BG_PANEL, DANGER, ONLINE_DOT, TEXT_MAIN, TEXT_SUB,
};
use crate::ui::{Message, TelegramApp};

#[inline]
fn txt<'a>(content: impl text::IntoFragment<'a>) -> Text<'a> {
    text(content).shaping(Shaping::Advanced)
}

#[inline]
fn h_fill<'a>() -> Element<'a, Message> {
    container(row![])
        .width(Length::Fill)
        .height(Length::Fixed(0.0))
        .into()
}

#[inline]
fn v_spacer<'a>(px: f32) -> Element<'a, Message> {
    container(column![])
        .width(Length::Fill)
        .height(Length::Fixed(px.max(0.0)))
        .into()
}

#[inline]
fn v_divider<'a>() -> Element<'a, Message> {
    container(column![])
        .width(Length::Fixed(1.0))
        .height(Length::Fill)
        .style(hairline_divider)
        .into()
}

#[inline]
fn h_divider<'a>() -> Element<'a, Message> {
    container(row![])
        .width(Length::Fill)
        .height(Length::Fixed(1.0))
        .style(hairline_divider)
        .into()
}

fn icon_btn<'a>(kind: VectorIconKind, on_press: Message, size: f32) -> Element<'a, Message> {
    let icon_canvas = canvas(VectorIconCanvas { kind })
        .width(Length::Fixed(size))
        .height(Length::Fixed(size));

    button(icon_canvas)
        .padding(0)
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .style(subtle_icon_button_style)
        .on_press(on_press)
        .into()
}

/// Entry point of the declarative UI tree (strictly non-blocking, zero I/O).
pub fn render_root(app: &TelegramApp) -> Element<'_, Message> {
    if app.self_profile.is_none() {
        render_auth_screen(app)
    } else {
        render_messenger_workspace(app)
    }
}

// ============================================================================
// 1. Onboarding / Login & Registration Screen (Telegram Night Blue)
// ============================================================================

fn render_auth_screen(app: &TelegramApp) -> Element<'_, Message> {
    let logo = canvas(AvatarCircleCanvas {
        title: "TG".to_owned(),
        color_rgb: 0x3E90DF,
        is_online: false,
        is_saved_messages: false,
        bg_cutout: BG_PANEL,
    })
    .width(Length::Fixed(68.0))
    .height(Length::Fixed(68.0));

    let title_str = if app.auth_mode_register {
        "Создание аккаунта"
    } else {
        "Вход в Telegram Native"
    };

    let subtitle_str = if app.auth_mode_register {
        "Зарегистрируйтесь для мгновенного защищённого общения"
    } else {
        "Введите адрес сервера, ключ Ed25519, логин и пароль"
    };

    let status_color = match app.conn_state {
        ConnectionState::Online => ONLINE_DOT,
        ConnectionState::Disconnected => TEXT_SUB,
        _ => ACCENT_TEXT,
    };

    let server_field = column![
        txt("Сервер MTWire (TCP)").size(12).color(TEXT_SUB),
        text_input("127.0.0.1:4430", &app.auth_server_input)
            .on_input(Message::AuthServerChanged)
            .on_submit(Message::SubmitAuth)
            .padding([10, 12])
            .size(14)
            .style(auth_input_style),
    ]
    .spacing(5);

    let pubkey_field = column![
        txt("Публичный ключ сервера Ed25519 (64 HEX)").size(12).color(TEXT_SUB),
        text_input(
            "ed25519_pubkey из лога запуска сервера",
            &app.auth_server_pubkey_input
        )
        .on_input(Message::AuthServerPubkeyChanged)
        .on_submit(Message::SubmitAuth)
        .padding([10, 12])
        .size(13)
        .style(auth_input_style),
    ]
    .spacing(5);

    let username_field = column![
        txt("Имя пользователя (@username)").size(12).color(TEXT_SUB),
        text_input("alice", &app.auth_username_input)
            .on_input(Message::AuthUsernameChanged)
            .on_submit(Message::SubmitAuth)
            .padding([10, 12])
            .size(14)
            .style(auth_input_style),
    ]
    .spacing(5);

    let password_field = column![
        txt("Пароль").size(12).color(TEXT_SUB),
        text_input("••••••••", &app.auth_password_input)
            .secure(true)
            .on_input(Message::AuthPasswordChanged)
            .on_submit(Message::SubmitAuth)
            .padding([10, 12])
            .size(14)
            .style(auth_input_style),
    ]
    .spacing(5);

    let mut form_col = column![
        container(logo).center_x(Length::Fill),
        container(txt(title_str).size(21).font(FONT_BOLD).color(TEXT_MAIN)).center_x(Length::Fill),
        container(txt(subtitle_str).size(13).color(TEXT_SUB)).center_x(Length::Fill),
        container(txt(app.conn_state.label_ru()).size(12).color(status_color))
            .center_x(Length::Fill),
        v_spacer(4.0),
        server_field,
        pubkey_field,
        username_field,
        password_field,
    ]
    .spacing(10)
    .width(Length::Fill);

    if app.auth_mode_register {
        let display_field = column![
            txt("Отображаемое имя").size(12).color(TEXT_SUB),
            text_input("Алиса Селезнёва", &app.auth_display_name_input)
                .on_input(Message::AuthDisplayNameChanged)
                .on_submit(Message::SubmitAuth)
                .padding([10, 12])
                .size(14)
                .style(auth_input_style),
        ]
        .spacing(5);
        form_col = form_col.push(display_field);
    }

    if let Some(ref err) = app.auth_error {
        form_col = form_col.push(
            container(txt(err.as_str()).size(13).color(DANGER))
                .padding([8, 10])
                .width(Length::Fill),
        );
    }

    let submit_label = if app.auth_submitting {
        "Установка защищённой сессии..."
    } else if app.auth_mode_register {
        "Зарегистрироваться"
    } else {
        "Продолжить"
    };

    let mut submit_btn = button(
        container(txt(submit_label).size(14.5).font(FONT_BOLD).color(TEXT_MAIN))
            .center_x(Length::Fill)
            .padding([9, 12]),
    )
    .width(Length::Fill)
    .style(primary_button_style);

    if !app.auth_submitting {
        submit_btn = submit_btn.on_press(Message::SubmitAuth);
    }

    let toggle_label = if app.auth_mode_register {
        "Уже есть аккаунт? Войти"
    } else {
        "Нет аккаунта? Создать новый"
    };

    let toggle_btn = button(
        container(txt(toggle_label).size(13).color(ACCENT_TEXT))
            .center_x(Length::Fill)
            .padding([6, 8]),
    )
    .width(Length::Fill)
    .style(transparent_row_button_style)
    .on_press(Message::ToggleAuthMode);

    form_col = form_col.push(v_spacer(4.0)).push(submit_btn).push(toggle_btn);

    let card = container(form_col)
        .width(Length::Fixed(400.0))
        .padding(28)
        .style(card_container);

    container(card)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(chat_view_container)
        .into()
}

// ============================================================================
// 2. Classic 2-Column / 3-Column Telegram Desktop Workspace
// ============================================================================

fn render_messenger_workspace(app: &TelegramApp) -> Element<'_, Message> {
    let left_sidebar = render_left_sidebar(app);
    let splitter = render_resizable_splitter();
    let center_chat = render_center_chat_panel(app);

    let mut main_row = row![left_sidebar, splitter, center_chat]
        .width(Length::Fill)
        .height(Length::Fill);

    if app.show_right_info {
        main_row = main_row.push(v_divider()).push(render_right_info_panel(app));
    }

    main_row.into()
}

/// Interactive 4px vertical splitter between Sidebar and Chat View.
fn render_resizable_splitter<'a>() -> Element<'a, Message> {
    let bar = row![
        v_divider(),
        container(column![])
            .width(Length::Fixed(3.0))
            .height(Length::Fill)
            .style(chat_view_container),
    ]
    .width(Length::Fixed(4.0))
    .height(Length::Fill);

    mouse_area(bar)
        .on_press(Message::StartSplitterDrag)
        .interaction(mouse::Interaction::ResizingHorizontally)
        .into()
}

// ============================================================================
// 2A. Left Sidebar: Burger Menu + Search + Drawer + O(1) Virtualized Dialogs
// ============================================================================

fn render_left_sidebar(app: &TelegramApp) -> Element<'_, Message> {
    let burger_btn = icon_btn(VectorIconKind::BurgerMenu, Message::ToggleDrawer, 38.0);

    let search_box = text_input("Поиск", &app.sidebar_search_query)
        .on_input(Message::SidebarSearchChanged)
        .padding([8, 14])
        .size(14)
        .width(Length::Fill)
        .style(search_input_style);

    let top_bar = container(
        row![burger_btn, search_box]
            .spacing(8)
            .align_y(Vertical::Center)
            .padding([0, 10]),
    )
    .width(Length::Fill)
    .height(Length::Fixed(56.0))
    .align_y(Vertical::Center);

    let mut sidebar_col = column![top_bar, h_divider()]
        .width(Length::Fixed(app.sidebar_width))
        .height(Length::Fill);

    // Optional collapsible profile/settings drawer
    if app.show_drawer {
        sidebar_col = sidebar_col.push(render_drawer_panel(app)).push(h_divider());
    }

    // Optional global @username directory search hits
    if !app.global_search_users.is_empty() {
        let mut global_col = Column::new().spacing(2).padding([6, 0]);
        global_col = global_col.push(
            container(
                txt("ГЛОБАЛЬНЫЙ ПОИСК ПОЛЬЗОВАТЕЛЕЙ")
                    .size(11)
                    .font(FONT_BOLD)
                    .color(TEXT_SUB),
            )
            .padding([4, 14]),
        );

        for user in app.global_search_users.iter().take(6) {
            let av = canvas(AvatarCircleCanvas {
                title: user.display_name.clone(),
                color_rgb: user.avatar_color_rgb,
                is_online: app.is_peer_online(user.user_id),
                is_saved_messages: false,
                bg_cutout: BG_PANEL,
            })
            .width(Length::Fixed(36.0))
            .height(Length::Fixed(36.0));

            let info = column![
                txt(user.display_name.as_str())
                    .size(13.5)
                    .font(FONT_BOLD)
                    .color(TEXT_MAIN),
                txt(format!("@{}", user.username)).size(12).color(ACCENT_TEXT),
            ]
            .spacing(2);

            let user_row = button(
                row![av, info]
                    .spacing(10)
                    .align_y(Vertical::Center)
                    .padding([6, 14])
                    .width(Length::Fill),
            )
            .width(Length::Fill)
            .padding(0)
            .style(subtle_icon_button_style)
            .on_press(Message::StartDirectChatWithUser(user.user_id));

            global_col = global_col.push(user_row);
        }

        sidebar_col = sidebar_col.push(global_col).push(h_divider());
    }

    // Filter dialogs locally by search query
    let q_lower = app.sidebar_search_query.trim().to_lowercase();
    let filtered: Vec<&UiDialog> = if q_lower.is_empty() {
        app.dialogs.iter().collect()
    } else {
        app.dialogs
            .iter()
            .filter(|d| {
                d.title.to_lowercase().contains(&q_lower)
                    || d.top_preview.to_lowercase().contains(&q_lower)
            })
            .collect()
    };

    let my_uid = app.self_profile.as_ref().map(|p| p.user_id).unwrap_or(0);
    let total_rows = filtered.len();

    if total_rows == 0 {
        let empty_hint = if q_lower.is_empty() {
            "Чатов пока нет.\nВведите логин в поиск сверху, чтобы начать диалог."
        } else {
            "Локальные чаты не найдены"
        };
        sidebar_col = sidebar_col.push(
            container(txt(empty_hint).size(13).color(TEXT_SUB))
                .padding(20)
                .center_x(Length::Fill),
        );
    } else {
        // O(1) Viewport Virtualization over 72px fixed-height dialog rows
        let overscan = 6usize;
        let raw_first = (app.sidebar_scroll_y / DIALOG_ROW_HEIGHT).floor().max(0.0) as usize;
        let visible_cnt =
            ((app.sidebar_viewport_h / DIALOG_ROW_HEIGHT).ceil().max(1.0) as usize) + overscan * 2;
        let first_idx = raw_first.saturating_sub(overscan).min(total_rows);
        let last_idx = (first_idx + visible_cnt).min(total_rows);

        let top_h = (first_idx as f32) * DIALOG_ROW_HEIGHT;
        let bottom_h = (total_rows.saturating_sub(last_idx) as f32) * DIALOG_ROW_HEIGHT;

        let mut list_col = Column::new().width(Length::Fill);
        if top_h > 0.0 {
            list_col = list_col.push(v_spacer(top_h));
        }

        for dialog in &filtered[first_idx..last_idx] {
            let is_selected = app.selected_chat_id == Some(dialog.chat_id);
            let is_saved = dialog.peer_type == PeerType::Direct && dialog.peer_user_id == my_uid;
            let is_online = dialog.peer_type == PeerType::Direct
                && !is_saved
                && app.is_peer_online(dialog.peer_user_id);
            let typing_label = app.typing_text_for_chat(dialog.chat_id, dialog.peer_type);

            let row_canvas = canvas(DialogRowCanvas {
                dialog: (*dialog).clone(),
                is_selected,
                is_peer_online: is_online,
                is_saved_messages: is_saved,
                typing_label,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DIALOG_ROW_HEIGHT));

            let row_btn = button(row_canvas)
                .padding(0)
                .width(Length::Fill)
                .height(Length::Fixed(DIALOG_ROW_HEIGHT))
                .style(transparent_row_button_style)
                .on_press(Message::SelectChat(dialog.chat_id));

            list_col = list_col.push(row_btn);
        }

        if bottom_h > 0.0 {
            list_col = list_col.push(v_spacer(bottom_h));
        }

        let dialogs_scroll = scrollable(list_col)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(thin_dark_scrollable_style)
            .on_scroll(Message::SidebarScrolled);

        sidebar_col = sidebar_col.push(dialogs_scroll);
    }

    container(sidebar_col)
        .width(Length::Fixed(app.sidebar_width))
        .height(Length::Fill)
        .style(sidebar_container)
        .into()
}

fn render_drawer_panel(app: &TelegramApp) -> Element<'_, Message> {
    let (name, uname, color_rgb) = match &app.self_profile {
        Some(p) => (
            p.display_name.as_str(),
            p.username.as_str(),
            p.avatar_color_rgb,
        ),
        None => ("Гость", "guest", 0x5288C1),
    };

    let avatar = canvas(AvatarCircleCanvas {
        title: name.to_owned(),
        color_rgb,
        is_online: matches!(app.conn_state, ConnectionState::Online),
        is_saved_messages: false,
        bg_cutout: BG_PANEL,
    })
    .width(Length::Fixed(44.0))
    .height(Length::Fixed(44.0));

    let conn_color = match app.conn_state {
        ConnectionState::Online => ONLINE_DOT,
        ConnectionState::Disconnected => DANGER,
        _ => ACCENT_TEXT,
    };

    let header = row![
        avatar,
        column![
            txt(name).size(14.5).font(FONT_BOLD).color(TEXT_MAIN),
            txt(format!("@{uname}")).size(12.5).color(ACCENT_TEXT),
            txt(app.conn_state.label_ru()).size(11.5).color(conn_color),
        ]
        .spacing(2),
    ]
    .spacing(12)
    .align_y(Vertical::Center);

    let mut drawer_col = column![header].spacing(8).padding([12, 14]);

    if app.selected_chat_id.is_some() {
        let stress_btn = button(
            txt("⚡ Сгенерировать +20 000 сообщений (SQLite WAL)")
                .size(12.5)
                .color(ACCENT_TEXT),
        )
        .width(Length::Fill)
        .padding([7, 10])
        .style(subtle_icon_button_style)
        .on_press(Message::GenerateStressMessages);

        drawer_col = drawer_col.push(stress_btn);
    }

    let logout_btn = button(txt("Выйти из аккаунта").size(12.5).color(DANGER))
        .width(Length::Fill)
        .padding([7, 10])
        .style(subtle_icon_button_style)
        .on_press(Message::LogoutPressed);

    drawer_col = drawer_col.push(logout_btn);
    drawer_col.into()
}

// ============================================================================
// 2B. Center Chat View: Header + O(log N) Virtualized Bubbles + Composer Bar
// ============================================================================

fn render_center_chat_panel(app: &TelegramApp) -> Element<'_, Message> {
    let mut root_col = Column::new().width(Length::Fill).height(Length::Fill);

    if let Some(ref toast) = app.toast_error {
        let banner = container(
            row![
                txt(format!("⚠ {toast}")).size(12.5).color(DANGER),
                h_fill(),
                button(txt("Скрыть").size(12).color(TEXT_MAIN))
                    .padding([3, 8])
                    .style(subtle_icon_button_style)
                    .on_press(Message::DismissToast),
            ]
            .align_y(Vertical::Center)
            .padding([6, 14]),
        )
        .width(Length::Fill)
        .style(sidebar_container);

        root_col = root_col.push(banner).push(h_divider());
    }

    let Some(chat_id) = app.selected_chat_id else {
        let pill = container(
            txt("Выберите чат для начала общения")
                .size(13.5)
                .color(TEXT_MAIN),
        )
        .padding([7, 16])
        .style(pill_chip_container);

        root_col = root_col.push(
            container(pill)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill),
        );

        return container(root_col)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(chat_view_container)
            .into();
    };

    let active_dialog = app.dialogs.iter().find(|d| d.chat_id == chat_id);
    let (chat_title, peer_type, peer_uid, avatar_rgb) = match active_dialog {
        Some(d) => (
            d.title.as_str(),
            d.peer_type,
            d.peer_user_id,
            d.avatar_color_rgb,
        ),
        None => ("Чат", PeerType::Direct, 0, 0x5288C1),
    };

    let my_uid = app.self_profile.as_ref().map(|p| p.user_id).unwrap_or(0);
    let is_saved = peer_type == PeerType::Direct && peer_uid == my_uid && my_uid != 0;
    let is_online = peer_type == PeerType::Direct && !is_saved && app.is_peer_online(peer_uid);

    // 1. Top Chat Header (56px, #17212b)
    let header_avatar = canvas(AvatarCircleCanvas {
        title: chat_title.to_owned(),
        color_rgb: avatar_rgb,
        is_online,
        is_saved_messages: is_saved,
        bg_cutout: BG_PANEL,
    })
    .width(Length::Fixed(38.0))
    .height(Length::Fixed(38.0));

    let (status_text, status_color) =
        if let Some(typing_str) = app.typing_text_for_chat(chat_id, peer_type) {
            (typing_str, ACCENT_TEXT)
        } else if is_saved {
            ("облачные заметки и файлы".to_owned(), TEXT_SUB)
        } else if peer_type == PeerType::Group {
            ("групповой чат".to_owned(), TEXT_SUB)
        } else if is_online {
            ("в сети".to_owned(), ACCENT_TEXT)
        } else {
            ("был(а) недавно".to_owned(), TEXT_SUB)
        };

    let title_stack = column![
        txt(chat_title).size(15).font(FONT_BOLD).color(TEXT_MAIN),
        txt(status_text).size(12.5).color(status_color),
    ]
    .spacing(2);

    let search_btn = icon_btn(
        VectorIconKind::SearchMagnifier,
        Message::ToggleChatSearch,
        36.0,
    );
    let info_btn = icon_btn(
        VectorIconKind::RightPanelToggle {
            active: app.show_right_info,
        },
        Message::ToggleRightInfoPanel,
        36.0,
    );

    let chat_header = container(
        row![header_avatar, title_stack, h_fill(), search_btn, info_btn]
            .spacing(10)
            .align_y(Vertical::Center)
            .padding([0, 14]),
    )
    .width(Length::Fill)
    .height(Length::Fixed(56.0))
    .align_y(Vertical::Center)
    .style(sidebar_container);

    root_col = root_col.push(chat_header).push(h_divider());

    // 2. Optional In-Chat Message Filter Bar
    if app.show_chat_search {
        let hits = app.active_layout.indices.len();
        let search_strip = container(
            row![
                text_input("Поиск по истории чата...", &app.chat_search_query)
                    .on_input(Message::ChatSearchChanged)
                    .padding([6, 12])
                    .size(13.5)
                    .width(Length::Fill)
                    .style(search_input_style),
                txt(format!("Найдено: {hits}")).size(12.5).color(TEXT_SUB),
            ]
            .spacing(12)
            .align_y(Vertical::Center)
            .padding([6, 14]),
        )
        .width(Length::Fill)
        .style(sidebar_container);

        root_col = root_col.push(search_strip).push(h_divider());
    }

    // 3. O(log N) Prefix-Sum Virtualized Message Bubble Feed
    let history_feed = render_virtualized_history(app, chat_id, peer_type);
    root_col = root_col.push(history_feed).push(h_divider());

    // 4. Bottom Auto-Expanding Multi-Line Composer (#17212b)
    let composer_bar = render_composer_bar(app);
    root_col = root_col.push(composer_bar);

    container(root_col)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(chat_view_container)
        .into()
}

fn render_virtualized_history(
    app: &TelegramApp,
    chat_id: u64,
    peer_type: PeerType,
) -> Element<'_, Message> {
    let layout = &app.active_layout;
    let total_items = layout.indices.len();

    let Some(messages) = app.messages_by_chat.get(&chat_id) else {
        let empty_pill = container(txt("Сообщений пока нет").size(13).color(TEXT_SUB))
            .padding([6, 14])
            .style(pill_chip_container);

        return container(empty_pill)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into();
    };

    if total_items == 0 {
        let label = if app.chat_search_query.trim().is_empty() {
            "История пуста — отправьте первое сообщение!"
        } else {
            "Совпадений не найдено"
        };
        let empty_pill = container(txt(label).size(13).color(TEXT_SUB))
            .padding([6, 14])
            .style(pill_chip_container);

        return container(empty_pill)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into();
    }

    // Anchor short chats cleanly to the bottom of the viewport (classic Telegram Desktop UX)
    let bottom_anchor_pad = (app.history_viewport_h - layout.total_height).max(0.0);

    // Binary search visible slice `[first_vis..last_vis]` in O(log N) over prefix_y
    let overscan_px = 440.0_f32;
    let min_y = (app.history_scroll_y - bottom_anchor_pad - overscan_px).max(0.0);
    let max_y = app.history_scroll_y - bottom_anchor_pad + app.history_viewport_h + overscan_px;

    let first_vis = layout
        .prefix_y
        .partition_point(|&py| py < min_y)
        .saturating_sub(1)
        .min(total_items);
    let last_vis = layout
        .prefix_y
        .partition_point(|&py| py <= max_y)
        .min(total_items);

    let top_virtual_h = bottom_anchor_pad + layout.prefix_y.get(first_vis).copied().unwrap_or(0.0);
    let rendered_end_y = if last_vis == 0 {
        0.0
    } else if last_vis < total_items {
        layout.prefix_y[last_vis]
    } else {
        layout.total_height
    };
    let bottom_virtual_h = (layout.total_height - rendered_end_y).max(0.0);

    let mut feed_col = Column::new().width(Length::Fill);
    if top_virtual_h > 0.0 {
        feed_col = feed_col.push(v_spacer(top_virtual_h));
    }

    for vis_i in first_vis..last_vis {
        let msg_idx = layout.indices[vis_i];
        let Some(ui_msg) = messages.get(msg_idx) else {
            continue;
        };
        let measured = &layout.measured[vis_i];
        let row_h = measured.row_height;

        let bubble_canvas = canvas(MessageBubbleCanvas {
            msg: ui_msg.clone(),
            group_pos: layout.group_positions[vis_i],
            peer_type,
            measured: measured.clone(),
        })
        .width(Length::Fill)
        .height(Length::Fixed(row_h));

        if ui_msg.media.is_some() {
            let interactive_bubble = mouse_area(bubble_canvas)
                .on_press(Message::MediaBubbleClicked { chat_id, msg_idx })
                .interaction(mouse::Interaction::Pointer);
            feed_col = feed_col.push(interactive_bubble);
        } else {
            feed_col = feed_col.push(bubble_canvas);
        }
    }

    if bottom_virtual_h > 0.0 {
        feed_col = feed_col.push(v_spacer(bottom_virtual_h));
    }

    scrollable(feed_col)
        .id(app.history_scroll_id.clone())
        .width(Length::Fill)
        .height(Length::Fill)
        .style(thin_dark_scrollable_style)
        .on_scroll(Message::HistoryScrolled)
        .into()
}

fn render_composer_bar(app: &TelegramApp) -> Element<'_, Message> {
    let attach_btn = icon_btn(
        VectorIconKind::AttachPaperclip,
        Message::AttachFilePressed,
        40.0,
    );

    let line_cnt = app.composer_content.line_count().clamp(1, 6) as f32;
    let editor_h = line_cnt * 21.0 + 18.0;

    let editor = text_editor(&app.composer_content)
        .placeholder("Написать сообщение...")
        .height(Length::Fixed(editor_h))
        .padding([9.0, 6.0])
        .size(14.5)
        .style(composer_editor_style)
        .on_action(Message::ComposerAction)
        .key_binding(|key_press| {
            let shift = key_press.modifiers.shift();
            match text_editor::Binding::from_key_press(key_press) {
                Some(text_editor::Binding::Enter) if !shift => {
                    Some(text_editor::Binding::Custom(Message::SendCurrentMessage))
                }
                other => other,
            }
        });

    let has_non_empty_text = !app.composer_content.text().trim().is_empty();
    let send_btn = icon_btn(
        VectorIconKind::SendPaperPlane {
            active: has_non_empty_text,
        },
        Message::SendCurrentMessage,
        40.0,
    );

    container(
        row![attach_btn, editor, send_btn]
            .spacing(6)
            .align_y(Vertical::Bottom)
            .padding([6, 10]),
    )
    .width(Length::Fill)
    .style(sidebar_container)
    .into()
}

// ============================================================================
// 2C. Optional 3rd Column: Chat / User Info & Telemetry Panel (280px)
// ============================================================================

fn render_right_info_panel(app: &TelegramApp) -> Element<'_, Message> {
    let header = container(
        row![
            txt("Информация").size(15).font(FONT_BOLD).color(TEXT_MAIN),
            h_fill(),
            button(txt("✕").size(14).color(TEXT_SUB))
                .width(Length::Fixed(32.0))
                .height(Length::Fixed(32.0))
                .padding(0)
                .style(subtle_icon_button_style)
                .on_press(Message::ToggleRightInfoPanel),
        ]
        .align_y(Vertical::Center)
        .padding([0, 14]),
    )
    .width(Length::Fill)
    .height(Length::Fixed(56.0))
    .align_y(Vertical::Center);

    let Some(chat_id) = app.selected_chat_id else {
        return container(column![header, h_divider()])
            .width(Length::Fixed(280.0))
            .height(Length::Fill)
            .style(sidebar_container)
            .into();
    };

    let dialog = app.dialogs.iter().find(|d| d.chat_id == chat_id);
    let (title, peer_type, peer_uid, avatar_rgb) = match dialog {
        Some(d) => (
            d.title.as_str(),
            d.peer_type,
            d.peer_user_id,
            d.avatar_color_rgb,
        ),
        None => ("Чат", PeerType::Direct, 0, 0x5288C1),
    };

    let my_uid = app.self_profile.as_ref().map(|p| p.user_id).unwrap_or(0);
    let is_saved = peer_type == PeerType::Direct && peer_uid == my_uid && my_uid != 0;
    let is_online = peer_type == PeerType::Direct && !is_saved && app.is_peer_online(peer_uid);

    let big_avatar = canvas(AvatarCircleCanvas {
        title: title.to_owned(),
        color_rgb: avatar_rgb,
        is_online,
        is_saved_messages: is_saved,
        bg_cutout: BG_PANEL,
    })
    .width(Length::Fixed(76.0))
    .height(Length::Fixed(76.0));

    let peer_handle = if peer_type == PeerType::Direct {
        app.users_by_id
            .get(&peer_uid)
            .map(|u| format!("@{}", u.username))
            .unwrap_or_else(|| format!("ID #{peer_uid}"))
    } else {
        format!("Chat ID #{chat_id}")
    };

    let cached_count = app
        .messages_by_chat
        .get(&chat_id)
        .map(|m| m.len())
        .unwrap_or(0);

    let telemetry_box = container(
        column![
            txt("ЗАЩИТА И ХРАНИЛИЩЕ")
                .size(11)
                .font(FONT_BOLD)
                .color(ACCENT),
            txt("Транспорт: MTWire v1 (TCP_NODELAY)")
                .size(12)
                .color(TEXT_MAIN),
            txt("Ключи: X25519 + Ed25519 + HKDF")
                .size(12)
                .color(TEXT_SUB),
            txt("Шифр пакетов: ChaCha20-Poly1305")
                .size(12)
                .color(TEXT_SUB),
            txt("Локальная БД: SQLite3 WAL + AEAD")
                .size(12)
                .color(TEXT_SUB),
            txt(format!("В кэше ленты: {cached_count} сообщ."))
                .size(12)
                .color(ACCENT_TEXT),
        ]
        .spacing(6),
    )
    .padding(12)
    .width(Length::Fill)
    .style(|_theme| container::Style {
        background: Some(BG_INPUT.into()),
        border: iced::Border {
            color: rgba8(0x52, 0x88, 0xC1, 0.25),
            width: 1.0,
            radius: 8.0.into(),
        },
        ..container::Style::default()
    });

    let stress_btn = button(
        container(
            txt("⚡ Стресс-тест: +20 000 сообщ.")
                .size(12.5)
                .font(FONT_BOLD)
                .color(TEXT_MAIN),
        )
        .center_x(Length::Fill)
        .padding([8, 10]),
    )
    .width(Length::Fill)
    .style(primary_button_style)
    .on_press(Message::GenerateStressMessages);

    let body = column![
        v_spacer(10.0),
        container(big_avatar).center_x(Length::Fill),
        container(txt(title).size(16).font(FONT_BOLD).color(TEXT_MAIN)).center_x(Length::Fill),
        container(txt(peer_handle).size(13).color(ACCENT_TEXT)).center_x(Length::Fill),
        v_spacer(6.0),
        telemetry_box,
        stress_btn,
    ]
    .spacing(8)
    .padding([8, 16])
    .width(Length::Fill);

    container(column![header, h_divider(), body])
        .width(Length::Fixed(280.0))
        .height(Length::Fill)
        .style(sidebar_container)
        .into()
}
