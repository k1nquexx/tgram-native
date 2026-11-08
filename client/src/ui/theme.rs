use iced::theme::Palette;
use iced::widget::{button, container, scrollable, text_editor, text_input};
use iced::{Background, Border, Color, Shadow, Theme};

#[inline]
pub const fn rgb8(r: u8, g: u8, b: u8) -> Color {
    Color {
        r: (r as f32) / 255.0,
        g: (g as f32) / 255.0,
        b: (b as f32) / 255.0,
        a: 1.0,
    }
}

#[inline]
pub const fn rgba8(r: u8, g: u8, b: u8, a: f32) -> Color {
    Color {
        r: (r as f32) / 255.0,
        g: (g as f32) / 255.0,
        b: (b as f32) / 255.0,
        a,
    }
}

#[inline]
pub const fn color_from_u32(rgb: u32) -> Color {
    let r = ((rgb >> 16) & 0xFF) as u8;
    let g = ((rgb >> 8) & 0xFF) as u8;
    let b = (rgb & 0xFF) as u8;
    rgb8(r, g, b)
}

// ============================================================================
// Official Telegram Desktop "Night Blue" Color Constants
// ============================================================================

/// `#17212b` — Sidebar, Chat Header & Composer Bar surface
pub const BG_PANEL: Color = rgb8(0x17, 0x21, 0x2B);

/// `#0e1621` — Chat Message History viewport background
pub const BG_CHAT: Color = rgb8(0x0E, 0x16, 0x21);

/// `#2b5278` — Outgoing message bubble & selected sidebar dialog row
pub const BUBBLE_OUT: Color = rgb8(0x2B, 0x52, 0x78);

/// `#182533` — Incoming message bubble & elevated cards
pub const BUBBLE_IN: Color = rgb8(0x18, 0x25, 0x33);

/// `#242f3d` — Search input field & subtle surface
pub const BG_INPUT: Color = rgb8(0x24, 0x2F, 0x3D);

/// `#202b36` — Hovered dialog item / icon button hover
pub const BG_HOVER: Color = rgb8(0x20, 0x2B, 0x36);

/// `#101921` — 1px structural divider hairline
pub const BORDER_DARK: Color = rgb8(0x10, 0x19, 0x21);

/// `#5288c1` — Primary Telegram Night Blue accent
pub const ACCENT: Color = rgb8(0x52, 0x88, 0xC1);

/// `#6499d3` — Brighter accent hover state
pub const ACCENT_HOVER: Color = rgb8(0x64, 0x99, 0xD3);

/// `#3e90df` — Unread counter pill badge & active send icon
pub const BADGE_UNREAD: Color = rgb8(0x3E, 0x90, 0xDF);

/// `#6ab3f3` — Typing status, links, and sidebar read checkmarks
pub const ACCENT_TEXT: Color = rgb8(0x6A, 0xB3, 0xF3);

/// `#78b9f5` — Read checkmarks (`✓` / `✓✓`) inside `#2b5278` outgoing bubbles
pub const TICK_OUT_COLOR: Color = rgb8(0x78, 0xB9, 0xF5);

/// `#f5f5f5` — Primary crisp white/off-white text
pub const TEXT_MAIN: Color = rgb8(0xF5, 0xF5, 0xF5);

/// `#7f91a4` — Muted secondary labels, previews & inactive icons
pub const TEXT_SUB: Color = rgb8(0x7F, 0x91, 0xA4);

/// `#7da8d3` — Inline timestamp inside `#2b5278` outgoing bubbles
pub const TEXT_TIME_OUT: Color = rgb8(0x7D, 0xA8, 0xD3);

/// `#6c7883` — Inline timestamp inside `#182533` incoming bubbles
pub const TEXT_TIME_IN: Color = rgb8(0x6C, 0x78, 0x83);

/// `#4dcd5e` — Online status dot
pub const ONLINE_DOT: Color = rgb8(0x4D, 0xCD, 0x5E);

/// `#e17076` — Error / Danger coral red
pub const DANGER: Color = rgb8(0xE1, 0x70, 0x76);

pub fn telegram_night_blue_theme() -> Theme {
    Theme::custom(
        "Telegram Night Blue".to_owned(),
        Palette {
            background: BG_CHAT,
            text: TEXT_MAIN,
            primary: ACCENT,
            success: ONLINE_DOT,
            warning: rgb8(0xFA, 0xA7, 0x74),
            danger: DANGER,
        },
    )
}

// ============================================================================
// Reusable Iced 0.13 Style Functions
// ============================================================================

pub fn sidebar_container(_theme: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT_MAIN),
        background: Some(Background::Color(BG_PANEL)),
        ..container::Style::default()
    }
}

pub fn chat_view_container(_theme: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT_MAIN),
        background: Some(Background::Color(BG_CHAT)),
        ..container::Style::default()
    }
}

pub fn card_container(_theme: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT_MAIN),
        background: Some(Background::Color(BG_PANEL)),
        border: Border {
            color: BORDER_DARK,
            width: 1.0,
            radius: 12.0.into(),
        },
        ..container::Style::default()
    }
}

pub fn pill_chip_container(_theme: &Theme) -> container::Style {
    container::Style {
        text_color: Some(TEXT_SUB),
        background: Some(Background::Color(rgba8(0x18, 0x25, 0x33, 0.88))),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 12.0.into(),
        },
        ..container::Style::default()
    }
}

pub fn hairline_divider(_theme: &Theme) -> container::Style {
    container::Style {
        text_color: None,
        background: Some(Background::Color(BORDER_DARK)),
        ..container::Style::default()
    }
}

pub fn search_input_style(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    let border_color = match status {
        text_input::Status::Focused => ACCENT,
        text_input::Status::Hovered => rgba8(0x52, 0x88, 0xC1, 0.45),
        _ => Color::TRANSPARENT,
    };
    text_input::Style {
        background: Background::Color(BG_INPUT),
        border: Border {
            color: border_color,
            width: 1.2,
            radius: 18.0.into(),
        },
        icon: TEXT_SUB,
        placeholder: TEXT_SUB,
        value: TEXT_MAIN,
        selection: rgba8(0x52, 0x88, 0xC1, 0.40),
    }
}

pub fn auth_input_style(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    let border_color = match status {
        text_input::Status::Focused => ACCENT,
        text_input::Status::Hovered => rgba8(0x7F, 0x91, 0xA4, 0.5),
        _ => rgba8(0x7F, 0x91, 0xA4, 0.22),
    };
    text_input::Style {
        background: Background::Color(BG_INPUT),
        border: Border {
            color: border_color,
            width: 1.2,
            radius: 8.0.into(),
        },
        icon: TEXT_SUB,
        placeholder: TEXT_SUB,
        value: TEXT_MAIN,
        selection: rgba8(0x52, 0x88, 0xC1, 0.40),
    }
}

pub fn composer_editor_style(_theme: &Theme, _status: text_editor::Status) -> text_editor::Style {
    text_editor::Style {
        background: Background::Color(BG_PANEL),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 0.0.into(),
        },
        placeholder: TEXT_SUB,
        value: TEXT_MAIN,
        selection: rgba8(0x52, 0x88, 0xC1, 0.42),
    }
}

pub fn primary_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => ACCENT_HOVER,
        button::Status::Pressed => rgb8(0x43, 0x74, 0xA8),
        button::Status::Disabled => BG_INPUT,
        button::Status::Active => ACCENT,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: TEXT_MAIN,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 8.0.into(),
        },
        ..button::Style::default()
    }
}

pub fn subtle_icon_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Some(Background::Color(BG_HOVER)),
        button::Status::Pressed => Some(Background::Color(BG_INPUT)),
        _ => None,
    };
    button::Style {
        background: bg,
        text_color: TEXT_SUB,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 20.0.into(),
        },
        ..button::Style::default()
    }
}

pub fn transparent_row_button_style(_theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: None,
        text_color: TEXT_MAIN,
        ..button::Style::default()
    }
}

pub fn thin_dark_scrollable_style(theme: &Theme, status: scrollable::Status) -> scrollable::Style {
    let mut style = scrollable::default(theme, status);
    style.container.background = None;
    style.vertical_rail.background = None;
    style.vertical_rail.border = Border::default();

    let thumb_alpha = match status {
        scrollable::Status::Hovered {
            is_vertical_scrollbar_hovered: true,
            ..
        }
        | scrollable::Status::Dragged {
            is_vertical_scrollbar_dragged: true,
            ..
        } => 0.65,
        scrollable::Status::Hovered { .. } => 0.38,
        _ => 0.18,
    };

    style.vertical_rail.scroller.background =
        Background::Color(rgba8(0x7F, 0x91, 0xA4, thumb_alpha));
    style.vertical_rail.scroller.border = Border {
        color: Color::TRANSPARENT,
        width: 0.0,
        radius: 3.0.into(),
    };
    style.horizontal_rail.background = None;
    style.gap = None;
    style
}
