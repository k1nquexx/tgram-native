use iced::alignment::{Horizontal, Vertical};
use iced::mouse;
use iced::widget::canvas::{self, Frame, LineCap, LineJoin, Path, Stroke, Text};
use iced::widget::text::Shaping;
use iced::{font, Color, Font, Pixels, Point, Rectangle, Renderer, Size, Theme};
use tgram_proto::{MessageDeliveryState, PeerType};

use crate::domain::{format_bytes_human, MediaTransferStatus, UiDialog, UiMessage};
use crate::ui::theme::{
    color_from_u32, rgba8, ACCENT, ACCENT_TEXT, BADGE_UNREAD, BG_HOVER, BG_PANEL, BUBBLE_IN,
    BUBBLE_OUT, ONLINE_DOT, TEXT_MAIN, TEXT_SUB, TEXT_TIME_IN, TEXT_TIME_OUT, TICK_OUT_COLOR,
};

pub const DIALOG_ROW_HEIGHT: f32 = 72.0;
pub const BUBBLE_LINE_HEIGHT: f32 = 20.0;
pub const FONT_BOLD: Font = Font {
    weight: font::Weight::Bold,
    ..Font::DEFAULT
};

/// Grouping position inside consecutive messages from the same author.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BubbleGroupPos {
    Single,
    Top,
    Middle,
    Bottom,
}

impl BubbleGroupPos {
    #[inline]
    pub fn has_tail(self) -> bool {
        matches!(self, Self::Single | Self::Bottom)
    }

    #[inline]
    pub fn is_group_start(self) -> bool {
        matches!(self, Self::Single | Self::Top)
    }

    #[inline]
    pub fn bottom_gap(self) -> f32 {
        match self {
            Self::Single | Self::Bottom => 9.0,
            Self::Top | Self::Middle => 2.5,
        }
    }
}

/// Precomputed deterministic geometry for a single message bubble in `HistoryView`.
#[derive(Debug, Clone)]
pub struct MeasuredBubble {
    pub lines: Vec<String>,
    pub bubble_width: f32,
    pub bubble_height: f32,
    pub row_height: f32,
    pub inline_meta: bool,
    pub show_sender_header: bool,
}

/// Estimates glyph advance at `14.5px` sans-serif for Cyrillic/Latin/Emoji wrapping.
#[inline]
fn approx_char_advance(ch: char) -> f32 {
    if ch == ' ' {
        4.1
    } else if matches!(ch, 'i' | 'l' | 'I' | '.' | ',' | ':' | ';' | '!' | '|' | '\'') {
        3.9
    } else if matches!(ch, 'm' | 'w' | 'M' | 'W' | 'Ш' | 'Щ' | 'Ю' | 'Ж' | 'Ф') {
        10.6
    } else if (ch as u32) > 0x2000 {
        15.0
    } else {
        7.7
    }
}

pub fn estimate_text_width(s: &str, scale: f32) -> f32 {
    s.chars().map(approx_char_advance).sum::<f32>() * scale
}

pub fn wrap_text_lines(text: &str, max_line_px: f32) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let limit = max_line_px.max(80.0);
    let mut out = Vec::new();

    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            out.push(String::new());
            continue;
        }

        let mut current = String::new();
        let mut current_w = 0.0_f32;

        for word in paragraph.split_inclusive(' ') {
            let word_w = estimate_text_width(word, 1.0);
            if current.is_empty() {
                if word_w <= limit {
                    current.push_str(word);
                    current_w = word_w;
                } else {
                    // Hard-break extra-long unbroken token (e.g. long URL or hash)
                    for ch in word.chars() {
                        let cw = approx_char_advance(ch);
                        if current_w + cw > limit && !current.is_empty() {
                            out.push(std::mem::take(&mut current));
                            current_w = 0.0;
                        }
                        current.push(ch);
                        current_w += cw;
                    }
                }
            } else if current_w + word_w <= limit {
                current.push_str(word);
                current_w += word_w;
            } else {
                out.push(current.trim_end().to_owned());
                current.clear();
                current_w = 0.0;

                if word_w <= limit {
                    current.push_str(word);
                    current_w = word_w;
                } else {
                    for ch in word.chars() {
                        let cw = approx_char_advance(ch);
                        if current_w + cw > limit && !current.is_empty() {
                            out.push(std::mem::take(&mut current));
                            current_w = 0.0;
                        }
                        current.push(ch);
                        current_w += cw;
                    }
                }
            }
        }

        if !current.is_empty() {
            out.push(current.trim_end().to_owned());
        }
    }

    out
}

/// Computes exact bubble width, wrapped lines, inline timestamp reflow, and total row height.
pub fn measure_bubble_layout(
    msg: &UiMessage,
    group_pos: BubbleGroupPos,
    is_group_chat: bool,
    viewport_width: f32,
) -> MeasuredBubble {
    let max_bubble_w = (viewport_width * 0.64).clamp(220.0, 540.0);
    let pad_x = 12.0_f32;
    let max_inner_w = (max_bubble_w - pad_x * 2.0).max(120.0);

    let show_sender_header = is_group_chat && !msg.is_outgoing && group_pos.is_group_start();

    let lines = wrap_text_lines(&msg.text, max_inner_w);
    let widest_line = lines
        .iter()
        .map(|l| estimate_text_width(l, 1.0))
        .fold(0.0_f32, f32::max);

    let meta_reserve_w = if msg.is_outgoing { 60.0 } else { 42.0 };
    let header_name_w = if show_sender_header {
        estimate_text_width(&msg.sender_name, 0.96) + 8.0
    } else {
        0.0
    };
    let media_min_w = if msg.media.is_some() { 248.0 } else { 0.0 };

    let last_line_w = lines
        .last()
        .map(|l| estimate_text_width(l, 1.0))
        .unwrap_or(0.0);

    let inline_meta = !lines.is_empty() && (last_line_w + meta_reserve_w + 12.0 <= max_inner_w);

    let desired_inner_w = if inline_meta && lines.len() == 1 {
        (last_line_w + meta_reserve_w + 12.0)
            .max(header_name_w)
            .max(media_min_w)
    } else {
        widest_line
            .max(meta_reserve_w + 8.0)
            .max(header_name_w)
            .max(media_min_w)
    };

    let bubble_width = (desired_inner_w + pad_x * 2.0).clamp(88.0, max_bubble_w);

    let mut inner_h = 8.0_f32; // Top padding
    if show_sender_header {
        inner_h += 19.0;
    }
    if msg.media.is_some() {
        inner_h += 54.0;
        if !lines.is_empty() {
            inner_h += 6.0;
        }
    }
    if !lines.is_empty() {
        inner_h += (lines.len() as f32) * BUBBLE_LINE_HEIGHT;
        if !inline_meta {
            inner_h += 16.0;
        }
    } else {
        // Media-only message still reserves timestamp footer line
        inner_h += 16.0;
    }
    inner_h += 7.0; // Bottom padding

    let bubble_height = inner_h.max(36.0);
    let row_height = bubble_height + group_pos.bottom_gap();

    MeasuredBubble {
        lines,
        bubble_width,
        bubble_height,
        row_height,
        inline_meta,
        show_sender_header,
    }
}

pub fn extract_initials(title: &str) -> String {
    let mut chars = Vec::new();
    for word in title.split_whitespace().take(2) {
        if let Some(ch) = word.chars().find(|c| c.is_alphanumeric()) {
            for up in ch.to_uppercase() {
                chars.push(up);
                break;
            }
        }
    }
    if chars.is_empty() {
        title
            .chars()
            .next()
            .map(|c| c.to_uppercase().collect())
            .unwrap_or_else(|| "TG".to_owned())
    } else {
        chars.into_iter().collect()
    }
}

fn truncate_to_px(s: &str, max_px: f32, scale: f32) -> String {
    if max_px <= 20.0 {
        return String::new();
    }
    let full = estimate_text_width(s, scale);
    if full <= max_px {
        return s.to_owned();
    }
    let target = (max_px - 14.0).max(8.0);
    let mut acc = 0.0;
    let mut out = String::new();
    for ch in s.chars() {
        let w = approx_char_advance(ch) * scale;
        if acc + w > target {
            break;
        }
        out.push(ch);
        acc += w;
    }
    out.push('…');
    out
}

// ============================================================================
// 1. Vector UI Icons (`☰`, `🔍`, `◧`, `📎`, `➤`)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorIconKind {
    BurgerMenu,
    SearchMagnifier,
    RightPanelToggle { active: bool },
    AttachPaperclip,
    SendPaperPlane { active: bool },
}

pub struct VectorIconCanvas {
    pub kind: VectorIconKind,
}

impl<Message> canvas::Program<Message> for VectorIconCanvas {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let cx = bounds.width * 0.5;
        let cy = bounds.height * 0.5;
        let hovered = cursor.is_over(bounds);

        let base_color = match self.kind {
            VectorIconKind::RightPanelToggle { active: true } => ACCENT_TEXT,
            VectorIconKind::SendPaperPlane { active: true } => BADGE_UNREAD,
            VectorIconKind::SendPaperPlane { active: false } => rgba8(0x7F, 0x91, 0xA4, 0.45),
            _ if hovered => TEXT_MAIN,
            _ => TEXT_SUB,
        };

        let stroke = Stroke {
            style: base_color.into(),
            width: 1.85,
            line_cap: LineCap::Round,
            line_join: LineJoin::Round,
            ..Stroke::default()
        };

        match self.kind {
            VectorIconKind::BurgerMenu => {
                let p = Path::new(|b| {
                    for dy in [-5.5_f32, 0.0, 5.5] {
                        b.move_to(Point::new(cx - 8.5, cy + dy));
                        b.line_to(Point::new(cx + 8.5, cy + dy));
                    }
                });
                frame.stroke(&p, stroke);
            }

            VectorIconKind::SearchMagnifier => {
                let circle = Path::circle(Point::new(cx - 1.5, cy - 1.5), 6.4);
                frame.stroke(&circle, stroke);
                let handle = Path::new(|b| {
                    b.move_to(Point::new(cx + 3.2, cy + 3.2));
                    b.line_to(Point::new(cx + 8.2, cy + 8.2));
                });
                frame.stroke(&handle, stroke);
            }

            VectorIconKind::RightPanelToggle { .. } => {
                let rect = Path::rounded_rectangle(
                    Point::new(cx - 8.5, cy - 7.0),
                    Size::new(17.0, 14.0),
                    2.5.into(),
                );
                frame.stroke(&rect, stroke);
                let split = Path::new(|b| {
                    b.move_to(Point::new(cx + 2.5, cy - 7.0));
                    b.line_to(Point::new(cx + 2.5, cy + 7.0));
                });
                frame.stroke(&split, stroke);
            }

            VectorIconKind::AttachPaperclip => {
                let clip = Path::new(|b| {
                    b.move_to(Point::new(cx + 5.5, cy - 2.0));
                    b.line_to(Point::new(cx - 1.5, cy + 5.0));
                    b.quadratic_curve_to(
                        Point::new(cx - 6.5, cy + 9.5),
                        Point::new(cx - 8.5, cy + 4.5),
                    );
                    b.quadratic_curve_to(
                        Point::new(cx - 10.0, cy + 0.5),
                        Point::new(cx - 5.5, cy - 4.0),
                    );
                    b.line_to(Point::new(cx + 2.5, cy - 10.5));
                    b.quadratic_curve_to(
                        Point::new(cx + 6.5, cy - 12.5),
                        Point::new(cx + 8.0, cy - 8.5),
                    );
                    b.quadratic_curve_to(
                        Point::new(cx + 9.0, cy - 5.5),
                        Point::new(cx + 5.5, cy - 2.0),
                    );
                    b.line_to(Point::new(cx - 2.0, cy + 4.5));
                });
                frame.stroke(&clip, stroke);
            }

            VectorIconKind::SendPaperPlane { .. } => {
                let plane = Path::new(|b| {
                    b.move_to(Point::new(cx - 8.5, cy - 8.0));
                    b.line_to(Point::new(cx + 10.0, cy));
                    b.line_to(Point::new(cx - 8.5, cy + 8.0));
                    b.line_to(Point::new(cx - 4.8, cy + 1.1));
                    b.line_to(Point::new(cx + 3.0, cy));
                    b.line_to(Point::new(cx - 4.8, cy - 1.1));
                    b.close();
                });
                frame.fill(&plane, base_color);
            }
        }

        vec![frame.into_geometry()]
    }
}

// ============================================================================
// 2. Reusable Circular Peer Avatar (`AvatarCircleCanvas`)
// ============================================================================

pub struct AvatarCircleCanvas {
    pub title: String,
    pub color_rgb: u32,
    pub is_online: bool,
    pub is_saved_messages: bool,
    pub bg_cutout: Color,
}

impl<Message> canvas::Program<Message> for AvatarCircleCanvas {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let r = bounds.width.min(bounds.height) * 0.5;
        let center = Point::new(bounds.width * 0.5, bounds.height * 0.5);

        draw_avatar(
            &mut frame,
            center,
            r,
            &self.title,
            self.color_rgb,
            self.is_online,
            self.is_saved_messages,
            self.bg_cutout,
        );

        vec![frame.into_geometry()]
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_avatar(
    frame: &mut Frame,
    center: Point,
    radius: f32,
    title: &str,
    color_rgb: u32,
    is_online: bool,
    is_saved_messages: bool,
    cutout_bg: Color,
) {
    let fill_color = if is_saved_messages {
        BADGE_UNREAD
    } else {
        color_from_u32(color_rgb)
    };
    frame.fill(&Path::circle(center, radius), fill_color);

    if is_saved_messages {
        let w = radius * 0.62;
        let h = radius * 0.78;
        let bookmark = Path::new(|b| {
            b.move_to(Point::new(center.x - w * 0.5, center.y - h * 0.5));
            b.line_to(Point::new(center.x + w * 0.5, center.y - h * 0.5));
            b.line_to(Point::new(center.x + w * 0.5, center.y + h * 0.5));
            b.line_to(Point::new(center.x, center.y + h * 0.18));
            b.line_to(Point::new(center.x - w * 0.5, center.y + h * 0.5));
            b.close();
        });
        frame.fill(&bookmark, TEXT_MAIN);
    } else {
        let initials = extract_initials(title);
        frame.fill_text(Text {
            content: initials,
            position: center,
            color: TEXT_MAIN,
            size: Pixels((radius * 0.76).clamp(11.0, 26.0)),
            font: FONT_BOLD,
            horizontal_alignment: Horizontal::Center,
            vertical_alignment: Vertical::Center,
            shaping: Shaping::Advanced,
            ..Text::default()
        });
    }

    if is_online && !is_saved_messages {
        let dot_r = (radius * 0.24).clamp(4.5, 7.0);
        let dot_pos = Point::new(center.x + radius * 0.70, center.y + radius * 0.70);
        frame.fill(&Path::circle(dot_pos, dot_r + 2.0), cutout_bg);
        frame.fill(&Path::circle(dot_pos, dot_r), ONLINE_DOT);
    }
}

/// Draws single (`✓`), double (`✓✓`), or sending clock (`🕒`) vector ticks.
fn draw_delivery_ticks(
    frame: &mut Frame,
    origin: Point,
    state: MessageDeliveryState,
    color: Color,
) {
    let stroke = Stroke {
        style: color.into(),
        width: 1.55,
        line_cap: LineCap::Round,
        line_join: LineJoin::Round,
        ..Stroke::default()
    };

    match state {
        MessageDeliveryState::Sending => {
            let c = Point::new(origin.x + 6.0, origin.y + 5.5);
            frame.stroke(&Path::circle(c, 5.0), stroke);
            let hands = Path::new(|b| {
                b.move_to(c);
                b.line_to(Point::new(c.x, c.y - 3.0));
                b.move_to(c);
                b.line_to(Point::new(c.x + 2.5, c.y + 1.2));
            });
            frame.stroke(&hands, stroke);
        }
        MessageDeliveryState::Sent | MessageDeliveryState::Unspecified => {
            let tick = Path::new(|b| {
                b.move_to(Point::new(origin.x + 2.0, origin.y + 6.0));
                b.line_to(Point::new(origin.x + 5.4, origin.y + 9.4));
                b.line_to(Point::new(origin.x + 11.8, origin.y + 2.2));
            });
            frame.stroke(&tick, stroke);
        }
        MessageDeliveryState::Read => {
            let tick1 = Path::new(|b| {
                b.move_to(Point::new(origin.x + 0.5, origin.y + 6.0));
                b.line_to(Point::new(origin.x + 3.9, origin.y + 9.4));
                b.line_to(Point::new(origin.x + 10.3, origin.y + 2.2));
            });
            let tick2 = Path::new(|b| {
                b.move_to(Point::new(origin.x + 5.2, origin.y + 6.0));
                b.line_to(Point::new(origin.x + 8.4, origin.y + 9.4));
                b.line_to(Point::new(origin.x + 15.0, origin.y + 2.2));
            });
            frame.stroke(&tick1, stroke);
            frame.stroke(&tick2, stroke);
        }
    }
}

// ============================================================================
// 3. Virtualized Sidebar Dialog Row (`DialogRowCanvas`, 72px height)
// ============================================================================

pub struct DialogRowCanvas {
    pub dialog: UiDialog,
    pub is_selected: bool,
    pub is_peer_online: bool,
    pub is_saved_messages: bool,
    pub typing_label: Option<String>,
}

impl<Message> canvas::Program<Message> for DialogRowCanvas {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let w = bounds.width;
        let h = bounds.height;
        let hovered = cursor.is_over(bounds);

        let row_bg = if self.is_selected {
            BUBBLE_OUT
        } else if hovered {
            BG_HOVER
        } else {
            BG_PANEL
        };
        frame.fill_rectangle(Point::ORIGIN, Size::new(w, h), row_bg);

        // 1. 48px circular avatar
        draw_avatar(
            &mut frame,
            Point::new(35.0, h * 0.5),
            24.0,
            &self.dialog.title,
            self.dialog.avatar_color_rgb,
            self.is_peer_online,
            self.is_saved_messages,
            row_bg,
        );

        let text_left = 70.0_f32;
        let right_margin = 12.0_f32;

        // 2. Top-right timestamp + outgoing delivery checkmarks
        let time_color = if self.is_selected {
            TEXT_MAIN
        } else {
            TEXT_SUB
        };
        let time_str = &self.dialog.top_time_label;
        let time_w = estimate_text_width(time_str, 0.85);
        frame.fill_text(Text {
            content: time_str.clone(),
            position: Point::new(w - right_margin, 16.0),
            color: time_color,
            size: Pixels(12.2),
            horizontal_alignment: Horizontal::Right,
            vertical_alignment: Vertical::Top,
            shaping: Shaping::Advanced,
            ..Text::default()
        });

        let mut title_max_right = w - right_margin - time_w - 8.0;
        if let Some(delivery) = self.dialog.top_delivery {
            let tick_color = if self.is_selected {
                TEXT_MAIN
            } else {
                ACCENT_TEXT
            };
            let tick_x = w - right_margin - time_w - 21.0;
            draw_delivery_ticks(&mut frame, Point::new(tick_x, 16.5), delivery, tick_color);
            title_max_right = tick_x - 6.0;
        }

        // 3. Top-left bold chat title
        let title_avail = (title_max_right - text_left).max(40.0);
        let clipped_title = truncate_to_px(&self.dialog.title, title_avail, 1.02);
        frame.fill_text(Text {
            content: clipped_title,
            position: Point::new(text_left, 14.0),
            color: TEXT_MAIN,
            size: Pixels(14.5),
            font: FONT_BOLD,
            horizontal_alignment: Horizontal::Left,
            vertical_alignment: Vertical::Top,
            shaping: Shaping::Advanced,
            ..Text::default()
        });

        // 4. Bottom-right Unread Counter Badge
        let mut preview_max_right = w - right_margin;
        if self.dialog.unread_count > 0 {
            let badge_txt = if self.dialog.unread_count > 999 {
                "999+".to_owned()
            } else {
                self.dialog.unread_count.to_string()
            };
            let badge_w = (estimate_text_width(&badge_txt, 0.88) + 12.0).max(20.0);
            let badge_h = 20.0_f32;
            let bx = w - right_margin - badge_w;
            let by = 40.0_f32;

            let (pill_bg, pill_fg) = if self.is_selected {
                (TEXT_MAIN, BUBBLE_OUT)
            } else {
                (BADGE_UNREAD, TEXT_MAIN)
            };

            let pill = Path::rounded_rectangle(
                Point::new(bx, by),
                Size::new(badge_w, badge_h),
                10.0.into(),
            );
            frame.fill(&pill, pill_bg);
            frame.fill_text(Text {
                content: badge_txt,
                position: Point::new(bx + badge_w * 0.5, by + badge_h * 0.5),
                color: pill_fg,
                size: Pixels(11.8),
                font: FONT_BOLD,
                horizontal_alignment: Horizontal::Center,
                vertical_alignment: Vertical::Center,
                shaping: Shaping::Advanced,
                ..Text::default()
            });

            preview_max_right = bx - 8.0;
        }

        // 5. Bottom-left Typing Indicator or Last Message Preview
        let preview_avail = (preview_max_right - text_left).max(40.0);
        if let Some(ref typing_str) = self.typing_label {
            let clipped_typing = truncate_to_px(typing_str, preview_avail, 0.94);
            frame.fill_text(Text {
                content: clipped_typing,
                position: Point::new(text_left, 41.0),
                color: if self.is_selected {
                    TEXT_MAIN
                } else {
                    ACCENT_TEXT
                },
                size: Pixels(13.5),
                horizontal_alignment: Horizontal::Left,
                vertical_alignment: Vertical::Top,
                shaping: Shaping::Advanced,
                ..Text::default()
            });
        } else {
            let full_preview = if self.dialog.top_sender_is_self && !self.dialog.top_preview.is_empty()
            {
                format!("Вы: {}", self.dialog.top_preview)
            } else if self.dialog.top_preview.is_empty() {
                "Нет сообщений".to_owned()
            } else {
                self.dialog.top_preview.clone()
            };

            let clipped_preview = truncate_to_px(&full_preview, preview_avail, 0.94);
            frame.fill_text(Text {
                content: clipped_preview,
                position: Point::new(text_left, 41.0),
                color: if self.is_selected {
                    rgba8(0xEB, 0xF3, 0xFA, 0.92)
                } else {
                    TEXT_SUB
                },
                size: Pixels(13.5),
                horizontal_alignment: Horizontal::Left,
                vertical_alignment: Vertical::Top,
                shaping: Shaping::Advanced,
                ..Text::default()
            });
        }

        vec![frame.into_geometry()]
    }
}

// ============================================================================
// 4. Virtualized Message Bubble (`MessageBubbleCanvas` with Bezier Tails & Media)
// ============================================================================

pub struct MessageBubbleCanvas {
    pub msg: UiMessage,
    pub group_pos: BubbleGroupPos,
    pub peer_type: PeerType,
    pub measured: MeasuredBubble,
}

impl<Message> canvas::Program<Message> for MessageBubbleCanvas {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let is_group = self.peer_type == PeerType::Group;
        let bw = self.measured.bubble_width;
        let bh = self.measured.bubble_height;

        let side_pad = 16.0_f32;
        let group_avatar_gutter = if is_group && !self.msg.is_outgoing {
            42.0
        } else {
            0.0
        };

        let bx = if self.msg.is_outgoing {
            (bounds.width - side_pad - bw).max(8.0)
        } else {
            side_pad + group_avatar_gutter
        };
        let by = 0.0_f32;

        // Draw group sender circular avatar at bottom of author chain
        if is_group && !self.msg.is_outgoing && self.group_pos.has_tail() {
            draw_avatar(
                &mut frame,
                Point::new(side_pad + 16.0, by + bh - 17.0),
                16.0,
                &self.msg.sender_name,
                self.msg.sender_color_rgb,
                false,
                false,
                Color::TRANSPARENT,
            );
        }

        // Draw asymmetric rounded bubble + Bezier tail
        let bubble_color = if self.msg.is_outgoing {
            BUBBLE_OUT
        } else {
            BUBBLE_IN
        };
        let bubble_path = build_telegram_bubble_path(
            bx,
            by,
            bw,
            bh,
            self.msg.is_outgoing,
            self.group_pos,
        );
        frame.fill(&bubble_path, bubble_color);

        let mut cursor_y = by + 8.0;
        let inner_x = bx + 12.0;
        let inner_w = bw - 24.0;

        // 1. Optional Group Author Name
        if self.measured.show_sender_header {
            frame.fill_text(Text {
                content: self.msg.sender_name.clone(),
                position: Point::new(inner_x, cursor_y),
                color: color_from_u32(self.msg.sender_color_rgb),
                size: Pixels(13.0),
                font: FONT_BOLD,
                horizontal_alignment: Horizontal::Left,
                vertical_alignment: Vertical::Top,
                shaping: Shaping::Advanced,
                ..Text::default()
            });
            cursor_y += 19.0;
        }

        // 2. Optional Media Attachment Card with Progress Bar
        if let Some(ref media_state) = self.msg.media {
            let card_rect = Rectangle {
                x: inner_x,
                y: cursor_y,
                width: inner_w,
                height: 50.0,
            };
            let card_hovered = cursor.is_over(bounds);
            draw_media_card(
                &mut frame,
                card_rect,
                media_state,
                self.msg.is_outgoing,
                card_hovered,
            );
            cursor_y += 54.0;
            if !self.measured.lines.is_empty() {
                cursor_y += 6.0;
            }
        }

        // 3. Wrapped Message Body Lines
        for line in &self.measured.lines {
            frame.fill_text(Text {
                content: line.clone(),
                position: Point::new(inner_x, cursor_y),
                color: TEXT_MAIN,
                size: Pixels(14.5),
                horizontal_alignment: Horizontal::Left,
                vertical_alignment: Vertical::Top,
                shaping: Shaping::Advanced,
                ..Text::default()
            });
            cursor_y += BUBBLE_LINE_HEIGHT;
        }

        // 4. Inline Bottom-Right Timestamp & Delivery Checkmarks (`✓` / `✓✓`)
        let meta_y = by + bh - 18.5;
        let time_color = if self.msg.is_outgoing {
            TEXT_TIME_OUT
        } else {
            TEXT_TIME_IN
        };

        if self.msg.is_outgoing {
            let tick_x = bx + bw - 12.0 - 15.5;
            draw_delivery_ticks(
                &mut frame,
                Point::new(tick_x, meta_y + 1.5),
                self.msg.delivery,
                TICK_OUT_COLOR,
            );
            frame.fill_text(Text {
                content: self.msg.time_label.clone(),
                position: Point::new(tick_x - 4.0, meta_y),
                color: time_color,
                size: Pixels(11.5),
                horizontal_alignment: Horizontal::Right,
                vertical_alignment: Vertical::Top,
                shaping: Shaping::Advanced,
                ..Text::default()
            });
        } else {
            frame.fill_text(Text {
                content: self.msg.time_label.clone(),
                position: Point::new(bx + bw - 12.0, meta_y),
                color: time_color,
                size: Pixels(11.5),
                horizontal_alignment: Horizontal::Right,
                vertical_alignment: Vertical::Top,
                shaping: Shaping::Advanced,
                ..Text::default()
            });
        }

        vec![frame.into_geometry()]
    }
}

fn draw_media_card(
    frame: &mut Frame,
    rect: Rectangle,
    media: &crate::domain::UiMediaState,
    is_outgoing: bool,
    hovered: bool,
) {
    let card_bg = if is_outgoing {
        if hovered {
            rgba8(0x1B, 0x3A, 0x59, 0.72)
        } else {
            rgba8(0x1B, 0x3A, 0x59, 0.52)
        }
    } else if hovered {
        rgba8(0x24, 0x36, 0x48, 0.85)
    } else {
        rgba8(0x20, 0x30, 0x40, 0.65)
    };

    frame.fill(
        &Path::rounded_rectangle(rect.position(), rect.size(), 9.0.into()),
        card_bg,
    );

    let icon_center = Point::new(rect.x + 25.0, rect.y + rect.height * 0.5);
    frame.fill(&Path::circle(icon_center, 18.0), BADGE_UNREAD);

    let icon_stroke = Stroke {
        style: TEXT_MAIN.into(),
        width: 1.9,
        line_cap: LineCap::Round,
        line_join: LineJoin::Round,
        ..Stroke::default()
    };

    let (status_line, progress_opt) = match &media.transfer {
        MediaTransferStatus::Idle => {
            // Downward download arrow glyph
            let arrow = Path::new(|b| {
                b.move_to(Point::new(icon_center.x, icon_center.y - 6.5));
                b.line_to(Point::new(icon_center.x, icon_center.y + 5.5));
                b.move_to(Point::new(icon_center.x - 4.8, icon_center.y + 1.0));
                b.line_to(Point::new(icon_center.x, icon_center.y + 6.0));
                b.line_to(Point::new(icon_center.x + 4.8, icon_center.y + 1.0));
            });
            frame.stroke(&arrow, icon_stroke);
            (
                format!(
                    "{} • Нажмите, чтобы скачать",
                    format_bytes_human(media.attachment.size_bytes)
                ),
                None,
            )
        }
        MediaTransferStatus::Uploading { progress } => {
            let arrow = Path::new(|b| {
                b.move_to(Point::new(icon_center.x, icon_center.y + 6.5));
                b.line_to(Point::new(icon_center.x, icon_center.y - 5.5));
                b.move_to(Point::new(icon_center.x - 4.8, icon_center.y - 1.0));
                b.line_to(Point::new(icon_center.x, icon_center.y - 6.0));
                b.line_to(Point::new(icon_center.x + 4.8, icon_center.y - 1.0));
            });
            frame.stroke(&arrow, icon_stroke);
            (
                format!(
                    "Отправка {:.0}% • {}",
                    (progress * 100.0).clamp(0.0, 100.0),
                    format_bytes_human(media.attachment.size_bytes)
                ),
                Some(*progress),
            )
        }
        MediaTransferStatus::Downloading { progress } => {
            let arrow = Path::new(|b| {
                b.move_to(Point::new(icon_center.x, icon_center.y - 6.5));
                b.line_to(Point::new(icon_center.x, icon_center.y + 5.5));
            });
            frame.stroke(&arrow, icon_stroke);
            (
                format!(
                    "Загрузка {:.0}% • {}",
                    (progress * 100.0).clamp(0.0, 100.0),
                    format_bytes_human(media.attachment.size_bytes)
                ),
                Some(*progress),
            )
        }
        MediaTransferStatus::Downloaded { .. } => {
            // Document / Check glyph
            let doc = Path::new(|b| {
                b.move_to(Point::new(icon_center.x - 5.0, icon_center.y + 0.5));
                b.line_to(Point::new(icon_center.x - 1.2, icon_center.y + 4.5));
                b.line_to(Point::new(icon_center.x + 6.0, icon_center.y - 4.0));
            });
            frame.stroke(&doc, icon_stroke);
            (
                format!(
                    "{} • Сохранено локально",
                    format_bytes_human(media.attachment.size_bytes)
                ),
                None,
            )
        }
        MediaTransferStatus::Failed(err) => (format!("Ошибка: {err}"), None),
    };

    let text_x = rect.x + 51.0;
    let max_text_w = (rect.width - 60.0).max(60.0);

    frame.fill_text(Text {
        content: truncate_to_px(&media.attachment.file_name, max_text_w, 0.96),
        position: Point::new(text_x, rect.y + 7.0),
        color: TEXT_MAIN,
        size: Pixels(13.2),
        font: FONT_BOLD,
        horizontal_alignment: Horizontal::Left,
        vertical_alignment: Vertical::Top,
        shaping: Shaping::Advanced,
        ..Text::default()
    });

    frame.fill_text(Text {
        content: truncate_to_px(&status_line, max_text_w, 0.85),
        position: Point::new(text_x, rect.y + 25.0),
        color: if is_outgoing { TEXT_TIME_OUT } else { ACCENT_TEXT },
        size: Pixels(11.5),
        horizontal_alignment: Horizontal::Left,
        vertical_alignment: Vertical::Top,
        shaping: Shaping::Advanced,
        ..Text::default()
    });

    if let Some(p) = progress_opt {
        let bar_y = rect.y + 42.5;
        let bar_w = max_text_w;
        frame.fill(
            &Path::rounded_rectangle(
                Point::new(text_x, bar_y),
                Size::new(bar_w, 4.0),
                2.0.into(),
            ),
            rgba8(0x0E, 0x16, 0x21, 0.55),
        );
        let filled_w = (bar_w * p.clamp(0.03, 1.0)).max(4.0);
        frame.fill(
            &Path::rounded_rectangle(
                Point::new(text_x, bar_y),
                Size::new(filled_w, 4.0),
                2.0.into(),
            ),
            ACCENT_TEXT,
        );
    } else {
        let _ = ACCENT;
    }
}

/// Constructs an asymmetric rounded Telegram message bubble with an optional bottom Bezier tail.
fn build_telegram_bubble_path(
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    is_outgoing: bool,
    pos: BubbleGroupPos,
) -> Path {
    let r_outer = 14.0_f32;
    let r_grouped = 5.0_f32;

    let (tl, tr, br, bl) = if is_outgoing {
        match pos {
            BubbleGroupPos::Single => (r_outer, r_outer, 0.0, r_outer),
            BubbleGroupPos::Top => (r_outer, r_outer, r_grouped, r_outer),
            BubbleGroupPos::Middle => (r_outer, r_grouped, r_grouped, r_outer),
            BubbleGroupPos::Bottom => (r_outer, r_grouped, 0.0, r_outer),
        }
    } else {
        match pos {
            BubbleGroupPos::Single => (r_outer, r_outer, r_outer, 0.0),
            BubbleGroupPos::Top => (r_outer, r_outer, r_outer, r_grouped),
            BubbleGroupPos::Middle => (r_grouped, r_outer, r_outer, r_grouped),
            BubbleGroupPos::Bottom => (r_grouped, r_outer, r_outer, 0.0),
        }
    };

    Path::new(|b| {
        // Start top-left edge
        b.move_to(Point::new(x + tl, y));
        // Top edge -> top-right corner
        b.line_to(Point::new(x + w - tr, y));
        if tr > 0.0 {
            b.quadratic_curve_to(Point::new(x + w, y), Point::new(x + w, y + tr));
        }

        // Right edge -> bottom-right corner (or outgoing Bezier tail)
        if is_outgoing && pos.has_tail() {
            b.line_to(Point::new(x + w, y + h - 11.0));
            b.quadratic_curve_to(
                Point::new(x + w + 0.5, y + h - 2.0),
                Point::new(x + w + 7.5, y + h),
            );
            b.line_to(Point::new(x + w - 4.0, y + h));
        } else {
            b.line_to(Point::new(x + w, y + h - br));
            if br > 0.0 {
                b.quadratic_curve_to(Point::new(x + w, y + h), Point::new(x + w - br, y + h));
            }
        }

        // Bottom edge -> bottom-left corner (or incoming Bezier tail)
        if !is_outgoing && pos.has_tail() {
            b.line_to(Point::new(x + 4.0, y + h));
            b.line_to(Point::new(x - 7.5, y + h));
            b.quadratic_curve_to(
                Point::new(x - 0.5, y + h - 2.0),
                Point::new(x, y + h - 11.0),
            );
        } else {
            b.line_to(Point::new(x + bl, y + h));
            if bl > 0.0 {
                b.quadratic_curve_to(Point::new(x, y + h), Point::new(x, y + h - bl));
            }
        }

        // Left edge -> top-left corner
        b.line_to(Point::new(x, y + tl));
        if tl > 0.0 {
            b.quadratic_curve_to(Point::new(x, y), Point::new(x + tl, y));
        }
        b.close();
    })
}
