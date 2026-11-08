use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use cosmic_text::{
    Attrs as CosmicAttrs, Buffer as CosmicBuffer, Family as CosmicFamily,
    FontSystem as CosmicFontSystem, Metrics as CosmicMetrics, Shaping as CosmicShaping,
    Weight as CosmicWeight, Wrap as CosmicWrap,
};
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

const MAX_WRAP_CACHE_ENTRIES: usize = 32_768;
const MAX_WIDTH_CACHE_ENTRIES: usize = 16_384;

/// Exact HarfRust-shaped wrapped lines and pixel metrics produced by `cosmic-text`.
#[derive(Debug, Clone)]
pub struct WrappedTextLayout {
    pub lines: Vec<String>,
    pub widest_line_px: f32,
    pub last_line_px: f32,
}

struct CosmicTextMeasurer {
    font_system: CosmicFontSystem,
    wrap_buffer: CosmicBuffer,
    line_buffer: CosmicBuffer,
    wrap_cache: HashMap<(u64, usize, u32, u16), WrappedTextLayout>,
    width_cache: HashMap<(u64, usize, u16, bool), f32>,
}

impl CosmicTextMeasurer {
    fn new() -> Self {
        let font_system = CosmicFontSystem::new();
        let mut wrap_buffer =
            CosmicBuffer::new_empty(CosmicMetrics::new(14.5, BUBBLE_LINE_HEIGHT));
        wrap_buffer.set_wrap(CosmicWrap::WordOrGlyph);

        let mut line_buffer = CosmicBuffer::new_empty(CosmicMetrics::new(14.5, 20.0));
        line_buffer.set_wrap(CosmicWrap::None);

        Self {
            font_system,
            wrap_buffer,
            line_buffer,
            wrap_cache: HashMap::with_capacity(1024),
            width_cache: HashMap::with_capacity(1024),
        }
    }

    #[inline]
    fn hash_str(s: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }

    fn wrap_and_measure(
        &mut self,
        text: &str,
        max_line_px: f32,
        font_size: f32,
    ) -> WrappedTextLayout {
        if text.is_empty() {
            return WrappedTextLayout {
                lines: Vec::new(),
                widest_line_px: 0.0,
                last_line_px: 0.0,
            };
        }

        let limit_px = max_line_px.max(80.0);
        let fs_px = font_size.max(1.0);
        let cache_key = (
            Self::hash_str(text),
            text.len(),
            (limit_px * 10.0).round() as u32,
            (fs_px * 10.0).round() as u16,
        );
        if let Some(cached) = self.wrap_cache.get(&cache_key) {
            return cached.clone();
        }

        let lh_px = BUBBLE_LINE_HEIGHT.max(fs_px * 1.25);
        self.wrap_buffer
            .set_metrics_and_size(CosmicMetrics::new(fs_px, lh_px), Some(limit_px), None);
        let attrs = CosmicAttrs::new().family(CosmicFamily::SansSerif);
        self.wrap_buffer
            .set_text(text, &attrs, CosmicShaping::Advanced, None);
        self.wrap_buffer
            .shape_until_scroll(&mut self.font_system, false);

        let mut lines = Vec::new();
        let mut widest_line_px = 0.0_f32;
        let mut last_line_px = 0.0_f32;

        for run in self.wrap_buffer.layout_runs() {
            if run.glyphs.is_empty() {
                lines.push(String::new());
                last_line_px = 0.0;
            } else {
                let start_b = run.glyphs.iter().map(|g| g.start).min().unwrap_or(0);
                let end_b = run
                    .glyphs
                    .iter()
                    .map(|g| g.end)
                    .max()
                    .unwrap_or(run.text.len());
                let slice = run
                    .text
                    .get(start_b..end_b)
                    .unwrap_or(run.text)
                    .trim_end_matches(' ');
                lines.push(slice.to_owned());
                let w = run.line_w.max(0.0);
                widest_line_px = widest_line_px.max(w);
                last_line_px = w;
            }
        }

        let result = if widest_line_px <= 0.0 && !text.trim().is_empty() {
            // Headless container fallback when zero OS fonts are installed on disk
            fallback_wrap_without_system_fonts(text, limit_px, fs_px)
        } else {
            WrappedTextLayout {
                lines,
                widest_line_px,
                last_line_px,
            }
        };

        if self.wrap_cache.len() >= MAX_WRAP_CACHE_ENTRIES {
            self.wrap_cache.clear();
        }
        self.wrap_cache.insert(cache_key, result.clone());
        result
    }

    fn measure_single_line(&mut self, text: &str, font_size: f32, bold: bool) -> f32 {
        if text.is_empty() {
            return 0.0;
        }

        let fs_px = font_size.max(1.0);
        let cache_key = (
            Self::hash_str(text),
            text.len(),
            (fs_px * 10.0).round() as u16,
            bold,
        );
        if let Some(&cached) = self.width_cache.get(&cache_key) {
            return cached;
        }

        self.line_buffer
            .set_metrics_and_size(CosmicMetrics::new(fs_px, fs_px * 1.35), None, None);
        let mut attrs = CosmicAttrs::new().family(CosmicFamily::SansSerif);
        if bold {
            attrs = attrs.weight(CosmicWeight::BOLD);
        }
        self.line_buffer
            .set_text(text, &attrs, CosmicShaping::Advanced, None);
        self.line_buffer
            .shape_until_scroll(&mut self.font_system, false);

        let mut width = 0.0_f32;
        for run in self.line_buffer.layout_runs() {
            width = width.max(run.line_w);
        }

        if width <= 0.0 && !text.trim().is_empty() {
            width = fallback_text_width_px(text, fs_px, bold);
        }

        if self.width_cache.len() >= MAX_WIDTH_CACHE_ENTRIES {
            self.width_cache.clear();
        }
        self.width_cache.insert(cache_key, width);
        width
    }

    fn truncate_single_line(
        &mut self,
        text: &str,
        max_px: f32,
        font_size: f32,
        bold: bool,
    ) -> String {
        if max_px <= 18.0 || text.is_empty() {
            return String::new();
        }

        let normalized: Cow<'_, str> = if text.contains('\n') || text.contains('\r') {
            Cow::Owned(
                text.chars()
                    .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
                    .collect(),
            )
        } else {
            Cow::Borrowed(text)
        };

        let full_w = self.measure_single_line(&normalized, font_size, bold);
        if full_w <= max_px {
            return normalized.into_owned();
        }

        let fs_px = font_size.max(1.0);
        let ellipsis_w = self.measure_single_line("…", fs_px, bold).max(8.0);
        let target_w = (max_px - ellipsis_w).max(4.0);

        self.line_buffer
            .set_metrics_and_size(CosmicMetrics::new(fs_px, fs_px * 1.35), None, None);
        let mut attrs = CosmicAttrs::new().family(CosmicFamily::SansSerif);
        if bold {
            attrs = attrs.weight(CosmicWeight::BOLD);
        }
        self.line_buffer
            .set_text(&normalized, &attrs, CosmicShaping::Advanced, None);
        self.line_buffer
            .shape_until_scroll(&mut self.font_system, false);

        if let Some(run) = self.line_buffer.layout_runs().next() {
            if !run.rtl && !run.glyphs.is_empty() {
                let mut cut_end = 0usize;
                for g in run.glyphs {
                    if g.x + g.w <= target_w {
                        cut_end = cut_end.max(g.end);
                    } else {
                        break;
                    }
                }
                let prefix = normalized.get(..cut_end).unwrap_or("").trim_end();
                let mut out = String::with_capacity(prefix.len() + 4);
                out.push_str(prefix);
                out.push('…');
                return out;
            }
        }

        // BiDi RTL or headless fontless fallback via exact char-boundary binary search
        let char_offsets: Vec<usize> = normalized
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(normalized.len()))
            .collect();
        let mut lo = 0usize;
        let mut hi = char_offsets.len().saturating_sub(1);
        while lo < hi {
            let mid = (lo + hi + 1) / 2;
            let slice = &normalized[..char_offsets[mid]];
            if self.measure_single_line(slice, fs_px, bold) <= target_w {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        let prefix = normalized[..char_offsets[lo]].trim_end();
        let mut out = String::with_capacity(prefix.len() + 4);
        out.push_str(prefix);
        out.push('…');
        out
    }
}

thread_local! {
    static COSMIC_MEASURER: RefCell<CosmicTextMeasurer> = RefCell::new(CosmicTextMeasurer::new());
}

#[inline]
fn fallback_glyph_advance_14_5(ch: char) -> f32 {
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

fn fallback_text_width_px(s: &str, font_size: f32, bold: bool) -> f32 {
    let scale = (font_size / 14.5) * if bold { 1.05 } else { 1.0 };
    s.chars().map(fallback_glyph_advance_14_5).sum::<f32>() * scale
}

fn fallback_wrap_without_system_fonts(
    text: &str,
    limit: f32,
    font_size: f32,
) -> WrappedTextLayout {
    let scale = font_size / 14.5;
    let mut lines = Vec::new();
    let mut widest_line_px = 0.0_f32;
    let mut last_line_px = 0.0_f32;

    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            lines.push(String::new());
            last_line_px = 0.0;
            continue;
        }
        let mut current = String::new();
        let mut current_w = 0.0_f32;

        for ch in paragraph.chars() {
            let cw = fallback_glyph_advance_14_5(ch) * scale;
            if current_w + cw > limit && !current.is_empty() {
                let trimmed = current.trim_end().to_owned();
                let w = fallback_text_width_px(&trimmed, font_size, false);
                widest_line_px = widest_line_px.max(w);
                last_line_px = w;
                lines.push(trimmed);
                current.clear();
                current_w = 0.0;
                if ch == ' ' {
                    continue;
                }
            }
            current.push(ch);
            current_w += cw;
        }

        if !current.is_empty() {
            let trimmed = current.trim_end().to_owned();
            let w = fallback_text_width_px(&trimmed, font_size, false);
            widest_line_px = widest_line_px.max(w);
            last_line_px = w;
            lines.push(trimmed);
        }
    }

    WrappedTextLayout {
        lines,
        widest_line_px,
        last_line_px,
    }
}

/// Measures single-line glyph advance width in pixels via `cosmic-text` (`HarfRust` shaping).
#[inline]
pub fn measure_text_px(s: &str, font_size: f32, bold: bool) -> f32 {
    COSMIC_MEASURER.with(|m| m.borrow_mut().measure_single_line(s, font_size, bold))
}

#[inline]
pub fn estimate_text_width(s: &str, scale: f32) -> f32 {
    measure_text_px(s, 14.5 * scale.max(0.1), false)
}

#[inline]
pub fn wrap_text_lines_measured(
    text: &str,
    max_line_px: f32,
    font_size: f32,
) -> WrappedTextLayout {
    COSMIC_MEASURER.with(|m| m.borrow_mut().wrap_and_measure(text, max_line_px, font_size))
}

pub fn wrap_text_lines(text: &str, max_line_px: f32) -> Vec<String> {
    wrap_text_lines_measured(text, max_line_px, 14.5).lines
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

    let wrapped = wrap_text_lines_measured(&msg.text, max_inner_w, 14.5);
    let widest_line = wrapped.widest_line_px;
    let last_line_w = wrapped.last_line_px;
    let lines = wrapped.lines;

    let time_w = measure_text_px(&msg.time_label, 11.5, false);
    let meta_reserve_w = time_w + if msg.is_outgoing { 24.0 } else { 6.0 };
    let header_name_w = if show_sender_header {
        measure_text_px(&msg.sender_name, 13.0, true) + 8.0
    } else {
        0.0
    };
    let media_min_w = if msg.media.is_some() { 248.0 } else { 0.0 };

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

fn truncate_to_px(s: &str, max_px: f32, font_size: f32, bold: bool) -> String {
    COSMIC_MEASURER.with(|m| m.borrow_mut().truncate_single_line(s, max_px, font_size, bold))
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
        let time_w = measure_text_px(time_str, 12.2, false);
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
        let clipped_title = truncate_to_px(&self.dialog.title, title_avail, 14.5, true);
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
            let badge_w = (measure_text_px(&badge_txt, 11.8, true) + 12.0).max(20.0);
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
            let clipped_typing = truncate_to_px(typing_str, preview_avail, 13.5, false);
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

            let clipped_preview = truncate_to_px(&full_preview, preview_avail, 13.5, false);
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
        content: truncate_to_px(&media.attachment.file_name, max_text_w, 13.2, true),
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
        content: truncate_to_px(&status_line, max_text_w, 11.5, false),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosmic_text_wrapping_and_truncation() {
        let wrapped = wrap_text_lines_measured(
            "Проверка точного замера глифов через cosmic-text!\n\nhttps://example.org/very_long_unbroken_path_segment_for_glyph_fallback_wrapping_1234567890",
            220.0,
            14.5,
        );
        assert!(wrapped.lines.len() >= 4);
        assert!(wrapped.lines.iter().any(|l| l.is_empty()));
        assert!(wrapped.widest_line_px > 0.0);

        let short = truncate_to_px("Telegram", 200.0, 14.5, true);
        assert_eq!(short, "Telegram");

        let clipped = truncate_to_px(
            "Очень длинный заголовок группового чата разработчиков нативного Rust",
            140.0,
            14.5,
            true,
        );
        assert!(clipped.ends_with('…'));
        assert!(measure_text_px(&clipped, 14.5, true) <= 145.0);
    }
}
