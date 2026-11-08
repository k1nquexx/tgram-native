#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod domain;
mod net;
mod storage;
mod ui;

use iced::Size;
use tracing_subscriber::EnvFilter;

use crate::domain::ClientLaunchConfig;
use crate::ui::TelegramApp;

fn main() -> iced::Result {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();

    let config = ClientLaunchConfig::from_args();

    iced::application(TelegramApp::title, TelegramApp::update, TelegramApp::view)
        .subscription(TelegramApp::subscription)
        .theme(TelegramApp::theme)
        .window_size(Size::new(1160.0, 760.0))
        .antialiasing(true)
        .run_with(move || TelegramApp::new(config))
}
