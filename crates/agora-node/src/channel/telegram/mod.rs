mod channel;
mod rich_message;
mod telegram_api;

pub(super) use channel::{TelegramChannel, TelegramRun, TelegramTask};

#[cfg(test)]
#[path = "../../../tests/internal/telegram_channel.rs"]
mod telegram_channel_tests;

#[cfg(test)]
#[path = "../../../tests/internal/telegram_rich_message.rs"]
mod telegram_rich_message_tests;
