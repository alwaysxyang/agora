use super::channel::{TelegramChannel, TelegramReplyTarget, TelegramUpdate};
use super::telegram_api::TelegramApi;
use crate::channel::test_http::HttpMockServer;
use crate::channel::{ChannelAgentStatus, ChannelReply, ChannelTask, ConfiguredChannel};
use crate::config::{ChannelConfig, TelegramChannelConfig};

#[path = "telegram_channel/api.rs"]
mod api;
#[path = "telegram_channel/messages.rs"]
mod messages;

fn telegram_config() -> TelegramChannelConfig {
    TelegramChannelConfig {
        name: "telegram-test".to_string(),
        token: "123456:secret".to_string(),
    }
}
