use super::super::telegram_api::{TelegramApi, TelegramBotCommand};
use super::{TelegramChannel, TelegramUpdate};
use crate::channel::test_http::{HttpMockServer, MockResponse};
use crate::channel::{
    Channel, ChannelAgent, ChannelAgentStatus, ChannelReply, ChannelRun, ChannelRunContext,
    ChannelTask, ConfiguredChannel, InterruptCallback, RunEvent,
};
use crate::config::{ChannelConfig, TelegramChannelConfig};

mod api;
mod messages;

fn telegram_config() -> TelegramChannelConfig {
    TelegramChannelConfig {
        name: "telegram-test".to_string(),
        token: "123456:secret".to_string(),
        proxy: None,
    }
}
