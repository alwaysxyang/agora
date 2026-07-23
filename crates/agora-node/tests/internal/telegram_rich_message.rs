use super::channel::TelegramReplyTarget;
use super::rich_message::{TelegramRichContent, TelegramRichMessage, TelegramRichTiming};
use super::telegram_api::TelegramApi;
use crate::channel::test_http::{HttpMockServer, MockResponse};
use crate::channel::{ChannelRun, RunEvent};
use crate::config::TelegramChannelConfig;
use crate::task::{OutputEvent, ProgressStatus, TokenUsage};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

#[path = "telegram_rich_message/api.rs"]
mod api;
#[path = "telegram_rich_message/content.rs"]
mod content;

fn telegram_api(server: &HttpMockServer) -> TelegramApi {
    TelegramApi::with_base_url(
        TelegramChannelConfig {
            name: "telegram-test".to_string(),
            token: "123456:secret".to_string(),
        },
        server.base_url(),
    )
    .unwrap()
}

fn private_target() -> TelegramReplyTarget {
    TelegramReplyTarget {
        chat_id: 1,
        message_id: 7,
        message_thread_id: Some(44),
        is_private: true,
    }
}

fn group_target() -> TelegramReplyTarget {
    TelegramReplyTarget {
        chat_id: -1001,
        message_id: 12,
        message_thread_id: Some(44),
        is_private: false,
    }
}

async fn rich_message_server() -> HttpMockServer {
    let next_message_id = AtomicI64::new(100);
    HttpMockServer::start(move |request| {
        let result = match request.endpoint() {
            "sendRichMessageDraft" => "true".to_string(),
            "sendRichMessage" => {
                let message_id = next_message_id.fetch_add(1, Ordering::Relaxed);
                format!(r#"{{"message_id":{message_id}}}"#)
            }
            "editMessageText" => r#"{"message_id":100}"#.to_string(),
            method => panic!("unexpected Telegram method {method}"),
        };
        MockResponse::json(format!(r#"{{"ok":true,"result":{result}}}"#))
    })
    .await
}
