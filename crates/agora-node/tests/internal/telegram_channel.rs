use super::channel::{TelegramChannel, TelegramReplyTarget, TelegramUpdate};
use super::telegram_api::TelegramApi;
use crate::channel::{ChannelAgentStatus, ChannelReply, ChannelTask, ConfiguredChannel};
use crate::config::{ChannelConfig, TelegramChannelConfig};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

#[test]
fn telegram_renders_agent_status_replies_without_interactive_controls() {
    let list = ChannelReply::agent_list(vec![
        ChannelAgentStatus::new("codex-dev", true),
        ChannelAgentStatus::new("reviewer", false),
    ]);
    assert_eq!(
        TelegramChannel::render_reply(&list),
        "当前对话的 Agent 状态\n✓ codex-dev — 已启用\n− reviewer — 已禁用"
    );

    let status = ChannelReply::agent_status(ChannelAgentStatus::new("reviewer", false));
    assert_eq!(
        TelegramChannel::render_reply(&status),
        "当前对话的 Agent 状态\n− reviewer — 已禁用"
    );
}

#[test]
fn normalizes_private_text_message() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 101,
            "message": {
                "message_id": 7,
                "from": {"id": 1, "is_bot": false},
                "chat": {"id": 1, "type": "private"},
                "text": "hello"
            }
        }"#,
    )
    .unwrap();

    let task = update.into_task("agora_bot").unwrap();

    assert_eq!(task.task_id(), "101");
    assert_eq!(task.session_id(), "chat:1");
    assert_eq!(task.input().message().unwrap().text(), "hello");
    assert_eq!(task.reply_target().chat_id, 1);
    assert_eq!(task.reply_target().message_id, 7);
    assert_eq!(task.reply_target().message_thread_id, None);
    assert!(task.reply_target().is_private);
}

#[test]
fn normalizes_forum_topic_session_and_reply_target() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 102,
            "message": {
                "message_id": 8,
                "message_thread_id": 44,
                "from": {"id": 1, "is_bot": false},
                "chat": {"id": -1001, "type": "supergroup"},
                "text": "run tests"
            }
        }"#,
    )
    .unwrap();

    let task = update.into_task("agora_bot").unwrap();

    assert_eq!(task.task_id(), "102");
    assert_eq!(task.session_id(), "chat:-1001:topic:44");
    assert_eq!(task.input().message().unwrap().text(), "run tests");
    assert_eq!(task.reply_target().chat_id, -1001);
    assert_eq!(task.reply_target().message_id, 8);
    assert_eq!(task.reply_target().message_thread_id, Some(44));
    assert!(!task.reply_target().is_private);
}

#[test]
fn ignores_messages_without_non_empty_text() {
    for payload in [
        r#"{
            "update_id": 103,
            "message": {
                "message_id": 9,
                "chat": {"id": 1, "type": "private"},
                "photo": [{"file_id": "photo-1"}]
            }
        }"#,
        r#"{
            "update_id": 104,
            "message": {
                "message_id": 10,
                "chat": {"id": 1, "type": "private"},
                "text": "   "
            }
        }"#,
    ] {
        let update = TelegramUpdate::from_json(payload).unwrap();
        assert!(update.into_task("agora_bot").is_none());
    }
}

#[test]
fn normalizes_commands_addressed_to_this_bot() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 105,
            "message": {
                "message_id": 11,
                "chat": {"id": -1001, "type": "group"},
                "text": "/stop@Agora_Bot codex-dev"
            }
        }"#,
    )
    .unwrap();

    let task = update.into_task("agora_bot").unwrap();

    assert_eq!(task.input().message().unwrap().text(), "/stop codex-dev");
}

#[test]
fn ignores_commands_addressed_to_another_bot() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 106,
            "message": {
                "message_id": 12,
                "chat": {"id": -1001, "type": "group"},
                "text": "/reset@another_bot"
            }
        }"#,
    )
    .unwrap();

    assert!(update.into_task("agora_bot").is_none());
}

#[tokio::test]
async fn telegram_api_gets_identity_and_polls_message_updates() {
    let server = TestTelegramServer::start([
        r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
        r#"{"ok":true,"result":[{"update_id":201,"message":{"message_id":9,"chat":{"id":1,"type":"private"},"text":"hello"}}]}"#,
    ])
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    assert_eq!(api.bot_username().await.unwrap(), "agora_bot");
    let updates = api.get_updates(Some(42)).await.unwrap();

    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0]["update_id"], 201);
    let requests = server.requests().await;
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/bot123456:secret/getMe");
    assert_eq!(requests[1].path, "/bot123456:secret/getUpdates");
    let poll: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
    assert_eq!(poll["offset"], 42);
    assert_eq!(poll["timeout"], 50);
    assert_eq!(poll["allowed_updates"], serde_json::json!(["message"]));
}

#[tokio::test]
async fn telegram_api_retries_after_rate_limit() {
    let server = TestTelegramServer::start([
        r#"{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":0}}"#,
        r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
    ])
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    assert_eq!(api.bot_username().await.unwrap(), "agora_bot");
    assert_eq!(server.requests().await.len(), 2);
}

#[tokio::test]
async fn telegram_api_errors_do_not_expose_the_bot_token() {
    let server = TestTelegramServer::start([
        r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
    ])
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    let error = api.bot_username().await.unwrap_err().to_string();

    assert!(error.contains("getMe"));
    assert!(error.contains("401"));
    assert!(error.contains("Unauthorized"));
    assert!(!error.contains("123456:secret"));
}

#[tokio::test]
async fn telegram_transport_errors_do_not_expose_the_bot_token() {
    let server = TestTelegramServer::start(["not-json"]).await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    let error = api.bot_username().await.unwrap_err();
    let report = format!("{error:#}");

    assert!(report.contains("getMe"));
    assert!(!report.contains("123456:secret"));
}

#[tokio::test]
async fn telegram_api_replies_to_the_source_message_and_topic() {
    let server = TestTelegramServer::start([r#"{"ok":true,"result":{"message_id":88}}"#]).await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();
    let target = TelegramReplyTarget {
        chat_id: -1001,
        message_id: 12,
        message_thread_id: Some(44),
        is_private: false,
    };

    api.reply_text(&target, "Reset successful.").await.unwrap();

    let requests = server.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/bot123456:secret/sendMessage");
    let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(body["chat_id"], -1001);
    assert_eq!(body["message_thread_id"], 44);
    assert_eq!(body["reply_parameters"]["message_id"], 12);
    assert_eq!(body["text"], "Reset successful.");
}

#[tokio::test]
async fn telegram_channel_returns_supported_updates_in_order_and_advances_offset() {
    let server = TestTelegramServer::start([
        r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
        r#"{"ok":true,"result":[
            {"update_id":301,"message":{"message_id":21,"chat":{"id":1,"type":"private"},"text":"first"}},
            {"update_id":302,"message":{"message_id":22,"chat":{"id":1,"type":"private"},"photo":[{"file_id":"photo-1"}]}},
            {"update_id":303,"message":{"message_id":23,"message_thread_id":44,"chat":{"id":-1001,"type":"supergroup"},"text":"second"}}
        ]}"#,
        r#"{"ok":true,"result":[
            {"update_id":304,"message":{"message_id":24,"chat":{"id":1,"type":"private"},"text":"third"}}
        ]}"#,
    ])
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();
    let mut channel = TelegramChannel::with_api(api);

    let first = channel.next_task().await.unwrap();
    let second = channel.next_task().await.unwrap();
    let third = channel.next_task().await.unwrap();

    assert_eq!(first.input().message().unwrap().text(), "first");
    assert_eq!(second.input().message().unwrap().text(), "second");
    assert_eq!(third.input().message().unwrap().text(), "third");
    let requests = server.requests().await;
    assert_eq!(requests.len(), 3);
    let second_poll: serde_json::Value = serde_json::from_str(&requests[2].body).unwrap();
    assert_eq!(second_poll["offset"], 304);
}

#[test]
fn configured_telegram_channel_is_active() {
    let channel = ConfiguredChannel::from_config(ChannelConfig::Telegram(telegram_config()))
        .unwrap()
        .expect("telegram channel should be active");

    assert!(matches!(channel, ConfiguredChannel::Telegram(_)));
}

fn telegram_config() -> TelegramChannelConfig {
    TelegramChannelConfig {
        name: "telegram-test".to_string(),
        token: "123456:secret".to_string(),
    }
}

#[derive(Clone, Debug)]
struct TestHttpRequest {
    path: String,
    body: String,
}

struct TestTelegramServer {
    base_url: String,
    requests: Arc<Mutex<Vec<TestHttpRequest>>>,
    task: JoinHandle<()>,
}

impl TestTelegramServer {
    async fn start<const N: usize>(responses: [&str; N]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let responses = Arc::new(Mutex::new(
            responses
                .into_iter()
                .map(str::to_string)
                .collect::<VecDeque<_>>(),
        ));
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let captured = Arc::clone(&captured);
                let responses = Arc::clone(&responses);
                tokio::spawn(async move {
                    let request = Self::read_request(&mut stream).await;
                    captured.lock().await.push(request);
                    let body = responses
                        .lock()
                        .await
                        .pop_front()
                        .expect("test server response should be configured");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        Self {
            base_url,
            requests,
            task,
        }
    }

    fn base_url(&self) -> String {
        self.base_url.clone()
    }

    async fn requests(&self) -> Vec<TestHttpRequest> {
        timeout(Duration::from_secs(2), async {
            loop {
                let requests = self.requests.lock().await.clone();
                if !requests.is_empty() {
                    return requests;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> TestHttpRequest {
        let mut received = Vec::new();
        let header_end = loop {
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            received.extend_from_slice(&buffer[..read]);
            if let Some(index) = find_bytes(&received, b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8_lossy(&received[..header_end]).into_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_string)
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or_default();
        while received.len() < header_end + content_length {
            let mut buffer = [0_u8; 4096];
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            received.extend_from_slice(&buffer[..read]);
        }
        let request_line = headers.lines().next().unwrap();
        let path = request_line.split_whitespace().nth(1).unwrap().to_string();
        let body = String::from_utf8_lossy(&received[header_end..header_end + content_length])
            .into_owned();
        TestHttpRequest { path, body }
    }
}

impl Drop for TestTelegramServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
