use super::channel::TelegramReplyTarget;
use super::rich_message::{TelegramRichContent, TelegramRichMessage, TelegramRichTiming};
use super::telegram_api::TelegramApi;
use crate::channel::{ChannelRun, RunEvent};
use crate::config::TelegramChannelConfig;
use crate::task::{OutputEvent, ProgressStatus, TokenUsage};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

#[test]
fn telegram_rich_message_uses_chinese_system_labels() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Inspecting the project".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Completed,
    }));
    content.apply(RunEvent::Output(OutputEvent::Answer {
        text: "All checks passed.".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Usage(TokenUsage {
        input_tokens: 42_800,
        cached_input_tokens: 31_600,
        output_tokens: 3_200,
        reasoning_output_tokens: 1_900,
    })));
    content.apply(RunEvent::Completed { exit_code: 0 });

    let rendered = content.render(false);

    assert!(rendered.starts_with("## codex-dev · 已完成"));
    assert!(rendered.contains("<summary>思考过程 · 1 条</summary>"));
    assert!(rendered.contains("<summary>执行进度 · ✓ 1 项已完成</summary>"));
    assert!(rendered.contains("## 最终回答"));
    assert!(rendered.contains("Total **46.0K**"));
    assert!(rendered.contains("Input **42.8K** · 31.6K cached"));
    assert!(rendered.contains("Output **3.2K**"));
    assert!(rendered.contains("Reasoning **1.9K**"));
}

#[test]
fn telegram_rich_message_separates_process_answer_and_usage() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Started {
        run_id: "run-1".to_string(),
    });
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Inspecting the project".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Checking tests".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Completed,
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-2".to_string(),
        text: "Run `cargo clippy`".to_string(),
        status: ProgressStatus::Running,
    }));
    content.apply(RunEvent::Output(OutputEvent::Answer {
        text: "**Ready.**\n\n- tests pass".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Usage(TokenUsage {
        input_tokens: 42_800,
        cached_input_tokens: 31_600,
        output_tokens: 3_200,
        reasoning_output_tokens: 1_900,
    })));

    assert!(!content.render(false).contains("42.8K"));
    content.apply(RunEvent::Completed { exit_code: 0 });
    let rendered = content.render(false);

    assert!(rendered.starts_with("## codex-dev · 已完成"));
    assert!(rendered.contains("<details><summary>思考过程 · 2 条</summary>"));
    assert!(
        rendered.find("Checking tests").unwrap() < rendered.find("Inspecting the project").unwrap()
    );
    assert!(
        rendered.contains("<details><summary>执行进度 · ✓ 1 项已完成 · ● 1 项进行中</summary>")
    );
    assert!(
        rendered.find("Run `cargo clippy`").unwrap() < rendered.find("Run `cargo test`").unwrap()
    );
    assert!(rendered.contains("## 最终回答\n\n**Ready.**\n\n- tests pass"));
    assert!(rendered.contains("Total **46.0K**"));
    assert!(rendered.contains("Input **42.8K** · 31.6K cached"));
    assert!(rendered.contains("Output **3.2K**"));
    assert!(rendered.contains("Reasoning **1.9K**"));
}

#[test]
fn telegram_rich_message_replaces_progress_by_id_and_keeps_latest_first() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Running,
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-2".to_string(),
        text: "Read `Cargo.toml`".to_string(),
        status: ProgressStatus::Completed,
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Failed,
    }));

    let rendered = content.render(false);

    assert_eq!(rendered.matches("Run `cargo test`").count(), 1);
    assert!(
        rendered.find("× Run `cargo test`").unwrap()
            < rendered.find("✓ Read `Cargo.toml`").unwrap()
    );
    assert!(rendered.contains("✓ 1 项已完成 · × 1 项失败"));
}

#[test]
fn telegram_rich_message_keeps_all_thinking_updates_with_latest_first() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    for index in 0..8 {
        content.apply(RunEvent::Output(OutputEvent::Thinking {
            text: format!("Thinking {index}"),
        }));
    }

    let rendered = content.render(false);

    assert!(rendered.contains("思考过程 · 8 条"));
    for index in 0..8 {
        assert_eq!(rendered.matches(&format!("Thinking {index}")).count(), 1);
    }
    assert!(rendered.find("Thinking 7").unwrap() < rendered.find("Thinking 0").unwrap());
}

#[test]
fn telegram_rich_message_uses_native_thinking_only_for_active_drafts() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Reviewing the change".to_string(),
    }));

    assert!(
        content
            .render(true)
            .contains("<tg-thinking>Reviewing the change</tg-thinking>")
    );
    assert!(!content.render(false).contains("<tg-thinking>"));

    content.apply(RunEvent::Completed { exit_code: 0 });
    assert!(!content.render(true).contains("<tg-thinking>"));
}

#[test]
fn telegram_rich_message_renders_queue_stop_and_interruption_states() {
    let mut queued = TelegramRichContent::new("codex-dev".to_string());
    queued.apply(RunEvent::Queued { ahead: 2 });
    assert!(queued.render(false).contains("## codex-dev · 排队中"));
    assert!(queued.render(false).contains("前面还有 2 个任务"));

    let mut stopped = TelegramRichContent::new("codex-dev".to_string());
    stopped.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run tests".to_string(),
        status: ProgressStatus::Running,
    }));
    stopped.apply(RunEvent::Output(OutputEvent::Answer {
        text: "Partial work".to_string(),
    }));
    stopped.apply(RunEvent::Stopped);
    let stopped = stopped.render(false);
    assert!(stopped.contains("## codex-dev · 已停止"));
    assert!(stopped.contains("■ Run tests"));
    assert!(stopped.contains("## 部分回答\n\nPartial work"));

    let mut interrupted = TelegramRichContent::new("codex-dev".to_string());
    interrupted.apply(RunEvent::Interrupted);
    let interrupted = interrupted.render(false);
    assert!(interrupted.contains("## codex-dev · 已中断"));
    assert!(interrupted.contains("Agora Node 即将退出"));
}

#[test]
fn telegram_rich_message_hides_raw_failure_details() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Failed {
        message: "secret backend process exited with token=abc".to_string(),
    });

    let rendered = content.render(false);

    assert!(rendered.contains("## codex-dev · 失败"));
    assert!(rendered.contains("## 任务失败"));
    assert!(rendered.contains("Agent 进程在完成任务前退出。"));
    assert!(!rendered.contains("token=abc"));
}

#[tokio::test]
async fn private_run_streams_a_draft_and_persists_one_final_reply() {
    let server = RichMessageServer::start().await;
    let message = TelegramRichMessage::with_timing(
        private_target(),
        "codex-dev".to_string(),
        telegram_api(&server),
        TelegramRichTiming::new(Duration::from_millis(20), Duration::from_secs(5)),
    );

    message
        .publish(RunEvent::Started {
            run_id: "run-1".to_string(),
        })
        .await
        .unwrap();
    for index in 0..3 {
        message
            .publish(RunEvent::Output(OutputEvent::Thinking {
                text: format!("Thinking {index}"),
            }))
            .await
            .unwrap();
    }
    server
        .wait_for_method_count("sendRichMessageDraft", 2)
        .await;
    message
        .publish(RunEvent::Completed { exit_code: 0 })
        .await
        .unwrap();
    message
        .publish(RunEvent::Completed { exit_code: 0 })
        .await
        .unwrap();

    let requests = server.requests().await;
    let drafts = requests
        .iter()
        .filter(|request| request.method == "sendRichMessageDraft")
        .collect::<Vec<_>>();
    let finals = requests
        .iter()
        .filter(|request| request.method == "sendRichMessage")
        .collect::<Vec<_>>();
    assert_eq!(drafts.len(), 2);
    assert_eq!(finals.len(), 1);
    let first_draft: serde_json::Value = serde_json::from_str(&drafts[0].body).unwrap();
    let latest_draft: serde_json::Value = serde_json::from_str(&drafts[1].body).unwrap();
    assert_ne!(first_draft["draft_id"], 0);
    assert_eq!(first_draft["draft_id"], latest_draft["draft_id"]);
    assert!(
        latest_draft["rich_message"]["markdown"]
            .as_str()
            .unwrap()
            .contains("Thinking 2")
    );
    let final_body: serde_json::Value = serde_json::from_str(&finals[0].body).unwrap();
    assert_eq!(final_body["chat_id"], 1);
    assert_eq!(final_body["reply_parameters"]["message_id"], 7);
    assert_eq!(final_body["message_thread_id"], 44);
    assert!(
        final_body["rich_message"]["markdown"]
            .as_str()
            .unwrap()
            .contains("## codex-dev · 已完成")
    );
}

#[tokio::test]
async fn private_run_refreshes_the_draft_until_terminal_state() {
    let server = RichMessageServer::start().await;
    let message = TelegramRichMessage::with_timing(
        private_target(),
        "codex-dev".to_string(),
        telegram_api(&server),
        TelegramRichTiming::new(Duration::from_millis(5), Duration::from_millis(25)),
    );

    message
        .publish(RunEvent::Started {
            run_id: "run-1".to_string(),
        })
        .await
        .unwrap();
    server
        .wait_for_method_count("sendRichMessageDraft", 2)
        .await;
    message.publish(RunEvent::Stopped).await.unwrap();
    let draft_count = server.method_count("sendRichMessageDraft").await;

    tokio::time::sleep(Duration::from_millis(70)).await;

    assert_eq!(
        server.method_count("sendRichMessageDraft").await,
        draft_count
    );
    assert_eq!(server.method_count("sendRichMessage").await, 1);
}

#[tokio::test]
async fn group_run_sends_once_and_edits_the_same_topic_message() {
    let server = RichMessageServer::start().await;
    let message = TelegramRichMessage::with_timing(
        group_target(),
        "codex-dev".to_string(),
        telegram_api(&server),
        TelegramRichTiming::new(Duration::from_millis(20), Duration::from_secs(5)),
    );

    message
        .publish(RunEvent::Started {
            run_id: "run-1".to_string(),
        })
        .await
        .unwrap();
    message
        .publish(RunEvent::Output(OutputEvent::Thinking {
            text: "Inspecting".to_string(),
        }))
        .await
        .unwrap();
    server.wait_for_method_count("editMessageText", 1).await;
    message
        .publish(RunEvent::Completed { exit_code: 0 })
        .await
        .unwrap();

    let requests = server.requests().await;
    let sends = requests
        .iter()
        .filter(|request| request.method == "sendRichMessage")
        .collect::<Vec<_>>();
    let edits = requests
        .iter()
        .filter(|request| request.method == "editMessageText")
        .collect::<Vec<_>>();
    assert_eq!(sends.len(), 1);
    assert_eq!(edits.len(), 2);
    let send: serde_json::Value = serde_json::from_str(&sends[0].body).unwrap();
    assert_eq!(send["chat_id"], -1001);
    assert_eq!(send["message_thread_id"], 44);
    assert_eq!(send["reply_parameters"]["message_id"], 12);
    for edit in edits {
        let body: serde_json::Value = serde_json::from_str(&edit.body).unwrap();
        assert_eq!(body["chat_id"], -1001);
        assert_eq!(body["message_id"], 100);
    }
}

#[tokio::test]
async fn subscribed_agents_keep_independent_telegram_messages() {
    let server = RichMessageServer::start().await;
    let first = TelegramRichMessage::with_timing(
        group_target(),
        "codex-a".to_string(),
        telegram_api(&server),
        TelegramRichTiming::new(Duration::from_millis(5), Duration::from_secs(5)),
    );
    let second = TelegramRichMessage::with_timing(
        group_target(),
        "codex-b".to_string(),
        telegram_api(&server),
        TelegramRichTiming::new(Duration::from_millis(5), Duration::from_secs(5)),
    );

    first
        .publish(RunEvent::Started {
            run_id: "run-a".to_string(),
        })
        .await
        .unwrap();
    second
        .publish(RunEvent::Started {
            run_id: "run-b".to_string(),
        })
        .await
        .unwrap();
    first
        .publish(RunEvent::Completed { exit_code: 0 })
        .await
        .unwrap();
    second
        .publish(RunEvent::Completed { exit_code: 0 })
        .await
        .unwrap();

    let requests = server.requests().await;
    let edited_ids = requests
        .iter()
        .filter(|request| request.method == "editMessageText")
        .map(|request| {
            serde_json::from_str::<serde_json::Value>(&request.body).unwrap()["message_id"]
                .as_i64()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(edited_ids, vec![100, 101]);
}

fn telegram_api(server: &RichMessageServer) -> TelegramApi {
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

#[derive(Clone, Debug)]
struct RichMessageRequest {
    method: String,
    body: String,
}

struct RichMessageServer {
    base_url: String,
    requests: Arc<Mutex<Vec<RichMessageRequest>>>,
    task: JoinHandle<()>,
}

impl RichMessageServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let next_message_id = Arc::new(Mutex::new(100_i64));
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let captured = Arc::clone(&captured);
                let next_message_id = Arc::clone(&next_message_id);
                tokio::spawn(async move {
                    let (method, body) = Self::read_request(&mut stream).await;
                    captured.lock().await.push(RichMessageRequest {
                        method: method.clone(),
                        body,
                    });
                    let result = match method.as_str() {
                        "sendRichMessageDraft" => "true".to_string(),
                        "sendRichMessage" => {
                            let mut message_id = next_message_id.lock().await;
                            let current = *message_id;
                            *message_id += 1;
                            format!(r#"{{"message_id":{current}}}"#)
                        }
                        "editMessageText" => r#"{"message_id":100}"#.to_string(),
                        _ => panic!("unexpected Telegram method {method}"),
                    };
                    let response_body = format!(r#"{{"ok":true,"result":{result}}}"#);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        response_body.len(),
                        response_body
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

    async fn requests(&self) -> Vec<RichMessageRequest> {
        self.requests.lock().await.clone()
    }

    async fn method_count(&self, method: &str) -> usize {
        self.requests
            .lock()
            .await
            .iter()
            .filter(|request| request.method == method)
            .count()
    }

    async fn wait_for_method_count(&self, method: &str, expected: usize) {
        timeout(Duration::from_secs(2), async {
            loop {
                if self.method_count(method).await >= expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> (String, String) {
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
        let path = headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let method = path.rsplit('/').next().unwrap().to_string();
        let body = String::from_utf8_lossy(&received[header_end..header_end + content_length])
            .into_owned();
        (method, body)
    }
}

impl Drop for RichMessageServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
