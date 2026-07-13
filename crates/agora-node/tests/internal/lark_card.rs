use crate::channel::lark::card::{LarkAgentCard, LarkCardContent};
use crate::channel::lark::{LarkApi, LarkChannelConfig, LarkReplyTarget};
use crate::channel::{ChannelRun, RunEvent};
use crate::output::{OutputEvent, ProgressStatus};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

#[test]
fn lark_card_separates_thinking_progress_and_final_answer() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Thinking {
        text: "Inspecting the channel\nChecking reply delivery".to_string(),
    });
    content.apply_output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Running,
    });
    content.apply_output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Completed,
    });
    content.apply_output(OutputEvent::Answer {
        text: "The Lark path is ready.".to_string(),
    });
    content.complete();

    let card = content.build_card();
    assert_eq!(
        card.pointer("/header/title/content")
            .and_then(|v| v.as_str()),
        Some("codex-dev")
    );
    assert_eq!(
        card.pointer("/header/text_tag_list/0/text/content")
            .and_then(|v| v.as_str()),
        Some("Completed")
    );
    let rendered = serde_json::to_string(&card).unwrap();
    assert!(rendered.contains("**Thinking**"));
    assert!(rendered.contains("> Inspecting the channel"));
    assert!(rendered.contains("> Checking reply delivery"));
    assert!(rendered.contains("**Progress**"));
    assert!(rendered.contains("**Done**  Run `cargo test`"));
    assert!(rendered.contains("**Final answer**"));
    assert!(rendered.contains("The Lark path is ready."));
    assert!(!rendered.contains("正在等待 Agent 输出"));
    assert_eq!(rendered.matches("Run `cargo test`").count(), 1);
}

#[test]
fn lark_card_shows_a_placeholder_before_agent_output() {
    let content = LarkCardContent::new("codex-dev".to_string());

    let rendered = serde_json::to_string(&content.build_card()).unwrap();

    assert!(rendered.contains("> 正在等待 Agent 输出..."));
}

#[test]
fn lark_card_keeps_only_the_five_latest_progress_entries() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    for index in 0..6 {
        content.apply_output(OutputEvent::Progress {
            id: format!("progress-{index}"),
            text: format!("Progress {index}"),
            status: ProgressStatus::Completed,
        });
    }

    let rendered = serde_json::to_string(&content.build_card()).unwrap();
    assert!(!rendered.contains("Progress 0"));
    for index in 1..6 {
        assert!(rendered.contains(format!("Progress {index}").as_str()));
    }
}

#[tokio::test]
async fn lark_card_coalesces_intermediate_updates_and_flushes_completion() {
    let server = TestHttpServer::start().await;
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            appid: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        server.base_url(),
    )
    .unwrap();
    let card = LarkAgentCard::new(
        LarkReplyTarget {
            message_id: "om_source".to_string(),
        },
        "codex-dev".to_string(),
        api,
    );

    card.publish(RunEvent::Started {
        run_id: "run-1".to_string(),
    })
    .await
    .unwrap();
    for index in 0..3 {
        card.publish(RunEvent::Output(OutputEvent::Thinking {
            text: format!("Thinking {index}"),
        }))
        .await
        .unwrap();
    }

    server.wait_for_patch_count(1).await;
    card.publish(RunEvent::Completed { exit_code: 0 })
        .await
        .unwrap();

    let requests = server.requests().await;
    let replies = requests
        .iter()
        .filter(|request| request.path == "/open-apis/im/v1/messages/om_source/reply")
        .collect::<Vec<_>>();
    let patches = requests
        .iter()
        .filter(|request| {
            request.method == "PATCH" && request.path == "/open-apis/im/v1/messages/om_reply"
        })
        .collect::<Vec<_>>();
    assert_eq!(replies.len(), 1);
    assert_eq!(patches.len(), 2);

    let reply_body: serde_json::Value = serde_json::from_str(&replies[0].body).unwrap();
    assert_eq!(reply_body["reply_in_thread"], true);
    let final_body: serde_json::Value = serde_json::from_str(&patches[1].body).unwrap();
    let final_card: serde_json::Value =
        serde_json::from_str(final_body["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        final_card
            .pointer("/header/text_tag_list/0/text/content")
            .and_then(serde_json::Value::as_str),
        Some("Completed")
    );
}

#[derive(Clone, Debug)]
struct TestHttpRequest {
    method: String,
    path: String,
    body: String,
}

struct TestHttpServer {
    base_url: String,
    requests: Arc<Mutex<Vec<TestHttpRequest>>>,
    task: JoinHandle<()>,
}

impl TestHttpServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let captured = Arc::clone(&captured);
                tokio::spawn(async move {
                    let mut received = Vec::new();
                    let header_end = loop {
                        let mut buffer = [0_u8; 4096];
                        let read = stream.read(&mut buffer).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        received.extend_from_slice(&buffer[..read]);
                        if let Some(index) = find_bytes(&received, b"\r\n\r\n") {
                            break index + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&received[..header_end]).into_owned();
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .or_else(|| line.strip_prefix("Content-Length: "))
                        })
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or_default();
                    while received.len() < header_end + content_length {
                        let mut buffer = [0_u8; 4096];
                        let read = stream.read(&mut buffer).await.unwrap();
                        if read == 0 {
                            break;
                        }
                        received.extend_from_slice(&buffer[..read]);
                    }
                    let request_line = headers.lines().next().unwrap();
                    let mut request_parts = request_line.split_whitespace();
                    let method = request_parts.next().unwrap().to_string();
                    let path = request_parts.next().unwrap().to_string();
                    let body =
                        String::from_utf8_lossy(&received[header_end..header_end + content_length])
                            .to_string();
                    captured.lock().await.push(TestHttpRequest {
                        method,
                        path: path.clone(),
                        body,
                    });

                    let body = if path.ends_with("tenant_access_token/internal") {
                        r#"{"code":0,"msg":"ok","tenant_access_token":"token"}"#
                    } else if path.ends_with("/reply") {
                        r#"{"code":0,"msg":"ok","data":{"message_id":"om_reply"}}"#
                    } else {
                        r#"{"code":0,"msg":"ok"}"#
                    };
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

    async fn wait_for_patch_count(&self, expected: usize) {
        timeout(Duration::from_secs(2), async {
            loop {
                let count = self
                    .requests
                    .lock()
                    .await
                    .iter()
                    .filter(|request| request.method == "PATCH")
                    .count();
                if count >= expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn requests(&self) -> Vec<TestHttpRequest> {
        self.requests.lock().await.clone()
    }
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
