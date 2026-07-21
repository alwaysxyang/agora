use super::LarkReplyTarget;
use super::card::{LarkAgentCard, LarkCardContent, LarkReplyCard};
use super::channel::{LarkCardActionEvent, LarkChannel, LarkMessageEvent, LarkTask};
use super::lark_api::LarkApi;
use crate::channel::{
    Channel, ChannelAgentStatus, ChannelButton, ChannelButtonStyle, ChannelReply, ChannelRun,
    RunEvent,
};
use crate::config::LarkChannelConfig;
use crate::task::{CommandRequest, OutputEvent, ProgressStatus, TokenUsage};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

fn agent_status_with_button(name: &str, enabled: bool) -> ChannelAgentStatus {
    let (text, style, command) = if enabled {
        ("Disable", ChannelButtonStyle::Default, "disable")
    } else {
        ("Enable", ChannelButtonStyle::Primary, "enable")
    };
    ChannelAgentStatus::new(name, enabled).with_button(ChannelButton::new(
        text,
        style,
        CommandRequest::new(["ask", command]).with_argument("agent_name", name),
    ))
}

#[test]
fn lark_card_uses_json_v2_for_standard_markdown() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Thinking {
        text: "Inspecting the channel".to_string(),
    });

    let card = content.build_card();

    assert_eq!(
        card.pointer("/schema").and_then(|v| v.as_str()),
        Some("2.0")
    );
    assert!(card.get("elements").is_none());
    assert!(card.pointer("/config/wide_screen_mode").is_none());
    assert_eq!(
        card.pointer("/body/elements/0/tag").unwrap(),
        "collapsible_panel"
    );
    assert_eq!(
        card.pointer("/body/elements/0/elements/0/content")
            .and_then(|v| v.as_str()),
        Some("> • Inspecting the channel")
    );
}

#[test]
fn lark_agent_list_card_renders_one_right_aligned_toggle_button_per_agent() {
    let reply = ChannelReply::agent_list(vec![
        agent_status_with_button("codex-dev", true),
        agent_status_with_button("reviewer", false),
    ]);

    let card = LarkReplyCard::build(&reply);
    assert_eq!(card.pointer("/header/title/content").unwrap(), "Agent 状态");
    assert_eq!(
        card.pointer("/header/subtitle/content").unwrap(),
        "当前对话 · 2 Agents"
    );
    let rows = card
        .pointer("/body/elements")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    let first_button = rows[0].pointer("/columns/1/elements/0").unwrap();
    let second_button = rows[2].pointer("/columns/1/elements/0").unwrap();
    assert_eq!(first_button.pointer("/text/content").unwrap(), "Disable");
    assert_eq!(first_button["type"], "default");
    assert_eq!(
        first_button.pointer("/behaviors/0/value").unwrap(),
        &serde_json::json!({
            "agora_command": {
                "path": ["ask", "disable"],
                "arguments": { "agent_name": "codex-dev" }
            }
        })
    );
    assert_eq!(second_button.pointer("/text/content").unwrap(), "Enable");
    assert_eq!(second_button["type"], "primary");
    assert_eq!(
        second_button.pointer("/behaviors/0/value").unwrap(),
        &serde_json::json!({
            "agora_command": {
                "path": ["ask", "enable"],
                "arguments": { "agent_name": "reviewer" }
            }
        })
    );
    let rendered = serde_json::to_string(&card).unwrap();
    assert!(rendered.contains("Enabled</font> · 接收后续消息"));
    assert!(rendered.contains("Disabled</font> · 不接收后续消息"));
    assert!(rendered.contains("配置仅对当前对话生效"));
}

#[test]
fn lark_agent_status_card_is_compact_and_has_no_toggle_button() {
    let reply = ChannelReply::agent_status(ChannelAgentStatus::new("reviewer", false));

    let card = LarkReplyCard::build(&reply);
    let rendered = serde_json::to_string(&card).unwrap();
    assert_eq!(
        card.pointer("/header/subtitle/content").unwrap(),
        "当前对话"
    );
    assert!(rendered.contains("**reviewer**"));
    assert!(rendered.contains("Disabled"));
    assert_eq!(
        card.pointer("/body/elements/0/columns/1/elements/0/text_align")
            .unwrap(),
        "right"
    );
    assert!(!rendered.contains("set_agent_enabled"));
    assert!(!rendered.contains("\"tag\":\"button\""));
}

#[test]
fn lark_card_collapses_thinking_and_expands_running_progress() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Thinking {
        text: "Inspecting the channel".to_string(),
    });
    content.apply_output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Running,
    });

    let card = content.build_card();
    let thinking = card.pointer("/body/elements/0").unwrap();
    let progress = card.pointer("/body/elements/1").unwrap();

    assert_eq!(thinking["tag"], "collapsible_panel");
    assert_eq!(thinking["expanded"], false);
    assert_eq!(thinking["background_color"], "grey-50");
    assert_eq!(thinking.pointer("/border/color").unwrap(), "grey-200");
    assert_eq!(thinking.pointer("/border/corner_radius").unwrap(), "8px");
    assert!(thinking.pointer("/header/background_color").is_none());
    assert_eq!(thinking["padding"], "2px 12px 10px 12px");
    assert_eq!(
        thinking.pointer("/header/padding").unwrap(),
        "8px 12px 8px 12px"
    );
    assert_eq!(
        thinking.pointer("/header/title/content").unwrap(),
        "**Thinking**  <font color='grey'>· 1 update</font>"
    );
    assert_eq!(progress["tag"], "collapsible_panel");
    assert_eq!(progress["expanded"], true);
    assert_eq!(progress["background_color"], "grey-50");
    assert_eq!(progress.pointer("/border/color").unwrap(), "grey-200");
    assert_eq!(progress.pointer("/border/corner_radius").unwrap(), "8px");
    assert_eq!(
        progress.pointer("/elements/0/content").unwrap(),
        "<font color='blue'>●</font>  Run `cargo test`"
    );
    assert_eq!(
        progress.pointer("/header/title/content").unwrap(),
        "**Progress**  <font color='grey'>·</font> <font color='blue'>●</font> <font color='grey'>1 running</font>"
    );
}

#[test]
fn lark_card_collapses_progress_after_completion() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Completed,
    });
    content.complete();

    let card = content.build_card();
    let progress = card.pointer("/body/elements/0").unwrap();

    assert_eq!(progress["tag"], "collapsible_panel");
    assert_eq!(progress["expanded"], false);
    assert_eq!(
        progress.pointer("/header/title/content").unwrap(),
        "**Progress**  <font color='grey'>·</font> <font color='green'>✓</font> <font color='grey'>1 completed</font>"
    );
}

#[test]
fn lark_card_progress_summary_shows_completed_and_failed_statuses() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    for index in 0..2 {
        content.apply_output(OutputEvent::Progress {
            id: format!("completed-{index}"),
            text: format!("Completed {index}"),
            status: ProgressStatus::Completed,
        });
    }
    content.apply_output(OutputEvent::Progress {
        id: "failed-1".to_string(),
        text: "Failed 1".to_string(),
        status: ProgressStatus::Failed,
    });
    content.complete();

    let card = content.build_card();
    let progress = card.pointer("/body/elements/0").unwrap();

    assert_eq!(
        progress.pointer("/header/title/content").unwrap(),
        "**Progress**  <font color='grey'>·</font> <font color='green'>✓</font> <font color='grey'>2 completed</font> · <font color='red'>×</font> <font color='grey'>1 failed</font>"
    );
}

#[test]
fn lark_card_failure_shows_safe_summary_and_collapsed_details() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.fail("agent process exited with code 1; Authorization: Bearer top-secret".to_string());

    let card = content.build_card();
    let rendered = serde_json::to_string(&card).unwrap();
    let details = card.pointer("/body/elements/1").unwrap();

    assert_eq!(
        card.pointer("/header/text_tag_list/0/text/content")
            .and_then(serde_json::Value::as_str),
        Some("Failed")
    );
    assert!(rendered.contains("<font color='red'>▌</font> **Run failed**"));
    assert!(rendered.contains("Agent 进程在完成任务前退出。"));
    assert!(rendered.contains("建议：请重试"));
    assert!(!rendered.contains("Authorization"));
    assert!(!rendered.contains("top-secret"));
    assert_eq!(details["tag"], "collapsible_panel");
    assert_eq!(details["expanded"], false);
    assert_eq!(
        details.pointer("/header/title/content").unwrap(),
        "**Technical details**  <font color='grey'>· Process exit</font>"
    );
    assert_eq!(
        details.pointer("/elements/0/content").unwrap(),
        "完整错误已写入 daemon 日志。"
    );
}

#[test]
fn lark_card_labels_an_answer_as_partial_when_the_run_fails() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Answer {
        text: "Work completed before the error.".to_string(),
    });
    content.fail("agent process exited with code 1".to_string());

    let rendered = serde_json::to_string(&content.build_card()).unwrap();
    let failure_index = rendered.find("**Run failed**").unwrap();
    let answer_index = rendered.find("**Partial answer**").unwrap();

    assert!(failure_index < answer_index);
    assert!(rendered.contains("<font color='blue'>▌</font> **Partial answer**"));
    assert!(!rendered.contains("**Final answer**"));
    assert!(rendered.contains("Work completed before the error."));
}

#[test]
fn lark_card_preserves_output_and_marks_the_run_as_stopped() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Thinking {
        text: "Inspecting the project".to_string(),
    });
    content.apply_output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Running,
    });
    content.apply_output(OutputEvent::Answer {
        text: "Work completed before the stop.".to_string(),
    });
    content.stop();

    let card = content.build_card();
    let rendered = serde_json::to_string(&card).unwrap();

    assert_eq!(
        card.pointer("/header/text_tag_list/0/text/content")
            .and_then(serde_json::Value::as_str),
        Some("Stopped")
    );
    assert_eq!(
        card.pointer("/header/template")
            .and_then(serde_json::Value::as_str),
        Some("grey")
    );
    assert!(rendered.contains("<font color='grey'>■</font>  Run `cargo test`"));
    assert!(rendered.contains("<font color='grey'>1 stopped</font>"));
    assert!(rendered.contains("<font color='grey'>▌</font> **Run stopped**"));
    assert!(rendered.contains("Stopped by request. Existing output is retained."));
    assert!(rendered.contains("<font color='blue'>▌</font> **Partial answer**"));
    assert!(rendered.contains("Work completed before the stop."));
}

#[test]
fn lark_card_preserves_output_and_marks_the_run_as_interrupted() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Running,
    });
    content.apply_output(OutputEvent::Answer {
        text: "Work completed before shutdown.".to_string(),
    });

    content.interrupt();

    let card = content.build_card();
    let rendered = serde_json::to_string(&card).unwrap();
    assert_eq!(
        card.pointer("/header/text_tag_list/0/text/content")
            .and_then(serde_json::Value::as_str),
        Some("Interrupted")
    );
    assert_eq!(
        card.pointer("/header/template")
            .and_then(serde_json::Value::as_str),
        Some("orange")
    );
    assert!(rendered.contains("<font color='grey'>■</font>  Run `cargo test`"));
    assert!(rendered.contains("<font color='orange'>▌</font> **Run interrupted**"));
    assert!(rendered.contains("Agora Node 即将退出，本次任务已中断，当前输出已保留。"));
    assert!(rendered.contains("Node 恢复后，请重新发送消息继续。"));
    assert!(rendered.contains("<font color='blue'>▌</font> **Partial answer**"));
    assert!(rendered.contains("Work completed before shutdown."));
}

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
    assert!(rendered.contains("> • Inspecting the channel"));
    assert!(rendered.contains("> • Checking reply delivery"));
    assert!(rendered.contains("**Progress**"));
    assert!(rendered.contains("<font color='green'>✓</font>  Run `cargo test`"));
    assert!(rendered.contains("<font color='blue'>▌</font> **Final answer**"));
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
fn lark_card_shows_a_bottom_stop_button_only_while_the_task_is_active() {
    let mut content =
        LarkCardContent::with_interrupt("codex-dev".to_string(), Some("interrupt-42".to_string()));

    let running = content.build_card();
    let elements = running
        .pointer("/body/elements")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    let action_row = elements.last().unwrap();
    let button = action_row.pointer("/columns/0/elements/0").unwrap();

    assert_eq!(action_row["tag"], "column_set");
    assert_eq!(action_row["horizontal_align"], "right");
    assert_eq!(button["tag"], "button");
    assert_eq!(button["type"], "danger");
    assert_eq!(button.pointer("/text/content").unwrap(), "结束任务");
    assert_eq!(button.pointer("/behaviors/0/type").unwrap(), "callback");
    assert_eq!(
        button.pointer("/behaviors/0/value").unwrap(),
        &serde_json::json!({
            "agora_interrupt": "interrupt-42"
        })
    );

    content.queue(2);
    assert!(
        serde_json::to_string(&content.build_card())
            .unwrap()
            .contains("agora_interrupt")
    );

    content.complete();
    assert!(
        !serde_json::to_string(&content.build_card())
            .unwrap()
            .contains("agora_interrupt")
    );
}

#[test]
fn lark_card_shows_queued_state_until_the_agent_starts() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.queue(2);

    let queued = content.build_card();
    assert_eq!(
        queued
            .pointer("/header/text_tag_list/0/text/content")
            .and_then(serde_json::Value::as_str),
        Some("Queued")
    );
    assert_eq!(
        queued
            .pointer("/header/template")
            .and_then(serde_json::Value::as_str),
        Some("grey")
    );
    assert_eq!(
        queued
            .pointer("/body/elements/0/content")
            .and_then(serde_json::Value::as_str),
        Some("> 正在排队，前面还有 2 个任务...")
    );

    content.queue(1);
    assert_eq!(
        content
            .build_card()
            .pointer("/body/elements/0/content")
            .and_then(serde_json::Value::as_str),
        Some("> 正在排队，前面还有 1 个任务...")
    );

    content.start();

    let running = content.build_card();
    assert_eq!(
        running
            .pointer("/header/text_tag_list/0/text/content")
            .and_then(serde_json::Value::as_str),
        Some("Running")
    );
    assert_eq!(
        running
            .pointer("/body/elements/0/content")
            .and_then(serde_json::Value::as_str),
        Some("> 正在等待 Agent 输出...")
    );
}

#[test]
fn lark_card_keeps_all_thinking_updates_with_latest_first() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    for index in 0..5 {
        content.apply_output(OutputEvent::Thinking {
            text: format!("Thinking {index}"),
        });
    }

    let card = content.build_card();
    let rendered = card
        .pointer("/body/elements/0/elements/0/content")
        .and_then(|value| value.as_str())
        .unwrap();
    assert_eq!(
        rendered,
        "> • Thinking 4\n> • Thinking 3\n> • Thinking 2\n> • Thinking 1\n> • Thinking 0"
    );
}

#[test]
fn lark_card_keeps_all_progress_entries_with_latest_first() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    for index in 0..6 {
        content.apply_output(OutputEvent::Progress {
            id: format!("progress-{index}"),
            text: format!("Progress {index}"),
            status: ProgressStatus::Completed,
        });
    }

    let card = content.build_card();
    let rendered = card
        .pointer("/body/elements/0/elements/0/content")
        .and_then(|value| value.as_str())
        .unwrap();
    assert_eq!(
        rendered,
        "<font color='green'>✓</font>  Progress 5\n<font color='green'>✓</font>  Progress 4\n<font color='green'>✓</font>  Progress 3\n<font color='green'>✓</font>  Progress 2\n<font color='green'>✓</font>  Progress 1\n<font color='green'>✓</font>  Progress 0"
    );
}

#[test]
fn lark_card_renders_token_usage_without_a_heading() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Answer {
        text: "All checks passed.".to_string(),
    });
    content.apply_output(OutputEvent::Usage(TokenUsage {
        input_tokens: 42_800,
        cached_input_tokens: 31_600,
        output_tokens: 3_200,
        reasoning_output_tokens: 1_900,
    }));

    content.complete();
    let card = content.build_card();
    let rendered = serde_json::to_string(&card).unwrap();
    assert!(rendered.contains("All checks passed."));
    assert!(!rendered.contains("Usage"));
    let elements = card
        .pointer("/body/elements")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(elements[elements.len() - 2]["tag"], "hr");
    let usage = elements.last().unwrap();
    assert_eq!(usage["tag"], "column_set");
    let columns = usage["columns"].as_array().unwrap();
    assert_eq!(columns.len(), 4);
    assert_eq!(
        columns[0].pointer("/elements/0/content").unwrap(),
        "<font color='grey'>Total</font>\n**46.0K**\n<font color='grey'>tokens</font>"
    );
    assert_eq!(
        columns[1].pointer("/elements/0/content").unwrap(),
        "<font color='grey'>Input</font>\n**42.8K**\n<font color='grey'>31.6K cached</font>"
    );
    assert_eq!(
        columns[2].pointer("/elements/0/content").unwrap(),
        "<font color='grey'>Output</font>\n**3.2K**\n<font color='grey'>tokens</font>"
    );
    assert_eq!(
        columns[3].pointer("/elements/0/content").unwrap(),
        "<font color='grey'>Reasoning</font>\n**1.9K**\n<font color='grey'>of output</font>"
    );
}

#[tokio::test]
async fn lark_card_coalesces_intermediate_updates_and_flushes_completion() {
    let server = TestHttpServer::start().await;
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
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
        None,
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

#[tokio::test]
async fn lark_api_replies_to_commands_with_threaded_text() {
    let server = TestHttpServer::start().await;
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        server.base_url(),
    )
    .unwrap();
    let token = api.tenant_access_token().await.unwrap();

    api.reply_text(
        &token,
        &LarkReplyTarget {
            message_id: "om_source".to_string(),
        },
        "Stopped 1 agent: codex-dev.",
    )
    .await
    .unwrap();

    let requests = server.requests().await;
    let request = requests
        .iter()
        .find(|request| request.path == "/open-apis/im/v1/messages/om_source/reply")
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
    let content: serde_json::Value =
        serde_json::from_str(body["content"].as_str().unwrap()).unwrap();

    assert_eq!(request.method, "POST");
    assert_eq!(body["msg_type"], "text");
    assert_eq!(body["reply_in_thread"], true);
    assert_eq!(content["text"], "Stopped 1 agent: codex-dev.");
}

#[tokio::test]
async fn lark_agent_toggle_action_patches_the_original_status_card() {
    let server = TestHttpServer::start().await;
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        server.base_url(),
    )
    .unwrap();
    let channel = LarkChannel::with_api(api);
    let task = LarkTask::from_card_action(LarkCardActionEvent {
        id: "evt_action".to_string(),
        session_id: "oc_chat".to_string(),
        message_id: "om_status_card".to_string(),
        command: CommandRequest::new(["ask", "enable"]).with_argument("agent_name", "reviewer"),
    });

    channel
        .reply(
            &task,
            ChannelReply::agent_list(vec![agent_status_with_button("reviewer", true)]),
        )
        .await
        .unwrap();

    let requests = server.requests().await;
    let patch = requests
        .iter()
        .find(|request| {
            request.method == "PATCH" && request.path == "/open-apis/im/v1/messages/om_status_card"
        })
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&patch.body).unwrap();
    let card: serde_json::Value = serde_json::from_str(body["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        card.pointer("/body/elements/0/columns/1/elements/0/text/content")
            .unwrap(),
        "Disable"
    );
}

#[tokio::test]
async fn lark_ask_message_replies_with_a_threaded_interactive_card() {
    let server = TestHttpServer::start().await;
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        server.base_url(),
    )
    .unwrap();
    let channel = LarkChannel::with_api(api);
    let task = LarkTask::from_message(
        LarkMessageEvent {
            id: "evt_message".to_string(),
            message_id: "om_ask".to_string(),
            chat_id: "oc_chat".to_string(),
            chat_type: "group".to_string(),
            sender_id: "ou_user".to_string(),
            message_type: "text".to_string(),
            content: "/ask list".to_string(),
            image_keys: Vec::new(),
        },
        crate::task::TaskContent::new("/ask list"),
    );

    channel
        .reply(
            &task,
            ChannelReply::agent_list(vec![agent_status_with_button("codex-dev", true)]),
        )
        .await
        .unwrap();

    let requests = server.requests().await;
    let reply = requests
        .iter()
        .find(|request| request.path == "/open-apis/im/v1/messages/om_ask/reply")
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(body["msg_type"], "interactive");
    assert_eq!(body["reply_in_thread"], true);
    let card: serde_json::Value = serde_json::from_str(body["content"].as_str().unwrap()).unwrap();
    assert_eq!(card.pointer("/header/title/content").unwrap(), "Agent 状态");
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
