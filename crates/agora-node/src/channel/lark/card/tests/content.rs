use super::*;

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
    assert_eq!(
        card.pointer("/header/title/content").unwrap(),
        "当前对话的 Agent 状态"
    );
    assert_eq!(
        card.pointer("/header/subtitle/content").unwrap(),
        "当前对话 · 2 个 Agent"
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
    assert!(rendered.contains("已启用</font> · 接收后续消息"));
    assert!(rendered.contains("已禁用</font> · 不接收后续消息"));
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
    assert!(rendered.contains("已禁用"));
    assert_eq!(
        card.pointer("/body/elements/0/columns/1/elements/0/text_align")
            .unwrap(),
        "right"
    );
    assert!(!rendered.contains("set_agent_enabled"));
    assert!(!rendered.contains("\"tag\":\"button\""));
}

#[test]
fn lark_card_uses_chinese_system_labels() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Thinking {
        text: "Inspecting the project".to_string(),
    });
    content.apply_output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Completed,
    });
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

    assert_eq!(
        card.pointer("/header/text_tag_list/0/text/content")
            .and_then(serde_json::Value::as_str),
        Some("已完成")
    );
    assert!(rendered.contains("**思考过程**"));
    assert!(rendered.contains("1 条"));
    assert!(rendered.contains("**执行进度**"));
    assert!(rendered.contains("1 项已完成"));
    assert!(rendered.contains("**最终回答**"));
    assert!(rendered.contains("<font color='grey'>Total</font>"));
    assert!(rendered.contains("<font color='grey'>Input</font>"));
    assert!(rendered.contains("<font color='grey'>Output</font>"));
    assert!(rendered.contains("<font color='grey'>Reasoning</font>"));
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
        "**思考过程**  <font color='grey'>· 1 条</font>"
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
        "**执行进度**  <font color='grey'>·</font> <font color='blue'>●</font> <font color='grey'>1 项进行中</font>"
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
        "**执行进度**  <font color='grey'>·</font> <font color='green'>✓</font> <font color='grey'>1 项已完成</font>"
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
        "**执行进度**  <font color='grey'>·</font> <font color='green'>✓</font> <font color='grey'>2 项已完成</font> · <font color='red'>×</font> <font color='grey'>1 项失败</font>"
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
        Some("失败")
    );
    assert!(rendered.contains("<font color='red'>▌</font> **任务失败**"));
    assert!(rendered.contains("Agent 进程在完成任务前退出。"));
    assert!(rendered.contains("建议：请重试"));
    assert!(!rendered.contains("Authorization"));
    assert!(!rendered.contains("top-secret"));
    assert_eq!(details["tag"], "collapsible_panel");
    assert_eq!(details["expanded"], false);
    assert_eq!(
        details.pointer("/header/title/content").unwrap(),
        "**技术详情**  <font color='grey'>· 进程退出</font>"
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
    let failure_index = rendered.find("**任务失败**").unwrap();
    let answer_index = rendered.find("**部分回答**").unwrap();

    assert!(failure_index < answer_index);
    assert!(rendered.contains("<font color='blue'>▌</font> **部分回答**"));
    assert!(!rendered.contains("**最终回答**"));
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
        Some("已停止")
    );
    assert_eq!(
        card.pointer("/header/template")
            .and_then(serde_json::Value::as_str),
        Some("grey")
    );
    assert!(rendered.contains("<font color='grey'>■</font>  Run `cargo test`"));
    assert!(rendered.contains("<font color='grey'>1 项已停止</font>"));
    assert!(rendered.contains("<font color='grey'>▌</font> **任务已停止**"));
    assert!(rendered.contains("已按请求停止任务，已有输出已保留。"));
    assert!(rendered.contains("<font color='blue'>▌</font> **部分回答**"));
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
        Some("已中断")
    );
    assert_eq!(
        card.pointer("/header/template")
            .and_then(serde_json::Value::as_str),
        Some("orange")
    );
    assert!(rendered.contains("<font color='grey'>■</font>  Run `cargo test`"));
    assert!(rendered.contains("<font color='orange'>▌</font> **任务已中断**"));
    assert!(rendered.contains("Agora Node 即将退出，本次任务已中断，当前输出已保留。"));
    assert!(rendered.contains("Node 恢复后，请重新发送消息继续。"));
    assert!(rendered.contains("<font color='blue'>▌</font> **部分回答**"));
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
        Some("已完成")
    );
    let rendered = serde_json::to_string(&card).unwrap();
    assert!(rendered.contains("**思考过程**"));
    assert!(rendered.contains("> • Inspecting the channel"));
    assert!(rendered.contains("> • Checking reply delivery"));
    assert!(rendered.contains("**执行进度**"));
    assert!(rendered.contains("<font color='green'>✓</font>  Run `cargo test`"));
    assert!(rendered.contains("<font color='blue'>▌</font> **最终回答**"));
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
        Some("排队中")
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
        Some("运行中")
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
