use super::*;

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
