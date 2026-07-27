use super::*;

#[test]
fn telegram_rich_message_puts_all_thinking_before_the_answer_and_usage() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Inspecting <the project>".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Checking the tests".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Completed,
    }));
    content.apply(RunEvent::Output(OutputEvent::Answer {
        text: "**All checks passed.**\n\n- tests\n- clippy".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Usage(TokenUsage {
        input_tokens: 42_800,
        cached_input_tokens: 31_600,
        output_tokens: 3_200,
        reasoning_output_tokens: 1_900,
    })));
    content.apply(RunEvent::Completed { exit_code: 0 });

    assert_eq!(
        content.render(false),
        "**✦ 思考过程 · 2 条**\n\n\
         <details><summary>◈ 推理节点 · 02</summary>\n\n\
         Checking the tests\n\n\
         </details>\n\n\
         <details><summary>◈ 推理节点 · 01</summary>\n\n\
         Inspecting &lt;the project&gt;\n\n\
         </details>\n\n\
         <details><summary>◇ 执行进度 · ✓ 1 项已完成</summary>\n\n\
         - ✓ Run `cargo test`\n\n\
         </details>\n\n\
         **All checks passed.**\n\n- tests\n- clippy\n\n\
         > **◈ TOKEN USAGE** · 46.0K tokens · Input 42.8K · 31.6K cached · Output 3.2K · Reasoning 1.9K"
    );
}

#[test]
fn telegram_rich_message_shows_all_thinking_while_running() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Inspecting the project".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Checking the tests".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Running,
    }));

    assert_eq!(
        content.render(false),
        "**✦ 思考过程 · 2 条**\n\n\
         <details><summary>◈ 推理节点 · 02</summary>\n\n\
         Checking the tests\n\n\
         </details>\n\n\
         <details><summary>◈ 推理节点 · 01</summary>\n\n\
         Inspecting the project\n\n\
         </details>\n\n\
         <details open><summary>◇ 执行进度 · ● 1 项进行中</summary>\n\n\
         - ● Run `cargo test`\n\n\
         </details>"
    );
    assert_eq!(
        content.render(true),
        "<tg-thinking>Checking the tests\n\n\
         Inspecting the project\n\n\
         ● Run `cargo test`</tg-thinking>"
    );
}

#[test]
fn telegram_rich_message_updates_the_latest_progress_marker() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    for (status, marker) in [
        (ProgressStatus::Completed, "✓"),
        (ProgressStatus::Failed, "×"),
        (ProgressStatus::Stopped, "■"),
    ] {
        content.apply(RunEvent::Output(OutputEvent::Progress {
            id: "command-1".to_string(),
            text: "Run tests".to_string(),
            status,
        }));
        assert!(
            content
                .render(false)
                .contains(&format!("{marker} Run tests"))
        );
    }
}

#[test]
fn telegram_rich_message_keeps_all_progress_after_completion_with_latest_first() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run tests".to_string(),
        status: ProgressStatus::Running,
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-2".to_string(),
        text: "Check formatting".to_string(),
        status: ProgressStatus::Completed,
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run tests".to_string(),
        status: ProgressStatus::Failed,
    }));
    content.apply(RunEvent::Completed { exit_code: 0 });

    let rendered = content.render(false);

    assert_eq!(rendered.matches("Run tests").count(), 1);
    assert_eq!(rendered.matches("Check formatting").count(), 1);
    assert!(rendered.contains("× Run tests"));
    assert!(rendered.contains("✓ Check formatting"));
    assert!(rendered.find("Run tests") < rendered.find("Check formatting"));
}

#[test]
fn telegram_rich_message_renders_latest_thinking_first() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "First update".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Latest update".to_string(),
    }));

    let rendered = content.render(false);

    assert!(rendered.find("Latest update") < rendered.find("First update"));
}

#[test]
fn telegram_rich_message_marks_running_progress_stopped_when_the_run_stops() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run tests".to_string(),
        status: ProgressStatus::Running,
    }));

    content.apply(RunEvent::Stopped);

    assert!(content.render(false).contains("■ Run tests"));
}

#[test]
fn telegram_rich_message_splits_oversized_content_without_losing_output() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Answer {
        text: "</pre><h1>& oversized answer\n".repeat(2_000),
    }));
    content.apply(RunEvent::Output(OutputEvent::Usage(TokenUsage {
        input_tokens: 1_500,
        cached_input_tokens: 1_000,
        output_tokens: 500,
        reasoning_output_tokens: 250,
    })));
    content.apply(RunEvent::Completed { exit_code: 0 });

    let messages = content.render_messages(false);

    assert!(messages.len() > 2);
    assert!(messages.iter().all(|message| {
        message.chars().count() <= 32_768
            && message
                .lines()
                .count()
                .saturating_add(message.matches('<').count())
                <= 400
    }));
    let rendered = messages.join("\n");
    assert!(!rendered.contains(i18n::OUTPUT_TRUNCATED.trim()));
    assert_eq!(
        rendered
            .matches("&lt;/pre&gt;&lt;h1&gt;&amp; oversized answer")
            .count(),
        2_000
    );
    assert!(messages.last().unwrap().ends_with(
        "> **◈ TOKEN USAGE** · 2.0K tokens · Input 1.5K · 1.0K cached · Output 500 · Reasoning 250"
    ));
}

#[test]
fn telegram_rich_message_uses_the_same_safe_fallback_while_running() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Reviewing <changes>".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Answer {
        text: "streaming answer\n".repeat(3_000),
    }));

    let rendered = content.render(true);

    assert!(rendered.contains(i18n::OUTPUT_TRUNCATED.trim()));
    assert!(rendered.contains("<tg-thinking>Reviewing &lt;changes&gt;</tg-thinking>"));
    assert_eq!(rendered.matches("<pre>").count(), 1);
    assert_eq!(rendered.matches("</pre>").count(), 1);
}

#[test]
fn telegram_rich_message_uses_native_thinking_only_for_active_drafts() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());

    assert_eq!(
        content.render(true),
        format!("<tg-thinking>{}</tg-thinking>", i18n::WAITING_FOR_AGENT)
    );
    assert_eq!(
        content.render(false),
        format!("> **codex-dev** · {}", i18n::WAITING_FOR_AGENT)
    );

    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Reviewing the change".to_string(),
    }));
    assert!(
        content
            .render(true)
            .contains("<tg-thinking>Reviewing the change</tg-thinking>")
    );
    assert!(!content.render(false).contains("<tg-thinking>"));

    content.apply(RunEvent::Output(OutputEvent::Usage(TokenUsage {
        input_tokens: 800,
        cached_input_tokens: 600,
        output_tokens: 200,
        reasoning_output_tokens: 100,
    })));
    content.apply(RunEvent::Completed { exit_code: 0 });
    assert!(!content.render(true).contains("<tg-thinking>"));
    assert_eq!(
        content.render(false),
        "**✦ 思考过程 · 1 条**\n\n\
         <details><summary>◈ 推理节点 · 01</summary>\n\n\
         Reviewing the change\n\n</details>\n\n**已完成**\n\n\
         > **◈ TOKEN USAGE** · 1.0K tokens · Input 800 · 600 cached · Output 200 · Reasoning 100"
    );
}

#[test]
fn telegram_rich_message_renders_queue_stop_and_interruption_states() {
    let mut queued = TelegramRichContent::new("codex-dev".to_string());
    queued.apply(RunEvent::Queued { ahead: 2 });
    assert_eq!(queued.render(false), "> 正在排队，前面还有 2 个任务...");

    let mut stopped = TelegramRichContent::new("codex-dev".to_string());
    stopped.apply(RunEvent::Output(OutputEvent::Answer {
        text: "Partial work".to_string(),
    }));
    stopped.apply(RunEvent::Stopped);
    let stopped = stopped.render(false);
    assert!(stopped.starts_with("**任务已停止**"));
    assert!(stopped.contains("**部分回答**\n\nPartial work"));
    assert!(!stopped.contains("codex-dev"));

    let mut interrupted = TelegramRichContent::new("codex-dev".to_string());
    interrupted.apply(RunEvent::Interrupted);
    let interrupted = interrupted.render(false);
    assert!(interrupted.starts_with("**任务已中断**"));
    assert!(interrupted.contains("Agora Node 即将退出"));
    assert!(!interrupted.contains("codex-dev"));
}

#[test]
fn telegram_rich_message_hides_raw_failure_details() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Failed {
        message: "secret backend process exited with token=abc".to_string(),
    });

    let rendered = content.render(false);

    assert!(rendered.starts_with("**任务失败**"));
    assert!(rendered.contains("Agent 进程在完成任务前退出。"));
    assert!(!rendered.contains("codex-dev"));
    assert!(!rendered.contains("token=abc"));
}
