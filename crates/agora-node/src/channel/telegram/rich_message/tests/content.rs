use super::*;

#[test]
fn telegram_rich_message_groups_thinking_and_commands_into_ordered_phases() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Inspecting <the project>".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Checking the tests".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::CommandExecution {
        id: "command-1".to_string(),
        command: "cargo test".to_string(),
        status: ProgressStatus::Completed,
        exit_code: Some(0),
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

    let rendered = content.render(false);

    assert!(
        rendered.starts_with("<details><summary>✦ 任务过程 · 2 个阶段 · ✓ 1 项已完成</summary>")
    );
    assert!(rendered.contains("**01 · 思考过程**\n\n> ✦ Inspecting &lt;the project&gt;"));
    assert!(rendered.contains("**02 · 思考过程**\n\n> ✦ Checking the tests"));
    assert!(rendered.contains(
        "<pre><code class=\"language-bash\"># SHELL · ✓ exit 0\n$ cargo test</code></pre>"
    ));
    assert!(rendered.find("Inspecting") < rendered.find("Checking"));
    assert!(rendered.find("Checking") < rendered.find("# SHELL"));
    assert!(rendered.find("</details>") < rendered.find("**All checks passed.**"));
    assert!(rendered.ends_with(
        "> **◈ TOKEN USAGE** · 46.0K tokens · Input 42.8K · 31.6K cached · Output 3.2K · Reasoning 1.9K"
    ));
}

#[test]
fn telegram_rich_message_expands_the_process_while_running() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Inspecting the project".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Checking the tests".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::CommandExecution {
        id: "command-1".to_string(),
        command: "cargo test".to_string(),
        status: ProgressStatus::Running,
        exit_code: None,
    }));

    let rendered = content.render(false);
    assert!(
        rendered
            .starts_with("<details open><summary>✦ 任务过程 · 2 个阶段 · ● 1 项进行中</summary>")
    );
    assert!(rendered.contains(
        "<pre><code class=\"language-bash\"># SHELL · ● Running\n$ cargo test</code></pre>"
    ));
    assert_eq!(
        content.render(true),
        "<tg-thinking>Checking the tests\n\n● $ cargo test</tg-thinking>"
    );
}

#[test]
fn telegram_rich_message_preserves_the_complete_agent_command() {
    let command = format!(
        "/bin/bash -lc \"pwd && {} && echo end-of-command\"",
        "rg --files ".repeat(40)
    );
    assert!(command.chars().count() > 400);
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::CommandExecution {
        id: "command-1".to_string(),
        command: command.clone(),
        status: ProgressStatus::Running,
        exit_code: None,
    }));

    let rendered = content.render(false);
    let escaped_command = TelegramRichContent::escape_structural_text(&command);

    assert!(rendered.contains("<pre><code class=\"language-bash\"># SHELL · ● Running\n$ "));
    assert!(rendered.contains(&escaped_command));
    assert!(rendered.contains("end-of-command"));
    assert!(!rendered.contains("..."));
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
fn telegram_rich_message_keeps_progress_in_its_original_phase() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Plan the checks".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run tests".to_string(),
        status: ProgressStatus::Running,
    }));
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Review the result".to_string(),
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
    assert!(rendered.find("Plan the checks") < rendered.find("Run tests"));
    assert!(rendered.find("Run tests") < rendered.find("Review the result"));
    assert!(rendered.find("Review the result") < rendered.find("Check formatting"));
}

#[test]
fn telegram_rich_message_renders_latest_thinking_last() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "First update".to_string(),
    }));
    content.apply(RunEvent::Output(OutputEvent::Thinking {
        text: "Latest update".to_string(),
    }));

    let rendered = content.render(false);

    assert!(rendered.find("First update") < rendered.find("Latest update"));
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
fn telegram_rich_message_omits_oldest_process_phases_before_latest_output() {
    let mut content = TelegramRichContent::new("codex-dev".to_string());
    for index in 0..500 {
        content.apply(RunEvent::Output(OutputEvent::Thinking {
            text: format!("phase-{index:03} {}", "detail ".repeat(20)),
        }));
    }
    content.apply(RunEvent::Output(OutputEvent::Answer {
        text: "Final answer remains visible".to_string(),
    }));
    content.apply(RunEvent::Completed { exit_code: 0 });

    let rendered = content.render(false);

    assert!(TelegramRichContent::within_limits(&rendered));
    assert!(rendered.contains("已省略"));
    assert!(!rendered.contains("phase-000"));
    assert!(rendered.contains("phase-499"));
    assert!(rendered.contains("Final answer remains visible"));
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
    let rendered = content.render(false);
    assert!(rendered.starts_with("<details><summary>✦ 任务过程 · 1 个阶段</summary>"));
    assert!(rendered.contains("**01 · 思考过程**\n\n> ✦ Reviewing the change"));
    assert!(rendered.contains("</details>\n\n**已完成**"));
    assert!(rendered.ends_with(
        "> **◈ TOKEN USAGE** · 1.0K tokens · Input 800 · 600 cached · Output 200 · Reasoning 100"
    ));
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
