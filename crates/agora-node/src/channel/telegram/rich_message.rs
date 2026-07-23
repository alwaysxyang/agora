use super::channel::TelegramReplyTarget;
use super::telegram_api::TelegramApi;
use crate::channel::{ChannelRun, RunEvent};
use crate::i18n::{self, RunStatus};
use crate::task::{OutputEvent, ProgressStatus, TokenUsage};
use agora_core::logger;
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const TELEGRAM_UPDATE_INTERVAL: Duration = Duration::from_millis(400);
const TELEGRAM_DRAFT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub(super) struct TelegramRichMessage {
    inner: Arc<TelegramRichMessageInner>,
}

struct TelegramRichMessageInner {
    target: TelegramReplyTarget,
    api: TelegramApi,
    timing: TelegramRichTiming,
    state: Mutex<TelegramRichMessageState>,
}

struct TelegramRichMessageState {
    content: TelegramRichContent,
    draft_id: i64,
    message_id: Option<i64>,
    version: u64,
    sent_version: u64,
    last_update: Option<Instant>,
    flush_scheduled: bool,
    heartbeat_started: bool,
    terminal_sent: bool,
}

#[derive(Clone, Copy)]
pub(super) struct TelegramRichTiming {
    update_interval: Duration,
    heartbeat_interval: Duration,
}

impl TelegramRichTiming {
    #[cfg(test)]
    pub(super) fn new(update_interval: Duration, heartbeat_interval: Duration) -> Self {
        Self {
            update_interval,
            heartbeat_interval,
        }
    }
}

impl Default for TelegramRichTiming {
    fn default() -> Self {
        Self {
            update_interval: TELEGRAM_UPDATE_INTERVAL,
            heartbeat_interval: TELEGRAM_DRAFT_HEARTBEAT_INTERVAL,
        }
    }
}

impl TelegramRichMessage {
    pub(super) fn new(target: TelegramReplyTarget, agent_name: String, api: TelegramApi) -> Self {
        Self::with_timing_inner(target, agent_name, api, TelegramRichTiming::default())
    }

    fn with_timing_inner(
        target: TelegramReplyTarget,
        agent_name: String,
        api: TelegramApi,
        timing: TelegramRichTiming,
    ) -> Self {
        let draft_id = api.allocate_draft_id();
        Self {
            inner: Arc::new(TelegramRichMessageInner {
                target,
                api,
                timing,
                state: Mutex::new(TelegramRichMessageState {
                    content: TelegramRichContent::new(agent_name),
                    draft_id,
                    message_id: None,
                    version: 0,
                    sent_version: 0,
                    last_update: None,
                    flush_scheduled: false,
                    heartbeat_started: false,
                    terminal_sent: false,
                }),
            }),
        }
    }

    #[cfg(test)]
    pub(super) fn with_timing(
        target: TelegramReplyTarget,
        agent_name: String,
        api: TelegramApi,
        timing: TelegramRichTiming,
    ) -> Self {
        Self::with_timing_inner(target, agent_name, api, timing)
    }

    async fn publish_event(&self, event: RunEvent) -> Result<()> {
        let flush_now = {
            let mut state = self.inner.state.lock().await;
            if state.content.is_terminal() {
                return Ok(());
            }
            let flush_now = !matches!(event, RunEvent::Output(_));
            state.content.apply(event);
            state.version = state.version.saturating_add(1);
            if !flush_now && !state.flush_scheduled {
                state.flush_scheduled = true;
                let delay = state
                    .last_update
                    .map(|last_update| {
                        self.inner
                            .timing
                            .update_interval
                            .saturating_sub(last_update.elapsed())
                    })
                    .unwrap_or_default();
                self.schedule_flush(delay);
            }
            flush_now
        };

        if flush_now {
            self.flush_latest(false).await
        } else {
            Ok(())
        }
    }

    fn schedule_flush(&self, delay: Duration) {
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let message = TelegramRichMessage { inner };
            {
                let mut state = message.inner.state.lock().await;
                state.flush_scheduled = false;
            }
            if let Err(err) = message.flush_latest(false).await {
                logger::error!(
                    "telegram rich message update failed chat_id={} error={}",
                    message.inner.target.chat_id,
                    err
                );
            }
        });
    }

    fn schedule_heartbeat(&self) {
        let weak = Arc::downgrade(&self.inner);
        let interval = self.inner.timing.heartbeat_interval;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                let message = TelegramRichMessage { inner };
                let active = {
                    let state = message.inner.state.lock().await;
                    message.inner.target.is_private && !state.content.is_terminal()
                };
                if !active {
                    return;
                }
                if let Err(err) = message.flush_latest(true).await {
                    logger::error!(
                        "telegram rich draft refresh failed chat_id={} error={}",
                        message.inner.target.chat_id,
                        err
                    );
                }
            }
        });
    }

    async fn flush_latest(&self, force_private_draft: bool) -> Result<()> {
        let start_heartbeat = {
            let mut state = self.inner.state.lock().await;
            let terminal = state.content.is_terminal();
            if terminal && state.terminal_sent {
                return Ok(());
            }
            if !terminal && !force_private_draft && state.version == state.sent_version {
                return Ok(());
            }

            let markdown = state
                .content
                .render(self.inner.target.is_private && !terminal);
            if self.inner.target.is_private {
                if terminal {
                    state.message_id = Some(
                        self.inner
                            .api
                            .send_rich_message(&self.inner.target, &markdown)
                            .await?,
                    );
                    state.terminal_sent = true;
                } else {
                    self.inner
                        .api
                        .send_rich_message_draft(&self.inner.target, state.draft_id, &markdown)
                        .await?;
                }
            } else if let Some(message_id) = state.message_id {
                self.inner
                    .api
                    .edit_rich_message(self.inner.target.chat_id, message_id, &markdown)
                    .await?;
                if terminal {
                    state.terminal_sent = true;
                }
            } else {
                state.message_id = Some(
                    self.inner
                        .api
                        .send_rich_message(&self.inner.target, &markdown)
                        .await?,
                );
                if terminal {
                    state.terminal_sent = true;
                }
            }

            state.sent_version = state.version;
            state.last_update = Some(Instant::now());
            let start_heartbeat =
                self.inner.target.is_private && !terminal && !state.heartbeat_started;
            if start_heartbeat {
                state.heartbeat_started = true;
            }
            start_heartbeat
        };
        if start_heartbeat {
            self.schedule_heartbeat();
        }
        Ok(())
    }
}

impl ChannelRun for TelegramRichMessage {
    async fn publish(&self, event: RunEvent) -> Result<()> {
        self.publish_event(event).await
    }
}

pub(super) struct TelegramRichContent {
    agent_name: String,
    thinking: VecDeque<String>,
    progress: VecDeque<TelegramProgressEntry>,
    answer: String,
    usage: Option<TokenUsage>,
    state: TelegramRunState,
}

enum TelegramRunState {
    Queued { ahead: usize },
    Running,
    Completed,
    Failed(String),
    Stopped,
    Interrupted,
}

struct TelegramProgressEntry {
    id: String,
    text: String,
    status: ProgressStatus,
}

impl TelegramRichContent {
    pub(super) fn new(agent_name: String) -> Self {
        Self {
            agent_name,
            thinking: VecDeque::new(),
            progress: VecDeque::new(),
            answer: String::new(),
            usage: None,
            state: TelegramRunState::Running,
        }
    }

    pub(super) fn apply(&mut self, event: RunEvent) {
        if self.is_terminal() {
            return;
        }
        match event {
            RunEvent::Queued { ahead } => self.state = TelegramRunState::Queued { ahead },
            RunEvent::Started { .. } => self.state = TelegramRunState::Running,
            RunEvent::Output(output) => self.apply_output(output),
            RunEvent::Completed { .. } => self.state = TelegramRunState::Completed,
            RunEvent::Failed { message } => self.state = TelegramRunState::Failed(message),
            RunEvent::Stopped => {
                self.stop_running_progress();
                self.state = TelegramRunState::Stopped;
            }
            RunEvent::Interrupted => {
                self.stop_running_progress();
                self.state = TelegramRunState::Interrupted;
            }
        }
    }

    pub(super) fn render(&self, draft: bool) -> String {
        let mut sections = vec![format!(
            "## {} · {}",
            Self::escape_structural_text(&self.agent_name),
            self.status()
        )];

        if draft && !self.is_terminal() {
            let thinking = self
                .thinking
                .front()
                .map(String::as_str)
                .unwrap_or(i18n::WAITING_FOR_AGENT);
            sections.push(format!(
                "<tg-thinking>{}</tg-thinking>",
                Self::escape_structural_text(thinking)
            ));
        }
        if !self.thinking.is_empty() {
            sections.push(self.thinking_section());
        }
        if !self.progress.is_empty() {
            sections.push(self.progress_section());
        }

        match &self.state {
            TelegramRunState::Queued { ahead }
                if self.thinking.is_empty() && self.progress.is_empty() =>
            {
                sections.push(format!("> {}", i18n::queued_message(*ahead)));
            }
            TelegramRunState::Running
                if self.thinking.is_empty()
                    && self.progress.is_empty()
                    && self.answer.is_empty() =>
            {
                sections.push(format!("> {}", i18n::WAITING_FOR_AGENT));
            }
            TelegramRunState::Failed(message) => sections.push(Self::failure_section(message)),
            TelegramRunState::Stopped => sections.push(format!(
                "## {}\n\n{}",
                i18n::RUN_STOPPED_TITLE,
                i18n::RUN_STOPPED_BODY
            )),
            TelegramRunState::Interrupted => sections.push(format!(
                "## {}\n\n{}",
                i18n::RUN_INTERRUPTED_TITLE,
                i18n::RUN_INTERRUPTED_BODY
            )),
            TelegramRunState::Queued { .. }
            | TelegramRunState::Running
            | TelegramRunState::Completed => {}
        }

        if !self.answer.is_empty() {
            let title = if matches!(
                self.state,
                TelegramRunState::Failed(_)
                    | TelegramRunState::Stopped
                    | TelegramRunState::Interrupted
            ) {
                i18n::PARTIAL_ANSWER_TITLE
            } else {
                i18n::FINAL_ANSWER_TITLE
            };
            sections.push(format!("## {title}\n\n{}", self.answer));
        }
        if self.is_terminal()
            && let Some(usage) = self.usage
        {
            sections.push(Self::usage_section(usage));
        }
        sections.join("\n\n")
    }

    pub(super) fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            TelegramRunState::Completed
                | TelegramRunState::Failed(_)
                | TelegramRunState::Stopped
                | TelegramRunState::Interrupted
        )
    }

    fn apply_output(&mut self, output: OutputEvent) {
        match output {
            OutputEvent::Thinking { text } => {
                if !text.trim().is_empty() {
                    self.thinking.push_front(text);
                }
            }
            OutputEvent::Progress { id, text, status } => {
                if let Some(index) = self.progress.iter().position(|entry| entry.id == id) {
                    self.progress.remove(index);
                }
                self.progress
                    .push_front(TelegramProgressEntry { id, text, status });
            }
            OutputEvent::Answer { text } => self.answer.push_str(&text),
            OutputEvent::Usage(usage) => self.usage = Some(usage),
        }
    }

    fn stop_running_progress(&mut self) {
        for entry in &mut self.progress {
            if entry.status == ProgressStatus::Running {
                entry.status = ProgressStatus::Stopped;
            }
        }
    }

    fn status(&self) -> &'static str {
        match self.state {
            TelegramRunState::Queued { .. } => i18n::run_status(RunStatus::Queued),
            TelegramRunState::Running => i18n::run_status(RunStatus::Running),
            TelegramRunState::Completed => i18n::run_status(RunStatus::Completed),
            TelegramRunState::Failed(_) => i18n::run_status(RunStatus::Failed),
            TelegramRunState::Stopped => i18n::run_status(RunStatus::Stopped),
            TelegramRunState::Interrupted => i18n::run_status(RunStatus::Interrupted),
        }
    }

    fn thinking_section(&self) -> String {
        let count = self.thinking.len();
        let body = self
            .thinking
            .iter()
            .map(|text| Self::list_item("", text))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "{}<summary>{} · {}</summary>\n\n{body}\n\n</details>",
            self.details_opening(),
            i18n::THINKING_TITLE,
            i18n::update_count(count)
        )
    }

    fn progress_section(&self) -> String {
        let body = self
            .progress
            .iter()
            .map(|entry| Self::list_item(Self::progress_marker(entry.status), &entry.text))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "{}<summary>{} · {}</summary>\n\n{body}\n\n</details>",
            self.details_opening(),
            i18n::PROGRESS_TITLE,
            self.progress_summary()
        )
    }

    fn details_opening(&self) -> &'static str {
        if self.is_terminal() {
            "<details>"
        } else {
            "<details open>"
        }
    }

    fn progress_summary(&self) -> String {
        let mut completed = 0;
        let mut running = 0;
        let mut failed = 0;
        let mut stopped = 0;
        for entry in &self.progress {
            match entry.status {
                ProgressStatus::Completed => completed += 1,
                ProgressStatus::Running => running += 1,
                ProgressStatus::Failed => failed += 1,
                ProgressStatus::Stopped => stopped += 1,
            }
        }
        let mut parts = Vec::new();
        if completed > 0 {
            parts.push(format!(
                "✓ {}",
                i18n::progress_count(ProgressStatus::Completed, completed)
            ));
        }
        if running > 0 {
            parts.push(format!(
                "● {}",
                i18n::progress_count(ProgressStatus::Running, running)
            ));
        }
        if failed > 0 {
            parts.push(format!(
                "× {}",
                i18n::progress_count(ProgressStatus::Failed, failed)
            ));
        }
        if stopped > 0 {
            parts.push(format!(
                "■ {}",
                i18n::progress_count(ProgressStatus::Stopped, stopped)
            ));
        }
        parts.join(" · ")
    }

    fn progress_marker(status: ProgressStatus) -> &'static str {
        match status {
            ProgressStatus::Running => "●",
            ProgressStatus::Completed => "✓",
            ProgressStatus::Failed => "×",
            ProgressStatus::Stopped => "■",
        }
    }

    fn list_item(marker: &str, text: &str) -> String {
        let escaped = text
            .lines()
            .map(Self::escape_structural_text)
            .collect::<Vec<_>>()
            .join("\n  ");
        if marker.is_empty() {
            format!("- {escaped}")
        } else {
            format!("- {marker} {escaped}")
        }
    }

    fn failure_section(message: &str) -> String {
        let copy = i18n::failure_copy(message);
        format!(
            "## {}\n\n{}\n\n{}",
            i18n::RUN_FAILED_TITLE,
            copy.summary,
            i18n::RETRY_ADVICE
        )
    }

    fn usage_section(usage: TokenUsage) -> String {
        let total = usage.input_tokens.saturating_add(usage.output_tokens);
        format!(
            "---\n\n{} **{}** · {} **{}** · {} · {} **{}** · {} **{}**",
            i18n::TOTAL,
            Self::format_tokens(total),
            i18n::INPUT,
            Self::format_tokens(usage.input_tokens),
            i18n::cached_tokens(Self::format_tokens(usage.cached_input_tokens)),
            i18n::OUTPUT,
            Self::format_tokens(usage.output_tokens),
            i18n::REASONING,
            Self::format_tokens(usage.reasoning_output_tokens)
        )
    }

    fn format_tokens(tokens: u64) -> String {
        if tokens < 1_000 {
            tokens.to_string()
        } else if tokens < 1_000_000 {
            format!("{:.1}K", tokens as f64 / 1_000.0)
        } else {
            format!("{:.1}M", tokens as f64 / 1_000_000.0)
        }
    }

    fn escape_structural_text(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
}
