use super::channel::{TelegramInterruptRegistration, TelegramReplyTarget};
use super::telegram_api::TelegramApi;
use crate::channel::{ChannelRun, RunEvent};
use crate::i18n::{self, RunStatus};
use crate::task::{OutputEvent, ProgressStatus, TokenUsage};
use agora_core::logger;
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const TELEGRAM_UPDATE_INTERVAL: Duration = Duration::from_millis(400);
const TELEGRAM_DRAFT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
const TELEGRAM_DELIVERY_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const TELEGRAM_DELIVERY_MAX_FAILURES: u32 = 3;
const TELEGRAM_RICH_MESSAGE_MAX_CHARS: usize = 32_768;
const TELEGRAM_RICH_MESSAGE_MAX_STRUCTURE_POINTS: usize = 400;

#[derive(Clone)]
pub(super) struct TelegramRichMessage {
    inner: Arc<TelegramRichMessageInner>,
}

struct TelegramRichMessageInner {
    target: TelegramReplyTarget,
    interrupt: Option<TelegramInterruptRegistration>,
    api: TelegramApi,
    timing: TelegramRichTiming,
    state: Mutex<TelegramRichMessageState>,
    delivery_lock: Mutex<()>,
}

struct TelegramRichMessageState {
    content: TelegramRichContent,
    draft_id: i64,
    message_ids: Vec<i64>,
    version: u64,
    sent_version: u64,
    last_update: Option<Instant>,
    flush_scheduled: bool,
    heartbeat_started: bool,
    terminal_sent: bool,
    delivery_failures: u32,
    retry_scheduled: bool,
}

#[derive(Clone, Copy)]
pub(super) struct TelegramRichTiming {
    update_interval: Duration,
    heartbeat_interval: Duration,
    retry_interval: Duration,
}

impl TelegramRichTiming {
    #[cfg(test)]
    pub(super) fn new(update_interval: Duration, heartbeat_interval: Duration) -> Self {
        Self {
            update_interval,
            heartbeat_interval,
            retry_interval: update_interval,
        }
    }
}

impl Default for TelegramRichTiming {
    fn default() -> Self {
        Self {
            update_interval: TELEGRAM_UPDATE_INTERVAL,
            heartbeat_interval: TELEGRAM_DRAFT_HEARTBEAT_INTERVAL,
            retry_interval: TELEGRAM_DELIVERY_RETRY_INTERVAL,
        }
    }
}

impl TelegramRichMessage {
    pub(super) fn new(
        target: TelegramReplyTarget,
        agent_name: String,
        interrupt: Option<TelegramInterruptRegistration>,
        api: TelegramApi,
    ) -> Self {
        Self::with_timing_inner(
            target,
            agent_name,
            interrupt,
            api,
            TelegramRichTiming::default(),
        )
    }

    fn with_timing_inner(
        target: TelegramReplyTarget,
        agent_name: String,
        interrupt: Option<TelegramInterruptRegistration>,
        api: TelegramApi,
        timing: TelegramRichTiming,
    ) -> Self {
        let draft_id = api.allocate_draft_id();
        Self {
            inner: Arc::new(TelegramRichMessageInner {
                target,
                interrupt,
                api,
                timing,
                state: Mutex::new(TelegramRichMessageState {
                    content: TelegramRichContent::new(agent_name),
                    draft_id,
                    message_ids: Vec::new(),
                    version: 0,
                    sent_version: 0,
                    last_update: None,
                    flush_scheduled: false,
                    heartbeat_started: false,
                    terminal_sent: false,
                    delivery_failures: 0,
                    retry_scheduled: false,
                }),
                delivery_lock: Mutex::new(()),
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
        Self::with_timing_inner(target, agent_name, None, api, timing)
    }

    async fn publish_event(&self, event: RunEvent) -> Result<()> {
        let flush_now = {
            let mut state = self.inner.state.lock().await;
            if state.content.is_terminal() {
                if state.terminal_sent {
                    return Ok(());
                }
                true
            } else {
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
            }
        };

        if flush_now {
            self.schedule_immediate_flush();
        }
        Ok(())
    }

    fn schedule_immediate_flush(&self) {
        let message = self.clone();
        tokio::spawn(async move {
            if let Err(err) = message.flush_latest(false).await {
                message.handle_flush_failure("publish", err).await;
            }
        });
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
                message.handle_flush_failure("update", err).await;
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
                    message.handle_flush_failure("draft refresh", err).await;
                }
            }
        });
    }

    async fn flush_latest(&self, force_private_draft: bool) -> Result<()> {
        let _delivery = self.inner.delivery_lock.lock().await;
        let TelegramPendingFlush {
            version,
            messages,
            action,
            terminal,
            callback_data,
        } = {
            let state = self.inner.state.lock().await;
            let terminal = state.content.is_terminal();
            if terminal && state.terminal_sent {
                return Ok(());
            }
            if !terminal && !force_private_draft && state.version == state.sent_version {
                return Ok(());
            }

            let callback_data = (!terminal)
                .then(|| {
                    self.inner
                        .interrupt
                        .as_ref()
                        .map(TelegramInterruptRegistration::callback_data)
                })
                .flatten();
            let action = if self.inner.target.is_private {
                if terminal {
                    state
                        .message_ids
                        .first()
                        .copied()
                        .map(|message_id| TelegramFlushAction::Edit { message_id })
                        .unwrap_or(TelegramFlushAction::Send)
                } else if callback_data.is_some() {
                    state
                        .message_ids
                        .first()
                        .copied()
                        .map(|message_id| TelegramFlushAction::Edit { message_id })
                        .unwrap_or(TelegramFlushAction::Send)
                } else {
                    TelegramFlushAction::Draft {
                        draft_id: state.draft_id,
                    }
                }
            } else if let Some(message_id) = state.message_ids.first().copied() {
                TelegramFlushAction::Edit { message_id }
            } else {
                TelegramFlushAction::Send
            };
            let draft = matches!(action, TelegramFlushAction::Draft { .. });
            TelegramPendingFlush {
                version: state.version,
                messages: state.content.render_messages(draft),
                action,
                terminal,
                callback_data,
            }
        };

        let primary = messages
            .first()
            .expect("telegram rich content must render at least one message");
        match action {
            TelegramFlushAction::Draft { draft_id } => {
                debug_assert_eq!(messages.len(), 1);
                self.inner
                    .api
                    .send_rich_message_draft(&self.inner.target, draft_id, primary)
                    .await?;
            }
            TelegramFlushAction::Send => {
                let message_id = self
                    .inner
                    .api
                    .send_rich_message(&self.inner.target, primary, callback_data.as_deref())
                    .await?;
                self.remember_message_id(0, message_id).await;
            }
            TelegramFlushAction::Edit { message_id } => {
                self.inner
                    .api
                    .edit_rich_message(
                        self.inner.target.chat_id,
                        message_id,
                        primary,
                        callback_data.as_deref(),
                    )
                    .await?;
            }
        }

        for (index, markdown) in messages.iter().enumerate().skip(1) {
            let message_id = {
                let state = self.inner.state.lock().await;
                state.message_ids.get(index).copied()
            };
            if let Some(message_id) = message_id {
                self.inner
                    .api
                    .edit_rich_message(self.inner.target.chat_id, message_id, markdown, None)
                    .await?;
            } else {
                let message_id = self
                    .inner
                    .api
                    .send_rich_message(&self.inner.target, markdown, None)
                    .await?;
                self.remember_message_id(index, message_id).await;
            }
        }

        let start_heartbeat = {
            let mut state = self.inner.state.lock().await;
            if terminal {
                state.terminal_sent = true;
            }
            state.sent_version = state.sent_version.max(version);
            state.last_update = Some(Instant::now());
            state.delivery_failures = 0;
            let start_heartbeat = self.inner.target.is_private
                && self.inner.interrupt.is_none()
                && !state.content.is_terminal()
                && !state.heartbeat_started;
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

    async fn remember_message_id(&self, index: usize, message_id: i64) {
        let mut state = self.inner.state.lock().await;
        if let Some(existing) = state.message_ids.get_mut(index) {
            *existing = message_id;
        } else {
            debug_assert_eq!(state.message_ids.len(), index);
            state.message_ids.push(message_id);
        }
    }

    async fn handle_flush_failure(&self, operation: &str, err: anyhow::Error) {
        let retry = {
            let mut state = self.inner.state.lock().await;
            let pending = if state.content.is_terminal() {
                !state.terminal_sent
            } else {
                state.version != state.sent_version
            };
            if !pending {
                None
            } else if !state.retry_scheduled {
                state.delivery_failures = state.delivery_failures.saturating_add(1);
                if state.delivery_failures > TELEGRAM_DELIVERY_MAX_FAILURES {
                    None
                } else {
                    state.retry_scheduled = true;
                    let multiplier = 1_u32 << state.delivery_failures.saturating_sub(1).min(3);
                    Some(self.inner.timing.retry_interval.saturating_mul(multiplier))
                }
            } else {
                None
            }
        };
        logger::error!(
            "telegram rich message {} failed chat_id={} retry_scheduled={} error={}",
            operation,
            self.inner.target.chat_id,
            retry.is_some(),
            err
        );
        if let Some(delay) = retry {
            self.schedule_retry(delay);
        }
    }

    fn schedule_retry(&self, delay: Duration) {
        let message = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            {
                let mut state = message.inner.state.lock().await;
                state.retry_scheduled = false;
            }
            if let Err(err) = message.flush_latest(false).await {
                message.handle_flush_failure("retry", err).await;
            }
        });
    }
}

enum TelegramFlushAction {
    Draft { draft_id: i64 },
    Send,
    Edit { message_id: i64 },
}

struct TelegramPendingFlush {
    version: u64,
    messages: Vec<String>,
    action: TelegramFlushAction,
    terminal: bool,
    callback_data: Option<String>,
}

impl ChannelRun for TelegramRichMessage {
    async fn publish(&self, event: RunEvent) -> Result<()> {
        self.publish_event(event).await
    }
}

pub(super) struct TelegramRichContent {
    agent_name: String,
    thinking: Vec<String>,
    latest_progress: Option<String>,
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

impl TelegramRichContent {
    pub(super) fn new(agent_name: String) -> Self {
        Self {
            agent_name,
            thinking: Vec::new(),
            latest_progress: None,
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
            RunEvent::Stopped => self.state = TelegramRunState::Stopped,
            RunEvent::Interrupted => self.state = TelegramRunState::Interrupted,
        }
    }

    #[cfg(test)]
    pub(super) fn render(&self, draft: bool) -> String {
        let rendered = self.render_full(draft);
        if Self::within_limits(&rendered) {
            rendered
        } else {
            self.render_truncated(draft)
        }
    }

    pub(super) fn render_messages(&self, draft: bool) -> Vec<String> {
        let sections = self.render_sections(draft);
        let rendered = sections.join("\n\n");
        if Self::within_limits(&rendered) {
            vec![rendered]
        } else if self.is_terminal() && !draft {
            Self::split_sections(sections)
        } else {
            vec![self.render_truncated(draft)]
        }
    }

    #[cfg(test)]
    fn render_full(&self, draft: bool) -> String {
        self.render_sections(draft).join("\n\n")
    }

    fn render_sections(&self, draft: bool) -> Vec<String> {
        let mut sections = Vec::new();
        if !draft || self.is_terminal() {
            sections.extend(self.thinking_sections());
        }
        if let Some(section) = self.terminal_state_section() {
            sections.push(section);
        }
        if let Some(section) = self.active_state_section(draft, true) {
            sections.push(section);
        }

        if !self.answer.is_empty() {
            if self.has_partial_answer() {
                sections.push(format!(
                    "**{}**\n\n{}",
                    i18n::PARTIAL_ANSWER_TITLE,
                    self.answer
                ));
            } else {
                sections.push(self.answer.clone());
            }
        }
        if self.is_terminal()
            && let Some(usage) = self.usage
        {
            sections.push(Self::usage_section(usage));
        }
        sections
    }

    fn split_sections(sections: Vec<String>) -> Vec<String> {
        let mut messages = Vec::new();
        let mut current = String::new();
        for section in sections {
            if !Self::within_limits(&section) {
                if !current.is_empty() {
                    messages.push(std::mem::take(&mut current));
                }
                messages.extend(Self::safe_section_chunks(&section));
                continue;
            }

            if current.is_empty() {
                current = section;
                continue;
            }
            let candidate = format!("{current}\n\n{section}");
            if Self::within_limits(&candidate) {
                current = candidate;
            } else {
                messages.push(std::mem::replace(&mut current, section));
            }
        }
        if !current.is_empty() {
            messages.push(current);
        }
        messages
    }

    fn safe_section_chunks(section: &str) -> Vec<String> {
        const OPENING: &str = "<pre>";
        const CLOSING: &str = "</pre>";

        let character_budget = TELEGRAM_RICH_MESSAGE_MAX_CHARS
            .saturating_sub(OPENING.chars().count())
            .saturating_sub(CLOSING.chars().count());
        let line_budget = TELEGRAM_RICH_MESSAGE_MAX_STRUCTURE_POINTS.saturating_sub(2);
        let mut chunks = Vec::new();
        let mut escaped = String::new();
        let mut character_count = 0_usize;
        let mut line_count = 1_usize;

        for character in section.chars() {
            let mut encoded = [0_u8; 4];
            let escaped_character = match character {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                _ => character.encode_utf8(&mut encoded),
            };
            let width = escaped_character.chars().count();
            let lines = usize::from(character == '\n');
            if !escaped.is_empty()
                && (character_count.saturating_add(width) > character_budget
                    || line_count.saturating_add(lines) > line_budget)
            {
                chunks.push(format!("{OPENING}{escaped}{CLOSING}"));
                escaped.clear();
                character_count = 0;
                line_count = 1;
            }
            escaped.push_str(escaped_character);
            character_count += width;
            line_count += lines;
        }
        if !escaped.is_empty() {
            chunks.push(format!("{OPENING}{escaped}{CLOSING}"));
        }
        chunks
    }

    fn within_limits(rendered: &str) -> bool {
        // Each Markdown line or HTML tag can introduce a rich block. Staying below
        // this conservative combined budget leaves room under Telegram's block cap.
        rendered.chars().count() <= TELEGRAM_RICH_MESSAGE_MAX_CHARS
            && rendered
                .lines()
                .count()
                .saturating_add(rendered.matches('<').count())
                <= TELEGRAM_RICH_MESSAGE_MAX_STRUCTURE_POINTS
    }

    fn render_truncated(&self, draft: bool) -> String {
        let mut sections = vec![format!("> {}", i18n::OUTPUT_TRUNCATED.trim())];
        if let Some(section) = self.active_state_section(draft, false) {
            sections.push(section);
        }
        if let Some(section) = self.terminal_state_section() {
            sections.push(section);
        }
        let usage = if self.is_terminal() {
            self.usage.map(Self::usage_section)
        } else {
            None
        };

        if self.answer.is_empty() {
            if let Some(usage) = usage {
                sections.push(usage);
            }
            return sections.join("\n\n");
        }

        let answer_heading = if self.has_partial_answer() {
            format!("**{}**\n\n", i18n::PARTIAL_ANSWER_TITLE)
        } else {
            String::new()
        };
        let prefix = format!("{}\n\n{answer_heading}<pre>", sections.join("\n\n"));
        let closing = usage
            .map(|usage| format!("</pre>\n\n{usage}"))
            .unwrap_or_else(|| "</pre>".to_string());
        let answer_budget = TELEGRAM_RICH_MESSAGE_MAX_CHARS
            .saturating_sub(prefix.chars().count())
            .saturating_sub(closing.chars().count());
        let answer = Self::escape_tail(&self.answer, answer_budget);
        format!("{prefix}{answer}{closing}")
    }

    fn active_state_section(&self, draft: bool, cumulative_thinking: bool) -> Option<String> {
        match &self.state {
            TelegramRunState::Queued { ahead } => {
                Some(format!("> {}", i18n::queued_message(*ahead)))
            }
            TelegramRunState::Running => {
                if draft {
                    let activity = self.draft_activity(cumulative_thinking);
                    Some(format!("<tg-thinking>{activity}</tg-thinking>"))
                } else if let Some(progress) = &self.latest_progress {
                    Some(format!(
                        "> **{}** · {}",
                        Self::escape_structural_text(&self.agent_name),
                        Self::escape_structural_text(progress)
                    ))
                } else if cumulative_thinking && !self.thinking.is_empty() {
                    None
                } else {
                    let activity = self
                        .thinking
                        .last()
                        .map(String::as_str)
                        .unwrap_or(i18n::WAITING_FOR_AGENT);
                    Some(format!(
                        "> **{}** · {}",
                        Self::escape_structural_text(&self.agent_name),
                        Self::escape_structural_text(activity)
                    ))
                }
            }
            TelegramRunState::Completed if self.answer.is_empty() => {
                Some(format!("**{}**", i18n::run_status(RunStatus::Completed)))
            }
            TelegramRunState::Completed
            | TelegramRunState::Failed(_)
            | TelegramRunState::Stopped
            | TelegramRunState::Interrupted => None,
        }
    }

    fn terminal_state_section(&self) -> Option<String> {
        match &self.state {
            TelegramRunState::Failed(message) => Some(Self::failure_section(message)),
            TelegramRunState::Stopped => Some(format!(
                "**{}**\n\n{}",
                i18n::RUN_STOPPED_TITLE,
                i18n::RUN_STOPPED_BODY
            )),
            TelegramRunState::Interrupted => Some(format!(
                "**{}**\n\n{}",
                i18n::RUN_INTERRUPTED_TITLE,
                i18n::RUN_INTERRUPTED_BODY
            )),
            TelegramRunState::Queued { .. }
            | TelegramRunState::Running
            | TelegramRunState::Completed => None,
        }
    }

    fn has_partial_answer(&self) -> bool {
        matches!(
            self.state,
            TelegramRunState::Failed(_) | TelegramRunState::Stopped | TelegramRunState::Interrupted
        )
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
                    self.thinking.push(text);
                    self.latest_progress = None;
                }
            }
            OutputEvent::Progress { text, status, .. } => {
                self.latest_progress = Some(format!("{} {text}", Self::progress_marker(status)));
            }
            OutputEvent::Answer { text } => self.answer.push_str(&text),
            OutputEvent::Usage(usage) => self.usage = Some(usage),
        }
    }

    fn progress_marker(status: ProgressStatus) -> &'static str {
        match status {
            ProgressStatus::Running => "●",
            ProgressStatus::Completed => "✓",
            ProgressStatus::Failed => "×",
            ProgressStatus::Stopped => "■",
        }
    }

    fn draft_activity(&self, cumulative_thinking: bool) -> String {
        let mut activity = if cumulative_thinking {
            self.thinking
                .iter()
                .map(|text| Self::escape_structural_text(text))
                .collect::<Vec<_>>()
        } else {
            self.thinking
                .last()
                .map(|text| vec![Self::escape_structural_text(text)])
                .unwrap_or_default()
        };
        if let Some(progress) = &self.latest_progress {
            activity.push(Self::escape_structural_text(progress));
        }
        if activity.is_empty() {
            Self::escape_structural_text(i18n::WAITING_FOR_AGENT)
        } else {
            activity.join("\n\n")
        }
    }

    fn thinking_sections(&self) -> Vec<String> {
        if self.thinking.is_empty() {
            return Vec::new();
        }
        let mut sections = vec![format!(
            "**✦ {} · {}**",
            i18n::THINKING_TITLE,
            i18n::update_count(self.thinking.len())
        )];
        sections.extend(self.thinking.iter().enumerate().map(|(index, text)| {
            format!(
                "<details><summary>◈ 推理节点 · {:02}</summary>\n\n{}\n\n</details>",
                index + 1,
                Self::escape_structural_text(text)
            )
        }));
        sections
    }

    fn usage_section(usage: TokenUsage) -> String {
        let total = usage.input_tokens.saturating_add(usage.output_tokens);
        format!(
            "> **◈ TOKEN USAGE** · {} {} · {} {} · {} · {} {} · {} {}",
            Self::format_tokens(total),
            i18n::TOKENS,
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

    fn failure_section(message: &str) -> String {
        let copy = i18n::failure_copy(message);
        format!(
            "**{}**\n\n{}\n\n{}",
            i18n::RUN_FAILED_TITLE,
            copy.summary,
            i18n::RETRY_ADVICE
        )
    }

    fn escape_structural_text(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn escape_tail(text: &str, budget: usize) -> String {
        let mut start = text.len();
        let mut escaped_chars = 0_usize;
        for (index, character) in text.char_indices().rev() {
            let width = match character {
                '&' => "&amp;".chars().count(),
                '<' => "&lt;".chars().count(),
                '>' => "&gt;".chars().count(),
                _ => 1,
            };
            if escaped_chars.saturating_add(width) > budget {
                break;
            }
            escaped_chars += width;
            start = index;
        }
        Self::escape_structural_text(&text[start..])
    }
}
