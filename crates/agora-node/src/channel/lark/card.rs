use super::LarkReplyTarget;
use super::channel::LarkInterruptRegistration;
use super::lark_api::LarkApi;
use crate::channel::{
    ChannelAgentStatus, ChannelButton, ChannelButtonStyle, ChannelReply, ChannelRun, RunEvent,
};
use crate::i18n::{self, RunStatus};
use crate::task::{OutputEvent, ProgressStatus, TokenUsage};
use agora_core::logger;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_ANSWER_BYTES: usize = 20 * 1024;
const CARD_UPDATE_INTERVAL: Duration = Duration::from_millis(400);

pub(super) struct LarkAgentCard {
    inner: Arc<LarkAgentCardInner>,
}

impl Clone for LarkAgentCard {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct LarkAgentCardInner {
    target: LarkReplyTarget,
    api: LarkApi,
    _interrupt: Option<LarkInterruptRegistration>,
    state: Mutex<LarkAgentCardState>,
}

struct LarkAgentCardState {
    token: Option<String>,
    message_id: Option<String>,
    content: LarkCardContent,
    version: u64,
    sent_version: u64,
    last_update: Option<Instant>,
    flush_scheduled: bool,
}

pub(super) struct LarkCardContent {
    agent_name: String,
    interrupt: Option<String>,
    thinking: VecDeque<String>,
    progress: VecDeque<LarkProgressEntry>,
    answer: String,
    usage: Option<TokenUsage>,
    state: LarkRunState,
}

enum LarkRunState {
    Queued { ahead: usize },
    Running,
    Completed,
    Failed(String),
    Stopped,
    Interrupted,
}

struct LarkProgressEntry {
    id: String,
    text: String,
    status: ProgressStatus,
}

pub(super) struct LarkReplyCard;

impl LarkReplyCard {
    pub(super) fn build(reply: &ChannelReply) -> Value {
        match reply {
            ChannelReply::Text(text) => Self::card(
                i18n::AGENT_STATUS_TITLE,
                i18n::CURRENT_CONVERSATION.to_string(),
                vec![json!({
                    "tag": "markdown",
                    "content": text
                })],
            ),
            ChannelReply::AgentList(agents) => Self::agent_list(agents),
            ChannelReply::AgentStatus(agent) => Self::agent_status(agent),
        }
    }

    fn agent_list(agents: &[ChannelAgentStatus]) -> Value {
        let mut elements = Vec::new();
        for (index, agent) in agents.iter().enumerate() {
            if index > 0 {
                elements.push(json!({ "tag": "hr" }));
            }
            elements.push(Self::agent_row(agent));
        }
        if !elements.is_empty() {
            elements.push(json!({ "tag": "hr" }));
        }
        elements.push(json!({
            "tag": "markdown",
            "content": format!(
                "<font color='grey'>{}</font>",
                i18n::CURRENT_CONVERSATION_ONLY
            )
        }));
        Self::card(
            i18n::AGENT_STATUS_TITLE,
            i18n::agent_count(agents.len()),
            elements,
        )
    }

    fn agent_status(agent: &ChannelAgentStatus) -> Value {
        let (color, state, _) = Self::status_text(agent.enabled());
        Self::card(
            i18n::AGENT_STATUS_TITLE,
            i18n::CURRENT_CONVERSATION.to_string(),
            vec![json!({
                "tag": "column_set",
                "flex_mode": "none",
                "columns": [
                    {
                        "tag": "column",
                        "width": "weighted",
                        "weight": 1,
                        "vertical_align": "center",
                        "elements": [{
                            "tag": "markdown",
                            "content": format!(
                                "**{}**\n<font color='grey'>{}</font>",
                                agent.name(),
                                i18n::MESSAGE_DELIVERY_STATUS
                            )
                        }]
                    },
                    {
                        "tag": "column",
                        "width": "auto",
                        "vertical_align": "center",
                        "elements": [{
                            "tag": "markdown",
                            "content": format!("<font color='{color}'>● {state}</font>"),
                            "text_align": "right"
                        }]
                    }
                ]
            })],
        )
    }

    fn agent_row(agent: &ChannelAgentStatus) -> Value {
        let (color, state, description) = Self::status_text(agent.enabled());
        let mut columns = vec![json!({
            "tag": "column",
            "width": "weighted",
            "weight": 1,
            "vertical_align": "center",
            "elements": [{
                "tag": "markdown",
                "content": format!(
                    "**{}**\n<font color='{color}'>{state}</font> · {description}",
                    agent.name()
                )
            }]
        })];
        if let Some(button) = agent.button() {
            columns.push(json!({
                "tag": "column",
                "width": "auto",
                "vertical_align": "center",
                "elements": [Self::button(button)]
            }));
        }
        json!({
            "tag": "column_set",
            "flex_mode": "none",
            "horizontal_spacing": "default",
            "columns": columns
        })
    }

    fn button(button: &ChannelButton) -> Value {
        let button_type = match button.style() {
            ChannelButtonStyle::Default => "default",
            ChannelButtonStyle::Primary => "primary",
            ChannelButtonStyle::Danger => "danger",
        };
        json!({
            "tag": "button",
            "text": {
                "tag": "plain_text",
                "content": button.text()
            },
            "type": button_type,
            "size": "medium",
            "behaviors": [{
                "type": "callback",
                "value": {
                    "agora_command": button.command()
                }
            }]
        })
    }

    fn status_text(enabled: bool) -> (&'static str, &'static str, &'static str) {
        if enabled {
            (
                "green",
                i18n::AGENT_ENABLED,
                i18n::AGENT_ENABLED_DESCRIPTION,
            )
        } else {
            (
                "grey",
                i18n::AGENT_DISABLED,
                i18n::AGENT_DISABLED_DESCRIPTION,
            )
        }
    }

    fn card(title: &str, subtitle: String, elements: Vec<Value>) -> Value {
        json!({
            "schema": "2.0",
            "config": {
                "update_multi": true,
                "summary": {
                    "content": title
                }
            },
            "header": {
                "template": "blue",
                "title": {
                    "tag": "plain_text",
                    "content": title
                },
                "subtitle": {
                    "tag": "plain_text",
                    "content": subtitle
                }
            },
            "body": {
                "elements": elements
            }
        })
    }
}

impl LarkCardContent {
    pub(super) fn new(agent_name: String) -> Self {
        Self {
            agent_name,
            interrupt: None,
            thinking: VecDeque::new(),
            progress: VecDeque::new(),
            answer: String::new(),
            usage: None,
            state: LarkRunState::Running,
        }
    }

    pub(super) fn with_interrupt(agent_name: String, interrupt: Option<String>) -> Self {
        Self {
            interrupt,
            ..Self::new(agent_name)
        }
    }

    pub(super) fn apply_output(&mut self, event: OutputEvent) {
        match event {
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
                    .push_front(LarkProgressEntry { id, text, status });
            }
            OutputEvent::Answer { text } => self.answer.push_str(&text),
            OutputEvent::Usage(usage) => self.usage = Some(usage),
        }
    }

    pub(super) fn complete(&mut self) {
        self.state = LarkRunState::Completed;
    }

    pub(super) fn queue(&mut self, ahead: usize) {
        self.state = LarkRunState::Queued { ahead };
    }

    pub(super) fn start(&mut self) {
        self.state = LarkRunState::Running;
    }

    pub(super) fn fail(&mut self, message: String) {
        self.state = LarkRunState::Failed(message);
    }

    pub(super) fn stop(&mut self) {
        for entry in &mut self.progress {
            if entry.status == ProgressStatus::Running {
                entry.status = ProgressStatus::Stopped;
            }
        }
        self.state = LarkRunState::Stopped;
    }

    pub(super) fn interrupt(&mut self) {
        for entry in &mut self.progress {
            if entry.status == ProgressStatus::Running {
                entry.status = ProgressStatus::Stopped;
            }
        }
        self.state = LarkRunState::Interrupted;
    }

    pub(super) fn build_card(&self) -> Value {
        let (template, status, status_color) = match &self.state {
            LarkRunState::Queued { .. } => ("grey", i18n::run_status(RunStatus::Queued), "grey"),
            LarkRunState::Running => ("blue", i18n::run_status(RunStatus::Running), "blue"),
            LarkRunState::Completed => ("green", i18n::run_status(RunStatus::Completed), "green"),
            LarkRunState::Failed(_) => ("red", i18n::run_status(RunStatus::Failed), "red"),
            LarkRunState::Stopped => ("grey", i18n::run_status(RunStatus::Stopped), "grey"),
            LarkRunState::Interrupted => {
                ("orange", i18n::run_status(RunStatus::Interrupted), "orange")
            }
        };
        let failure_view = match &self.state {
            LarkRunState::Failed(message) => Some(Self::failure_view(message)),
            _ => None,
        };
        let finished = !matches!(
            &self.state,
            LarkRunState::Queued { .. } | LarkRunState::Running
        );
        let mut elements = Vec::new();

        if !self.thinking.is_empty() {
            let thinking = self
                .thinking
                .iter()
                .flat_map(|entry| entry.lines())
                .map(|line| format!("> • {}", line.trim()))
                .collect::<Vec<_>>()
                .join("\n");
            let count = self.thinking.len();
            elements.push(Self::collapsible_panel(
                format!(
                    "**{}**  <font color='grey'>· {}</font>",
                    i18n::THINKING_TITLE,
                    i18n::update_count(count)
                ),
                false,
                thinking,
            ));
        }

        if !self.progress.is_empty() {
            let progress = self
                .progress
                .iter()
                .map(|entry| {
                    let marker = match entry.status {
                        ProgressStatus::Running => "<font color='blue'>●</font>",
                        ProgressStatus::Completed => "<font color='green'>✓</font>",
                        ProgressStatus::Failed => "<font color='red'>×</font>",
                        ProgressStatus::Stopped => "<font color='grey'>■</font>",
                    };
                    format!("{marker}  {}", entry.text)
                })
                .collect::<Vec<_>>()
                .join("\n");
            elements.push(Self::collapsible_panel(
                format!(
                    "**{}**  <font color='grey'>·</font> {}",
                    i18n::PROGRESS_TITLE,
                    self.progress_summary()
                ),
                !finished,
                progress,
            ));
        }

        if let Some((category, summary)) = failure_view {
            if !elements.is_empty() {
                elements.push(json!({ "tag": "hr" }));
            }
            elements.push(json!({
                "tag": "markdown",
                "content": format!(
                    "<font color='red'>▌</font> **{}**\n{}\n\n<font color='grey'>{summary}</font>\n<font color='grey'>{}</font>",
                    i18n::RUN_FAILED_TITLE,
                    i18n::AGENT_RUN_FAILED,
                    i18n::RETRY_ADVICE
                )
            }));
            elements.push(Self::collapsible_panel(
                format!(
                    "**{}**  <font color='grey'>· {category}</font>",
                    i18n::TECHNICAL_DETAILS_TITLE
                ),
                false,
                i18n::ERROR_WRITTEN_TO_LOG.to_string(),
            ));
        }

        if matches!(&self.state, LarkRunState::Stopped) {
            if !elements.is_empty() {
                elements.push(json!({ "tag": "hr" }));
            }
            elements.push(json!({
                "tag": "markdown",
                "content": format!(
                    "<font color='grey'>▌</font> **{}**\n{}",
                    i18n::RUN_STOPPED_TITLE,
                    i18n::RUN_STOPPED_BODY
                )
            }));
        }

        if matches!(&self.state, LarkRunState::Interrupted) {
            if !elements.is_empty() {
                elements.push(json!({ "tag": "hr" }));
            }
            elements.push(json!({
                "tag": "markdown",
                "content": format!(
                    "<font color='orange'>▌</font> **{}**\n{}",
                    i18n::RUN_INTERRUPTED_TITLE,
                    i18n::RUN_INTERRUPTED_BODY
                )
            }));
        }

        if !self.answer.is_empty() {
            if !elements.is_empty() {
                elements.push(json!({ "tag": "hr" }));
            }
            let title = if matches!(
                &self.state,
                LarkRunState::Failed(_) | LarkRunState::Stopped | LarkRunState::Interrupted
            ) {
                i18n::PARTIAL_ANSWER_TITLE
            } else {
                i18n::FINAL_ANSWER_TITLE
            };
            elements.push(json!({
                "tag": "markdown",
                "content": format!(
                    "<font color='blue'>▌</font> **{title}**\n{}",
                    Self::truncate_answer(&self.answer)
                )
            }));
        }

        if finished && let Some(usage) = self.usage {
            if !elements.is_empty() {
                elements.push(json!({ "tag": "hr" }));
            }
            elements.push(Self::usage_element(usage));
        }

        if elements.is_empty() && !finished {
            elements.push(json!({
                "tag": "markdown",
                "content": match &self.state {
                    LarkRunState::Queued { ahead } => {
                        format!("> {}", i18n::queued_message(*ahead))
                    }
                    _ => format!("> {}", i18n::WAITING_FOR_AGENT),
                }
            }));
        }

        if !finished && self.interrupt.is_some() {
            if !elements.is_empty() {
                elements.push(json!({ "tag": "hr" }));
            }
            if let Some(action_row) = self.action_row() {
                elements.push(action_row);
            }
        }

        let mut card = json!({
            "schema": "2.0",
            "config": {
                "update_multi": true,
                "summary": {
                    "content": format!("{}: {}", self.agent_name, status)
                }
            },
            "header": {
                "template": template,
                "title": {
                    "tag": "plain_text",
                    "content": self.agent_name
                },
                "text_tag_list": [{
                    "tag": "text_tag",
                    "text": {
                        "tag": "plain_text",
                        "content": status
                    },
                    "color": status_color
                }]
            }
        });
        if !elements.is_empty() {
            card["body"] = json!({ "elements": elements });
        }
        card
    }

    fn action_row(&self) -> Option<Value> {
        let interrupt = self.interrupt.as_ref()?;
        Some(json!({
            "tag": "column_set",
            "flex_mode": "none",
            "horizontal_align": "right",
            "columns": [json!({
                "tag": "column",
                "width": "auto",
                "elements": [{
                    "tag": "button",
                    "text": {
                        "tag": "plain_text",
                        "content": i18n::STOP_TASK
                    },
                    "type": "danger",
                    "size": "medium",
                    "behaviors": [{
                        "type": "callback",
                        "value": {
                            "agora_interrupt": interrupt
                        }
                    }]
                }]
            })]
        }))
    }

    fn collapsible_panel(title: String, expanded: bool, content: String) -> Value {
        json!({
            "tag": "collapsible_panel",
            "expanded": expanded,
            "background_color": "grey-50",
            "header": {
                "title": {
                    "tag": "markdown",
                    "content": title
                },
                "vertical_align": "center",
                "padding": "8px 12px 8px 12px",
                "icon": {
                    "tag": "standard_icon",
                    "token": "down-small-ccm_outlined",
                    "size": "16px 16px"
                },
                "icon_position": "right",
                "icon_expanded_angle": -180
            },
            "border": {
                "color": "grey-200",
                "corner_radius": "8px"
            },
            "vertical_spacing": "6px",
            "padding": "2px 12px 10px 12px",
            "elements": [{
                "tag": "markdown",
                "content": content
            }]
        })
    }

    fn progress_summary(&self) -> String {
        let completed = self
            .progress
            .iter()
            .filter(|entry| entry.status == ProgressStatus::Completed)
            .count();
        let running = self
            .progress
            .iter()
            .filter(|entry| entry.status == ProgressStatus::Running)
            .count();
        let failed = self
            .progress
            .iter()
            .filter(|entry| entry.status == ProgressStatus::Failed)
            .count();
        let stopped = self
            .progress
            .iter()
            .filter(|entry| entry.status == ProgressStatus::Stopped)
            .count();

        let mut parts = Vec::new();
        if completed > 0 {
            parts.push(format!(
                "<font color='green'>✓</font> <font color='grey'>{}</font>",
                i18n::progress_count(ProgressStatus::Completed, completed)
            ));
        }
        if running > 0 {
            parts.push(format!(
                "<font color='blue'>●</font> <font color='grey'>{}</font>",
                i18n::progress_count(ProgressStatus::Running, running)
            ));
        }
        if failed > 0 {
            parts.push(format!(
                "<font color='red'>×</font> <font color='grey'>{}</font>",
                i18n::progress_count(ProgressStatus::Failed, failed)
            ));
        }
        if stopped > 0 {
            parts.push(format!(
                "<font color='grey'>■</font> <font color='grey'>{}</font>",
                i18n::progress_count(ProgressStatus::Stopped, stopped)
            ));
        }
        parts.join(" · ")
    }

    fn failure_view(message: &str) -> (&'static str, &'static str) {
        let copy = i18n::failure_copy(message);
        (copy.category, copy.summary)
    }

    fn usage_element(usage: TokenUsage) -> Value {
        let total_tokens = usage.input_tokens.saturating_add(usage.output_tokens);
        json!({
            "tag": "column_set",
            "flex_mode": "none",
            "horizontal_spacing": "small",
            "horizontal_align": "left",
            "columns": [
                Self::usage_column(i18n::TOTAL, total_tokens, i18n::TOKENS),
                Self::usage_column(
                    i18n::INPUT,
                    usage.input_tokens,
                    &i18n::cached_tokens(Self::format_tokens(usage.cached_input_tokens)),
                ),
                Self::usage_column(i18n::OUTPUT, usage.output_tokens, i18n::TOKENS),
                Self::usage_column(
                    i18n::REASONING,
                    usage.reasoning_output_tokens,
                    i18n::REASONING_DETAIL,
                ),
            ]
        })
    }

    fn usage_column(label: &str, tokens: u64, detail: &str) -> Value {
        json!({
            "tag": "column",
            "width": "weighted",
            "weight": 1,
            "vertical_align": "top",
            "vertical_spacing": "0px",
            "elements": [{
                "tag": "markdown",
                "content": format!(
                    "<font color='grey'>{label}</font>\n**{}**\n<font color='grey'>{detail}</font>",
                    Self::format_tokens(tokens),
                ),
                "text_align": "center",
                "text_size": "notation",
            }]
        })
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

    fn truncate_answer(answer: &str) -> String {
        if answer.len() <= MAX_ANSWER_BYTES {
            return answer.to_string();
        }
        let marker = i18n::OUTPUT_TRUNCATED;
        let budget = MAX_ANSWER_BYTES.saturating_sub(marker.len());
        let mut start = answer.len().saturating_sub(budget);
        while !answer.is_char_boundary(start) {
            start += 1;
        }
        format!("{}{}", marker, &answer[start..])
    }
}

impl LarkAgentCard {
    pub(super) fn new(
        target: LarkReplyTarget,
        agent_name: String,
        interrupt: Option<LarkInterruptRegistration>,
        api: LarkApi,
    ) -> Self {
        let interrupt_id = interrupt
            .as_ref()
            .map(LarkInterruptRegistration::id)
            .map(str::to_string);
        Self {
            inner: Arc::new(LarkAgentCardInner {
                target,
                api,
                _interrupt: interrupt,
                state: Mutex::new(LarkAgentCardState {
                    token: None,
                    message_id: None,
                    content: LarkCardContent::with_interrupt(agent_name, interrupt_id),
                    version: 0,
                    sent_version: 0,
                    last_update: None,
                    flush_scheduled: false,
                }),
            }),
        }
    }

    async fn publish_event(&self, event: RunEvent) -> Result<()> {
        let flush_now = {
            let mut state = self.inner.state.lock().await;
            let flush_now = match event {
                RunEvent::Queued { ahead } => {
                    state.content.queue(ahead);
                    true
                }
                RunEvent::Started { .. } => {
                    state.content.start();
                    true
                }
                RunEvent::Output(event) => {
                    state.content.apply_output(event);
                    false
                }
                RunEvent::Completed { .. } => {
                    state.content.complete();
                    true
                }
                RunEvent::Failed { message } => {
                    state.content.fail(message);
                    true
                }
                RunEvent::Stopped => {
                    state.content.stop();
                    true
                }
                RunEvent::Interrupted => {
                    state.content.interrupt();
                    true
                }
            };
            state.version = state.version.saturating_add(1);
            if !flush_now && !state.flush_scheduled {
                state.flush_scheduled = true;
                let delay = state
                    .last_update
                    .map(|last_update| CARD_UPDATE_INTERVAL.saturating_sub(last_update.elapsed()))
                    .unwrap_or_default();
                self.schedule_flush(delay);
            }
            flush_now
        };

        if flush_now {
            self.flush_latest().await
        } else {
            Ok(())
        }
    }

    fn schedule_flush(&self, delay: Duration) {
        let card = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            {
                let mut state = card.inner.state.lock().await;
                state.flush_scheduled = false;
            }
            if let Err(err) = card.flush_latest().await {
                logger::error!(
                    "lark card update failed source_message_id={} error={}",
                    card.inner.target.message_id,
                    err
                );
            }
        });
    }

    async fn flush_latest(&self) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        if state.version == state.sent_version {
            return Ok(());
        }
        if state.token.is_none() {
            state.token = Some(self.inner.api.tenant_access_token().await?);
        }
        let token = state
            .token
            .clone()
            .ok_or_else(|| anyhow!("lark tenant token initialization failed"))?;
        let card = state.content.build_card();
        let version = state.version;
        if let Some(message_id) = state.message_id.clone() {
            self.inner
                .api
                .patch_card(&token, &message_id, &card)
                .await?;
        } else {
            state.message_id = Some(
                self.inner
                    .api
                    .reply_card(&token, &self.inner.target, &card)
                    .await?,
            );
        }
        state.sent_version = version;
        state.last_update = Some(Instant::now());
        Ok(())
    }
}

impl ChannelRun for LarkAgentCard {
    async fn publish(&self, event: RunEvent) -> Result<()> {
        self.publish_event(event).await
    }
}
