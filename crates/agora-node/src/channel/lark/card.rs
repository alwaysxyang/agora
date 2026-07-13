use super::{LarkApi, LarkReplyTarget};
use crate::channel::{ChannelRun, RunEvent};
use crate::output::{OutputEvent, ProgressStatus};
use agora_core::logger;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_THINKING_ENTRIES: usize = 3;
const MAX_PROGRESS_ENTRIES: usize = 5;
const MAX_ANSWER_BYTES: usize = 20 * 1024;
const CARD_UPDATE_INTERVAL: Duration = Duration::from_millis(400);

pub struct LarkAgentCard {
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

pub(crate) struct LarkCardContent {
    agent_name: String,
    thinking: VecDeque<String>,
    progress: VecDeque<LarkProgressEntry>,
    answer: String,
    failure: Option<String>,
    finished: bool,
}

struct LarkProgressEntry {
    id: String,
    text: String,
    status: ProgressStatus,
}

impl LarkCardContent {
    pub(crate) fn new(agent_name: String) -> Self {
        Self {
            agent_name,
            thinking: VecDeque::new(),
            progress: VecDeque::new(),
            answer: String::new(),
            failure: None,
            finished: false,
        }
    }

    pub(crate) fn apply_output(&mut self, event: OutputEvent) {
        match event {
            OutputEvent::Thinking { text } => {
                if !text.trim().is_empty() {
                    self.thinking.push_back(text);
                    while self.thinking.len() > MAX_THINKING_ENTRIES {
                        self.thinking.pop_front();
                    }
                }
            }
            OutputEvent::Progress { id, text, status } => {
                if let Some(index) = self.progress.iter().position(|entry| entry.id == id) {
                    self.progress.remove(index);
                }
                self.progress
                    .push_back(LarkProgressEntry { id, text, status });
                while self.progress.len() > MAX_PROGRESS_ENTRIES {
                    self.progress.pop_front();
                }
            }
            OutputEvent::Answer { text } => self.answer.push_str(&text),
        }
    }

    pub(crate) fn complete(&mut self) {
        self.finished = true;
    }

    pub(crate) fn fail(&mut self, message: String) {
        self.finished = true;
        self.failure = Some(message);
    }

    pub(crate) fn build_card(&self) -> Value {
        let (template, status, status_color) = if self.failure.is_some() {
            ("red", "Failed", "red")
        } else if self.finished {
            ("green", "Completed", "green")
        } else {
            ("blue", "Running", "blue")
        };
        let mut elements = Vec::new();

        if !self.thinking.is_empty() {
            let thinking = self
                .thinking
                .iter()
                .flat_map(|entry| entry.lines())
                .map(|line| format!("> {}", line.trim()))
                .collect::<Vec<_>>()
                .join("\n");
            elements.push(json!({
                "tag": "markdown",
                "content": format!("**Thinking**\n{thinking}")
            }));
        }

        if !self.progress.is_empty() {
            let progress = self
                .progress
                .iter()
                .map(|entry| {
                    let status = match entry.status {
                        ProgressStatus::Running => "Running",
                        ProgressStatus::Completed => "Done",
                        ProgressStatus::Failed => "Failed",
                    };
                    format!("- **{status}**  {}", entry.text)
                })
                .collect::<Vec<_>>()
                .join("\n");
            elements.push(json!({
                "tag": "markdown",
                "content": format!("**Progress**\n{progress}")
            }));
        }

        if !self.answer.is_empty() {
            if !elements.is_empty() {
                elements.push(json!({ "tag": "hr" }));
            }
            elements.push(json!({
                "tag": "markdown",
                "content": format!("**Final answer**\n{}", Self::truncate_answer(&self.answer))
            }));
        }

        if let Some(message) = &self.failure {
            if !elements.is_empty() {
                elements.push(json!({ "tag": "hr" }));
            }
            elements.push(json!({
                "tag": "markdown",
                "content": format!("**Failure**\n{}", message)
            }));
        }

        let mut card = json!({
            "config": {
                "update_multi": true,
                "wide_screen_mode": true,
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
            card["elements"] = Value::Array(elements);
        }
        card
    }

    fn truncate_answer(answer: &str) -> String {
        if answer.len() <= MAX_ANSWER_BYTES {
            return answer.to_string();
        }
        let marker = "[output truncated]\n\n";
        let budget = MAX_ANSWER_BYTES.saturating_sub(marker.len());
        let mut start = answer.len().saturating_sub(budget);
        while !answer.is_char_boundary(start) {
            start += 1;
        }
        format!("{}{}", marker, &answer[start..])
    }
}

impl LarkAgentCard {
    pub(crate) fn new(target: LarkReplyTarget, agent_name: String, api: LarkApi) -> Self {
        Self {
            inner: Arc::new(LarkAgentCardInner {
                target,
                api,
                state: Mutex::new(LarkAgentCardState {
                    token: None,
                    message_id: None,
                    content: LarkCardContent::new(agent_name),
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
                RunEvent::Started { .. } => true,
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
