use super::rich_message::TelegramRichMessage;
use super::telegram_api::{TelegramApi, TelegramBotCommand};
use crate::channel::{
    Channel, ChannelReply, ChannelRun, ChannelRunContext, ChannelTask, InterruptCallback, RunEvent,
};
use crate::config::TelegramChannelConfig;
use crate::i18n;
use crate::task::{ChannelTaskInput, TaskAttachment, TaskContent};
use agora_core::logger;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

const TELEGRAM_INTERRUPT_PREFIX: &str = "agora_interrupt:";
const TELEGRAM_COMMANDS: &[TelegramBotCommand<'static>] = &[
    TelegramBotCommand::new("stop", i18n::STOP_COMMAND_DESCRIPTION),
    TelegramBotCommand::new("reset", i18n::RESET_COMMAND_DESCRIPTION),
    TelegramBotCommand::new("ask", i18n::ASK_COMMAND_DESCRIPTION),
    TelegramBotCommand::new("help", i18n::HELP_DESCRIPTION),
];

pub struct TelegramChannel {
    api: TelegramApi,
    interrupts: TelegramInterruptCallbacks,
    pending: VecDeque<TelegramTask>,
    next_offset: Option<i64>,
    bot_username: Option<String>,
}

#[derive(Clone)]
pub struct TelegramRun {
    message: TelegramRichMessage,
}

struct TelegramInterruptCallbacksInner {
    next_id: AtomicU64,
    callbacks: StdMutex<HashMap<String, InterruptCallback>>,
}

#[derive(Clone)]
pub(super) struct TelegramInterruptCallbacks {
    inner: Arc<TelegramInterruptCallbacksInner>,
}

impl Default for TelegramInterruptCallbacks {
    fn default() -> Self {
        Self {
            inner: Arc::new(TelegramInterruptCallbacksInner {
                next_id: AtomicU64::new(1),
                callbacks: StdMutex::new(HashMap::new()),
            }),
        }
    }
}

impl TelegramInterruptCallbacks {
    fn register(&self, callback: InterruptCallback) -> TelegramInterruptRegistration {
        let id = format!(
            "interrupt-{}",
            self.inner.next_id.fetch_add(1, Ordering::Relaxed)
        );
        self.callbacks().insert(id.clone(), callback);
        TelegramInterruptRegistration {
            id,
            callbacks: self.clone(),
        }
    }

    fn trigger(&self, id: &str) -> bool {
        self.callbacks()
            .remove(id)
            .is_some_and(|callback| callback.trigger())
    }

    fn remove(&self, id: &str) {
        self.callbacks().remove(id);
    }

    fn callbacks(&self) -> std::sync::MutexGuard<'_, HashMap<String, InterruptCallback>> {
        self.inner
            .callbacks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(super) struct TelegramInterruptRegistration {
    id: String,
    callbacks: TelegramInterruptCallbacks,
}

impl TelegramInterruptRegistration {
    pub(super) fn callback_data(&self) -> String {
        format!("{TELEGRAM_INTERRUPT_PREFIX}{}", self.id)
    }
}

impl Drop for TelegramInterruptRegistration {
    fn drop(&mut self) {
        self.callbacks.remove(&self.id);
    }
}

impl ChannelRun for TelegramRun {
    async fn publish(&self, event: RunEvent) -> Result<()> {
        self.message.publish(event).await
    }
}

impl TelegramChannel {
    pub fn new(config: TelegramChannelConfig) -> Result<Self> {
        Ok(Self::with_api_inner(TelegramApi::new(config)?))
    }

    fn with_api_inner(api: TelegramApi) -> Self {
        Self {
            api,
            interrupts: TelegramInterruptCallbacks::default(),
            pending: VecDeque::new(),
            next_offset: None,
            bot_username: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_api(api: TelegramApi) -> Self {
        Self::with_api_inner(api)
    }

    pub(super) async fn next_task(&mut self) -> Result<TelegramTask> {
        loop {
            if let Some(task) = self.pending.pop_front() {
                return Ok(task);
            }
            self.ensure_bot_username().await?;
            let updates = self.api.get_updates(self.next_offset).await?;
            let bot_username = self.bot_username.clone().unwrap_or_default();
            for value in updates {
                let Some(update_id) = value.get("update_id").and_then(Value::as_i64) else {
                    logger::error!(
                        "telegram update ignored channel={} reason=missing_update_id",
                        self.api.name()
                    );
                    continue;
                };
                match TelegramUpdate::from_value(value) {
                    Ok(update) => {
                        debug_assert_eq!(update.update_id(), update_id);
                        if let Some(callback) = update.callback_query() {
                            let interrupt_id = callback
                                .data
                                .as_deref()
                                .and_then(|data| data.strip_prefix(TELEGRAM_INTERRUPT_PREFIX));
                            let triggered =
                                interrupt_id.is_some_and(|id| self.interrupts.trigger(id));
                            logger::info!(
                                "telegram callback received channel={} update_id={} triggered={}",
                                self.api.name(),
                                update_id,
                                triggered
                            );
                            self.answer_callback_query(callback.id.clone());
                        } else if let Some(task) = update.into_task(&bot_username) {
                            let task = self.resolve_task_image(task).await?;
                            logger::info!(
                                "telegram message received channel={} session={} message_id={} input={} attachments={}",
                                self.api.name(),
                                task.session_id(),
                                task.reply_target.message_id,
                                task.input
                                    .message()
                                    .map(TaskContent::text)
                                    .unwrap_or_default(),
                                task.input
                                    .message()
                                    .map(|content| content.attachments().len())
                                    .unwrap_or_default()
                            );
                            self.pending.push_back(task);
                        }
                    }
                    Err(err) => logger::error!(
                        "telegram update ignored channel={} update_id={} error={}",
                        self.api.name(),
                        update_id,
                        err
                    ),
                }
                self.advance_offset(update_id);
            }
        }
    }

    async fn ensure_bot_username(&mut self) -> Result<()> {
        if self.bot_username.is_some() {
            return Ok(());
        }
        logger::info!("telegram channel connecting channel={}", self.api.name());
        let username = self.api.bot_username().await?;
        self.bot_username = Some(username.clone());
        if let Err(err) = self.api.set_commands(TELEGRAM_COMMANDS).await {
            logger::error!(
                "telegram command registration failed channel={} error={}",
                self.api.name(),
                err
            );
        }
        logger::info!(
            "telegram channel connected channel={} bot=@{}",
            self.api.name(),
            username
        );
        Ok(())
    }

    async fn resolve_task_image(&self, mut task: TelegramTask) -> Result<TelegramTask> {
        let Some(file_id) = task.image_file_id.take() else {
            return Ok(task);
        };
        let image = self
            .api
            .download_file(&file_id)
            .await
            .with_context(|| format!("download telegram image failed: {file_id}"))?;
        if let ChannelTaskInput::Message(content) = &mut task.input {
            *content = std::mem::take(content).with_attachment(TaskAttachment::image(
                image.file_name,
                image.media_type,
                image.data,
            ));
        }
        Ok(task)
    }

    fn advance_offset(&mut self, update_id: i64) {
        let next = update_id.saturating_add(1);
        self.next_offset = Some(self.next_offset.map_or(next, |current| current.max(next)));
    }

    fn answer_callback_query(&self, query_id: String) {
        let api = self.api.clone();
        tokio::spawn(async move {
            if let Err(err) = api.answer_callback_query(&query_id).await {
                logger::error!(
                    "telegram callback acknowledgement failed channel={} error={}",
                    api.name(),
                    err
                );
            }
        });
    }

    pub(super) fn render_reply(reply: &ChannelReply) -> String {
        match reply {
            ChannelReply::Text(text) => text.clone(),
            ChannelReply::AgentList(agents) => {
                let mut sections = vec![format!(
                    "**{}**\n> {}",
                    i18n::AGENT_STATUS_TITLE,
                    i18n::CURRENT_CONVERSATION_ONLY
                )];
                sections.extend(agents.iter().map(Self::render_agent_status));
                sections.join("\n\n")
            }
            ChannelReply::AgentStatus(agent) => format!(
                "**{}**\n> {}\n\n{}",
                i18n::AGENT_STATUS_TITLE,
                i18n::CURRENT_CONVERSATION_ONLY,
                Self::render_agent_status(agent)
            ),
        }
    }

    fn render_agent_status(agent: &crate::channel::ChannelAgentStatus) -> String {
        let (marker, state, description) = if agent.enabled() {
            ("🟢", i18n::AGENT_ENABLED, i18n::AGENT_ENABLED_DESCRIPTION)
        } else {
            ("⚪", i18n::AGENT_DISABLED, i18n::AGENT_DISABLED_DESCRIPTION)
        };
        format!(
            "{marker} **{}** · {state}\n{description}",
            Self::escape_structural_text(agent.name())
        )
    }

    fn escape_structural_text(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
}

impl Channel for TelegramChannel {
    type Task = TelegramTask;
    type Run = TelegramRun;

    fn name(&self) -> &str {
        self.api.name()
    }

    async fn recv(&mut self) -> Result<Option<Self::Task>> {
        self.next_task().await.map(Some)
    }

    async fn open_run(&self, task: &Self::Task, context: ChannelRunContext) -> Result<Self::Run> {
        let interrupt = context
            .interrupt
            .map(|callback| self.interrupts.register(callback));
        Ok(TelegramRun {
            message: TelegramRichMessage::new(
                task.reply_target().clone(),
                context.agent.name,
                interrupt,
                self.api.clone(),
            ),
        })
    }

    async fn reply(&self, task: &Self::Task, reply: ChannelReply) -> Result<()> {
        self.api
            .send_rich_message(task.reply_target(), &Self::render_reply(&reply), None)
            .await?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TelegramReplyTarget {
    pub(super) chat_id: i64,
    pub(super) message_id: i64,
    pub(super) message_thread_id: Option<i64>,
    pub(super) is_private: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelegramTask {
    task_id: String,
    session_id: String,
    input: ChannelTaskInput,
    reply_target: TelegramReplyTarget,
    image_file_id: Option<String>,
}

impl TelegramTask {
    pub(super) fn reply_target(&self) -> &TelegramReplyTarget {
        &self.reply_target
    }
}

impl ChannelTask for TelegramTask {
    fn task_id(&self) -> &str {
        &self.task_id
    }

    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn input(&self) -> &ChannelTaskInput {
        &self.input
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct TelegramUpdate {
    update_id: i64,
    #[serde(default)]
    message: Option<TelegramMessage>,
    #[serde(default)]
    callback_query: Option<TelegramCallbackQuery>,
}

impl TelegramUpdate {
    #[cfg(test)]
    pub(super) fn from_json(payload: &str) -> Result<Self> {
        serde_json::from_str(payload).context("telegram update is not valid json")
    }

    pub(super) fn from_value(value: Value) -> Result<Self> {
        serde_json::from_value(value).context("telegram update has an invalid shape")
    }

    pub(super) fn update_id(&self) -> i64 {
        self.update_id
    }

    fn callback_query(&self) -> Option<&TelegramCallbackQuery> {
        self.callback_query.as_ref()
    }

    pub(super) fn into_task(self, bot_username: &str) -> Option<TelegramTask> {
        let message = self.message?;
        if !message.chat.is_supported() {
            return None;
        }
        let text = message.normalized_text(bot_username)?;
        let image_file_id = message.photo.last().map(|photo| photo.file_id.clone());
        let session_id = match message.message_thread_id {
            Some(thread_id) => {
                format!("chat:{}:topic:{thread_id}", message.chat.id)
            }
            None => format!("chat:{}", message.chat.id),
        };
        let reply_target = TelegramReplyTarget {
            chat_id: message.chat.id,
            message_id: message.message_id,
            message_thread_id: message.message_thread_id,
            is_private: message.chat.is_private(),
        };
        Some(TelegramTask {
            task_id: self.update_id.to_string(),
            session_id,
            input: ChannelTaskInput::Message(TaskContent::new(text)),
            reply_target,
            image_file_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct TelegramCallbackQuery {
    id: String,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct TelegramMessage {
    message_id: i64,
    #[serde(default)]
    message_thread_id: Option<i64>,
    chat: TelegramChat,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    caption: Option<String>,
    #[serde(default)]
    photo: Vec<TelegramPhotoSize>,
}

impl TelegramMessage {
    fn normalized_text(&self, bot_username: &str) -> Option<String> {
        let Some(text) = self.text.as_ref().or(self.caption.as_ref()) else {
            return (!self.photo.is_empty()).then(String::new);
        };
        if text.trim().is_empty() {
            return (!self.photo.is_empty()).then(String::new);
        }
        let command_end = text.find(char::is_whitespace).unwrap_or(text.len());
        let (command, suffix) = text.split_at(command_end);
        if !command.starts_with('/') {
            return Some(text.clone());
        }
        let Some((command, target)) = command.split_once('@') else {
            return Some(text.clone());
        };
        if !target.eq_ignore_ascii_case(bot_username.trim_start_matches('@')) {
            return None;
        }
        Some(format!("{command}{suffix}"))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct TelegramPhotoSize {
    file_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct TelegramChat {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
}

impl TelegramChat {
    fn is_private(&self) -> bool {
        self.kind == "private"
    }

    fn is_supported(&self) -> bool {
        matches!(self.kind.as_str(), "private" | "group" | "supergroup")
    }
}

#[cfg(test)]
mod tests;
