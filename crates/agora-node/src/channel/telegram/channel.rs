use super::rich_message::TelegramRichMessage;
use super::telegram_api::TelegramApi;
use crate::channel::{Channel, ChannelReply, ChannelRun, ChannelRunContext, ChannelTask, RunEvent};
use crate::config::TelegramChannelConfig;
use crate::task::TaskContent;
use agora_core::logger;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::VecDeque;

pub struct TelegramChannel {
    api: TelegramApi,
    pending: VecDeque<TelegramTask>,
    next_offset: Option<i64>,
    bot_username: Option<String>,
}

#[derive(Clone)]
pub struct TelegramRun {
    message: TelegramRichMessage,
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
                self.advance_offset(update_id);
                match TelegramUpdate::from_value(value) {
                    Ok(update) => {
                        debug_assert_eq!(update.update_id(), update_id);
                        if let Some(task) = update.into_task(&bot_username) {
                            logger::info!(
                                "telegram message received channel={} session={} message_id={} input={}",
                                self.api.name(),
                                task.session_id(),
                                task.reply_target.message_id,
                                task.content.text()
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
            }
        }
    }

    async fn ensure_bot_username(&mut self) -> Result<()> {
        if self.bot_username.is_some() {
            return Ok(());
        }
        logger::info!("telegram channel connecting channel={}", self.api.name());
        let username = self.api.bot_username().await?;
        logger::info!(
            "telegram channel connected channel={} bot=@{}",
            self.api.name(),
            username
        );
        self.bot_username = Some(username);
        Ok(())
    }

    fn advance_offset(&mut self, update_id: i64) {
        let next = update_id.saturating_add(1);
        self.next_offset = Some(self.next_offset.map_or(next, |current| current.max(next)));
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
        Ok(TelegramRun {
            message: TelegramRichMessage::new(
                task.reply_target().clone(),
                context.agent.name,
                self.api.clone(),
            ),
        })
    }

    async fn reply(&self, task: &Self::Task, reply: ChannelReply) -> Result<()> {
        self.api.reply_text(task.reply_target(), reply.text()).await
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
    content: TaskContent,
    reply_target: TelegramReplyTarget,
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

    fn content(&self) -> &TaskContent {
        &self.content
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct TelegramUpdate {
    update_id: i64,
    #[serde(default)]
    message: Option<TelegramMessage>,
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

    pub(super) fn into_task(self, bot_username: &str) -> Option<TelegramTask> {
        let message = self.message?;
        let text = message.normalized_text(bot_username)?;
        if !message.chat.is_supported() {
            return None;
        }
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
            content: TaskContent::new(text),
            reply_target,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct TelegramMessage {
    message_id: i64,
    #[serde(default)]
    message_thread_id: Option<i64>,
    chat: TelegramChat,
    #[serde(default)]
    text: Option<String>,
}

impl TelegramMessage {
    fn normalized_text(&self, bot_username: &str) -> Option<String> {
        let text = self.text.as_ref()?;
        if text.trim().is_empty() {
            return None;
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
