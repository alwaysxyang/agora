use super::LarkReplyTarget;
use super::card::LarkAgentCard;
use super::lark_api::LarkApi;
use crate::channel::{Channel, ChannelRun, ChannelRunContext, ChannelTask, RunEvent};
use crate::config::LarkChannelConfig;
use crate::task::{TaskAttachment, TaskContent};
use agora_core::logger;
use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct LarkMessageEvent {
    #[serde(rename = "event_id")]
    pub(super) id: String,
    pub(super) message_id: String,
    pub(super) chat_id: String,
    pub(super) chat_type: String,
    pub(super) sender_id: String,
    pub(super) message_type: String,
    pub(super) content: String,
    pub(super) image_keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LarkEvent {
    Message(LarkMessageEvent),
    Ignore { event_type: String },
}

impl LarkEvent {
    pub(super) fn from_lark_event_payload(payload: impl AsRef<[u8]>) -> Result<Self> {
        let value: Value = serde_json::from_slice(payload.as_ref())
            .context("lark event payload is not valid json")?;
        let event_type = value
            .pointer("/header/event_type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("lark message event missing header.event_type"))?;
        match event_type {
            "im.message.receive_v1" => {
                LarkMessageEvent::from_lark_event_value(&value).map(Self::Message)
            }
            _ => Ok(Self::Ignore {
                event_type: event_type.to_string(),
            }),
        }
    }
}

impl LarkMessageEvent {
    fn from_lark_event_value(value: &Value) -> Result<Self> {
        let id = value
            .pointer("/header/event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("lark message event missing header.event_id"))?
            .to_string();
        let message = value
            .pointer("/event/message")
            .ok_or_else(|| anyhow!("lark message event missing event.message"))?;
        let sender_id = value
            .pointer("/event/sender/sender_id/open_id")
            .or_else(|| value.pointer("/event/sender/sender_id/user_id"))
            .or_else(|| value.pointer("/event/sender/sender_id/union_id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let message_type = Self::required_str(message, "message_type")?.to_string();
        let raw_content = Self::required_str(message, "content")?;
        let (content, image_keys) = Self::normalize_content(&message_type, raw_content);
        Ok(Self {
            id,
            message_id: Self::required_str(message, "message_id")?.to_string(),
            chat_id: Self::required_str(message, "chat_id")?.to_string(),
            chat_type: Self::required_str(message, "chat_type")?.to_string(),
            sender_id,
            content,
            image_keys,
            message_type,
        })
    }

    pub(super) fn session_id(&self) -> &str {
        &self.chat_id
    }

    pub(super) fn input(&self) -> &str {
        &self.content
    }

    pub(super) fn image_keys(&self) -> &[String] {
        &self.image_keys
    }

    pub(super) fn reply_target(&self) -> LarkReplyTarget {
        LarkReplyTarget {
            message_id: self.message_id.clone(),
        }
    }

    pub(super) fn is_supported_message(&self) -> bool {
        matches!(self.message_type.as_str(), "text" | "post" | "image")
    }

    fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
        value
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("lark message event missing event.message.{field}"))
    }

    fn normalize_content(message_type: &str, raw_content: &str) -> (String, Vec<String>) {
        match message_type {
            "text" => (
                serde_json::from_str::<Value>(raw_content)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("text")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| raw_content.to_string()),
                Vec::new(),
            ),
            "post" => serde_json::from_str::<Value>(raw_content)
                .ok()
                .map(|value| Self::flatten_post_content(&value))
                .unwrap_or_else(|| (raw_content.to_string(), Vec::new())),
            "image" => {
                let image_keys = serde_json::from_str::<Value>(raw_content)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("image_key")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .into_iter()
                    .collect();
                (String::new(), image_keys)
            }
            _ => (raw_content.to_string(), Vec::new()),
        }
    }

    fn flatten_post_content(value: &Value) -> (String, Vec<String>) {
        let items = value
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_array)
            .flat_map(|line| line.iter())
            .collect::<Vec<_>>();
        let text = items
            .iter()
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("");
        let image_keys = items
            .iter()
            .filter_map(|item| item.get("image_key").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        (text, image_keys)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LarkTask {
    event: LarkMessageEvent,
    content: TaskContent,
}

impl LarkTask {
    fn new(event: LarkMessageEvent, content: TaskContent) -> Self {
        Self { event, content }
    }

    fn reply_target(&self) -> LarkReplyTarget {
        self.event.reply_target()
    }
}

impl ChannelTask for LarkTask {
    fn task_id(&self) -> &str {
        &self.event.message_id
    }

    fn session_id(&self) -> &str {
        &self.event.chat_id
    }

    fn content(&self) -> &TaskContent {
        &self.content
    }
}

#[derive(Clone)]
pub struct LarkRun {
    card: LarkAgentCard,
}

impl ChannelRun for LarkRun {
    async fn publish(&self, event: RunEvent) -> Result<()> {
        self.card.publish(event).await
    }
}

pub struct LarkChannel {
    api: LarkApi,
    receiver: Option<LarkWebSocketReceiver>,
}

impl LarkChannel {
    pub fn new(config: LarkChannelConfig) -> Result<Self> {
        Ok(Self {
            api: LarkApi::new(config)?,
            receiver: None,
        })
    }

    #[cfg(test)]
    pub(super) fn with_api(api: LarkApi) -> Self {
        Self {
            api,
            receiver: None,
        }
    }

    fn receiver(&mut self) -> &mut LarkWebSocketReceiver {
        self.receiver
            .get_or_insert_with(|| LarkWebSocketReceiver::spawn(self.api.clone()))
    }

    pub(super) async fn task_from_event(&self, event: LarkMessageEvent) -> Result<LarkTask> {
        let mut content = TaskContent::new(event.input());
        if !event.image_keys().is_empty() {
            let token = self
                .api
                .tenant_access_token()
                .await
                .context("get lark token for message images failed")?;
            for (index, image_key) in event.image_keys().iter().enumerate() {
                let image = self
                    .api
                    .download_message_image(&token, &event.message_id, image_key)
                    .await
                    .with_context(|| format!("download lark message image failed: {image_key}"))?;
                let file_name = format!(
                    "lark-image-{}.{}",
                    index + 1,
                    Self::image_extension(&image.media_type)
                );
                content = content.with_attachment(TaskAttachment::image(
                    file_name,
                    image.media_type,
                    image.data,
                ));
            }
        }
        Ok(LarkTask::new(event, content))
    }

    fn image_extension(media_type: &str) -> &'static str {
        match media_type {
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/webp" => "webp",
            "image/gif" => "gif",
            "image/bmp" => "bmp",
            "image/tiff" => "tiff",
            "image/heic" => "heic",
            _ => "img",
        }
    }
}

impl Channel for LarkChannel {
    type Task = LarkTask;
    type Run = LarkRun;

    fn name(&self) -> &str {
        self.api.name()
    }

    async fn recv(&mut self) -> Result<Option<Self::Task>> {
        loop {
            let Some(event) = self.receiver().next_event().await? else {
                return Ok(None);
            };
            if event.is_supported_message() {
                let task = self.task_from_event(event).await?;
                logger::info!(
                    "lark message received channel={} session={} sender={} message_id={} input={} attachments={}",
                    self.name(),
                    task.event.session_id(),
                    task.event.sender_id,
                    task.event.message_id,
                    task.content.text(),
                    task.content.attachments().len()
                );
                return Ok(Some(task));
            }
        }
    }

    async fn open_run(&self, task: &Self::Task, context: ChannelRunContext) -> Result<Self::Run> {
        Ok(LarkRun {
            card: LarkAgentCard::new(task.reply_target(), context.agent.name, self.api.clone()),
        })
    }
}

struct LarkWebSocketReceiver {
    events: mpsc::UnboundedReceiver<Result<LarkMessageEvent>>,
    task: Option<JoinHandle<Result<()>>>,
}

impl LarkWebSocketReceiver {
    fn spawn(api: LarkApi) -> Self {
        let (sender, events) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move { api.run_websocket_loop(sender).await });
        Self {
            events,
            task: Some(task),
        }
    }

    async fn next_event(&mut self) -> Result<Option<LarkMessageEvent>> {
        match self.events.recv().await {
            Some(event) => event.map(Some),
            None => {
                if let Some(task) = self.task.take() {
                    task.await
                        .map_err(|err| anyhow!("lark websocket receiver task failed: {err}"))??;
                }
                Ok(None)
            }
        }
    }
}
