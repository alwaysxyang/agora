mod output;

pub use output::{OutputEvent, ProgressStatus, TokenUsage};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CommandRequest {
    path: Vec<String>,
    arguments: BTreeMap<String, String>,
}

impl CommandRequest {
    pub fn new<I, S>(path: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            path: path.into_iter().map(Into::into).collect(),
            arguments: BTreeMap::new(),
        }
    }

    pub fn with_argument(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.arguments.insert(name.into(), value.into());
        self
    }

    pub fn path(&self) -> &[String] {
        &self.path
    }

    pub fn arguments(&self) -> &BTreeMap<String, String> {
        &self.arguments
    }

    pub fn argument(&self, name: &str) -> Option<&str> {
        self.arguments.get(name).map(String::as_str)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelTaskInput {
    Message(TaskContent),
    Command(CommandRequest),
}

impl ChannelTaskInput {
    pub fn message(&self) -> Option<&TaskContent> {
        match self {
            Self::Message(content) => Some(content),
            Self::Command(_) => None,
        }
    }

    pub fn command(&self) -> Option<&CommandRequest> {
        match self {
            Self::Message(_) => None,
            Self::Command(command) => Some(command),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskAttachmentKind {
    Image,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TaskAttachment {
    kind: TaskAttachmentKind,
    file_name: String,
    media_type: String,
    data: Arc<[u8]>,
}

impl TaskAttachment {
    pub fn image(
        file_name: impl Into<String>,
        media_type: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            kind: TaskAttachmentKind::Image,
            file_name: file_name.into(),
            media_type: media_type.into(),
            data: Arc::from(data.into()),
        }
    }

    pub fn kind(&self) -> TaskAttachmentKind {
        self.kind
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for TaskAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskAttachment")
            .field("kind", &self.kind)
            .field("file_name", &self.file_name)
            .field("media_type", &self.media_type)
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskContent {
    text: String,
    attachments: Vec<TaskAttachment>,
}

impl TaskContent {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            attachments: Vec::new(),
        }
    }

    pub fn with_attachment(mut self, attachment: TaskAttachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn attachments(&self) -> &[TaskAttachment] {
        &self.attachments
    }

    pub(crate) fn into_parts(self) -> (String, Vec<TaskAttachment>) {
        (self.text, self.attachments)
    }
}

impl From<String> for TaskContent {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl From<&str> for TaskContent {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_and_message_inputs_expose_only_their_own_payload() {
        let command =
            CommandRequest::new(["ask", "status"]).with_argument("agent_name", "reviewer");
        assert_eq!(command.path(), &["ask", "status"]);
        assert_eq!(command.argument("agent_name"), Some("reviewer"));
        assert_eq!(command.argument("missing"), None);
        assert_eq!(command.arguments().len(), 1);

        let command_input = ChannelTaskInput::Command(command.clone());
        assert_eq!(command_input.command(), Some(&command));
        assert_eq!(command_input.message(), None);

        let message = TaskContent::new("inspect");
        let message_input = ChannelTaskInput::Message(message.clone());
        assert_eq!(message_input.message(), Some(&message));
        assert_eq!(message_input.command(), None);
    }

    #[test]
    fn attachments_and_task_content_keep_owned_metadata_and_hide_bytes_in_debug() {
        let image = TaskAttachment::image("trace.png", "image/png", b"pixels".to_vec());
        assert_eq!(image.kind(), TaskAttachmentKind::Image);
        assert_eq!(image.file_name(), "trace.png");
        assert_eq!(image.media_type(), "image/png");
        assert_eq!(image.data(), b"pixels");
        assert_eq!(
            format!("{image:?}"),
            "TaskAttachment { kind: Image, file_name: \"trace.png\", media_type: \"image/png\", data_len: 6 }"
        );

        let content = TaskContent::new("inspect").with_attachment(image);
        assert_eq!(content.text(), "inspect");
        assert_eq!(content.attachments().len(), 1);
        let (text, attachments) = content.into_parts();
        assert_eq!(text, "inspect");
        assert_eq!(attachments.len(), 1);
        assert_eq!(TaskContent::from(String::from("owned")).text(), "owned");
        assert_eq!(TaskContent::from("borrowed").text(), "borrowed");
    }
}
