mod output;

pub use output::{OutputEvent, ProgressStatus, TokenUsage};

use std::fmt;
use std::sync::Arc;

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
