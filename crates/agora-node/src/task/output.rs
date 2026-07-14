#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputEvent {
    Thinking {
        text: String,
    },
    Progress {
        id: String,
        text: String,
        status: ProgressStatus,
    },
    Answer {
        text: String,
    },
    Usage(TokenUsage),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_output_tokens: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressStatus {
    Running,
    Completed,
    Failed,
}
