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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressStatus {
    Running,
    Completed,
    Failed,
}
