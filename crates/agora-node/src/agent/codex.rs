use super::command::{Command, CommandOutput};
use super::{Agent, AgentOutcome, AgentOutput, AgentRequest, AgentSessionUpdate};
use crate::output::{OutputEvent, ProgressStatus};
use agora_core::logger;
use anyhow::Result;
use serde_json::Value;

#[derive(Clone)]
pub(super) struct CodexAgent {
    name: String,
    path: String,
    model: Option<String>,
    effort: Option<String>,
}

impl CodexAgent {
    pub(super) fn new(
        name: String,
        path: String,
        model: Option<String>,
        effort: Option<String>,
    ) -> Self {
        Self {
            name,
            path,
            model,
            effort,
        }
    }

    fn command(&self, request: AgentRequest) -> (Command, bool) {
        let (workdir, input, session_id) = request.into_parts();
        let resume_requested = session_id.is_some();
        let mut args = match &session_id {
            Some(_) => vec![
                "exec".to_string(),
                "resume".to_string(),
                "--json".to_string(),
            ],
            None => vec![
                "exec".to_string(),
                "--json".to_string(),
                "--color".to_string(),
                "never".to_string(),
            ],
        };
        self.append_options(&mut args);
        if let Some(session_id) = session_id {
            args.push(session_id);
        }
        args.push("-".to_string());
        (
            Command::new(&self.path)
                .args(args)
                .current_dir(workdir)
                .input(input),
            resume_requested,
        )
    }

    fn append_options(&self, args: &mut Vec<String>) {
        if let Some(model) = &self.model {
            args.push("--model".to_string());
            args.push(model.clone());
        }
        if let Some(effort) = &self.effort {
            args.push("--config".to_string());
            args.push(format!("model_reasoning_effort={effort}"));
        }
        args.push("--config".to_string());
        args.push("model_reasoning_summary=concise".to_string());
    }
}

impl Agent for CodexAgent {
    async fn run<O>(&self, request: AgentRequest, output: &mut O) -> Result<AgentOutcome>
    where
        O: AgentOutput + Send,
    {
        let (command, resume_requested) = self.command(request);
        let mut command_output = CodexCommandOutput::new(&self.name, output, resume_requested);
        let outcome = command.run(&mut command_output).await?;
        let session_update = if command_output.session_not_found() {
            AgentSessionUpdate::NotFound
        } else if let Some(next_session_id) = command_output.take_session_id() {
            logger::info!(
                "agent session updated agent={} session_id={}",
                self.name,
                next_session_id
            );
            AgentSessionUpdate::Set(next_session_id)
        } else {
            AgentSessionUpdate::Unchanged
        };
        Ok(AgentOutcome::new(outcome.exit_code(), session_update))
    }
}

struct CodexCommandOutput<'a, O> {
    agent_name: &'a str,
    output: &'a mut O,
    stdout_buffer: Vec<u8>,
    stderr_buffer: Vec<u8>,
    session_id: Option<String>,
    pending_message: Option<PendingAgentMessage>,
    resume_requested: bool,
    session_not_found: bool,
}

impl<'a, O> CodexCommandOutput<'a, O>
where
    O: AgentOutput + Send,
{
    fn new(agent_name: &'a str, output: &'a mut O, resume_requested: bool) -> Self {
        Self {
            agent_name,
            output,
            stdout_buffer: Vec::new(),
            stderr_buffer: Vec::new(),
            session_id: None,
            pending_message: None,
            resume_requested,
            session_not_found: false,
        }
    }

    fn take_session_id(&mut self) -> Option<String> {
        self.session_id.take()
    }

    fn session_not_found(&self) -> bool {
        self.session_not_found
    }

    async fn push_stdout(&mut self, chunk: &[u8]) -> Result<()> {
        self.stdout_buffer.extend_from_slice(chunk);
        while let Some(newline) = self.stdout_buffer.iter().position(|byte| *byte == b'\n') {
            let mut line = self.stdout_buffer.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.handle_line(&String::from_utf8_lossy(&line)).await?;
        }
        Ok(())
    }

    async fn flush_stdout(&mut self) -> Result<()> {
        if self.stdout_buffer.is_empty() {
            return Ok(());
        }
        let line = std::mem::take(&mut self.stdout_buffer);
        self.handle_line(&String::from_utf8_lossy(&line)).await
    }

    async fn flush_stderr(&mut self) -> Result<()> {
        if self.stderr_buffer.is_empty() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&self.stderr_buffer).into_owned();
        if self.resume_requested && Self::is_missing_session_message(&stderr) {
            self.session_not_found = true;
            return Ok(());
        }
        logger::error!(
            "codex stderr agent={}: {}",
            self.agent_name,
            stderr.trim_end()
        );
        Ok(())
    }

    fn is_missing_session_message(message: &str) -> bool {
        message.contains("no rollout found for thread id")
            || message.contains("session not found")
            || message.contains("thread not found")
    }

    async fn publish_pending_message(&mut self, final_answer: bool) -> Result<()> {
        let Some(message) = self.pending_message.take() else {
            return Ok(());
        };
        let event = if final_answer {
            OutputEvent::Answer { text: message.text }
        } else {
            OutputEvent::Progress {
                id: message.id,
                text: Self::concise(&message.text, 240),
                status: ProgressStatus::Completed,
            }
        };
        self.output.write(event).await
    }

    async fn handle_item(&mut self, event_type: &str, item: &Value) -> Result<()> {
        let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
        if item_type == "agent_message" && event_type == "item.completed" {
            self.publish_pending_message(false).await?;
            if let Some(text) = item.get("text").and_then(Value::as_str) {
                self.pending_message = Some(PendingAgentMessage {
                    id: item
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("agent-message")
                        .to_string(),
                    text: text.to_string(),
                });
            }
            return Ok(());
        }

        self.publish_pending_message(false).await?;
        match item_type {
            "reasoning" if event_type == "item.completed" => {
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    let text = Self::concise(text, 600);
                    if !text.is_empty() {
                        self.output.write(OutputEvent::Thinking { text }).await?;
                    }
                }
            }
            "command_execution" => {
                let command = item
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or("command");
                self.publish_progress(
                    item,
                    format!("Run `{}`", Self::concise(&command.replace('`', "'"), 160)),
                    Self::progress_status(event_type, item),
                )
                .await?;
            }
            "file_change" => {
                let count = item
                    .get("changes")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                self.publish_progress(
                    item,
                    format!("Changed {count} file(s)"),
                    Self::progress_status(event_type, item),
                )
                .await?;
            }
            "todo_list" => {
                let items = item
                    .get("items")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let completed = items
                    .iter()
                    .filter(|item| {
                        item.get("completed")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                    })
                    .count();
                self.publish_progress(
                    item,
                    format!("Plan progress: {completed}/{}", items.len()),
                    Self::progress_status(event_type, item),
                )
                .await?;
            }
            "mcp_tool_call" => {
                let server = item.get("server").and_then(Value::as_str).unwrap_or("mcp");
                let tool = item.get("tool").and_then(Value::as_str).unwrap_or("tool");
                self.publish_progress(
                    item,
                    format!("Call `{server}/{tool}`"),
                    Self::progress_status(event_type, item),
                )
                .await?;
            }
            "web_search" => {
                let query = item
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or("web search");
                self.publish_progress(
                    item,
                    format!("Search `{}`", Self::concise(&query.replace('`', "'"), 160)),
                    Self::progress_status(event_type, item),
                )
                .await?;
            }
            "error" => {
                let message = item
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("codex item failed");
                self.publish_progress(item, message.to_string(), ProgressStatus::Failed)
                    .await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn publish_progress(
        &mut self,
        item: &Value,
        text: String,
        status: ProgressStatus,
    ) -> Result<()> {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("codex-progress")
            .to_string();
        self.output
            .write(OutputEvent::Progress { id, text, status })
            .await
    }

    fn progress_status(event_type: &str, item: &Value) -> ProgressStatus {
        match item.get("status").and_then(Value::as_str) {
            Some("completed") => ProgressStatus::Completed,
            Some("failed" | "declined") => ProgressStatus::Failed,
            Some("in_progress") => ProgressStatus::Running,
            _ if event_type == "item.completed" => ProgressStatus::Completed,
            _ => ProgressStatus::Running,
        }
    }

    fn concise(text: &str, max_chars: usize) -> String {
        let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized.chars().count() <= max_chars {
            return normalized;
        }
        let mut result = normalized.chars().take(max_chars).collect::<String>();
        result.push_str("...");
        result
    }

    async fn handle_line(&mut self, line: &str) -> Result<()> {
        let event = match serde_json::from_str::<Value>(line) {
            Ok(event) => event,
            Err(_) => {
                return self
                    .output
                    .write(OutputEvent::Answer {
                        text: format!("{line}\n"),
                    })
                    .await;
            }
        };

        match event.get("type").and_then(Value::as_str) {
            Some("thread.started") => {
                if let Some(thread_id) = event.get("thread_id").and_then(Value::as_str) {
                    self.session_id = Some(thread_id.to_string());
                }
            }
            Some(event_type @ ("item.started" | "item.updated" | "item.completed")) => {
                if let Some(item) = event.get("item") {
                    self.handle_item(event_type, item).await?;
                }
            }
            Some("turn.completed") => {
                self.publish_pending_message(true).await?;
            }
            Some("error") | Some("turn.failed") => {
                self.publish_pending_message(false).await?;
                let message = event
                    .get("message")
                    .or_else(|| event.pointer("/error/message"))
                    .and_then(Value::as_str)
                    .unwrap_or("codex execution failed");
                self.output
                    .write(OutputEvent::Answer {
                        text: message.to_string(),
                    })
                    .await?;
            }
            _ => {}
        }
        Ok(())
    }
}

struct PendingAgentMessage {
    id: String,
    text: String,
}

impl<O> CommandOutput for CodexCommandOutput<'_, O>
where
    O: AgentOutput + Send,
{
    async fn stdout(&mut self, chunk: &[u8]) -> Result<()> {
        self.push_stdout(chunk).await
    }

    async fn stderr(&mut self, chunk: &[u8]) -> Result<()> {
        self.stderr_buffer.extend_from_slice(chunk);
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        self.flush_stdout().await?;
        self.publish_pending_message(true).await?;
        self.flush_stderr().await
    }
}
