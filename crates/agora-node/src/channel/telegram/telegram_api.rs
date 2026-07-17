use super::channel::TelegramReplyTarget;
use crate::config::TelegramChannelConfig;
use anyhow::{Context, Result, anyhow, bail};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const TELEGRAM_BOT_API: &str = "https://api.telegram.org";
const TELEGRAM_LONG_POLL_SECONDS: u64 = 50;
const TELEGRAM_HTTP_MAX_IDLE_CONNECTIONS_PER_HOST: usize = 10;
const TELEGRAM_HTTP_IDLE_TIMEOUT_SECONDS: u64 = 300;
const TELEGRAM_HTTP_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const TELEGRAM_HTTP_REQUEST_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone)]
pub(super) struct TelegramApi {
    name: String,
    token: String,
    client: Client,
    base_url: String,
    next_draft_id: Arc<AtomicI64>,
}

impl TelegramApi {
    pub(super) fn new(config: TelegramChannelConfig) -> Result<Self> {
        Self::with_base_url(config, TELEGRAM_BOT_API.to_string())
    }

    pub(super) fn with_base_url(config: TelegramChannelConfig, base_url: String) -> Result<Self> {
        Ok(Self {
            name: config.name,
            token: config.token,
            client: Self::http_client()?,
            base_url: base_url.trim_end_matches('/').to_string(),
            next_draft_id: Arc::new(AtomicI64::new(Self::draft_id_seed())),
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) async fn bot_username(&self) -> Result<String> {
        let user: TelegramUser = self.request("getMe", &EmptyRequest {}).await?;
        user.username
            .filter(|username| !username.is_empty())
            .ok_or_else(|| anyhow!("telegram getMe response missing bot username"))
    }

    pub(super) async fn get_updates(&self, offset: Option<i64>) -> Result<Vec<Value>> {
        self.request(
            "getUpdates",
            &GetUpdatesRequest {
                offset,
                timeout: TELEGRAM_LONG_POLL_SECONDS,
                allowed_updates: ["message"],
            },
        )
        .await
    }

    pub(super) async fn reply_text(&self, target: &TelegramReplyTarget, text: &str) -> Result<()> {
        let _: TelegramSentMessage = self
            .request(
                "sendMessage",
                &SendMessageRequest {
                    chat_id: target.chat_id,
                    message_thread_id: target.message_thread_id,
                    text,
                    reply_parameters: ReplyParameters {
                        message_id: target.message_id,
                    },
                },
            )
            .await?;
        Ok(())
    }

    pub(super) fn allocate_draft_id(&self) -> i64 {
        let draft_id = self.next_draft_id.fetch_add(1, Ordering::Relaxed);
        if draft_id == 0 {
            self.next_draft_id.fetch_add(1, Ordering::Relaxed)
        } else {
            draft_id
        }
    }

    pub(super) async fn send_rich_message_draft(
        &self,
        target: &TelegramReplyTarget,
        draft_id: i64,
        markdown: &str,
    ) -> Result<()> {
        let sent: bool = self
            .request(
                "sendRichMessageDraft",
                &SendRichMessageDraftRequest {
                    chat_id: target.chat_id,
                    message_thread_id: target.message_thread_id,
                    draft_id,
                    rich_message: InputRichMessage { markdown },
                },
            )
            .await?;
        if !sent {
            bail!("telegram sendRichMessageDraft returned false");
        }
        Ok(())
    }

    pub(super) async fn send_rich_message(
        &self,
        target: &TelegramReplyTarget,
        markdown: &str,
    ) -> Result<i64> {
        let message: TelegramSentMessage = self
            .request(
                "sendRichMessage",
                &SendRichMessageRequest {
                    chat_id: target.chat_id,
                    message_thread_id: target.message_thread_id,
                    rich_message: InputRichMessage { markdown },
                    reply_parameters: ReplyParameters {
                        message_id: target.message_id,
                    },
                },
            )
            .await?;
        Ok(message.message_id)
    }

    pub(super) async fn edit_rich_message(
        &self,
        chat_id: i64,
        message_id: i64,
        markdown: &str,
    ) -> Result<()> {
        let _: TelegramSentMessage = self
            .request(
                "editMessageText",
                &EditRichMessageRequest {
                    chat_id,
                    message_id,
                    rich_message: InputRichMessage { markdown },
                },
            )
            .await?;
        Ok(())
    }

    async fn request<B, T>(&self, method: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let mut retried_after_rate_limit = false;
        loop {
            let response = self
                .client
                .post(self.method_url(method))
                .json(body)
                .send()
                .await
                .map_err(|err| Self::safe_transport_error(method, "request", &err))?;
            let envelope = response
                .json::<TelegramResponse<T>>()
                .await
                .map_err(|err| Self::safe_transport_error(method, "response", &err))?;
            if envelope.ok {
                return envelope
                    .result
                    .ok_or_else(|| anyhow!("telegram {method} response missing result"));
            }

            if !retried_after_rate_limit
                && envelope.error_code == Some(429)
                && let Some(retry_after) = envelope
                    .parameters
                    .as_ref()
                    .and_then(|parameters| parameters.retry_after)
            {
                retried_after_rate_limit = true;
                tokio::time::sleep(Duration::from_secs(retry_after)).await;
                continue;
            }

            let code = envelope
                .error_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let description = envelope
                .description
                .unwrap_or_else(|| "unknown Telegram API error".to_string());
            bail!("telegram {method} failed code={code}: {description}");
        }
    }

    fn method_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.base_url, self.token, method)
    }

    fn safe_transport_error(method: &str, phase: &str, err: &reqwest::Error) -> anyhow::Error {
        let kind = if err.is_timeout() {
            "timed out"
        } else if err.is_connect() {
            "connection failed"
        } else if err.is_decode() {
            "invalid response"
        } else if err.is_request() {
            "invalid request"
        } else {
            "transport failed"
        };
        anyhow!("telegram {method} {phase} failed: {kind}")
    }

    fn draft_id_seed() -> i64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        millis.max(1)
    }

    fn http_client() -> Result<Client> {
        Client::builder()
            .pool_max_idle_per_host(TELEGRAM_HTTP_MAX_IDLE_CONNECTIONS_PER_HOST)
            .pool_idle_timeout(Some(Duration::from_secs(
                TELEGRAM_HTTP_IDLE_TIMEOUT_SECONDS,
            )))
            .connect_timeout(Duration::from_secs(TELEGRAM_HTTP_CONNECT_TIMEOUT_SECONDS))
            .timeout(Duration::from_secs(TELEGRAM_HTTP_REQUEST_TIMEOUT_SECONDS))
            .build()
            .context("build telegram http client failed")
    }
}

#[derive(Serialize)]
struct EmptyRequest {}

#[derive(Serialize)]
struct GetUpdatesRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<i64>,
    timeout: u64,
    allowed_updates: [&'a str; 1],
}

#[derive(Serialize)]
struct SendMessageRequest<'a> {
    chat_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_thread_id: Option<i64>,
    text: &'a str,
    reply_parameters: ReplyParameters,
}

#[derive(Serialize)]
struct InputRichMessage<'a> {
    markdown: &'a str,
}

#[derive(Serialize)]
struct SendRichMessageDraftRequest<'a> {
    chat_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_thread_id: Option<i64>,
    draft_id: i64,
    rich_message: InputRichMessage<'a>,
}

#[derive(Serialize)]
struct SendRichMessageRequest<'a> {
    chat_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_thread_id: Option<i64>,
    rich_message: InputRichMessage<'a>,
    reply_parameters: ReplyParameters,
}

#[derive(Serialize)]
struct EditRichMessageRequest<'a> {
    chat_id: i64,
    message_id: i64,
    rich_message: InputRichMessage<'a>,
}

#[derive(Serialize)]
struct ReplyParameters {
    message_id: i64,
}

#[derive(Deserialize)]
struct TelegramResponse<T> {
    ok: bool,
    result: Option<T>,
    error_code: Option<i64>,
    description: Option<String>,
    parameters: Option<TelegramResponseParameters>,
}

#[derive(Deserialize)]
struct TelegramResponseParameters {
    retry_after: Option<u64>,
}

#[derive(Deserialize)]
struct TelegramUser {
    username: Option<String>,
}

#[derive(Deserialize)]
struct TelegramSentMessage {
    message_id: i64,
}
