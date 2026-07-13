use crate::channel::{Channel, ChannelRun, ChannelRunContext, ChannelTask, RunEvent};
use agora_core::logger;
use anyhow::{Context, Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WebSocketMessage;

const LARK_OPENAPI: &str = "https://open.feishu.cn";
const LARK_WS_ENDPOINT_PATH: &str = "/callback/ws/endpoint";
const MAX_CARD_CONTENT_BYTES: usize = 24 * 1024;
const LARK_FRAME_TYPE_CONTROL: i32 = 0;
const LARK_FRAME_TYPE_DATA: i32 = 1;
const LARK_MESSAGE_TYPE_EVENT: &str = "event";
const LARK_MESSAGE_TYPE_PING: &str = "ping";
const DEFAULT_WS_PING_INTERVAL_SECONDS: u64 = 120;
const LARK_RECONNECT_INITIAL_DELAY_SECONDS: u64 = 1;
const LARK_RECONNECT_MAX_DELAY_SECONDS: u64 = 60;
const LARK_HTTP_MAX_IDLE_CONNECTIONS_PER_HOST: usize = 10;
const LARK_HTTP_IDLE_TIMEOUT_SECONDS: u64 = 300;
const LARK_HTTP_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const LARK_HTTP_REQUEST_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LarkChannelConfig {
    pub name: String,
    pub appid: String,
    pub secret: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LarkReplyTarget {
    pub receive_id_type: String,
    pub receive_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LarkMessageEvent {
    #[serde(rename = "event_id")]
    pub id: String,
    pub message_id: String,
    pub chat_id: String,
    pub chat_type: String,
    pub sender_id: String,
    pub message_type: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LarkEvent {
    Message(LarkMessageEvent),
    Ignore { event_type: String },
}

impl LarkEvent {
    pub fn from_lark_event_payload(payload: impl AsRef<[u8]>) -> Result<Self> {
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
        Ok(Self {
            id,
            message_id: Self::required_str(message, "message_id")?.to_string(),
            chat_id: Self::required_str(message, "chat_id")?.to_string(),
            chat_type: Self::required_str(message, "chat_type")?.to_string(),
            sender_id,
            content: Self::normalize_content(&message_type, raw_content),
            message_type,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.chat_id
    }

    pub fn input(&self) -> &str {
        &self.content
    }

    pub fn reply_target(&self) -> LarkReplyTarget {
        LarkReplyTarget {
            receive_id_type: "chat_id".to_string(),
            receive_id: self.chat_id.clone(),
        }
    }

    pub fn is_supported_message(&self) -> bool {
        matches!(self.message_type.as_str(), "text" | "post")
    }

    fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
        value
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("lark message event missing event.message.{field}"))
    }

    fn normalize_content(message_type: &str, raw_content: &str) -> String {
        match message_type {
            "text" => serde_json::from_str::<Value>(raw_content)
                .ok()
                .and_then(|value| {
                    value
                        .get("text")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_else(|| raw_content.to_string()),
            "post" => serde_json::from_str::<Value>(raw_content)
                .ok()
                .map(|value| Self::flatten_post_content(&value))
                .filter(|content| !content.is_empty())
                .unwrap_or_else(|| raw_content.to_string()),
            _ => raw_content.to_string(),
        }
    }

    fn flatten_post_content(value: &Value) -> String {
        value
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_array)
            .flat_map(|line| line.iter())
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("")
    }
}

impl ChannelTask for LarkMessageEvent {
    fn task_id(&self) -> &str {
        &self.message_id
    }

    fn session_id(&self) -> &str {
        &self.chat_id
    }

    fn input(&self) -> &str {
        &self.content
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

    fn receiver(&mut self) -> &mut LarkWebSocketReceiver {
        self.receiver
            .get_or_insert_with(|| LarkWebSocketReceiver::spawn(self.api.clone()))
    }
}

impl Channel for LarkChannel {
    type Task = LarkMessageEvent;
    type Run = LarkAgentCard;

    fn name(&self) -> &str {
        &self.api.name
    }

    async fn recv(&mut self) -> Result<Option<Self::Task>> {
        loop {
            let Some(event) = self.receiver().next_event().await? else {
                return Ok(None);
            };
            if event.is_supported_message() {
                logger::info!(
                    "lark message received channel={} session={} sender={} message_id={} input={}",
                    self.name(),
                    event.session_id(),
                    event.sender_id,
                    event.message_id,
                    event.input()
                );
                return Ok(Some(event));
            }
        }
    }

    async fn open_run(&self, task: &Self::Task, context: ChannelRunContext) -> Result<Self::Run> {
        Ok(LarkAgentCard::new(
            task.reply_target(),
            context.agent.name,
            self.api.clone(),
        ))
    }
}

pub struct LarkWebSocketReceiver {
    events: mpsc::UnboundedReceiver<Result<LarkMessageEvent>>,
    task: Option<JoinHandle<Result<()>>>,
}

impl LarkWebSocketReceiver {
    pub fn spawn(api: LarkApi) -> Self {
        let (sender, events) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move { api.run_websocket_loop(sender).await });
        Self {
            events,
            task: Some(task),
        }
    }

    pub async fn next_event(&mut self) -> Result<Option<LarkMessageEvent>> {
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

impl LarkApi {
    async fn run_websocket_loop(
        &self,
        events: mpsc::UnboundedSender<Result<LarkMessageEvent>>,
    ) -> Result<()> {
        let mut backoff = LarkReconnectBackoff::default();
        logger::info!("lark channel starting channel={}", self.name);
        loop {
            let mut connected = false;
            logger::info!("lark websocket connecting channel={}", self.name);
            match self
                .run_websocket_once(events.clone(), &mut connected)
                .await
            {
                Ok(()) => {
                    logger::info!(
                        "lark websocket disconnected channel={}, reconnecting",
                        self.name
                    );
                    backoff.reset();
                }
                Err(_) => {
                    if connected {
                        logger::error!(
                            "lark websocket disconnected channel={} reason=connection_error",
                            self.name
                        );
                    } else {
                        logger::error!(
                            "lark channel startup failed channel={} reason=connection_error",
                            self.name
                        );
                    }
                }
            }

            let delay = backoff.next_delay();
            logger::info!(
                "lark websocket reconnect scheduled channel={} delay_secs={}",
                self.name,
                delay.as_secs()
            );
            tokio::time::sleep(delay).await;
        }
    }

    async fn run_websocket_once(
        &self,
        events: mpsc::UnboundedSender<Result<LarkMessageEvent>>,
        connected: &mut bool,
    ) -> Result<()> {
        let (endpoint_url, client_config) = self.websocket_endpoint().await?;
        let service_id = Self::query_param(&endpoint_url, "service_id")
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or_default();
        let ping_interval_seconds = if client_config.ping_interval > 0 {
            client_config.ping_interval as u64
        } else {
            DEFAULT_WS_PING_INTERVAL_SECONDS
        };

        let (mut socket, _) = connect_async(endpoint_url.as_str())
            .await
            .context("connect lark websocket failed")?;
        *connected = true;
        logger::info!("lark websocket connected channel={}", self.name);
        let mut ping_interval = tokio::time::interval(Duration::from_secs(ping_interval_seconds));

        loop {
            tokio::select! {
                message = socket.next() => {
                    let Some(message) = message else {
                        return Ok(());
                    };
                    match message.context("read lark websocket message failed")? {
                        WebSocketMessage::Binary(payload) => {
                        if let Some(ack) = self.handle_websocket_binary(&payload, &events)? {
                                socket
                                    .send(WebSocketMessage::Binary(ack.encode_to_vec().into()))
                                    .await
                                    .context("send lark websocket ack failed")?;
                            }
                        }
                        WebSocketMessage::Ping(payload) => {
                            socket
                                .send(WebSocketMessage::Pong(payload))
                                .await
                                .context("send lark websocket pong failed")?;
                        }
                        WebSocketMessage::Close(_) => return Ok(()),
                        _ => {}
                    }
                }
                _ = ping_interval.tick() => {
                    let ping = LarkFrame::ping(service_id);
                    socket
                        .send(WebSocketMessage::Binary(ping.encode_to_vec().into()))
                        .await
                        .context("send lark websocket ping failed")?;
                }
            }
        }
    }

    async fn websocket_endpoint(&self) -> Result<(String, LarkWebSocketClientConfig)> {
        let url = format!("{LARK_OPENAPI}{LARK_WS_ENDPOINT_PATH}");
        let response = self
            .client
            .post(url)
            .header("locale", "zh")
            .json(&json!({
                "AppID": self.appid,
                "AppSecret": self.secret,
            }))
            .send()
            .await
            .context("request lark websocket endpoint failed")?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("lark websocket endpoint http failed: {status}"));
        }
        let endpoint = response
            .json::<LarkWebSocketEndpointResponse>()
            .await
            .context("parse lark websocket endpoint response failed")?;
        if endpoint.code != 0 {
            return Err(anyhow!(
                "lark websocket endpoint failed: code={}, msg={}",
                endpoint.code,
                endpoint.msg
            ));
        }
        let data = endpoint
            .data
            .ok_or_else(|| anyhow!("lark websocket endpoint response missing data"))?;
        Ok((data.url, data.client_config.unwrap_or_default()))
    }

    fn http_client() -> Result<Client> {
        Client::builder()
            .pool_max_idle_per_host(LARK_HTTP_MAX_IDLE_CONNECTIONS_PER_HOST)
            .pool_idle_timeout(Some(Duration::from_secs(LARK_HTTP_IDLE_TIMEOUT_SECONDS)))
            .connect_timeout(Duration::from_secs(LARK_HTTP_CONNECT_TIMEOUT_SECONDS))
            .timeout(Duration::from_secs(LARK_HTTP_REQUEST_TIMEOUT_SECONDS))
            .build()
            .context("build lark http client failed")
    }

    fn query_param(url: &str, key: &str) -> Option<String> {
        let query = url.split_once('?')?.1;
        query.split('&').find_map(|part| {
            let (name, value) = part.split_once('=')?;
            (name == key).then(|| value.to_string())
        })
    }

    fn handle_websocket_binary(
        &self,
        payload: &[u8],
        events: &mpsc::UnboundedSender<Result<LarkMessageEvent>>,
    ) -> Result<Option<LarkFrame>> {
        let frame = LarkFrame::decode(payload).context("decode lark websocket frame failed")?;
        match frame.method {
            LARK_FRAME_TYPE_CONTROL => Ok(None),
            LARK_FRAME_TYPE_DATA => self.handle_data_frame(frame, events),
            _ => Ok(None),
        }
    }

    fn handle_data_frame(
        &self,
        frame: LarkFrame,
        events: &mpsc::UnboundedSender<Result<LarkMessageEvent>>,
    ) -> Result<Option<LarkFrame>> {
        if frame.header("type") != Some(LARK_MESSAGE_TYPE_EVENT) {
            return Ok(None);
        }

        let started = Instant::now();
        let status_code = match LarkEvent::from_lark_event_payload(&frame.payload) {
            Ok(LarkEvent::Message(event)) => {
                self.send_event(events, event)?;
                200
            }
            Ok(LarkEvent::Ignore { .. }) => 200,
            Err(err) => {
                logger::error!("ignore invalid lark event payload: {}", err);
                500
            }
        };
        Ok(Some(
            frame.into_ack(status_code, started.elapsed().as_millis())?,
        ))
    }

    fn send_event(
        &self,
        events: &mpsc::UnboundedSender<Result<LarkMessageEvent>>,
        event: LarkMessageEvent,
    ) -> Result<()> {
        events
            .send(Ok(event))
            .map_err(|_| anyhow!("agora lark receiver closed"))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LarkWebSocketEndpointResponse {
    pub code: i32,
    #[serde(default)]
    pub msg: String,
    pub data: Option<LarkWebSocketEndpoint>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LarkWebSocketEndpoint {
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(default)]
    pub client_config: Option<LarkWebSocketClientConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LarkWebSocketClientConfig {
    #[serde(default)]
    pub reconnect_count: i32,
    #[serde(default)]
    pub reconnect_interval: i32,
    #[serde(default)]
    pub reconnect_nonce: i32,
    #[serde(default)]
    pub ping_interval: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LarkReconnectBackoff {
    next_delay: Duration,
}

impl Default for LarkReconnectBackoff {
    fn default() -> Self {
        Self {
            next_delay: Duration::from_secs(LARK_RECONNECT_INITIAL_DELAY_SECONDS),
        }
    }
}

impl LarkReconnectBackoff {
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.next_delay;
        self.next_delay = self
            .next_delay
            .saturating_mul(2)
            .min(Duration::from_secs(LARK_RECONNECT_MAX_DELAY_SECONDS));
        delay
    }

    pub fn reset(&mut self) {
        self.next_delay = Duration::from_secs(LARK_RECONNECT_INITIAL_DELAY_SECONDS);
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct LarkFrameHeader {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

impl LarkFrameHeader {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct LarkFrame {
    #[prost(uint64, tag = "1")]
    pub seq_id: u64,
    #[prost(uint64, tag = "2")]
    pub log_id: u64,
    #[prost(int32, tag = "3")]
    pub service: i32,
    #[prost(int32, tag = "4")]
    pub method: i32,
    #[prost(message, repeated, tag = "5")]
    pub headers: Vec<LarkFrameHeader>,
    #[prost(string, tag = "6")]
    pub payload_encoding: String,
    #[prost(string, tag = "7")]
    pub payload_type: String,
    #[prost(bytes, tag = "8")]
    pub payload: Vec<u8>,
    #[prost(string, tag = "9")]
    pub log_id_new: String,
}

impl LarkFrame {
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.key == key)
            .map(|header| header.value.as_str())
    }

    pub fn into_ack(mut self, status_code: u16, biz_rt_ms: u128) -> Result<Self> {
        self.upsert_header("biz_rt", biz_rt_ms.to_string());
        self.payload = serde_json::to_vec(&LarkWebSocketAck {
            code: status_code,
            headers: None,
            data: None,
        })?;
        Ok(self)
    }

    fn ping(service_id: i32) -> Self {
        Self {
            seq_id: 0,
            log_id: 0,
            service: service_id,
            method: LARK_FRAME_TYPE_CONTROL,
            headers: vec![LarkFrameHeader::new("type", LARK_MESSAGE_TYPE_PING)],
            payload_encoding: String::new(),
            payload_type: String::new(),
            payload: Vec::new(),
            log_id_new: String::new(),
        }
    }

    fn upsert_header(&mut self, key: &str, value: impl Into<String>) {
        let value = value.into();
        if let Some(header) = self.headers.iter_mut().find(|header| header.key == key) {
            header.value = value;
        } else {
            self.headers.push(LarkFrameHeader::new(key, value));
        }
    }
}

#[derive(Serialize)]
struct LarkWebSocketAck {
    code: u16,
    headers: Option<BTreeMap<String, String>>,
    data: Option<Value>,
}

#[derive(Clone)]
pub struct LarkApi {
    name: String,
    appid: String,
    secret: String,
    client: Client,
    base_url: String,
}

impl LarkApi {
    pub fn new(config: LarkChannelConfig) -> Result<Self> {
        Ok(Self {
            name: config.name,
            appid: config.appid,
            secret: config.secret,
            client: Self::http_client()?,
            base_url: LARK_OPENAPI.to_string(),
        })
    }

    async fn tenant_access_token(&self) -> Result<String> {
        let response = self
            .client
            .post(format!(
                "{}/open-apis/auth/v3/tenant_access_token/internal",
                self.base_url
            ))
            .json(&json!({
                "app_id": self.appid,
                "app_secret": self.secret,
            }))
            .send()
            .await?
            .json::<TenantTokenResponse>()
            .await?;
        response.into_result()
    }

    async fn send_card(
        &self,
        token: &str,
        target: &LarkReplyTarget,
        card: &Value,
    ) -> Result<String> {
        let response = self
            .client
            .post(format!("{}/open-apis/im/v1/messages", self.base_url))
            .bearer_auth(token)
            .query(&[("receive_id_type", target.receive_id_type.as_str())])
            .json(&SendCardRequest {
                receive_id: target.receive_id.as_str(),
                msg_type: "interactive",
                content: serde_json::to_string(card)?,
            })
            .send()
            .await?
            .json::<SendCardResponse>()
            .await?;
        response.into_result()
    }

    async fn patch_card(&self, token: &str, message_id: &str, card: &Value) -> Result<()> {
        let response = self
            .client
            .patch(format!(
                "{}/open-apis/im/v1/messages/{}",
                self.base_url, message_id
            ))
            .bearer_auth(token)
            .json(&PatchCardRequest {
                content: serde_json::to_string(card)?,
            })
            .send()
            .await?
            .json::<LarkEmptyResponse>()
            .await?;
        response.into_result()
    }
}

#[derive(Deserialize)]
struct TenantTokenResponse {
    code: i32,
    msg: String,
    tenant_access_token: Option<String>,
}

impl TenantTokenResponse {
    fn into_result(self) -> Result<String> {
        if self.code == 0 {
            self.tenant_access_token
                .ok_or_else(|| anyhow!("lark response missing tenant_access_token"))
        } else {
            Err(anyhow!("lark tenant token failed: {}", self.msg))
        }
    }
}

#[derive(Serialize)]
struct SendCardRequest<'a> {
    receive_id: &'a str,
    msg_type: &'a str,
    content: String,
}

#[derive(Deserialize)]
struct SendCardResponse {
    code: i32,
    msg: String,
    data: Option<SendCardData>,
}

#[derive(Deserialize)]
struct SendCardData {
    message_id: String,
}

impl SendCardResponse {
    fn into_result(self) -> Result<String> {
        if self.code == 0 {
            self.data
                .map(|data| data.message_id)
                .ok_or_else(|| anyhow!("lark response missing message_id"))
        } else {
            Err(anyhow!("lark send card failed: {}", self.msg))
        }
    }
}

#[derive(Serialize)]
struct PatchCardRequest {
    content: String,
}

#[derive(Deserialize)]
struct LarkEmptyResponse {
    code: i32,
    msg: String,
}

impl LarkEmptyResponse {
    fn into_result(self) -> Result<()> {
        if self.code == 0 {
            Ok(())
        } else {
            Err(anyhow!("lark patch card failed: {}", self.msg))
        }
    }
}

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
    agent_name: String,
    output: String,
    finished: bool,
    failed: bool,
}

impl LarkAgentCardState {
    fn build_card(&self) -> Value {
        let mut card = json!({
            "config": { "update_multi": true },
            "header": {
                "template": if self.failed { "red" } else if self.finished { "green" } else { "blue" },
                "title": {
                    "tag": "plain_text",
                    "content": if self.finished {
                        format!("{} completed", self.agent_name)
                    } else {
                        format!("{} is running", self.agent_name)
                    }
                }
            }
        });
        if !self.output.is_empty() {
            card["elements"] = json!([{
                "tag": "markdown",
                "content": Self::truncate_output(&self.output)
            }]);
        }
        card
    }

    fn truncate_output(output: &str) -> String {
        if output.len() <= MAX_CARD_CONTENT_BYTES {
            return output.to_string();
        }
        let marker = "[output truncated]\n\n";
        let budget = MAX_CARD_CONTENT_BYTES.saturating_sub(marker.len());
        let mut start = output.len().saturating_sub(budget);
        while !output.is_char_boundary(start) {
            start += 1;
        }
        format!("{}{}", marker, &output[start..])
    }
}

impl LarkAgentCard {
    pub fn new(target: LarkReplyTarget, agent_name: String, api: LarkApi) -> Self {
        Self {
            inner: Arc::new(LarkAgentCardInner {
                target,
                api,
                state: Mutex::new(LarkAgentCardState {
                    token: None,
                    message_id: None,
                    agent_name,
                    output: String::new(),
                    finished: false,
                    failed: false,
                }),
            }),
        }
    }
}

impl LarkAgentCard {
    async fn publish_event(&self, event: RunEvent) -> Result<()> {
        let mut state = self.inner.state.lock().await;

        match event {
            RunEvent::Started { .. } => {}
            RunEvent::OutputChunk { text } => {
                state.output.push_str(&text);
            }
            RunEvent::Completed { .. } => {
                state.finished = true;
            }
            RunEvent::Failed { message } => {
                state.finished = true;
                state.failed = true;
                if !state.output.is_empty() {
                    state.output.push_str("\n\n");
                }
                state
                    .output
                    .push_str(format!("Failed: `{}`.", message).as_str());
            }
        }

        if state.token.is_none() {
            state.token = Some(self.inner.api.tenant_access_token().await?);
        }
        let token = state
            .token
            .as_deref()
            .ok_or_else(|| anyhow!("lark tenant token initialization failed"))?;
        let card = state.build_card();

        if let Some(message_id) = state.message_id.as_deref() {
            self.inner.api.patch_card(token, message_id, &card).await
        } else {
            state.message_id = Some(
                self.inner
                    .api
                    .send_card(token, &self.inner.target, &card)
                    .await?,
            );
            Ok(())
        }
    }
}

impl ChannelRun for LarkAgentCard {
    async fn publish(&self, event: RunEvent) -> Result<()> {
        self.publish_event(event).await
    }
}
