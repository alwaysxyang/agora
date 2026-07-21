use super::LarkReplyTarget;
use super::channel::LarkEvent;
use crate::config::LarkChannelConfig;
use agora_core::logger;
use anyhow::{Context, Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use reqwest::Client;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WebSocketMessage;

const LARK_OPENAPI: &str = "https://open.feishu.cn";
const LARK_WS_ENDPOINT_PATH: &str = "/callback/ws/endpoint";
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

#[derive(Clone)]
pub(super) struct LarkApi {
    name: String,
    app_id: String,
    secret: String,
    client: Client,
    base_url: String,
}

pub(super) struct LarkImageResource {
    pub(super) media_type: String,
    pub(super) data: Vec<u8>,
}

impl LarkApi {
    pub(super) fn new(config: LarkChannelConfig) -> Result<Self> {
        Self::with_base_url(config, LARK_OPENAPI.to_string())
    }

    pub(super) fn with_base_url(config: LarkChannelConfig, base_url: String) -> Result<Self> {
        Ok(Self {
            name: config.name,
            app_id: config.app_id,
            secret: config.secret,
            client: Self::http_client()?,
            base_url,
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) async fn run_websocket_loop(
        &self,
        events: mpsc::UnboundedSender<Result<LarkEvent>>,
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
        events: mpsc::UnboundedSender<Result<LarkEvent>>,
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
                "AppID": self.app_id,
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
        events: &mpsc::UnboundedSender<Result<LarkEvent>>,
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
        events: &mpsc::UnboundedSender<Result<LarkEvent>>,
    ) -> Result<Option<LarkFrame>> {
        if frame.header("type") != Some(LARK_MESSAGE_TYPE_EVENT) {
            return Ok(None);
        }

        let started = Instant::now();
        let status_code = match LarkEvent::from_lark_event_payload(&frame.payload) {
            Ok(
                event
                @ (LarkEvent::Message(_) | LarkEvent::CardAction(_) | LarkEvent::Interrupt(_)),
            ) => {
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
        events: &mpsc::UnboundedSender<Result<LarkEvent>>,
        event: LarkEvent,
    ) -> Result<()> {
        events
            .send(Ok(event))
            .map_err(|_| anyhow!("agora lark receiver closed"))
    }

    pub(super) async fn tenant_access_token(&self) -> Result<String> {
        let response = self
            .client
            .post(format!(
                "{}/open-apis/auth/v3/tenant_access_token/internal",
                self.base_url
            ))
            .json(&json!({
                "app_id": self.app_id,
                "app_secret": self.secret,
            }))
            .send()
            .await?
            .json::<TenantTokenResponse>()
            .await?;
        response.into_result()
    }

    pub(super) async fn download_message_image(
        &self,
        token: &str,
        message_id: &str,
        image_key: &str,
    ) -> Result<LarkImageResource> {
        let response = self
            .client
            .get(format!(
                "{}/open-apis/im/v1/messages/{}/resources/{}",
                self.base_url, message_id, image_key
            ))
            .query(&[("type", "image")])
            .bearer_auth(token)
            .send()
            .await
            .context("download lark message image failed")?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("download lark message image http failed: {status}"));
        }
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or("application/octet-stream")
            .to_string();
        let data = response
            .bytes()
            .await
            .context("read lark message image failed")?
            .to_vec();
        Ok(LarkImageResource { media_type, data })
    }

    pub(super) async fn reply_card(
        &self,
        token: &str,
        target: &LarkReplyTarget,
        card: &Value,
    ) -> Result<String> {
        self.reply_message(token, target, "interactive", serde_json::to_string(card)?)
            .await
    }

    pub(super) async fn reply_text(
        &self,
        token: &str,
        target: &LarkReplyTarget,
        text: &str,
    ) -> Result<()> {
        self.reply_message(
            token,
            target,
            "text",
            serde_json::to_string(&json!({ "text": text }))?,
        )
        .await?;
        Ok(())
    }

    async fn reply_message(
        &self,
        token: &str,
        target: &LarkReplyTarget,
        msg_type: &str,
        content: String,
    ) -> Result<String> {
        let response = self
            .client
            .post(format!(
                "{}/open-apis/im/v1/messages/{}/reply",
                self.base_url, target.message_id
            ))
            .bearer_auth(token)
            .json(&ReplyMessageRequest {
                msg_type,
                content,
                reply_in_thread: true,
            })
            .send()
            .await?
            .json::<SendCardResponse>()
            .await?;
        response.into_result()
    }

    pub(super) async fn patch_card(
        &self,
        token: &str,
        message_id: &str,
        card: &Value,
    ) -> Result<()> {
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct LarkWebSocketEndpointResponse {
    pub(super) code: i32,
    #[serde(default)]
    pub(super) msg: String,
    pub(super) data: Option<LarkWebSocketEndpoint>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub(super) struct LarkWebSocketEndpoint {
    #[serde(rename = "URL")]
    pub(super) url: String,
    #[serde(default)]
    pub(super) client_config: Option<LarkWebSocketClientConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub(super) struct LarkWebSocketClientConfig {
    #[serde(default)]
    pub(super) reconnect_count: i32,
    #[serde(default)]
    pub(super) reconnect_interval: i32,
    #[serde(default)]
    pub(super) reconnect_nonce: i32,
    #[serde(default)]
    pub(super) ping_interval: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LarkReconnectBackoff {
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
    pub(super) fn next_delay(&mut self) -> Duration {
        let delay = self.next_delay;
        self.next_delay = self
            .next_delay
            .saturating_mul(2)
            .min(Duration::from_secs(LARK_RECONNECT_MAX_DELAY_SECONDS));
        delay
    }

    pub(super) fn reset(&mut self) {
        self.next_delay = Duration::from_secs(LARK_RECONNECT_INITIAL_DELAY_SECONDS);
    }
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct LarkFrameHeader {
    #[prost(string, tag = "1")]
    pub(super) key: String,
    #[prost(string, tag = "2")]
    pub(super) value: String,
}

impl LarkFrameHeader {
    pub(super) fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct LarkFrame {
    #[prost(uint64, tag = "1")]
    pub(super) seq_id: u64,
    #[prost(uint64, tag = "2")]
    pub(super) log_id: u64,
    #[prost(int32, tag = "3")]
    pub(super) service: i32,
    #[prost(int32, tag = "4")]
    pub(super) method: i32,
    #[prost(message, repeated, tag = "5")]
    pub(super) headers: Vec<LarkFrameHeader>,
    #[prost(string, tag = "6")]
    pub(super) payload_encoding: String,
    #[prost(string, tag = "7")]
    pub(super) payload_type: String,
    #[prost(bytes, tag = "8")]
    pub(super) payload: Vec<u8>,
    #[prost(string, tag = "9")]
    pub(super) log_id_new: String,
}

impl LarkFrame {
    pub(super) fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.key == key)
            .map(|header| header.value.as_str())
    }

    pub(super) fn into_ack(mut self, status_code: u16, biz_rt_ms: u128) -> Result<Self> {
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
struct ReplyMessageRequest<'a> {
    msg_type: &'a str,
    content: String,
    reply_in_thread: bool,
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
            Err(anyhow!("lark reply message failed: {}", self.msg))
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
