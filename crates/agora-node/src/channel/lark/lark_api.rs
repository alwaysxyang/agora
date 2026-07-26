use super::LarkReplyTarget;
use super::channel::LarkEvent;
use super::proxy;
use crate::config::LarkChannelConfig;
use crate::http;
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
use tokio_tungstenite::tungstenite::Message as WebSocketMessage;
use tokio_tungstenite::{client_async_tls, connect_async};

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
    proxy: Option<crate::config::HttpProxy>,
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
        let client = Self::http_client(config.proxy.as_ref())?;
        Ok(Self {
            name: config.name,
            app_id: config.app_id,
            secret: config.secret,
            client,
            base_url,
            proxy: config.proxy,
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

        let (mut socket, _) = match &self.proxy {
            Some(proxy) => {
                let stream = proxy::connect_tunnel(proxy, &endpoint_url).await?;
                client_async_tls(endpoint_url.as_str(), stream).await
            }
            None => connect_async(endpoint_url.as_str()).await,
        }
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
        let url = format!("{}{LARK_WS_ENDPOINT_PATH}", self.base_url);
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

    fn http_client(proxy: Option<&crate::config::HttpProxy>) -> Result<Client> {
        let builder = Client::builder()
            .pool_max_idle_per_host(LARK_HTTP_MAX_IDLE_CONNECTIONS_PER_HOST)
            .pool_idle_timeout(Some(Duration::from_secs(LARK_HTTP_IDLE_TIMEOUT_SECONDS)))
            .connect_timeout(Duration::from_secs(LARK_HTTP_CONNECT_TIMEOUT_SECONDS))
            .timeout(Duration::from_secs(LARK_HTTP_REQUEST_TIMEOUT_SECONDS));
        http::client(builder, proxy).context("build lark http client failed")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::test_http::{HttpMockServer, MockResponse};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    fn config() -> LarkChannelConfig {
        LarkChannelConfig {
            name: "lark-api-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
            proxy: None,
        }
    }

    fn event_frame(payload: impl Into<Vec<u8>>) -> LarkFrame {
        LarkFrame {
            seq_id: 7,
            log_id: 8,
            service: 1001,
            method: LARK_FRAME_TYPE_DATA,
            headers: vec![LarkFrameHeader::new("type", LARK_MESSAGE_TYPE_EVENT)],
            payload_encoding: String::new(),
            payload_type: String::new(),
            payload: payload.into(),
            log_id_new: String::new(),
        }
    }

    fn message_event_payload() -> Vec<u8> {
        br#"{"schema":"2.0","header":{"event_id":"evt_1","event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_1"}},"message":{"message_id":"om_1","chat_id":"oc_1","chat_type":"group","message_type":"text","content":"{\"text\":\"hello\"}"}}}"#.to_vec()
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        loop {
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
            else {
                continue;
            };
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or_default();
            if request.len() >= header_end + content_length {
                return String::from_utf8(request).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn websocket_once_forwards_events_and_answers_ack_ping_and_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let websocket_url = format!("ws://{}/?service_id=1001", listener.local_addr().unwrap());
        let endpoint = HttpMockServer::start({
            let websocket_url = websocket_url.clone();
            move |_| {
                MockResponse::json(format!(
                    r#"{{"code":0,"msg":"ok","data":{{"URL":"{websocket_url}","ClientConfig":{{"PingInterval":3600}}}}}}"#
                ))
            }
        })
        .await;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            socket
                .send(WebSocketMessage::Binary(
                    event_frame(message_event_payload()).encode_to_vec().into(),
                ))
                .await
                .unwrap();

            loop {
                let message = socket.next().await.unwrap().unwrap();
                if let WebSocketMessage::Binary(payload) = message {
                    let frame = LarkFrame::decode(payload).unwrap();
                    if frame.method == LARK_FRAME_TYPE_DATA {
                        assert_eq!(
                            serde_json::from_slice::<Value>(&frame.payload).unwrap()["code"],
                            200
                        );
                        break;
                    }
                }
            }

            socket
                .send(WebSocketMessage::Ping(vec![1, 2, 3].into()))
                .await
                .unwrap();
            loop {
                if matches!(
                    socket.next().await.unwrap().unwrap(),
                    WebSocketMessage::Pong(_)
                ) {
                    break;
                }
            }
            socket.send(WebSocketMessage::Close(None)).await.unwrap();
        });
        let api = LarkApi::with_base_url(config(), endpoint.base_url()).unwrap();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let mut connected = false;

        api.run_websocket_once(sender, &mut connected)
            .await
            .unwrap();

        assert!(connected);
        assert!(matches!(
            receiver.recv().await.unwrap().unwrap(),
            LarkEvent::Message(_)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn websocket_once_uses_the_configured_proxy_for_http_and_websocket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut endpoint_stream, _) = listener.accept().await.unwrap();
            let endpoint_request = read_http_request(&mut endpoint_stream).await;
            assert!(
                endpoint_request
                    .starts_with("POST http://lark.openapi.test/callback/ws/endpoint HTTP/1.1\r\n")
            );
            assert!(
                endpoint_request
                    .to_ascii_lowercase()
                    .contains("proxy-authorization: basic dxnlcjpwyxnzd29yza==\r\n")
            );
            let body = r#"{"code":0,"msg":"ok","data":{"URL":"ws://lark.websocket.test/?service_id=1001","ClientConfig":{"PingInterval":3600}}}"#;
            endpoint_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            let (mut websocket_stream, _) = listener.accept().await.unwrap();
            let connect_request = read_http_request(&mut websocket_stream).await;
            assert!(connect_request.starts_with("CONNECT lark.websocket.test:80 HTTP/1.1\r\n"));
            assert!(
                connect_request
                    .to_ascii_lowercase()
                    .contains("proxy-authorization: basic dxnlcjpwyxnzd29yza==\r\n")
            );
            websocket_stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut socket = accept_async(websocket_stream).await.unwrap();
            socket.send(WebSocketMessage::Close(None)).await.unwrap();
        });
        let mut config = config();
        config.proxy = Some(format!("user:password@{proxy_address}").parse().unwrap());
        let api = LarkApi::with_base_url(config, "http://lark.openapi.test".to_string()).unwrap();
        let (sender, _) = mpsc::unbounded_channel();
        let mut connected = false;

        api.run_websocket_once(sender, &mut connected)
            .await
            .unwrap();

        assert!(connected);
        server.await.unwrap();
    }

    #[test]
    fn websocket_frame_routing_handles_control_unknown_ignore_invalid_and_closed_receivers() {
        let api = LarkApi::with_base_url(config(), "http://127.0.0.1:1".to_string()).unwrap();
        let (sender, mut receiver) = mpsc::unbounded_channel();

        assert!(api.handle_websocket_binary(b"invalid", &sender).is_err());

        let mut control = LarkFrame::ping(42);
        assert_eq!(control.header("type"), Some("ping"));
        assert!(
            api.handle_websocket_binary(&control.encode_to_vec(), &sender)
                .unwrap()
                .is_none()
        );
        control.method = 99;
        assert!(
            api.handle_websocket_binary(&control.encode_to_vec(), &sender)
                .unwrap()
                .is_none()
        );

        let mut not_event = event_frame(Vec::new());
        not_event.headers = vec![LarkFrameHeader::new("type", "other")];
        assert!(
            api.handle_websocket_binary(&not_event.encode_to_vec(), &sender)
                .unwrap()
                .is_none()
        );

        let ignored =
            event_frame(br#"{"header":{"event_id":"evt_ignore","event_type":"other"}}"#.to_vec());
        let ack = api
            .handle_websocket_binary(&ignored.encode_to_vec(), &sender)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&ack.payload).unwrap()["code"],
            200
        );

        let invalid = event_frame(br#"{"header":{}}"#.to_vec());
        let ack = api
            .handle_websocket_binary(&invalid.encode_to_vec(), &sender)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&ack.payload).unwrap()["code"],
            500
        );

        let message = event_frame(message_event_payload());
        api.handle_websocket_binary(&message.encode_to_vec(), &sender)
            .unwrap();
        assert!(matches!(
            receiver.try_recv().unwrap().unwrap(),
            LarkEvent::Message(_)
        ));
        drop(receiver);
        assert!(
            api.handle_websocket_binary(&message.encode_to_vec(), &sender)
                .is_err()
        );
    }

    #[tokio::test]
    async fn websocket_endpoint_validates_http_application_and_data_responses() {
        let server = HttpMockServer::start_json_queue([
            r#"{"code":0,"msg":"ok","data":{"URL":"ws://127.0.0.1:9"}}"#,
            r#"{"code":7,"msg":"denied","data":null}"#,
            r#"{"code":0,"msg":"ok","data":null}"#,
            "not-json",
        ])
        .await;
        let api = LarkApi::with_base_url(config(), server.base_url()).unwrap();

        let (url, client_config) = api.websocket_endpoint().await.unwrap();
        assert_eq!(url, "ws://127.0.0.1:9");
        assert_eq!(client_config, LarkWebSocketClientConfig::default());
        assert!(
            api.websocket_endpoint()
                .await
                .unwrap_err()
                .to_string()
                .contains("code=7")
        );
        assert!(
            api.websocket_endpoint()
                .await
                .unwrap_err()
                .to_string()
                .contains("missing data")
        );
        assert!(
            api.websocket_endpoint()
                .await
                .unwrap_err()
                .to_string()
                .contains("parse")
        );

        let server =
            HttpMockServer::start(|_| MockResponse::json("server error").with_status(503)).await;
        let api = LarkApi::with_base_url(config(), server.base_url()).unwrap();
        assert!(
            api.websocket_endpoint()
                .await
                .unwrap_err()
                .to_string()
                .contains("503")
        );
    }

    #[tokio::test]
    async fn lark_http_results_cover_missing_fields_errors_and_binary_defaults() {
        let token_missing: TenantTokenResponse =
            serde_json::from_str(r#"{"code":0,"msg":"ok","tenant_access_token":null}"#).unwrap();
        assert!(
            token_missing
                .into_result()
                .unwrap_err()
                .to_string()
                .contains("missing")
        );
        let token_error: TenantTokenResponse =
            serde_json::from_str(r#"{"code":1,"msg":"denied"}"#).unwrap();
        assert!(
            token_error
                .into_result()
                .unwrap_err()
                .to_string()
                .contains("denied")
        );

        let reply_missing: SendCardResponse =
            serde_json::from_str(r#"{"code":0,"msg":"ok","data":null}"#).unwrap();
        assert!(
            reply_missing
                .into_result()
                .unwrap_err()
                .to_string()
                .contains("message_id")
        );
        let reply_error: SendCardResponse =
            serde_json::from_str(r#"{"code":1,"msg":"denied","data":null}"#).unwrap();
        assert!(
            reply_error
                .into_result()
                .unwrap_err()
                .to_string()
                .contains("denied")
        );

        let patch_ok: LarkEmptyResponse = serde_json::from_str(r#"{"code":0,"msg":"ok"}"#).unwrap();
        patch_ok.into_result().unwrap();
        let patch_error: LarkEmptyResponse =
            serde_json::from_str(r#"{"code":1,"msg":"denied"}"#).unwrap();
        assert!(
            patch_error
                .into_result()
                .unwrap_err()
                .to_string()
                .contains("denied")
        );

        assert_eq!(LarkApi::query_param("ws://host/path", "service_id"), None);
        assert_eq!(
            LarkApi::query_param("ws://host/path?bad&service_id=42", "service_id"),
            Some("42".to_string())
        );
        assert_eq!(
            LarkApi::query_param("ws://host/path?other=1", "service_id"),
            None
        );

        let server = HttpMockServer::start(|request| {
            if request.path.contains("missing") {
                MockResponse::json("missing").with_status(404)
            } else {
                MockResponse::bytes(b"raw-image".to_vec(), "invalid content type")
            }
        })
        .await;
        let api = LarkApi::with_base_url(config(), server.base_url()).unwrap();
        let image = api
            .download_message_image("token", "message", "raw")
            .await
            .unwrap();
        assert_eq!(image.media_type, "invalid content type");
        assert_eq!(image.data, b"raw-image");
        assert!(
            api.download_message_image("token", "message", "missing")
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("404")
        );
    }
}
