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
