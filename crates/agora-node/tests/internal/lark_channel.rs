use super::channel::{LarkChannel, LarkEvent, LarkInterruptCallbacks};
use super::lark_api::{
    LarkApi, LarkFrame, LarkFrameHeader, LarkReconnectBackoff, LarkWebSocketEndpointResponse,
};
use crate::channel::{ChannelTask, InterruptCallback};
use crate::config::LarkChannelConfig;
use crate::task::{CommandRequest, TaskAttachmentKind};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn parses_lark_message_receive_event_payload() {
    let LarkEvent::Message(event) = LarkEvent::from_lark_event_payload(
        r#"{
            "schema": "2.0",
            "header": {
                "event_id": "evt_1",
                "event_type": "im.message.receive_v1",
                "create_time": "1608725989000",
                "tenant_key": "tenant_1"
            },
            "event": {
                "sender": {
                    "sender_id": {
                        "open_id": "ou_123"
                    },
                    "sender_type": "user"
                },
                "message": {
                    "message_id": "om_123",
                    "chat_id": "oc_123",
                    "chat_type": "group",
                    "message_type": "text",
                    "content": "{\"text\":\"run tests\"}"
                }
            }
        }"#,
    )
    .unwrap() else {
        panic!("receive event should contain a message");
    };

    assert_eq!(event.id, "evt_1");
    assert_eq!(event.message_id, "om_123");
    assert_eq!(event.session_id(), "oc_123");
    assert_eq!(event.input(), "run tests");
    assert_eq!(event.reply_target().message_id, "om_123");
}

#[test]
fn parses_lark_post_text_and_image_references() {
    let LarkEvent::Message(event) = LarkEvent::from_lark_event_payload(
        r#"{
            "schema": "2.0",
            "header": {
                "event_id": "evt_post_1",
                "event_type": "im.message.receive_v1"
            },
            "event": {
                "sender": {"sender_id": {"open_id": "ou_123"}},
                "message": {
                    "message_id": "om_post_1",
                    "chat_id": "oc_123",
                    "chat_type": "group",
                    "message_type": "post",
                    "content": "{\"title\":\"\",\"content\":[[{\"tag\":\"img\",\"image_key\":\"img_trace\"}],[{\"tag\":\"text\",\"text\":\"analyze this image\"}]]}"
                }
            }
        }"#,
    )
    .unwrap() else {
        panic!("receive event should contain a message");
    };

    assert_eq!(event.input(), "analyze this image");
    assert_eq!(event.image_keys(), &["img_trace"]);
    assert!(event.is_supported_message());
}

#[test]
fn accepts_a_standalone_lark_image_message() {
    let LarkEvent::Message(event) = LarkEvent::from_lark_event_payload(
        r#"{
            "schema": "2.0",
            "header": {
                "event_id": "evt_image_1",
                "event_type": "im.message.receive_v1"
            },
            "event": {
                "sender": {"sender_id": {"open_id": "ou_123"}},
                "message": {
                    "message_id": "om_image_1",
                    "chat_id": "oc_123",
                    "chat_type": "group",
                    "message_type": "image",
                    "content": "{\"image_key\":\"img_standalone\"}"
                }
            }
        }"#,
    )
    .unwrap() else {
        panic!("receive event should contain a message");
    };

    assert_eq!(event.input(), "");
    assert_eq!(event.image_keys(), &["img_standalone"]);
    assert!(event.is_supported_message());
}

#[tokio::test]
async fn downloads_a_lark_message_image_resource() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut buffer = [0_u8; 1024];
            let size = stream.read(&mut buffer).await.unwrap();
            if size == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..size]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with(
            "GET /open-apis/im/v1/messages/om_post_1/resources/img_trace?type=image HTTP/1.1"
        ));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer token")
        );

        let body = b"image-bytes";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    });
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        base_url,
    )
    .unwrap();

    let image = api
        .download_message_image("token", "om_post_1", "img_trace")
        .await
        .unwrap();

    assert_eq!(image.media_type, "image/png");
    assert_eq!(image.data, b"image-bytes");
    server.await.unwrap();
}

#[tokio::test]
async fn resolves_lark_post_images_into_task_attachments() {
    let LarkEvent::Message(event) = LarkEvent::from_lark_event_payload(
        r#"{
            "schema": "2.0",
            "header": {"event_id": "evt_post_1", "event_type": "im.message.receive_v1"},
            "event": {
                "sender": {"sender_id": {"open_id": "ou_123"}},
                "message": {
                    "message_id": "om_post_1",
                    "chat_id": "oc_123",
                    "chat_type": "group",
                    "message_type": "post",
                    "content": "{\"title\":\"\",\"content\":[[{\"tag\":\"img\",\"image_key\":\"img_trace\"}],[{\"tag\":\"text\",\"text\":\"analyze this image\"}]]}"
                }
            }
        }"#,
    )
    .unwrap() else {
        panic!("receive event should contain a message");
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0_u8; 1024];
                let size = stream.read(&mut buffer).await.unwrap();
                if size == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..size]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            let (content_type, body) = if request.contains("tenant_access_token/internal") {
                (
                    "application/json",
                    br#"{"code":0,"msg":"ok","tenant_access_token":"token"}"#.as_slice(),
                )
            } else {
                assert!(request.contains(
                    "/open-apis/im/v1/messages/om_post_1/resources/img_trace?type=image"
                ));
                ("image/png", b"image-bytes".as_slice())
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        }
    });
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        base_url,
    )
    .unwrap();
    let channel = LarkChannel::with_api(api);

    let task = channel.task_from_event(event).await.unwrap();

    let content = task.input().message().unwrap();
    assert_eq!(content.text(), "analyze this image");
    let [image] = content.attachments() else {
        panic!("task should contain one image");
    };
    assert_eq!(image.kind(), TaskAttachmentKind::Image);
    assert_eq!(image.file_name(), "lark-image-1.png");
    assert_eq!(image.media_type(), "image/png");
    assert_eq!(image.data(), b"image-bytes");
    server.await.unwrap();
}

#[test]
fn ignores_lark_events_that_are_not_agent_tasks() {
    let event = LarkEvent::from_lark_event_payload(
        r#"{
            "schema": "2.0",
            "header": {
                "event_id": "evt_read_1",
                "event_type": "im.message.message_read_v1"
            },
            "event": {
                "message_id_list": ["om_bot_1"],
                "reader": {
                    "reader_id": {"open_id": "ou_123"},
                    "read_time": "1608725989000",
                    "tenant_key": "tenant_1"
                }
            }
        }"#,
    )
    .unwrap();

    assert_eq!(
        event,
        LarkEvent::Ignore {
            event_type: "im.message.message_read_v1".to_string()
        }
    );
}

#[test]
fn parses_lark_interrupt_card_action() {
    let LarkEvent::Interrupt(event) = LarkEvent::from_lark_event_payload(
        r#"{
            "schema": "2.0",
            "header": {
                "event_id": "evt_action_1",
                "event_type": "card.action.trigger"
            },
            "event": {
                "operator": {"open_id": "ou_123"},
                "action": {
                    "tag": "button",
                    "value": {
                        "agora_interrupt": "interrupt-42"
                    }
                },
                "context": {
                    "open_message_id": "om_card_1",
                    "open_chat_id": "oc_123"
                }
            }
        }"#,
    )
    .unwrap() else {
        panic!("card action should contain an interrupt action");
    };

    assert_eq!(event.id, "evt_action_1");
    assert_eq!(event.callback_id, "interrupt-42");
}

#[test]
fn lark_interrupt_callbacks_are_one_shot_and_removed_with_their_registration() {
    let callbacks = LarkInterruptCallbacks::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = Arc::clone(&calls);
    let registration = callbacks.register(InterruptCallback::new(move || {
        callback_calls.fetch_add(1, Ordering::Relaxed);
        true
    }));
    let callback_id = registration.id().to_string();

    assert!(callbacks.trigger(&callback_id));
    assert!(!callbacks.trigger(&callback_id));
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let registration = callbacks.register(InterruptCallback::new(|| true));
    let callback_id = registration.id().to_string();
    drop(registration);
    assert!(!callbacks.trigger(&callback_id));
}

#[test]
fn parses_lark_agent_enabled_card_action() {
    let LarkEvent::CardAction(event) = LarkEvent::from_lark_event_payload(
        r#"{
            "schema": "2.0",
            "header": {
                "event_id": "evt_action_2",
                "event_type": "card.action.trigger"
            },
            "event": {
                "operator": {"open_id": "ou_123"},
                "action": {
                    "tag": "button",
                    "value": {
                        "agora_command": {
                            "path": ["ask", "enable"],
                            "arguments": {
                                "agent_name": "reviewer"
                            }
                        }
                    }
                },
                "context": {
                    "open_message_id": "om_card_2",
                    "open_chat_id": "oc_123"
                }
            }
        }"#,
    )
    .unwrap() else {
        panic!("card action should contain an agent-enabled action");
    };

    assert_eq!(event.message_id, "om_card_2");
    assert_eq!(
        event.command,
        CommandRequest::new(["ask", "enable"]).with_argument("agent_name", "reviewer")
    );
}

#[test]
fn parses_lark_websocket_endpoint_response_from_official_api_shape() {
    let endpoint: LarkWebSocketEndpointResponse = serde_json::from_str(
        r#"{
            "code": 0,
            "msg": "ok",
            "data": {
                "URL": "wss://example.com/ws?device_id=device-1&service_id=1001",
                "ClientConfig": {
                    "ReconnectCount": -1,
                    "ReconnectInterval": 120,
                    "ReconnectNonce": 30,
                    "PingInterval": 120
                }
            }
        }"#,
    )
    .unwrap();

    assert_eq!(endpoint.code, 0);
    assert_eq!(
        endpoint.data.unwrap().url,
        "wss://example.com/ws?device_id=device-1&service_id=1001"
    );
}

#[test]
fn lark_frame_ack_preserves_official_message_headers() {
    let frame = LarkFrame {
        seq_id: 7,
        log_id: 11,
        service: 1001,
        method: 1,
        headers: vec![
            LarkFrameHeader::new("type", "event"),
            LarkFrameHeader::new("message_id", "msg_1"),
            LarkFrameHeader::new("trace_id", "trace_1"),
        ],
        payload_encoding: String::new(),
        payload_type: String::new(),
        payload: br#"{"schema":"2.0","header":{"event_id":"evt_1","event_type":"im.message.receive_v1"},"event":{"sender":{"sender_id":{"open_id":"ou_123"}},"message":{"message_id":"om_123","chat_id":"oc_123","chat_type":"group","message_type":"text","content":"{\"text\":\"hello\"}"}}}"#.to_vec(),
        log_id_new: String::new(),
    };

    let ack = frame.into_ack(200, 12).unwrap();
    assert_eq!(ack.method, 1);
    assert_eq!(ack.header("type"), Some("event"));
    assert_eq!(ack.header("message_id"), Some("msg_1"));
    assert_eq!(ack.header("trace_id"), Some("trace_1"));
    assert_eq!(ack.header("biz_rt"), Some("12"));
    assert_eq!(
        serde_json::from_slice::<Value>(&ack.payload).unwrap(),
        serde_json::json!({
            "code": 200,
            "headers": null,
            "data": null
        })
    );
}

#[test]
fn lark_reconnect_backoff_retries_forever_with_a_cap() {
    let mut backoff = LarkReconnectBackoff::default();

    assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    assert_eq!(backoff.next_delay(), Duration::from_secs(2));
    assert_eq!(backoff.next_delay(), Duration::from_secs(4));

    let mut last = Duration::ZERO;
    for _ in 0..10 {
        last = backoff.next_delay();
    }
    assert_eq!(last, Duration::from_secs(60));

    backoff.reset();
    assert_eq!(backoff.next_delay(), Duration::from_secs(1));
}

#[test]
fn lark_card_body_does_not_repeat_run_status() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/channel/lark/card.rs"),
    )
    .unwrap();

    assert!(!source.contains("Run `{}` started."));
    assert!(!source.contains("Completed with exit code"));
    assert!(!source.contains("Waiting for output."));
}

#[test]
fn lark_card_uses_the_message_reply_api() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/channel/lark/lark_api.rs"),
    )
    .unwrap();

    assert!(source.contains("/open-apis/im/v1/messages/{}/reply"));
    assert!(!source.contains("receive_id_type"));
}
