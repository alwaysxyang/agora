use agora_node::channel::lark::{
    LarkEvent, LarkFrame, LarkFrameHeader, LarkReconnectBackoff, LarkWebSocketEndpointResponse,
};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

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
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/channel/lark.rs"))
            .unwrap();

    assert!(!source.contains("Run `{}` started."));
    assert!(!source.contains("Completed with exit code"));
    assert!(!source.contains("Waiting for output."));
}

#[test]
fn lark_card_uses_the_message_reply_api() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/channel/lark.rs"))
            .unwrap();

    assert!(source.contains("/open-apis/im/v1/messages/{}/reply"));
    assert!(!source.contains("receive_id_type"));
}
