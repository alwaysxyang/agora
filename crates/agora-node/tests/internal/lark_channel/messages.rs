use super::*;

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
