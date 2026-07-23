use super::*;

#[tokio::test]
async fn telegram_api_gets_identity_and_polls_message_updates() {
    let server = HttpMockServer::start_json_queue([
        r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
        r#"{"ok":true,"result":[{"update_id":201,"message":{"message_id":9,"chat":{"id":1,"type":"private"},"text":"hello"}}]}"#,
    ])
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    assert_eq!(api.bot_username().await.unwrap(), "agora_bot");
    let updates = api.get_updates(Some(42)).await.unwrap();

    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0]["update_id"], 201);
    let requests = server.requests().await;
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/bot123456:secret/getMe");
    assert_eq!(requests[1].path, "/bot123456:secret/getUpdates");
    let poll: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
    assert_eq!(poll["offset"], 42);
    assert_eq!(poll["timeout"], 50);
    assert_eq!(poll["allowed_updates"], serde_json::json!(["message"]));
}

#[tokio::test]
async fn telegram_api_retries_after_rate_limit() {
    let server = HttpMockServer::start_json_queue([
        r#"{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":0}}"#,
        r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
    ])
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    assert_eq!(api.bot_username().await.unwrap(), "agora_bot");
    assert_eq!(server.requests().await.len(), 2);
}

#[tokio::test]
async fn telegram_api_errors_do_not_expose_the_bot_token() {
    let server = HttpMockServer::start_json_queue([
        r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
    ])
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    let error = api.bot_username().await.unwrap_err().to_string();

    assert!(error.contains("getMe"));
    assert!(error.contains("401"));
    assert!(error.contains("Unauthorized"));
    assert!(!error.contains("123456:secret"));
}

#[tokio::test]
async fn telegram_transport_errors_do_not_expose_the_bot_token() {
    let server = HttpMockServer::start_json_queue(["not-json"]).await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    let error = api.bot_username().await.unwrap_err();
    let report = format!("{error:#}");

    assert!(report.contains("getMe"));
    assert!(!report.contains("123456:secret"));
}

#[tokio::test]
async fn telegram_api_replies_to_the_source_message_and_topic() {
    let server =
        HttpMockServer::start_json_queue([r#"{"ok":true,"result":{"message_id":88}}"#]).await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();
    let target = TelegramReplyTarget {
        chat_id: -1001,
        message_id: 12,
        message_thread_id: Some(44),
        is_private: false,
    };

    api.reply_text(&target, "Reset successful.").await.unwrap();

    let requests = server.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/bot123456:secret/sendMessage");
    let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(body["chat_id"], -1001);
    assert_eq!(body["message_thread_id"], 44);
    assert_eq!(body["reply_parameters"]["message_id"], 12);
    assert_eq!(body["text"], "Reset successful.");
}

#[tokio::test]
async fn telegram_channel_returns_supported_updates_in_order_and_advances_offset() {
    let server = HttpMockServer::start_json_queue([
        r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
        r#"{"ok":true,"result":[
            {"update_id":301,"message":{"message_id":21,"chat":{"id":1,"type":"private"},"text":"first"}},
            {"update_id":302,"message":{"message_id":22,"chat":{"id":1,"type":"private"},"photo":[{"file_id":"photo-1"}]}},
            {"update_id":303,"message":{"message_id":23,"message_thread_id":44,"chat":{"id":-1001,"type":"supergroup"},"text":"second"}}
        ]}"#,
        r#"{"ok":true,"result":[
            {"update_id":304,"message":{"message_id":24,"chat":{"id":1,"type":"private"},"text":"third"}}
        ]}"#,
    ])
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();
    let mut channel = TelegramChannel::with_api(api);

    let first = channel.next_task().await.unwrap();
    let second = channel.next_task().await.unwrap();
    let third = channel.next_task().await.unwrap();

    assert_eq!(first.input().message().unwrap().text(), "first");
    assert_eq!(second.input().message().unwrap().text(), "second");
    assert_eq!(third.input().message().unwrap().text(), "third");
    let requests = server.requests().await;
    assert_eq!(requests.len(), 3);
    let second_poll: serde_json::Value = serde_json::from_str(&requests[2].body).unwrap();
    assert_eq!(second_poll["offset"], 304);
}
