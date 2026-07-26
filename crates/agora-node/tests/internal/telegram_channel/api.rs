use super::*;

#[tokio::test]
async fn telegram_api_uses_an_authenticated_http_proxy() {
    let proxy = HttpMockServer::start_json_queue([
        r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
    ])
    .await;
    let mut config = telegram_config();
    config.proxy = Some(
        format!(
            "user:password@{}",
            proxy.base_url().trim_start_matches("http://")
        )
        .parse()
        .unwrap(),
    );
    let api = TelegramApi::with_base_url(config, "http://telegram.invalid".to_string()).unwrap();

    assert_eq!(api.bot_username().await.unwrap(), "agora_bot");

    let requests = proxy.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path,
        "http://telegram.invalid/bot123456:secret/getMe"
    );
    assert_eq!(
        requests[0].header("proxy-authorization"),
        Some("Basic dXNlcjpwYXNzd29yZA==")
    );
}

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
    assert_eq!(
        poll["allowed_updates"],
        serde_json::json!(["message", "callback_query"])
    );
}

#[tokio::test]
async fn telegram_api_registers_bot_commands() {
    let server = HttpMockServer::start_json_queue([r#"{"ok":true,"result":true}"#]).await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    api.set_commands(&[
        TelegramBotCommand::new("stop", "停止当前任务。"),
        TelegramBotCommand::new("help", "显示所有命令。"),
    ])
    .await
    .unwrap();

    let requests = server.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/bot123456:secret/setMyCommands");
    let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(
        body["commands"],
        serde_json::json!([
            {"command": "stop", "description": "停止当前任务。"},
            {"command": "help", "description": "显示所有命令。"}
        ])
    );
}

#[tokio::test]
async fn telegram_api_rejects_false_command_registration_result() {
    let server = HttpMockServer::start_json_queue([r#"{"ok":true,"result":false}"#]).await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    let error = api
        .set_commands(&[TelegramBotCommand::new("help", "显示所有命令。")])
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "telegram setMyCommands returned false");
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
async fn telegram_api_retries_server_errors() {
    let server = HttpMockServer::start_json_queue([
        r#"{"ok":false,"error_code":500,"description":"Internal Server Error"}"#,
        r#"{"ok":false,"error_code":502,"description":"Bad Gateway"}"#,
        r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
    ])
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();

    assert_eq!(api.bot_username().await.unwrap(), "agora_bot");
    assert_eq!(server.requests().await.len(), 3);
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
async fn telegram_channel_returns_supported_updates_in_order_and_advances_offset() {
    let server = HttpMockServer::start_json_queue([
        r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
        r#"{"ok":true,"result":true}"#,
        r#"{"ok":true,"result":[
            {"update_id":301,"message":{"message_id":21,"chat":{"id":1,"type":"private"},"text":"first"}},
            {"update_id":302,"message":{"message_id":22,"chat":{"id":1,"type":"private"},"text":"   "}},
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
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[1].path, "/bot123456:secret/setMyCommands");
    let commands: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
    assert_eq!(commands["commands"].as_array().unwrap().len(), 4);
    assert_eq!(commands["commands"][0]["command"], "stop");
    assert_eq!(commands["commands"][1]["command"], "reset");
    assert_eq!(commands["commands"][2]["command"], "ask");
    assert_eq!(commands["commands"][3]["command"], "help");
    let second_poll: serde_json::Value = serde_json::from_str(&requests[3].body).unwrap();
    assert_eq!(second_poll["offset"], 304);
}

#[tokio::test]
async fn telegram_channel_downloads_the_largest_photo_as_an_attachment() {
    use crate::task::TaskAttachmentKind;

    let server = HttpMockServer::start(|request| match (request.method.as_str(), request.endpoint()) {
        ("POST", "getMe") => MockResponse::json(
            r#"{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}}"#,
        ),
        ("POST", "setMyCommands") => MockResponse::json(r#"{"ok":true,"result":true}"#),
        ("POST", "getUpdates") => MockResponse::json(
            r#"{"ok":true,"result":[{"update_id":305,"message":{"message_id":25,"chat":{"id":1,"type":"private"},"caption":"inspect","photo":[{"file_id":"small"},{"file_id":"large"}]}}]}"#,
        ),
        ("POST", "getFile") => MockResponse::json(
            r#"{"ok":true,"result":{"file_id":"large","file_unique_id":"unique","file_path":"photos/image.jpg"}}"#,
        ),
        ("GET", "image.jpg") => MockResponse::bytes(b"image-bytes".to_vec(), "image/jpeg"),
        (method, endpoint) => panic!("unexpected Telegram request {method} {endpoint}"),
    })
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();
    let mut channel = TelegramChannel::with_api(api);

    let task = channel.next_task().await.unwrap();

    let content = task.input().message().unwrap();
    assert_eq!(content.text(), "inspect");
    let [image] = content.attachments() else {
        panic!("task should contain one image");
    };
    assert_eq!(image.kind(), TaskAttachmentKind::Image);
    assert_eq!(image.file_name(), "image.jpg");
    assert_eq!(image.media_type(), "image/jpeg");
    assert_eq!(image.data(), b"image-bytes");
    let requests = server.requests().await;
    let get_file = requests
        .iter()
        .find(|request| request.endpoint() == "getFile")
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&get_file.body).unwrap()["file_id"],
        "large"
    );
    assert!(requests.iter().any(|request| {
        request.method == "GET" && request.path == "/file/bot123456:secret/photos/image.jpg"
    }));
}

#[tokio::test]
async fn telegram_channel_enqueues_command_replies_without_waiting_for_delivery() {
    let server = HttpMockServer::start(|request| {
        assert_eq!(request.endpoint(), "sendRichMessage");
        MockResponse::json(r#"{"ok":true,"result":{"message_id":88}}"#)
            .with_delay(std::time::Duration::from_millis(200))
    })
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();
    let channel = TelegramChannel::with_api(api);
    let task = TelegramUpdate::from_json(
        r#"{
            "update_id": 401,
            "message": {
                "message_id": 31,
                "chat": {"id": 1, "type": "private"},
                "text": "/help"
            }
        }"#,
    )
    .unwrap()
    .into_task("agora_bot")
    .unwrap();

    tokio::time::timeout(
        std::time::Duration::from_millis(50),
        channel.reply(&task, ChannelReply::new("**Agora 命令**")),
    )
    .await
    .expect("reply should only enqueue delivery")
    .unwrap();

    server.wait_for_endpoint_count("sendRichMessage", 1).await;
    let requests = server.requests().await;
    let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
    assert_eq!(body["rich_message"]["markdown"], "**Agora 命令**");
    assert_eq!(body["reply_parameters"]["message_id"], 31);
}

#[tokio::test]
async fn telegram_run_button_interrupts_the_run_and_is_removed_after_stop() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let server = HttpMockServer::start(|request| {
        let result = match request.endpoint() {
            "getMe" => r#"{"id":123,"is_bot":true,"first_name":"Agora","username":"agora_bot"}"#,
            "setMyCommands" | "answerCallbackQuery" => "true",
            "sendRichMessage" | "editMessageText" => r#"{"message_id":88}"#,
            "getUpdates" => {
                r#"[
                    {
                        "update_id":501,
                        "callback_query":{
                            "id":"callback-1",
                            "data":"agora_interrupt:interrupt-1"
                        }
                    },
                    {
                        "update_id":502,
                        "message":{
                            "message_id":32,
                            "chat":{"id":1,"type":"private"},
                            "text":"after stop"
                        }
                    }
                ]"#
            }
            method => panic!("unexpected Telegram method {method}"),
        };
        MockResponse::json(format!(r#"{{"ok":true,"result":{result}}}"#))
    })
    .await;
    let api = TelegramApi::with_base_url(telegram_config(), server.base_url()).unwrap();
    let mut channel = TelegramChannel::with_api(api);
    let source = TelegramUpdate::from_json(
        r#"{
            "update_id": 500,
            "message": {
                "message_id": 31,
                "chat": {"id": 1, "type": "private"},
                "text": "run"
            }
        }"#,
    )
    .unwrap()
    .into_task("agora_bot")
    .unwrap();
    let interrupted = Arc::new(AtomicBool::new(false));
    let callback_interrupted = Arc::clone(&interrupted);
    let run = channel
        .open_run(
            &source,
            ChannelRunContext {
                agent: ChannelAgent {
                    name: "codex".to_string(),
                },
                interrupt: Some(InterruptCallback::new(move || {
                    callback_interrupted.store(true, Ordering::Relaxed);
                    true
                })),
            },
        )
        .await
        .unwrap();

    run.publish(RunEvent::Started {
        run_id: "run-1".to_string(),
    })
    .await
    .unwrap();
    server.wait_for_endpoint_count("sendRichMessage", 1).await;
    let active = server
        .requests()
        .await
        .into_iter()
        .find(|request| request.endpoint() == "sendRichMessage")
        .unwrap();
    let active: serde_json::Value = serde_json::from_str(&active.body).unwrap();
    assert_eq!(
        active["rich_message"]["markdown"],
        format!("> **codex** · {}", crate::i18n::WAITING_FOR_AGENT)
    );
    assert!(
        !active["rich_message"]["markdown"]
            .as_str()
            .unwrap()
            .contains("<tg-thinking>")
    );
    assert_eq!(
        active["reply_markup"]["inline_keyboard"][0][0]["text"],
        "结束任务"
    );
    assert_eq!(
        active["reply_markup"]["inline_keyboard"][0][0]["callback_data"],
        "agora_interrupt:interrupt-1"
    );
    assert_eq!(
        active["reply_markup"]["inline_keyboard"][0][0]["style"],
        "danger"
    );

    run.publish(RunEvent::Output(crate::task::OutputEvent::Thinking {
        text: "Inspecting the project".to_string(),
    }))
    .await
    .unwrap();
    run.publish(RunEvent::Output(crate::task::OutputEvent::Answer {
        text: "Partial answer".to_string(),
    }))
    .await
    .unwrap();
    server.wait_for_endpoint_count("editMessageText", 1).await;
    assert_eq!(server.endpoint_count("sendRichMessage").await, 1);
    assert_eq!(server.endpoint_count("sendRichMessageDraft").await, 0);
    let streaming = server
        .requests()
        .await
        .into_iter()
        .find(|request| request.endpoint() == "editMessageText")
        .unwrap();
    let streaming: serde_json::Value = serde_json::from_str(&streaming.body).unwrap();
    assert_eq!(streaming["message_id"], 88);
    assert!(
        streaming["rich_message"]["markdown"]
            .as_str()
            .unwrap()
            .contains("Inspecting the project")
    );
    assert!(
        streaming["rich_message"]["markdown"]
            .as_str()
            .unwrap()
            .contains("Partial answer")
    );

    let next = channel.next_task().await.unwrap();
    assert_eq!(next.input().message().unwrap().text(), "after stop");
    assert!(interrupted.load(Ordering::Relaxed));
    server
        .wait_for_endpoint_count("answerCallbackQuery", 1)
        .await;
    run.publish(RunEvent::Stopped).await.unwrap();
    server.wait_for_endpoint_count("editMessageText", 2).await;
    let terminal = server
        .requests()
        .await
        .into_iter()
        .rfind(|request| request.endpoint() == "editMessageText")
        .unwrap();
    let terminal: serde_json::Value = serde_json::from_str(&terminal.body).unwrap();
    assert_eq!(
        terminal["reply_markup"]["inline_keyboard"],
        serde_json::json!([])
    );
}
