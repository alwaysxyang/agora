use super::*;

#[tokio::test]
async fn lark_card_coalesces_intermediate_updates_and_flushes_completion() {
    let server = lark_http_server().await;
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        server.base_url(),
    )
    .unwrap();
    let card = LarkAgentCard::new(
        LarkReplyTarget {
            message_id: "om_source".to_string(),
        },
        "codex-dev".to_string(),
        None,
        api,
    );

    card.publish(RunEvent::Started {
        run_id: "run-1".to_string(),
    })
    .await
    .unwrap();
    for index in 0..3 {
        card.publish(RunEvent::Output(OutputEvent::Thinking {
            text: format!("Thinking {index}"),
        }))
        .await
        .unwrap();
    }

    server.wait_for_method_count("PATCH", 1).await;
    card.publish(RunEvent::Completed { exit_code: 0 })
        .await
        .unwrap();

    let requests = server.requests().await;
    let replies = requests
        .iter()
        .filter(|request| request.path == "/open-apis/im/v1/messages/om_source/reply")
        .collect::<Vec<_>>();
    let patches = requests
        .iter()
        .filter(|request| {
            request.method == "PATCH" && request.path == "/open-apis/im/v1/messages/om_reply"
        })
        .collect::<Vec<_>>();
    assert_eq!(replies.len(), 1);
    assert_eq!(patches.len(), 2);

    let reply_body: serde_json::Value = serde_json::from_str(&replies[0].body).unwrap();
    assert_eq!(reply_body["reply_in_thread"], true);
    let final_body: serde_json::Value = serde_json::from_str(&patches[1].body).unwrap();
    let final_card: serde_json::Value =
        serde_json::from_str(final_body["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        final_card
            .pointer("/header/text_tag_list/0/text/content")
            .and_then(serde_json::Value::as_str),
        Some("已完成")
    );
}

#[tokio::test]
async fn lark_api_replies_to_commands_with_threaded_text() {
    let server = lark_http_server().await;
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        server.base_url(),
    )
    .unwrap();
    let token = api.tenant_access_token().await.unwrap();

    api.reply_text(
        &token,
        &LarkReplyTarget {
            message_id: "om_source".to_string(),
        },
        "Stopped 1 agent: codex-dev.",
    )
    .await
    .unwrap();

    let requests = server.requests().await;
    let request = requests
        .iter()
        .find(|request| request.path == "/open-apis/im/v1/messages/om_source/reply")
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
    let content: serde_json::Value =
        serde_json::from_str(body["content"].as_str().unwrap()).unwrap();

    assert_eq!(request.method, "POST");
    assert_eq!(body["msg_type"], "text");
    assert_eq!(body["reply_in_thread"], true);
    assert_eq!(content["text"], "Stopped 1 agent: codex-dev.");
}

#[tokio::test]
async fn lark_agent_toggle_action_patches_the_original_status_card() {
    let server = lark_http_server().await;
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        server.base_url(),
    )
    .unwrap();
    let channel = LarkChannel::with_api(api);
    let task = LarkTask::from_card_action(LarkCardActionEvent {
        id: "evt_action".to_string(),
        session_id: "oc_chat".to_string(),
        message_id: "om_status_card".to_string(),
        command: CommandRequest::new(["ask", "enable"]).with_argument("agent_name", "reviewer"),
    });

    channel
        .reply(
            &task,
            ChannelReply::agent_list(vec![agent_status_with_button("reviewer", true)]),
        )
        .await
        .unwrap();

    let requests = server.requests().await;
    let patch = requests
        .iter()
        .find(|request| {
            request.method == "PATCH" && request.path == "/open-apis/im/v1/messages/om_status_card"
        })
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&patch.body).unwrap();
    let card: serde_json::Value = serde_json::from_str(body["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        card.pointer("/body/elements/0/columns/1/elements/0/text/content")
            .unwrap(),
        "Disable"
    );
}

#[tokio::test]
async fn lark_ask_message_replies_with_a_threaded_interactive_card() {
    let server = lark_http_server().await;
    let api = LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
        },
        server.base_url(),
    )
    .unwrap();
    let channel = LarkChannel::with_api(api);
    let task = LarkTask::from_message(
        LarkMessageEvent {
            id: "evt_message".to_string(),
            message_id: "om_ask".to_string(),
            chat_id: "oc_chat".to_string(),
            chat_type: "group".to_string(),
            sender_id: "ou_user".to_string(),
            message_type: "text".to_string(),
            content: "/ask list".to_string(),
            image_keys: Vec::new(),
        },
        crate::task::TaskContent::new("/ask list"),
    );

    channel
        .reply(
            &task,
            ChannelReply::agent_list(vec![agent_status_with_button("codex-dev", true)]),
        )
        .await
        .unwrap();

    let requests = server.requests().await;
    let reply = requests
        .iter()
        .find(|request| request.path == "/open-apis/im/v1/messages/om_ask/reply")
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(body["msg_type"], "interactive");
    assert_eq!(body["reply_in_thread"], true);
    let card: serde_json::Value = serde_json::from_str(body["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        card.pointer("/header/title/content").unwrap(),
        "当前对话的 Agent 状态"
    );
}
