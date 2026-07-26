use super::*;

#[test]
fn telegram_renders_agent_status_replies_without_interactive_controls() {
    let list = ChannelReply::agent_list(vec![
        ChannelAgentStatus::new("codex-dev", true),
        ChannelAgentStatus::new("reviewer", false),
    ]);
    assert_eq!(
        TelegramChannel::render_reply(&list),
        "**当前对话的 Agent 状态**\n> 配置仅对当前对话生效\n\n\
         🟢 **codex-dev** · 已启用\n接收后续消息\n\n\
         ⚪ **reviewer** · 已禁用\n不接收后续消息"
    );

    let status = ChannelReply::agent_status(ChannelAgentStatus::new("reviewer", false));
    assert_eq!(
        TelegramChannel::render_reply(&status),
        "**当前对话的 Agent 状态**\n> 配置仅对当前对话生效\n\n\
         ⚪ **reviewer** · 已禁用\n不接收后续消息"
    );
}

#[test]
fn normalizes_private_text_message() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 101,
            "message": {
                "message_id": 7,
                "from": {"id": 1, "is_bot": false},
                "chat": {"id": 1, "type": "private"},
                "text": "hello"
            }
        }"#,
    )
    .unwrap();

    let task = update.into_task("agora_bot").unwrap();

    assert_eq!(task.task_id(), "101");
    assert_eq!(task.session_id(), "chat:1");
    assert_eq!(task.input().message().unwrap().text(), "hello");
    assert_eq!(task.reply_target().chat_id, 1);
    assert_eq!(task.reply_target().message_id, 7);
    assert_eq!(task.reply_target().message_thread_id, None);
    assert!(task.reply_target().is_private);
}

#[test]
fn normalizes_forum_topic_session_and_reply_target() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 102,
            "message": {
                "message_id": 8,
                "message_thread_id": 44,
                "from": {"id": 1, "is_bot": false},
                "chat": {"id": -1001, "type": "supergroup"},
                "text": "run tests"
            }
        }"#,
    )
    .unwrap();

    let task = update.into_task("agora_bot").unwrap();

    assert_eq!(task.task_id(), "102");
    assert_eq!(task.session_id(), "chat:-1001:topic:44");
    assert_eq!(task.input().message().unwrap().text(), "run tests");
    assert_eq!(task.reply_target().chat_id, -1001);
    assert_eq!(task.reply_target().message_id, 8);
    assert_eq!(task.reply_target().message_thread_id, Some(44));
    assert!(!task.reply_target().is_private);
}

#[test]
fn normalizes_photo_caption() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 103,
            "message": {
                "message_id": 9,
                "chat": {"id": 1, "type": "private"},
                "caption": "analyze this image",
                "photo": [
                    {"file_id": "photo-small"},
                    {"file_id": "photo-large"}
                ]
            }
        }"#,
    )
    .unwrap();

    let task = update.into_task("agora_bot").unwrap();

    assert_eq!(task.input().message().unwrap().text(), "analyze this image");
}

#[test]
fn accepts_a_photo_without_a_caption() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 104,
            "message": {
                "message_id": 10,
                "chat": {"id": 1, "type": "private"},
                "photo": [{"file_id": "photo-1"}]
            }
        }"#,
    )
    .unwrap();

    let task = update.into_task("agora_bot").unwrap();

    assert_eq!(task.input().message().unwrap().text(), "");
}

#[test]
fn ignores_messages_without_text_or_photos() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 104,
            "message": {
                "message_id": 10,
                "chat": {"id": 1, "type": "private"},
                "text": "   "
            }
        }"#,
    )
    .unwrap();

    assert!(update.into_task("agora_bot").is_none());
}

#[test]
fn normalizes_commands_addressed_to_this_bot() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 105,
            "message": {
                "message_id": 11,
                "chat": {"id": -1001, "type": "group"},
                "text": "/stop@Agora_Bot codex-dev"
            }
        }"#,
    )
    .unwrap();

    let task = update.into_task("agora_bot").unwrap();

    assert_eq!(task.input().message().unwrap().text(), "/stop codex-dev");
}

#[test]
fn ignores_commands_addressed_to_another_bot() {
    let update = TelegramUpdate::from_json(
        r#"{
            "update_id": 106,
            "message": {
                "message_id": 12,
                "chat": {"id": -1001, "type": "group"},
                "text": "/reset@another_bot"
            }
        }"#,
    )
    .unwrap();

    assert!(update.into_task("agora_bot").is_none());
}

#[test]
fn configured_telegram_channel_is_active() {
    let channel = ConfiguredChannel::from_config(ChannelConfig::Telegram(telegram_config()))
        .unwrap()
        .expect("telegram channel should be active");

    assert!(matches!(channel, ConfiguredChannel::Telegram(_)));
}
