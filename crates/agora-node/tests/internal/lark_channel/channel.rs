use super::*;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

fn api() -> LarkApi {
    LarkApi::with_base_url(
        LarkChannelConfig {
            name: "lark-channel-test".to_string(),
            app_id: "app-id".to_string(),
            secret: "secret".to_string(),
            proxy: None,
        },
        "http://127.0.0.1:1".to_string(),
    )
    .unwrap()
}

fn message(message_type: &str) -> LarkMessageEvent {
    LarkMessageEvent {
        id: "evt-message".to_string(),
        message_id: "om-message".to_string(),
        chat_id: "oc-chat".to_string(),
        chat_type: "group".to_string(),
        sender_id: "ou-user".to_string(),
        message_type: message_type.to_string(),
        content: "hello".to_string(),
        image_keys: Vec::new(),
    }
}

#[test]
fn image_extensions_cover_known_and_unknown_media_types() {
    assert_eq!(LarkChannel::image_extension("image/png"), "png");
    assert_eq!(LarkChannel::image_extension("image/jpeg"), "jpg");
    assert_eq!(LarkChannel::image_extension("image/webp"), "webp");
    assert_eq!(LarkChannel::image_extension("image/gif"), "gif");
    assert_eq!(LarkChannel::image_extension("image/bmp"), "bmp");
    assert_eq!(LarkChannel::image_extension("image/tiff"), "tiff");
    assert_eq!(LarkChannel::image_extension("image/heic"), "heic");
    assert_eq!(
        LarkChannel::image_extension("application/octet-stream"),
        "img"
    );
}

#[tokio::test]
async fn receiver_routes_ignored_interrupt_card_and_message_events() {
    let mut channel = LarkChannel::with_api(api());
    let interrupted = Arc::new(AtomicBool::new(false));
    let callback_interrupted = Arc::clone(&interrupted);
    let registration = channel.interrupts.register(InterruptCallback::new(move || {
        callback_interrupted.store(true, AtomicOrdering::Relaxed);
        true
    }));
    let (sender, events) = mpsc::unbounded_channel();
    sender
        .send(Ok(LarkEvent::Ignore {
            event_type: "ignored".to_string(),
        }))
        .unwrap();
    sender
        .send(Ok(LarkEvent::Message(message("file"))))
        .unwrap();
    sender
        .send(Ok(LarkEvent::Interrupt(LarkInterruptEvent {
            id: "evt-interrupt".to_string(),
            callback_id: registration.id().to_string(),
        })))
        .unwrap();
    sender
        .send(Ok(LarkEvent::CardAction(LarkCardActionEvent {
            id: "evt-action".to_string(),
            session_id: "oc-chat".to_string(),
            message_id: "om-card".to_string(),
            command: CommandRequest::new(["ask", "list"]),
        })))
        .unwrap();
    channel.receiver = Some(LarkWebSocketReceiver { events, task: None });

    let task = channel.recv().await.unwrap().unwrap();
    assert!(interrupted.load(AtomicOrdering::Relaxed));
    assert_eq!(task.task_id(), "evt-action");
    assert_eq!(task.session_id(), "oc-chat");
    assert_eq!(task.input().command().unwrap().path(), &["ask", "list"]);

    let (sender, events) = mpsc::unbounded_channel();
    sender
        .send(Ok(LarkEvent::Message(message("text"))))
        .unwrap();
    drop(sender);
    channel.receiver = Some(LarkWebSocketReceiver { events, task: None });
    let task = channel.recv().await.unwrap().unwrap();
    assert_eq!(task.task_id(), "om-message");
    assert_eq!(task.session_id(), "oc-chat");
    assert_eq!(task.input().message().unwrap().text(), "hello");
    assert_eq!(channel.recv().await.unwrap(), None);
}

#[tokio::test]
async fn receiver_propagates_event_task_and_join_errors() {
    let (sender, events) = mpsc::unbounded_channel();
    sender.send(Err(anyhow!("event failed"))).unwrap();
    let mut receiver = LarkWebSocketReceiver { events, task: None };
    assert!(
        receiver
            .next_event()
            .await
            .unwrap_err()
            .to_string()
            .contains("event failed")
    );

    let (sender, events) = mpsc::unbounded_channel();
    drop(sender);
    let mut receiver = LarkWebSocketReceiver {
        events,
        task: Some(tokio::spawn(async { Err(anyhow!("websocket failed")) })),
    };
    assert!(
        receiver
            .next_event()
            .await
            .unwrap_err()
            .to_string()
            .contains("websocket failed")
    );

    let (sender, events) = mpsc::unbounded_channel();
    drop(sender);
    let mut receiver = LarkWebSocketReceiver {
        events,
        task: Some(tokio::spawn(async {
            panic!("websocket panicked");
            #[allow(unreachable_code)]
            Ok(())
        })),
    };
    assert!(
        receiver
            .next_event()
            .await
            .unwrap_err()
            .to_string()
            .contains("receiver task failed")
    );
}

#[tokio::test]
async fn card_action_tasks_cannot_open_agent_runs() {
    let channel = LarkChannel::with_api(api());
    assert_eq!(channel.name(), "lark-channel-test");
    let task = LarkTask::from_card_action(LarkCardActionEvent {
        id: "evt-action".to_string(),
        session_id: "oc-chat".to_string(),
        message_id: "om-card".to_string(),
        command: CommandRequest::new(["ask", "list"]),
    });
    let error = channel
        .open_run(
            &task,
            ChannelRunContext {
                agent: crate::channel::ChannelAgent {
                    name: "codex".to_string(),
                },
                interrupt: None,
            },
        )
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("cannot open"));
}

#[tokio::test]
async fn configured_channel_rejects_a_task_from_another_channel_type() {
    use crate::channel::{ConfiguredChannel, ConfiguredTask};
    use crate::config::{ChannelConfig, TelegramChannelConfig};

    let channel = ConfiguredChannel::from_config(ChannelConfig::Telegram(TelegramChannelConfig {
        name: "telegram".to_string(),
        token: "123:secret".to_string(),
        proxy: None,
    }))
    .unwrap()
    .unwrap();
    let task = ConfiguredTask::Lark(LarkTask::from_message(
        message("text"),
        TaskContent::new("hello"),
    ));

    assert_eq!(task.task_id(), "om-message");
    assert_eq!(task.session_id(), "oc-chat");
    assert_eq!(task.input().message().unwrap().text(), "hello");

    let error = channel
        .open_run(
            &task,
            ChannelRunContext {
                agent: crate::channel::ChannelAgent {
                    name: "codex".to_string(),
                },
                interrupt: None,
            },
        )
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "configured channel and task types do not match"
    );

    let error = channel
        .reply(&task, ChannelReply::new("ignored"))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "configured channel and task types do not match"
    );
}
