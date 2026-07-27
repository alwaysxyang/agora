use super::*;

#[test]
fn command_and_message_inputs_expose_only_their_own_payload() {
    let command = CommandRequest::new(["ask", "status"]).with_argument("agent_name", "reviewer");
    assert_eq!(command.path(), &["ask", "status"]);
    assert_eq!(command.argument("agent_name"), Some("reviewer"));
    assert_eq!(command.argument("missing"), None);
    assert_eq!(command.arguments().len(), 1);

    let command_input = ChannelTaskInput::Command(command.clone());
    assert_eq!(command_input.command(), Some(&command));
    assert_eq!(command_input.message(), None);

    let message = TaskContent::new("inspect");
    let message_input = ChannelTaskInput::Message(message.clone());
    assert_eq!(message_input.message(), Some(&message));
    assert_eq!(message_input.command(), None);
}

#[test]
fn attachments_and_task_content_keep_owned_metadata_and_hide_bytes_in_debug() {
    let image = TaskAttachment::image("trace.png", "image/png", b"pixels".to_vec());
    assert_eq!(image.kind(), TaskAttachmentKind::Image);
    assert_eq!(image.file_name(), "trace.png");
    assert_eq!(image.media_type(), "image/png");
    assert_eq!(image.data(), b"pixels");
    assert_eq!(
        format!("{image:?}"),
        "TaskAttachment { kind: Image, file_name: \"trace.png\", media_type: \"image/png\", data_len: 6 }"
    );

    let content = TaskContent::new("inspect").with_attachment(image);
    assert_eq!(content.text(), "inspect");
    assert_eq!(content.attachments().len(), 1);
    let (text, attachments) = content.into_parts();
    assert_eq!(text, "inspect");
    assert_eq!(attachments.len(), 1);
    assert_eq!(TaskContent::from(String::from("owned")).text(), "owned");
    assert_eq!(TaskContent::from("borrowed").text(), "borrowed");
}
