use crate::channel::lark::card::LarkCardContent;
use crate::output::{OutputEvent, ProgressStatus};

#[test]
fn lark_card_separates_thinking_progress_and_final_answer() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    content.apply_output(OutputEvent::Thinking {
        text: "Inspecting the channel\nChecking reply delivery".to_string(),
    });
    content.apply_output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Running,
    });
    content.apply_output(OutputEvent::Progress {
        id: "command-1".to_string(),
        text: "Run `cargo test`".to_string(),
        status: ProgressStatus::Completed,
    });
    content.apply_output(OutputEvent::Answer {
        text: "The Lark path is ready.".to_string(),
    });
    content.complete();

    let card = content.build_card();
    assert_eq!(
        card.pointer("/header/title/content")
            .and_then(|v| v.as_str()),
        Some("codex-dev")
    );
    assert_eq!(
        card.pointer("/header/text_tag_list/0/text/content")
            .and_then(|v| v.as_str()),
        Some("Completed")
    );
    let rendered = serde_json::to_string(&card).unwrap();
    assert!(rendered.contains("**Thinking**"));
    assert!(rendered.contains("> Inspecting the channel"));
    assert!(rendered.contains("> Checking reply delivery"));
    assert!(rendered.contains("**Progress**"));
    assert!(rendered.contains("**Done**  Run `cargo test`"));
    assert!(rendered.contains("**Final answer**"));
    assert!(rendered.contains("The Lark path is ready."));
    assert_eq!(rendered.matches("Run `cargo test`").count(), 1);
}

#[test]
fn lark_card_keeps_only_the_five_latest_progress_entries() {
    let mut content = LarkCardContent::new("codex-dev".to_string());
    for index in 0..6 {
        content.apply_output(OutputEvent::Progress {
            id: format!("progress-{index}"),
            text: format!("Progress {index}"),
            status: ProgressStatus::Completed,
        });
    }

    let rendered = serde_json::to_string(&content.build_card()).unwrap();
    assert!(!rendered.contains("Progress 0"));
    for index in 1..6 {
        assert!(rendered.contains(format!("Progress {index}").as_str()));
    }
}
