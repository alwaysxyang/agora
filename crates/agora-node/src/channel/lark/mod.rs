mod card;
mod channel;
mod lark_api;

pub use channel::{LarkChannel, LarkRun, LarkTask};

#[derive(Clone, Debug, PartialEq, Eq)]
struct LarkReplyTarget {
    message_id: String,
}

#[cfg(test)]
#[path = "../../../tests/internal/lark_card.rs"]
mod lark_card_tests;

#[cfg(test)]
#[path = "../../../tests/internal/lark_channel.rs"]
mod lark_channel_tests;
