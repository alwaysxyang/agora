use super::LarkReplyTarget;
use super::card::{LarkAgentCard, LarkCardContent, LarkReplyCard};
use super::channel::{LarkCardActionEvent, LarkChannel, LarkMessageEvent, LarkTask};
use super::lark_api::LarkApi;
use crate::channel::test_http::{HttpMockServer, MockResponse};
use crate::channel::{
    Channel, ChannelAgentStatus, ChannelButton, ChannelButtonStyle, ChannelReply, ChannelRun,
    RunEvent,
};
use crate::config::LarkChannelConfig;
use crate::task::{CommandRequest, OutputEvent, ProgressStatus, TokenUsage};

fn agent_status_with_button(name: &str, enabled: bool) -> ChannelAgentStatus {
    let (text, style, command) = if enabled {
        ("Disable", ChannelButtonStyle::Default, "disable")
    } else {
        ("Enable", ChannelButtonStyle::Primary, "enable")
    };
    ChannelAgentStatus::new(name, enabled).with_button(ChannelButton::new(
        text,
        style,
        CommandRequest::new(["ask", command]).with_argument("agent_name", name),
    ))
}

#[path = "lark_card/api.rs"]
mod api;
#[path = "lark_card/content.rs"]
mod content;

async fn lark_http_server() -> HttpMockServer {
    HttpMockServer::start(|request| {
        let body = if request.path.ends_with("tenant_access_token/internal") {
            r#"{"code":0,"msg":"ok","tenant_access_token":"token"}"#
        } else if request.path.ends_with("/reply") {
            r#"{"code":0,"msg":"ok","data":{"message_id":"om_reply"}}"#
        } else {
            r#"{"code":0,"msg":"ok"}"#
        };
        MockResponse::json(body)
    })
    .await
}
