use super::config::HookConfig;
use crate::protocol::{
    ControlRequest, ControlResponse, CoverageGap, RouteOutcome, RouteRegistration, read_message,
    write_message,
};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub(super) enum RouteDecision {
    Accepted,
    Rejected { errno: Option<i32> },
}

pub(super) struct ControlClient<'a> {
    config: &'a HookConfig,
}

impl<'a> ControlClient<'a> {
    pub(super) fn new(config: &'a HookConfig) -> Self {
        Self { config }
    }

    pub(super) fn register_route(
        &self,
        registration: RouteRegistration,
    ) -> Result<RouteDecision, String> {
        let connection_id = registration.connection_id.clone();
        match self.exchange(&ControlRequest::RegisterRoute(registration))? {
            ControlResponse::Route {
                connection_id: response_id,
                outcome: RouteOutcome::Accepted,
                ..
            } if response_id == connection_id => Ok(RouteDecision::Accepted),
            ControlResponse::Route {
                connection_id: response_id,
                outcome: RouteOutcome::Rejected,
                errno,
                ..
            } if response_id == connection_id => Ok(RouteDecision::Rejected { errno }),
            ControlResponse::ProtocolRejected { message } => Err(message),
            _ => Err("unexpected route registration response".to_string()),
        }
    }

    pub(super) fn report_coverage_gap(&self, gap: CoverageGap) -> Result<(), String> {
        match self.exchange(&ControlRequest::CoverageGap(gap))? {
            ControlResponse::CoverageGapRecorded => Ok(()),
            ControlResponse::ProtocolRejected { message } => Err(message),
            _ => Err("unexpected coverage-gap response".to_string()),
        }
    }

    fn exchange(&self, request: &ControlRequest) -> Result<ControlResponse, String> {
        let mut stream = UnixStream::connect(self.config.control_socket())
            .map_err(|error| format!("control socket connect failed: {error}"))?;
        let timeout = Some(Duration::from_secs(15));
        stream
            .set_read_timeout(timeout)
            .map_err(|error| format!("control read timeout setup failed: {error}"))?;
        stream
            .set_write_timeout(timeout)
            .map_err(|error| format!("control write timeout setup failed: {error}"))?;
        write_message(&mut stream, request)
            .map_err(|error| format!("control request failed: {error}"))?;
        read_message(&mut stream).map_err(|error| format!("control response failed: {error}"))
    }
}
