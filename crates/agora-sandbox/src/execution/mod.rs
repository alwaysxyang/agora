mod controller;
mod protocol;
mod store;

pub(crate) use controller::ExecutionController;
pub(crate) use protocol::{
    CommandRequest, PrepareResponse, ProcessOperation, TRUNCATED_ARGUMENTS,
    decode_prepare_response, encode_prepare_request, encode_prepare_request_with_command,
    frame_length,
};
#[cfg(test)]
pub(crate) use protocol::{EXECUTION_PROTOCOL_VERSION, decode_prepare_request};
pub(crate) use store::{resolve_executable, resolve_shebang};

#[cfg(test)]
mod tests;
